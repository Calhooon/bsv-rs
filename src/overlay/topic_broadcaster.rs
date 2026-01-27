//! SHIP topic broadcaster.
//!
//! Broadcasts transactions to overlay topics via SHIP (Submit Hierarchical
//! Information Protocol).

use crate::overlay::{
    facilitators::{HttpsOverlayBroadcastFacilitator, OverlayBroadcastFacilitator},
    host_reputation_tracker::get_overlay_host_reputation_tracker,
    lookup_resolver::{LookupResolver, LookupResolverConfig},
    overlay_admin_token_template::decode_overlay_admin_token,
    types::{
        HostResponse, LookupAnswer, LookupQuestion, NetworkPreset, Protocol, TaggedBEEF,
        MAX_SHIP_QUERY_TIMEOUT_MS,
    },
};
use crate::transaction::{
    BroadcastFailure, BroadcastResponse, BroadcastResult, BroadcastStatus, Broadcaster, Transaction,
};
use crate::{Error, Result};
use async_trait::async_trait;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

/// Acknowledgment requirement for broadcast success.
#[derive(Debug, Clone)]
pub enum RequireAck {
    /// No acknowledgment required.
    None,
    /// Acknowledgment from any host.
    Any,
    /// Acknowledgment from specific hosts.
    Some(Vec<String>),
    /// Acknowledgment from all hosts.
    All,
}

impl Default for RequireAck {
    fn default() -> Self {
        Self::None
    }
}

/// Configuration for the topic broadcaster.
#[derive(Clone)]
pub struct TopicBroadcasterConfig {
    /// Network preset.
    pub network_preset: NetworkPreset,
    /// Custom broadcast facilitator.
    pub facilitator: Option<Arc<dyn OverlayBroadcastFacilitator>>,
    /// Custom lookup resolver.
    pub resolver: Option<Arc<LookupResolver>>,
    /// Required acknowledgment from all hosts for these topics.
    ///
    /// - `All`: All topics must be acknowledged by all hosts
    /// - `Any`: At least one topic must be acknowledged by each host
    /// - `Some(topics)`: Specified topics must be acknowledged by all hosts
    /// - `None`: No requirement
    pub require_ack_from_all_hosts: RequireAck,
    /// Required acknowledgment from any host for these topics.
    ///
    /// - `All`: All topics must be acknowledged by at least one host
    /// - `Any`: At least one topic must be acknowledged by at least one host (default)
    /// - `Some(topics)`: Specified topics must be acknowledged by at least one host
    /// - `None`: No requirement
    pub require_ack_from_any_host: RequireAck,
    /// Specific host requirements.
    ///
    /// Map of host URL to required acknowledgment for that host.
    pub require_ack_from_specific_hosts: HashMap<String, RequireAck>,
}

impl Default for TopicBroadcasterConfig {
    fn default() -> Self {
        Self {
            network_preset: NetworkPreset::Mainnet,
            facilitator: None,
            resolver: None,
            require_ack_from_all_hosts: RequireAck::None,
            require_ack_from_any_host: RequireAck::All,
            require_ack_from_specific_hosts: HashMap::new(),
        }
    }
}

/// Broadcasts transactions to SHIP overlay topics.
///
/// Implements the `Broadcaster` trait for integration with the transaction
/// module's broadcasting infrastructure.
pub struct TopicBroadcaster {
    topics: Vec<String>,
    facilitator: Arc<dyn OverlayBroadcastFacilitator>,
    resolver: Arc<LookupResolver>,
    require_ack_from_all_hosts: RequireAck,
    require_ack_from_any_host: RequireAck,
    require_ack_from_specific_hosts: HashMap<String, RequireAck>,
    network_preset: NetworkPreset,
}

impl TopicBroadcaster {
    /// Create a new broadcaster for the given topics.
    ///
    /// # Arguments
    ///
    /// * `topics` - List of topics to broadcast to. Each must start with "tm_".
    /// * `config` - Configuration options
    ///
    /// # Returns
    ///
    /// A new TopicBroadcaster, or an error if topics are invalid.
    pub fn new(topics: Vec<String>, config: TopicBroadcasterConfig) -> Result<Self> {
        // Validate at least one topic
        if topics.is_empty() {
            return Err(Error::OverlayError(
                "At least one topic is required for broadcast.".into(),
            ));
        }

        // Validate topic names
        for topic in &topics {
            if !topic.starts_with("tm_") {
                return Err(Error::OverlayError(format!(
                    "Every topic must start with \"tm_\": {}",
                    topic
                )));
            }
        }

        let facilitator = config.facilitator.unwrap_or_else(|| {
            Arc::new(HttpsOverlayBroadcastFacilitator::new(
                config.network_preset.allow_http(),
            ))
        });

        let resolver = config.resolver.unwrap_or_else(|| {
            Arc::new(LookupResolver::new(LookupResolverConfig {
                network_preset: config.network_preset,
                ..Default::default()
            }))
        });

        Ok(Self {
            topics,
            facilitator,
            resolver,
            require_ack_from_all_hosts: config.require_ack_from_all_hosts,
            require_ack_from_any_host: config.require_ack_from_any_host,
            require_ack_from_specific_hosts: config.require_ack_from_specific_hosts,
            network_preset: config.network_preset,
        })
    }

    /// Broadcast a transaction to all interested hosts.
    pub async fn broadcast_tx(&self, tx: &Transaction) -> BroadcastResult {
        // Serialize to BEEF
        let beef = tx.to_beef(true).map_err(|e| BroadcastFailure {
            status: BroadcastStatus::Error,
            code: "ERR_BEEF_SERIALIZATION".into(),
            txid: Some(tx.id()),
            description: format!(
                "Transactions sent via SHIP to Overlay Services must be serializable to BEEF format: {}",
                e
            ),
            more: None,
        })?;

        // Get off-chain values from metadata if present
        let off_chain_values = tx
            .metadata
            .get("OffChainValues")
            .and_then(|v| serde_json::from_value::<Vec<u8>>(v.clone()).ok());

        let tagged = TaggedBEEF {
            beef,
            topics: self.topics.clone(),
            off_chain_values,
        };

        // Find interested hosts
        let interested_hosts = self.find_interested_hosts().await.map_err(|e| {
            BroadcastFailure {
                status: BroadcastStatus::Error,
                code: "ERR_HOST_DISCOVERY".into(),
                txid: Some(tx.id()),
                description: e.to_string(),
                more: None,
            }
        })?;

        if interested_hosts.is_empty() {
            return Err(BroadcastFailure {
                status: BroadcastStatus::Error,
                code: "ERR_NO_HOSTS_INTERESTED".into(),
                txid: Some(tx.id()),
                description: format!(
                    "No {} hosts are interested in receiving this transaction.",
                    self.network_preset_str()
                ),
                more: None,
            });
        }

        // Broadcast to all interested hosts in parallel
        let reputation_tracker = get_overlay_host_reputation_tracker();

        let futures: Vec<_> = interested_hosts
            .iter()
            .map(|(host, host_topics)| {
                let host = host.clone();
                let facilitator = self.facilitator.clone();
                let tagged = TaggedBEEF {
                    beef: tagged.beef.clone(),
                    topics: host_topics.iter().cloned().collect(),
                    off_chain_values: tagged.off_chain_values.clone(),
                };

                async move {
                    let start = Instant::now();
                    let result = facilitator.send(&host, &tagged).await;
                    let elapsed = start.elapsed().as_millis() as u64;
                    (host, result, elapsed)
                }
            })
            .collect();

        let results = futures::future::join_all(futures).await;

        // Collect responses
        let mut host_responses: Vec<HostResponse> = Vec::new();
        let mut host_acks: HashMap<String, HashSet<String>> = HashMap::new();

        for (host, result, elapsed) in results {
            match result {
                Ok(steak) => {
                    reputation_tracker.record_success(&host, elapsed);

                    // Track which topics this host acknowledged
                    let mut acknowledged_topics = HashSet::new();
                    for (topic, instructions) in &steak {
                        if instructions.has_activity() {
                            acknowledged_topics.insert(topic.clone());
                        }
                    }

                    // Only count as success if steak has topics
                    if !steak.is_empty() {
                        host_acks.insert(host.clone(), acknowledged_topics);
                        host_responses.push(HostResponse::success(host, steak));
                    } else {
                        host_responses.push(HostResponse::failure(
                            host.clone(),
                            "Steak has no topics".into(),
                        ));
                    }
                }
                Err(e) => {
                    reputation_tracker.record_failure(&host, Some(&e.to_string()));
                    host_responses.push(HostResponse::failure(host, e.to_string()));
                }
            }
        }

        // Check if any host succeeded
        let success_count = host_responses.iter().filter(|r| r.success).count();
        if success_count == 0 {
            return Err(BroadcastFailure {
                status: BroadcastStatus::Error,
                code: "ERR_ALL_HOSTS_REJECTED".into(),
                txid: Some(tx.id()),
                description: format!(
                    "All {} topical hosts have rejected the transaction.",
                    self.network_preset_str()
                ),
                more: None,
            });
        }

        // Check acknowledgment requirements
        if let Err(e) = self.check_acknowledgments(&host_acks) {
            return Err(BroadcastFailure {
                status: BroadcastStatus::Error,
                code: "ERR_REQUIRE_ACK_FAILED".into(),
                txid: Some(tx.id()),
                description: e.to_string(),
                more: None,
            });
        }

        Ok(BroadcastResponse {
            status: BroadcastStatus::Success,
            txid: tx.id(),
            message: format!(
                "Sent to {} Overlay Services {}.",
                success_count,
                if success_count == 1 { "host" } else { "hosts" }
            ),
            competing_txs: None,
        })
    }

    /// Find hosts interested in the configured topics.
    ///
    /// Returns a map of host URL to the set of topics that host is interested in.
    pub async fn find_interested_hosts(&self) -> Result<HashMap<String, HashSet<String>>> {
        // Handle local preset
        if self.network_preset == NetworkPreset::Local {
            let mut result = HashMap::new();
            result.insert(
                "http://localhost:8080".to_string(),
                self.topics.iter().cloned().collect(),
            );
            return Ok(result);
        }

        // Query for hosts interested in our topics via SHIP lookup
        let question = LookupQuestion::new(
            "ls_ship",
            serde_json::json!({ "topics": self.topics }),
        );

        let answer = self
            .resolver
            .query(&question, Some(MAX_SHIP_QUERY_TIMEOUT_MS))
            .await?;

        let mut results: HashMap<String, HashSet<String>> = HashMap::new();

        if let LookupAnswer::OutputList { outputs } = answer {
            for output in outputs {
                // Parse BEEF and extract admin token
                if let Ok(tx) = crate::transaction::Transaction::from_beef(&output.beef, None) {
                    if let Some(script) = tx
                        .outputs
                        .get(output.output_index as usize)
                        .map(|o| &o.locking_script)
                    {
                        if let Ok(token) = decode_overlay_admin_token(script) {
                            // Only include SHIP tokens for our topics
                            if token.protocol == Protocol::Ship
                                && self.topics.contains(&token.topic_or_service)
                            {
                                results
                                    .entry(token.domain.clone())
                                    .or_default()
                                    .insert(token.topic_or_service);
                            }
                        }
                    }
                }
            }
        }

        Ok(results)
    }

    /// Check acknowledgment requirements.
    fn check_acknowledgments(
        &self,
        host_acks: &HashMap<String, HashSet<String>>,
    ) -> Result<()> {
        // Check require_ack_from_all_hosts
        self.check_all_hosts_requirement(host_acks)?;

        // Check require_ack_from_any_host
        self.check_any_host_requirement(host_acks)?;

        // Check require_ack_from_specific_hosts
        self.check_specific_hosts_requirement(host_acks)?;

        Ok(())
    }

    fn check_all_hosts_requirement(
        &self,
        host_acks: &HashMap<String, HashSet<String>>,
    ) -> Result<()> {
        let required_topics = match &self.require_ack_from_all_hosts {
            RequireAck::None => return Ok(()),
            RequireAck::All => self.topics.clone(),
            RequireAck::Any => self.topics.clone(),
            RequireAck::Some(topics) => topics.clone(),
        };

        let require_all = !matches!(self.require_ack_from_all_hosts, RequireAck::Any);

        for acked_topics in host_acks.values() {
            if require_all {
                // All required topics must be acknowledged by this host
                for topic in &required_topics {
                    if !acked_topics.contains(topic) {
                        return Err(Error::OverlayError(
                            "Not all hosts acknowledged the required topics.".into(),
                        ));
                    }
                }
            } else {
                // At least one required topic must be acknowledged by this host
                let any_acked = required_topics.iter().any(|t| acked_topics.contains(t));
                if !any_acked {
                    return Err(Error::OverlayError(
                        "Not all hosts acknowledged at least one required topic.".into(),
                    ));
                }
            }
        }

        Ok(())
    }

    fn check_any_host_requirement(
        &self,
        host_acks: &HashMap<String, HashSet<String>>,
    ) -> Result<()> {
        let required_topics = match &self.require_ack_from_any_host {
            RequireAck::None => return Ok(()),
            RequireAck::All => self.topics.clone(),
            RequireAck::Any => self.topics.clone(),
            RequireAck::Some(topics) => topics.clone(),
        };

        let require_all = matches!(self.require_ack_from_any_host, RequireAck::All);

        if require_all {
            // All required topics must be acknowledged by at least one host
            for acked_topics in host_acks.values() {
                let acks_all = required_topics.iter().all(|t| acked_topics.contains(t));
                if acks_all {
                    return Ok(());
                }
            }
            Err(Error::OverlayError(
                "No host acknowledged all required topics.".into(),
            ))
        } else {
            // At least one required topic must be acknowledged by at least one host
            for acked_topics in host_acks.values() {
                let any_acked = required_topics.iter().any(|t| acked_topics.contains(t));
                if any_acked {
                    return Ok(());
                }
            }
            Err(Error::OverlayError(
                "No host acknowledged the required topics.".into(),
            ))
        }
    }

    fn check_specific_hosts_requirement(
        &self,
        host_acks: &HashMap<String, HashSet<String>>,
    ) -> Result<()> {
        for (host, requirement) in &self.require_ack_from_specific_hosts {
            let acked_topics = match host_acks.get(host) {
                Some(topics) => topics,
                None => {
                    return Err(Error::OverlayError(format!(
                        "Required host {} did not respond successfully.",
                        host
                    )));
                }
            };

            let (required_topics, require_all) = match requirement {
                RequireAck::None => continue,
                RequireAck::All => (self.topics.clone(), true),
                RequireAck::Any => (self.topics.clone(), false),
                RequireAck::Some(topics) => (topics.clone(), true),
            };

            if require_all {
                for topic in &required_topics {
                    if !acked_topics.contains(topic) {
                        return Err(Error::OverlayError(format!(
                            "Host {} did not acknowledge required topic {}.",
                            host, topic
                        )));
                    }
                }
            } else {
                let any_acked = required_topics.iter().any(|t| acked_topics.contains(t));
                if !any_acked {
                    return Err(Error::OverlayError(format!(
                        "Host {} did not acknowledge any required topic.",
                        host
                    )));
                }
            }
        }

        Ok(())
    }

    fn network_preset_str(&self) -> &'static str {
        match self.network_preset {
            NetworkPreset::Mainnet => "mainnet",
            NetworkPreset::Testnet => "testnet",
            NetworkPreset::Local => "local",
        }
    }
}

#[async_trait(?Send)]
impl Broadcaster for TopicBroadcaster {
    async fn broadcast(&self, tx: &Transaction) -> BroadcastResult {
        self.broadcast_tx(tx).await
    }

    async fn broadcast_many(&self, txs: Vec<Transaction>) -> Vec<BroadcastResult> {
        // Broadcast each transaction sequentially
        // Could be parallelized if needed
        let mut results = Vec::with_capacity(txs.len());
        for tx in &txs {
            results.push(self.broadcast_tx(tx).await);
        }
        results
    }
}

/// Alias for backward compatibility with TypeScript SDK naming.
pub type SHIPBroadcaster = TopicBroadcaster;

/// Alias for alternate naming.
pub type SHIPCast = TopicBroadcaster;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_topic_validation() {
        let result = TopicBroadcaster::new(
            vec!["tm_valid".to_string()],
            TopicBroadcasterConfig::default(),
        );
        assert!(result.is_ok());

        let result = TopicBroadcaster::new(
            vec!["invalid_topic".to_string()],
            TopicBroadcasterConfig::default(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_topics_rejected() {
        let result = TopicBroadcaster::new(vec![], TopicBroadcasterConfig::default());
        match result {
            Err(e) => assert!(e.to_string().contains("At least one topic")),
            Ok(_) => panic!("Expected error for empty topics"),
        }
    }

    #[test]
    fn test_require_ack_default() {
        let config = TopicBroadcasterConfig::default();
        assert!(matches!(config.require_ack_from_all_hosts, RequireAck::None));
        assert!(matches!(config.require_ack_from_any_host, RequireAck::All));
    }

    #[test]
    fn test_check_all_hosts_requirement() {
        let broadcaster = TopicBroadcaster::new(
            vec!["tm_test".to_string()],
            TopicBroadcasterConfig {
                require_ack_from_all_hosts: RequireAck::All,
                ..Default::default()
            },
        )
        .unwrap();

        // All hosts acknowledge
        let mut host_acks = HashMap::new();
        host_acks.insert(
            "host1".to_string(),
            vec!["tm_test".to_string()].into_iter().collect(),
        );
        host_acks.insert(
            "host2".to_string(),
            vec!["tm_test".to_string()].into_iter().collect(),
        );

        assert!(broadcaster.check_all_hosts_requirement(&host_acks).is_ok());

        // One host doesn't acknowledge
        let mut host_acks = HashMap::new();
        host_acks.insert(
            "host1".to_string(),
            vec!["tm_test".to_string()].into_iter().collect(),
        );
        host_acks.insert("host2".to_string(), HashSet::new());

        assert!(broadcaster.check_all_hosts_requirement(&host_acks).is_err());
    }

    #[test]
    fn test_check_any_host_requirement() {
        let broadcaster = TopicBroadcaster::new(
            vec!["tm_test".to_string()],
            TopicBroadcasterConfig {
                require_ack_from_any_host: RequireAck::Any,
                ..Default::default()
            },
        )
        .unwrap();

        // At least one host acknowledges
        let mut host_acks = HashMap::new();
        host_acks.insert(
            "host1".to_string(),
            vec!["tm_test".to_string()].into_iter().collect(),
        );
        host_acks.insert("host2".to_string(), HashSet::new());

        assert!(broadcaster.check_any_host_requirement(&host_acks).is_ok());

        // No host acknowledges
        let mut host_acks = HashMap::new();
        host_acks.insert("host1".to_string(), HashSet::new());
        host_acks.insert("host2".to_string(), HashSet::new());

        assert!(broadcaster.check_any_host_requirement(&host_acks).is_err());
    }

    #[test]
    fn test_aliases() {
        // Ensure type aliases compile
        let _: fn(Vec<String>, TopicBroadcasterConfig) -> Result<SHIPBroadcaster> =
            SHIPBroadcaster::new;
        let _: fn(Vec<String>, TopicBroadcasterConfig) -> Result<SHIPCast> = SHIPCast::new;
    }
}
