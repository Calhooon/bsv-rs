//! SHIP topic broadcaster.
//!
//! Broadcasts transactions to overlay topics via SHIP (Submit Hierarchical
//! Information Protocol).

use crate::overlay::{
    facilitators::{HttpsOverlayBroadcastFacilitator, OverlayBroadcastFacilitator},
    host_reputation_tracker::get_overlay_host_reputation_tracker,
    lookup_resolver::{LookupResolver, LookupResolverConfig},
    types::{HostResponse, LookupQuestion, NetworkPreset, TaggedBEEF, MAX_SHIP_QUERY_TIMEOUT_MS},
};
use crate::transaction::{
    BroadcastFailure, BroadcastResponse, BroadcastResult, BroadcastStatus, Broadcaster, Transaction,
};
use crate::Result;
use async_trait::async_trait;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

mod cache; // the interested hosts cached five minutes, one discovery in flight (#815)
mod discovery; // the discovery's admission and the endpoint's origin (#804)
mod requirements; // the acknowledgment requirements as the reference has them
mod steak; // a host's STEAK judged as the reference's `validateSTEAK` (#815)

/// Acknowledgment requirement for broadcast success.
#[derive(Debug, Clone, Default)]
pub enum RequireAck {
    /// No acknowledgment required.
    #[default]
    None,
    /// Acknowledgment from any host.
    Any,
    /// Acknowledgment from specific hosts.
    Some(Vec<String>),
    /// Acknowledgment from all hosts.
    All,
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
    ///
    /// Every interested host is judged, a host that failed as one that
    /// acknowledged nothing (`SHIPBroadcaster.ts:511-512`). A list naming a
    /// topic outside the broadcast's refuses [`TopicBroadcaster::new`]
    /// (`:182-193`), as it does in the two fields below.
    pub require_ack_from_all_hosts: RequireAck,
    /// Required acknowledgment from any host for these topics.
    ///
    /// - `All`: All topics must be acknowledged by at least one host (default,
    ///   the reference's `'all'`, `SHIPBroadcaster.ts:436`)
    /// - `Any`: At least one topic must be acknowledged by at least one host
    /// - `Some(topics)`: One host must acknowledge every specified topic
    ///   (the reference's list reads `require: 'all'`, `SHIPBroadcaster.ts:584`)
    /// - `None`: No requirement
    pub require_ack_from_any_host: RequireAck,
    /// Specific host requirements.
    ///
    /// Map of host URL to required acknowledgment for that host. At most 32
    /// entries; each key is read as the reference's `shipEndpoint` reads it
    /// (`https:`, or `http:` under [`NetworkPreset::Local`], no credentials,
    /// query, fragment or path) and held as its origin, the form the
    /// discovery admits a host in; a key that is no such URL, or a second
    /// key of one origin, refuses [`TopicBroadcaster::new`] (#804).
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
    interested_hosts: cache::InterestedHostsCache,
}

impl TopicBroadcaster {
    /// Create a new broadcaster for the given topics.
    ///
    /// # Arguments
    ///
    /// * `topics` - List of topics to broadcast to: one to 64 unique
    ///   canonical names, each matching the reference's
    ///   `^(?=.{1,50}$)tm_[a-z]+(?:_[a-z]+)*$` (`SHIPBroadcaster.ts:156-179`,
    ///   `:420`, #815), else refused in the reference's words.
    /// * `config` - Configuration options
    ///
    /// # Returns
    ///
    /// A new TopicBroadcaster, or an error if topics are invalid or the
    /// specific-host requirements are refused as the reference's
    /// constructor refuses them (`SHIPBroadcaster.ts:195-219`, #804): more
    /// than 32 hosts, a host that is no endpoint origin, two hosts of one
    /// origin; or a requirement's topic list (all hosts, any host, each
    /// specific host) is refused as `snapshotAcknowledgmentRequirement`
    /// refuses it (`:182-193`): more than 64 topics, one not a unique
    /// canonical `tm_` name, or one outside `topics`
    /// (`<label> may only reference topics included in this broadcast.`).
    pub fn new(topics: Vec<String>, config: TopicBroadcasterConfig) -> Result<Self> {
        // The broadcast topics as the reference reads them
        // (`canonicalTopics(topics, 'Broadcast topics')`,
        // `SHIPBroadcaster.ts:420`, `:156-179`, #815): one to 64 unique
        // canonical `tm_` names, ahead of the requirements.
        requirements::canonical_topics(&topics, "Broadcast topics", false)?;

        // The all-host and any-host requirements' topic lists, as the
        // reference snapshots them (`SHIPBroadcaster.ts:430-439`,
        // `snapshotAcknowledgmentRequirement`, `:182-193`): nothing is sent
        // under a requirement naming a topic outside the broadcast's.
        requirements::snapshot(
            &config.require_ack_from_all_hosts,
            &topics,
            "All-host acknowledgment requirement",
        )?;
        requirements::snapshot(
            &config.require_ack_from_any_host,
            &topics,
            "Any-host acknowledgment requirement",
        )?;

        // Each key its endpoint's origin, as the reference snapshots them
        // (`SHIPBroadcaster.ts:195-219`, under `allowHTTP` for the local
        // preset alone, `:426`; #804), each requirement's topics checked
        // after its key (`:212-216`)
        let require_ack_from_specific_hosts = discovery::specific_hosts(
            config.require_ack_from_specific_hosts,
            config.network_preset.allow_http(),
            |origin, requirement| {
                requirements::snapshot(
                    requirement,
                    &topics,
                    &format!("Acknowledgment requirement for {origin}"),
                )
            },
        )?;

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
            require_ack_from_specific_hosts,
            network_preset: config.network_preset,
            interested_hosts: cache::InterestedHostsCache::new(),
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
        let interested_hosts =
            self.find_interested_hosts()
                .await
                .map_err(|e| BroadcastFailure {
                    status: BroadcastStatus::Error,
                    code: "ERR_HOST_DISCOVERY".into(),
                    txid: Some(tx.id()),
                    description: e.to_string(),
                    more: None,
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

                let sent = host_topics.clone();
                async move {
                    let start = Instant::now();
                    let result = facilitator.send(&host, &tagged).await;
                    let elapsed = start.elapsed().as_millis() as u64;
                    (host, sent, result, elapsed)
                }
            })
            .collect();

        let results = futures::future::join_all(futures).await;

        // Collect responses
        let mut host_responses: Vec<HostResponse> = Vec::new();
        let mut host_acks: HashMap<String, HashSet<String>> = HashMap::new();

        for (host, sent, result, elapsed) in results {
            match result {
                Ok(steak) => {
                    reputation_tracker.record_success(&host, elapsed);

                    // The STEAK judged as the reference judges it, over the
                    // topics sent to this host (`SHIPBroadcaster.ts:486-496`,
                    // `validateSTEAK`, `:240-269`, #815): the empty one or a
                    // refused one fails the host. Its acknowledgments and
                    // its success are read from the judged value alone
                    match steak::judge(steak, &sent) {
                        Ok(taken) => {
                            host_acks.insert(host.clone(), taken.acknowledged());
                            host_responses.push(HostResponse::success(host, taken.into_steak()));
                        }
                        Err(words) => host_responses.push(HostResponse::failure(host, words)),
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

        // Every interested host seeded with an empty set, so a host that
        // failed acknowledged nothing (`SHIPBroadcaster.ts:511-512`); then
        // the three checks in the reference's order and codes (`:538-546`)
        let host_acks = requirements::seeded(interested_hosts.keys(), host_acks);
        if let Err(failure) = self.check_acknowledgments(&host_acks) {
            return Err(BroadcastFailure {
                status: BroadcastStatus::Error,
                code: failure.code().into(),
                txid: Some(tx.id()),
                description: failure.description().into(),
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
    ///
    /// The `ls_ship` answer is read as the reference's `#fetchInterestedHosts`
    /// reads it (`ts-stack@edf6e03` `SHIPBroadcaster.ts:725-789`, #804): an
    /// answer that is no output list, or carries more than 256 outputs, is
    /// refused (`SHIP answer is not a bounded output list.`); an output is
    /// skipped when its BEEF is empty or over 16 MiB, its `txid` hint is not
    /// 64 hex digits or, lower-cased, not its BEEF's subject, the answer's
    /// BEEF passes 64 MiB at or before it, its selected output does not carry
    /// exactly 1 satoshi, its advertisement does not authenticate as SHIP for
    /// one of our topics, or the advertised domain is no `https:` origin; a
    /// host is keyed by that origin, and at most 32 are admitted.
    ///
    /// The answer is kept five minutes and one discovery runs at a time, as
    /// the reference's `findInterestedHosts` keeps it (`:700-718`, #815): a
    /// broadcaster reused within five minutes of a discovery does not see a
    /// host advertised since. A failed discovery is not kept; a caller
    /// waiting on it then asks for itself.
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

        // The answer kept five minutes and one discovery in flight, as the
        // reference's `findInterestedHosts` keeps it
        // (`SHIPBroadcaster.ts:700-718`, #815)
        self.interested_hosts
            .get_or_fetch(|| self.fetch_interested_hosts())
            .await
    }

    /// `#fetchInterestedHosts` (`SHIPBroadcaster.ts:725-789`): the `ls_ship`
    /// lookup, read by `discovery::interested_hosts`.
    async fn fetch_interested_hosts(&self) -> Result<HashMap<String, HashSet<String>>> {
        // Query for hosts interested in our topics via SHIP lookup
        let question = LookupQuestion::new("ls_ship", serde_json::json!({ "topics": self.topics }));

        let answer = self
            .resolver
            .query(&question, Some(MAX_SHIP_QUERY_TIMEOUT_MS))
            .await?;

        // Admitted as the reference's `#fetchInterestedHosts` admits them
        // (`SHIPBroadcaster.ts:737-786`, #804; the authentication, `:775`,
        // since #544)
        discovery::interested_hosts(&self.topics, answer)
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
            Err(e) => assert_eq!(
                e.to_string(),
                "overlay error: Broadcast topics must be a bounded array of canonical topic names."
            ),
            Ok(_) => panic!("Expected error for empty topics"),
        }
    }

    #[test]
    fn test_require_ack_default() {
        let config = TopicBroadcasterConfig::default();
        assert!(matches!(
            config.require_ack_from_all_hosts,
            RequireAck::None
        ));
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
    fn the_broadcaster_stays_send_and_sync_815() {
        fn send_sync<T: Send + Sync>() {}
        send_sync::<TopicBroadcaster>();
    }

    #[test]
    fn test_aliases() {
        // Ensure type aliases compile
        let _: fn(Vec<String>, TopicBroadcasterConfig) -> Result<SHIPBroadcaster> =
            SHIPBroadcaster::new;
        let _: fn(Vec<String>, TopicBroadcasterConfig) -> Result<SHIPCast> = SHIPCast::new;
    }
}
