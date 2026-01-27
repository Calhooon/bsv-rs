//! SLAP lookup resolver.
//!
//! Resolves lookup queries by discovering competent hosts via SLAP trackers
//! and querying them in parallel with aggregation.

use crate::overlay::{
    facilitators::{HttpsOverlayLookupFacilitator, OverlayLookupFacilitator},
    host_reputation_tracker::{get_overlay_host_reputation_tracker, HostReputationTracker},
    overlay_admin_token_template::decode_overlay_admin_token,
    types::{
        LookupAnswer, LookupQuestion, NetworkPreset, OutputListItem, Protocol,
        DEFAULT_HOSTS_CACHE_MAX_ENTRIES, DEFAULT_HOSTS_CACHE_TTL_MS, MAX_TRACKER_WAIT_TIME_MS,
    },
};
use crate::transaction::Transaction;
use crate::{Error, Result};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

/// Configuration for the lookup resolver.
#[derive(Clone)]
pub struct LookupResolverConfig {
    /// Network preset (mainnet, testnet, local).
    pub network_preset: NetworkPreset,
    /// Custom lookup facilitator.
    pub facilitator: Option<Arc<dyn OverlayLookupFacilitator>>,
    /// Custom SLAP tracker URLs.
    pub slap_trackers: Option<Vec<String>>,
    /// Manual host overrides per service.
    pub host_overrides: Option<HashMap<String, Vec<String>>>,
    /// Additional hosts to query per service.
    pub additional_hosts: Option<HashMap<String, Vec<String>>>,
    /// TTL for hosts cache in milliseconds.
    pub hosts_cache_ttl_ms: u64,
    /// Maximum entries in hosts cache.
    pub hosts_cache_max_entries: usize,
}

impl Default for LookupResolverConfig {
    fn default() -> Self {
        Self {
            network_preset: NetworkPreset::Mainnet,
            facilitator: None,
            slap_trackers: None,
            host_overrides: None,
            additional_hosts: None,
            hosts_cache_ttl_ms: DEFAULT_HOSTS_CACHE_TTL_MS,
            hosts_cache_max_entries: DEFAULT_HOSTS_CACHE_MAX_ENTRIES,
        }
    }
}

/// Cache entry for host discovery.
struct HostsCacheEntry {
    hosts: Vec<String>,
    expires_at: u64,
}

/// Resolver for SLAP lookup queries.
///
/// Discovers competent hosts via SLAP trackers, caches the results,
/// and queries them in parallel with response aggregation.
pub struct LookupResolver {
    facilitator: Arc<dyn OverlayLookupFacilitator>,
    slap_trackers: Vec<String>,
    host_overrides: HashMap<String, Vec<String>>,
    additional_hosts: HashMap<String, Vec<String>>,
    reputation_tracker: &'static HostReputationTracker,
    network_preset: NetworkPreset,
    hosts_cache: RwLock<HashMap<String, HostsCacheEntry>>,
    hosts_cache_ttl_ms: u64,
    hosts_cache_max_entries: usize,
}

impl LookupResolver {
    /// Create a new resolver with configuration.
    pub fn new(config: LookupResolverConfig) -> Self {
        let facilitator = config.facilitator.unwrap_or_else(|| {
            Arc::new(HttpsOverlayLookupFacilitator::new(
                config.network_preset.allow_http(),
            ))
        });

        let slap_trackers = config.slap_trackers.unwrap_or_else(|| {
            config
                .network_preset
                .slap_trackers()
                .iter()
                .map(|s| s.to_string())
                .collect()
        });

        // Validate host override service names
        if let Some(ref overrides) = config.host_overrides {
            for service in overrides.keys() {
                if !service.starts_with("ls_") {
                    panic!(
                        "Host override service names must start with \"ls_\": {}",
                        service
                    );
                }
            }
        }

        Self {
            facilitator,
            slap_trackers,
            host_overrides: config.host_overrides.unwrap_or_default(),
            additional_hosts: config.additional_hosts.unwrap_or_default(),
            reputation_tracker: get_overlay_host_reputation_tracker(),
            network_preset: config.network_preset,
            hosts_cache: RwLock::new(HashMap::new()),
            hosts_cache_ttl_ms: config.hosts_cache_ttl_ms,
            hosts_cache_max_entries: config.hosts_cache_max_entries,
        }
    }

    /// Execute a lookup query.
    ///
    /// Discovers competent hosts and queries them in parallel,
    /// aggregating results.
    ///
    /// # Arguments
    ///
    /// * `question` - The lookup question to execute
    /// * `timeout_ms` - Optional timeout in milliseconds
    ///
    /// # Returns
    ///
    /// The aggregated lookup answer.
    pub async fn query(
        &self,
        question: &LookupQuestion,
        timeout_ms: Option<u64>,
    ) -> Result<LookupAnswer> {
        // Find hosts that can answer this query
        let hosts = self.get_competent_hosts(&question.service).await?;

        if hosts.is_empty() {
            return Err(Error::OverlayError(format!(
                "No competent {} hosts found by the SLAP trackers for lookup service: {}",
                self.network_preset_str(),
                question.service
            )));
        }

        // Rank hosts by reputation, filtering out those in backoff
        let now = now_ms();
        let ranked = self.reputation_tracker.rank_hosts(&hosts);
        let available: Vec<_> = ranked
            .iter()
            .filter(|h| h.entry.backoff_until <= now)
            .map(|h| h.entry.host.clone())
            .collect();

        if available.is_empty() {
            let soonest = ranked
                .iter()
                .map(|h| h.entry.backoff_until)
                .min()
                .unwrap_or(0);
            let wait_ms = soonest.saturating_sub(now);
            return Err(Error::OverlayError(format!(
                "All competent hosts for {} are backing off for approximately {}ms",
                question.service, wait_ms
            )));
        }

        // Query all available hosts in parallel
        let mut all_outputs: Vec<OutputListItem> = Vec::new();
        let mut seen_outputs: HashSet<String> = HashSet::new();
        let mut first_freeform: Option<LookupAnswer> = None;

        let futures: Vec<_> = available
            .iter()
            .map(|host| {
                let host = host.clone();
                let facilitator = self.facilitator.clone();
                let question = question.clone();
                let timeout = timeout_ms;

                async move {
                    let start = Instant::now();
                    let result = facilitator.lookup(&host, &question, timeout).await;
                    let elapsed = start.elapsed().as_millis() as u64;
                    (host, result, elapsed)
                }
            })
            .collect();

        let results = futures::future::join_all(futures).await;

        for (host, result, elapsed) in results {
            match result {
                Ok(answer) => {
                    // Validate the response
                    let is_valid = matches!(&answer, LookupAnswer::OutputList { outputs } if !outputs.is_empty())
                        || matches!(&answer, LookupAnswer::Freeform { .. });

                    if is_valid {
                        self.reputation_tracker.record_success(&host, elapsed);
                    } else {
                        self.reputation_tracker
                            .record_failure(&host, Some("Invalid lookup response"));
                    }

                    match answer {
                        LookupAnswer::OutputList { outputs } => {
                            // Deduplicate by computing a key from BEEF prefix and output_index
                            for output in outputs {
                                let key = self.output_key(&output);
                                if !seen_outputs.contains(&key) {
                                    seen_outputs.insert(key);
                                    all_outputs.push(output);
                                }
                            }
                        }
                        LookupAnswer::Freeform { .. } => {
                            if first_freeform.is_none() {
                                first_freeform = Some(answer);
                            }
                        }
                        LookupAnswer::Formula { .. } => {
                            // Formula responses are not aggregated
                        }
                    }
                }
                Err(e) => {
                    self.reputation_tracker
                        .record_failure(&host, Some(&e.to_string()));
                }
            }
        }

        // Return freeform if we got one, otherwise aggregated output list
        if let Some(freeform) = first_freeform {
            Ok(freeform)
        } else {
            Ok(LookupAnswer::OutputList {
                outputs: all_outputs,
            })
        }
    }

    /// Get competent hosts for a service with caching.
    async fn get_competent_hosts(&self, service: &str) -> Result<Vec<String>> {
        // Check for override
        if let Some(hosts) = self.host_overrides.get(service) {
            return Ok(hosts.clone());
        }

        // Handle local preset
        if self.network_preset == NetworkPreset::Local {
            let mut hosts = vec!["http://localhost:8080".to_string()];
            if let Some(additional) = self.additional_hosts.get(service) {
                hosts.extend(additional.clone());
            }
            return Ok(hosts);
        }

        // Handle ls_slap queries directly against trackers
        if service == "ls_slap" {
            return Ok(self.slap_trackers.clone());
        }

        // Check cache
        let now = now_ms();
        {
            let cache = self.hosts_cache.read().await;
            if let Some(entry) = cache.get(service) {
                if entry.expires_at > now {
                    let mut hosts = entry.hosts.clone();
                    if let Some(additional) = self.additional_hosts.get(service) {
                        for h in additional {
                            if !hosts.contains(h) {
                                hosts.push(h.clone());
                            }
                        }
                    }
                    return Ok(hosts);
                }
            }
        }

        // Discover hosts via SLAP
        let hosts = self.find_competent_hosts(service).await?;

        // Update cache
        {
            let mut cache = self.hosts_cache.write().await;

            // Evict oldest if at capacity
            if !cache.contains_key(service) && cache.len() >= self.hosts_cache_max_entries {
                if let Some(oldest_key) = cache.keys().next().cloned() {
                    cache.remove(&oldest_key);
                }
            }

            cache.insert(
                service.to_string(),
                HostsCacheEntry {
                    hosts: hosts.clone(),
                    expires_at: now + self.hosts_cache_ttl_ms,
                },
            );
        }

        // Add additional hosts
        let mut result = hosts;
        if let Some(additional) = self.additional_hosts.get(service) {
            for h in additional {
                if !result.contains(h) {
                    result.push(h.clone());
                }
            }
        }

        Ok(result)
    }

    /// Find hosts that can answer queries for a service via SLAP.
    async fn find_competent_hosts(&self, service: &str) -> Result<Vec<String>> {
        let question = LookupQuestion::new("ls_slap", serde_json::json!({ "service": service }));

        // Rank trackers and filter out those in backoff
        let now = now_ms();
        let ranked = self.reputation_tracker.rank_hosts(&self.slap_trackers);
        let available: Vec<_> = ranked
            .iter()
            .filter(|h| h.entry.backoff_until <= now)
            .map(|h| h.entry.host.clone())
            .collect();

        if available.is_empty() {
            return Ok(Vec::new());
        }

        let mut hosts: HashSet<String> = HashSet::new();

        // Query all available trackers in parallel
        let futures: Vec<_> = available
            .iter()
            .map(|tracker| {
                let tracker = tracker.clone();
                let facilitator = self.facilitator.clone();
                let question = question.clone();

                async move {
                    let start = Instant::now();
                    let result = facilitator
                        .lookup(&tracker, &question, Some(MAX_TRACKER_WAIT_TIME_MS))
                        .await;
                    let elapsed = start.elapsed().as_millis() as u64;
                    (tracker, result, elapsed)
                }
            })
            .collect();

        let results = futures::future::join_all(futures).await;

        for (tracker, result, elapsed) in results {
            match result {
                Ok(LookupAnswer::OutputList { outputs }) => {
                    self.reputation_tracker.record_success(&tracker, elapsed);

                    for output in outputs {
                        if let Ok(domain) = self.parse_slap_token(&output, service) {
                            hosts.insert(domain);
                        }
                    }
                }
                Ok(_) => {
                    // Non-output-list response from SLAP tracker
                }
                Err(e) => {
                    self.reputation_tracker
                        .record_failure(&tracker, Some(&e.to_string()));
                }
            }
        }

        Ok(hosts.into_iter().collect())
    }

    /// Parse a SLAP token from an output and extract the domain.
    fn parse_slap_token(&self, output: &OutputListItem, expected_service: &str) -> Result<String> {
        // Parse BEEF to get transaction
        let tx = Transaction::from_beef(&output.beef, None)
            .map_err(|e| Error::OverlayError(format!("Failed to parse BEEF: {}", e)))?;

        // Get the output's locking script
        let script = tx
            .outputs
            .get(output.output_index as usize)
            .ok_or_else(|| Error::OverlayError("Output index out of bounds".into()))?
            .locking_script
            .clone();

        // Decode as admin token
        let token = decode_overlay_admin_token(&script)?;

        // Validate protocol and service
        if token.protocol != Protocol::Slap {
            return Err(Error::OverlayError(
                "Token is not a SLAP advertisement".into(),
            ));
        }

        if token.topic_or_service != expected_service {
            return Err(Error::OverlayError(format!(
                "Service mismatch: expected {}, got {}",
                expected_service, token.topic_or_service
            )));
        }

        Ok(token.domain)
    }

    /// Generate a deduplication key for an output.
    fn output_key(&self, output: &OutputListItem) -> String {
        // Use txid from BEEF (first 32 bytes after version) + output index
        // This is a simplified approach; a proper implementation would parse the BEEF
        use std::fmt::Write;
        let beef_prefix = output
            .beef
            .iter()
            .take(40)
            .fold(String::new(), |mut acc, b| {
                let _ = write!(acc, "{:02x}", b);
                acc
            });
        format!("{}:{}", beef_prefix, output.output_index)
    }

    /// Get network preset as string.
    fn network_preset_str(&self) -> &'static str {
        match self.network_preset {
            NetworkPreset::Mainnet => "mainnet",
            NetworkPreset::Testnet => "testnet",
            NetworkPreset::Local => "local",
        }
    }
}

impl Default for LookupResolver {
    fn default() -> Self {
        Self::new(LookupResolverConfig::default())
    }
}

/// Get current time in milliseconds since epoch.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = LookupResolverConfig::default();
        assert_eq!(config.network_preset, NetworkPreset::Mainnet);
        assert!(config.facilitator.is_none());
        assert!(config.slap_trackers.is_none());
    }

    #[test]
    fn test_resolver_creation() {
        let resolver = LookupResolver::default();
        assert!(!resolver.slap_trackers.is_empty());
    }

    #[test]
    fn test_resolver_with_custom_trackers() {
        let config = LookupResolverConfig {
            slap_trackers: Some(vec!["https://custom.tracker".to_string()]),
            ..Default::default()
        };
        let resolver = LookupResolver::new(config);
        assert_eq!(resolver.slap_trackers, vec!["https://custom.tracker"]);
    }

    #[test]
    fn test_resolver_with_host_overrides() {
        let mut overrides = HashMap::new();
        overrides.insert(
            "ls_test".to_string(),
            vec!["https://override.host".to_string()],
        );

        let config = LookupResolverConfig {
            host_overrides: Some(overrides),
            ..Default::default()
        };
        let resolver = LookupResolver::new(config);
        assert!(resolver.host_overrides.contains_key("ls_test"));
    }

    #[test]
    #[should_panic(expected = "Host override service names must start with")]
    fn test_resolver_rejects_invalid_override_service() {
        let mut overrides = HashMap::new();
        overrides.insert(
            "invalid_service".to_string(),
            vec!["https://host".to_string()],
        );

        let config = LookupResolverConfig {
            host_overrides: Some(overrides),
            ..Default::default()
        };
        let _ = LookupResolver::new(config);
    }

    #[test]
    fn test_resolver_local_preset() {
        let config = LookupResolverConfig {
            network_preset: NetworkPreset::Local,
            ..Default::default()
        };
        let resolver = LookupResolver::new(config);
        assert_eq!(resolver.network_preset, NetworkPreset::Local);
    }

    #[test]
    fn test_output_key_generation() {
        let resolver = LookupResolver::default();

        let output1 = OutputListItem {
            beef: vec![1, 2, 3, 4, 5],
            output_index: 0,
            context: None,
        };
        let output2 = OutputListItem {
            beef: vec![1, 2, 3, 4, 5],
            output_index: 1,
            context: None,
        };

        let key1 = resolver.output_key(&output1);
        let key2 = resolver.output_key(&output2);

        // Same BEEF, different output index should have different keys
        assert_ne!(key1, key2);
    }
}
