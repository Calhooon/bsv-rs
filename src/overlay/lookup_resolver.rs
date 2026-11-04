//! SLAP lookup resolver.
//!
//! Resolves lookup queries by discovering competent hosts via SLAP trackers
//! and querying them in parallel with aggregation.

use crate::overlay::{
    facilitators::{HttpsOverlayLookupFacilitator, OverlayLookupFacilitator},
    host_reputation_tracker::{get_overlay_host_reputation_tracker, HostReputationTracker},
    overlay_admin_token_template::decode_and_verify_overlay_admin_token,
    types::{
        LookupAnswer, LookupQuestion, NetworkPreset, OutputListItem, Protocol,
        DEFAULT_HOSTS_CACHE_MAX_ENTRIES, DEFAULT_HOSTS_CACHE_TTL_MS, DEFAULT_TX_MEMO_MAX_ENTRIES,
        DEFAULT_TX_MEMO_TTL_MS, MAX_TRACKER_WAIT_TIME_MS,
    },
};
use crate::transaction::Transaction;
use crate::{Error, Result};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{watch, RwLock};

mod backoff; // the trackers' backoff and the cache's reuse rule (#769)
mod query; // `query` and the ordered lookup (#394)

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
    /// TTL for TX memoization cache in milliseconds (default 10 minutes).
    pub tx_memo_ttl_ms: u64,
    /// Maximum entries in TX memoization cache (default 4096).
    pub tx_memo_max_entries: usize,
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
            tx_memo_ttl_ms: DEFAULT_TX_MEMO_TTL_MS,
            tx_memo_max_entries: DEFAULT_TX_MEMO_MAX_ENTRIES,
        }
    }
}

/// Cache entry for host discovery.
struct HostsCacheEntry {
    hosts: Vec<String>,
    expires_at: u64,
}

/// Cache entry for TX memoization.
/// Stores parsed transaction ID to avoid re-parsing the same BEEF.
struct TxMemoEntry {
    tx_id: String,
    expires_at: u64,
}

/// Result type for in-flight host discovery requests.
/// Carries the `Error` itself (`Clone`), so a waiter's refusal is the
/// leader's (#769).
type InFlightResult = Option<Result<Vec<String>>>;

/// Resolver for SLAP lookup queries.
///
/// Discovers competent hosts via SLAP trackers, caches the results,
/// and queries them in parallel with response aggregation.
///
/// Also provides TX memoization to cache parsed transaction IDs,
/// avoiding repeated BEEF parsing for duplicate outputs.
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
    /// TX memoization cache: BEEF key -> (txId, expiration).
    tx_memo: RwLock<HashMap<String, TxMemoEntry>>,
    tx_memo_ttl_ms: u64,
    tx_memo_max_entries: usize,
    /// In-flight host discovery requests for request coalescing.
    /// Maps service name to watch sender for the result.
    hosts_in_flight: RwLock<HashMap<String, watch::Sender<InFlightResult>>>,
}

impl LookupResolver {
    /// Create a new resolver with configuration.
    ///
    /// # Panics
    ///
    /// Panics if a host override's service name does not start with `ls_`.
    #[allow(clippy::panic)] // #134: a bad override name is the caller's bug, as the TypeScript throws; a Result here is a breaking change
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
            tx_memo: RwLock::new(HashMap::new()),
            tx_memo_ttl_ms: config.tx_memo_ttl_ms,
            tx_memo_max_entries: config.tx_memo_max_entries,
            hosts_in_flight: RwLock::new(HashMap::new()),
        }
    }

    /// Get competent hosts for a service with caching and request coalescing.
    ///
    /// Request coalescing ensures that concurrent requests for the same service
    /// share a single SLAP tracker query, reducing network overhead. A cached
    /// list is reused only while some host in it is not backing off, so an
    /// empty one never is (`ts-stack@edf6e03` `LookupResolver.ts:1898-1918`,
    /// #769); a discovery's refusal is not cached, and with additional hosts
    /// configured for the service it is an empty discovery they stand beside
    /// (cached as an empty entry, which is never reused).
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

        // Check cache first
        let now = now_ms();
        {
            let cache = self.hosts_cache.read().await;
            if let Some(entry) = cache.get(service) {
                if entry.expires_at > now && self.has_available_host(&entry.hosts, now) {
                    return Ok(self.add_additional_hosts(service, entry.hosts.clone()));
                }
            }
        }

        // Check for in-flight request (request coalescing)
        let maybe_receiver = {
            let in_flight = self.hosts_in_flight.read().await;
            in_flight.get(service).map(|tx| tx.subscribe())
        };

        if let Some(mut receiver) = maybe_receiver {
            // Wait for the in-flight request to complete
            loop {
                let result = receiver.borrow_and_update().clone();
                if let Some(res) = result {
                    return match res {
                        Ok(hosts) => Ok(self.add_additional_hosts(service, hosts)),
                        Err(e) => Err(e),
                    };
                }
                // Wait for next update
                if receiver.changed().await.is_err() {
                    // Sender dropped without result - fall through to make our own request
                    break;
                }
            }
        }

        // No cache, no in-flight request - start a new one with coalescing
        let (tx, _rx) = watch::channel(None);

        // Register the in-flight request
        {
            let mut in_flight = self.hosts_in_flight.write().await;
            // Double-check another request didn't start while we were waiting
            if let Some(existing_tx) = in_flight.get(service) {
                let mut receiver = existing_tx.subscribe();
                drop(in_flight); // Release lock before waiting

                // Wait for the existing request
                loop {
                    let result = receiver.borrow_and_update().clone();
                    if let Some(res) = result {
                        return match res {
                            Ok(hosts) => Ok(self.add_additional_hosts(service, hosts)),
                            Err(e) => Err(e),
                        };
                    }
                    if receiver.changed().await.is_err() {
                        break;
                    }
                }
                // Fall through if sender dropped
            } else {
                in_flight.insert(service.to_string(), tx.clone());
            }
        }

        // Discover hosts via SLAP, the additional hosts admitted beside a refusal
        let result =
            self.beside_additional_hosts(service, self.find_competent_hosts(service).await);

        // Broadcast result to any waiters and clean up
        {
            let mut in_flight = self.hosts_in_flight.write().await;
            in_flight.remove(service);
        }

        // Broadcast the result itself, so a waiter's error is the leader's (#769)
        let _ = tx.send(Some(result.clone()));

        // Process result
        let hosts = result?;

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

        Ok(self.add_additional_hosts(service, hosts))
    }

    /// Add additional hosts to a host list, avoiding duplicates.
    fn add_additional_hosts(&self, service: &str, mut hosts: Vec<String>) -> Vec<String> {
        if let Some(additional) = self.additional_hosts.get(service) {
            for h in additional {
                if !hosts.contains(h) {
                    hosts.push(h.clone());
                }
            }
        }
        hosts
    }

    /// Find hosts that can answer queries for a given lookup service via SLAP.
    ///
    /// Queries all available SLAP trackers in parallel to discover hosts that
    /// advertise the specified service. Each tracker response is parsed as a
    /// SLAP admin token to extract the host domain. Each tracker is accounted
    /// as a host is (#760, #762): an output list a success, a freeform answer
    /// nothing, an error or a formula answer a failure. A tracker backing off
    /// is not asked; with every tracker backing off the discovery refuses in
    /// the reference's words, `All SLAP trackers hosts are backing off for
    /// approximately <N>ms due to repeated failures.`, N the soonest end of a
    /// backoff (`LookupResolver.ts:2306-2314`, #769).
    ///
    /// This is the low-level discovery method. It does **not** use the hosts
    /// cache or request coalescing (those are handled by `get_competent_hosts`,
    /// which is called internally by `query`).
    ///
    /// # Arguments
    ///
    /// * `service` - The lookup service name (e.g. `"ls_myservice"`)
    ///
    /// # Returns
    ///
    /// A list of host URLs that advertise the given service, empty when the
    /// trackers asked named none (or no tracker is configured).
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let resolver = LookupResolver::default();
    /// let hosts = resolver.find_competent_hosts("ls_myservice").await?;
    /// for host in &hosts {
    ///     println!("Found host: {}", host);
    /// }
    /// ```
    pub async fn find_competent_hosts(&self, service: &str) -> Result<Vec<String>> {
        let question = LookupQuestion::new("ls_slap", serde_json::json!({ "service": service }));

        // The trackers not backing off; every one backing off refuses (#769)
        let available = self.available_slap_trackers()?;
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
                // A tracker's question is the reference's tracked call too
                // (`ts-stack@edf6e03` `LookupResolver.ts:1974`, #762): a
                // freeform answer neutral, a formula one a failure (`:2399-2405`).
                Ok(LookupAnswer::Freeform { .. }) => {}
                Ok(LookupAnswer::Formula { .. }) => self
                    .reputation_tracker
                    .record_failure(&tracker, Some("Invalid lookup response")),
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

        // Decode and authenticate as the reference's resolver does
        // (`LookupResolver.ts:2206`, #544)
        let token = decode_and_verify_overlay_admin_token(&script, Some(Protocol::Slap))?;

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

    /// Generate a cache key from BEEF bytes.
    ///
    /// Uses a fast, deterministic approach by joining byte values with commas.
    /// This matches the TypeScript SDK's memoization strategy.
    fn beef_key(beef: &[u8]) -> String {
        beef.iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Get transaction ID from BEEF, using memoization cache.
    ///
    /// Returns cached txId if available and not expired, otherwise parses
    /// the BEEF and caches the result.
    async fn get_or_cache_tx_id(&self, beef: &[u8]) -> Option<String> {
        let key = Self::beef_key(beef);
        let now = now_ms();

        // Check cache first
        {
            let cache = self.tx_memo.read().await;
            if let Some(entry) = cache.get(&key) {
                if entry.expires_at > now {
                    return Some(entry.tx_id.clone());
                }
            }
        }

        // Parse BEEF and cache the result
        let tx = Transaction::from_beef(beef, None).ok()?;
        let tx_id = tx.id();

        // Update cache
        {
            let mut cache = self.tx_memo.write().await;

            // Evict oldest if at capacity
            if cache.len() >= self.tx_memo_max_entries {
                if let Some(oldest_key) = cache.keys().next().cloned() {
                    cache.remove(&oldest_key);
                }
            }

            cache.insert(
                key,
                TxMemoEntry {
                    tx_id: tx_id.clone(),
                    expires_at: now + self.tx_memo_ttl_ms,
                },
            );
        }

        Some(tx_id)
    }

    /// Clear expired entries from the TX memoization cache.
    ///
    /// Returns the number of entries removed.
    pub async fn prune_tx_memo_cache(&self) -> usize {
        let now = now_ms();
        let mut cache = self.tx_memo.write().await;
        let before = cache.len();
        cache.retain(|_, entry| entry.expires_at > now);
        before - cache.len()
    }

    /// Get the current size of the TX memoization cache.
    pub async fn tx_memo_cache_size(&self) -> usize {
        self.tx_memo.read().await.len()
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
    crate::util::time::current_time_ms()
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
    fn test_beef_key_generation() {
        let beef1 = vec![1, 2, 3, 4, 5];
        let beef2 = vec![1, 2, 3, 4, 6];
        let beef3 = vec![1, 2, 3, 4, 5];

        let key1 = LookupResolver::beef_key(&beef1);
        let key2 = LookupResolver::beef_key(&beef2);
        let key3 = LookupResolver::beef_key(&beef3);

        // Different BEEF should produce different keys
        assert_ne!(key1, key2);
        // Same BEEF should produce same key
        assert_eq!(key1, key3);

        // Key format should be comma-separated
        assert_eq!(key1, "1,2,3,4,5");
    }

    #[test]
    fn test_config_tx_memo_defaults() {
        let config = LookupResolverConfig::default();
        assert_eq!(config.tx_memo_ttl_ms, DEFAULT_TX_MEMO_TTL_MS);
        assert_eq!(config.tx_memo_max_entries, DEFAULT_TX_MEMO_MAX_ENTRIES);
    }

    #[test]
    fn test_resolver_tx_memo_config() {
        let config = LookupResolverConfig {
            tx_memo_ttl_ms: 5000,
            tx_memo_max_entries: 100,
            ..Default::default()
        };
        let resolver = LookupResolver::new(config);
        assert_eq!(resolver.tx_memo_ttl_ms, 5000);
        assert_eq!(resolver.tx_memo_max_entries, 100);
    }

    #[tokio::test]
    async fn test_tx_memo_cache_size() {
        let resolver = LookupResolver::default();
        // Initially empty
        assert_eq!(resolver.tx_memo_cache_size().await, 0);
    }

    #[tokio::test]
    async fn test_prune_tx_memo_cache_empty() {
        let resolver = LookupResolver::default();
        // Pruning an empty cache should remove 0 entries
        let pruned = resolver.prune_tx_memo_cache().await;
        assert_eq!(pruned, 0);
    }

    #[test]
    fn test_add_additional_hosts() {
        let mut additional = HashMap::new();
        additional.insert(
            "ls_test".to_string(),
            vec![
                "https://extra1.com".to_string(),
                "https://extra2.com".to_string(),
            ],
        );

        let config = LookupResolverConfig {
            additional_hosts: Some(additional),
            ..Default::default()
        };
        let resolver = LookupResolver::new(config);

        // Should add hosts that aren't already present
        let hosts = vec!["https://original.com".to_string()];
        let result = resolver.add_additional_hosts("ls_test", hosts);
        assert_eq!(result.len(), 3);
        assert!(result.contains(&"https://original.com".to_string()));
        assert!(result.contains(&"https://extra1.com".to_string()));
        assert!(result.contains(&"https://extra2.com".to_string()));

        // Should not duplicate existing hosts
        let hosts = vec![
            "https://original.com".to_string(),
            "https://extra1.com".to_string(),
        ];
        let result = resolver.add_additional_hosts("ls_test", hosts);
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_add_additional_hosts_no_extras() {
        let resolver = LookupResolver::default();
        let hosts = vec!["https://original.com".to_string()];
        let result = resolver.add_additional_hosts("ls_unknown", hosts.clone());
        assert_eq!(result, hosts);
    }

    #[tokio::test]
    async fn test_hosts_in_flight_initially_empty() {
        let resolver = LookupResolver::default();
        let in_flight = resolver.hosts_in_flight.read().await;
        assert!(in_flight.is_empty());
    }
}
