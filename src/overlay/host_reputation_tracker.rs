//! Host reputation tracking for overlay services.
//!
//! Tracks success/failure rates and latency for overlay hosts,
//! enabling intelligent host selection and automatic backoff.
//!
//! ## Persistence
//!
//! The tracker supports optional persistence via the `ReputationStorage` trait.
//! This allows reputation data to survive application restarts.
//!
//! ```rust,ignore
//! use bsv_sdk::overlay::host_reputation_tracker::{HostReputationTracker, ReputationStorage};
//!
//! // Custom storage implementation
//! struct MyStorage { /* ... */ }
//!
//! impl ReputationStorage for MyStorage {
//!     fn get(&self, key: &str) -> Option<String> { /* ... */ }
//!     fn set(&self, key: &str, value: &str) { /* ... */ }
//! }
//!
//! let storage = Box::new(MyStorage { /* ... */ });
//! let tracker = HostReputationTracker::with_storage(storage);
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;

/// Default capacity for the rank change broadcast channel.
const DEFAULT_BROADCAST_CHANNEL_CAPACITY: usize = 64;

/// Event emitted when a host's reputation score changes.
///
/// Subscribers receive this event whenever `record_success()` or `record_failure()`
/// causes a change in a host's computed reputation score.
#[derive(Debug, Clone)]
pub struct RankChangeEvent {
    /// The host whose rank changed.
    pub host: String,
    /// The previous reputation score (lower = better).
    pub old_rank: f64,
    /// The new reputation score (lower = better).
    pub new_rank: f64,
    /// Human-readable reason for the change.
    pub reason: String,
}

/// Storage trait for persisting reputation data.
///
/// Implement this trait to provide custom storage backends for reputation data.
/// The default implementation uses in-memory storage only.
pub trait ReputationStorage: Send + Sync {
    /// Get a value by key.
    fn get(&self, key: &str) -> Option<String>;

    /// Set a value by key.
    fn set(&self, key: &str, value: &str);

    /// Remove a value by key.
    fn remove(&self, key: &str);
}

/// Storage key for reputation data.
const REPUTATION_STORAGE_KEY: &str = "bsv_overlay_host_reputation";

/// Reputation entry for a single host.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostReputationEntry {
    /// Host URL.
    pub host: String,
    /// Total successful requests.
    pub total_successes: u64,
    /// Total failed requests.
    pub total_failures: u64,
    /// Consecutive failures (resets on success).
    pub consecutive_failures: u32,
    /// Exponential moving average latency (ms).
    pub avg_latency_ms: Option<f64>,
    /// Most recent latency (ms).
    pub last_latency_ms: Option<u64>,
    /// Don't use this host until this timestamp (ms since epoch).
    pub backoff_until: u64,
    /// Last update timestamp (ms since epoch).
    pub last_updated_at: u64,
    /// Last error message.
    pub last_error: Option<String>,
}

impl HostReputationEntry {
    fn new(host: String) -> Self {
        Self {
            host,
            total_successes: 0,
            total_failures: 0,
            consecutive_failures: 0,
            avg_latency_ms: None,
            last_latency_ms: None,
            backoff_until: 0,
            last_updated_at: now_ms(),
            last_error: None,
        }
    }
}

/// Ranked host with computed score.
#[derive(Debug, Clone)]
pub struct RankedHost {
    /// The underlying reputation entry.
    pub entry: HostReputationEntry,
    /// Lower score = better host.
    pub score: f64,
}

/// Configuration for reputation tracking.
#[derive(Debug, Clone)]
pub struct ReputationConfig {
    /// Smoothing factor for latency EMA (0.0-1.0).
    pub latency_smoothing: f64,
    /// Number of failures before backoff starts.
    pub grace_failures: u32,
    /// Base backoff time (ms).
    pub backoff_base_ms: u64,
    /// Maximum backoff time (ms).
    pub backoff_max_ms: u64,
    /// Default latency for new hosts (ms).
    pub default_latency_ms: f64,
    /// Penalty per consecutive failure (ms).
    pub failure_penalty_ms: f64,
    /// Bonus per success (ms), capped at half of latency.
    pub success_bonus_ms: f64,
}

impl Default for ReputationConfig {
    fn default() -> Self {
        Self {
            latency_smoothing: 0.25,
            grace_failures: 2,
            backoff_base_ms: 1000,
            backoff_max_ms: 60_000,
            default_latency_ms: 1500.0,
            failure_penalty_ms: 400.0,
            success_bonus_ms: 30.0,
        }
    }
}

/// Tracks reputation of overlay hosts.
///
/// Thread-safe implementation that records success/failure metrics
/// and provides host ranking for optimal selection.
///
/// Supports optional persistence via the `ReputationStorage` trait.
pub struct HostReputationTracker {
    entries: RwLock<HashMap<String, HostReputationEntry>>,
    config: ReputationConfig,
    storage: Option<Box<dyn ReputationStorage>>,
    rank_change_tx: broadcast::Sender<RankChangeEvent>,
}

impl Default for HostReputationTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl HostReputationTracker {
    /// Create a new tracker with default config and no persistence.
    pub fn new() -> Self {
        let (rank_change_tx, _) = broadcast::channel(DEFAULT_BROADCAST_CHANNEL_CAPACITY);
        Self {
            entries: RwLock::new(HashMap::new()),
            config: ReputationConfig::default(),
            storage: None,
            rank_change_tx,
        }
    }

    /// Create with custom config and no persistence.
    pub fn with_config(config: ReputationConfig) -> Self {
        let (rank_change_tx, _) = broadcast::channel(DEFAULT_BROADCAST_CHANNEL_CAPACITY);
        Self {
            entries: RwLock::new(HashMap::new()),
            config,
            storage: None,
            rank_change_tx,
        }
    }

    /// Create with storage backend for persistence.
    ///
    /// On creation, loads existing reputation data from storage if available.
    pub fn with_storage(storage: Box<dyn ReputationStorage>) -> Self {
        let entries = Self::load_from_storage(&*storage);
        let (rank_change_tx, _) = broadcast::channel(DEFAULT_BROADCAST_CHANNEL_CAPACITY);
        Self {
            entries: RwLock::new(entries),
            config: ReputationConfig::default(),
            storage: Some(storage),
            rank_change_tx,
        }
    }

    /// Create with custom config and storage backend.
    ///
    /// On creation, loads existing reputation data from storage if available.
    pub fn with_config_and_storage(
        config: ReputationConfig,
        storage: Box<dyn ReputationStorage>,
    ) -> Self {
        let entries = Self::load_from_storage(&*storage);
        let (rank_change_tx, _) = broadcast::channel(DEFAULT_BROADCAST_CHANNEL_CAPACITY);
        Self {
            entries: RwLock::new(entries),
            config,
            storage: Some(storage),
            rank_change_tx,
        }
    }

    /// Load entries from storage.
    fn load_from_storage(storage: &dyn ReputationStorage) -> HashMap<String, HostReputationEntry> {
        storage
            .get(REPUTATION_STORAGE_KEY)
            .and_then(|json| serde_json::from_str(&json).ok())
            .unwrap_or_default()
    }

    /// Save entries to storage (if storage is configured).
    fn save_to_storage(&self) {
        if let Some(ref storage) = self.storage {
            let entries = self.entries.read().unwrap();
            if let Ok(json) = serde_json::to_string(&*entries) {
                storage.set(REPUTATION_STORAGE_KEY, &json);
            }
        }
    }

    /// Record a successful request.
    ///
    /// Updates the latency average, resets failure counters, and
    /// clears any backoff status. Emits a `RankChangeEvent` if the
    /// host's computed reputation score changes.
    pub fn record_success(&self, host: &str, latency_ms: u64) {
        let now = now_ms();
        let mut entries = self.entries.write().unwrap();
        let entry = entries
            .entry(host.to_string())
            .or_insert_with(|| HostReputationEntry::new(host.to_string()));

        // Compute old score before mutation
        let old_rank = self.compute_score(entry, now);

        let safe_latency = if latency_ms > 0 {
            latency_ms as f64
        } else {
            self.config.default_latency_ms
        };

        entry.total_successes += 1;
        entry.consecutive_failures = 0;
        entry.backoff_until = 0;
        entry.last_latency_ms = Some(latency_ms);
        entry.last_updated_at = now;
        entry.last_error = None;

        // Update EMA
        entry.avg_latency_ms = Some(match entry.avg_latency_ms {
            Some(avg) => {
                avg * (1.0 - self.config.latency_smoothing)
                    + safe_latency * self.config.latency_smoothing
            }
            None => safe_latency,
        });

        // Compute new score after mutation
        let new_rank = self.compute_score(entry, now);
        let host_name = host.to_string();

        drop(entries);
        self.save_to_storage();

        // Emit rank change event (ignore send errors - no receivers is fine)
        if (old_rank - new_rank).abs() > f64::EPSILON {
            let _ = self.rank_change_tx.send(RankChangeEvent {
                host: host_name,
                old_rank,
                new_rank,
                reason: format!("success (latency: {}ms)", latency_ms),
            });
        }
    }

    /// Record a failed request.
    ///
    /// Increments failure counters and applies exponential backoff
    /// after the grace period is exceeded. Emits a `RankChangeEvent`
    /// if the host's computed reputation score changes.
    pub fn record_failure(&self, host: &str, reason: Option<&str>) {
        let now = now_ms();
        let mut entries = self.entries.write().unwrap();
        let entry = entries
            .entry(host.to_string())
            .or_insert_with(|| HostReputationEntry::new(host.to_string()));

        // Compute old score before mutation
        let old_rank = self.compute_score(entry, now);

        entry.total_failures += 1;
        entry.consecutive_failures += 1;
        entry.last_updated_at = now;
        entry.last_error = reason.map(String::from);

        // Check for immediate backoff on certain errors (DNS failures, etc.)
        let immediate_backoff = reason.is_some_and(|r| {
            r.contains("ERR_NAME_NOT_RESOLVED")
                || r.contains("ENOTFOUND")
                || r.contains("getaddrinfo")
                || r.contains("Failed to fetch")
        });

        if immediate_backoff && entry.consecutive_failures < self.config.grace_failures + 1 {
            entry.consecutive_failures = self.config.grace_failures + 1;
        }

        // Apply backoff if past grace period
        let penalty_level = entry
            .consecutive_failures
            .saturating_sub(self.config.grace_failures);

        if penalty_level > 0 {
            let backoff_time = std::cmp::min(
                self.config.backoff_base_ms * (1 << (penalty_level - 1).min(10)),
                self.config.backoff_max_ms,
            );
            entry.backoff_until = now + backoff_time;
        } else {
            entry.backoff_until = 0;
        }

        // Compute new score after mutation
        let new_rank = self.compute_score(entry, now);
        let host_name = host.to_string();
        let reason_str = reason.unwrap_or("unknown").to_string();

        drop(entries);
        self.save_to_storage();

        // Emit rank change event (ignore send errors - no receivers is fine)
        if (old_rank - new_rank).abs() > f64::EPSILON {
            let _ = self.rank_change_tx.send(RankChangeEvent {
                host: host_name,
                old_rank,
                new_rank,
                reason: format!("failure ({})", reason_str),
            });
        }
    }

    /// Rank hosts by reputation.
    ///
    /// Returns hosts sorted by score (lower = better).
    /// Hosts currently in backoff are deprioritized but still included.
    pub fn rank_hosts(&self, hosts: &[String]) -> Vec<RankedHost> {
        self.rank_hosts_at(hosts, now_ms())
    }

    /// Rank hosts by reputation at a specific time.
    ///
    /// Useful for testing or when you need to evaluate at a specific timestamp.
    pub fn rank_hosts_at(&self, hosts: &[String], now: u64) -> Vec<RankedHost> {
        let entries = self.entries.read().unwrap();

        // Deduplicate hosts while preserving order
        let mut seen = std::collections::HashSet::new();
        let unique_hosts: Vec<_> = hosts
            .iter()
            .filter(|h| !h.is_empty() && seen.insert(h.as_str()))
            .cloned()
            .collect();

        let mut ranked: Vec<RankedHost> = unique_hosts
            .into_iter()
            .enumerate()
            .map(|(original_order, host)| {
                let entry = entries
                    .get(&host)
                    .cloned()
                    .unwrap_or_else(|| HostReputationEntry::new(host));

                let score = self.compute_score(&entry, now);
                RankedHost {
                    entry,
                    score: score + (original_order as f64 * 0.001), // Tie-break by original order
                }
            })
            .collect();

        // Sort by: not in backoff, then by score, then by successes
        ranked.sort_by(|a, b| {
            let a_backoff = a.entry.backoff_until > now;
            let b_backoff = b.entry.backoff_until > now;

            if a_backoff != b_backoff {
                return a_backoff.cmp(&b_backoff);
            }

            match a.score.partial_cmp(&b.score) {
                Some(std::cmp::Ordering::Equal) | None => {
                    b.entry.total_successes.cmp(&a.entry.total_successes)
                }
                Some(ord) => ord,
            }
        });

        ranked
    }

    /// Get snapshot of a single host's reputation.
    pub fn snapshot(&self, host: &str) -> Option<HostReputationEntry> {
        self.entries.read().unwrap().get(host).cloned()
    }

    /// Reset all tracking data.
    ///
    /// If storage is configured, clears stored data as well.
    pub fn reset(&self) {
        self.entries.write().unwrap().clear();
        if let Some(ref storage) = self.storage {
            storage.remove(REPUTATION_STORAGE_KEY);
        }
    }

    /// Check if storage is configured.
    pub fn has_storage(&self) -> bool {
        self.storage.is_some()
    }

    /// Force save to storage.
    ///
    /// Normally, the tracker auto-saves after each update. Use this method
    /// if you need to ensure data is persisted immediately.
    pub fn flush(&self) {
        self.save_to_storage();
    }

    /// Subscribe to rank change events.
    ///
    /// Returns a `broadcast::Receiver` that receives `RankChangeEvent` whenever
    /// a host's reputation score changes due to `record_success()` or `record_failure()`.
    ///
    /// Dropping the receiver naturally unsubscribes. If the receiver falls behind,
    /// older messages are dropped (lagged).
    ///
    /// ```rust,ignore
    /// use bsv_sdk::overlay::host_reputation_tracker::{HostReputationTracker, RankChangeEvent};
    ///
    /// let tracker = HostReputationTracker::new();
    /// let mut rx = tracker.subscribe();
    ///
    /// // In an async context:
    /// tokio::spawn(async move {
    ///     while let Ok(event) = rx.recv().await {
    ///         println!("{}: {} -> {} ({})", event.host, event.old_rank, event.new_rank, event.reason);
    ///     }
    /// });
    /// ```
    pub fn subscribe(&self) -> broadcast::Receiver<RankChangeEvent> {
        self.rank_change_tx.subscribe()
    }

    /// Register a callback for rank change events.
    ///
    /// Spawns a tokio task that listens for `RankChangeEvent`s and invokes the
    /// provided callback for each one. The task runs until the tracker is dropped
    /// or the channel closes.
    ///
    /// Returns a `tokio::task::JoinHandle` that can be used to abort the listener.
    ///
    /// ```rust,ignore
    /// use bsv_sdk::overlay::host_reputation_tracker::HostReputationTracker;
    ///
    /// let tracker = HostReputationTracker::new();
    /// let handle = tracker.on_rank_change(|event| {
    ///     println!("Host {} rank changed: {} -> {}", event.host, event.old_rank, event.new_rank);
    /// });
    ///
    /// // To stop listening:
    /// handle.abort();
    /// ```
    pub fn on_rank_change(
        &self,
        callback: impl Fn(RankChangeEvent) + Send + Sync + 'static,
    ) -> tokio::task::JoinHandle<()> {
        let mut rx = self.subscribe();
        tokio::spawn(async move {
            while let Ok(event) = rx.recv().await {
                callback(event);
            }
        })
    }

    /// Export all entries as JSON.
    ///
    /// Useful for debugging or manual persistence.
    pub fn to_json(&self) -> String {
        let entries = self.entries.read().unwrap();
        serde_json::to_string(&*entries).unwrap_or_else(|_| "{}".to_string())
    }

    /// Import entries from JSON.
    ///
    /// Replaces all existing entries with the imported data.
    pub fn from_json(&self, json: &str) -> bool {
        if let Ok(entries) = serde_json::from_str::<HashMap<String, HostReputationEntry>>(json) {
            let mut current = self.entries.write().unwrap();
            *current = entries;
            drop(current);
            self.save_to_storage();
            true
        } else {
            false
        }
    }

    /// Compute reputation score for a host.
    ///
    /// Lower score = better reputation.
    fn compute_score(&self, entry: &HostReputationEntry, now: u64) -> f64 {
        let latency = entry
            .avg_latency_ms
            .unwrap_or(self.config.default_latency_ms);

        let failure_penalty = (entry.consecutive_failures as f64) * self.config.failure_penalty_ms;

        let backoff_penalty = if entry.backoff_until > now {
            ((entry.backoff_until - now) as f64) / 100.0
        } else {
            0.0
        };

        let success_bonus =
            (entry.total_successes as f64 * self.config.success_bonus_ms).min(latency / 2.0);

        latency + failure_penalty + backoff_penalty - success_bonus
    }
}

/// Get current time in milliseconds since epoch.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

// Global singleton
use std::sync::OnceLock;
static GLOBAL_TRACKER: OnceLock<HostReputationTracker> = OnceLock::new();

/// Get the global host reputation tracker.
///
/// This is a singleton instance shared across the entire application.
pub fn get_overlay_host_reputation_tracker() -> &'static HostReputationTracker {
    GLOBAL_TRACKER.get_or_init(HostReputationTracker::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_success() {
        let tracker = HostReputationTracker::new();
        tracker.record_success("host1", 100);
        tracker.record_success("host1", 200);

        let entry = tracker.snapshot("host1").unwrap();
        assert_eq!(entry.total_successes, 2);
        assert_eq!(entry.consecutive_failures, 0);
        assert!(entry.avg_latency_ms.is_some());
    }

    #[test]
    fn test_record_failure() {
        let tracker = HostReputationTracker::new();
        tracker.record_failure("host1", Some("test error"));

        let entry = tracker.snapshot("host1").unwrap();
        assert_eq!(entry.total_failures, 1);
        assert_eq!(entry.consecutive_failures, 1);
        assert_eq!(entry.last_error, Some("test error".to_string()));
    }

    #[test]
    fn test_backoff_after_failures() {
        let tracker = HostReputationTracker::new();

        // Fail enough times to trigger backoff (grace = 2)
        for _ in 0..5 {
            tracker.record_failure("host1", Some("test error"));
        }

        let entry = tracker.snapshot("host1").unwrap();
        assert!(entry.backoff_until > now_ms());
    }

    #[test]
    fn test_success_resets_backoff() {
        let tracker = HostReputationTracker::new();

        // Trigger backoff
        for _ in 0..5 {
            tracker.record_failure("host1", None);
        }

        let entry = tracker.snapshot("host1").unwrap();
        assert!(entry.backoff_until > 0);

        // Success should reset
        tracker.record_success("host1", 100);

        let entry = tracker.snapshot("host1").unwrap();
        assert_eq!(entry.backoff_until, 0);
        assert_eq!(entry.consecutive_failures, 0);
    }

    #[test]
    fn test_rank_hosts() {
        let tracker = HostReputationTracker::new();

        // Good host
        tracker.record_success("good", 50);
        tracker.record_success("good", 60);

        // Bad host
        for _ in 0..5 {
            tracker.record_failure("bad", None);
        }

        // New host (no records)

        let hosts = vec!["good".to_string(), "bad".to_string(), "new".to_string()];
        let ranked = tracker.rank_hosts(&hosts);

        assert_eq!(ranked.len(), 3);
        assert_eq!(ranked[0].entry.host, "good");
    }

    #[test]
    fn test_rank_hosts_deduplicates() {
        let tracker = HostReputationTracker::new();

        let hosts = vec![
            "host1".to_string(),
            "host2".to_string(),
            "host1".to_string(), // Duplicate
        ];
        let ranked = tracker.rank_hosts(&hosts);

        assert_eq!(ranked.len(), 2);
    }

    #[test]
    fn test_rank_hosts_filters_empty() {
        let tracker = HostReputationTracker::new();

        let hosts = vec![
            "host1".to_string(),
            "".to_string(), // Empty
            "host2".to_string(),
        ];
        let ranked = tracker.rank_hosts(&hosts);

        assert_eq!(ranked.len(), 2);
    }

    #[test]
    fn test_latency_ema() {
        let tracker = HostReputationTracker::new();

        tracker.record_success("host1", 100);
        let entry = tracker.snapshot("host1").unwrap();
        assert_eq!(entry.avg_latency_ms, Some(100.0));

        // Second measurement should update EMA
        tracker.record_success("host1", 200);
        let entry = tracker.snapshot("host1").unwrap();

        // EMA = 0.75 * 100 + 0.25 * 200 = 125
        assert!((entry.avg_latency_ms.unwrap() - 125.0).abs() < 0.1);
    }

    #[test]
    fn test_reset() {
        let tracker = HostReputationTracker::new();
        tracker.record_success("host1", 100);

        assert!(tracker.snapshot("host1").is_some());

        tracker.reset();

        assert!(tracker.snapshot("host1").is_none());
    }

    #[test]
    fn test_immediate_backoff_on_dns_error() {
        let tracker = HostReputationTracker::new();

        // DNS error should trigger immediate backoff
        tracker.record_failure("host1", Some("ERR_NAME_NOT_RESOLVED"));

        let entry = tracker.snapshot("host1").unwrap();
        assert!(entry.backoff_until > now_ms());
    }

    #[test]
    fn test_global_tracker() {
        let tracker = get_overlay_host_reputation_tracker();
        tracker.record_success("global_test", 100);

        let same_tracker = get_overlay_host_reputation_tracker();
        let entry = same_tracker.snapshot("global_test");
        assert!(entry.is_some());
    }

    #[test]
    fn test_has_storage() {
        let tracker = HostReputationTracker::new();
        assert!(!tracker.has_storage());
    }

    #[test]
    fn test_to_json() {
        let tracker = HostReputationTracker::new();
        tracker.record_success("host1", 100);

        let json = tracker.to_json();
        assert!(json.contains("host1"));
        assert!(json.contains("totalSuccesses"));
    }

    #[test]
    fn test_from_json_valid() {
        let tracker = HostReputationTracker::new();
        tracker.record_success("original", 50);

        let json = r#"{"imported":{"host":"imported","totalSuccesses":10,"totalFailures":0,"consecutiveFailures":0,"avgLatencyMs":100.0,"lastLatencyMs":100,"backoffUntil":0,"lastUpdatedAt":0,"lastError":null}}"#;
        let result = tracker.from_json(json);

        assert!(result);
        assert!(tracker.snapshot("imported").is_some());
        // Original data should be replaced
        assert!(tracker.snapshot("original").is_none());
    }

    #[test]
    fn test_from_json_invalid() {
        let tracker = HostReputationTracker::new();
        tracker.record_success("original", 50);

        let result = tracker.from_json("invalid json");

        assert!(!result);
        // Original data should be preserved
        assert!(tracker.snapshot("original").is_some());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let tracker = HostReputationTracker::new();
        tracker.record_success("host1", 100);
        tracker.record_success("host1", 150);
        tracker.record_failure("host2", Some("test error"));

        let json = tracker.to_json();

        let tracker2 = HostReputationTracker::new();
        tracker2.from_json(&json);

        let entry1 = tracker2.snapshot("host1").unwrap();
        assert_eq!(entry1.total_successes, 2);

        let entry2 = tracker2.snapshot("host2").unwrap();
        assert_eq!(entry2.total_failures, 1);
        assert_eq!(entry2.last_error, Some("test error".to_string()));
    }

    /// Mock storage for testing persistence
    struct MockStorage {
        data: std::sync::Mutex<HashMap<String, String>>,
    }

    impl MockStorage {
        fn new() -> Self {
            Self {
                data: std::sync::Mutex::new(HashMap::new()),
            }
        }
    }

    impl ReputationStorage for MockStorage {
        fn get(&self, key: &str) -> Option<String> {
            self.data.lock().unwrap().get(key).cloned()
        }

        fn set(&self, key: &str, value: &str) {
            self.data
                .lock()
                .unwrap()
                .insert(key.to_string(), value.to_string());
        }

        fn remove(&self, key: &str) {
            self.data.lock().unwrap().remove(key);
        }
    }

    #[test]
    fn test_storage_persistence() {
        let storage = Box::new(MockStorage::new());
        let tracker = HostReputationTracker::with_storage(storage);

        assert!(tracker.has_storage());

        tracker.record_success("host1", 100);

        // Check that data was saved
        let entry = tracker.snapshot("host1").unwrap();
        assert_eq!(entry.total_successes, 1);
    }

    #[test]
    fn test_storage_load_on_create() {
        // Create storage with pre-existing data
        let storage = MockStorage::new();
        let json = r#"{"preexisting":{"host":"preexisting","totalSuccesses":5,"totalFailures":0,"consecutiveFailures":0,"avgLatencyMs":50.0,"lastLatencyMs":50,"backoffUntil":0,"lastUpdatedAt":0,"lastError":null}}"#;
        storage.set(REPUTATION_STORAGE_KEY, json);

        // Create tracker with storage - should load existing data
        let tracker = HostReputationTracker::with_storage(Box::new(storage));

        let entry = tracker.snapshot("preexisting").unwrap();
        assert_eq!(entry.total_successes, 5);
    }

    #[test]
    fn test_storage_reset_clears_data() {
        let storage = Box::new(MockStorage::new());
        let tracker = HostReputationTracker::with_storage(storage);

        tracker.record_success("host1", 100);
        assert!(tracker.snapshot("host1").is_some());

        tracker.reset();
        assert!(tracker.snapshot("host1").is_none());
    }

    #[tokio::test]
    async fn test_subscribe_receives_rank_change() {
        let tracker = HostReputationTracker::new();
        let mut rx = tracker.subscribe();

        // Record a success which should change the rank from default
        tracker.record_success("host1", 100);

        // We should receive the rank change event
        let event = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .expect("timed out waiting for event")
            .expect("channel closed");

        assert_eq!(event.host, "host1");
        assert!(event.reason.contains("success"));
    }

    #[tokio::test]
    async fn test_multiple_subscribers_reputation() {
        let tracker = HostReputationTracker::new();
        let mut rx1 = tracker.subscribe();
        let mut rx2 = tracker.subscribe();

        // Record a failure which should change the rank
        tracker.record_failure("host1", Some("timeout"));

        let timeout = std::time::Duration::from_secs(1);

        // Both subscribers should receive the same event
        let event1 = tokio::time::timeout(timeout, rx1.recv())
            .await
            .expect("rx1 timed out")
            .expect("rx1 channel closed");

        let event2 = tokio::time::timeout(timeout, rx2.recv())
            .await
            .expect("rx2 timed out")
            .expect("rx2 channel closed");

        assert_eq!(event1.host, event2.host);
        assert_eq!(event1.host, "host1");
        assert!((event1.old_rank - event2.old_rank).abs() < f64::EPSILON);
        assert!((event1.new_rank - event2.new_rank).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_rank_change_event_fields() {
        let tracker = HostReputationTracker::new();
        let mut rx = tracker.subscribe();

        // First record a success to establish a baseline
        tracker.record_success("host1", 100);
        let event1 = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .expect("timed out")
            .expect("channel closed");

        assert_eq!(event1.host, "host1");
        // For a brand new host, old_rank is the default latency score (1500ms)
        // and new_rank should be based on the recorded latency (100ms) minus success bonus
        assert!(event1.old_rank > event1.new_rank, "success should improve rank");
        assert!(event1.reason.contains("success"));
        assert!(event1.reason.contains("100ms"));

        // Now record a failure and check fields
        tracker.record_failure("host1", Some("connection refused"));
        let event2 = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .expect("timed out")
            .expect("channel closed");

        assert_eq!(event2.host, "host1");
        assert!(event2.new_rank > event2.old_rank, "failure should worsen rank");
        assert!(event2.reason.contains("failure"));
        assert!(event2.reason.contains("connection refused"));
    }

    #[tokio::test]
    async fn test_unsubscribe_reputation() {
        let tracker = HostReputationTracker::new();

        // Subscribe and then immediately drop the receiver
        let rx = tracker.subscribe();
        drop(rx);

        // Recording should still work fine without panicking
        tracker.record_success("host1", 100);
        tracker.record_failure("host2", Some("error"));

        // Verify data is still recorded
        let entry1 = tracker.snapshot("host1").unwrap();
        assert_eq!(entry1.total_successes, 1);
        let entry2 = tracker.snapshot("host2").unwrap();
        assert_eq!(entry2.total_failures, 1);

        // Subscribe again after drop - should only get new events
        let mut rx2 = tracker.subscribe();
        tracker.record_success("host3", 50);

        let event = tokio::time::timeout(std::time::Duration::from_secs(1), rx2.recv())
            .await
            .expect("timed out")
            .expect("channel closed");

        assert_eq!(event.host, "host3");
    }
}
