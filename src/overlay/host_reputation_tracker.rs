//! Host reputation tracking for overlay services.
//!
//! Tracks success/failure rates and latency for overlay hosts,
//! enabling intelligent host selection and automatic backoff.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

/// Reputation entry for a single host.
#[derive(Debug, Clone)]
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
pub struct HostReputationTracker {
    entries: RwLock<HashMap<String, HostReputationEntry>>,
    config: ReputationConfig,
}

impl Default for HostReputationTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl HostReputationTracker {
    /// Create a new tracker with default config.
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            config: ReputationConfig::default(),
        }
    }

    /// Create with custom config.
    pub fn with_config(config: ReputationConfig) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            config,
        }
    }

    /// Record a successful request.
    ///
    /// Updates the latency average, resets failure counters, and
    /// clears any backoff status.
    pub fn record_success(&self, host: &str, latency_ms: u64) {
        let mut entries = self.entries.write().unwrap();
        let entry = entries
            .entry(host.to_string())
            .or_insert_with(|| HostReputationEntry::new(host.to_string()));

        let safe_latency = if latency_ms > 0 {
            latency_ms as f64
        } else {
            self.config.default_latency_ms
        };

        entry.total_successes += 1;
        entry.consecutive_failures = 0;
        entry.backoff_until = 0;
        entry.last_latency_ms = Some(latency_ms);
        entry.last_updated_at = now_ms();
        entry.last_error = None;

        // Update EMA
        entry.avg_latency_ms = Some(match entry.avg_latency_ms {
            Some(avg) => {
                avg * (1.0 - self.config.latency_smoothing)
                    + safe_latency * self.config.latency_smoothing
            }
            None => safe_latency,
        });
    }

    /// Record a failed request.
    ///
    /// Increments failure counters and applies exponential backoff
    /// after the grace period is exceeded.
    pub fn record_failure(&self, host: &str, reason: Option<&str>) {
        let mut entries = self.entries.write().unwrap();
        let entry = entries
            .entry(host.to_string())
            .or_insert_with(|| HostReputationEntry::new(host.to_string()));

        entry.total_failures += 1;
        entry.consecutive_failures += 1;
        entry.last_updated_at = now_ms();
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
            entry.backoff_until = now_ms() + backoff_time;
        } else {
            entry.backoff_until = 0;
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
    pub fn reset(&self) {
        self.entries.write().unwrap().clear();
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
}
