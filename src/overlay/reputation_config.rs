//! `ReputationConfig`, the host reputation tracker's configuration (moved
//! from `host_reputation_tracker.rs` by #843d8c for that file's line ceiling;
//! re-exported there, so every public path still names it).

/// Configuration for reputation tracking.
///
/// `#[non_exhaustive]` (#843d8c): no struct expression builds one outside the
/// crate, a functional update that names no field included:
///
/// ```compile_fail,E0639
/// fn rebuilt(value: bsv_rs::overlay::ReputationConfig) -> bsv_rs::overlay::ReputationConfig {
///     bsv_rs::overlay::ReputationConfig { ..value }
/// }
/// ```
///
/// ```
/// fn kept(value: bsv_rs::overlay::ReputationConfig) -> bsv_rs::overlay::ReputationConfig {
///     value
/// }
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
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

crate::util::non_exhaustive::assert_no_drop!(ReputationConfig, bsv_rs::overlay::ReputationConfig);

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

impl ReputationConfig {
    /// Sets `latency_smoothing`.
    #[must_use]
    pub fn with_latency_smoothing(mut self, latency_smoothing: f64) -> Self {
        self.latency_smoothing = latency_smoothing;
        self
    }

    /// Sets `grace_failures`.
    #[must_use]
    pub fn with_grace_failures(mut self, grace_failures: u32) -> Self {
        self.grace_failures = grace_failures;
        self
    }

    /// Sets `backoff_base_ms`.
    #[must_use]
    pub fn with_backoff_base_ms(mut self, backoff_base_ms: u64) -> Self {
        self.backoff_base_ms = backoff_base_ms;
        self
    }

    /// Sets `backoff_max_ms`.
    #[must_use]
    pub fn with_backoff_max_ms(mut self, backoff_max_ms: u64) -> Self {
        self.backoff_max_ms = backoff_max_ms;
        self
    }

    /// Sets `default_latency_ms`.
    #[must_use]
    pub fn with_default_latency_ms(mut self, default_latency_ms: f64) -> Self {
        self.default_latency_ms = default_latency_ms;
        self
    }

    /// Sets `failure_penalty_ms`.
    #[must_use]
    pub fn with_failure_penalty_ms(mut self, failure_penalty_ms: f64) -> Self {
        self.failure_penalty_ms = failure_penalty_ms;
        self
    }

    /// Sets `success_bonus_ms`.
    #[must_use]
    pub fn with_success_bonus_ms(mut self, success_bonus_ms: f64) -> Self {
        self.success_bonus_ms = success_bonus_ms;
        self
    }
}
