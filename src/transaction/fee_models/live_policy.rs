//! Live Policy Fee Model
//!
//! This module provides the [`LivePolicy`] fee model that fetches the current
//! fee rate from an ARC (Avalanche Relay Client) service's policy endpoint.
//!
//! The fee rate is cached to avoid excessive API calls, with a configurable TTL.
//!
//! # Example
//!
//! ```rust,ignore
//! use bsv_rs::transaction::{LivePolicy, FeeModel, Transaction};
//!
//! #[tokio::main]
//! async fn main() {
//!     // Use default GorillaPool ARC endpoint
//!     let fee_model = LivePolicy::default();
//!
//!     // Refresh the cached fee rate (fetches from API)
//!     fee_model.refresh().await?;
//!
//!     // Compute fee using the live rate
//!     let tx = Transaction::new();
//!     let fee = fee_model.compute_fee(&tx)?;
//! }
//! ```
//!
//! # Reference
//!
//! - [ARC Policy Endpoint](https://arc.gorillapool.io/v1/policy)

use std::sync::RwLock;
use std::time::{Duration, Instant};

use crate::transaction::fee_model::FeeModel;
use crate::transaction::fee_models::SatoshisPerKilobyte;
use crate::transaction::transaction::Transaction;
use crate::Result;

/// Default ARC policy endpoint URL.
pub const DEFAULT_POLICY_URL: &str = "https://arc.gorillapool.io/v1/policy";

/// Default cache TTL (5 minutes).
pub const DEFAULT_CACHE_TTL_SECS: u64 = 300;

/// Default fallback fee rate (100 sat/KB) if API is unavailable.
pub const DEFAULT_FALLBACK_RATE: u64 = 100;

/// Live policy fee model configuration.
#[derive(Debug, Clone)]
pub struct LivePolicyConfig {
    /// URL for the ARC policy endpoint
    pub policy_url: String,
    /// API key for authentication (optional)
    pub api_key: Option<String>,
    /// Cache time-to-live
    pub cache_ttl: Duration,
    /// Fallback fee rate (sat/KB) if API is unavailable
    pub fallback_rate: u64,
    /// Request timeout in milliseconds
    pub timeout_ms: u64,
}

impl Default for LivePolicyConfig {
    fn default() -> Self {
        Self {
            policy_url: DEFAULT_POLICY_URL.to_string(),
            api_key: None,
            cache_ttl: Duration::from_secs(DEFAULT_CACHE_TTL_SECS),
            fallback_rate: DEFAULT_FALLBACK_RATE,
            timeout_ms: 10_000,
        }
    }
}

/// Cached fee rate with timestamp.
struct CachedRate {
    rate: u64,
    fetched_at: Instant,
}

/// Live policy fee model.
///
/// Fetches the current fee rate from an ARC policy endpoint and caches it
/// for a configurable duration. Falls back to a default rate if the API
/// is unavailable.
///
/// # Example
///
/// ```rust,ignore
/// use bsv_rs::transaction::{LivePolicy, FeeModel};
///
/// let fee_model = LivePolicy::default();
///
/// // Refresh the cached rate
/// fee_model.refresh().await?;
///
/// // Use the cached rate for fee calculation
/// let fee = fee_model.compute_fee(&tx)?;
/// ```
pub struct LivePolicy {
    config: LivePolicyConfig,
    cached_rate: RwLock<Option<CachedRate>>,
    #[cfg(feature = "http")]
    client: reqwest::Client,
}

impl Default for LivePolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl LivePolicy {
    /// Create a new live policy fee model with default configuration.
    pub fn new() -> Self {
        Self::with_config(LivePolicyConfig::default())
    }

    /// Create a live policy fee model with a custom policy URL.
    ///
    /// # Arguments
    ///
    /// * `policy_url` - The URL for the ARC policy endpoint
    pub fn with_url(policy_url: &str) -> Self {
        Self::with_config(LivePolicyConfig {
            policy_url: policy_url.to_string(),
            ..Default::default()
        })
    }

    /// Create a live policy fee model with full configuration.
    pub fn with_config(config: LivePolicyConfig) -> Self {
        Self {
            config,
            cached_rate: RwLock::new(None),
            #[cfg(feature = "http")]
            client: reqwest::Client::new(),
        }
    }

    /// Get the configured policy URL.
    pub fn policy_url(&self) -> &str {
        &self.config.policy_url
    }

    /// Get the configured cache TTL.
    pub fn cache_ttl(&self) -> Duration {
        self.config.cache_ttl
    }

    /// Get the current cached rate, if any and not expired.
    pub fn cached_rate(&self) -> Option<u64> {
        let cache = self.cached_rate.read().ok()?;
        let cached = cache.as_ref()?;
        if cached.fetched_at.elapsed() < self.config.cache_ttl {
            Some(cached.rate)
        } else {
            None
        }
    }

    /// Get the effective fee rate (cached or fallback).
    pub fn effective_rate(&self) -> u64 {
        self.cached_rate().unwrap_or(self.config.fallback_rate)
    }

    /// Manually set the cached rate (useful for testing or offline use).
    pub fn set_rate(&self, rate: u64) {
        if let Ok(mut cache) = self.cached_rate.write() {
            *cache = Some(CachedRate {
                rate,
                fetched_at: Instant::now(),
            });
        }
    }

    /// Refresh the cached fee rate from the policy endpoint.
    ///
    /// This method fetches the current fee rate from the configured ARC
    /// policy endpoint and updates the cache.
    ///
    /// # Returns
    ///
    /// The fetched fee rate in satoshis per kilobyte, or an error if the
    /// request fails.
    #[cfg(feature = "http")]
    pub async fn refresh(&self) -> Result<u64> {
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct Policy {
            #[serde(rename = "miningFee")]
            mining_fee: Option<MiningFee>,
            policy: Option<InnerPolicy>,
        }

        #[derive(Deserialize)]
        struct InnerPolicy {
            #[serde(rename = "miningFee")]
            mining_fee: Option<MiningFee>,
        }

        #[derive(Deserialize)]
        struct MiningFee {
            satoshis: Option<u64>,
            bytes: Option<u64>,
        }

        let mut request = self.client.get(&self.config.policy_url);

        if let Some(ref api_key) = self.config.api_key {
            request = request.header("Authorization", format!("Bearer {}", api_key));
        }

        let response = request
            .timeout(Duration::from_millis(self.config.timeout_ms))
            .send()
            .await
            .map_err(|e| crate::Error::FeeModelError(format!("Policy fetch failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(crate::Error::FeeModelError(format!(
                "Policy endpoint returned HTTP {}",
                response.status()
            )));
        }

        let policy: Policy = response
            .json()
            .await
            .map_err(|e| crate::Error::FeeModelError(format!("Failed to parse policy: {}", e)))?;

        // Try to extract the fee rate from various possible locations
        let mining_fee = policy
            .mining_fee
            .or_else(|| policy.policy.and_then(|p| p.mining_fee))
            .ok_or_else(|| {
                crate::Error::FeeModelError("No mining fee found in policy response".to_string())
            })?;

        // Convert satoshis/bytes to satoshis/kilobyte
        let satoshis = mining_fee.satoshis.unwrap_or(1);
        let bytes = mining_fee.bytes.unwrap_or(1);
        let rate_per_kb = (satoshis * 1000) / bytes;

        // Update the cache
        if let Ok(mut cache) = self.cached_rate.write() {
            *cache = Some(CachedRate {
                rate: rate_per_kb,
                fetched_at: Instant::now(),
            });
        }

        Ok(rate_per_kb)
    }

    /// Refresh the cached fee rate (no-op without HTTP feature).
    #[cfg(not(feature = "http"))]
    pub async fn refresh(&self) -> Result<u64> {
        Err(crate::Error::FeeModelError(
            "HTTP feature not enabled. Add 'http' feature to Cargo.toml".to_string(),
        ))
    }
}

impl FeeModel for LivePolicy {
    /// Computes the fee for a given transaction using the cached or fallback rate.
    ///
    /// This method uses the currently cached fee rate if available and not expired,
    /// otherwise it falls back to the configured fallback rate (default: 100 sat/KB).
    ///
    /// To ensure you're using an up-to-date rate, call `refresh()` before
    /// computing fees.
    ///
    /// # Arguments
    ///
    /// * `tx` - The transaction for which a fee is to be computed
    ///
    /// # Returns
    ///
    /// The fee in satoshis for the transaction.
    fn compute_fee(&self, tx: &Transaction) -> Result<u64> {
        let rate = self.effective_rate();
        SatoshisPerKilobyte::new(rate).compute_fee(tx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = LivePolicyConfig::default();
        assert_eq!(config.policy_url, DEFAULT_POLICY_URL);
        assert!(config.api_key.is_none());
        assert_eq!(
            config.cache_ttl,
            Duration::from_secs(DEFAULT_CACHE_TTL_SECS)
        );
        assert_eq!(config.fallback_rate, DEFAULT_FALLBACK_RATE);
    }

    #[test]
    fn test_new() {
        let fee_model = LivePolicy::new();
        assert_eq!(fee_model.policy_url(), DEFAULT_POLICY_URL);
        assert_eq!(
            fee_model.cache_ttl(),
            Duration::from_secs(DEFAULT_CACHE_TTL_SECS)
        );
    }

    #[test]
    fn test_with_url() {
        let fee_model = LivePolicy::with_url("https://custom.arc.com/v1/policy");
        assert_eq!(fee_model.policy_url(), "https://custom.arc.com/v1/policy");
    }

    #[test]
    fn test_fallback_rate() {
        let fee_model = LivePolicy::new();
        // Without any cached rate, should use fallback
        assert_eq!(fee_model.effective_rate(), DEFAULT_FALLBACK_RATE);
    }

    #[test]
    fn test_set_rate() {
        let fee_model = LivePolicy::new();
        fee_model.set_rate(200);
        assert_eq!(fee_model.cached_rate(), Some(200));
        assert_eq!(fee_model.effective_rate(), 200);
    }

    #[test]
    fn test_compute_fee_with_fallback() {
        let fee_model = LivePolicy::new();
        let tx = Transaction::new();
        // Empty transaction: 10 bytes * 100 sat/KB / 1000 = 1 sat (ceiling)
        let fee = fee_model.compute_fee(&tx).unwrap();
        assert_eq!(fee, 1);
    }

    #[test]
    fn test_compute_fee_with_cached_rate() {
        let fee_model = LivePolicy::new();
        fee_model.set_rate(1000); // 1 sat/byte
        let tx = Transaction::new();
        // Empty transaction: 10 bytes * 1000 sat/KB / 1000 = 10 sats
        let fee = fee_model.compute_fee(&tx).unwrap();
        assert_eq!(fee, 10);
    }

    #[test]
    fn test_with_config() {
        let config = LivePolicyConfig {
            policy_url: "https://test.arc.com/policy".to_string(),
            api_key: Some("test-key".to_string()),
            cache_ttl: Duration::from_secs(60),
            fallback_rate: 50,
            timeout_ms: 5_000,
        };
        let fee_model = LivePolicy::with_config(config);
        assert_eq!(fee_model.policy_url(), "https://test.arc.com/policy");
        assert_eq!(fee_model.cache_ttl(), Duration::from_secs(60));
        assert_eq!(fee_model.effective_rate(), 50); // Using fallback since no cache
    }
}
