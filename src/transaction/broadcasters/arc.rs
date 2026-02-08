//! ARC (Avalanche Relay Client) Broadcaster
//!
//! Implements the [`Broadcaster`] trait for the ARC network.
//!
//! ARC is TAAL's transaction processing service that provides reliable
//! transaction broadcasting with callback notifications.
//!
//! # Example
//!
//! ```rust,ignore
//! use bsv_sdk::transaction::{ArcBroadcaster, Broadcaster, Transaction};
//!
//! #[tokio::main]
//! async fn main() {
//!     let broadcaster = ArcBroadcaster::new("https://arc.taal.com", None);
//!     let tx = Transaction::from_hex("...").unwrap();
//!
//!     match broadcaster.broadcast(&tx).await {
//!         Ok(response) => println!("Broadcast success: {}", response.txid),
//!         Err(failure) => println!("Broadcast failed: {}", failure.description),
//!     }
//! }
//! ```
//!
//! # Reference
//!
//! - [ARC Documentation](https://github.com/bitcoin-sv/arc)

use async_trait::async_trait;

#[cfg(feature = "http")]
use crate::transaction::BroadcastResponse;
use crate::transaction::{
    BroadcastFailure, BroadcastResult, BroadcastStatus, Broadcaster, Transaction,
};

/// ARC broadcaster configuration.
#[derive(Debug, Clone)]
pub struct ArcConfig {
    /// ARC API URL (e.g., `https://arc.taal.com`)
    pub url: String,
    /// API key for authentication (optional)
    pub api_key: Option<String>,
    /// Request timeout in milliseconds
    pub timeout_ms: u64,
}

impl Default for ArcConfig {
    fn default() -> Self {
        Self {
            url: "https://arc.taal.com".to_string(),
            api_key: None,
            timeout_ms: 30_000,
        }
    }
}

/// ARC broadcaster implementation.
///
/// Broadcasts transactions to the BSV network via TAAL's ARC service.
///
/// # Example
///
/// ```rust,ignore
/// use bsv_sdk::transaction::{ArcBroadcaster, Broadcaster};
///
/// // Create with default URL
/// let broadcaster = ArcBroadcaster::default();
///
/// // Or with custom configuration
/// let broadcaster = ArcBroadcaster::new(
///     "https://arc.taal.com",
///     Some("your-api-key".to_string())
/// );
/// ```
pub struct ArcBroadcaster {
    config: ArcConfig,
    #[cfg(feature = "http")]
    client: reqwest::Client,
}

impl Default for ArcBroadcaster {
    fn default() -> Self {
        Self::new("https://arc.taal.com", None)
    }
}

impl ArcBroadcaster {
    /// Create a new ARC broadcaster.
    ///
    /// # Arguments
    ///
    /// * `url` - The ARC API URL
    /// * `api_key` - Optional API key for authentication
    pub fn new(url: &str, api_key: Option<String>) -> Self {
        Self {
            config: ArcConfig {
                url: url.to_string(),
                api_key,
                ..Default::default()
            },
            #[cfg(feature = "http")]
            client: reqwest::Client::new(),
        }
    }

    /// Create with full configuration.
    pub fn with_config(config: ArcConfig) -> Self {
        Self {
            config,
            #[cfg(feature = "http")]
            client: reqwest::Client::new(),
        }
    }

    /// Get the configured URL.
    pub fn url(&self) -> &str {
        &self.config.url
    }

    /// Get the configured API key.
    pub fn api_key(&self) -> Option<&str> {
        self.config.api_key.as_deref()
    }
}

#[async_trait(?Send)]
impl Broadcaster for ArcBroadcaster {
    #[cfg(feature = "http")]
    async fn broadcast(&self, tx: &Transaction) -> BroadcastResult {
        use serde::{Deserialize, Serialize};

        #[derive(Serialize)]
        struct ArcRequest {
            #[serde(rename = "rawTx")]
            raw_tx: String,
        }

        #[derive(Deserialize)]
        struct ArcResponse {
            txid: Option<String>,
            #[serde(rename = "txStatus")]
            tx_status: Option<String>,
            #[serde(rename = "extraInfo")]
            extra_info: Option<String>,
            status: Option<u16>,
            title: Option<String>,
            detail: Option<String>,
        }

        let url = format!("{}/v1/tx", self.config.url);
        let raw_tx = tx.to_hex();
        let txid = tx.id();

        let mut request = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&ArcRequest { raw_tx });

        if let Some(ref api_key) = self.config.api_key {
            request = request.header("Authorization", format!("Bearer {}", api_key));
        }

        let response = request
            .timeout(std::time::Duration::from_millis(self.config.timeout_ms))
            .send()
            .await
            .map_err(|e| BroadcastFailure {
                status: BroadcastStatus::Error,
                code: "NETWORK_ERROR".to_string(),
                txid: Some(txid.clone()),
                description: format!("Network error: {}", e),
                more: None,
            })?;

        let status_code = response.status();
        let body: ArcResponse = response.json().await.map_err(|e| BroadcastFailure {
            status: BroadcastStatus::Error,
            code: "PARSE_ERROR".to_string(),
            txid: Some(txid.clone()),
            description: format!("Failed to parse response: {}", e),
            more: None,
        })?;

        if status_code.is_success() {
            Ok(BroadcastResponse {
                status: BroadcastStatus::Success,
                txid: body.txid.unwrap_or(txid),
                message: body.tx_status.unwrap_or_else(|| "Success".to_string()),
                competing_txs: None,
            })
        } else {
            Err(BroadcastFailure {
                status: BroadcastStatus::Error,
                code: body
                    .status
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "UNKNOWN".to_string()),
                txid: Some(txid),
                description: body
                    .detail
                    .or(body.title)
                    .unwrap_or_else(|| "Unknown error".to_string()),
                more: body.extra_info.map(serde_json::Value::String),
            })
        }
    }

    #[cfg(not(feature = "http"))]
    async fn broadcast(&self, tx: &Transaction) -> BroadcastResult {
        Err(BroadcastFailure {
            status: BroadcastStatus::Error,
            code: "NO_HTTP".to_string(),
            txid: Some(tx.id()),
            description: "HTTP feature not enabled. Add 'http' feature to Cargo.toml".to_string(),
            more: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arc_config_default() {
        let config = ArcConfig::default();
        assert_eq!(config.url, "https://arc.taal.com");
        assert!(config.api_key.is_none());
        assert_eq!(config.timeout_ms, 30_000);
    }

    #[test]
    fn test_arc_broadcaster_new() {
        let broadcaster =
            ArcBroadcaster::new("https://custom.arc.com", Some("api_key".to_string()));
        assert_eq!(broadcaster.url(), "https://custom.arc.com");
        assert_eq!(broadcaster.api_key(), Some("api_key"));
    }

    #[test]
    fn test_arc_broadcaster_default() {
        let broadcaster = ArcBroadcaster::default();
        assert_eq!(broadcaster.url(), "https://arc.taal.com");
        assert!(broadcaster.api_key().is_none());
    }

    #[test]
    fn test_arc_broadcaster_with_config() {
        let config = ArcConfig {
            url: "https://test.arc.com".to_string(),
            api_key: Some("test-key".to_string()),
            timeout_ms: 60_000,
        };
        let broadcaster = ArcBroadcaster::with_config(config);
        assert_eq!(broadcaster.url(), "https://test.arc.com");
        assert_eq!(broadcaster.api_key(), Some("test-key"));
    }
}
