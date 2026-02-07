//! Teranode Broadcaster
//!
//! Implements the [`Broadcaster`] trait for Teranode's transaction processing service.
//!
//! Teranode accepts transactions in Extended Format (EF/BRC-30) as raw binary data,
//! which is more efficient than the JSON format used by ARC.
//!
//! # Example
//!
//! ```rust,ignore
//! use bsv_sdk::transaction::{TeranodeBroadcaster, Broadcaster, Transaction};
//!
//! #[tokio::main]
//! async fn main() {
//!     let broadcaster = TeranodeBroadcaster::new("https://teranode.example.com", None);
//!     let tx = Transaction::from_hex("...").unwrap();
//!
//!     match broadcaster.broadcast(&tx).await {
//!         Ok(response) => println!("Broadcast success: {}", response.txid),
//!         Err(failure) => println!("Broadcast failed: {}", failure.description),
//!     }
//! }
//! ```

use async_trait::async_trait;

#[cfg(feature = "http")]
use crate::transaction::BroadcastResponse;
use crate::transaction::{
    BroadcastFailure, BroadcastResult, BroadcastStatus, Broadcaster, Transaction,
};

/// Teranode broadcaster configuration.
#[derive(Debug, Clone)]
pub struct TeranodeConfig {
    /// Teranode API URL (no default - must be provided)
    pub url: String,
    /// API key for authentication (optional)
    pub api_key: Option<String>,
    /// Request timeout in milliseconds
    pub timeout_ms: u64,
}

/// Teranode broadcaster implementation.
///
/// Broadcasts transactions to the BSV network via Teranode's service.
/// Unlike ARC, Teranode accepts Extended Format (EF) binary data.
///
/// # Example
///
/// ```rust,ignore
/// use bsv_sdk::transaction::{TeranodeBroadcaster, Broadcaster};
///
/// let broadcaster = TeranodeBroadcaster::new(
///     "https://teranode.example.com",
///     None
/// );
/// ```
pub struct TeranodeBroadcaster {
    config: TeranodeConfig,
    #[cfg(feature = "http")]
    client: reqwest::Client,
}

impl TeranodeBroadcaster {
    /// Create a new Teranode broadcaster.
    ///
    /// # Arguments
    ///
    /// * `url` - The Teranode API URL (required, no default)
    /// * `api_key` - Optional API key for authentication
    pub fn new(url: &str, api_key: Option<String>) -> Self {
        Self {
            config: TeranodeConfig {
                url: url.to_string(),
                api_key,
                timeout_ms: 30_000,
            },
            #[cfg(feature = "http")]
            client: reqwest::Client::new(),
        }
    }

    /// Create with full configuration.
    pub fn with_config(config: TeranodeConfig) -> Self {
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
impl Broadcaster for TeranodeBroadcaster {
    #[cfg(feature = "http")]
    async fn broadcast(&self, tx: &Transaction) -> BroadcastResult {
        let txid = tx.id();

        // Serialize to Extended Format (EF) binary
        let ef_bytes = tx.to_ef().map_err(|e| BroadcastFailure {
            status: BroadcastStatus::Error,
            code: "EF_SERIALIZATION_ERROR".to_string(),
            txid: Some(txid.clone()),
            description: format!("Failed to serialize transaction to EF format: {}", e),
            more: None,
        })?;

        let url = format!("{}/v1/tx", self.config.url);

        let mut request = self
            .client
            .post(&url)
            .header("Content-Type", "application/octet-stream")
            .body(ef_bytes);

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
        let body = response.text().await.map_err(|e| BroadcastFailure {
            status: BroadcastStatus::Error,
            code: "PARSE_ERROR".to_string(),
            txid: Some(txid.clone()),
            description: format!("Failed to read response: {}", e),
            more: None,
        })?;

        if status_code.is_success() {
            Ok(BroadcastResponse {
                status: BroadcastStatus::Success,
                txid,
                message: if body.is_empty() {
                    "Success".to_string()
                } else {
                    body
                },
                competing_txs: None,
            })
        } else {
            Err(BroadcastFailure {
                status: BroadcastStatus::Error,
                code: status_code.as_u16().to_string(),
                txid: Some(txid),
                description: if body.is_empty() {
                    format!("HTTP {}", status_code)
                } else {
                    body
                },
                more: None,
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
    fn test_teranode_broadcaster_new() {
        let broadcaster =
            TeranodeBroadcaster::new("https://teranode.example.com", Some("api_key".to_string()));
        assert_eq!(broadcaster.url(), "https://teranode.example.com");
        assert_eq!(broadcaster.api_key(), Some("api_key"));
    }

    #[test]
    fn test_teranode_broadcaster_with_config() {
        let config = TeranodeConfig {
            url: "https://test.teranode.com".to_string(),
            api_key: Some("test-key".to_string()),
            timeout_ms: 60_000,
        };
        let broadcaster = TeranodeBroadcaster::with_config(config);
        assert_eq!(broadcaster.url(), "https://test.teranode.com");
        assert_eq!(broadcaster.api_key(), Some("test-key"));
    }

    #[test]
    fn test_teranode_no_default() {
        // Teranode has no default URL - this test just verifies construction
        let broadcaster = TeranodeBroadcaster::new("https://custom.teranode.io", None);
        assert_eq!(broadcaster.url(), "https://custom.teranode.io");
        assert!(broadcaster.api_key().is_none());
    }
}
