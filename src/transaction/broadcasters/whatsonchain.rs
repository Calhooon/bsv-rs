//! WhatsOnChain Broadcaster
//!
//! Implements the [`Broadcaster`] trait using the WhatsOnChain API.
//!
//! WhatsOnChain is a blockchain explorer that provides free API access
//! for broadcasting transactions to the BSV network.
//!
//! # Example
//!
//! ```rust,ignore
//! use bsv_rs::transaction::{Broadcaster, WhatsOnChainBroadcaster, WocBroadcastNetwork};
//!
//! #[tokio::main]
//! async fn main() {
//!     let broadcaster = WhatsOnChainBroadcaster::mainnet();
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
//! - [WhatsOnChain API](https://developers.whatsonchain.com/)

use async_trait::async_trait;

#[cfg(feature = "http")]
use crate::transaction::BroadcastResponse;
use crate::transaction::{
    BroadcastFailure, BroadcastResult, BroadcastStatus, Broadcaster, Transaction,
};

/// WhatsOnChain broadcast network selection.
///
/// Supports mainnet, testnet, and STN (Scaling Test Network).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WocBroadcastNetwork {
    /// BSV Mainnet
    #[default]
    Mainnet,
    /// BSV Testnet
    Testnet,
    /// BSV Scaling Test Network
    Stn,
}

impl WocBroadcastNetwork {
    /// Get the API path segment for this network.
    fn path_segment(&self) -> &'static str {
        match self {
            WocBroadcastNetwork::Mainnet => "main",
            WocBroadcastNetwork::Testnet => "test",
            WocBroadcastNetwork::Stn => "stn",
        }
    }

    /// Get the broadcast URL for this network.
    pub fn broadcast_url(&self) -> String {
        format!(
            "https://api.whatsonchain.com/v1/bsv/{}/tx/raw",
            self.path_segment()
        )
    }
}

/// WhatsOnChain broadcaster configuration.
#[derive(Debug, Clone)]
pub struct WocBroadcastConfig {
    /// Network to broadcast to
    pub network: WocBroadcastNetwork,
    /// API key for authentication (optional, for higher rate limits)
    pub api_key: Option<String>,
    /// Request timeout in milliseconds
    pub timeout_ms: u64,
    /// Optional base URL override (for testing with mock servers).
    /// When set, this replaces the standard WhatsOnChain API URL.
    pub base_url: Option<String>,
}

impl Default for WocBroadcastConfig {
    fn default() -> Self {
        Self {
            network: WocBroadcastNetwork::Mainnet,
            api_key: None,
            timeout_ms: 30_000,
            base_url: None,
        }
    }
}

/// WhatsOnChain broadcaster implementation.
///
/// Broadcasts transactions to the BSV network via the WhatsOnChain API.
///
/// # Example
///
/// ```rust,ignore
/// use bsv_rs::transaction::{WhatsOnChainBroadcaster, Broadcaster};
///
/// // Create mainnet broadcaster
/// let broadcaster = WhatsOnChainBroadcaster::mainnet();
///
/// // Or testnet
/// let broadcaster = WhatsOnChainBroadcaster::testnet();
///
/// // Or with API key for higher rate limits
/// let broadcaster = WhatsOnChainBroadcaster::new(
///     WocBroadcastNetwork::Mainnet,
///     Some("your-api-key".to_string())
/// );
/// ```
pub struct WhatsOnChainBroadcaster {
    config: WocBroadcastConfig,
    #[cfg(feature = "http")]
    client: reqwest::Client,
}

impl Default for WhatsOnChainBroadcaster {
    fn default() -> Self {
        Self::mainnet()
    }
}

impl WhatsOnChainBroadcaster {
    /// Create a mainnet broadcaster.
    pub fn mainnet() -> Self {
        Self::new(WocBroadcastNetwork::Mainnet, None)
    }

    /// Create a testnet broadcaster.
    pub fn testnet() -> Self {
        Self::new(WocBroadcastNetwork::Testnet, None)
    }

    /// Create an STN (Scaling Test Network) broadcaster.
    pub fn stn() -> Self {
        Self::new(WocBroadcastNetwork::Stn, None)
    }

    /// Create a new WhatsOnChain broadcaster.
    ///
    /// # Arguments
    ///
    /// * `network` - The network to broadcast to
    /// * `api_key` - Optional API key for higher rate limits
    pub fn new(network: WocBroadcastNetwork, api_key: Option<String>) -> Self {
        Self {
            config: WocBroadcastConfig {
                network,
                api_key,
                ..Default::default()
            },
            #[cfg(feature = "http")]
            client: reqwest::Client::new(),
        }
    }

    /// Create with full configuration.
    pub fn with_config(config: WocBroadcastConfig) -> Self {
        Self {
            config,
            #[cfg(feature = "http")]
            client: reqwest::Client::new(),
        }
    }

    /// Create a new broadcaster with a custom base URL.
    ///
    /// This is primarily useful for testing with a mock HTTP server.
    ///
    /// # Arguments
    ///
    /// * `base_url` - The base URL to use instead of the standard WhatsOnChain API URL
    /// * `network` - The network to broadcast to (used for URL path segment)
    /// * `api_key` - Optional API key
    pub fn with_base_url(
        base_url: &str,
        network: WocBroadcastNetwork,
        api_key: Option<String>,
    ) -> Self {
        Self {
            config: WocBroadcastConfig {
                network,
                api_key,
                timeout_ms: 30_000,
                base_url: Some(base_url.to_string()),
            },
            #[cfg(feature = "http")]
            client: reqwest::Client::new(),
        }
    }

    /// Get the configured network.
    pub fn network(&self) -> WocBroadcastNetwork {
        self.config.network
    }

    /// Get the configured API key.
    pub fn api_key(&self) -> Option<&str> {
        self.config.api_key.as_deref()
    }
}

#[async_trait(?Send)]
impl Broadcaster for WhatsOnChainBroadcaster {
    #[cfg(feature = "http")]
    async fn broadcast(&self, tx: &Transaction) -> BroadcastResult {
        let url = match &self.config.base_url {
            Some(base) => format!(
                "{}/v1/bsv/{}/tx/raw",
                base,
                self.config.network.path_segment()
            ),
            None => self.config.network.broadcast_url(),
        };
        let raw_tx = tx.to_hex();
        let txid = tx.id();

        let mut request = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .body(raw_tx.clone());

        if let Some(ref api_key) = self.config.api_key {
            request = request.header("Authorization", api_key);
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
            // WhatsOnChain returns the txid on success
            let returned_txid = body.trim().trim_matches('"').to_string();
            Ok(BroadcastResponse {
                status: BroadcastStatus::Success,
                txid: if returned_txid.is_empty() {
                    txid
                } else {
                    returned_txid
                },
                message: "Transaction broadcast successfully".to_string(),
                competing_txs: None,
            })
        } else {
            Err(BroadcastFailure {
                status: BroadcastStatus::Error,
                code: status_code.as_u16().to_string(),
                txid: Some(txid),
                description: body,
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
    fn test_woc_broadcast_network_urls() {
        assert_eq!(
            WocBroadcastNetwork::Mainnet.broadcast_url(),
            "https://api.whatsonchain.com/v1/bsv/main/tx/raw"
        );
        assert_eq!(
            WocBroadcastNetwork::Testnet.broadcast_url(),
            "https://api.whatsonchain.com/v1/bsv/test/tx/raw"
        );
        assert_eq!(
            WocBroadcastNetwork::Stn.broadcast_url(),
            "https://api.whatsonchain.com/v1/bsv/stn/tx/raw"
        );
    }

    #[test]
    fn test_woc_broadcast_network_default() {
        assert_eq!(WocBroadcastNetwork::default(), WocBroadcastNetwork::Mainnet);
    }

    #[test]
    fn test_woc_broadcaster_mainnet() {
        let broadcaster = WhatsOnChainBroadcaster::mainnet();
        assert_eq!(broadcaster.network(), WocBroadcastNetwork::Mainnet);
        assert!(broadcaster.api_key().is_none());
    }

    #[test]
    fn test_woc_broadcaster_testnet() {
        let broadcaster = WhatsOnChainBroadcaster::testnet();
        assert_eq!(broadcaster.network(), WocBroadcastNetwork::Testnet);
    }

    #[test]
    fn test_woc_broadcaster_stn() {
        let broadcaster = WhatsOnChainBroadcaster::stn();
        assert_eq!(broadcaster.network(), WocBroadcastNetwork::Stn);
    }

    #[test]
    fn test_woc_broadcaster_with_api_key() {
        let broadcaster = WhatsOnChainBroadcaster::new(
            WocBroadcastNetwork::Mainnet,
            Some("test-key".to_string()),
        );
        assert_eq!(broadcaster.api_key(), Some("test-key"));
    }

    #[test]
    fn test_woc_broadcaster_default() {
        let broadcaster = WhatsOnChainBroadcaster::default();
        assert_eq!(broadcaster.network(), WocBroadcastNetwork::Mainnet);
    }

    #[test]
    fn test_woc_broadcast_config_default() {
        let config = WocBroadcastConfig::default();
        assert_eq!(config.network, WocBroadcastNetwork::Mainnet);
        assert!(config.api_key.is_none());
        assert_eq!(config.timeout_ms, 30_000);
    }

    #[test]
    fn test_woc_broadcaster_with_config() {
        let config = WocBroadcastConfig {
            network: WocBroadcastNetwork::Testnet,
            api_key: Some("custom-key".to_string()),
            timeout_ms: 60_000,
            base_url: None,
        };
        let broadcaster = WhatsOnChainBroadcaster::with_config(config);
        assert_eq!(broadcaster.network(), WocBroadcastNetwork::Testnet);
        assert_eq!(broadcaster.api_key(), Some("custom-key"));
    }
}
