//! WhatsOnChain Chain Tracker
//!
//! Implements the [`ChainTracker`] trait using the WhatsOnChain API.
//!
//! WhatsOnChain is a blockchain explorer that provides free API access
//! for querying block headers and chain information.
//!
//! # Example
//!
//! ```rust,ignore
//! use bsv_sdk::transaction::{ChainTracker, WhatsOnChainTracker, WocNetwork};
//!
//! #[tokio::main]
//! async fn main() {
//!     // Use mainnet
//!     let tracker = WhatsOnChainTracker::mainnet();
//!
//!     // Or testnet
//!     let tracker = WhatsOnChainTracker::testnet();
//!
//!     // Verify a merkle root
//!     let is_valid = tracker
//!         .is_valid_root_for_height("abc123...", 700000)
//!         .await
//!         .unwrap();
//!
//!     // Get current height
//!     let height = tracker.current_height().await.unwrap();
//! }
//! ```
//!
//! # Reference
//!
//! - [WhatsOnChain API](https://developers.whatsonchain.com/)

use async_trait::async_trait;

use crate::transaction::{ChainTracker, ChainTrackerError};

/// WhatsOnChain network selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WocNetwork {
    /// BSV Mainnet
    #[default]
    Mainnet,
    /// BSV Testnet
    Testnet,
}

impl WocNetwork {
    /// Get the base URL for this network.
    pub fn base_url(&self) -> &'static str {
        match self {
            WocNetwork::Mainnet => "https://api.whatsonchain.com/v1/bsv/main",
            WocNetwork::Testnet => "https://api.whatsonchain.com/v1/bsv/test",
        }
    }
}

/// WhatsOnChain chain tracker.
///
/// Verifies merkle roots and queries chain height using the WhatsOnChain API.
///
/// # Example
///
/// ```rust,ignore
/// use bsv_sdk::transaction::{ChainTracker, WhatsOnChainTracker};
///
/// let tracker = WhatsOnChainTracker::mainnet();
/// let height = tracker.current_height().await?;
/// ```
pub struct WhatsOnChainTracker {
    network: WocNetwork,
    base_url_override: Option<String>,
    #[cfg(feature = "http")]
    client: reqwest::Client,
}

impl WhatsOnChainTracker {
    /// Create a tracker for mainnet.
    pub fn mainnet() -> Self {
        Self::new(WocNetwork::Mainnet)
    }

    /// Create a tracker for testnet.
    pub fn testnet() -> Self {
        Self::new(WocNetwork::Testnet)
    }

    /// Create a tracker for the specified network.
    pub fn new(network: WocNetwork) -> Self {
        Self {
            network,
            base_url_override: None,
            #[cfg(feature = "http")]
            client: reqwest::Client::new(),
        }
    }

    /// Create a tracker with a custom base URL (useful for testing).
    pub fn with_base_url(base_url: &str, network: WocNetwork) -> Self {
        Self {
            network,
            base_url_override: Some(base_url.to_string()),
            #[cfg(feature = "http")]
            client: reqwest::Client::new(),
        }
    }

    /// Get the configured network.
    pub fn network(&self) -> WocNetwork {
        self.network
    }

    /// Get the effective base URL.
    #[cfg(feature = "http")]
    fn base_url(&self) -> &str {
        self.base_url_override
            .as_deref()
            .unwrap_or_else(|| self.network.base_url())
    }
}

impl Default for WhatsOnChainTracker {
    fn default() -> Self {
        Self::mainnet()
    }
}

impl std::fmt::Debug for WhatsOnChainTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WhatsOnChainTracker")
            .field("network", &self.network)
            .field("base_url_override", &self.base_url_override)
            .finish()
    }
}

#[async_trait]
impl ChainTracker for WhatsOnChainTracker {
    #[cfg(feature = "http")]
    async fn is_valid_root_for_height(
        &self,
        root: &str,
        height: u32,
    ) -> Result<bool, ChainTrackerError> {
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct BlockHeader {
            merkleroot: String,
        }

        let url = format!("{}/block/{}/header", self.base_url(), height);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| ChainTrackerError::NetworkError(e.to_string()))?;

        if response.status().as_u16() == 404 {
            return Err(ChainTrackerError::BlockNotFound(height));
        }

        if !response.status().is_success() {
            return Err(ChainTrackerError::InvalidResponse(format!(
                "HTTP {}",
                response.status()
            )));
        }

        let header: BlockHeader = response
            .json()
            .await
            .map_err(|e| ChainTrackerError::InvalidResponse(e.to_string()))?;

        // Compare merkle roots case-insensitively
        Ok(header.merkleroot.to_lowercase() == root.to_lowercase())
    }

    #[cfg(not(feature = "http"))]
    async fn is_valid_root_for_height(
        &self,
        _root: &str,
        _height: u32,
    ) -> Result<bool, ChainTrackerError> {
        Err(ChainTrackerError::NetworkError(
            "HTTP feature not enabled. Add 'http' feature to Cargo.toml".to_string(),
        ))
    }

    #[cfg(feature = "http")]
    async fn current_height(&self) -> Result<u32, ChainTrackerError> {
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct ChainInfo {
            blocks: u32,
        }

        let url = format!("{}/chain/info", self.base_url());

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| ChainTrackerError::NetworkError(e.to_string()))?;

        if !response.status().is_success() {
            return Err(ChainTrackerError::InvalidResponse(format!(
                "HTTP {}",
                response.status()
            )));
        }

        let info: ChainInfo = response
            .json()
            .await
            .map_err(|e| ChainTrackerError::InvalidResponse(e.to_string()))?;

        Ok(info.blocks)
    }

    #[cfg(not(feature = "http"))]
    async fn current_height(&self) -> Result<u32, ChainTrackerError> {
        Err(ChainTrackerError::NetworkError(
            "HTTP feature not enabled. Add 'http' feature to Cargo.toml".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_woc_network_urls() {
        assert_eq!(
            WocNetwork::Mainnet.base_url(),
            "https://api.whatsonchain.com/v1/bsv/main"
        );
        assert_eq!(
            WocNetwork::Testnet.base_url(),
            "https://api.whatsonchain.com/v1/bsv/test"
        );
    }

    #[test]
    fn test_woc_network_default() {
        assert_eq!(WocNetwork::default(), WocNetwork::Mainnet);
    }

    #[test]
    fn test_woc_tracker_mainnet() {
        let tracker = WhatsOnChainTracker::mainnet();
        assert_eq!(tracker.network(), WocNetwork::Mainnet);
    }

    #[test]
    fn test_woc_tracker_testnet() {
        let tracker = WhatsOnChainTracker::testnet();
        assert_eq!(tracker.network(), WocNetwork::Testnet);
    }

    #[test]
    fn test_woc_tracker_new() {
        let tracker = WhatsOnChainTracker::new(WocNetwork::Testnet);
        assert_eq!(tracker.network(), WocNetwork::Testnet);
    }

    #[test]
    fn test_woc_tracker_default() {
        let tracker = WhatsOnChainTracker::default();
        assert_eq!(tracker.network(), WocNetwork::Mainnet);
    }
}
