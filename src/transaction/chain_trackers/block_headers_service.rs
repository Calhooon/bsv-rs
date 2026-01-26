//! Block Headers Service Chain Tracker
//!
//! Implements the [`ChainTracker`] trait using the Block Headers Service API.
//!
//! The Block Headers Service (headers.spv.money) provides a fast, reliable way
//! to verify merkle roots and query blockchain headers for SPV verification.
//!
//! # Example
//!
//! ```rust,ignore
//! use bsv_sdk::transaction::{ChainTracker, BlockHeadersServiceTracker};
//!
//! #[tokio::main]
//! async fn main() {
//!     let tracker = BlockHeadersServiceTracker::default();
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
//! - [Block Headers Service](https://headers.spv.money)

use async_trait::async_trait;

use crate::transaction::{ChainTracker, ChainTrackerError};

/// Default URL for the Block Headers Service.
pub const DEFAULT_HEADERS_URL: &str = "https://headers.spv.money";

/// Block Headers Service chain tracker configuration.
#[derive(Debug, Clone)]
pub struct BlockHeadersServiceConfig {
    /// Base URL for the headers service
    pub base_url: String,
    /// Authentication token (optional)
    pub auth_token: Option<String>,
    /// Request timeout in milliseconds
    pub timeout_ms: u64,
}

impl Default for BlockHeadersServiceConfig {
    fn default() -> Self {
        Self {
            base_url: DEFAULT_HEADERS_URL.to_string(),
            auth_token: None,
            timeout_ms: 30_000,
        }
    }
}

/// Block Headers Service chain tracker.
///
/// Verifies merkle roots and queries chain height using the Block Headers Service API.
///
/// # Example
///
/// ```rust,ignore
/// use bsv_sdk::transaction::{ChainTracker, BlockHeadersServiceTracker};
///
/// let tracker = BlockHeadersServiceTracker::default();
/// let height = tracker.current_height().await?;
/// ```
pub struct BlockHeadersServiceTracker {
    config: BlockHeadersServiceConfig,
    #[cfg(feature = "http")]
    client: reqwest::Client,
}

impl BlockHeadersServiceTracker {
    /// Create a tracker with the default URL (<https://headers.spv.money>).
    pub fn new() -> Self {
        Self::with_url(DEFAULT_HEADERS_URL)
    }

    /// Create a tracker with a custom base URL.
    ///
    /// # Arguments
    ///
    /// * `base_url` - The base URL for the headers service
    pub fn with_url(base_url: &str) -> Self {
        Self {
            config: BlockHeadersServiceConfig {
                base_url: base_url.to_string(),
                ..Default::default()
            },
            #[cfg(feature = "http")]
            client: reqwest::Client::new(),
        }
    }

    /// Create a tracker with full configuration.
    pub fn with_config(config: BlockHeadersServiceConfig) -> Self {
        Self {
            config,
            #[cfg(feature = "http")]
            client: reqwest::Client::new(),
        }
    }

    /// Get the configured base URL.
    pub fn base_url(&self) -> &str {
        &self.config.base_url
    }

    /// Get the configured auth token.
    pub fn auth_token(&self) -> Option<&str> {
        self.config.auth_token.as_deref()
    }
}

impl Default for BlockHeadersServiceTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ChainTracker for BlockHeadersServiceTracker {
    #[cfg(feature = "http")]
    async fn is_valid_root_for_height(
        &self,
        root: &str,
        height: u32,
    ) -> Result<bool, ChainTrackerError> {
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct HeaderResponse {
            merkleroot: Option<String>,
            #[serde(rename = "merkleRoot")]
            merkle_root_alt: Option<String>,
        }

        let url = format!("{}/api/v1/chain/header/{}", self.config.base_url, height);

        let mut request = self.client.get(&url);

        if let Some(ref token) = self.config.auth_token {
            request = request.header("Authorization", format!("Bearer {}", token));
        }

        let response = request
            .timeout(std::time::Duration::from_millis(self.config.timeout_ms))
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

        let header: HeaderResponse = response
            .json()
            .await
            .map_err(|e| ChainTrackerError::InvalidResponse(e.to_string()))?;

        // Handle both possible field names
        let merkle_root = header
            .merkleroot
            .or(header.merkle_root_alt)
            .ok_or_else(|| {
                ChainTrackerError::InvalidResponse("Missing merkleroot in response".to_string())
            })?;

        // Compare merkle roots case-insensitively
        Ok(merkle_root.to_lowercase() == root.to_lowercase())
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
            height: Option<u32>,
            #[serde(rename = "blockHeight")]
            block_height: Option<u32>,
            blocks: Option<u32>,
        }

        let url = format!("{}/api/v1/chain/tip", self.config.base_url);

        let mut request = self.client.get(&url);

        if let Some(ref token) = self.config.auth_token {
            request = request.header("Authorization", format!("Bearer {}", token));
        }

        let response = request
            .timeout(std::time::Duration::from_millis(self.config.timeout_ms))
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

        // Handle various possible field names
        info.height
            .or(info.block_height)
            .or(info.blocks)
            .ok_or_else(|| {
                ChainTrackerError::InvalidResponse("Missing height in response".to_string())
            })
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
    fn test_default_url() {
        let tracker = BlockHeadersServiceTracker::default();
        assert_eq!(tracker.base_url(), DEFAULT_HEADERS_URL);
    }

    #[test]
    fn test_custom_url() {
        let tracker = BlockHeadersServiceTracker::with_url("https://custom.headers.com");
        assert_eq!(tracker.base_url(), "https://custom.headers.com");
    }

    #[test]
    fn test_config_default() {
        let config = BlockHeadersServiceConfig::default();
        assert_eq!(config.base_url, DEFAULT_HEADERS_URL);
        assert!(config.auth_token.is_none());
        assert_eq!(config.timeout_ms, 30_000);
    }

    #[test]
    fn test_with_config() {
        let config = BlockHeadersServiceConfig {
            base_url: "https://test.headers.com".to_string(),
            auth_token: Some("test-token".to_string()),
            timeout_ms: 60_000,
        };
        let tracker = BlockHeadersServiceTracker::with_config(config);
        assert_eq!(tracker.base_url(), "https://test.headers.com");
        assert_eq!(tracker.auth_token(), Some("test-token"));
    }

    #[test]
    fn test_new() {
        let tracker = BlockHeadersServiceTracker::new();
        assert_eq!(tracker.base_url(), DEFAULT_HEADERS_URL);
        assert!(tracker.auth_token().is_none());
    }
}
