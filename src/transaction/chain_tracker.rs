//! Chain tracker trait for SPV verification.
//!
//! This module provides the [`ChainTracker`] trait that defines how merkle roots
//! are verified against the blockchain. This is essential for SPV (Simplified
//! Payment Verification) of transactions.
//!
//! # Example
//!
//! ```rust,ignore
//! use bsv_rs::transaction::{ChainTracker, ChainTrackerError};
//! use async_trait::async_trait;
//!
//! struct MyChainTracker;
//!
//! #[async_trait]
//! impl ChainTracker for MyChainTracker {
//!     async fn is_valid_root_for_height(&self, root: &str, height: u32)
//!         -> Result<bool, ChainTrackerError>
//!     {
//!         // Async verify root against blockchain
//!     }
//!
//!     async fn current_height(&self) -> Result<u32, ChainTrackerError> {
//!         // Async return current block height
//!     }
//! }
//! ```

use async_trait::async_trait;
use std::collections::HashMap;
use thiserror::Error;

/// Errors that can occur during chain tracking operations.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ChainTrackerError {
    /// Network error occurred while communicating with the blockchain.
    #[error("network error: {0}")]
    NetworkError(String),

    /// Invalid response received from the blockchain service.
    #[error("invalid response: {0}")]
    InvalidResponse(String),

    /// The requested block was not found.
    #[error("block not found at height: {0}")]
    BlockNotFound(u32),

    /// General chain tracker error.
    #[error("chain tracker error: {0}")]
    Other(String),
}

/// The Chain Tracker is responsible for verifying the validity of a given Merkle root
/// for a specific block height within the blockchain.
///
/// Chain Trackers ensure the integrity of the blockchain by validating new headers
/// against the chain's history. They use accumulated proof-of-work and protocol
/// adherence as metrics to assess the legitimacy of blocks.
///
/// # Example
///
/// ```rust,ignore
/// use bsv_rs::transaction::{ChainTracker, ChainTrackerError};
/// use async_trait::async_trait;
///
/// struct WhatsOnChainTracker {
///     api_key: String,
/// }
///
/// #[async_trait]
/// impl ChainTracker for WhatsOnChainTracker {
///     async fn is_valid_root_for_height(&self, root: &str, height: u32)
///         -> Result<bool, ChainTrackerError>
///     {
///         // Call WhatsOnChain API to verify the merkle root
///         // GET https://api.whatsonchain.com/v1/bsv/main/block/height/{height}
///     }
///
///     async fn current_height(&self) -> Result<u32, ChainTrackerError> {
///         // Call WhatsOnChain API to get current height
///         // GET https://api.whatsonchain.com/v1/bsv/main/chain/info
///     }
/// }
/// ```
#[async_trait]
pub trait ChainTracker: Send + Sync {
    /// Verifies if a merkle root is valid for a given block height asynchronously.
    ///
    /// This method checks if the provided merkle root matches the merkle root
    /// of the block at the specified height in the blockchain.
    ///
    /// # Arguments
    ///
    /// * `root` - The merkle root to verify (hex-encoded)
    /// * `height` - The block height to check against
    ///
    /// # Returns
    ///
    /// `true` if the root is valid for the height, `false` otherwise.
    async fn is_valid_root_for_height(
        &self,
        root: &str,
        height: u32,
    ) -> Result<bool, ChainTrackerError>;

    /// Returns the current block height of the blockchain asynchronously.
    ///
    /// # Returns
    ///
    /// The current block height.
    async fn current_height(&self) -> Result<u32, ChainTrackerError>;
}

/// A mock chain tracker for testing purposes.
///
/// This tracker stores merkle roots in memory and can be configured with
/// known valid roots for specific heights.
///
/// # Example
///
/// ```rust,ignore
/// use bsv_rs::transaction::MockChainTracker;
///
/// let mut tracker = MockChainTracker::new(1000); // Current height = 1000
/// tracker.add_root(999, "abc123...".to_string());
///
/// assert!(tracker.is_valid_root_for_height("abc123...", 999).await?);
/// assert_eq!(tracker.current_height().await?, 1000);
/// ```
#[derive(Debug, Clone, Default)]
pub struct MockChainTracker {
    /// The current block height.
    pub height: u32,
    /// Known valid merkle roots by block height.
    pub roots: HashMap<u32, String>,
}

impl MockChainTracker {
    /// Creates a new mock chain tracker with the given current height.
    pub fn new(height: u32) -> Self {
        Self {
            height,
            roots: HashMap::new(),
        }
    }

    /// Adds a known valid merkle root for a specific height.
    pub fn add_root(&mut self, height: u32, root: String) {
        self.roots.insert(height, root);
    }

    /// Creates a mock tracker that always returns true for any root.
    pub fn always_valid(height: u32) -> AlwaysValidChainTracker {
        AlwaysValidChainTracker { height }
    }
}

#[async_trait]
impl ChainTracker for MockChainTracker {
    async fn is_valid_root_for_height(
        &self,
        root: &str,
        height: u32,
    ) -> Result<bool, ChainTrackerError> {
        Ok(self.roots.get(&height).map(|r| r == root).unwrap_or(false))
    }

    async fn current_height(&self) -> Result<u32, ChainTrackerError> {
        Ok(self.height)
    }
}

/// A chain tracker that always returns true for any merkle root.
///
/// This is useful for testing when you want to skip chain validation.
#[derive(Debug, Clone, Copy)]
pub struct AlwaysValidChainTracker {
    /// The current block height to report.
    pub height: u32,
}

impl AlwaysValidChainTracker {
    /// Creates a new always-valid tracker with the given height.
    pub fn new(height: u32) -> Self {
        Self { height }
    }
}

#[async_trait]
impl ChainTracker for AlwaysValidChainTracker {
    async fn is_valid_root_for_height(
        &self,
        _root: &str,
        _height: u32,
    ) -> Result<bool, ChainTrackerError> {
        Ok(true)
    }

    async fn current_height(&self) -> Result<u32, ChainTrackerError> {
        Ok(self.height)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_chain_tracker() {
        let mut tracker = MockChainTracker::new(1000);
        tracker.add_root(999, "abc123".to_string());

        assert!(tracker
            .is_valid_root_for_height("abc123", 999)
            .await
            .unwrap());
        assert!(!tracker
            .is_valid_root_for_height("abc123", 998)
            .await
            .unwrap());
        assert!(!tracker
            .is_valid_root_for_height("xyz789", 999)
            .await
            .unwrap());
        assert_eq!(tracker.current_height().await.unwrap(), 1000);
    }

    #[tokio::test]
    async fn test_always_valid_chain_tracker() {
        let tracker = AlwaysValidChainTracker::new(500);

        assert!(tracker
            .is_valid_root_for_height("anything", 123)
            .await
            .unwrap());
        assert_eq!(tracker.current_height().await.unwrap(), 500);
    }

    #[test]
    fn test_chain_tracker_error_display() {
        let err = ChainTrackerError::NetworkError("timeout".to_string());
        assert_eq!(err.to_string(), "network error: timeout");

        let err = ChainTrackerError::BlockNotFound(12345);
        assert_eq!(err.to_string(), "block not found at height: 12345");
    }
}
