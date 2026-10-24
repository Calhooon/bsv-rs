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

use crate::error::TransportFault;

/// Errors that can occur during chain tracking operations.
///
/// A provider's error is an error, never a verdict: a tracker that could not
/// ask its provider answers `Err`, never `Ok(false)`.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChainTrackerError {
    /// Network error occurred while communicating with the blockchain. The
    /// HTTP trackers of this crate answer [`ChainTrackerError::TransportFault`]
    /// for a fault of the way; this one stays for a tracker built without the
    /// `http` feature and for a caller's own tracker.
    #[error("network error: {0}")]
    NetworkError(String),

    /// A transport fault with its class (Calhooon/bsv-rs#87): the provider
    /// gave no answer in its word, so the root is neither valid nor invalid.
    ///
    /// [`TransportFault::NeverSent`]: the connection was never made; asking
    /// again is a new request. [`TransportFault::MayHaveBeenReceived`]:
    /// a timeout, a connection lost or a body cut after the request was
    /// written, or a 502, 503 or 504; a lookup is safe to repeat.
    /// [`TransportFault::RateLimited`]: a 429, or a 503 with `Retry-After`;
    /// ask again after its wait (the crate never retries by itself).
    /// [`ChainTrackerError::transport_fault`] reads the class, and the
    /// crate's [`crate::Error`] carries it as `Error::TransportFault`.
    #[error("transport fault {fault}: {detail}")]
    TransportFault {
        /// What the caller may assume about the provider.
        fault: TransportFault,
        /// The HTTP status of the answer, when one arrived; `None` when no
        /// answer arrived (a connection error, a timeout, a body cut).
        status: Option<u16>,
        /// What failed, in the transport's words.
        detail: String,
    },

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

impl ChainTrackerError {
    /// The transport fault this error reports, if it is one:
    /// [`ChainTrackerError::TransportFault`]'s class; every other variant is
    /// `None`.
    #[must_use]
    pub fn transport_fault(&self) -> Option<TransportFault> {
        match self {
            Self::TransportFault { fault, .. } => Some(*fault),
            _ => None,
        }
    }
}

/// A tracker's error as the crate's: [`ChainTrackerError::TransportFault`]
/// is `Error::TransportFault` with its three fields (with the `wallet`
/// feature, which carries that variant), so `Error::transport_fault()` reads
/// the class; every other error is `Error::TransactionError` with
/// `"Chain tracker error: {e}"`, as `Transaction::verify` answered it.
impl From<ChainTrackerError> for crate::Error {
    fn from(e: ChainTrackerError) -> Self {
        match e {
            #[cfg(feature = "wallet")]
            ChainTrackerError::TransportFault {
                fault,
                status,
                detail,
            } => crate::Error::TransportFault {
                fault,
                status,
                detail,
            },
            other => crate::Error::TransactionError(format!("Chain tracker error: {}", other)),
        }
    }
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

    /// Active tip, median time past and network activation heights for the streaming reader.
    /// Existing trackers default to no contextual evidence; current_height alone is insufficient.
    async fn mining_tip(&self) -> Result<Option<super::beef_stream::ChainTip>, ChainTrackerError> {
        Ok(None)
    }
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

        let err = ChainTrackerError::TransportFault {
            fault: TransportFault::MayHaveBeenReceived,
            status: Some(503),
            detail: "HTTP 503 Service Unavailable".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "transport fault MAY_HAVE_BEEN_RECEIVED: HTTP 503 Service Unavailable"
        );
    }
}
