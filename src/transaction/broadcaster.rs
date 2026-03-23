//! Broadcaster trait for transaction broadcasting.
//!
//! This module provides the [`Broadcaster`] trait that defines how transactions
//! are broadcast to the BSV network. Implementations can use different broadcasting
//! services such as ARC, WhatsOnChain, or custom endpoints.
//!
//! # Example
//!
//! ```rust,ignore
//! use bsv_rs::transaction::{Broadcaster, BroadcastResponse, Transaction};
//! use async_trait::async_trait;
//!
//! struct MyBroadcaster {
//!     endpoint: String,
//! }
//!
//! #[async_trait(?Send)]
//! impl Broadcaster for MyBroadcaster {
//!     async fn broadcast(&self, tx: &Transaction) -> BroadcastResult {
//!         // Async HTTP POST to endpoint
//!     }
//! }
//! ```

use super::transaction::Transaction;
use async_trait::async_trait;
use serde_json::Value;

/// Defines the structure of a successful broadcast response.
#[derive(Debug, Clone)]
pub struct BroadcastResponse {
    /// The status of the response, indicating success.
    pub status: BroadcastStatus,
    /// The transaction ID of the broadcasted transaction.
    pub txid: String,
    /// A human-readable success message.
    pub message: String,
    /// TXIDs of competing transactions, if any.
    pub competing_txs: Option<Vec<String>>,
}

impl BroadcastResponse {
    /// Creates a new successful broadcast response.
    pub fn success(txid: String, message: String) -> Self {
        Self {
            status: BroadcastStatus::Success,
            txid,
            message,
            competing_txs: None,
        }
    }

    /// Creates a new successful broadcast response with competing transactions.
    pub fn success_with_competing(
        txid: String,
        message: String,
        competing_txs: Vec<String>,
    ) -> Self {
        Self {
            status: BroadcastStatus::Success,
            txid,
            message,
            competing_txs: Some(competing_txs),
        }
    }
}

/// Defines the structure of a failed broadcast response.
#[derive(Debug, Clone)]
pub struct BroadcastFailure {
    /// The status of the response, indicating an error.
    pub status: BroadcastStatus,
    /// A machine-readable error code representing the type of error encountered.
    pub code: String,
    /// The transaction ID, if available.
    pub txid: Option<String>,
    /// A detailed description of the error.
    pub description: String,
    /// Additional details from the broadcast service.
    pub more: Option<Value>,
}

impl BroadcastFailure {
    /// Creates a new broadcast failure.
    pub fn new(code: String, description: String) -> Self {
        Self {
            status: BroadcastStatus::Error,
            code,
            txid: None,
            description,
            more: None,
        }
    }

    /// Creates a new broadcast failure with a transaction ID.
    pub fn with_txid(code: String, txid: String, description: String) -> Self {
        Self {
            status: BroadcastStatus::Error,
            code,
            txid: Some(txid),
            description,
            more: None,
        }
    }

    /// Creates a new broadcast failure with additional details.
    pub fn with_details(code: String, description: String, more: Value) -> Self {
        Self {
            status: BroadcastStatus::Error,
            code,
            txid: None,
            description,
            more: Some(more),
        }
    }
}

/// The status of a broadcast operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BroadcastStatus {
    /// The broadcast was successful.
    Success,
    /// The broadcast failed with an error.
    Error,
}

/// Result type for broadcast operations.
pub type BroadcastResult = Result<BroadcastResponse, BroadcastFailure>;

/// Represents the interface for a transaction broadcaster.
///
/// This trait defines a standard async method for broadcasting transactions to the
/// BSV network. Implementations can use different services such as:
///
/// - ARC (TAAL's broadcast service)
/// - WhatsOnChain
/// - Custom node endpoints
///
/// # Example
///
/// ```rust,ignore
/// use bsv_rs::transaction::{Broadcaster, BroadcastResult, Transaction};
/// use async_trait::async_trait;
///
/// struct MyBroadcaster {
///     endpoint: String,
/// }
///
/// #[async_trait(?Send)]
/// impl Broadcaster for MyBroadcaster {
///     async fn broadcast(&self, tx: &Transaction) -> BroadcastResult {
///         // Async HTTP POST to endpoint
///     }
///     // broadcast_many() has a default sequential implementation
/// }
/// ```
#[async_trait(?Send)]
pub trait Broadcaster: Send + Sync {
    /// Broadcasts a transaction to the network asynchronously.
    ///
    /// # Arguments
    ///
    /// * `tx` - The transaction to broadcast
    ///
    /// # Returns
    ///
    /// A [`BroadcastResponse`] on success or [`BroadcastFailure`] on error.
    async fn broadcast(&self, tx: &Transaction) -> BroadcastResult;

    /// Broadcasts multiple transactions to the network asynchronously.
    ///
    /// The default implementation broadcasts each transaction sequentially.
    /// Implementations may override this to use batch endpoints.
    ///
    /// # Arguments
    ///
    /// * `txs` - The transactions to broadcast
    ///
    /// # Returns
    ///
    /// A vector of results, one per transaction.
    async fn broadcast_many(&self, txs: Vec<Transaction>) -> Vec<BroadcastResult> {
        let mut results = Vec::with_capacity(txs.len());
        for tx in &txs {
            results.push(self.broadcast(tx).await);
        }
        results
    }
}

/// Convenience function to check if a result is a successful broadcast.
pub fn is_broadcast_success(result: &BroadcastResult) -> bool {
    matches!(result, Ok(r) if r.status == BroadcastStatus::Success)
}

/// Convenience function to check if a result is a failed broadcast.
pub fn is_broadcast_failure(result: &BroadcastResult) -> bool {
    result.is_err()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_broadcast_response_success() {
        let response =
            BroadcastResponse::success("abc123".to_string(), "Transaction accepted".to_string());
        assert_eq!(response.status, BroadcastStatus::Success);
        assert_eq!(response.txid, "abc123");
        assert!(response.competing_txs.is_none());
    }

    #[test]
    fn test_broadcast_failure_new() {
        let failure = BroadcastFailure::new(
            "INVALID_TX".to_string(),
            "Transaction is invalid".to_string(),
        );
        assert_eq!(failure.status, BroadcastStatus::Error);
        assert_eq!(failure.code, "INVALID_TX");
        assert!(failure.txid.is_none());
    }

    #[test]
    fn test_is_broadcast_success() {
        let success: BroadcastResult = Ok(BroadcastResponse::success(
            "abc".to_string(),
            "ok".to_string(),
        ));
        let failure: BroadcastResult = Err(BroadcastFailure::new(
            "ERR".to_string(),
            "error".to_string(),
        ));

        assert!(is_broadcast_success(&success));
        assert!(!is_broadcast_success(&failure));
        assert!(!is_broadcast_failure(&success));
        assert!(is_broadcast_failure(&failure));
    }
}
