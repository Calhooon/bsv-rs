//! # BSV Transaction
//!
//! Transaction construction, signing, serialization, and SPV verification.
//!
//! This module provides:
//! - Transaction building with inputs and outputs
//! - Input/Output management
//! - Fee calculation and change distribution
//! - Signing with script templates
//! - Serialization (hex, binary, Extended Format)
//! - MerklePath (BRC-74 BUMP) for merkle proofs
//! - BEEF format (BRC-62/95/96) for SPV proofs
//! - Fee models for computing transaction fees
//! - Broadcaster trait for transaction broadcasting
//! - ChainTracker trait for SPV verification
//!
//! # Example
//!
//! ```rust,ignore
//! use bsv_rs::transaction::{Transaction, TransactionInput, TransactionOutput, ChangeDistribution};
//! use bsv_rs::script::LockingScript;
//!
//! // Create a new transaction
//! let mut tx = Transaction::new();
//!
//! // Add an input
//! tx.add_input(TransactionInput::new(
//!     "abc123...".to_string(),
//!     0,
//! ))?;
//!
//! // Add an output
//! tx.add_output(TransactionOutput::new(
//!     100_000,
//!     LockingScript::from_hex("76a914...88ac")?,
//! ))?;
//!
//! // Compute fees and sign
//! tx.fee(None, ChangeDistribution::Equal).await?;
//! tx.sign().await?;
//!
//! // Serialize
//! let hex = tx.to_hex();
//! let txid = tx.id();
//! ```
//!
//! # Fee Models
//!
//! ```rust,ignore
//! use bsv_rs::transaction::{FeeModel, SatoshisPerKilobyte};
//!
//! // 100 satoshis per kilobyte
//! let fee_model = SatoshisPerKilobyte::new(100);
//! let fee = fee_model.compute_fee(&tx)?;
//! ```
//!
//! # BEEF Format
//!
//! ```rust,ignore
//! use bsv_rs::transaction::{Beef, MerklePath};
//!
//! // Parse BEEF from hex
//! let beef = Beef::from_hex("0100beef...")?;
//!
//! // Validate structure
//! assert!(beef.is_valid(false));
//!
//! // Find a transaction
//! if let Some(tx) = beef.find_txid("abc123...") {
//!     println!("Found transaction");
//! }
//! ```
//!
//! # Chain Tracking
//!
//! ```rust,ignore
//! use bsv_rs::transaction::{ChainTracker, MockChainTracker};
//!
//! // Create a mock tracker for testing
//! let mut tracker = MockChainTracker::new(1000);
//! tracker.add_root(999, "merkle_root_hex".to_string());
//!
//! // Verify a merkle root
//! let is_valid = tracker.is_valid_root_for_height("merkle_root_hex", 999)?;
//! ```

pub mod beef;
pub mod beef_tx;
pub mod broadcaster;
pub mod broadcasters;
pub mod chain_tracker;
pub mod chain_trackers;
pub mod fee_model;
pub mod fee_models;
pub mod input;
pub mod merkle_path;
pub mod output;
#[allow(clippy::module_inception)]
pub mod transaction;
pub mod tx_json;

// Re-exports for convenience
pub use beef::{Beef, BeefValidationResult, SortResult};
pub use beef_tx::{BeefTx, TxDataFormat, ATOMIC_BEEF, BEEF_V1, BEEF_V2};
pub use broadcaster::{
    is_broadcast_failure, is_broadcast_success, BroadcastFailure, BroadcastResponse,
    BroadcastResult, BroadcastStatus, Broadcaster,
};
pub use broadcasters::{
    ArcBroadcaster, ArcConfig, TeranodeBroadcaster, TeranodeConfig, WhatsOnChainBroadcaster,
    WocBroadcastConfig, WocBroadcastNetwork,
};
pub use chain_tracker::{
    AlwaysValidChainTracker, ChainTracker, ChainTrackerError, MockChainTracker,
};
pub use chain_trackers::{
    BlockHeadersServiceConfig, BlockHeadersServiceTracker, WhatsOnChainTracker, WocNetwork,
    DEFAULT_HEADERS_URL,
};
pub use fee_model::{FeeModel, FixedFee};
pub use fee_models::{
    LivePolicy, LivePolicyConfig, SatoshisPerKilobyte, DEFAULT_CACHE_TTL_SECS,
    DEFAULT_FALLBACK_RATE, DEFAULT_POLICY_URL,
};
pub use input::{TransactionInput, Utxo};
pub use merkle_path::{MerklePath, MerklePathLeaf};
pub use output::TransactionOutput;
pub use transaction::{ChangeDistribution, ScriptOffset, ScriptOffsets, Transaction};

// Sighash constants re-exported for convenience
pub use crate::primitives::bsv::sighash::{
    SIGHASH_ALL, SIGHASH_ANYONECANPAY, SIGHASH_FORKID, SIGHASH_NONE, SIGHASH_SINGLE,
};
