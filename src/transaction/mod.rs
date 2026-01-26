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
//!
//! # Example
//!
//! ```rust,ignore
//! use bsv_sdk::transaction::{Transaction, TransactionInput, TransactionOutput, ChangeDistribution};
//! use bsv_sdk::script::LockingScript;
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
//! # BEEF Format
//!
//! ```rust,ignore
//! use bsv_sdk::transaction::{Beef, MerklePath};
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

pub mod beef;
pub mod beef_tx;
pub mod input;
pub mod merkle_path;
pub mod output;
#[allow(clippy::module_inception)]
pub mod transaction;

// Re-exports for convenience
pub use beef::{Beef, BeefValidationResult, SortResult};
pub use beef_tx::{BeefTx, TxDataFormat, ATOMIC_BEEF, BEEF_V1, BEEF_V2};
pub use input::TransactionInput;
pub use merkle_path::{MerklePath, MerklePathLeaf};
pub use output::TransactionOutput;
pub use transaction::{ChangeDistribution, ScriptOffset, ScriptOffsets, Transaction};
