//! # BSV Transaction
//!
//! Transaction construction, signing, and serialization.
//!
//! This module provides:
//! - Transaction building with inputs and outputs
//! - Input/Output management
//! - Fee calculation and change distribution
//! - Signing with script templates
//! - Serialization (hex, binary, Extended Format)
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

pub mod input;
pub mod output;
#[allow(clippy::module_inception)]
pub mod transaction;

// Re-exports for convenience
pub use input::TransactionInput;
pub use output::TransactionOutput;
pub use transaction::{ChangeDistribution, ScriptOffset, ScriptOffsets, Transaction};
