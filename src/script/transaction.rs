//! Transaction interface traits for Script module integration.
//!
//! This module defines traits that the future Transaction module will implement
//! to integrate with the Script module for spend validation.
//!
//! The traits provide a clean abstraction layer that allows the Script module
//! to work with transaction data without depending on specific Transaction
//! implementations.
//!
//! # Example Implementation
//!
//! ```rust,ignore
//! use bsv_rs::script::transaction::{TransactionInputContext, TransactionOutputContext};
//!
//! impl TransactionInputContext for TransactionInput {
//!     fn source_txid(&self) -> &[u8; 32] { &self.prev_txid }
//!     fn source_output_index(&self) -> u32 { self.prev_output_index }
//!     fn sequence(&self) -> u32 { self.sequence }
//!     fn source_satoshis(&self) -> Option<u64> { self.source_satoshis }
//!     fn source_locking_script(&self) -> Option<&LockingScript> { self.source_script.as_ref() }
//! }
//! ```

use super::{LockingScript, UnlockingScript};

// ============================================================================
// Transaction Input Context
// ============================================================================

/// Context from a transaction input needed for script validation.
///
/// This trait abstracts the transaction input data needed by the Script module
/// to validate spends. The Transaction module will implement this trait.
pub trait TransactionInputContext {
    /// The transaction ID of the UTXO being spent (32 bytes, internal byte order).
    fn source_txid(&self) -> &[u8; 32];

    /// The index of the output being spent in the source transaction.
    fn source_output_index(&self) -> u32;

    /// The sequence number of this input.
    fn sequence(&self) -> u32;

    /// The satoshi value of the UTXO being spent.
    ///
    /// Returns `None` if the source transaction data is not available.
    /// This is required for sighash computation (BIP-143).
    fn source_satoshis(&self) -> Option<u64>;

    /// The locking script of the UTXO being spent.
    ///
    /// Returns `None` if the source transaction data is not available.
    fn source_locking_script(&self) -> Option<&LockingScript>;

    /// The unlocking script for this input.
    fn unlocking_script(&self) -> &UnlockingScript;
}

// ============================================================================
// Transaction Output Context
// ============================================================================

/// Context from a transaction output.
///
/// This trait abstracts transaction output data. The Transaction module
/// will implement this trait.
pub trait TransactionOutputContext {
    /// The satoshi value of this output.
    fn satoshis(&self) -> u64;

    /// The locking script of this output.
    fn locking_script(&self) -> &LockingScript;
}

// ============================================================================
// Transaction Context
// ============================================================================

/// Full transaction context for script validation.
///
/// This trait provides all the data needed by the Spend validator to
/// validate a transaction input. The Transaction module will implement
/// this trait.
pub trait TransactionContext {
    /// The input type implementing TransactionInputContext.
    type Input: TransactionInputContext;

    /// The output type implementing TransactionOutputContext.
    type Output: TransactionOutputContext;

    /// Transaction version.
    fn version(&self) -> i32;

    /// All inputs in this transaction.
    fn inputs(&self) -> &[Self::Input];

    /// All outputs in this transaction.
    fn outputs(&self) -> &[Self::Output];

    /// The lock time.
    fn lock_time(&self) -> u32;

    /// Get a specific input by index.
    fn input(&self, index: usize) -> Option<&Self::Input> {
        self.inputs().get(index)
    }

    /// Get a specific output by index.
    fn output(&self, index: usize) -> Option<&Self::Output> {
        self.outputs().get(index)
    }

    /// Number of inputs.
    fn input_count(&self) -> usize {
        self.inputs().len()
    }

    /// Number of outputs.
    fn output_count(&self) -> usize {
        self.outputs().len()
    }
}

// ============================================================================
// Spend Validation Extension
// ============================================================================

/// Extension trait for validating all inputs of a transaction.
///
/// This trait provides convenient methods for validating transaction spends
/// when the transaction implements `TransactionContext`.
pub trait SpendValidation: TransactionContext {
    /// Validate a specific input by index.
    ///
    /// Returns `Ok(true)` if the input is valid, `Ok(false)` if invalid,
    /// or `Err` with details if validation fails with an error.
    fn validate_input(
        &self,
        index: usize,
    ) -> Result<bool, Box<crate::script::ScriptEvaluationError>>;

    /// Validate all inputs in the transaction.
    ///
    /// Returns `Ok(())` if all inputs are valid, or the first error encountered.
    fn validate_all_inputs(&self) -> Result<(), Box<crate::script::ScriptEvaluationError>> {
        for i in 0..self.input_count() {
            match self.validate_input(i) {
                Ok(true) => continue,
                Ok(false) => {
                    return Err(Box::new(crate::script::ScriptEvaluationError {
                        message: format!("Input {} validation returned false", i),
                        source_txid: String::new(),
                        source_output_index: 0,
                        context: crate::script::ExecutionContext::UnlockingScript,
                        program_counter: 0,
                        stack: vec![],
                        alt_stack: vec![],
                        if_stack: vec![],
                        stack_mem: 0,
                        alt_stack_mem: 0,
                    }));
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

// ============================================================================
// UTXO Provider
// ============================================================================

/// Trait for looking up UTXOs for spend validation.
///
/// Transaction validation requires knowing the locking scripts and values
/// of the UTXOs being spent. This trait abstracts UTXO lookup.
pub trait UtxoProvider {
    /// Look up a UTXO by transaction ID and output index.
    ///
    /// Returns the satoshi value and locking script if found.
    fn get_utxo(&self, txid: &[u8; 32], output_index: u32) -> Option<(u64, LockingScript)>;
}

// ============================================================================
// Simple Implementations for Testing
// ============================================================================

/// A simple UTXO for testing purposes.
#[derive(Debug, Clone)]
pub struct SimpleUtxo {
    /// Satoshi value.
    pub satoshis: u64,
    /// Locking script.
    pub locking_script: LockingScript,
}

impl TransactionOutputContext for SimpleUtxo {
    fn satoshis(&self) -> u64 {
        self.satoshis
    }

    fn locking_script(&self) -> &LockingScript {
        &self.locking_script
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_utxo() {
        let utxo = SimpleUtxo {
            satoshis: 100_000,
            locking_script: LockingScript::from_asm("OP_DUP OP_HASH160").unwrap(),
        };

        assert_eq!(utxo.satoshis(), 100_000);
        assert!(utxo.locking_script().to_asm().contains("OP_DUP"));
    }
}
