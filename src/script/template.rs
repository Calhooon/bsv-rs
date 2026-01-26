//! Script template trait and types.
//!
//! This module provides the [`ScriptTemplate`] trait for creating reusable script patterns,
//! and the [`ScriptTemplateUnlock`] type for generating unlocking scripts.
//!
//! # Example
//!
//! ```rust,ignore
//! use bsv_sdk::script::templates::P2PKH;
//! use bsv_sdk::script::template::ScriptTemplate;
//!
//! let template = P2PKH::new();
//! let locking_script = template.lock(&pubkey_hash)?;
//! ```

use crate::primitives::bsv::sighash::{
    compute_sighash_for_signing, parse_transaction, SighashParams, SIGHASH_ALL, SIGHASH_ANYONECANPAY,
    SIGHASH_FORKID, SIGHASH_NONE, SIGHASH_SINGLE,
};
use crate::primitives::bsv::TransactionSignature;
use crate::primitives::ec::PrivateKey;
use crate::script::{LockingScript, UnlockingScript};
use crate::Result;

// Re-export for convenience
pub use crate::script::Script;

/// Specifies which outputs to sign in a transaction signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignOutputs {
    /// Sign all outputs (SIGHASH_ALL).
    All,
    /// Sign no outputs (SIGHASH_NONE).
    None,
    /// Sign only the output at the same index as the input (SIGHASH_SINGLE).
    Single,
}

impl SignOutputs {
    /// Converts to the sighash flag value.
    pub fn to_sighash_flag(self) -> u32 {
        match self {
            SignOutputs::All => SIGHASH_ALL,
            SignOutputs::None => SIGHASH_NONE,
            SignOutputs::Single => SIGHASH_SINGLE,
        }
    }
}

/// Context for signing a transaction input.
///
/// This provides all the information needed to compute a sighash and produce
/// a signature for a specific input.
#[derive(Debug, Clone)]
pub struct SigningContext<'a> {
    /// The raw transaction bytes being signed.
    pub raw_tx: &'a [u8],
    /// The index of the input being signed.
    pub input_index: usize,
    /// The satoshi value of the UTXO being spent.
    pub source_satoshis: u64,
    /// The locking script of the UTXO being spent.
    pub locking_script: &'a Script,
}

impl<'a> SigningContext<'a> {
    /// Creates a new signing context.
    pub fn new(
        raw_tx: &'a [u8],
        input_index: usize,
        source_satoshis: u64,
        locking_script: &'a Script,
    ) -> Self {
        Self {
            raw_tx,
            input_index,
            source_satoshis,
            locking_script,
        }
    }

    /// Computes the sighash for this input with the given scope.
    ///
    /// The scope should include SIGHASH_FORKID for BSV transactions.
    pub fn compute_sighash(&self, scope: u32) -> Result<[u8; 32]> {
        let tx = parse_transaction(self.raw_tx)?;
        let subscript = self.locking_script.to_binary();

        Ok(compute_sighash_for_signing(&SighashParams {
            version: tx.version,
            inputs: &tx.inputs,
            outputs: &tx.outputs,
            locktime: tx.locktime,
            input_index: self.input_index,
            subscript: &subscript,
            satoshis: self.source_satoshis,
            scope,
        }))
    }
}

/// Computes the sighash scope byte from options.
///
/// # Arguments
///
/// * `sign_outputs` - Which outputs to sign
/// * `anyone_can_pay` - Whether to allow other inputs to be added
///
/// # Returns
///
/// The sighash scope value (always includes SIGHASH_FORKID for BSV)
pub fn compute_sighash_scope(sign_outputs: SignOutputs, anyone_can_pay: bool) -> u32 {
    let mut scope = SIGHASH_FORKID | sign_outputs.to_sighash_flag();

    if anyone_can_pay {
        scope |= SIGHASH_ANYONECANPAY;
    }

    scope
}

/// A trait for reusable script patterns.
///
/// Script templates provide a high-level API for creating common script types
/// like P2PKH (Pay-to-Public-Key-Hash) and RPuzzle scripts.
///
/// # Example
///
/// ```rust,ignore
/// use bsv_sdk::script::templates::P2PKH;
/// use bsv_sdk::script::template::ScriptTemplate;
///
/// let template = P2PKH::new();
/// let locking_script = template.lock(&pubkey_hash)?;
/// ```
pub trait ScriptTemplate {
    /// Creates a locking script with the given parameters.
    ///
    /// # Arguments
    ///
    /// * `params` - The parameters required to create the locking script.
    ///   For P2PKH, this is the 20-byte public key hash.
    ///   For RPuzzle, this is the R value or its hash.
    ///
    /// # Returns
    ///
    /// The locking script, or an error if parameters are invalid.
    fn lock(&self, params: &[u8]) -> Result<LockingScript>;
}

/// Return type for template unlock methods.
///
/// Contains functions to sign a transaction input and estimate the
/// unlocking script length.
#[allow(clippy::type_complexity)]
pub struct ScriptTemplateUnlock {
    sign_fn: Box<dyn Fn(&SigningContext) -> Result<UnlockingScript> + Send + Sync>,
    estimate_length_fn: Box<dyn Fn() -> usize + Send + Sync>,
}

impl ScriptTemplateUnlock {
    /// Creates a new ScriptTemplateUnlock.
    ///
    /// # Arguments
    ///
    /// * `sign_fn` - A function that signs a transaction input
    /// * `estimate_length_fn` - A function that estimates the unlocking script length
    pub fn new<S, E>(sign_fn: S, estimate_length_fn: E) -> Self
    where
        S: Fn(&SigningContext) -> Result<UnlockingScript> + Send + Sync + 'static,
        E: Fn() -> usize + Send + Sync + 'static,
    {
        Self {
            sign_fn: Box::new(sign_fn),
            estimate_length_fn: Box::new(estimate_length_fn),
        }
    }

    /// Signs a transaction input to produce an unlocking script.
    ///
    /// # Arguments
    ///
    /// * `context` - The signing context with transaction data
    ///
    /// # Returns
    ///
    /// The unlocking script, or an error if signing fails.
    pub fn sign(&self, context: &SigningContext) -> Result<UnlockingScript> {
        (self.sign_fn)(context)
    }

    /// Estimates the unlocking script length in bytes.
    ///
    /// This is useful for fee estimation before the actual signature is created.
    pub fn estimate_length(&self) -> usize {
        (self.estimate_length_fn)()
    }
}

impl std::fmt::Debug for ScriptTemplateUnlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScriptTemplateUnlock")
            .field("estimate_length", &self.estimate_length())
            .finish_non_exhaustive()
    }
}

/// Helper function to create a transaction signature.
///
/// Signs the sighash with the private key and returns a TransactionSignature.
pub fn create_transaction_signature(
    private_key: &PrivateKey,
    sighash: &[u8; 32],
    scope: u32,
) -> Result<TransactionSignature> {
    let signature = private_key.sign(sighash)?;
    Ok(TransactionSignature::new(signature, scope))
}

/// Helper function to build an unlocking script from signature and public key.
///
/// Creates an unlocking script with the signature in checksig format followed
/// by the compressed public key.
pub fn build_p2pkh_unlocking_script(
    tx_sig: &TransactionSignature,
    private_key: &PrivateKey,
) -> UnlockingScript {
    let sig_bytes = tx_sig.to_checksig_format();
    let pubkey_bytes = private_key.public_key().to_compressed();

    let mut script = Script::new();
    script.write_bin(&sig_bytes).write_bin(&pubkey_bytes);

    UnlockingScript::from_script(script)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_outputs_to_sighash() {
        assert_eq!(SignOutputs::All.to_sighash_flag(), SIGHASH_ALL);
        assert_eq!(SignOutputs::None.to_sighash_flag(), SIGHASH_NONE);
        assert_eq!(SignOutputs::Single.to_sighash_flag(), SIGHASH_SINGLE);
    }

    #[test]
    fn test_compute_sighash_scope() {
        // Standard BSV signature: ALL | FORKID
        assert_eq!(
            compute_sighash_scope(SignOutputs::All, false),
            SIGHASH_ALL | SIGHASH_FORKID
        );

        // With ANYONECANPAY
        assert_eq!(
            compute_sighash_scope(SignOutputs::All, true),
            SIGHASH_ALL | SIGHASH_FORKID | SIGHASH_ANYONECANPAY
        );

        // NONE | FORKID
        assert_eq!(
            compute_sighash_scope(SignOutputs::None, false),
            SIGHASH_NONE | SIGHASH_FORKID
        );

        // SINGLE | FORKID | ANYONECANPAY
        assert_eq!(
            compute_sighash_scope(SignOutputs::Single, true),
            SIGHASH_SINGLE | SIGHASH_FORKID | SIGHASH_ANYONECANPAY
        );
    }
}
