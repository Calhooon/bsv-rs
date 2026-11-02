//! Script template trait and types.
//!
//! This module provides the [`ScriptTemplate`] trait for creating reusable script patterns,
//! and the [`ScriptTemplateUnlock`] type for generating unlocking scripts.
//!
//! # Example
//!
//! ```rust,ignore
//! use bsv_rs::script::templates::P2PKH;
//! use bsv_rs::script::template::ScriptTemplate;
//!
//! let template = P2PKH::new();
//! let locking_script = template.lock(&pubkey_hash)?;
//! ```

use crate::primitives::bsv::sighash::{
    after_last_code_separator, compute_sighash_dispatched_for_signing, parse_transaction,
    SighashParams, SIGHASH_ALL, SIGHASH_ANYONECANPAY, SIGHASH_FORKID, SIGHASH_NONE, SIGHASH_SINGLE,
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
///
/// # The scriptCode
///
/// The signature commits to a scriptCode, and where the CHECKSIG executes
/// decides what it is: the context cannot know that, so it is an input.
/// Without an override ([`SigningContext::script_code`] `None`) the scriptCode
/// is the source output's locking script, which is what the node signs for a
/// CHECKSIG in the locking script that no `OP_CODESEPARATOR` precedes
/// (bitcoin-sv v1.2.3 `src/script/interpreter.cpp:1471-1473`: the script from
/// the last executed separator to its end). It is wrong in two cases, and the
/// override ([`SigningContext::with_script_code`]) is what to pass:
///
/// - a CHECKSIG in the locking script after an executed `OP_CODESEPARATOR`:
///   pass the locking script's bytes after that separator;
/// - a CHECKSIG executing inside the UNLOCKING script of a post-Chronicle
///   spend: the node signs the unlocking script from its last executed
///   separator to its end followed by the locking script
///   (`interpreter.cpp:1474-1481`, CHECKMULTISIG `:1569-1576`, gated on
///   `IsChronicle(flags)`; `VerifyScript` passes the scriptPubKey as
///   `checksigData`, `:2336-2342`): pass [`chronicle_unlocking_script_code`].
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
    /// The scriptCode the signature commits to when it is not the locking
    /// script (see the type's documentation for when it is not); `None` signs
    /// over `locking_script`.
    pub script_code: Option<&'a Script>,
}

impl<'a> SigningContext<'a> {
    /// Creates a new signing context, its scriptCode the locking script.
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
            script_code: None,
        }
    }

    /// The same context signing over `script_code` in place of the locking
    /// script: the bytes the CHECKSIG's scriptCode holds at the site where it
    /// executes (for a CHECKSIG in a post-Chronicle unlocking script,
    /// [`chronicle_unlocking_script_code`]). The bytes are signed as given:
    /// under the BIP143 digest whole, under the original digest with their
    /// `OP_CODESEPARATOR`s removed, as the node serializes them
    /// (`interpreter.cpp:1864-1892`).
    pub fn with_script_code(mut self, script_code: &'a Script) -> Self {
        self.script_code = Some(script_code);
        self
    }

    /// Computes the digest a signature over this input with the hash type
    /// `scope` must verify against, in the internal byte order ECDSA signs.
    ///
    /// The digest is chosen as the node's `SignatureHash` chooses it
    /// (bitcoin-sv v1.2.3 `interpreter.cpp:2112-2124`), through
    /// [`compute_sighash_dispatched_for_signing`]: BIP143 when `scope` carries
    /// `SIGHASH_FORKID` and not `SIGHASH_CHRONICLE`, the original digest
    /// otherwise, and under the original digest the constant `one` (`0x01`
    /// then 31 zero bytes) when `SIGHASH_SINGLE` names an output the
    /// transaction does not have (`:2095-2100`).
    ///
    /// # Errors
    ///
    /// The transaction does not parse, or it has no input at `input_index`.
    pub fn compute_sighash(&self, scope: u32) -> Result<[u8; 32]> {
        let tx = parse_transaction(self.raw_tx)?;
        if self.input_index >= tx.inputs.len() {
            return Err(crate::Error::CryptoError(format!(
                "Input index {} out of range (transaction has {} inputs)",
                self.input_index,
                tx.inputs.len()
            )));
        }
        let subscript = self.script_code.unwrap_or(self.locking_script).to_binary();

        Ok(compute_sighash_dispatched_for_signing(&SighashParams {
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

/// The scriptCode of a CHECKSIG executing inside the unlocking script of a
/// post-Chronicle spend: the bytes of `unlocking_script` after its last
/// `OP_CODESEPARATOR` (all of it when it has none), followed by
/// `locking_script` (bitcoin-sv v1.2.3 `src/script/interpreter.cpp:1471-1481`,
/// CHECKMULTISIG `:1569-1576`; the node's `VerifyScript` passes the
/// scriptPubKey as `checksigData`, `:2336-2342`). Pass it to [`SigningContext::with_script_code`].
///
/// `unlocking_script` is the script as it will be spent; its bytes before the
/// last separator are not signed, so a signature pushed there can be a
/// placeholder while the digest is computed. The helper assumes the CHECKSIG
/// executes after the unlocking script's last separator and that separator
/// executes (none sits in an unexecuted branch or after the CHECKSIG); for any
/// other layout form the scriptCode by hand from the separator the node last
/// executed before the CHECKSIG. A separator is the opcode as the node's
/// parser reads it, never a `0xab` inside push data.
///
/// Before Chronicle a CHECKSIG in the unlocking script signs the unlocking
/// script from its last executed separator to its end alone, without the
/// locking script (`interpreter.cpp:1471`, the lock appended only under
/// `IsChronicle(flags)`, `:1474`); such a CHECKSIG executes only where the
/// unlocking script need not be push-only (pre-Genesis; after Genesis
/// `VerifyScript` refuses it, and after Chronicle it still does for a
/// non-malleable transaction version, `:2321-2330`). For a CHECKSIG in the
/// locking script no unlocking script byte is signed; the context's default
/// is right there.
///
/// Under a hash type with `SIGHASH_FORKID` (CHRONICLE or not) the node
/// deletes nothing from the scriptCode; without it the node deletes the
/// signature's own push (`CleanupScriptCode`, `:255-263`), which neither this
/// helper nor `SigningContext` does: it only matters when the signature is
/// pushed after the last separator, and then the caller removes it from the
/// scriptCode it passes.
pub fn chronicle_unlocking_script_code(
    unlocking_script: &Script,
    locking_script: &Script,
) -> Script {
    let unlocking = unlocking_script.to_binary();
    let mut code = after_last_code_separator(&unlocking).to_vec();
    code.extend_from_slice(&locking_script.to_binary());
    Script::from_binary(&code).unwrap_or_default()
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
/// use bsv_rs::script::templates::P2PKH;
/// use bsv_rs::script::template::ScriptTemplate;
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

    /// #603: the unlock's `Debug` follows the Rust API Guidelines' C-DEBUG
    /// (every public type implements `Debug`) and C-DEBUG-NONEMPTY (a `Debug`
    /// representation is never empty),
    /// <https://rust-lang.github.io/api-guidelines/debuggability.html>: the
    /// text is non-empty, names the type, shows the one field it can show (the
    /// estimate's value; the two functions are opaque) and marks the rest
    /// elided. Kills `template.rs:299:9` (`fmt` answering `Ok(())` and writing
    /// nothing).
    #[test]
    fn the_unlock_debug_is_nonempty_and_names_its_estimate_c_debug_nonempty_603() {
        let unlock = ScriptTemplateUnlock::new(|_| Ok(UnlockingScript::new()), || 74);
        let text = format!("{unlock:?}");
        assert!(
            !text.is_empty(),
            "C-DEBUG-NONEMPTY: the representation is empty"
        );
        assert!(text.starts_with("ScriptTemplateUnlock"), "{text}");
        assert!(text.contains("estimate_length: 74"), "{text}");
        assert!(text.contains(".."), "the opaque rest is not elided: {text}");
    }
}
