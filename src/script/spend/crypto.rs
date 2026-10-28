//! The crypto opcodes: the hashes, `OP_CODESEPARATOR`, `OP_CHECKSIG` and
//! `OP_CHECKMULTISIG`; the signature and public key encoding rules, the
//! scriptCode a signature commits to, and the sighash dispatch it is verified
//! against.

use crate::primitives::bsv::sighash::SIGHASH_FORKID;
use crate::primitives::bsv::tx_signature::TransactionSignature;
use crate::primitives::ec::PublicKey;
use crate::primitives::{hash160, ripemd160, sha1, sha256, sha256d, BigNumber};
use crate::script::evaluation_error::{ExecutionContext, ScriptEvaluationError};
use crate::script::op::{opcode_to_name, OP_CHECKMULTISIGVERIFY, OP_CHECKSIGVERIFY};
use crate::script::{Script, ScriptChunk};

use super::limits::MAX_MULTISIG_KEY_COUNT;
use super::Spend;

/// Whether the signature's `r` or `s` is at or above the curve order: the
/// reference's lax DER parse (`ecdsa_signature_parse_der_lax`, pubkey.cpp:146-173)
/// overwrites such a signature with the all-zero one, which is low for
/// `CheckLowS` (356-365) and never verifies.
pub(super) fn signature_overflows_the_order(sig: &TransactionSignature) -> bool {
    let n = BigNumber::secp256k1_order();
    BigNumber::from_bytes_be(sig.r()) >= n || BigNumber::from_bytes_be(sig.s()) >= n
}

/// Whether a signature's hash type carries `SIGHASH_FORKID`; an empty
/// signature has no hash type (`GetHashType`, interpreter.cpp:246-252).
pub(super) fn has_forkid_bit(sig: &[u8]) -> bool {
    sig.last().is_some_and(|t| t & (SIGHASH_FORKID as u8) != 0)
}

/// Validates DER signature encoding (simplified check).
pub(super) fn is_valid_signature_encoding(sig: &[u8]) -> bool {
    if sig.len() < 9 || sig.len() > 73 {
        return false;
    }

    // Sequence tag
    if sig[0] != 0x30 {
        return false;
    }

    // Length check
    if sig[1] as usize != sig.len() - 3 {
        return false;
    }

    // R value
    if sig[2] != 0x02 {
        return false;
    }

    let r_len = sig[3] as usize;
    if r_len == 0 || 5 + r_len >= sig.len() {
        return false;
    }

    // S value
    let s_offset = 4 + r_len;
    if sig[s_offset] != 0x02 {
        return false;
    }

    let s_len = sig[s_offset + 1] as usize;
    if s_len == 0 {
        return false;
    }

    // Check total length
    if r_len + s_len + 7 != sig.len() {
        return false;
    }

    // Check R not negative
    if (sig[4] & 0x80) != 0 {
        return false;
    }

    // Check R not excessively padded
    if r_len > 1 && sig[4] == 0x00 && (sig[5] & 0x80) == 0 {
        return false;
    }

    // Check S not negative
    let s_value_offset = s_offset + 2;
    if (sig[s_value_offset] & 0x80) != 0 {
        return false;
    }

    // Check S not excessively padded
    if s_len > 1 && sig[s_value_offset] == 0x00 && (sig[s_value_offset + 1] & 0x80) == 0 {
        return false;
    }

    true
}

impl Spend {
    pub(super) fn op_ripemd160(&mut self) -> Result<(), ScriptEvaluationError> {
        if self.stack.is_empty() {
            return Err(self.error("OP_RIPEMD160 requires at least one item to be on the stack."));
        }
        let buf = self.pop_stack()?;
        self.charge_work(buf.len() as u64)?;
        let hash = ripemd160(&buf);
        self.push_stack(hash.to_vec())?;
        Ok(())
    }

    pub(super) fn op_sha1(&mut self) -> Result<(), ScriptEvaluationError> {
        if self.stack.is_empty() {
            return Err(self.error("OP_SHA1 requires at least one item to be on the stack."));
        }
        let buf = self.pop_stack()?;
        self.charge_work(buf.len() as u64)?;
        let hash = sha1(&buf);
        self.push_stack(hash.to_vec())?;
        Ok(())
    }

    pub(super) fn op_sha256(&mut self) -> Result<(), ScriptEvaluationError> {
        if self.stack.is_empty() {
            return Err(self.error("OP_SHA256 requires at least one item to be on the stack."));
        }
        let buf = self.pop_stack()?;
        self.charge_work(buf.len() as u64)?;
        let hash = sha256(&buf);
        self.push_stack(hash.to_vec())?;
        Ok(())
    }

    pub(super) fn op_hash160(&mut self) -> Result<(), ScriptEvaluationError> {
        if self.stack.is_empty() {
            return Err(self.error("OP_HASH160 requires at least one item to be on the stack."));
        }
        let buf = self.pop_stack()?;
        self.charge_work(buf.len() as u64 + 32)?;
        let hash = hash160(&buf);
        self.push_stack(hash.to_vec())?;
        Ok(())
    }

    pub(super) fn op_hash256(&mut self) -> Result<(), ScriptEvaluationError> {
        if self.stack.is_empty() {
            return Err(self.error("OP_HASH256 requires at least one item to be on the stack."));
        }
        let buf = self.pop_stack()?;
        self.charge_work(buf.len() as u64 + 32)?;
        let hash = sha256d(&buf);
        self.push_stack(hash.to_vec())?;
        Ok(())
    }

    pub(super) fn op_codeseparator(&mut self) {
        self.last_code_separator = Some(self.program_counter);
    }

    pub(super) fn op_checksig(&mut self, opcode: u8) -> Result<(), ScriptEvaluationError> {
        self.require_two_items(opcode, "OP_CHECKSIG")?;
        let pubkey_bytes = self.pop_stack()?;
        let sig_bytes = self.pop_stack()?;

        // Validate encodings
        self.check_signature_encoding(&sig_bytes)?;
        self.check_public_key_encoding(&pubkey_bytes)?;

        // Build subscript
        let subscript = self.build_subscript(&sig_bytes)?;

        // Verify signature
        let success = if sig_bytes.is_empty() {
            false
        } else {
            self.verify_signature(&sig_bytes, &pubkey_bytes, &subscript)?
        };

        // NULLFAIL (interpreter.cpp:1491-1497, under the version gate):
        // a signature that fails must be the empty vector.
        if !success && self.require_null_fail && !sig_bytes.is_empty() {
            return Err(self.error(&format!(
                "{} requires failing signatures to be empty.",
                opcode_to_name(opcode).unwrap_or("OP_CHECKSIG")
            )));
        }

        self.push_stack(if success { vec![1] } else { vec![] })?;

        if opcode == OP_CHECKSIGVERIFY {
            if !success {
                return Err(
                    self.error("OP_CHECKSIGVERIFY requires that a valid signature is provided.")
                );
            }
            self.pop_stack()?;
        }
        Ok(())
    }

    // ========================================================================
    // OP_CHECKMULTISIG Implementation
    // ========================================================================

    pub(super) fn op_checkmultisig(&mut self, opcode: u8) -> Result<(), ScriptEvaluationError> {
        // Get number of public keys
        if self.stack.is_empty() {
            return Err(self.error(&format!(
                "{} requires at least 1 item for nKeys.",
                opcode_to_name(opcode).unwrap_or("OP_CHECKMULTISIG")
            )));
        }

        let n_keys_bytes = self.pop_stack()?;
        let n_keys_bn = self.read_count(&n_keys_bytes)?;
        let n_keys = n_keys_bn.to_i64().unwrap_or(-1);

        if !(0..=MAX_MULTISIG_KEY_COUNT).contains(&n_keys) {
            return Err(self.error(&format!(
                "{} requires a key count between 0 and {}.",
                opcode_to_name(opcode).unwrap_or("OP_CHECKMULTISIG"),
                MAX_MULTISIG_KEY_COUNT
            )));
        }
        let n_keys = n_keys as usize;

        // Get public keys
        if self.stack.len() < n_keys {
            return Err(self.error(&format!(
                "{} stack too small for keys. Need {}, have {}.",
                opcode_to_name(opcode).unwrap_or("OP_CHECKMULTISIG"),
                n_keys,
                self.stack.len()
            )));
        }

        let mut pubkeys = Vec::with_capacity(n_keys);
        for _ in 0..n_keys {
            pubkeys.push(self.pop_stack()?);
        }

        // Get number of signatures
        if self.stack.is_empty() {
            return Err(self.error(&format!(
                "{} requires item for nSigs.",
                opcode_to_name(opcode).unwrap_or("OP_CHECKMULTISIG")
            )));
        }

        let n_sigs_bytes = self.pop_stack()?;
        let n_sigs_bn = self.read_count(&n_sigs_bytes)?;
        let n_sigs = n_sigs_bn.to_i64().unwrap_or(-1);

        if n_sigs < 0 || n_sigs as usize > n_keys {
            return Err(self.error(&format!(
                "{} requires the number of signatures to be no greater than the number of keys.",
                opcode_to_name(opcode).unwrap_or("OP_CHECKMULTISIG")
            )));
        }
        let n_sigs = n_sigs as usize;

        // Get signatures
        if self.stack.len() < n_sigs {
            return Err(self.error(&format!(
                "{} stack too small for sigs. Need {}, have {}.",
                opcode_to_name(opcode).unwrap_or("OP_CHECKMULTISIG"),
                n_sigs,
                self.stack.len()
            )));
        }

        let mut sigs = Vec::with_capacity(n_sigs);
        for _ in 0..n_sigs {
            sigs.push(self.pop_stack()?);
        }

        // Build subscript and remove all signatures
        let base_script = match self.context {
            ExecutionContext::UnlockingScript => self.unlocking_script.as_script().clone(),
            ExecutionContext::LockingScript => self.locking_script.as_script().clone(),
        };
        let start_idx = self.last_code_separator.map(|i| i + 1).unwrap_or(0);
        let chunks = base_script.chunks();
        let mut subscript_chunks: Vec<ScriptChunk> = chunks.into_iter().skip(start_idx).collect();
        // See build_subscript: unlock-context subscripts continue into the
        // full locking script (combined-script semantics, ts-sdk parity).
        if self.context == ExecutionContext::UnlockingScript {
            subscript_chunks.extend(self.locking_script.as_script().chunks());
        }
        let mut subscript = Script::from_chunks(subscript_chunks);

        // CleanupScriptCode (interpreter.cpp:255-263, applied per signature at
        // 1573-1578): a signature's push is deleted from the scriptCode only when
        // it does not carry SIGHASH_FORKID; FORKID is always enabled here, so
        // only an empty signature (no hash type) is deleted, as an OP_0 push.
        for sig in &sigs {
            if !has_forkid_bit(sig) {
                let mut sig_script = Script::new();
                sig_script.write_bin(sig);
                subscript.find_and_delete(&sig_script);
            }
        }

        // Verify signatures
        let mut success = true;
        let mut sig_idx = 0;
        let mut key_idx = 0;

        while success && sig_idx < n_sigs {
            if key_idx >= n_keys {
                success = false;
                break;
            }

            let sig_bytes = &sigs[sig_idx];
            let pubkey_bytes = &pubkeys[key_idx];

            // Validate encodings
            if self.check_signature_encoding(sig_bytes).is_err()
                || self.check_public_key_encoding(pubkey_bytes).is_err()
            {
                return Err(self.error(&format!(
                    "{} requires correct encoding for the public key and signature.",
                    opcode_to_name(opcode).unwrap_or("OP_CHECKMULTISIG")
                )));
            }

            let sig_valid = if sig_bytes.is_empty() {
                false
            } else {
                self.verify_signature(sig_bytes, pubkey_bytes, &subscript)?
            };

            if sig_valid {
                sig_idx += 1;
            }
            key_idx += 1;

            if n_sigs - sig_idx > n_keys - key_idx {
                success = false;
            }
        }

        // NULLFAIL (interpreter.cpp:1640-1646, under the version gate): when
        // the operation fails, every signature must be the empty vector.
        if !success && self.require_null_fail && sigs.iter().any(|s| !s.is_empty()) {
            return Err(self.error(&format!(
                "{} requires failing signatures to be empty.",
                opcode_to_name(opcode).unwrap_or("OP_CHECKMULTISIG")
            )));
        }

        // Pop the dummy element. NULLDUMMY (interpreter.cpp:1664-1670, under
        // the version gate) requires it to be empty.
        if self.stack.is_empty() {
            return Err(self.error(&format!(
                "{} requires an extra item (dummy) to be on the stack.",
                opcode_to_name(opcode).unwrap_or("OP_CHECKMULTISIG")
            )));
        }
        let dummy = self.pop_stack()?;
        if self.require_null_dummy && !dummy.is_empty() {
            return Err(self.error(&format!(
                "{} requires the extra stack item (dummy) to be empty.",
                opcode_to_name(opcode).unwrap_or("OP_CHECKMULTISIG")
            )));
        }

        self.push_stack(if success { vec![1] } else { vec![] })?;

        if opcode == OP_CHECKMULTISIGVERIFY {
            if !success {
                return Err(self.error(
                    "OP_CHECKMULTISIGVERIFY requires that a sufficient number of valid signatures are provided.",
                ));
            }
            self.pop_stack()?;
        }

        Ok(())
    }

    // ========================================================================
    // Signature Verification Helpers
    // ========================================================================

    pub(super) fn check_signature_encoding(&self, sig: &[u8]) -> Result<(), ScriptEvaluationError> {
        if sig.is_empty() {
            return Ok(());
        }

        // Check basic DER format
        if !is_valid_signature_encoding(sig) {
            return Err(self.error("The signature format is invalid."));
        }

        // Parse and check additional requirements
        let tx_sig = TransactionSignature::from_checksig_format(sig)
            .map_err(|_| self.error("The signature format is invalid."))?;

        // LOW_S as the reference checks it (`CPubKey::CheckLowS`, pubkey.cpp:356-365):
        // the lax parser (146-173) turns an `r` or `s` at or above the curve order
        // into the zero signature, which is low, so the check passes and the
        // signature fails to verify afterwards (NULLFAIL under the flag, else a
        // false top). Only n/2 < s < n is a high-S refusal.
        if self.require_low_s && !tx_sig.has_low_s() && !signature_overflows_the_order(&tx_sig) {
            return Err(self.error("The signature must have a low S value."));
        }

        self.check_signature_hash_type(tx_sig.scope())?;

        if (tx_sig.scope() & SIGHASH_FORKID) == 0 {
            return Err(self.error("The signature must use SIGHASH_FORKID."));
        }

        Ok(())
    }

    pub(super) fn check_public_key_encoding(
        &self,
        pubkey: &[u8],
    ) -> Result<(), ScriptEvaluationError> {
        if pubkey.is_empty() {
            return Err(self.error("Public key is empty."));
        }

        if pubkey.len() < 33 {
            return Err(self.error("The public key is too short, it must be at least 33 bytes."));
        }

        if pubkey[0] == 0x04 {
            if pubkey.len() != 65 {
                return Err(self.error("The non-compressed public key must be 65 bytes."));
            }
        } else if pubkey[0] == 0x02 || pubkey[0] == 0x03 {
            if pubkey.len() != 33 {
                return Err(self.error("The compressed public key must be 33 bytes."));
            }
        } else {
            return Err(self.error("The public key is in an unknown format."));
        }

        // COMPRESSED_PUBKEYTYPE (interpreter.cpp:322-327): only compressed
        // keys are accepted under the flag.
        if self.require_compressed_pubkey && pubkey[0] == 0x04 {
            return Err(self.error("The public key must be compressed."));
        }

        // Try to parse it
        PublicKey::from_bytes(pubkey)
            .map_err(|_| self.error("The public key is in an unknown format."))?;

        Ok(())
    }

    pub(super) fn build_subscript(
        &self,
        sig_bytes: &[u8],
    ) -> Result<Script, ScriptEvaluationError> {
        let base_script = match self.context {
            ExecutionContext::UnlockingScript => self.unlocking_script.as_script().clone(),
            ExecutionContext::LockingScript => self.locking_script.as_script().clone(),
        };

        let start_idx = self.last_code_separator.map(|i| i + 1).unwrap_or(0);
        let chunks = base_script.chunks();
        let mut subscript_chunks: Vec<ScriptChunk> = chunks.into_iter().skip(start_idx).collect();
        // When a CHECKSIG executes in the unlocking script, the subscript
        // continues across the unlock/lock boundary into the full locking
        // script (legacy combined-script semantics; matches BSV node consensus
        // and ts-sdk). Without this, signatures taken over such a subscript
        // (e.g. OP_PUSH_TX-style contracts) are wrongly rejected.
        if self.context == ExecutionContext::UnlockingScript {
            subscript_chunks.extend(self.locking_script.as_script().chunks());
        }
        let mut subscript = Script::from_chunks(subscript_chunks);

        // CleanupScriptCode (interpreter.cpp:255-263, applied at 1484): the
        // signature's push is deleted from the scriptCode only when the
        // signature does not carry SIGHASH_FORKID (FORKID is always enabled
        // here). A signature that does is hashed with its own push in place, so
        // a signature whose push appears in the scriptCode cannot verify, as on
        // the reference. An empty signature carries no hash type and is deleted
        // as an OP_0 push, as on the reference.
        if !has_forkid_bit(sig_bytes) {
            let mut sig_script = Script::new();
            sig_script.write_bin(sig_bytes);
            subscript.find_and_delete(&sig_script);
        }

        Ok(subscript)
    }

    pub(super) fn verify_signature(
        &mut self,
        sig_bytes: &[u8],
        pubkey_bytes: &[u8],
        subscript: &Script,
    ) -> Result<bool, ScriptEvaluationError> {
        // Parse signature and public key
        let tx_sig = match TransactionSignature::from_checksig_format(sig_bytes) {
            Ok(s) => s,
            Err(_) => return Ok(false),
        };

        let pubkey = match PublicKey::from_bytes(pubkey_bytes) {
            Ok(p) => p,
            Err(_) => return Ok(false),
        };

        // The digest, dispatched as the reference's `SignatureHash` does
        // (`interpreter.cpp:2112-2124`; FORKID is always enabled here): BIP143
        // for a FORKID type without the CHRONICLE bit, the original digest
        // otherwise (Calhooon/bsv-rs#22). The BIP143 midstates are the
        // transaction's, shared by every input's spend (bsv-low #591).
        let script_bytes = subscript.to_binary();
        if self.work_limit.is_some() {
            let cost =
                self.transaction
                    .hashing_work(self.input_index, &script_bytes, tx_sig.scope());
            self.charge_work(cost)?;
        }
        let sighash = self.transaction.sighash_dispatched_for_signing(
            self.input_index,
            &script_bytes,
            self.source_satoshis,
            tx_sig.scope(),
        );

        // Verify
        Ok(pubkey.verify(&sighash, tx_sig.signature()))
    }
}
