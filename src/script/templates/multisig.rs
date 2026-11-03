//! Multisig (M-of-N) script template.
//!
//! This module provides the [`Multisig`] template for creating and spending
//! M-of-N multi-signature outputs using OP_CHECKMULTISIG.
//!
//! # Locking Script Pattern
//!
//! ```text
//! OP_M <pubkey1> <pubkey2> ... <pubkeyN> OP_N OP_CHECKMULTISIG
//! ```
//!
//! # Unlocking Script Pattern
//!
//! ```text
//! OP_0 <sig1> <sig2> ... <sigM>
//! ```
//!
//! The leading OP_0 is required due to a historical off-by-one bug in
//! Bitcoin's OP_CHECKMULTISIG implementation.
//!
//! # Example
//!
//! ```rust,ignore
//! use bsv_rs::script::templates::Multisig;
//! use bsv_rs::script::template::SignOutputs;
//! use bsv_rs::primitives::ec::PrivateKey;
//!
//! let key1 = PrivateKey::random();
//! let key2 = PrivateKey::random();
//! let key3 = PrivateKey::random();
//!
//! // Create 2-of-3 multisig locking script
//! let template = Multisig::new(2);
//! let pubkeys = vec![
//!     key1.public_key(),
//!     key2.public_key(),
//!     key3.public_key(),
//! ];
//! let locking = template.lock_from_keys(&pubkeys)?;
//!
//! // Sign with keys 1 and 3 (in order matching the locking script)
//! let signers = vec![key1.clone(), key3.clone()];
//! let unlock = Multisig::unlock(&signers, SignOutputs::All, false);
//! let unlocking = unlock.sign(&context)?;
//! ```

use crate::error::Error;
use crate::primitives::bsv::TransactionSignature;
use crate::primitives::ec::{PrivateKey, PublicKey};
use crate::script::op::*;
use crate::script::template::{
    compute_sighash_scope, ScriptTemplate, ScriptTemplateUnlock, SignOutputs, SigningContext,
};
use crate::script::{LockingScript, Script, ScriptChunk, UnlockingScript};
use crate::Result;

/// Converts a small integer (1-16) to its opcode (OP_1 through OP_16).
fn small_int_to_opcode(n: u8) -> Result<u8> {
    if (1..=16).contains(&n) {
        Ok(OP_1 + n - 1)
    } else {
        Err(Error::CryptoError(format!(
            "Value {} out of range for small int opcode (1-16)",
            n
        )))
    }
}

/// Multisig (M-of-N) script template.
///
/// Creates scripts that require M signatures from a set of N public keys.
/// The threshold M is stored in the template; the public keys are provided
/// when creating the locking script.
///
/// # Signature Order
///
/// Signatures in the unlocking script must appear in the same order as their
/// corresponding public keys in the locking script. The OP_CHECKMULTISIG
/// opcode walks through keys and signatures in order, matching each signature
/// to the next available key.
#[derive(Debug, Clone)]
pub struct Multisig {
    /// M — the number of required signatures.
    pub threshold: u8,
}

impl Multisig {
    /// Creates a new Multisig template with the given threshold.
    ///
    /// # Arguments
    ///
    /// * `threshold` - The number of signatures required (M). Must be 1-16.
    pub fn new(threshold: u8) -> Self {
        Self { threshold }
    }

    /// Creates a multisig locking script from public keys.
    ///
    /// This is the recommended API. Keys are encoded in compressed form (33 bytes).
    ///
    /// # Arguments
    ///
    /// * `pubkeys` - The N public keys. Must have 1-16 keys, and threshold <= N.
    pub fn lock_from_keys(&self, pubkeys: &[PublicKey]) -> Result<LockingScript> {
        let m = self.threshold;
        let n = pubkeys.len();

        if m == 0 || m > 16 {
            return Err(Error::CryptoError(format!(
                "Threshold must be 1-16, got {}",
                m
            )));
        }
        if n == 0 || n > 16 {
            return Err(Error::CryptoError(format!(
                "Number of keys must be 1-16, got {}",
                n
            )));
        }
        if (m as usize) > n {
            return Err(Error::CryptoError(format!(
                "Threshold {} exceeds number of keys {}",
                m, n
            )));
        }

        let mut chunks = Vec::with_capacity(n + 3);

        // OP_M
        chunks.push(ScriptChunk::new_opcode(small_int_to_opcode(m)?));

        // Push each compressed pubkey
        for pk in pubkeys {
            let compressed = pk.to_compressed();
            chunks.push(ScriptChunk::new(
                compressed.len() as u8,
                Some(compressed.to_vec()),
            ));
        }

        // OP_N
        chunks.push(ScriptChunk::new_opcode(small_int_to_opcode(n as u8)?));

        // OP_CHECKMULTISIG
        chunks.push(ScriptChunk::new_opcode(OP_CHECKMULTISIG));

        Ok(LockingScript::from_chunks(chunks))
    }

    /// Creates an unlock template for spending a multisig output.
    ///
    /// # Arguments
    ///
    /// * `signers` - The M private keys to sign with. Must be in the same
    ///   order as their corresponding public keys appear in the locking script.
    /// * `sign_outputs` - Which outputs to sign.
    /// * `anyone_can_pay` - Whether to allow other inputs to be added.
    pub fn unlock(
        signers: &[PrivateKey],
        sign_outputs: SignOutputs,
        anyone_can_pay: bool,
    ) -> ScriptTemplateUnlock {
        let keys: Vec<PrivateKey> = signers.to_vec();
        let scope = compute_sighash_scope(sign_outputs, anyone_can_pay);
        let m = keys.len();

        ScriptTemplateUnlock::new(
            move |context: &SigningContext| {
                let sighash = context.compute_sighash(scope)?;

                let mut script = Script::new();
                // OP_0 dummy element (required by OP_CHECKMULTISIG off-by-one bug)
                script.write_opcode(OP_0);

                for key in &keys {
                    let signature = key.sign(&sighash)?;
                    let tx_sig = TransactionSignature::new(signature, scope);
                    script.write_bin(&tx_sig.to_checksig_format());
                }

                Ok(UnlockingScript::from_script(script))
            },
            move || {
                // OP_0 (1 byte) + M signatures (1 push + 72 DER max + 1 sighash each)
                1 + m * 74
            },
        )
    }

    /// Signs with a precomputed sighash.
    ///
    /// # Arguments
    ///
    /// * `signers` - The M private keys to sign with (in pubkey order).
    /// * `sighash` - The precomputed sighash to sign.
    /// * `sign_outputs` - Which outputs to sign (for the scope byte).
    /// * `anyone_can_pay` - Whether to allow other inputs to be added.
    pub fn sign_with_sighash(
        signers: &[PrivateKey],
        sighash: &[u8; 32],
        sign_outputs: SignOutputs,
        anyone_can_pay: bool,
    ) -> Result<UnlockingScript> {
        let scope = compute_sighash_scope(sign_outputs, anyone_can_pay);

        let mut script = Script::new();
        // OP_0 dummy element
        script.write_opcode(OP_0);

        for key in signers {
            let signature = key.sign(sighash)?;
            let tx_sig = TransactionSignature::new(signature, scope);
            script.write_bin(&tx_sig.to_checksig_format());
        }

        Ok(UnlockingScript::from_script(script))
    }
}

impl ScriptTemplate for Multisig {
    /// Creates a multisig locking script from concatenated 33-byte compressed public keys.
    ///
    /// The `params` slice must be a multiple of 33 bytes (each key is 33 bytes compressed).
    /// A key whose tag is not `02`/`03` is refused only where every spend
    /// reaches it (#625): CHECKMULTISIG checks the keys from the last pushed
    /// backwards and stops at the threshold's last match (bitcoin-sv v1.2.3
    /// `interpreter.cpp:1538-1633`), refusing a key it reaches under STRICTENC,
    /// so with `j` the highest index of such a key the lock is refused when
    /// the `n - 1 - j` keys after it cannot meet the threshold.
    fn lock(&self, params: &[u8]) -> Result<LockingScript> {
        if params.is_empty() || !params.len().is_multiple_of(33) {
            return Err(Error::CryptoError(
                "Params must be concatenated 33-byte compressed public keys".to_string(),
            ));
        }

        let n = params.len() / 33;
        if n > 16 {
            return Err(Error::CryptoError(format!("Too many keys: {} (max 16)", n)));
        }
        if (self.threshold as usize) > n {
            return Err(Error::CryptoError(format!(
                "Threshold {} exceeds number of keys {}",
                self.threshold, n
            )));
        }

        let mut chunks = Vec::with_capacity(n + 3);
        chunks.push(ScriptChunk::new_opcode(small_int_to_opcode(
            self.threshold,
        )?));

        let keys = params.as_chunks::<33>().0;
        // A tag not 02/03 at 33 bytes is refused by the node's
        // IsCompressedOrUncompressedPubKey under STRICTENC, which every word
        // carries (interpreter.cpp:132-152, :1611), but only for a key the walk
        // reaches: from index n - 1 down, ending at the threshold's last match.
        // The highest bad index j is avoidable when the n - 1 - j keys after it
        // can meet the threshold (#625)
        if let Some((j, key)) = keys
            .iter()
            .enumerate()
            .rev()
            .find(|(_, key)| key[0] != 0x02 && key[0] != 0x03)
        {
            let after = n - 1 - j;
            if after < self.threshold as usize {
                return Err(Error::InvalidPublicKey(format!(
                    "public key {j} has tag 0x{:02x}, not a compressed key's 0x02 or 0x03, \
                     and the {after} key(s) after it cannot meet the threshold {}: \
                     every spend reaches it and fails under STRICTENC \
                     (IsCompressedOrUncompressedPubKey)",
                    key[0], self.threshold
                )));
            }
        }
        for key in keys {
            chunks.push(ScriptChunk::new(33, Some(key.to_vec())));
        }

        chunks.push(ScriptChunk::new_opcode(small_int_to_opcode(n as u8)?));
        chunks.push(ScriptChunk::new_opcode(OP_CHECKMULTISIG));

        Ok(LockingScript::from_chunks(chunks))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multisig_2_of_3_lock() {
        let key1 = PrivateKey::random();
        let key2 = PrivateKey::random();
        let key3 = PrivateKey::random();

        let template = Multisig::new(2);
        let locking = template
            .lock_from_keys(&[key1.public_key(), key2.public_key(), key3.public_key()])
            .unwrap();

        let chunks = locking.chunks();
        // OP_2 + 3 pubkeys + OP_3 + OP_CHECKMULTISIG = 6 chunks
        assert_eq!(chunks.len(), 6);

        // First chunk: OP_2
        assert_eq!(chunks[0].op, OP_2);

        // Middle chunks: 33-byte pubkeys
        for chunk in chunks.iter().take(3 + 1).skip(1) {
            assert_eq!(chunk.data.as_ref().unwrap().len(), 33);
        }

        // OP_3
        assert_eq!(chunks[4].op, OP_3);

        // OP_CHECKMULTISIG
        assert_eq!(chunks[5].op, OP_CHECKMULTISIG);

        // Script detection
        assert_eq!(locking.as_script().is_multisig(), Some((2, 3)));
    }

    #[test]
    fn test_multisig_1_of_1_lock() {
        let key = PrivateKey::random();

        let template = Multisig::new(1);
        let locking = template.lock_from_keys(&[key.public_key()]).unwrap();

        assert_eq!(locking.as_script().is_multisig(), Some((1, 1)));
    }

    #[test]
    fn test_multisig_invalid_threshold_exceeds_keys() {
        let key = PrivateKey::random();
        let template = Multisig::new(3);
        assert!(template.lock_from_keys(&[key.public_key()]).is_err());
    }

    #[test]
    fn test_multisig_invalid_zero_threshold() {
        let key = PrivateKey::random();
        let template = Multisig::new(0);
        assert!(template.lock_from_keys(&[key.public_key()]).is_err());
    }

    #[test]
    fn test_multisig_invalid_too_many_keys() {
        let keys: Vec<PublicKey> = (0..17).map(|_| PrivateKey::random().public_key()).collect();
        let template = Multisig::new(1);
        assert!(template.lock_from_keys(&keys).is_err());
    }

    #[test]
    fn test_multisig_unlock_has_dummy_op_0() {
        // Fixed keys: RFC 6979 makes the signature bytes a function of the
        // key and the digest, so the test is deterministic (#16).
        let key1 = PrivateKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        let key2 = PrivateKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000002",
        )
        .unwrap();
        let sighash = [1u8; 32];

        let unlocking =
            Multisig::sign_with_sighash(&[key1, key2], &sighash, SignOutputs::All, false).unwrap();

        let chunks = unlocking.chunks();
        // OP_0 + 2 signatures = 3 chunks
        assert_eq!(chunks.len(), 3);

        // First chunk must be OP_0
        assert_eq!(chunks[0].op, OP_0);
        assert!(chunks[0].data.is_none());

        // Second and third chunks are signatures: a DER signature with its
        // sighash byte, 9 to 73 bytes (`IsValidSignatureEncoding`,
        // interpreter.cpp:177-194). A minimal DER `r` or `s` is shorter than
        // 32 bytes when its leading byte is zero, so a fixed lower bound of 70
        // failed on about one key in 13,000 (#16).
        for chunk in chunks.iter().take(2 + 1).skip(1) {
            let sig = chunk.data.as_ref().unwrap();
            let parsed = TransactionSignature::from_checksig_format(sig)
                .expect("a DER signature with a sighash byte");
            assert_eq!(parsed.to_checksig_format(), *sig);
            assert!((9..=73).contains(&sig.len()), "{} bytes", sig.len());
            assert_eq!(*sig.last().unwrap(), 0x41u8);
        }
    }

    #[test]
    fn test_multisig_estimate_length() {
        let key1 = PrivateKey::random();
        let key2 = PrivateKey::random();

        let unlock = Multisig::unlock(&[key1, key2], SignOutputs::All, false);
        // OP_0 (1) + 2 * (1 push + 73 max sig) = 1 + 148 = 149
        assert_eq!(unlock.estimate_length(), 149);
    }

    #[test]
    fn test_multisig_trait_lock_concatenated_keys() {
        let key1 = PrivateKey::random();
        let key2 = PrivateKey::random();

        let pk1 = key1.public_key().to_compressed();
        let pk2 = key2.public_key().to_compressed();

        let mut params = Vec::with_capacity(66);
        params.extend_from_slice(&pk1);
        params.extend_from_slice(&pk2);

        let template = Multisig::new(1);
        let locking = template.lock(&params).unwrap();

        assert_eq!(locking.as_script().is_multisig(), Some((1, 2)));
    }

    #[test]
    fn test_multisig_trait_lock_invalid_params() {
        let template = Multisig::new(1);

        // Empty
        assert!(template.lock(&[]).is_err());

        // Not a multiple of 33
        assert!(template.lock(&[0x02; 34]).is_err());
    }

    #[test]
    fn test_multisig_asm() {
        let key1 = PrivateKey::random();
        let key2 = PrivateKey::random();

        let template = Multisig::new(2);
        let locking = template
            .lock_from_keys(&[key1.public_key(), key2.public_key()])
            .unwrap();

        let asm = locking.to_asm();
        assert!(asm.contains("OP_2"));
        assert!(asm.contains("OP_CHECKMULTISIG"));
    }

    #[test]
    fn test_small_int_to_opcode() {
        assert_eq!(small_int_to_opcode(1).unwrap(), OP_1);
        assert_eq!(small_int_to_opcode(2).unwrap(), OP_2);
        assert_eq!(small_int_to_opcode(16).unwrap(), OP_16);
        assert!(small_int_to_opcode(0).is_err());
        assert!(small_int_to_opcode(17).is_err());
    }

    // The m-of-n edges (#681). The node writes a multisig lock as
    // `CScript() << m << keys... << n << OP_CHECKMULTISIG` (bitcoin-sv
    // 879fc8b src/script/standard.cpp:315-324), a count of 1 to 16 as OP_1 to
    // OP_16 (src/script/script.cpp:224-229) and reads 1 <= m <= n
    // (standard.cpp:135). Its key bound is 20 before Genesis and UINT32_MAX
    // after (src/consensus/consensus.h:50,55; interpreter.cpp:1531-1532); this
    // template's own bound is 16, the small-integer counts ("Must have 1-16
    // keys, and threshold <= N", `lock_from_keys`'s rustdoc). The TypeScript
    // SDK has no Multisig template, so its citation is left out.

    /// Private key `k` (1, 2, 3...): its public key is `k * G`.
    fn key(k: u32) -> PrivateKey {
        PrivateKey::from_hex(&format!("{k:064x}")).unwrap()
    }

    /// `n` compressed keys, `1 * G`, `2 * G`, `3 * G` in turn, the one at
    /// `bad` retagged 0x06 (a hybrid tag, neither 02 nor 03).
    fn params(n: usize, bad: Option<usize>) -> Vec<u8> {
        let mut out = Vec::with_capacity(n * 33);
        for i in 0..n {
            let mut pk = key(i as u32 % 3 + 1).public_key().to_compressed();
            if bad == Some(i) {
                pk[0] = 0x06;
            }
            out.extend_from_slice(&pk);
        }
        out
    }

    const G: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const G2: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
    const G3: &str = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";

    #[test]
    fn a_one_of_one_and_a_two_of_three_lock_write_the_nodes_cscript_bytes() {
        // GetScriptForMultisig's bytes (standard.cpp:315-324) for 1*G, 2*G, 3*G
        let one = format!("5121{G}51ae");
        let two_of_three = format!("5221{G}21{G2}21{G3}53ae");
        assert_eq!(
            Multisig::new(1).lock(&params(1, None)).unwrap().to_hex(),
            one
        );
        let keys = [key(1).public_key()];
        assert_eq!(
            Multisig::new(1).lock_from_keys(&keys).unwrap().to_hex(),
            one
        );
        let keys = [
            key(1).public_key(),
            key(2).public_key(),
            key(3).public_key(),
        ];
        let lock = Multisig::new(2).lock(&params(3, None)).unwrap();
        assert_eq!(lock.to_hex(), two_of_three);
        let lock = Multisig::new(2).lock_from_keys(&keys).unwrap();
        assert_eq!(lock.to_hex(), two_of_three);
    }

    #[test]
    fn a_threshold_equal_to_the_key_count_is_written_and_one_above_is_refused() {
        // 1 <= m <= n (standard.cpp:135; `lock_from_keys`'s "threshold <= N"):
        // the node's rule, its m = n edge the kills of 241:38. The n = 16 cell
        // also pins the 16-key bound (238:14): crate-contract pin, no sibling
        // rule, stated: `multisig.rs:103`
        for n in [1usize, 2, 3, 16] {
            let m = n as u8;
            let lock = Multisig::new(m).lock(&params(n, None)).unwrap();
            assert_eq!(lock.as_script().is_multisig(), Some((m, m)));
            let refused = Multisig::new(m + 1).lock(&params(n, None));
            assert!(
                matches!(refused, Err(Error::CryptoError(_))),
                "{m}+1 of {n}"
            );
        }
        let keys = [key(1).public_key(), key(2).public_key()];
        assert!(Multisig::new(2).lock_from_keys(&keys).is_ok());
        let refused = Multisig::new(3).lock_from_keys(&keys);
        assert!(matches!(refused, Err(Error::CryptoError(_))));
    }

    #[test]
    fn sixteen_of_sixteen_writes_op_16_twice_and_seventeen_keys_are_refused() {
        // The template's bound, 16 keys as OP_16 (script.cpp:226-228)
        // crate-contract pin, no sibling rule, stated: `multisig.rs:103`
        let lock = Multisig::new(16).lock(&params(16, None)).unwrap();
        let bytes = lock.to_binary();
        assert_eq!(bytes.len(), 16 * 34 + 3);
        assert_eq!(bytes[0], OP_16);
        assert_eq!(&bytes[bytes.len() - 2..], &[OP_16, OP_CHECKMULTISIG]);
        let keys: Vec<PublicKey> = (0..16).map(|i| key(i % 3 + 1).public_key()).collect();
        assert_eq!(
            Multisig::new(16).lock_from_keys(&keys).unwrap().to_binary(),
            bytes
        );

        let refused = Multisig::new(1).lock(&params(17, None));
        assert!(matches!(refused, Err(Error::CryptoError(_))));
        let keys: Vec<PublicKey> = (0..17).map(|_| key(1).public_key()).collect();
        let refused = Multisig::new(1).lock_from_keys(&keys);
        assert!(matches!(refused, Err(Error::CryptoError(_))));
    }

    #[test]
    fn a_key_count_of_257_is_refused_not_written_as_a_count_of_one() {
        // 257 as u8 is 1: a count past the bound must be refused before the
        // OP_N is written ("Must have 1-16 keys"), or the lock would read
        // 1-of-1 over 257 keys
        // crate-contract pin, no sibling rule, stated: `multisig.rs:103`
        let refused = Multisig::new(1).lock(&params(257, None));
        assert!(matches!(refused, Err(Error::CryptoError(_))));
        let keys: Vec<PublicKey> = (0..257).map(|_| key(1).public_key()).collect();
        let refused = Multisig::new(1).lock_from_keys(&keys);
        assert!(matches!(refused, Err(Error::CryptoError(_))));
    }

    #[test]
    fn the_last_key_retagged_in_a_one_of_two_is_refused_as_every_spend_reaches_it() {
        // `lock`'s rustdoc (#625): the walk starts at the last key
        // (interpreter.cpp:1588-1611 at 879fc8b, CheckPubKeyEncoding under
        // STRICTENC, :312-315), so with j = n - 1 no key after it can meet the
        // threshold 1. Every spend fails, and the lock is refused
        // crate-contract pin, no sibling rule, stated: `multisig.rs:224-229`
        let refused = Multisig::new(1).lock(&params(2, Some(1)));
        assert!(matches!(refused, Err(Error::InvalidPublicKey(_))));
        let refused = Multisig::new(2).lock(&params(3, Some(1)));
        assert!(matches!(refused, Err(Error::InvalidPublicKey(_))));
    }

    #[test]
    fn a_retagged_key_with_enough_keys_after_it_is_avoidable_and_written() {
        // `lock`'s rustdoc (#625): refused only "when the n - 1 - j keys after
        // it cannot meet the threshold"; here exactly m keys follow it
        // crate-contract pin, no sibling rule, stated: `multisig.rs:224-229`
        for (m, n, j) in [(1u8, 2usize, 0usize), (2, 3, 0), (1, 3, 1)] {
            let given = params(n, Some(j));
            let lock = Multisig::new(m).lock(&given).unwrap();
            let bytes = lock.to_binary();
            assert_eq!(bytes[1 + j * 34 + 1], 0x06, "{m}-of-{n}, key {j}");
            assert_eq!(lock.as_script().is_multisig(), Some((m, n as u8)));
        }
    }
}
