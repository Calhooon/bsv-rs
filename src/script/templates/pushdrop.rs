//! PushDrop Script Template
//!
//! A data envelope template that embeds arbitrary data in a Bitcoin transaction
//! output, protected by a signature. Used by token protocols like BSV-20.
//!
//! # Script Structure
//!
//! ## Lock-Before Pattern (default)
//! ```text
//! <pubkey> OP_CHECKSIG <field1> <field2> ... OP_2DROP ... OP_DROP
//! ```
//!
//! ## Lock-After Pattern
//! ```text
//! <field1> <field2> ... OP_2DROP ... OP_DROP <pubkey> OP_CHECKSIG
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use bsv_rs::script::templates::PushDrop;
//! use bsv_rs::primitives::ec::PrivateKey;
//!
//! let privkey = PrivateKey::random();
//! let pubkey = privkey.public_key();
//! let fields = vec![b"hello".to_vec(), b"world".to_vec()];
//!
//! let pushdrop = PushDrop::new(pubkey, fields);
//! let script = pushdrop.lock();
//! ```

use crate::error::Error;
use crate::primitives::bsv::TransactionSignature;
use crate::primitives::ec::{PrivateKey, PublicKey};
use crate::script::op::*;
use crate::script::template::{
    compute_sighash_scope, ScriptTemplateUnlock, SignOutputs, SigningContext,
};
use crate::script::{LockingScript, Script, ScriptChunk, UnlockingScript};
use crate::Result;

/// Lock position for PushDrop template.
///
/// Determines whether the public key and OP_CHECKSIG come before or after
/// the data fields in the locking script.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LockPosition {
    /// Pubkey and OP_CHECKSIG come before data fields (default).
    /// Script: `<pubkey> OP_CHECKSIG <fields...> OP_2DROP... OP_DROP`
    #[default]
    Before,
    /// Pubkey and OP_CHECKSIG come after data fields.
    /// Script: `<fields...> OP_2DROP... OP_DROP <pubkey> OP_CHECKSIG`
    After,
}

/// PushDrop locking script template.
///
/// This template creates scripts that embed arbitrary data fields alongside
/// a P2PK (Pay-to-Public-Key) lock. The data fields are pushed onto the stack
/// and then dropped, leaving only the signature verification.
///
/// # Example
///
/// ```rust,ignore
/// use bsv_rs::script::templates::PushDrop;
/// use bsv_rs::primitives::ec::PrivateKey;
///
/// let privkey = PrivateKey::random();
/// let pubkey = privkey.public_key();
///
/// // Create with embedded token data
/// let fields = vec![
///     b"BSV20".to_vec(),
///     b"transfer".to_vec(),
///     b"1000".to_vec(),
/// ];
///
/// let pushdrop = PushDrop::new(pubkey, fields);
/// let locking_script = pushdrop.lock();
/// ```
#[derive(Debug, Clone)]
pub struct PushDrop {
    /// The public key that can unlock this output.
    pub locking_public_key: PublicKey,
    /// Embedded data fields.
    pub fields: Vec<Vec<u8>>,
    /// Lock position (before or after data).
    pub lock_position: LockPosition,
}

impl PushDrop {
    /// Creates a new PushDrop template with lock-before pattern.
    ///
    /// # Arguments
    ///
    /// * `locking_public_key` - Public key that can spend this output
    /// * `fields` - Data fields to embed
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use bsv_rs::script::templates::PushDrop;
    /// use bsv_rs::primitives::ec::PrivateKey;
    ///
    /// let privkey = PrivateKey::random();
    /// let pubkey = privkey.public_key();
    /// let fields = vec![b"hello".to_vec(), b"world".to_vec()];
    ///
    /// let pushdrop = PushDrop::new(pubkey, fields);
    /// let script = pushdrop.lock();
    /// ```
    pub fn new(locking_public_key: PublicKey, fields: Vec<Vec<u8>>) -> Self {
        Self {
            locking_public_key,
            fields,
            lock_position: LockPosition::Before,
        }
    }

    /// Sets the lock position and returns self for chaining.
    ///
    /// # Arguments
    ///
    /// * `position` - The lock position (Before or After)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use bsv_rs::script::templates::{PushDrop, LockPosition};
    /// use bsv_rs::primitives::ec::PrivateKey;
    ///
    /// let privkey = PrivateKey::random();
    /// let pubkey = privkey.public_key();
    ///
    /// let pushdrop = PushDrop::new(pubkey, vec![b"data".to_vec()])
    ///     .with_position(LockPosition::After);
    /// ```
    pub fn with_position(mut self, position: LockPosition) -> Self {
        self.lock_position = position;
        self
    }

    /// Creates the locking script.
    ///
    /// # Returns
    ///
    /// The locking script containing the embedded data and P2PK lock.
    pub fn lock(&self) -> LockingScript {
        let mut chunks = Vec::new();

        match self.lock_position {
            LockPosition::Before => {
                // <pubkey> OP_CHECKSIG <fields...> OP_2DROP... OP_DROP
                chunks.push(ScriptChunk::new_push(
                    self.locking_public_key.to_compressed().to_vec(),
                ));
                chunks.push(ScriptChunk::new_opcode(OP_CHECKSIG));

                // Add fields with minimal encoding
                for field in &self.fields {
                    chunks.push(Self::create_minimally_encoded_chunk(field));
                }

                // Add DROP operations
                Self::add_drop_operations(&mut chunks, self.fields.len());
            }
            LockPosition::After => {
                // <fields...> OP_2DROP... OP_DROP <pubkey> OP_CHECKSIG
                for field in &self.fields {
                    chunks.push(Self::create_minimally_encoded_chunk(field));
                }

                Self::add_drop_operations(&mut chunks, self.fields.len());

                chunks.push(ScriptChunk::new_push(
                    self.locking_public_key.to_compressed().to_vec(),
                ));
                chunks.push(ScriptChunk::new_opcode(OP_CHECKSIG));
            }
        }

        LockingScript::from_chunks(chunks)
    }

    /// Creates a minimally encoded script chunk for data.
    ///
    /// Bitcoin Script requires minimal encoding for data pushes:
    /// - Empty data or single zero byte -> OP_0
    /// - Single byte 1-16 -> OP_1 through OP_16
    /// - Single byte 0x81 (-1) -> OP_1NEGATE
    /// - Otherwise -> standard data push
    fn create_minimally_encoded_chunk(data: &[u8]) -> ScriptChunk {
        // Empty or single zero byte -> OP_0
        if data.is_empty() || (data.len() == 1 && data[0] == 0) {
            return ScriptChunk::new_opcode(OP_0);
        }

        // Single byte special cases
        if data.len() == 1 {
            let byte = data[0];
            // Values 1-16 -> OP_1 through OP_16
            if (1..=16).contains(&byte) {
                // OP_1 = 0x51, so OP_N = 0x50 + N
                return ScriptChunk::new_opcode(0x50 + byte);
            }
            // 0x81 (-1 in Bitcoin script number encoding) -> OP_1NEGATE
            if byte == 0x81 {
                return ScriptChunk::new_opcode(OP_1NEGATE);
            }
        }

        // Otherwise, standard data push
        ScriptChunk::new_push(data.to_vec())
    }

    /// Adds appropriate DROP operations for the field count.
    ///
    /// Uses OP_2DROP for pairs of fields and OP_DROP for a remaining single field.
    fn add_drop_operations(chunks: &mut Vec<ScriptChunk>, count: usize) {
        let mut remaining = count;

        // Use OP_2DROP for pairs
        while remaining >= 2 {
            chunks.push(ScriptChunk::new_opcode(OP_2DROP));
            remaining -= 2;
        }

        // Use OP_DROP for remaining single item
        if remaining == 1 {
            chunks.push(ScriptChunk::new_opcode(OP_DROP));
        }
    }

    /// Decodes a PushDrop locking script.
    ///
    /// Extracts the public key and embedded fields from a locking script.
    ///
    /// # Arguments
    ///
    /// * `script` - The locking script to decode
    ///
    /// # Returns
    ///
    /// The decoded PushDrop template, or an error if the script format is invalid.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use bsv_rs::script::templates::PushDrop;
    /// use bsv_rs::script::LockingScript;
    ///
    /// let script = LockingScript::from_hex("...")?;
    /// let pushdrop = PushDrop::decode(&script)?;
    /// println!("Fields: {:?}", pushdrop.fields);
    /// ```
    pub fn decode(script: &LockingScript) -> Result<Self> {
        let chunks = script.chunks();

        if chunks.len() < 2 {
            return Err(Error::ScriptParseError(
                "Script too short for PushDrop".into(),
            ));
        }

        // Determine lock position by checking first chunk
        // If first chunk is a 33 or 65 byte data push, it's lock-before
        let first_is_pubkey = chunks[0]
            .data
            .as_ref()
            .map(|d| d.len() == 33 || d.len() == 65)
            .unwrap_or(false);

        if first_is_pubkey {
            Self::decode_lock_before(&chunks)
        } else {
            Self::decode_lock_after(&chunks)
        }
    }

    /// Decodes a lock-before pattern script.
    /// Pattern: <pubkey> OP_CHECKSIG <fields...> OP_2DROP... OP_DROP
    fn decode_lock_before(chunks: &[ScriptChunk]) -> Result<Self> {
        // First chunk must be pubkey data
        let pubkey_data = chunks[0]
            .data
            .as_ref()
            .ok_or_else(|| Error::ScriptParseError("Expected public key".into()))?;
        let locking_public_key = PublicKey::from_bytes(pubkey_data)?;

        // Second chunk must be OP_CHECKSIG
        if chunks[1].op != OP_CHECKSIG {
            return Err(Error::ScriptParseError(
                "Expected OP_CHECKSIG after pubkey".into(),
            ));
        }

        // Extract fields (between OP_CHECKSIG and first DROP)
        let mut fields = Vec::new();
        for chunk in chunks.iter().skip(2) {
            // Stop when we hit a DROP operation
            if chunk.op == OP_DROP || chunk.op == OP_2DROP {
                break;
            }
            fields.push(Self::chunk_to_bytes(chunk));
        }

        Ok(Self {
            locking_public_key,
            fields,
            lock_position: LockPosition::Before,
        })
    }

    /// Decodes a lock-after pattern script.
    /// Pattern: <fields...> OP_2DROP... OP_DROP <pubkey> OP_CHECKSIG
    fn decode_lock_after(chunks: &[ScriptChunk]) -> Result<Self> {
        if chunks.len() < 2 {
            return Err(Error::ScriptParseError("Script too short".into()));
        }

        let last_idx = chunks.len() - 1;

        // Last chunk must be OP_CHECKSIG
        if chunks[last_idx].op != OP_CHECKSIG {
            return Err(Error::ScriptParseError(
                "Expected OP_CHECKSIG at end".into(),
            ));
        }

        // Second to last must be pubkey
        let pubkey_data = chunks[last_idx - 1].data.as_ref().ok_or_else(|| {
            Error::ScriptParseError("Expected public key before OP_CHECKSIG".into())
        })?;
        let locking_public_key = PublicKey::from_bytes(pubkey_data)?;

        // Extract fields (before the DROP operations)
        let mut fields = Vec::new();
        for chunk in chunks.iter().take(last_idx - 1) {
            // Stop when we hit a DROP operation
            if chunk.op == OP_DROP || chunk.op == OP_2DROP {
                break;
            }
            fields.push(Self::chunk_to_bytes(chunk));
        }

        Ok(Self {
            locking_public_key,
            fields,
            lock_position: LockPosition::After,
        })
    }

    /// Converts a script chunk to bytes, handling minimal encoding.
    fn chunk_to_bytes(chunk: &ScriptChunk) -> Vec<u8> {
        // If chunk has data, return it
        if let Some(ref data) = chunk.data {
            return data.clone();
        }

        // Handle opcodes that represent data
        let op = chunk.op;

        // OP_0 -> [0]
        if op == OP_0 {
            return vec![0];
        }

        // OP_1 through OP_16 -> [1] through [16]
        if (OP_1..=OP_16).contains(&op) {
            return vec![op - 0x50];
        }

        // OP_1NEGATE -> [0x81]
        if op == OP_1NEGATE {
            return vec![0x81];
        }

        // Other opcodes have no data representation
        Vec::new()
    }

    /// Creates an unlock template for spending a PushDrop output.
    ///
    /// PushDrop uses a P2PK (Pay-to-Public-Key) lock, so the unlocking script
    /// is just a signature. Unlike P2PKH, the public key is already in the
    /// locking script, so it doesn't need to be repeated in the unlock.
    ///
    /// # Arguments
    ///
    /// * `private_key` - The private key for signing (must match the public key in the lock)
    /// * `sign_outputs` - Which outputs to sign
    /// * `anyone_can_pay` - Whether to allow other inputs to be added
    ///
    /// # Returns
    ///
    /// A [`ScriptTemplateUnlock`] that can sign transaction inputs.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use bsv_rs::script::templates::PushDrop;
    /// use bsv_rs::script::template::{SignOutputs, SigningContext};
    /// use bsv_rs::primitives::ec::PrivateKey;
    ///
    /// let private_key = PrivateKey::random();
    /// let public_key = private_key.public_key();
    /// let fields = vec![b"token_data".to_vec()];
    ///
    /// // Create locking script
    /// let pushdrop = PushDrop::new(public_key, fields);
    /// let locking_script = pushdrop.lock();
    ///
    /// // Create unlock template
    /// let unlock = PushDrop::unlock(&private_key, SignOutputs::All, false);
    ///
    /// // Estimate length for fee calculation (73 bytes)
    /// let estimated_size = unlock.estimate_length();
    ///
    /// // Sign with a transaction context
    /// let context = SigningContext::new(&raw_tx, input_index, satoshis, locking_script.as_script());
    /// let unlocking_script = unlock.sign(&context)?;
    /// ```
    pub fn unlock(
        private_key: &PrivateKey,
        sign_outputs: SignOutputs,
        anyone_can_pay: bool,
    ) -> ScriptTemplateUnlock {
        let key = private_key.clone();
        let scope = compute_sighash_scope(sign_outputs, anyone_can_pay);

        ScriptTemplateUnlock::new(
            move |context: &SigningContext| {
                // Compute the sighash
                let sighash = context.compute_sighash(scope)?;

                // Sign the sighash
                let signature = key.sign(&sighash)?;
                let tx_sig = TransactionSignature::new(signature, scope);

                // Build the unlocking script (signature only, no pubkey for P2PK)
                let sig_bytes = tx_sig.to_checksig_format();

                let mut script = Script::new();
                script.write_bin(&sig_bytes);

                Ok(UnlockingScript::from_script(script))
            },
            || {
                // Estimate length: 1 (push opcode) + 72 (max DER signature + sighash byte)
                // = 73 bytes (matches TypeScript SDK)
                73
            },
        )
    }

    /// Creates an unlocking script with a precomputed sighash.
    ///
    /// This is useful when you already have the sighash computed and don't
    /// need to parse the transaction.
    ///
    /// # Arguments
    ///
    /// * `private_key` - The private key for signing
    /// * `sighash` - The precomputed sighash to sign
    /// * `sign_outputs` - Which outputs to sign (for the scope byte)
    /// * `anyone_can_pay` - Whether to allow other inputs to be added
    ///
    /// # Returns
    ///
    /// The unlocking script, or an error if signing fails.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use bsv_rs::script::templates::PushDrop;
    /// use bsv_rs::script::template::SignOutputs;
    /// use bsv_rs::primitives::ec::PrivateKey;
    ///
    /// let private_key = PrivateKey::random();
    /// let sighash: [u8; 32] = compute_sighash_externally();
    ///
    /// let unlocking = PushDrop::sign_with_sighash(
    ///     &private_key,
    ///     &sighash,
    ///     SignOutputs::All,
    ///     false,
    /// )?;
    /// ```
    pub fn sign_with_sighash(
        private_key: &PrivateKey,
        sighash: &[u8; 32],
        sign_outputs: SignOutputs,
        anyone_can_pay: bool,
    ) -> Result<UnlockingScript> {
        let scope = compute_sighash_scope(sign_outputs, anyone_can_pay);

        // Sign the sighash
        let signature = private_key.sign(sighash)?;
        let tx_sig = TransactionSignature::new(signature, scope);

        // Build the unlocking script (signature only for P2PK)
        let sig_bytes = tx_sig.to_checksig_format();

        let mut script = Script::new();
        script.write_bin(&sig_bytes);

        Ok(UnlockingScript::from_script(script))
    }

    /// Estimates the unlocking script length.
    ///
    /// For a PushDrop output (P2PK lock), the unlocking script is just a signature.
    /// Unlike P2PKH, the public key is already in the locking script.
    ///
    /// # Returns
    ///
    /// The estimated length in bytes (73 bytes for signature only).
    /// This matches the TypeScript SDK's estimate.
    pub fn estimate_unlocking_length(&self) -> usize {
        // For P2PK style: 1 (push opcode) + ~72 (DER signature + sighash byte)
        // = 73 bytes max
        // This matches the TypeScript SDK's estimateLength() return value
        73
    }
}

impl PartialEq for PushDrop {
    fn eq(&self, other: &Self) -> bool {
        self.locking_public_key.to_compressed() == other.locking_public_key.to_compressed()
            && self.fields == other.fields
            && self.lock_position == other.lock_position
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::ec::PrivateKey;

    #[test]
    fn test_pushdrop_lock_before() {
        let privkey = PrivateKey::random();
        let pubkey = privkey.public_key();

        let fields = vec![b"field1".to_vec(), b"field2".to_vec()];
        let pushdrop = PushDrop::new(pubkey.clone(), fields.clone());
        let script = pushdrop.lock();

        // Decode and verify
        let decoded = PushDrop::decode(&script).unwrap();
        assert_eq!(
            decoded.locking_public_key.to_compressed(),
            pubkey.to_compressed()
        );
        assert_eq!(decoded.fields, fields);
        assert_eq!(decoded.lock_position, LockPosition::Before);
    }

    #[test]
    fn test_pushdrop_lock_after() {
        let privkey = PrivateKey::random();
        let pubkey = privkey.public_key();

        let fields = vec![b"data".to_vec()];
        let pushdrop =
            PushDrop::new(pubkey.clone(), fields.clone()).with_position(LockPosition::After);
        let script = pushdrop.lock();

        let decoded = PushDrop::decode(&script).unwrap();
        assert_eq!(decoded.lock_position, LockPosition::After);
        assert_eq!(
            decoded.locking_public_key.to_compressed(),
            pubkey.to_compressed()
        );
    }

    #[test]
    fn test_pushdrop_minimal_encoding() {
        let privkey = PrivateKey::random();
        let pubkey = privkey.public_key();

        // Test minimal encoding for small values
        let fields = vec![
            vec![0],    // Should become OP_0
            vec![1],    // Should become OP_1
            vec![16],   // Should become OP_16
            vec![0x81], // Should become OP_1NEGATE
            vec![17],   // Regular push (not a special opcode)
        ];

        let pushdrop = PushDrop::new(pubkey, fields.clone());
        let script = pushdrop.lock();

        let decoded = PushDrop::decode(&script).unwrap();
        assert_eq!(decoded.fields.len(), 5);

        // Check the decoded values match the original fields
        assert_eq!(decoded.fields[0], vec![0]);
        assert_eq!(decoded.fields[1], vec![1]);
        assert_eq!(decoded.fields[2], vec![16]);
        assert_eq!(decoded.fields[3], vec![0x81]);
        assert_eq!(decoded.fields[4], vec![17]);
    }

    #[test]
    fn test_pushdrop_empty_fields() {
        let privkey = PrivateKey::random();
        let pubkey = privkey.public_key();

        let pushdrop = PushDrop::new(pubkey.clone(), vec![]);
        let script = pushdrop.lock();

        // Should be simple <pubkey> OP_CHECKSIG (like P2PK)
        let chunks = script.chunks();
        assert_eq!(chunks.len(), 2);

        let decoded = PushDrop::decode(&script).unwrap();
        assert!(decoded.fields.is_empty());
    }

    #[test]
    fn test_pushdrop_large_field() {
        let privkey = PrivateKey::random();
        let pubkey = privkey.public_key();

        // 10KB field
        let large_field = vec![0xABu8; 10_000];
        let pushdrop = PushDrop::new(pubkey, vec![large_field.clone()]);
        let script = pushdrop.lock();

        let decoded = PushDrop::decode(&script).unwrap();
        assert_eq!(decoded.fields[0], large_field);
    }

    #[test]
    fn test_pushdrop_drop_count() {
        let privkey = PrivateKey::random();
        let pubkey = privkey.public_key();

        // 5 fields should produce 2x OP_2DROP + 1x OP_DROP
        let fields: Vec<Vec<u8>> = (0..5).map(|i| vec![i as u8 + 17]).collect(); // Use values > 16 to avoid OP_N
        let pushdrop = PushDrop::new(pubkey, fields);
        let script = pushdrop.lock();

        let chunks = script.chunks();
        let drop_count = chunks.iter().filter(|c| c.op == OP_DROP).count();
        let drop2_count = chunks.iter().filter(|c| c.op == OP_2DROP).count();

        assert_eq!(drop2_count, 2);
        assert_eq!(drop_count, 1);
    }

    #[test]
    fn test_pushdrop_estimate_unlocking_length() {
        let privkey = PrivateKey::random();
        let pubkey = privkey.public_key();

        let pushdrop = PushDrop::new(pubkey, vec![b"test".to_vec()]);
        // P2PK unlocking is just <signature>, so 73 bytes (1 push + 72 max DER + sighash)
        assert_eq!(pushdrop.estimate_unlocking_length(), 73);
    }

    #[test]
    fn test_pushdrop_unlock_estimate_length() {
        use crate::script::template::SignOutputs;

        let privkey = PrivateKey::random();
        let unlock = PushDrop::unlock(&privkey, SignOutputs::All, false);

        // Should match the instance method
        assert_eq!(unlock.estimate_length(), 73);
    }

    #[test]
    fn test_pushdrop_sign_with_sighash() {
        use crate::script::template::SignOutputs;

        let private_key = PrivateKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();

        // Create a simple test case with a mock sighash
        let sighash = [1u8; 32];
        let unlocking =
            PushDrop::sign_with_sighash(&private_key, &sighash, SignOutputs::All, false).unwrap();

        // The unlocking script should have 1 chunk: signature only (P2PK style)
        let chunks = unlocking.chunks();
        assert_eq!(chunks.len(), 1);

        // First (and only) chunk should be the signature (push data)
        assert!(chunks[0].data.is_some());
        let sig_data = chunks[0].data.as_ref().unwrap();
        // DER signature + 1 byte sighash
        assert!(sig_data.len() >= 70 && sig_data.len() <= 73);

        // Last byte should be the sighash type
        assert_eq!(
            sig_data.last().unwrap(),
            &0x41_u8 // SIGHASH_ALL | SIGHASH_FORKID
        );
    }

    #[test]
    fn test_pushdrop_sign_outputs_variants() {
        use crate::script::template::SignOutputs;

        let private_key = PrivateKey::random();
        let sighash = [1u8; 32];

        // Test ALL
        let unlocking =
            PushDrop::sign_with_sighash(&private_key, &sighash, SignOutputs::All, false).unwrap();
        let chunks = unlocking.chunks();
        let sig_data = chunks[0].data.as_ref().unwrap();
        assert_eq!(sig_data.last().unwrap(), &0x41u8); // ALL | FORKID

        // Test NONE
        let unlocking =
            PushDrop::sign_with_sighash(&private_key, &sighash, SignOutputs::None, false).unwrap();
        let chunks = unlocking.chunks();
        let sig_data = chunks[0].data.as_ref().unwrap();
        assert_eq!(sig_data.last().unwrap(), &0x42u8); // NONE | FORKID

        // Test SINGLE
        let unlocking =
            PushDrop::sign_with_sighash(&private_key, &sighash, SignOutputs::Single, false)
                .unwrap();
        let chunks = unlocking.chunks();
        let sig_data = chunks[0].data.as_ref().unwrap();
        assert_eq!(sig_data.last().unwrap(), &0x43u8); // SINGLE | FORKID

        // Test ALL | ANYONECANPAY
        let unlocking =
            PushDrop::sign_with_sighash(&private_key, &sighash, SignOutputs::All, true).unwrap();
        let chunks = unlocking.chunks();
        let sig_data = chunks[0].data.as_ref().unwrap();
        assert_eq!(sig_data.last().unwrap(), &0xC1u8); // ALL | FORKID | ANYONECANPAY
    }

    #[test]
    fn test_pushdrop_empty_data_becomes_op_0() {
        let privkey = PrivateKey::random();
        let pubkey = privkey.public_key();

        // Empty vec should become OP_0
        let fields = vec![vec![]];
        let pushdrop = PushDrop::new(pubkey, fields);
        let script = pushdrop.lock();

        // Third chunk (after pubkey and OP_CHECKSIG) should be OP_0
        let chunks = script.chunks();
        assert_eq!(chunks[2].op, OP_0);
        assert!(chunks[2].data.is_none());

        // Decoded should give us [0] back (our convention for OP_0)
        let decoded = PushDrop::decode(&script).unwrap();
        assert_eq!(decoded.fields[0], vec![0]);
    }

    #[test]
    fn test_pushdrop_roundtrip_all_special_values() {
        let privkey = PrivateKey::random();
        let pubkey = privkey.public_key();

        // Test all special encoding cases
        let fields = vec![
            vec![],     // OP_0
            vec![0],    // OP_0
            vec![1],    // OP_1
            vec![2],    // OP_2
            vec![15],   // OP_15
            vec![16],   // OP_16
            vec![0x81], // OP_1NEGATE
            vec![17],   // Regular push
            vec![255],  // Regular push
        ];

        let pushdrop = PushDrop::new(pubkey, fields);
        let script = pushdrop.lock();

        let decoded = PushDrop::decode(&script).unwrap();

        // Empty and [0] both decode to [0] (OP_0)
        assert_eq!(decoded.fields[0], vec![0]);
        assert_eq!(decoded.fields[1], vec![0]);
        assert_eq!(decoded.fields[2], vec![1]);
        assert_eq!(decoded.fields[3], vec![2]);
        assert_eq!(decoded.fields[4], vec![15]);
        assert_eq!(decoded.fields[5], vec![16]);
        assert_eq!(decoded.fields[6], vec![0x81]);
        assert_eq!(decoded.fields[7], vec![17]);
        assert_eq!(decoded.fields[8], vec![255]);
    }

    #[test]
    fn test_pushdrop_lock_after_multiple_fields() {
        let privkey = PrivateKey::random();
        let pubkey = privkey.public_key();

        let fields = vec![b"token".to_vec(), b"transfer".to_vec(), b"100".to_vec()];
        let pushdrop =
            PushDrop::new(pubkey.clone(), fields.clone()).with_position(LockPosition::After);
        let script = pushdrop.lock();

        let decoded = PushDrop::decode(&script).unwrap();
        assert_eq!(decoded.fields, fields);
        assert_eq!(decoded.lock_position, LockPosition::After);
        assert_eq!(
            decoded.locking_public_key.to_compressed(),
            pubkey.to_compressed()
        );
    }
}
