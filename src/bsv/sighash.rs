//! Sighash computation for BSV transactions.
//!
//! This module implements the BIP-143 style signature hash computation used by BSV.
//! The sighash is the 32-byte message digest that gets signed when authorizing
//! a transaction input.
//!
//! # SIGHASH Types
//!
//! The sighash type determines which parts of the transaction are committed to in
//! the signature:
//!
//! - `ALL` (0x01): Signs all inputs and all outputs
//! - `NONE` (0x02): Signs all inputs, no outputs
//! - `SINGLE` (0x03): Signs all inputs, only the output at the same index
//! - `ANYONECANPAY` (0x80): Flag to sign only this input (can combine with others)
//! - `FORKID` (0x40): BSV-specific flag (required for BIP-143 style)
//!
//! # Example
//!
//! ```rust,ignore
//! use bsv_primitives::bsv::sighash::{compute_sighash, SighashParams, parse_transaction};
//!
//! // Parse a raw transaction
//! let raw_tx = hex::decode("0100000001...").unwrap();
//! let tx = parse_transaction(&raw_tx).unwrap();
//!
//! // Compute sighash for input 0
//! let subscript = hex::decode("76a914...88ac").unwrap();
//! let sighash = compute_sighash(&SighashParams {
//!     version: tx.version,
//!     inputs: &tx.inputs,
//!     outputs: &tx.outputs,
//!     locktime: tx.locktime,
//!     input_index: 0,
//!     subscript: &subscript,
//!     satoshis: 100000,
//!     scope: SIGHASH_ALL | SIGHASH_FORKID,
//! });
//! ```

use crate::encoding::{Reader, Writer};
use crate::error::{Error, Result};
use crate::hash::sha256d;

// ============================================================================
// SIGHASH Constants
// ============================================================================

/// Sign all inputs and all outputs.
pub const SIGHASH_ALL: u32 = 0x00000001;

/// Sign all inputs, but no outputs (allows anyone to modify outputs).
pub const SIGHASH_NONE: u32 = 0x00000002;

/// Sign all inputs and only the output at the same index as this input.
pub const SIGHASH_SINGLE: u32 = 0x00000003;

/// BSV-specific flag indicating BIP-143 style hashing.
pub const SIGHASH_FORKID: u32 = 0x00000040;

/// Only sign this one input (allows others to add inputs).
pub const SIGHASH_ANYONECANPAY: u32 = 0x00000080;

/// Mask for the base sighash type (ALL, NONE, SINGLE).
const SIGHASH_BASE_MASK: u32 = 0x1F;

// ============================================================================
// Transaction Structures
// ============================================================================

/// A transaction input as parsed from raw bytes.
#[derive(Debug, Clone)]
pub struct TxInput {
    /// Previous transaction ID (32 bytes, internal byte order).
    pub txid: [u8; 32],
    /// Index of the output in the previous transaction.
    pub output_index: u32,
    /// The input script (scriptSig).
    pub script: Vec<u8>,
    /// Sequence number.
    pub sequence: u32,
}

/// A transaction output as parsed from raw bytes.
#[derive(Debug, Clone)]
pub struct TxOutput {
    /// Value in satoshis.
    pub satoshis: u64,
    /// The output script (scriptPubKey).
    pub script: Vec<u8>,
}

/// A parsed raw transaction.
#[derive(Debug, Clone)]
pub struct RawTransaction {
    /// Transaction version (can be negative in theory, but usually 1 or 2).
    pub version: i32,
    /// Transaction inputs.
    pub inputs: Vec<TxInput>,
    /// Transaction outputs.
    pub outputs: Vec<TxOutput>,
    /// Lock time.
    pub locktime: u32,
}

// ============================================================================
// Transaction Parsing
// ============================================================================

/// Parses a raw transaction from bytes.
///
/// # Arguments
///
/// * `raw` - The serialized transaction bytes
///
/// # Returns
///
/// The parsed transaction, or an error if parsing fails
///
/// # Example
///
/// ```rust,ignore
/// use bsv_primitives::bsv::sighash::parse_transaction;
///
/// let raw = hex::decode("0100000001...").unwrap();
/// let tx = parse_transaction(&raw).unwrap();
/// println!("Version: {}", tx.version);
/// println!("Inputs: {}", tx.inputs.len());
/// ```
pub fn parse_transaction(raw: &[u8]) -> Result<RawTransaction> {
    let mut reader = Reader::new(raw);

    // Version (4 bytes, signed LE)
    let version = reader.read_i32_le()?;

    // Input count (varint)
    let input_count = reader.read_var_int_num()?;
    let mut inputs = Vec::with_capacity(input_count);

    for _ in 0..input_count {
        // Previous transaction ID (32 bytes)
        let txid_bytes = reader.read_bytes(32)?;
        let mut txid = [0u8; 32];
        txid.copy_from_slice(txid_bytes);

        // Output index (4 bytes LE)
        let output_index = reader.read_u32_le()?;

        // Script (varint length + bytes)
        let script = reader.read_var_bytes()?.to_vec();

        // Sequence (4 bytes LE)
        let sequence = reader.read_u32_le()?;

        inputs.push(TxInput {
            txid,
            output_index,
            script,
            sequence,
        });
    }

    // Output count (varint)
    let output_count = reader.read_var_int_num()?;
    let mut outputs = Vec::with_capacity(output_count);

    for _ in 0..output_count {
        // Value (8 bytes LE)
        let satoshis = reader.read_u64_le()?;

        // Script (varint length + bytes)
        let script = reader.read_var_bytes()?.to_vec();

        outputs.push(TxOutput { satoshis, script });
    }

    // Locktime (4 bytes LE)
    let locktime = reader.read_u32_le()?;

    Ok(RawTransaction {
        version,
        inputs,
        outputs,
        locktime,
    })
}

// ============================================================================
// Sighash Computation
// ============================================================================

/// Parameters for computing a sighash.
#[derive(Debug)]
pub struct SighashParams<'a> {
    /// Transaction version.
    pub version: i32,
    /// All transaction inputs.
    pub inputs: &'a [TxInput],
    /// All transaction outputs.
    pub outputs: &'a [TxOutput],
    /// Transaction locktime.
    pub locktime: u32,
    /// Index of the input being signed.
    pub input_index: usize,
    /// The subscript (scriptCode) to use for signing.
    pub subscript: &'a [u8],
    /// The satoshi value of the input being spent.
    pub satoshis: u64,
    /// The sighash type/scope.
    pub scope: u32,
}

/// Computes the hash of all input outpoints (prevouts).
///
/// Returns 32 zero bytes if ANYONECANPAY is set.
fn compute_hash_prevouts(inputs: &[TxInput], scope: u32) -> [u8; 32] {
    // If ANYONECANPAY is set, return zeros
    if (scope & SIGHASH_ANYONECANPAY) != 0 {
        return [0u8; 32];
    }

    let mut writer = Writer::new();

    for input in inputs {
        // Write txid as-is (internal byte order, same as stored in transaction)
        // The BIP-143 preimage uses the same byte order as the serialized transaction
        writer.write_bytes(&input.txid);

        // Write output index (4 bytes LE)
        writer.write_u32_le(input.output_index);
    }

    sha256d(writer.as_bytes())
}

/// Computes the hash of all input sequence numbers.
///
/// Returns 32 zero bytes if ANYONECANPAY, SINGLE, or NONE is set.
fn compute_hash_sequence(inputs: &[TxInput], scope: u32) -> [u8; 32] {
    let base_type = scope & SIGHASH_BASE_MASK;

    // Return zeros if ANYONECANPAY is set, or if base type is SINGLE or NONE
    if (scope & SIGHASH_ANYONECANPAY) != 0
        || base_type == SIGHASH_SINGLE
        || base_type == SIGHASH_NONE
    {
        return [0u8; 32];
    }

    let mut writer = Writer::new();

    for input in inputs {
        writer.write_u32_le(input.sequence);
    }

    sha256d(writer.as_bytes())
}

/// Computes the hash of outputs.
///
/// - ALL: Hash all outputs
/// - SINGLE (in range): Hash only the output at the same index
/// - SINGLE (out of range) or NONE: Return 32 zero bytes
fn compute_hash_outputs(outputs: &[TxOutput], input_index: usize, scope: u32) -> [u8; 32] {
    let base_type = scope & SIGHASH_BASE_MASK;

    if base_type != SIGHASH_SINGLE && base_type != SIGHASH_NONE {
        // SIGHASH_ALL: hash all outputs
        let mut writer = Writer::new();

        for output in outputs {
            writer.write_u64_le(output.satoshis);
            writer.write_var_int(output.script.len() as u64);
            writer.write_bytes(&output.script);
        }

        sha256d(writer.as_bytes())
    } else if base_type == SIGHASH_SINGLE && input_index < outputs.len() {
        // SIGHASH_SINGLE with valid index: hash only that output
        let output = &outputs[input_index];
        let mut writer = Writer::new();

        writer.write_u64_le(output.satoshis);
        writer.write_var_int(output.script.len() as u64);
        writer.write_bytes(&output.script);

        sha256d(writer.as_bytes())
    } else {
        // SIGHASH_NONE or SIGHASH_SINGLE with out-of-range index
        [0u8; 32]
    }
}

/// Builds the sighash preimage.
///
/// This is the message that gets hashed to produce the sighash.
/// The preimage follows the BIP-143 format:
///
/// 1. nVersion (4 bytes LE)
/// 2. hashPrevouts (32 bytes)
/// 3. hashSequence (32 bytes)
/// 4. outpoint (36 bytes: 32 txid + 4 index)
/// 5. scriptCode (varint + bytes)
/// 6. value (8 bytes LE)
/// 7. nSequence (4 bytes LE)
/// 8. hashOutputs (32 bytes)
/// 9. nLocktime (4 bytes LE)
/// 10. sighash type (4 bytes LE)
pub fn build_sighash_preimage(params: &SighashParams) -> Vec<u8> {
    let input = &params.inputs[params.input_index];

    // Compute the three hash components
    let hash_prevouts = compute_hash_prevouts(params.inputs, params.scope);
    let hash_sequence = compute_hash_sequence(params.inputs, params.scope);
    let hash_outputs = compute_hash_outputs(params.outputs, params.input_index, params.scope);

    // Build the preimage
    let mut writer = Writer::with_capacity(
        4 + // version
        32 + // hashPrevouts
        32 + // hashSequence
        32 + // txid
        4 + // output index
        9 + params.subscript.len() + // scriptCode (varint + data)
        8 + // value
        4 + // sequence
        32 + // hashOutputs
        4 + // locktime
        4, // sighash type
    );

    // 1. nVersion (4 bytes, signed LE)
    writer.write_i32_le(params.version);

    // 2. hashPrevouts (32 bytes)
    writer.write_bytes(&hash_prevouts);

    // 3. hashSequence (32 bytes)
    writer.write_bytes(&hash_sequence);

    // 4. outpoint (32 bytes txid + 4 bytes index)
    // The txid is written in the same byte order as stored in the transaction (internal order)
    writer.write_bytes(&input.txid);
    writer.write_u32_le(input.output_index);

    // 5. scriptCode (varint length + bytes)
    writer.write_var_int(params.subscript.len() as u64);
    writer.write_bytes(params.subscript);

    // 6. value (8 bytes LE)
    writer.write_u64_le(params.satoshis);

    // 7. nSequence (4 bytes LE)
    writer.write_u32_le(input.sequence);

    // 8. hashOutputs (32 bytes)
    writer.write_bytes(&hash_outputs);

    // 9. nLocktime (4 bytes LE)
    writer.write_u32_le(params.locktime);

    // 10. sighash type (4 bytes LE, unsigned)
    writer.write_u32_le(params.scope);

    writer.into_bytes()
}

/// Computes the sighash for a transaction input.
///
/// This is the main entry point for sighash computation. It builds the
/// BIP-143 style preimage and returns SHA256d(preimage).
///
/// # Arguments
///
/// * `params` - Parameters specifying the transaction and input to sign
///
/// # Returns
///
/// The 32-byte sighash digest in display order (big-endian, as typically shown)
///
/// # Example
///
/// ```rust,ignore
/// use bsv_primitives::bsv::sighash::{compute_sighash, SighashParams, SIGHASH_ALL, SIGHASH_FORKID};
///
/// let sighash = compute_sighash(&SighashParams {
///     version: 1,
///     inputs: &tx.inputs,
///     outputs: &tx.outputs,
///     locktime: 0,
///     input_index: 0,
///     subscript: &script_code,
///     satoshis: 100000,
///     scope: SIGHASH_ALL | SIGHASH_FORKID,
/// });
/// ```
pub fn compute_sighash(params: &SighashParams) -> [u8; 32] {
    let preimage = build_sighash_preimage(params);
    let mut hash = sha256d(&preimage);
    // Return in display order (reversed) to match TypeScript SDK behavior
    hash.reverse();
    hash
}

/// Computes the sighash for signing purposes.
///
/// This returns the hash in internal byte order (little-endian), which is
/// what ECDSA signing functions expect.
///
/// # Arguments
///
/// * `params` - Parameters specifying the transaction and input to sign
///
/// # Returns
///
/// The 32-byte sighash digest in internal order (for ECDSA signing)
pub fn compute_sighash_for_signing(params: &SighashParams) -> [u8; 32] {
    let preimage = build_sighash_preimage(params);
    sha256d(&preimage)
}

// ============================================================================
// Convenience Functions
// ============================================================================

/// Computes the sighash directly from a raw transaction.
///
/// This is a convenience function that parses the transaction and computes
/// the sighash in one call.
///
/// # Arguments
///
/// * `raw_tx` - The raw transaction bytes
/// * `input_index` - The index of the input being signed
/// * `subscript` - The subscript (scriptCode) to use
/// * `satoshis` - The satoshi value of the input being spent
/// * `scope` - The sighash type/scope
///
/// # Returns
///
/// The 32-byte sighash digest, or an error if parsing fails
pub fn compute_sighash_from_raw(
    raw_tx: &[u8],
    input_index: usize,
    subscript: &[u8],
    satoshis: u64,
    scope: u32,
) -> Result<[u8; 32]> {
    let tx = parse_transaction(raw_tx)?;

    if input_index >= tx.inputs.len() {
        return Err(Error::CryptoError(format!(
            "Input index {} out of range (transaction has {} inputs)",
            input_index,
            tx.inputs.len()
        )));
    }

    Ok(compute_sighash(&SighashParams {
        version: tx.version,
        inputs: &tx.inputs,
        outputs: &tx.outputs,
        locktime: tx.locktime,
        input_index,
        subscript,
        satoshis,
        scope,
    }))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_transaction() {
        // A simple 1-input, 1-output transaction
        let raw = hex::decode(
            "01000000\
             01\
             0000000000000000000000000000000000000000000000000000000000000000\
             ffffffff\
             00\
             ffffffff\
             01\
             0000000000000000\
             00\
             00000000",
        )
        .unwrap();

        let tx = parse_transaction(&raw).unwrap();
        assert_eq!(tx.version, 1);
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.locktime, 0);
        assert_eq!(tx.inputs[0].output_index, 0xffffffff); // Coinbase marker
        assert_eq!(tx.inputs[0].sequence, 0xffffffff);
    }

    #[test]
    fn test_sighash_constants() {
        assert_eq!(SIGHASH_ALL, 0x01);
        assert_eq!(SIGHASH_NONE, 0x02);
        assert_eq!(SIGHASH_SINGLE, 0x03);
        assert_eq!(SIGHASH_FORKID, 0x40);
        assert_eq!(SIGHASH_ANYONECANPAY, 0x80);
    }

    #[test]
    fn test_base_type_extraction() {
        // Test that base type extraction works correctly
        assert_eq!(SIGHASH_ALL & SIGHASH_BASE_MASK, SIGHASH_ALL);
        assert_eq!(
            (SIGHASH_ALL | SIGHASH_FORKID) & SIGHASH_BASE_MASK,
            SIGHASH_ALL
        );
        assert_eq!(
            (SIGHASH_SINGLE | SIGHASH_ANYONECANPAY | SIGHASH_FORKID) & SIGHASH_BASE_MASK,
            SIGHASH_SINGLE
        );
    }

    #[test]
    fn test_hash_prevouts_anyonecanpay() {
        let inputs = vec![TxInput {
            txid: [1u8; 32],
            output_index: 0,
            script: vec![],
            sequence: 0xffffffff,
        }];

        // With ANYONECANPAY, should return zeros
        let hash = compute_hash_prevouts(&inputs, SIGHASH_ALL | SIGHASH_ANYONECANPAY);
        assert_eq!(hash, [0u8; 32]);

        // Without ANYONECANPAY, should return actual hash
        let hash = compute_hash_prevouts(&inputs, SIGHASH_ALL);
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn test_hash_sequence_conditions() {
        let inputs = vec![TxInput {
            txid: [1u8; 32],
            output_index: 0,
            script: vec![],
            sequence: 0xffffffff,
        }];

        // ANYONECANPAY: zeros
        let hash = compute_hash_sequence(&inputs, SIGHASH_ALL | SIGHASH_ANYONECANPAY);
        assert_eq!(hash, [0u8; 32]);

        // SINGLE: zeros
        let hash = compute_hash_sequence(&inputs, SIGHASH_SINGLE);
        assert_eq!(hash, [0u8; 32]);

        // NONE: zeros
        let hash = compute_hash_sequence(&inputs, SIGHASH_NONE);
        assert_eq!(hash, [0u8; 32]);

        // ALL: actual hash
        let hash = compute_hash_sequence(&inputs, SIGHASH_ALL);
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn test_hash_outputs_all() {
        let outputs = vec![
            TxOutput {
                satoshis: 1000,
                script: vec![0x76, 0xa9],
            },
            TxOutput {
                satoshis: 2000,
                script: vec![0x76, 0xa9, 0x14],
            },
        ];

        // ALL: hash all outputs
        let hash = compute_hash_outputs(&outputs, 0, SIGHASH_ALL);
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn test_hash_outputs_single() {
        let outputs = vec![
            TxOutput {
                satoshis: 1000,
                script: vec![0x76, 0xa9],
            },
            TxOutput {
                satoshis: 2000,
                script: vec![0x76, 0xa9, 0x14],
            },
        ];

        // SINGLE with valid index
        let hash = compute_hash_outputs(&outputs, 0, SIGHASH_SINGLE);
        assert_ne!(hash, [0u8; 32]);

        // SINGLE with out-of-range index
        let hash = compute_hash_outputs(&outputs, 5, SIGHASH_SINGLE);
        assert_eq!(hash, [0u8; 32]);
    }

    #[test]
    fn test_hash_outputs_none() {
        let outputs = vec![TxOutput {
            satoshis: 1000,
            script: vec![0x76, 0xa9],
        }];

        // NONE: zeros
        let hash = compute_hash_outputs(&outputs, 0, SIGHASH_NONE);
        assert_eq!(hash, [0u8; 32]);
    }
}
