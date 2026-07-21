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
//! use bsv_rs::primitives::bsv::sighash::{compute_sighash, SighashParams, parse_transaction};
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
//!
//! # Midstate reuse: [`SighashCache`]
//!
//! The free functions above recompute the three BIP-143 midstates
//! (`hashPrevouts`, `hashSequence`, `hashOutputs`) on every call, which makes
//! signing an n-input transaction O(n²) in hashing work. When computing
//! sighashes for more than one input of the same transaction, use
//! [`SighashCache`], which computes each midstate lazily at most once per
//! scope class and reuses it across inputs:
//!
//! ```rust,ignore
//! use bsv_rs::primitives::bsv::sighash::{SighashCache, SIGHASH_ALL, SIGHASH_FORKID};
//!
//! let mut cache = SighashCache::new(&tx);
//! for i in 0..tx.inputs.len() {
//!     let digest = cache
//!         .sighash_for_signing(i, &subscript, satoshis[i], SIGHASH_ALL | SIGHASH_FORKID)
//!         .unwrap();
//!     // feed `digest` to PrivateKey::sign ...
//! }
//! ```
//!
//! # ECDSA digest handling (RFC 6979, digest >= n)
//!
//! The 32-byte signing-order digests produced by this module feed
//! [`crate::primitives::ec::PrivateKey::sign`], which uses k256's RFC 6979
//! deterministic nonce generation. For the astronomically unlikely case of a
//! digest >= n (the secp256k1 group order; P ≈ 2⁻¹²⁸ for sha256d output),
//! k256 seeds the nonce DRBG with `bits2octets(digest)` exactly per
//! RFC 6979 §2.3.4, whereas libsecp256k1 and the TypeScript `@bsv/sdk` seed
//! it with the raw digest bytes. The two derivations agree for every in-range
//! digest (< n) and diverge only for digest >= n; in that regime both stacks
//! still produce *valid* low-S signatures over the same reduced message —
//! only the deterministic signature bytes differ. In-range digests are signed
//! byte-identically across all three stacks. This asymmetry is pinned by
//! `rfc6979_in_range_digest_der_is_pinned` and
//! `rfc6979_digest_ge_n_der_is_pinned` in `tests/ec_tests.rs` so a future
//! k256 upgrade that changes it is noticed.

use crate::error::{Error, Result};
use crate::primitives::encoding::{bounded_capacity, Reader, Writer};
use crate::primitives::hash::sha256d;
use std::collections::HashMap;

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
/// use bsv_rs::primitives::bsv::sighash::parse_transaction;
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
    // Each input is >= 41 bytes (txid 32 + vout 4 + script len 1 + sequence 4);
    // bound the pre-allocation so a bogus count varint cannot OOM-abort here.
    let mut inputs = Vec::with_capacity(bounded_capacity(input_count, reader.remaining(), 41));

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
    // Each output is >= 9 bytes (satoshis 8 + script len 1); bound the
    // pre-allocation so a bogus count cannot OOM-abort before any read.
    let mut outputs = Vec::with_capacity(bounded_capacity(output_count, reader.remaining(), 9));

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
///
/// This is a thin wrapper over a fresh single-use [`SighashCache`], so the
/// preimage logic exists exactly once in the crate. When computing preimages
/// for more than one input of the same transaction, use [`SighashCache`]
/// directly to reuse the midstate hashes.
///
/// # Panics
///
/// Panics if `params.input_index` is out of range (the historical contract of
/// this function; [`SighashCache::preimage`] returns an error instead).
pub fn build_sighash_preimage(params: &SighashParams) -> Vec<u8> {
    let mut cache = SighashCache::from_parts(
        params.version,
        params.inputs,
        params.outputs,
        params.locktime,
    );
    match cache.preimage(
        params.input_index,
        params.subscript,
        params.satoshis,
        params.scope,
    ) {
        Ok(preimage) => preimage,
        Err(_) => panic!(
            "input index {} out of range (transaction has {} inputs)",
            params.input_index,
            params.inputs.len()
        ),
    }
}

// ============================================================================
// SighashCache — midstate reuse across inputs
// ============================================================================

/// A cache of the BIP-143 midstate hashes (`hashPrevouts`, `hashSequence`,
/// `hashOutputs`) over one transaction, following rust-bitcoin's
/// `SighashCache` pattern.
///
/// The free functions ([`build_sighash_preimage`], [`compute_sighash`],
/// [`compute_sighash_for_signing`]) recompute all three midstates on every
/// call, so per-input signing of an n-input transaction performs O(n²)
/// hashing. `SighashCache` computes each midstate lazily, at most once per
/// scope class, and reuses it across inputs.
///
/// One cache instance may serve **mixed sighash scopes**: every cached value
/// is stored only for the scope class it is valid in. `hashPrevouts` is
/// cached only for non-ANYONECANPAY scopes (ANYONECANPAY short-circuits to
/// zeros without touching the cache); `hashSequence` only for the ALL class;
/// `hashOutputs` once for the ALL class and per input index for in-range
/// SINGLE. Interleaving scopes on one cache is therefore byte-identical to
/// fresh per-call computation (asserted by unit tests).
///
/// The cache borrows the transaction, so the transaction cannot be mutated
/// while the cache is alive — a stale-midstate hazard by construction.
///
/// # Example
///
/// ```rust,ignore
/// use bsv_rs::primitives::bsv::sighash::{
///     parse_transaction, SighashCache, SIGHASH_ALL, SIGHASH_FORKID,
/// };
///
/// let tx = parse_transaction(&raw_tx).unwrap();
/// let mut cache = SighashCache::new(&tx);
/// for i in 0..tx.inputs.len() {
///     let digest = cache
///         .sighash_for_signing(i, &subscripts[i], satoshis[i], SIGHASH_ALL | SIGHASH_FORKID)
///         .unwrap();
///     // feed `digest` to PrivateKey::sign ...
/// }
/// ```
#[derive(Debug, Clone)]
pub struct SighashCache<'t> {
    version: i32,
    inputs: &'t [TxInput],
    outputs: &'t [TxOutput],
    locktime: u32,
    /// Cached hashPrevouts — valid for every non-ANYONECANPAY scope.
    hash_prevouts: Option<[u8; 32]>,
    /// Cached hashSequence — valid for every scope in the ALL class
    /// (!ANYONECANPAY && base not in {SINGLE, NONE}).
    hash_sequence: Option<[u8; 32]>,
    /// Cached hashOutputs for the ALL class (base not in {SINGLE, NONE}).
    hash_outputs_all: Option<[u8; 32]>,
    /// Cached hashOutputs per input index for in-range SIGHASH_SINGLE.
    hash_outputs_single: HashMap<usize, [u8; 32]>,
}

impl<'t> SighashCache<'t> {
    /// Creates a cache over a parsed transaction.
    pub fn new(tx: &'t RawTransaction) -> Self {
        Self::from_parts(tx.version, &tx.inputs, &tx.outputs, tx.locktime)
    }

    /// Creates a cache from transaction parts, for callers that hold the
    /// inputs/outputs as slices rather than a [`RawTransaction`] (e.g. the
    /// script interpreter).
    pub fn from_parts(
        version: i32,
        inputs: &'t [TxInput],
        outputs: &'t [TxOutput],
        locktime: u32,
    ) -> Self {
        Self {
            version,
            inputs,
            outputs,
            locktime,
            hash_prevouts: None,
            hash_sequence: None,
            hash_outputs_all: None,
            hash_outputs_single: HashMap::new(),
        }
    }

    /// `hashPrevouts` for `scope`: zeros under ANYONECANPAY, otherwise the
    /// (cached) SHA256d over all input outpoints.
    pub fn hash_prevouts(&mut self, scope: u32) -> [u8; 32] {
        if (scope & SIGHASH_ANYONECANPAY) != 0 {
            return [0u8; 32];
        }
        let inputs = self.inputs;
        *self
            .hash_prevouts
            .get_or_insert_with(|| compute_hash_prevouts(inputs, scope))
    }

    /// `hashSequence` for `scope`: zeros under ANYONECANPAY/SINGLE/NONE,
    /// otherwise the (cached) SHA256d over all input sequence numbers.
    pub fn hash_sequence(&mut self, scope: u32) -> [u8; 32] {
        let base_type = scope & SIGHASH_BASE_MASK;
        if (scope & SIGHASH_ANYONECANPAY) != 0
            || base_type == SIGHASH_SINGLE
            || base_type == SIGHASH_NONE
        {
            return [0u8; 32];
        }
        let inputs = self.inputs;
        *self
            .hash_sequence
            .get_or_insert_with(|| compute_hash_sequence(inputs, scope))
    }

    /// `hashOutputs` for `(input_index, scope)`: all outputs for the ALL
    /// class (cached once), the matching output for in-range SINGLE (cached
    /// per index), zeros for NONE and out-of-range SINGLE.
    pub fn hash_outputs(&mut self, input_index: usize, scope: u32) -> [u8; 32] {
        let base_type = scope & SIGHASH_BASE_MASK;
        let outputs = self.outputs;
        if base_type != SIGHASH_SINGLE && base_type != SIGHASH_NONE {
            *self
                .hash_outputs_all
                .get_or_insert_with(|| compute_hash_outputs(outputs, input_index, scope))
        } else if base_type == SIGHASH_SINGLE && input_index < outputs.len() {
            *self
                .hash_outputs_single
                .entry(input_index)
                .or_insert_with(|| compute_hash_outputs(outputs, input_index, scope))
        } else {
            [0u8; 32]
        }
    }

    /// Builds the BIP-143 preimage for one input, reusing cached midstates.
    ///
    /// Byte-identical to [`build_sighash_preimage`] for the same parameters.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CryptoError`] if `input_index` is out of range.
    pub fn preimage(
        &mut self,
        input_index: usize,
        subscript: &[u8],
        satoshis: u64,
        scope: u32,
    ) -> Result<Vec<u8>> {
        let inputs = self.inputs;
        let input = inputs.get(input_index).ok_or_else(|| {
            Error::CryptoError(format!(
                "Input index {} out of range (transaction has {} inputs)",
                input_index,
                inputs.len()
            ))
        })?;

        let hash_prevouts = self.hash_prevouts(scope);
        let hash_sequence = self.hash_sequence(scope);
        let hash_outputs = self.hash_outputs(input_index, scope);

        let mut writer = Writer::with_capacity(
            4 + // version
            32 + // hashPrevouts
            32 + // hashSequence
            32 + // txid
            4 + // output index
            9 + subscript.len() + // scriptCode (varint + data)
            8 + // value
            4 + // sequence
            32 + // hashOutputs
            4 + // locktime
            4, // sighash type
        );

        // 1. nVersion (4 bytes, signed LE)
        writer.write_i32_le(self.version);

        // 2. hashPrevouts (32 bytes)
        writer.write_bytes(&hash_prevouts);

        // 3. hashSequence (32 bytes)
        writer.write_bytes(&hash_sequence);

        // 4. outpoint (32 bytes txid + 4 bytes index)
        // The txid is written in the same byte order as stored in the
        // transaction (internal order)
        writer.write_bytes(&input.txid);
        writer.write_u32_le(input.output_index);

        // 5. scriptCode (varint length + bytes)
        writer.write_var_int(subscript.len() as u64);
        writer.write_bytes(subscript);

        // 6. value (8 bytes LE)
        writer.write_u64_le(satoshis);

        // 7. nSequence (4 bytes LE)
        writer.write_u32_le(input.sequence);

        // 8. hashOutputs (32 bytes)
        writer.write_bytes(&hash_outputs);

        // 9. nLocktime (4 bytes LE)
        writer.write_u32_le(self.locktime);

        // 10. sighash type (4 bytes LE, unsigned)
        writer.write_u32_le(scope);

        Ok(writer.into_bytes())
    }

    /// Computes the sighash digest in display order (reversed, as typically
    /// shown). Equal to [`compute_sighash`] for the same parameters.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CryptoError`] if `input_index` is out of range.
    pub fn sighash(
        &mut self,
        input_index: usize,
        subscript: &[u8],
        satoshis: u64,
        scope: u32,
    ) -> Result<[u8; 32]> {
        let preimage = self.preimage(input_index, subscript, satoshis, scope)?;
        let mut hash = sha256d(&preimage);
        hash.reverse();
        Ok(hash)
    }

    /// Computes the sighash digest in internal (signing) order, ready for
    /// ECDSA. Equal to [`compute_sighash_for_signing`] for the same
    /// parameters.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CryptoError`] if `input_index` is out of range.
    pub fn sighash_for_signing(
        &mut self,
        input_index: usize,
        subscript: &[u8],
        satoshis: u64,
        scope: u32,
    ) -> Result<[u8; 32]> {
        let preimage = self.preimage(input_index, subscript, satoshis, scope)?;
        Ok(sha256d(&preimage))
    }
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
/// use bsv_rs::primitives::bsv::sighash::{compute_sighash, SighashParams, SIGHASH_ALL, SIGHASH_FORKID};
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

    // ========================================================================
    // SighashCache byte-equality tests (mirrors the native-engine-poc spike's
    // scope-class tests): the cached path must be byte-identical to fresh
    // per-call computation for EVERY scope class and every input.
    // ========================================================================

    /// Deterministic little tx builder: n_in inputs, n_out outputs.
    fn cache_test_tx(n_in: usize, n_out: usize) -> RawTransaction {
        let inputs = (0..n_in)
            .map(|i| {
                let mut txid = [0u8; 32];
                txid[0] = i as u8;
                txid[31] = 0xaa;
                TxInput {
                    txid,
                    output_index: i as u32,
                    script: vec![],
                    sequence: 0xffff_ffff - i as u32,
                }
            })
            .collect();
        let outputs = (0..n_out)
            .map(|i| {
                let mut script = vec![0x76, 0xa9, 0x14];
                script.extend((0..20).map(|j| (i + j) as u8));
                script.extend([0x88, 0xac]);
                TxOutput {
                    satoshis: 1000 + i as u64,
                    script,
                }
            })
            .collect();
        RawTransaction {
            version: 1,
            inputs,
            outputs,
            locktime: 17,
        }
    }

    const CACHE_TEST_LOCK: [u8; 25] = [
        0x76, 0xa9, 0x14, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 0x88, 0xac,
    ];

    /// Every scope class (ALL/NONE/SINGLE × ANYONECANPAY, FORKID set, plus
    /// non-standard base values that behave as ALL) — one shared cache across
    /// all inputs must equal the free function on every call.
    #[test]
    fn sighash_cache_preimage_equals_free_functions_all_scope_classes() {
        let tx = cache_test_tx(7, 3);
        let scopes = [
            SIGHASH_ALL | SIGHASH_FORKID,
            SIGHASH_NONE | SIGHASH_FORKID,
            SIGHASH_SINGLE | SIGHASH_FORKID,
            SIGHASH_ALL | SIGHASH_FORKID | SIGHASH_ANYONECANPAY,
            SIGHASH_NONE | SIGHASH_FORKID | SIGHASH_ANYONECANPAY,
            SIGHASH_SINGLE | SIGHASH_FORKID | SIGHASH_ANYONECANPAY,
            // non-standard base values behave as ALL in both paths
            0x04 | SIGHASH_FORKID,
            0x1f | SIGHASH_FORKID,
        ];
        for &scope in &scopes {
            let mut cache = SighashCache::new(&tx);
            for i in 0..tx.inputs.len() {
                let params = SighashParams {
                    version: tx.version,
                    inputs: &tx.inputs,
                    outputs: &tx.outputs,
                    locktime: tx.locktime,
                    input_index: i,
                    subscript: &CACHE_TEST_LOCK,
                    satoshis: 500 + i as u64,
                    scope,
                };
                let cached = cache
                    .preimage(i, &CACHE_TEST_LOCK, 500 + i as u64, scope)
                    .unwrap();
                assert_eq!(
                    cached,
                    build_sighash_preimage(&params),
                    "preimage: scope {scope:#x} input {i}"
                );
                assert_eq!(
                    cache
                        .sighash(i, &CACHE_TEST_LOCK, 500 + i as u64, scope)
                        .unwrap(),
                    compute_sighash(&params),
                    "sighash (display order): scope {scope:#x} input {i}"
                );
                assert_eq!(
                    cache
                        .sighash_for_signing(i, &CACHE_TEST_LOCK, 500 + i as u64, scope)
                        .unwrap(),
                    compute_sighash_for_signing(&params),
                    "sighash (signing order): scope {scope:#x} input {i}"
                );
            }
        }
    }

    /// Interleaving different scopes on ONE cache must be byte-identical to
    /// fresh per-call computation (cached values must never leak across scope
    /// classes).
    #[test]
    fn sighash_cache_mixed_scopes_on_one_cache() {
        let tx = cache_test_tx(6, 2);
        let scopes = [
            SIGHASH_ALL | SIGHASH_FORKID,
            SIGHASH_SINGLE | SIGHASH_FORKID,
            SIGHASH_NONE | SIGHASH_FORKID | SIGHASH_ANYONECANPAY,
            SIGHASH_ALL | SIGHASH_FORKID,
            SIGHASH_SINGLE | SIGHASH_FORKID | SIGHASH_ANYONECANPAY,
            SIGHASH_NONE | SIGHASH_FORKID,
        ];
        let mut cache = SighashCache::new(&tx);
        for (i, &scope) in scopes.iter().enumerate() {
            let cached = cache.preimage(i, &CACHE_TEST_LOCK, 42, scope).unwrap();
            let fresh = build_sighash_preimage(&SighashParams {
                version: tx.version,
                inputs: &tx.inputs,
                outputs: &tx.outputs,
                locktime: tx.locktime,
                input_index: i,
                subscript: &CACHE_TEST_LOCK,
                satoshis: 42,
                scope,
            });
            assert_eq!(cached, fresh, "input {i} scope {scope:#x}");
        }
    }

    /// SINGLE with input_index >= outputs.len() must hit the zeros branch —
    /// and still equal the free function exactly (the fund-loss family).
    #[test]
    fn sighash_cache_single_out_of_range_zeros() {
        let tx = cache_test_tx(5, 2);
        let scope = SIGHASH_SINGLE | SIGHASH_FORKID;
        let mut cache = SighashCache::new(&tx);
        for i in 2..5 {
            let cached = cache.preimage(i, &CACHE_TEST_LOCK, 42, scope).unwrap();
            let fresh = build_sighash_preimage(&SighashParams {
                version: tx.version,
                inputs: &tx.inputs,
                outputs: &tx.outputs,
                locktime: tx.locktime,
                input_index: i,
                subscript: &CACHE_TEST_LOCK,
                satoshis: 42,
                scope,
            });
            assert_eq!(cached, fresh, "input {i}");
            // zeros branch really taken (hashOutputs field)
            assert_eq!(&cached[cached.len() - 40..cached.len() - 8], &[0u8; 32]);
        }
    }

    /// `from_parts` and `new(&tx)` must be equivalent.
    #[test]
    fn sighash_cache_from_parts_equals_new() {
        let tx = cache_test_tx(3, 3);
        let scope = SIGHASH_ALL | SIGHASH_FORKID;
        let mut a = SighashCache::new(&tx);
        let mut b = SighashCache::from_parts(tx.version, &tx.inputs, &tx.outputs, tx.locktime);
        for i in 0..3 {
            assert_eq!(
                a.preimage(i, &CACHE_TEST_LOCK, 7, scope).unwrap(),
                b.preimage(i, &CACHE_TEST_LOCK, 7, scope).unwrap(),
            );
        }
    }

    /// Out-of-range input index is an error (not a panic) on the cache API.
    #[test]
    fn sighash_cache_input_index_out_of_range_errors() {
        let tx = cache_test_tx(2, 1);
        let mut cache = SighashCache::new(&tx);
        let scope = SIGHASH_ALL | SIGHASH_FORKID;
        assert!(cache.preimage(2, &CACHE_TEST_LOCK, 1, scope).is_err());
        assert!(cache.sighash(9, &CACHE_TEST_LOCK, 1, scope).is_err());
        assert!(cache
            .sighash_for_signing(2, &CACHE_TEST_LOCK, 1, scope)
            .is_err());
        // In-range still fine after the errors.
        assert!(cache.preimage(1, &CACHE_TEST_LOCK, 1, scope).is_ok());
    }

    /// The midstates really are cached: a second call in the same scope class
    /// must not recompute (observed via the cache fields).
    #[test]
    fn sighash_cache_midstates_computed_once() {
        let tx = cache_test_tx(4, 2);
        let mut cache = SighashCache::new(&tx);

        // ANYONECANPAY never populates the prevouts cache.
        cache
            .preimage(
                0,
                &CACHE_TEST_LOCK,
                1,
                SIGHASH_ALL | SIGHASH_FORKID | SIGHASH_ANYONECANPAY,
            )
            .unwrap();
        assert!(cache.hash_prevouts.is_none());
        assert!(cache.hash_sequence.is_none());

        // ALL populates all three midstates once.
        cache
            .preimage(0, &CACHE_TEST_LOCK, 1, SIGHASH_ALL | SIGHASH_FORKID)
            .unwrap();
        let prevouts = cache.hash_prevouts;
        let sequence = cache.hash_sequence;
        let outputs_all = cache.hash_outputs_all;
        assert!(prevouts.is_some() && sequence.is_some() && outputs_all.is_some());

        // Further calls reuse the same cached values.
        cache
            .preimage(3, &CACHE_TEST_LOCK, 1, SIGHASH_ALL | SIGHASH_FORKID)
            .unwrap();
        assert_eq!(cache.hash_prevouts, prevouts);
        assert_eq!(cache.hash_sequence, sequence);
        assert_eq!(cache.hash_outputs_all, outputs_all);

        // SINGLE caches per-index output hashes.
        cache
            .preimage(1, &CACHE_TEST_LOCK, 1, SIGHASH_SINGLE | SIGHASH_FORKID)
            .unwrap();
        assert!(cache.hash_outputs_single.contains_key(&1));
        // Out-of-range SINGLE (zeros) is not cached.
        cache
            .preimage(3, &CACHE_TEST_LOCK, 1, SIGHASH_SINGLE | SIGHASH_FORKID)
            .unwrap();
        assert!(!cache.hash_outputs_single.contains_key(&3));
    }
}
