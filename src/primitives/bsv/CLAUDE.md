# BSV Module
> BSV-specific cryptographic operations for transaction signing and key management

## Overview

This module provides BSV blockchain-specific operations including transaction signature hash computation (BIP-143 style), transaction signatures with sighash scope, Schnorr zero-knowledge proofs for ECDH verification, and Shamir Secret Sharing for private key backup and recovery. All implementations maintain byte-for-byte compatibility with the TypeScript and Go BSV SDKs.

## Files

| File | Lines | Purpose |
|------|-------|---------|
| `mod.rs` | 75 | Module declarations and re-exports |
| `sighash.rs` | 623 | BIP-143 style sighash computation for transaction signing |
| `tx_signature.rs` | 309 | Transaction signatures with sighash scope (checksig format) |
| `schnorr.rs` | 413 | Schnorr ZK proofs for ECDH shared secret verification |
| `polynomial.rs` | 394 | Polynomial operations for Lagrange interpolation |
| `shamir.rs` | 1007 | Shamir Secret Sharing for private key backup |

## Key Exports

### Sighash Constants

```rust
pub const SIGHASH_ALL: u32 = 0x01;          // Sign all inputs and outputs
pub const SIGHASH_NONE: u32 = 0x02;         // Sign all inputs, no outputs
pub const SIGHASH_SINGLE: u32 = 0x03;       // Sign all inputs, matching output only
pub const SIGHASH_FORKID: u32 = 0x40;       // BSV-specific BIP-143 flag
pub const SIGHASH_ANYONECANPAY: u32 = 0x80; // Sign only this input
```

### Sighash Computation

```rust
/// Parameters for computing a sighash (derives Debug)
pub struct SighashParams<'a> {
    pub version: i32,
    pub inputs: &'a [TxInput],
    pub outputs: &'a [TxOutput],
    pub locktime: u32,
    pub input_index: usize,
    pub subscript: &'a [u8],
    pub satoshis: u64,
    pub scope: u32,
}

/// Compute sighash (returns display order, big-endian)
pub fn compute_sighash(params: &SighashParams) -> [u8; 32]

/// Compute sighash for ECDSA signing (returns internal order, little-endian)
pub fn compute_sighash_for_signing(params: &SighashParams) -> [u8; 32]

/// Build the BIP-143 preimage (the message to be hashed)
pub fn build_sighash_preimage(params: &SighashParams) -> Vec<u8>

/// Convenience: parse raw tx and compute sighash in one call
pub fn compute_sighash_from_raw(
    raw_tx: &[u8],
    input_index: usize,
    subscript: &[u8],
    satoshis: u64,
    scope: u32,
) -> Result<[u8; 32]>
```

### Transaction Structures

```rust
/// A transaction input (derives Debug, Clone)
pub struct TxInput {
    pub txid: [u8; 32],      // Previous tx ID (internal byte order)
    pub output_index: u32,
    pub script: Vec<u8>,      // scriptSig
    pub sequence: u32,
}

/// A transaction output (derives Debug, Clone)
pub struct TxOutput {
    pub satoshis: u64,
    pub script: Vec<u8>,      // scriptPubKey
}

/// A parsed raw transaction (derives Debug, Clone)
pub struct RawTransaction {
    pub version: i32,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub locktime: u32,
}

/// Parse a serialized transaction
pub fn parse_transaction(raw: &[u8]) -> Result<RawTransaction>
```

### Transaction Signature

```rust
/// ECDSA signature with sighash scope for OP_CHECKSIG
/// Derives Clone, PartialEq, Eq. Implements Debug (hex-formatted) and Display.
pub struct TransactionSignature {
    // Private fields: signature (Signature), scope (u32)
}

impl TransactionSignature {
    pub fn new(signature: Signature, scope: u32) -> Self
    pub fn from_components(r: [u8; 32], s: [u8; 32], scope: u32) -> Self
    pub fn from_checksig_format(data: &[u8]) -> Result<Self>  // Empty data → blank sig

    pub fn signature(&self) -> &Signature
    pub fn scope(&self) -> u32
    pub fn r(&self) -> &[u8; 32]
    pub fn s(&self) -> &[u8; 32]

    pub fn has_low_s(&self) -> bool           // BIP-62 check
    pub fn to_low_s(&self) -> Self            // Convert to low-S form

    pub fn to_checksig_format(&self) -> Vec<u8>  // DER || sighash_byte
    pub fn to_der(&self) -> Vec<u8>
    pub fn to_compact(&self) -> [u8; 64]         // R || S
}

// Display outputs hex-encoded checksig format
impl Display for TransactionSignature { ... }

// Debug outputs struct with hex-encoded R, S, and scope
impl Debug for TransactionSignature { ... }
```

**Blank signature handling**: `from_checksig_format(&[])` creates a placeholder signature with R=1, S=1, scope=1. This is used for unsigned inputs during transaction construction.

### Schnorr ZK Proofs

```rust
/// A Schnorr zero-knowledge proof (derives Clone, Debug)
pub struct SchnorrProof {
    pub r: PublicKey,       // R = r*G (nonce commitment)
    pub s_prime: PublicKey, // S' = r*B (blinded shared secret)
    pub z: BigNumber,       // z = r + e*a mod n (response)
}

/// Schnorr ZK proof generation and verification
pub struct Schnorr;

impl Schnorr {
    /// Generate proof of private key knowledge and ECDH computation
    pub fn generate_proof(
        a: &PrivateKey,      // Prover's private key
        big_a: &PublicKey,   // Prover's public key (a*G)
        big_b: &PublicKey,   // Other party's public key
        big_s: &PublicKey,   // Shared secret (a*B)
    ) -> Result<SchnorrProof>

    /// Verify a Schnorr proof
    pub fn verify_proof(
        big_a: &PublicKey,
        big_b: &PublicKey,
        big_s: &PublicKey,
        proof: &SchnorrProof,
    ) -> bool
}
```

**Verification algorithm**:
1. Recompute challenge `e = SHA256(A || B || S || S' || R) mod n` (Fiat-Shamir)
2. Check `z*G == R + e*A`
3. Check `z*B == S' + e*S`

All points serialized in 33-byte compressed format for the challenge hash.

### Shamir Secret Sharing

```rust
/// A collection of key shares for recovery (derives Clone, Debug)
pub struct KeyShares {
    pub points: Vec<PointInFiniteField>,
    pub threshold: usize,
    pub integrity: String,  // First 4 chars of base58(sha256(secret))
}

impl KeyShares {
    pub fn new(points: Vec<PointInFiniteField>, threshold: usize, integrity: String) -> Self
    pub fn from_backup_format(shares: &[String]) -> Result<Self>
    pub fn to_backup_format(&self) -> Vec<String>
    pub fn recover_private_key(&self) -> Result<PrivateKey>
}

/// Split a private key into shares
pub fn split_private_key(
    key: &PrivateKey,
    threshold: usize,  // Minimum shares needed (2..=255)
    total: usize,      // Total shares to generate (>= threshold)
) -> Result<KeyShares>
```

**Parameter constraints**:
- `threshold` must be >= 2 (1-of-N is just copying the secret)
- `threshold` must be <= 255
- `total` must be >= `threshold`

**Recovery validation**:
- `from_backup_format` validates that all shares have matching threshold and integrity values
- `recover_private_key` checks that `points.len() >= threshold` before interpolation
- After recovery, the integrity checksum is verified against the recovered key

### Polynomial Operations

```rust
/// A point in a finite field (for Shamir shares)
/// Derives Clone, Debug, PartialEq, Eq. Implements Display (same as to_point_string).
pub struct PointInFiniteField {
    pub x: BigNumber,
    pub y: BigNumber,
}

impl PointInFiniteField {
    pub fn new(x: BigNumber, y: BigNumber) -> Self   // Reduces mod secp256k1 prime
    pub fn from_string(s: &str) -> Result<Self>       // "base58(x).base58(y)"
    pub fn to_point_string(&self) -> String
}

/// Polynomial for Lagrange interpolation (derives Clone, Debug)
pub struct Polynomial {
    pub points: Vec<PointInFiniteField>,
    pub threshold: usize,
}

impl Polynomial {
    pub fn new(points: Vec<PointInFiniteField>, threshold: usize) -> Self
    pub fn value_at(&self, x: &BigNumber) -> BigNumber  // Lagrange interpolation
}
```

**Lagrange interpolation formula**: `y = Σ(i=0..t-1) y_i * Π(j≠i) (x - x_j) / (x_i - x_j)`, all arithmetic mod secp256k1 prime. Uses modular inverse for division; returns zero if inverse fails (e.g., duplicate x coordinates).

## Internal Functions

These are not publicly exported but are key to understanding the implementation:

| Function | File | Purpose |
|----------|------|---------|
| `compute_hash_prevouts()` | sighash.rs | SHA256d of all input outpoints (zeros if ANYONECANPAY) |
| `compute_hash_sequence()` | sighash.rs | SHA256d of all input sequences (zeros if ANYONECANPAY/SINGLE/NONE) |
| `compute_hash_outputs()` | sighash.rs | SHA256d of outputs (all, single, or zeros depending on scope) |
| `compute_challenge()` | schnorr.rs | Fiat-Shamir challenge: `SHA256(A\|\|B\|\|S\|\|S'\|\|R) mod n` |
| `evaluate_polynomial()` | shamir.rs | Horner's method polynomial evaluation mod prime |
| `compute_integrity()` | shamir.rs | First 4 chars of `base58(sha256(key_bytes))` |
| `decode_share()` | shamir.rs | Parse backup format string into point + threshold + integrity |

## Usage

### Computing a Sighash

```rust
use bsv_sdk::primitives::bsv::sighash::{
    compute_sighash, parse_transaction, SighashParams,
    SIGHASH_ALL, SIGHASH_FORKID,
};

// Parse raw transaction bytes
let raw_tx = hex::decode("0100000001...").unwrap();
let tx = parse_transaction(&raw_tx).unwrap();

// The subscript is typically the scriptPubKey of the UTXO being spent
let subscript = hex::decode("76a914...88ac").unwrap();

// Compute sighash for input 0
let sighash = compute_sighash(&SighashParams {
    version: tx.version,
    inputs: &tx.inputs,
    outputs: &tx.outputs,
    locktime: tx.locktime,
    input_index: 0,
    subscript: &subscript,
    satoshis: 100_000,  // Value of the UTXO being spent
    scope: SIGHASH_ALL | SIGHASH_FORKID,
});
```

### Creating and Parsing Transaction Signatures

```rust
use bsv_sdk::primitives::bsv::tx_signature::TransactionSignature;
use bsv_sdk::primitives::bsv::sighash::{SIGHASH_ALL, SIGHASH_FORKID};

// Parse from checksig format (DER || sighash_byte)
let checksig_bytes = hex::decode("3044...41").unwrap();
let tx_sig = TransactionSignature::from_checksig_format(&checksig_bytes).unwrap();

// Check sighash type
let scope = tx_sig.scope();
if scope & 0xff == SIGHASH_ALL | SIGHASH_FORKID {
    println!("Standard BSV signature");
}

// Ensure low-S form (BIP-62 compliance)
let normalized = tx_sig.to_low_s();

// Encode back to checksig format for use in scripts
let encoded = normalized.to_checksig_format();

// Display as hex string
println!("{}", tx_sig);  // Outputs hex-encoded checksig format
```

### Proving ECDH Computation with Schnorr

```rust
use bsv_sdk::primitives::ec::PrivateKey;
use bsv_sdk::primitives::bsv::schnorr::Schnorr;

// Alice and Bob have key pairs
let alice = PrivateKey::random();
let bob = PrivateKey::random();

// Alice computes shared secret
let shared = alice.derive_shared_secret(&bob.public_key()).unwrap();

// Alice generates a proof she knows her private key and computed S correctly
let proof = Schnorr::generate_proof(
    &alice,
    &alice.public_key(),
    &bob.public_key(),
    &shared,
).unwrap();

// Anyone can verify without learning Alice's private key
let valid = Schnorr::verify_proof(
    &alice.public_key(),
    &bob.public_key(),
    &shared,
    &proof,
);
assert!(valid);
```

### Splitting and Recovering Private Keys

```rust
use bsv_sdk::primitives::bsv::shamir::{split_private_key, KeyShares};
use bsv_sdk::primitives::ec::PrivateKey;

// Generate a key to protect
let key = PrivateKey::random();

// Split into 5 shares with threshold of 3
let shares = split_private_key(&key, 3, 5).unwrap();

// Export to backup format for storage
let backup: Vec<String> = shares.to_backup_format();
// Each string: "base58(x).base58(y).threshold.integrity"

// Later, recover from any 3 shares
let subset = KeyShares::from_backup_format(&backup[0..3]).unwrap();
let recovered = subset.recover_private_key().unwrap();

assert_eq!(key.to_bytes(), recovered.to_bytes());
```

## BIP-143 Preimage Format

The sighash preimage follows this exact layout (used by `build_sighash_preimage`):

| Field | Size | Description |
|-------|------|-------------|
| nVersion | 4 bytes LE | Transaction version |
| hashPrevouts | 32 bytes | SHA256d of all outpoints (or zeros) |
| hashSequence | 32 bytes | SHA256d of all sequences (or zeros) |
| outpoint | 36 bytes | txid (32) + output index (4) of the input being signed |
| scriptCode | varint + N bytes | The subscript for signing |
| value | 8 bytes LE | Satoshi value of the input being spent |
| nSequence | 4 bytes LE | Sequence of the input being signed |
| hashOutputs | 32 bytes | SHA256d of outputs (all, single, or zeros) |
| nLocktime | 4 bytes LE | Transaction locktime |
| sighash type | 4 bytes LE | Sighash scope flags |

## Sighash Types Explained

| Type | Value | Description |
|------|-------|-------------|
| `SIGHASH_ALL` | 0x01 | Sign all inputs and all outputs (most common) |
| `SIGHASH_NONE` | 0x02 | Sign all inputs, allow anyone to modify outputs |
| `SIGHASH_SINGLE` | 0x03 | Sign all inputs, only the output at same index |
| `SIGHASH_FORKID` | 0x40 | BSV flag for BIP-143 style hashing (required) |
| `SIGHASH_ANYONECANPAY` | 0x80 | Sign only this input, allow others to add inputs |

Common combinations:
- `SIGHASH_ALL | SIGHASH_FORKID` (0x41) - Standard BSV signature
- `SIGHASH_ALL | SIGHASH_FORKID | SIGHASH_ANYONECANPAY` (0xC1) - Crowdfunding

Base type extraction uses `SIGHASH_BASE_MASK` (0x1F) internally.

## Backup Format

Shamir shares use this string format for storage:

```
base58(x).base58(y).threshold.integrity
```

Example: `2.8hKJ7vP...3.ABCD`

- `2`: x-coordinate (share index, starting at 1)
- `8hKJ7vP...`: y-coordinate (the share value in base58)
- `3`: threshold (minimum shares needed)
- `ABCD`: integrity checksum (first 4 chars of base58(sha256(secret)))

The integrity field allows verification that shares belong together and that recovery succeeded. `from_backup_format` validates that all shares have consistent threshold and integrity values.

## Security Notes

### Sighash
- Always include `SIGHASH_FORKID` for BSV transactions
- `compute_sighash` returns display order (reversed); use `compute_sighash_for_signing` for ECDSA
- `compute_sighash_from_raw` validates input_index is within range

### Transaction Signatures
- Always normalize to low-S form for BIP-62 compliance using `to_low_s()`
- Check with `has_low_s()` before broadcasting
- `from_checksig_format` re-exports sighash constants for convenience

### Schnorr Proofs
- Proofs are non-transferable (bound to specific public keys A and B)
- Uses Fiat-Shamir heuristic for non-interactive verification
- Challenge hash: `SHA256(A || B || S || S' || R) mod n` (5 compressed points, 165 bytes)
- Both parties can independently generate and verify proofs for the same shared secret

### Shamir Secret Sharing
- Threshold must be >= 2 and <= 255 (1-of-N is just copying)
- All arithmetic is modulo the secp256k1 field prime
- Polynomial coefficients generated from `PrivateKey::random()` for cryptographic randomness
- Store shares in separate secure locations
- Never store more than (threshold - 1) shares together
- Duplicate shares in recovery cause failure (Lagrange interpolation requires unique x-coordinates)
- Providing more shares than threshold works (only first `threshold` points are used)

## Testing

| File | Tests | Coverage |
|------|-------|----------|
| `sighash.rs` | 7 unit tests | Parsing, constants, hash component conditions |
| `tx_signature.rs` | 6 unit tests | Roundtrip, blank sig, scope values, low-S |
| `schnorr.rs` | 7 unit tests | Roundtrip, wrong inputs, mutual verification, deterministic challenge |
| `polynomial.rs` | 6 unit tests | Linear/quadratic/constant polys, large numbers, string roundtrip |
| `shamir.rs` | 21 unit tests | Split/recover, backup format, edge cases, parameter validation |

Cross-SDK sighash test vectors (500 vectors) are in `tests/vectors/` and exercised by integration tests.

## Related Documentation

- `../CLAUDE.md` - Primitives module documentation
- `../ec/CLAUDE.md` - Elliptic curve operations (PrivateKey, PublicKey, Signature)
- `/CLAUDE.md` - Root SDK documentation
