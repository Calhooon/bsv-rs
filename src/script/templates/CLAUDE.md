# BSV Script Templates
> High-level APIs for common Bitcoin script patterns

## Overview

This module provides ready-to-use templates for creating and spending common Bitcoin script types. Templates abstract away the complexity of script construction and signing, providing simple interfaces for standard transaction patterns like P2PKH (Pay-to-Public-Key-Hash) and R-Puzzles.

The implementation maintains cross-SDK compatibility with the TypeScript and Go BSV SDKs through shared script structures and signing conventions.

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | Module root; submodule declarations and public re-exports |
| `p2pkh.rs` | P2PKH template for the most common Bitcoin transaction type |
| `rpuzzle.rs` | R-Puzzle template for knowledge-based locking using ECDSA K-values |

## Key Exports

The module re-exports the following from `mod.rs`:

```rust
pub use p2pkh::P2PKH;
pub use rpuzzle::{RPuzzle, RPuzzleType};
```

### P2PKH

Pay-to-Public-Key-Hash is the most common Bitcoin transaction type. Funds are locked to a public key hash and can only be spent by providing a valid signature from the corresponding private key.

**Locking Script Pattern:**
```text
OP_DUP OP_HASH160 <20-byte pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG
```

**Unlocking Script Pattern:**
```text
<signature> <publicKey>
```

```rust
#[derive(Debug, Clone, Copy, Default)]
pub struct P2PKH;

impl P2PKH {
    /// Creates a new P2PKH template instance
    pub fn new() -> Self

    /// Creates a locking script from a Base58Check address string
    /// Supports mainnet (0x00) and testnet (0x6f) prefixes
    pub fn lock_from_address(address: &str) -> Result<LockingScript>

    /// Creates an unlock template for spending a P2PKH output
    pub fn unlock(
        private_key: &PrivateKey,
        sign_outputs: SignOutputs,
        anyone_can_pay: bool,
    ) -> ScriptTemplateUnlock

    /// Signs with a precomputed sighash (useful when transaction is already parsed)
    pub fn sign_with_sighash(
        private_key: &PrivateKey,
        sighash: &[u8; 32],
        sign_outputs: SignOutputs,
        anyone_can_pay: bool,
    ) -> Result<UnlockingScript>
}

impl ScriptTemplate for P2PKH {
    /// Creates a locking script from a 20-byte public key hash
    fn lock(&self, params: &[u8]) -> Result<LockingScript>
}
```

### RPuzzle

R-Puzzles allow anyone who knows a specific K-value (ECDSA nonce) to spend funds, regardless of which private key they use. This creates "knowledge-based" locking where the secret is the K-value rather than a private key.

**Locking Script Pattern (raw):**
```text
OP_OVER OP_3 OP_SPLIT OP_NIP OP_1 OP_SPLIT OP_SWAP OP_SPLIT OP_DROP
<r-value> OP_EQUALVERIFY OP_CHECKSIG
```

**Locking Script Pattern (hashed):**
```text
OP_OVER OP_3 OP_SPLIT OP_NIP OP_1 OP_SPLIT OP_SWAP OP_SPLIT OP_DROP
OP_<HASH> <r-hash> OP_EQUALVERIFY OP_CHECKSIG
```

The R-extraction prefix parses a DER-encoded signature to extract the R value:
1. `OP_OVER` - Copy the signature
2. `OP_3 OP_SPLIT` - Split at byte 3 (skip DER header)
3. `OP_NIP` - Remove the header bytes
4. `OP_1 OP_SPLIT` - Extract the R-length byte
5. `OP_SWAP OP_SPLIT` - Split out the R value
6. `OP_DROP` - Discard remainder

```rust
/// Hash variants for R-Puzzle locking scripts
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RPuzzleType {
    #[default]
    Raw,       // Store raw R value (largest script, simplest)
    Sha1,      // SHA-1 hash (20 bytes)
    Sha256,    // SHA-256 hash (32 bytes)
    Hash256,   // Double SHA-256 (32 bytes)
    Ripemd160, // RIPEMD-160 (20 bytes)
    Hash160,   // HASH160: RIPEMD-160(SHA-256) (20 bytes)
}

impl RPuzzleType {
    /// Computes the hash of data using this hash type
    pub fn hash(self, data: &[u8]) -> Vec<u8>
}

#[derive(Debug, Clone, Copy)]
pub struct RPuzzle {
    pub puzzle_type: RPuzzleType,
}

impl RPuzzle {
    /// Creates a new R-Puzzle template with the specified type
    pub fn new(puzzle_type: RPuzzleType) -> Self

    /// Computes the R value (x-coordinate of k*G) from a K value
    pub fn compute_r_from_k(k: &BigNumber) -> Result<[u8; 32]>

    /// Creates an unlock template for spending an R-Puzzle output
    pub fn unlock(
        k: &BigNumber,
        private_key: &PrivateKey,
        sign_outputs: SignOutputs,
        anyone_can_pay: bool,
    ) -> ScriptTemplateUnlock

    /// Signs with a precomputed sighash using a specific K value
    pub fn sign_with_sighash(
        k: &BigNumber,
        private_key: &PrivateKey,
        sighash: &[u8; 32],
        sign_outputs: SignOutputs,
        anyone_can_pay: bool,
    ) -> Result<UnlockingScript>
}

impl ScriptTemplate for RPuzzle {
    /// Creates a locking script from R value or its hash
    fn lock(&self, params: &[u8]) -> Result<LockingScript>
}
```

## Usage

### P2PKH: Lock to Public Key Hash

```rust
use bsv_sdk::script::templates::P2PKH;
use bsv_sdk::script::template::ScriptTemplate;
use bsv_sdk::primitives::ec::PrivateKey;

// Create from public key hash (20 bytes)
let private_key = PrivateKey::random();
let pubkey_hash = private_key.public_key().hash160();

let template = P2PKH::new();
let locking = template.lock(&pubkey_hash)?;
// Produces: OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG

// Or create directly from a Base58Check address
let locking = P2PKH::lock_from_address("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")?;
```

### P2PKH: Spend with Signature

```rust
use bsv_sdk::script::templates::P2PKH;
use bsv_sdk::script::template::{SignOutputs, SigningContext};
use bsv_sdk::primitives::ec::PrivateKey;

let private_key = PrivateKey::from_hex("...")?;

// Create unlock template
let unlock = P2PKH::unlock(&private_key, SignOutputs::All, false);

// Estimated length for fee calculation (108 bytes: sig + pubkey)
let estimated_size = unlock.estimate_length();

// Sign with a transaction context
let context = SigningContext::new(&raw_tx, input_index, satoshis, &locking_script);
let unlocking = unlock.sign(&context)?;
// Produces: <signature> <publicKey>
```

### P2PKH: Sign with Precomputed Sighash

```rust
use bsv_sdk::script::templates::P2PKH;
use bsv_sdk::script::template::SignOutputs;

// When you already have the sighash computed
let sighash: [u8; 32] = compute_sighash_externally();

let unlocking = P2PKH::sign_with_sighash(
    &private_key,
    &sighash,
    SignOutputs::All,
    false,  // anyone_can_pay
)?;
```

### R-Puzzle: Lock to K Value

```rust
use bsv_sdk::script::templates::{RPuzzle, RPuzzleType};
use bsv_sdk::script::template::ScriptTemplate;
use bsv_sdk::primitives::BigNumber;

// Generate or obtain a K value (must be kept secret)
let k = BigNumber::from_hex("...")?;
let r_value = RPuzzle::compute_r_from_k(&k)?;

// Lock with raw R value (largest script)
let template = RPuzzle::new(RPuzzleType::Raw);
let locking = template.lock(&r_value)?;

// Or lock with hashed R value (smaller script)
let template = RPuzzle::new(RPuzzleType::Hash160);
let r_hash = RPuzzleType::Hash160.hash(&r_value);
let locking = template.lock(&r_hash)?;
```

### R-Puzzle: Spend with K Value

```rust
use bsv_sdk::script::templates::RPuzzle;
use bsv_sdk::script::template::SignOutputs;
use bsv_sdk::primitives::ec::PrivateKey;

// The K value is the secret; any private key works for signing
let private_key = PrivateKey::random();

// Create unlock template with the K value
let unlock = RPuzzle::unlock(&k, &private_key, SignOutputs::All, false);
let unlocking = unlock.sign(&context)?;

// Or sign directly with precomputed sighash
let unlocking = RPuzzle::sign_with_sighash(
    &k,
    &private_key,
    &sighash,
    SignOutputs::All,
    false,
)?;
```

### Sighash Types

The `SignOutputs` enum and `anyone_can_pay` flag control which parts of the transaction are signed:

| SignOutputs | anyone_can_pay | Scope Byte | Description |
|-------------|----------------|------------|-------------|
| `All` | `false` | `0x41` | Sign all inputs and outputs (most common) |
| `All` | `true` | `0xC1` | Sign only this input, all outputs |
| `None` | `false` | `0x42` | Sign all inputs, no outputs |
| `None` | `true` | `0xC2` | Sign only this input, no outputs |
| `Single` | `false` | `0x43` | Sign all inputs, only the output at same index |
| `Single` | `true` | `0xC3` | Sign only this input and corresponding output |

All scope bytes include `SIGHASH_FORKID` (0x40) as required by BSV.

## Implementation Notes

### Signature Format

Both templates produce DER-encoded ECDSA signatures with:
- Appended sighash scope byte (including FORKID)
- Low-S normalization per BIP 62

### Estimated Lengths

The `estimate_length()` method returns 108 bytes for both templates:
- Signature push: 1 + 73 bytes (max DER + sighash byte)
- Public key push: 1 + 33 bytes (compressed)

This is a worst-case estimate; actual signatures may be 1-2 bytes shorter.

### R-Puzzle K Value Security

The K value for R-Puzzles must be:
- Non-zero
- Less than the secp256k1 curve order
- Kept secret until spending (anyone who knows K can spend)

The `compute_r_from_k` function computes `R = k * G` where G is the secp256k1 generator point, returning the x-coordinate.

### Low-Level Signing

The `sign_with_k` function in `rpuzzle.rs` performs raw ECDSA signing with a specific nonce:

```rust
// s = k^-1 * (z + r * d) mod n
// where z = message hash, r = R value x-coordinate, d = private key
```

This bypasses RFC 6979 deterministic nonce generation, which is necessary for R-Puzzles but should be avoided for regular signatures.

## Related Documentation

- `../CLAUDE.md` - Script module documentation
- `../template.rs` - `ScriptTemplate` trait and `SigningContext` (not in templates/)
- `../../primitives/ec/CLAUDE.md` - Elliptic curve primitives (PrivateKey, PublicKey, Signature)
- `../../primitives/bsv/CLAUDE.md` - BSV primitives (TransactionSignature, sighash computation)
- `../../CLAUDE.md` - Root SDK documentation
