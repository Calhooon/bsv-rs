# BSV Script Templates
> High-level APIs for common Bitcoin script patterns

## Overview

This module provides ready-to-use templates for creating and spending common Bitcoin script types. Templates abstract away the complexity of script construction and signing, providing simple interfaces for standard transaction patterns like P2PKH (Pay-to-Public-Key-Hash), P2PK (Pay-to-Public-Key), Multisig (M-of-N), R-Puzzles, and PushDrop data envelopes.

The implementation maintains cross-SDK compatibility with the TypeScript and Go BSV SDKs through shared script structures and signing conventions.

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | Module root; submodule declarations and public re-exports |
| `p2pkh.rs` | P2PKH template for the most common Bitcoin transaction type |
| `p2pk.rs` | P2PK template for direct public key locking (simpler than P2PKH) |
| `multisig.rs` | Multisig (M-of-N) template using OP_CHECKMULTISIG |
| `pushdrop.rs` | PushDrop template for data envelopes with embedded fields and P2PK lock |
| `rpuzzle.rs` | R-Puzzle template for knowledge-based locking using ECDSA K-values |

## Key Exports

The module re-exports the following from `mod.rs`:

```rust
pub use multisig::Multisig;
pub use p2pk::P2PK;
pub use p2pkh::P2PKH;
pub use pushdrop::{LockPosition, PushDrop};
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
    pub fn new() -> Self
    pub fn lock_from_address(address: &str) -> Result<LockingScript>
    pub fn unlock(
        private_key: &PrivateKey,
        sign_outputs: SignOutputs,
        anyone_can_pay: bool,
    ) -> ScriptTemplateUnlock
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

### P2PK

Pay-to-Public-Key locks funds directly to a public key rather than its hash. Simpler than P2PKH but reveals the public key in the locking script before spending. The unlock only requires a signature (no public key needed since it's already in the lock).

**Locking Script Pattern:**
```text
<pubkey> OP_CHECKSIG
```

**Unlocking Script Pattern:**
```text
<signature>
```

```rust
#[derive(Debug, Clone, Copy, Default)]
pub struct P2PK;

impl P2PK {
    pub fn new() -> Self
    pub fn unlock(
        private_key: &PrivateKey,
        sign_outputs: SignOutputs,
        anyone_can_pay: bool,
    ) -> ScriptTemplateUnlock
    pub fn sign_with_sighash(
        private_key: &PrivateKey,
        sighash: &[u8; 32],
        sign_outputs: SignOutputs,
        anyone_can_pay: bool,
    ) -> Result<UnlockingScript>
}

impl ScriptTemplate for P2PK {
    /// Creates a locking script from a compressed (33-byte) or uncompressed (65-byte) public key.
    /// Validates the key prefix (0x02/0x03 for compressed, 0x04/0x06/0x07 for uncompressed).
    fn lock(&self, params: &[u8]) -> Result<LockingScript>
}
```

### Multisig

M-of-N multi-signature scripts require M valid signatures from a set of N public keys using OP_CHECKMULTISIG. Supports 1-16 keys with a threshold of 1-16 (where threshold <= N).

**Locking Script Pattern:**
```text
OP_M <pubkey1> <pubkey2> ... <pubkeyN> OP_N OP_CHECKMULTISIG
```

**Unlocking Script Pattern:**
```text
OP_0 <sig1> <sig2> ... <sigM>
```

The leading OP_0 is required due to a historical off-by-one bug in Bitcoin's OP_CHECKMULTISIG implementation. Signatures must appear in the same order as their corresponding public keys in the locking script.

```rust
#[derive(Debug, Clone)]
pub struct Multisig {
    pub threshold: u8,
}

impl Multisig {
    pub fn new(threshold: u8) -> Self
    /// Recommended API: creates locking script from PublicKey objects
    pub fn lock_from_keys(&self, pubkeys: &[PublicKey]) -> Result<LockingScript>
    pub fn unlock(
        signers: &[PrivateKey],
        sign_outputs: SignOutputs,
        anyone_can_pay: bool,
    ) -> ScriptTemplateUnlock
    pub fn sign_with_sighash(
        signers: &[PrivateKey],
        sighash: &[u8; 32],
        sign_outputs: SignOutputs,
        anyone_can_pay: bool,
    ) -> Result<UnlockingScript>
}

impl ScriptTemplate for Multisig {
    /// Creates locking script from concatenated 33-byte compressed public keys.
    /// Params must be a multiple of 33 bytes.
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
/// Hash variants for R-Puzzle locking scripts (default: Raw)
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
    pub fn hash(self, data: &[u8]) -> Vec<u8>
}

#[derive(Debug, Clone, Copy)]
pub struct RPuzzle {
    pub puzzle_type: RPuzzleType,
}

impl RPuzzle {
    pub fn new(puzzle_type: RPuzzleType) -> Self
    pub fn compute_r_from_k(k: &BigNumber) -> Result<[u8; 32]>
    pub fn unlock(
        k: &BigNumber,
        private_key: &PrivateKey,
        sign_outputs: SignOutputs,
        anyone_can_pay: bool,
    ) -> ScriptTemplateUnlock
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

### PushDrop

PushDrop is a data envelope template that embeds arbitrary data fields in a transaction output, protected by a P2PK (Pay-to-Public-Key) signature. It's commonly used by token protocols like BSV-20.

**Locking Script Pattern (lock-before, default):**
```text
<pubkey> OP_CHECKSIG <field1> <field2> ... OP_2DROP ... OP_DROP
```

**Locking Script Pattern (lock-after):**
```text
<field1> <field2> ... OP_2DROP ... OP_DROP <pubkey> OP_CHECKSIG
```

**Unlocking Script Pattern:**
```text
<signature>
```

Note: Unlike P2PKH, the public key is already in the locking script, so only the signature is needed in the unlock.

The script pushes data fields onto the stack, then drops them using `OP_2DROP` (for pairs) and `OP_DROP` (for remaining single field), leaving only the P2PK signature check.

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LockPosition {
    #[default]
    Before,  // <pubkey> OP_CHECKSIG comes before data fields
    After,   // <pubkey> OP_CHECKSIG comes after data fields
}

#[derive(Debug, Clone)]
pub struct PushDrop {
    pub locking_public_key: PublicKey,
    pub fields: Vec<Vec<u8>>,
    pub lock_position: LockPosition,
}

impl PushDrop {
    pub fn new(locking_public_key: PublicKey, fields: Vec<Vec<u8>>) -> Self
    pub fn with_position(mut self, position: LockPosition) -> Self
    pub fn lock(&self) -> LockingScript
    pub fn decode(script: &LockingScript) -> Result<Self>
    pub fn unlock(
        private_key: &PrivateKey,
        sign_outputs: SignOutputs,
        anyone_can_pay: bool,
    ) -> ScriptTemplateUnlock
    pub fn sign_with_sighash(
        private_key: &PrivateKey,
        sighash: &[u8; 32],
        sign_outputs: SignOutputs,
        anyone_can_pay: bool,
    ) -> Result<UnlockingScript>
    pub fn estimate_unlocking_length(&self) -> usize
}
```

**Minimal Encoding:**
PushDrop automatically applies Bitcoin Script minimal encoding rules:
- Empty data or `[0]` → `OP_0`
- Single byte 1-16 → `OP_1` through `OP_16`
- Single byte `0x81` (-1) → `OP_1NEGATE`
- Other data → standard push

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

### P2PK: Lock to Public Key

```rust
use bsv_sdk::script::templates::P2PK;
use bsv_sdk::script::template::ScriptTemplate;
use bsv_sdk::primitives::ec::PrivateKey;

let private_key = PrivateKey::random();
let pubkey = private_key.public_key().to_compressed();

let template = P2PK::new();
let locking = template.lock(&pubkey)?;
// Produces: <pubkey> OP_CHECKSIG
```

### P2PK: Spend with Signature

```rust
use bsv_sdk::script::templates::P2PK;
use bsv_sdk::script::template::{SignOutputs, SigningContext};
use bsv_sdk::primitives::ec::PrivateKey;

let private_key = PrivateKey::from_hex("...")?;

// Create unlock template (signature only, 74 bytes estimated)
let unlock = P2PK::unlock(&private_key, SignOutputs::All, false);
let unlocking = unlock.sign(&context)?;
// Produces: <signature>
```

### Multisig: Lock to M-of-N Keys

```rust
use bsv_sdk::script::templates::Multisig;
use bsv_sdk::script::template::ScriptTemplate;
use bsv_sdk::primitives::ec::PrivateKey;

let key1 = PrivateKey::random();
let key2 = PrivateKey::random();
let key3 = PrivateKey::random();

// Create 2-of-3 multisig locking script
let template = Multisig::new(2);
let pubkeys = vec![key1.public_key(), key2.public_key(), key3.public_key()];
let locking = template.lock_from_keys(&pubkeys)?;
// Produces: OP_2 <pk1> <pk2> <pk3> OP_3 OP_CHECKMULTISIG

// Alternative: use ScriptTemplate trait with concatenated 33-byte keys
let mut params = Vec::new();
params.extend_from_slice(&key1.public_key().to_compressed());
params.extend_from_slice(&key2.public_key().to_compressed());
let locking = Multisig::new(1).lock(&params)?;
```

### Multisig: Spend with M Signatures

```rust
use bsv_sdk::script::templates::Multisig;
use bsv_sdk::script::template::{SignOutputs, SigningContext};
use bsv_sdk::primitives::ec::PrivateKey;

// Sign with keys 1 and 3 (must be in same order as locking script)
let signers = vec![key1.clone(), key3.clone()];
let unlock = Multisig::unlock(&signers, SignOutputs::All, false);
let unlocking = unlock.sign(&context)?;
// Produces: OP_0 <sig1> <sig3>
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

### PushDrop: Create Data Envelope

```rust
use bsv_sdk::script::templates::{PushDrop, LockPosition};
use bsv_sdk::primitives::ec::PrivateKey;

let privkey = PrivateKey::random();
let pubkey = privkey.public_key();

// Create with embedded token data (lock-before pattern)
let fields = vec![
    b"BSV20".to_vec(),
    b"transfer".to_vec(),
    b"1000".to_vec(),
];
let pushdrop = PushDrop::new(pubkey.clone(), fields);
let locking = pushdrop.lock();
// Produces: <pubkey> OP_CHECKSIG <"BSV20"> <"transfer"> <"1000"> OP_2DROP OP_DROP

// Lock-after pattern (data fields first)
let pushdrop = PushDrop::new(pubkey, vec![b"data".to_vec()])
    .with_position(LockPosition::After);
let locking = pushdrop.lock();
// Produces: <"data"> OP_DROP <pubkey> OP_CHECKSIG
```

### PushDrop: Decode Existing Script

```rust
use bsv_sdk::script::templates::PushDrop;
use bsv_sdk::script::LockingScript;

let script = LockingScript::from_hex("...")?;
let decoded = PushDrop::decode(&script)?;

println!("Public key: {:?}", decoded.locking_public_key);
println!("Fields: {:?}", decoded.fields);
println!("Lock position: {:?}", decoded.lock_position);
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

All templates produce DER-encoded ECDSA signatures with:
- Appended sighash scope byte (including FORKID)
- Low-S normalization per BIP 62

### Estimated Lengths

| Template | `estimate_length()` | Components |
|----------|---------------------|------------|
| P2PKH | 108 bytes | 1 push + 72 sig + 1 push + 33 pubkey + 1 sighash |
| P2PK | 74 bytes | 1 push + 72 sig + 1 sighash |
| RPuzzle | 108 bytes | Same as P2PKH (sig + pubkey) |
| PushDrop | 73 bytes | 1 push + 72 sig (signature only, pubkey in lock) |
| Multisig | 1 + M*74 bytes | OP_0 + M * (1 push + 72 sig + 1 sighash) |

These are worst-case estimates; actual signatures may be 1-2 bytes shorter.

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

### PushDrop DROP Operations

PushDrop efficiently cleans up the stack using:
- `OP_2DROP` for each pair of fields (removes 2 items)
- `OP_DROP` for a remaining single field

Example for 5 fields: `OP_2DROP OP_2DROP OP_DROP` (removes 2+2+1 = 5 items)

### PushDrop Decoding

The `decode` method determines the lock position by examining the first chunk:
- If first chunk is a 33 or 65-byte data push (public key), it's lock-before
- Otherwise, it's lock-after

Decoded minimal-encoded values are converted back to their byte representations:
- `OP_0` → `[0]`
- `OP_1` through `OP_16` → `[1]` through `[16]`
- `OP_1NEGATE` → `[0x81]`

### Multisig Signature Ordering

OP_CHECKMULTISIG walks through keys and signatures in order, matching each signature to the next available key. Signatures in the unlock must appear in the same relative order as their corresponding public keys in the lock. For example, in a 2-of-3 with keys [A, B, C], signing with keys A and C is valid, but signatures must appear as `<sigA> <sigC>`, not `<sigC> <sigA>`.

## Related Documentation

- `../CLAUDE.md` - Script module documentation
- `../template.rs` - `ScriptTemplate` trait and `SigningContext` (not in templates/)
- `../../primitives/ec/CLAUDE.md` - Elliptic curve primitives (PrivateKey, PublicKey, Signature)
- `../../primitives/bsv/CLAUDE.md` - BSV primitives (TransactionSignature, sighash computation)
- `../../CLAUDE.md` - Root SDK documentation
