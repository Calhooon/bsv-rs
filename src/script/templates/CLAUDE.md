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

```rust
pub use multisig::Multisig;
pub use p2pk::P2PK;
pub use p2pkh::P2PKH;
pub use pushdrop::{LockPosition, PushDrop};
pub use rpuzzle::{RPuzzle, RPuzzleType};
```

## Template APIs

### P2PKH

Pay-to-Public-Key-Hash is the most common Bitcoin transaction type. Funds are locked to a public key hash and can only be spent by providing a valid signature from the corresponding private key.

**Locking:** `OP_DUP OP_HASH160 <20-byte pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG`
**Unlocking:** `<signature> <publicKey>`

```rust
#[derive(Debug, Clone, Copy, Default)]
pub struct P2PKH;

impl P2PKH {
    pub fn new() -> Self
    pub fn lock_from_address(address: &str) -> Result<LockingScript>  // mainnet 0x00 or testnet 0x6f
    pub fn unlock(private_key: &PrivateKey, sign_outputs: SignOutputs, anyone_can_pay: bool) -> ScriptTemplateUnlock
    pub fn sign_with_sighash(private_key: &PrivateKey, sighash: &[u8; 32], sign_outputs: SignOutputs, anyone_can_pay: bool) -> Result<UnlockingScript>
}

impl ScriptTemplate for P2PKH {
    fn lock(&self, params: &[u8]) -> Result<LockingScript>  // params = 20-byte pubkey hash
}
```

### P2PK

Pay-to-Public-Key locks funds directly to a public key. Simpler than P2PKH but reveals the public key before spending. The unlock only requires a signature.

**Locking:** `<pubkey> OP_CHECKSIG`
**Unlocking:** `<signature>`

```rust
#[derive(Debug, Clone, Copy, Default)]
pub struct P2PK;

impl P2PK {
    pub fn new() -> Self
    pub fn unlock(private_key: &PrivateKey, sign_outputs: SignOutputs, anyone_can_pay: bool) -> ScriptTemplateUnlock
    pub fn sign_with_sighash(private_key: &PrivateKey, sighash: &[u8; 32], sign_outputs: SignOutputs, anyone_can_pay: bool) -> Result<UnlockingScript>
}

impl ScriptTemplate for P2PK {
    fn lock(&self, params: &[u8]) -> Result<LockingScript>  // params = 33-byte compressed or 65-byte uncompressed key
}
```

### Multisig

M-of-N multi-signature scripts require M valid signatures from a set of N public keys. Supports 1-16 keys with threshold 1-16 (threshold <= N).

**Locking:** `OP_M <pubkey1> ... <pubkeyN> OP_N OP_CHECKMULTISIG`
**Unlocking:** `OP_0 <sig1> ... <sigM>` (OP_0 required by historical off-by-one bug)

Signatures must appear in the same order as their corresponding public keys in the locking script.

```rust
#[derive(Debug, Clone)]
pub struct Multisig {
    pub threshold: u8,
}

impl Multisig {
    pub fn new(threshold: u8) -> Self
    pub fn lock_from_keys(&self, pubkeys: &[PublicKey]) -> Result<LockingScript>  // recommended API
    pub fn unlock(signers: &[PrivateKey], sign_outputs: SignOutputs, anyone_can_pay: bool) -> ScriptTemplateUnlock
    pub fn sign_with_sighash(signers: &[PrivateKey], sighash: &[u8; 32], sign_outputs: SignOutputs, anyone_can_pay: bool) -> Result<UnlockingScript>
}

impl ScriptTemplate for Multisig {
    fn lock(&self, params: &[u8]) -> Result<LockingScript>  // params = concatenated 33-byte compressed keys
}
```

### RPuzzle

R-Puzzles lock funds using the R-value component of an ECDSA signature. Anyone who knows the K-value (nonce) can spend, regardless of which private key they use.

**Locking (raw):** `OP_OVER OP_3 OP_SPLIT OP_NIP OP_1 OP_SPLIT OP_SWAP OP_SPLIT OP_DROP <r-value> OP_EQUALVERIFY OP_CHECKSIG`
**Locking (hashed):** Same prefix + `OP_<HASH> <r-hash> OP_EQUALVERIFY OP_CHECKSIG`
**Unlocking:** `<signature> <publicKey>`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RPuzzleType {
    #[default] Raw,    // Raw R value (largest script)
    Sha1,              // SHA-1 (20 bytes)
    Sha256,            // SHA-256 (32 bytes)
    Hash256,           // Double SHA-256 (32 bytes)
    Ripemd160,         // RIPEMD-160 (20 bytes)
    Hash160,           // HASH160 (20 bytes)
}

impl RPuzzleType {
    pub fn hash(self, data: &[u8]) -> Vec<u8>
}

#[derive(Debug, Clone, Copy, Default)]  // Default = RPuzzleType::Raw
pub struct RPuzzle { pub puzzle_type: RPuzzleType }

impl RPuzzle {
    pub fn new(puzzle_type: RPuzzleType) -> Self
    pub fn compute_r_from_k(k: &BigNumber) -> Result<[u8; 32]>  // R = k*G x-coordinate
    pub fn unlock(k: &BigNumber, private_key: &PrivateKey, sign_outputs: SignOutputs, anyone_can_pay: bool) -> ScriptTemplateUnlock
    pub fn sign_with_sighash(k: &BigNumber, private_key: &PrivateKey, sighash: &[u8; 32], sign_outputs: SignOutputs, anyone_can_pay: bool) -> Result<UnlockingScript>
}

impl ScriptTemplate for RPuzzle {
    fn lock(&self, params: &[u8]) -> Result<LockingScript>  // params = R value or its hash
}
```

### PushDrop

Data envelope template that embeds arbitrary data fields alongside a P2PK lock. Used by token protocols like BSV-20. Implements `PartialEq` (compares compressed pubkey, fields, and position).

**Locking (before, default):** `<pubkey> OP_CHECKSIG <field1> <field2> ... OP_2DROP ... OP_DROP`
**Locking (after):** `<field1> <field2> ... OP_2DROP ... OP_DROP <pubkey> OP_CHECKSIG`
**Unlocking:** `<signature>` (pubkey already in locking script)

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LockPosition {
    #[default] Before,  // P2PK lock before data fields
    After,              // P2PK lock after data fields
}

#[derive(Debug, Clone)]
pub struct PushDrop {
    pub locking_public_key: PublicKey,
    pub fields: Vec<Vec<u8>>,
    pub lock_position: LockPosition,
}

impl PushDrop {
    pub fn new(locking_public_key: PublicKey, fields: Vec<Vec<u8>>) -> Self
    pub fn with_position(self, position: LockPosition) -> Self  // builder pattern
    pub fn lock(&self) -> LockingScript                          // note: no Result, infallible
    pub fn decode(script: &LockingScript) -> Result<Self>        // decode existing script
    pub fn unlock(private_key: &PrivateKey, sign_outputs: SignOutputs, anyone_can_pay: bool) -> ScriptTemplateUnlock
    pub fn sign_with_sighash(private_key: &PrivateKey, sighash: &[u8; 32], sign_outputs: SignOutputs, anyone_can_pay: bool) -> Result<UnlockingScript>
    pub fn estimate_unlocking_length(&self) -> usize             // always 73
}
```

**Minimal Encoding:** PushDrop automatically applies Bitcoin Script minimal encoding rules:
- Empty data or `[0]` -> `OP_0`
- Single byte 1-16 -> `OP_1` through `OP_16`
- Single byte `0x81` (-1) -> `OP_1NEGATE`
- Other data -> standard push

**DROP Operations:** Uses `OP_2DROP` for pairs and `OP_DROP` for remaining single field. Example for 5 fields: `OP_2DROP OP_2DROP OP_DROP`.

## Sighash Types

| SignOutputs | anyone_can_pay | Scope Byte | Description |
|-------------|----------------|------------|-------------|
| `All` | `false` | `0x41` | Sign all inputs and outputs (most common) |
| `All` | `true` | `0xC1` | Sign only this input, all outputs |
| `None` | `false` | `0x42` | Sign all inputs, no outputs |
| `None` | `true` | `0xC2` | Sign only this input, no outputs |
| `Single` | `false` | `0x43` | Sign all inputs, only output at same index |
| `Single` | `true` | `0xC3` | Sign only this input and corresponding output |

All scope bytes include `SIGHASH_FORKID` (0x40) as required by BSV.

## Implementation Notes

### Estimated Unlocking Lengths

| Template | Estimate | Components |
|----------|----------|------------|
| P2PKH | 108 bytes | 1 push + 72 sig + 1 sighash + 1 push + 33 pubkey |
| P2PK | 74 bytes | 1 push + 72 sig + 1 sighash |
| RPuzzle | 108 bytes | Same as P2PKH (sig + pubkey) |
| PushDrop | 73 bytes | 1 push + 72 sig (signature only, pubkey in lock) |
| Multisig | 1 + M*74 | OP_0 + M * (1 push + 72 sig + 1 sighash) |

These are worst-case estimates; actual DER signatures may be 1-2 bytes shorter.

### R-Puzzle Internals

- **K value security:** Must be non-zero, less than curve order, and kept secret until spending
- **`compute_r_from_k`:** Computes `R = k * G` using secp256k1, returns x-coordinate as 32 bytes
- **`sign_with_k` (private):** Raw ECDSA signing with predetermined nonce `k`, computing `s = k^-1 * (z + r * d) mod n`. Bypasses RFC 6979 deterministic nonces. Enforces low-S (BIP 62).
- **R-extraction prefix:** The 9-opcode prefix parses a DER signature on the stack to extract the R value for comparison

### PushDrop Decoding

`decode()` determines lock position by examining the first chunk:
- If first chunk is a 33 or 65-byte data push (public key) -> lock-before
- Otherwise -> lock-after

Minimal-encoded opcodes are converted back to bytes: `OP_0` -> `[0]`, `OP_1`-`OP_16` -> `[1]`-`[16]`, `OP_1NEGATE` -> `[0x81]`

### Multisig Signature Ordering

OP_CHECKMULTISIG walks through keys and signatures in order, matching each signature to the next available key. In a 2-of-3 with keys [A, B, C], signing with A and C produces `<sigA> <sigC>`, not `<sigC> <sigA>`.

## Related Documentation

- `../CLAUDE.md` - Script module documentation
- `../template.rs` - `ScriptTemplate` trait and `SigningContext` (not in templates/)
- `../../primitives/ec/CLAUDE.md` - Elliptic curve primitives (PrivateKey, PublicKey, Signature)
- `../../primitives/bsv/CLAUDE.md` - BSV primitives (TransactionSignature, sighash computation)
