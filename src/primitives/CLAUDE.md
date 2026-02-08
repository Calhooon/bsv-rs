# BSV Primitives Module
> Cryptographic primitives for the BSV blockchain in Rust

## Overview

This module provides cryptographic primitives compatible with the BSV TypeScript and Go SDKs: hash functions, symmetric encryption (AES-256-GCM), encoding utilities, binary serialization, arbitrary-precision integers (BigNumber), HMAC-DRBG, secp256k1 elliptic curve operations (ECDSA, BRC-42), and P-256 curve operations.

**Status**: Complete - All cryptographic primitives implemented with cross-SDK compatibility verified.

## Files

| File | Purpose | Lines |
|------|---------|-------|
| `mod.rs` | Module declarations and re-exports | 36 |
| `hash.rs` | SHA-1, SHA-256, SHA-512, RIPEMD-160, HMAC, PBKDF2 | 800 |
| `symmetric.rs` | AES-256-GCM encryption (32-byte nonce for BSV SDK compatibility) | 972 |
| `encoding.rs` | Hex, Base58, Base58Check, Base64, UTF-8, Reader/Writer | 1696 |
| `bignum.rs` | Arbitrary-precision integers for EC scalars | 1550 |
| `drbg.rs` | HMAC-DRBG for RFC 6979 deterministic signatures | 201 |
| `p256.rs` | P-256 (secp256r1): P256PrivateKey, P256PublicKey, P256Signature | 910 |
| `ec/` | secp256k1: PrivateKey, PublicKey, Signature, ECDSA, BRC-42 | ~2157 |
| `bsv/` | Sighash, transaction signatures, Schnorr proofs, Shamir sharing | ~2837 |

## Key Exports (from mod.rs)

```rust
// Hash functions
pub fn sha1(data: &[u8]) -> [u8; 20]       // Legacy (cryptographically broken)
pub fn sha256(data: &[u8]) -> [u8; 32]
pub fn sha512(data: &[u8]) -> [u8; 64]
pub fn ripemd160(data: &[u8]) -> [u8; 20]
pub fn sha256d(data: &[u8]) -> [u8; 32]    // Bitcoin double-SHA256
pub fn hash160(data: &[u8]) -> [u8; 20]    // RIPEMD160(SHA256(x))
pub fn sha1_hmac(key: &[u8], data: &[u8]) -> [u8; 20]   // HMAC-SHA1
pub fn sha256_hmac(key: &[u8], data: &[u8]) -> [u8; 32]
pub fn sha512_hmac(key: &[u8], data: &[u8]) -> [u8; 64]
pub fn pbkdf2_sha512(password: &[u8], salt: &[u8], iterations: u32, key_len: usize) -> Vec<u8>

// Encoding
pub fn to_hex(data: &[u8]) -> String
pub fn from_hex(s: &str) -> Result<Vec<u8>>
pub fn to_base58(data: &[u8]) -> String
pub fn from_base58(s: &str) -> Result<Vec<u8>>
pub fn to_base58_check(payload: &[u8], version: &[u8]) -> String
pub fn from_base58_check(s: &str) -> Result<(Vec<u8>, Vec<u8>)>
pub fn to_base64(data: &[u8]) -> String
pub fn from_base64(s: &str) -> Result<Vec<u8>>
pub fn to_utf8_bytes(s: &str) -> Vec<u8>
pub fn from_utf8_bytes(data: &[u8]) -> Result<String>

// Binary serialization
pub struct Reader<'a> { ... }  // read_u8, read_u16_le, read_u32_le, read_u64_le,
                                // read_i8, read_i16_le, read_i32_le, read_i64_le,
                                // read_var_int, read_var_int_num, read_bytes,
                                // read_var_bytes, read_remaining, remaining, is_empty, position
pub struct Writer { ... }       // write_u8, write_u16_le, write_u32_le, write_u64_le,
                                // write_i8, write_i16_le, write_i32_le, write_i64_le,
                                // write_var_int, write_bytes, write_var_bytes,
                                // len, is_empty, as_bytes, into_bytes, with_capacity

// Symmetric encryption
pub struct SymmetricKey { ... }  // random(), from_bytes(), as_bytes(), encrypt(), decrypt()

// BigNumber (arbitrary precision)
pub struct BigNumber { ... }  // from_hex(), from_dec_str(), from_bytes_be(), from_bytes_le(),
                               // from_signed_bytes_be(), from_i64(), from_u64(), zero(), one(),
                               // to_hex(), to_bytes_be(), to_bytes_le(), to_bytes_be_min(),
                               // to_bytes_le_min(), to_dec_string(), to_i64(), to_u64(),
                               // add(), sub(), mul(), div(), modulo(), mod_floor(), neg(), abs(),
                               // pow(), mod_inverse(), mod_pow(), gcd(), compare(),
                               // is_zero(), is_negative(), is_positive(), is_odd(), is_even(),
                               // bit_length(), byte_length(), secp256k1_order(), secp256k1_prime(),
                               // as_bigint(), from_bigint()

// HMAC-DRBG
pub struct HmacDrbg { ... }  // new(), new_with_hash(), generate(), reseed()

// EC (secp256k1)
pub struct PrivateKey { ... }  // random(), from_bytes(), from_hex(), from_wif(), sign(),
                                // public_key(), to_bytes(), to_hex(), to_wif(), to_wif_with_prefix(),
                                // derive_child(), derive_shared_secret()
pub struct PublicKey { ... }   // from_bytes(), from_hex(), from_private_key(), from_scalar_mul_generator(),
                                // verify(), to_compressed(), to_uncompressed(), to_hex(),
                                // to_hex_uncompressed(), x(), y(), y_is_even(), hash160(),
                                // to_address(), to_address_with_prefix(), derive_child(),
                                // derive_shared_secret(), mul_scalar(), add(), is_valid()
pub struct Signature { ... }   // new(), from_der(), from_compact(), from_compact_slice(),
                                // r(), s(), to_der(), to_compact(), is_low_s(), to_low_s(), verify()
```

## Cross-SDK Compatibility Notes

### AES-256-GCM (SymmetricKey)
- Uses **non-standard 32-byte nonce** (not 12-byte standard)
- Output: `IV (32) || ciphertext || tag (16)`
- Keys < 32 bytes padded with **leading zeros** (critical for 31-byte EC X coordinates)

### Base58Check
- Bitcoin alphabet (excludes 0, O, I, l)
- Checksum: first 4 bytes of SHA256(SHA256(version || payload))
- Addresses: version 0x00, WIF keys: version 0x80
- `from_base58_check_with_prefix_length()` supports custom version prefix lengths

### Bitcoin Varint Encoding
| Value Range | Encoding |
|-------------|----------|
| 0x00-0xFC | 1 byte |
| 0xFD-0xFFFF | 0xFD + uint16 LE (3 bytes) |
| 0x10000-0xFFFFFFFF | 0xFE + uint32 LE (5 bytes) |
| > 0xFFFFFFFF | 0xFF + uint64 LE (9 bytes) |

### PublicKey.is_valid()
- Always returns `true` for successfully parsed keys (matches Go `Validate()` / TS `validate()`)
- Invalid keys fail at parse time (`from_bytes()` / `from_hex()`)

## Usage Examples

### Hashing and Encryption
```rust
use bsv_sdk::primitives::{sha256, sha256d, hash160, SymmetricKey};

let digest = sha256(b"hello world");
let double_hash = sha256d(b"hello world");  // Transaction hashes
let h160 = hash160(&pubkey_bytes);           // Address generation

let key = SymmetricKey::random();
let ciphertext = key.encrypt(b"secret")?;
let plaintext = key.decrypt(&ciphertext)?;
```

### Elliptic Curve Operations
```rust
use bsv_sdk::primitives::{PrivateKey, PublicKey};
use bsv_sdk::primitives::hash::sha256;

let private_key = PrivateKey::random();
let public_key = private_key.public_key();
let msg_hash = sha256(b"Hello, BSV!");
let signature = private_key.sign(&msg_hash)?;
assert!(public_key.verify(&msg_hash, &signature));
assert!(signature.is_low_s());  // BIP 62 compliant

// WIF and address
let wif = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";
let key = PrivateKey::from_wif(wif)?;
let address = public_key.to_address();  // P2PKH mainnet
```

### BRC-42 Key Derivation
```rust
use bsv_sdk::primitives::PrivateKey;

let alice = PrivateKey::random();
let bob = PrivateKey::random();
let alice_child = alice.derive_child(&bob.public_key(), "invoice-123")?;
let bob_derived = alice.public_key().derive_child(&bob, "invoice-123")?;
assert_eq!(alice_child.public_key().to_compressed(), bob_derived.to_compressed());
```

### ECDH Shared Secret
```rust
use bsv_sdk::primitives::PrivateKey;

let alice = PrivateKey::random();
let bob = PrivateKey::random();
let shared_ab = alice.derive_shared_secret(&bob.public_key())?;
let shared_ba = bob.derive_shared_secret(&alice.public_key())?;
assert_eq!(shared_ab.to_compressed(), shared_ba.to_compressed());
```

### BigNumber for Key Math
```rust
use bsv_sdk::primitives::BigNumber;

let private_key = BigNumber::from_hex("0123...").unwrap();
let hmac_value = BigNumber::from_hex("fedc...").unwrap();
let order = BigNumber::secp256k1_order();
let new_key = private_key.add(&hmac_value).modulo(&order);
let key_bytes = new_key.to_bytes_be(32);
```

### Binary Serialization
```rust
use bsv_sdk::primitives::{Reader, Writer};

let mut writer = Writer::new();
writer.write_u32_le(0x01000000).write_var_int(1).write_var_bytes(b"data");
let bytes = writer.into_bytes();

let mut reader = Reader::new(&bytes);
let version = reader.read_u32_le()?;
let count = reader.read_var_int()?;
let data = reader.read_var_bytes()?;
```

### P-256 Operations
```rust
use bsv_sdk::primitives::p256::{P256PrivateKey, P256PublicKey};

let private_key = P256PrivateKey::random();
let public_key = private_key.public_key();

// Sign a message (will be hashed with SHA-256)
let signature = private_key.sign(b"Hello, P-256!");
assert!(public_key.verify(b"Hello, P-256!", &signature));

// Sign a pre-hashed message
let hash = bsv_sdk::primitives::hash::sha256(b"Hello, P-256!");
let sig2 = private_key.sign_hash(&hash);
assert!(public_key.verify_hash(&hash, &sig2));
```

### Shamir Secret Sharing
```rust
use bsv_sdk::primitives::bsv::shamir::{split_private_key, KeyShares};
use bsv_sdk::primitives::PrivateKey;

let key = PrivateKey::random();

// Split into 5 shares with threshold of 3
let shares = split_private_key(&key, 3, 5)?;
let backup = shares.to_backup_format();

// Recover from any 3 shares
let subset = KeyShares::from_backup_format(&backup[0..3])?;
let recovered = subset.recover_private_key()?;
assert_eq!(key.to_bytes(), recovered.to_bytes());
```

## Submodule Structure

### ec/ (secp256k1 Elliptic Curve)

| File | Lines | Purpose |
|------|-------|---------|
| `mod.rs` | 77 | Module exports |
| `private_key.rs` | 564 | PrivateKey: random generation, WIF, signing, BRC-42 derivation, ECDH |
| `public_key.rs` | 679 | PublicKey: verification, addresses, BRC-42 derivation, ECDH, point math |
| `signature.rs` | 531 | Signature: DER/compact encoding, low-S normalization, standalone verify |
| `ecdsa.rs` | 306 | Core ECDSA sign/verify/recover functions |

Key exports: `PrivateKey`, `PublicKey`, `Signature`, `sign`, `verify`, `recover_public_key`, `calculate_recovery_id`

### bsv/ (BSV-Specific Operations)

| File | Lines | Purpose |
|------|-------|---------|
| `mod.rs` | 75 | Module exports |
| `sighash.rs` | 623 | BIP-143 style sighash computation |
| `tx_signature.rs` | 309 | Transaction signature encoding/decoding with sighash scope |
| `schnorr.rs` | 413 | Schnorr zero-knowledge proofs for ECDH verification |
| `shamir.rs` | 1023 | Shamir secret sharing for private key backup/recovery |
| `polynomial.rs` | 394 | Polynomial operations over finite field (for Shamir) |

Key exports: `compute_sighash`, `build_sighash_preimage`, `compute_sighash_for_signing`, `compute_sighash_from_raw`, `parse_transaction`, `RawTransaction`, `SighashParams`, `TxInput`, `TxOutput`, `TransactionSignature`, `Schnorr`, `SchnorrProof`, `split_private_key`, `KeyShares`, `Polynomial`, `PointInFiniteField`, sighash constants (`SIGHASH_ALL`, `SIGHASH_NONE`, `SIGHASH_SINGLE`, `SIGHASH_ANYONECANPAY`, `SIGHASH_FORKID`)

### p256 (P-256/secp256r1)

Key types: `P256PrivateKey`, `P256PublicKey`, `P256Signature`

Convenience functions: `generate_private_key_hex()`, `public_key_from_private()`, `sign()`, `verify()`

P256Signature supports DER and compact encoding, low-S normalization via `to_low_s()`.

## Error Handling

Key error variants in `src/error.rs`:
- `InvalidKeyLength { expected, actual }` - Key size mismatch
- `InvalidHex(String)` / `InvalidBase58(String)` / `InvalidBase64(String)` - Encoding errors
- `InvalidChecksum` - Base58Check checksum failed
- `InvalidSignature(String)` / `InvalidPublicKey(String)` / `InvalidPrivateKey(String)`
- `DecryptionFailed` - AES-GCM authentication failed
- `ReaderUnderflow { needed, available }` - Not enough bytes to read
- `InvalidUtf8(String)` - UTF-8 decoding failed
- `CryptoError(String)` - General crypto errors (e.g., varint overflow)

## Dependencies

- `sha1`, `sha2`, `ripemd` - Hash algorithms
- `hmac`, `pbkdf2` - Key derivation
- `aes-gcm` - Authenticated encryption
- `k256` - secp256k1 operations
- `p256` - P-256 operations
- `num-bigint`, `num-integer`, `num-traits` - BigNumber backing
- `hex`, `bs58`, `base64` - Encoding
- `rand`, `getrandom` - Secure randomness
- `subtle` - Constant-time comparison

## Testing

```bash
cargo test primitives
```

Tests include NIST vectors, RFC 2202 HMAC-SHA1 vectors, PBKDF2-SHA512 vectors, TypeScript/Go SDK compatibility, round-trip encoding, UTF-8 multi-byte handling, and edge cases. Test vectors in `tests/vectors/symmetric_key.json`.

## Related Documentation

- `ec/CLAUDE.md` - secp256k1 submodule details
- `bsv/CLAUDE.md` - BSV-specific operations
