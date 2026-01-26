# BSV Primitives Module
> Cryptographic primitives for the BSV blockchain in Rust

## Overview

This module provides cryptographic primitives compatible with the BSV TypeScript and Go SDKs. The library implements hash functions, symmetric encryption (AES-256-GCM), encoding utilities, binary serialization, arbitrary-precision integers (BigNumber), HMAC-DRBG for deterministic randomness, secp256k1 elliptic curve operations (ECDSA, BRC-42 key derivation), and P-256 (secp256r1) curve operations for certain authentication scenarios.

## Files

| File | Purpose | Lines |
|------|---------|-------|
| `mod.rs` | Module declarations and re-exports | 35 |
| `hash.rs` | SHA-1, SHA-256, SHA-512, RIPEMD-160, HMAC, PBKDF2 | 702 |
| `symmetric.rs` | AES-256-GCM encryption with BSV SDK compatibility | 972 |
| `encoding.rs` | Hex, Base58, Base58Check, Base64, UTF-8, Reader/Writer | 1696 |
| `bignum.rs` | Arbitrary-precision integers for EC scalars and key derivation | 1550 |
| `drbg.rs` | HMAC-DRBG deterministic random bit generator (RFC 6979) | 201 |
| `p256.rs` | P-256 (secp256r1) elliptic curve: P256PrivateKey, P256PublicKey, P256Signature | 910 |
| `ec/` | secp256k1 elliptic curve: PrivateKey, PublicKey, Signature, ECDSA, BRC-42 | (subdir) |
| `bsv/` | BSV-specific operations (sighash, transaction signatures, Schnorr proofs, Shamir secret sharing) | (subdir) |

Note: Error types are defined in `src/error.rs` at the crate root.

## Key Exports

The module re-exports commonly used items from `mod.rs`:

### Hash Functions
```rust
pub fn sha1(data: &[u8]) -> [u8; 20]      // Legacy, cryptographically broken
pub fn sha256(data: &[u8]) -> [u8; 32]
pub fn sha512(data: &[u8]) -> [u8; 64]
pub fn ripemd160(data: &[u8]) -> [u8; 20]
pub fn sha256d(data: &[u8]) -> [u8; 32]   // Bitcoin double-SHA256 (hash256)
pub fn hash160(data: &[u8]) -> [u8; 20]   // RIPEMD160(SHA256(x))
```

### HMAC and Key Derivation
```rust
pub fn sha256_hmac(key: &[u8], data: &[u8]) -> [u8; 32]
pub fn sha512_hmac(key: &[u8], data: &[u8]) -> [u8; 64]
pub fn pbkdf2_sha512(password: &[u8], salt: &[u8], iterations: u32, key_len: usize) -> Vec<u8>
```

### Symmetric Encryption
```rust
pub struct SymmetricKey {
    pub fn random() -> Self
    pub fn from_bytes(bytes: &[u8]) -> Result<Self>
    pub fn as_bytes(&self) -> &[u8; 32]
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>>
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>>
}
```

**Important**: Uses non-standard 32-byte nonce for BSV SDK compatibility. Output format: `IV (32 bytes) || ciphertext || auth_tag (16 bytes)`. Keys shorter than 32 bytes are padded with leading zeros. Implements constant-time comparison (`PartialEq`) and secure zeroing on drop.

### Encoding Functions
```rust
// Hex
pub fn to_hex(data: &[u8]) -> String
pub fn from_hex(s: &str) -> Result<Vec<u8>>

// Base58 (Bitcoin alphabet)
pub fn to_base58(data: &[u8]) -> String
pub fn from_base58(s: &str) -> Result<Vec<u8>>

// Base58Check (with version byte and checksum)
pub fn to_base58_check(payload: &[u8], version: &[u8]) -> String
pub fn from_base58_check(s: &str) -> Result<(Vec<u8>, Vec<u8>)>
pub fn from_base58_check_with_prefix_length(s: &str, prefix_length: usize) -> Result<(Vec<u8>, Vec<u8>)>

// Base64
pub fn to_base64(data: &[u8]) -> String
pub fn from_base64(s: &str) -> Result<Vec<u8>>  // Handles URL-safe variants and whitespace

// UTF-8
pub fn to_utf8_bytes(s: &str) -> Vec<u8>
pub fn from_utf8_bytes(data: &[u8]) -> Result<String>
```

### BigNumber (Arbitrary-Precision Integers)
```rust
pub struct BigNumber {
    // Construction
    pub fn zero() -> Self
    pub fn one() -> Self
    pub fn from_i64(val: i64) -> Self
    pub fn from_u64(val: u64) -> Self
    pub fn from_hex(s: &str) -> Result<Self>         // Parses "deadbeef" or "0xDEADBEEF"
    pub fn from_dec_str(s: &str) -> Result<Self>     // Parses decimal strings
    pub fn from_bytes_be(bytes: &[u8]) -> Self       // Big-endian unsigned
    pub fn from_bytes_le(bytes: &[u8]) -> Self       // Little-endian unsigned
    pub fn from_signed_bytes_be(bytes: &[u8]) -> Self // Two's complement

    // Serialization
    pub fn to_hex(&self) -> String                   // Lowercase, no prefix
    pub fn to_dec_string(&self) -> String
    pub fn to_bytes_be(&self, len: usize) -> Vec<u8> // Padded to length
    pub fn to_bytes_le(&self, len: usize) -> Vec<u8>
    pub fn to_bytes_be_min(&self) -> Vec<u8>         // Minimum bytes
    pub fn to_bytes_le_min(&self) -> Vec<u8>         // Minimum bytes (LE)

    // Arithmetic
    pub fn add(&self, other: &BigNumber) -> BigNumber
    pub fn sub(&self, other: &BigNumber) -> BigNumber
    pub fn mul(&self, other: &BigNumber) -> BigNumber
    pub fn div(&self, other: &BigNumber) -> BigNumber
    pub fn modulo(&self, other: &BigNumber) -> BigNumber  // Always positive result
    pub fn mod_floor(&self, other: &BigNumber) -> BigNumber // Can be negative
    pub fn neg(&self) -> BigNumber
    pub fn abs(&self) -> BigNumber
    pub fn pow(&self, exp: u32) -> BigNumber

    // Comparisons
    pub fn compare(&self, other: &BigNumber) -> Ordering
    pub fn is_zero(&self) -> bool
    pub fn is_negative(&self) -> bool
    pub fn is_positive(&self) -> bool
    pub fn is_odd(&self) -> bool
    pub fn is_even(&self) -> bool

    // Bit operations
    pub fn bit_length(&self) -> usize
    pub fn byte_length(&self) -> usize

    // Modular arithmetic (for EC operations)
    pub fn mod_inverse(&self, modulus: &BigNumber) -> Option<BigNumber>
    pub fn mod_pow(&self, exp: &BigNumber, modulus: &BigNumber) -> BigNumber
    pub fn gcd(&self, other: &BigNumber) -> BigNumber

    // Curve constants
    pub fn secp256k1_order() -> BigNumber   // Curve order n
    pub fn secp256k1_prime() -> BigNumber   // Field prime p

    // Primitive conversion
    pub fn to_i64(&self) -> Option<i64>
    pub fn to_u64(&self) -> Option<u64>

    // Internal access (for EC operations)
    pub fn as_bigint(&self) -> &BigInt
    pub fn from_bigint(inner: BigInt) -> Self
}
```

**Design Note**: Following the Go SDK approach, this is a minimal compatibility layer wrapping `num-bigint`. It does NOT implement the full bn.js API (no word arrays, reduction contexts, or in-place mutation). It provides what's needed for EC scalar operations and BRC-42 key derivation.

**Trait Implementations**: `From<i64>`, `From<u64>`, `From<i32>`, `From<u32>`, `From<BigInt>`, `Into<BigInt>`, `Default`, `Debug`, `Display`, `PartialOrd`, `Ord`, `Hash`.

### HMAC-DRBG (Deterministic Random Bit Generator)
```rust
pub struct HmacDrbg {
    pub fn new(entropy: &[u8], nonce: &[u8], personalization: &[u8]) -> Self  // SHA-256 DRBG
    pub fn new_with_hash(entropy: &[u8], nonce: &[u8], personalization: &[u8], use_sha512: bool) -> Self
    pub fn generate(&mut self, num_bytes: usize) -> Vec<u8>   // Generate random bytes
    pub fn reseed(&mut self, entropy: &[u8], additional_input: &[u8])  // Reseed with new entropy
}
```

**Implementation**: NIST SP 800-90A compliant HMAC-DRBG. Used internally for RFC 6979 deterministic ECDSA signatures. Supports both SHA-256 and SHA-512 as the underlying hash function.

**Security Note**: This is designed for deterministic signature generation and is NOT forward-secure. Do not use as a general-purpose RNG.

### Elliptic Curve (secp256k1)
```rust
pub struct PrivateKey {
    pub fn random() -> Self                                      // Generate random key
    pub fn from_bytes(bytes: &[u8]) -> Result<Self>              // From 32 bytes
    pub fn from_hex(hex: &str) -> Result<Self>                   // From hex string
    pub fn from_wif(wif: &str) -> Result<Self>                   // From WIF (Base58Check)
    pub fn public_key(&self) -> PublicKey                        // Derive public key
    pub fn sign(&self, msg_hash: &[u8; 32]) -> Result<Signature> // ECDSA sign (low-S)
    pub fn to_bytes(&self) -> [u8; 32]                           // Export as bytes
    pub fn to_hex(&self) -> String                               // Export as hex
    pub fn to_wif(&self) -> String                               // Export as WIF (mainnet)
    pub fn to_wif_with_prefix(&self, prefix: u8) -> String       // Export as WIF (custom)
    pub fn derive_shared_secret(&self, other_pubkey: &PublicKey) -> Result<PublicKey>  // ECDH
    pub fn derive_child(&self, other_pubkey: &PublicKey, invoice_number: &str) -> Result<PrivateKey>  // BRC-42
}

pub struct PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self>              // From 33 or 65 bytes
    pub fn from_hex(hex: &str) -> Result<Self>                   // From hex string
    pub fn from_private_key(private_key: &PrivateKey) -> Self    // From private key
    pub fn verify(&self, msg_hash: &[u8; 32], signature: &Signature) -> bool  // Verify signature
    pub fn to_compressed(&self) -> [u8; 33]                      // 02/03 prefix + X
    pub fn to_uncompressed(&self) -> [u8; 65]                    // 04 prefix + X + Y
    pub fn to_hex(&self) -> String                               // Compressed hex
    pub fn to_hex_uncompressed(&self) -> String                  // Uncompressed hex
    pub fn x(&self) -> [u8; 32]                                  // X coordinate
    pub fn y(&self) -> [u8; 32]                                  // Y coordinate
    pub fn y_is_even(&self) -> bool                              // Check Y parity
    pub fn hash160(&self) -> [u8; 20]                            // RIPEMD160(SHA256(compressed))
    pub fn to_address(&self) -> String                           // P2PKH mainnet address
    pub fn to_address_with_prefix(&self, version: u8) -> String  // P2PKH custom prefix
    pub fn derive_child(&self, other_privkey: &PrivateKey, invoice_number: &str) -> Result<PublicKey>  // BRC-42
    pub fn mul_scalar(&self, scalar: &[u8; 32]) -> Result<PublicKey>  // Scalar multiplication
    pub fn derive_shared_secret(&self, other_privkey: &PrivateKey) -> Result<PublicKey>  // ECDH
}

pub struct Signature {
    pub fn new(r: [u8; 32], s: [u8; 32]) -> Self                 // Create from R, S
    pub fn from_der(der: &[u8]) -> Result<Self>                  // Parse DER format
    pub fn from_compact(data: &[u8; 64]) -> Result<Self>         // Parse 64-byte format
    pub fn r(&self) -> &[u8; 32]                                 // R component
    pub fn s(&self) -> &[u8; 32]                                 // S component
    pub fn to_der(&self) -> Vec<u8>                              // Encode as DER (low-S)
    pub fn to_compact(&self) -> [u8; 64]                         // Encode as 64 bytes
    pub fn is_low_s(&self) -> bool                               // Check BIP 62 compliance
    pub fn to_low_s(&self) -> Signature                          // Convert to low-S form
    pub fn verify(&self, msg_hash: &[u8; 32], public_key: &PublicKey) -> bool  // Verify
}

// ECDSA functions
pub fn sign(msg_hash: &[u8; 32], private_key: &PrivateKey) -> Result<Signature>
pub fn verify(msg_hash: &[u8; 32], signature: &Signature, public_key: &PublicKey) -> bool
pub fn recover_public_key(msg_hash: &[u8; 32], signature: &Signature, recovery_id: u8) -> Result<PublicKey>
```

**Key Features:**
- RFC 6979 deterministic nonce generation for signing
- BIP 62 compliant (low-S signatures enforced)
- BRC-42 key derivation for hierarchical key generation
- ECDH for shared secret computation
- WIF encoding/decoding for wallet import/export
- Address generation (P2PKH, Base58Check encoded)

### P-256 (secp256r1) Elliptic Curve

The P-256 (NIST secp256r1) curve, used for certain authentication scenarios:

```rust
pub struct P256PrivateKey {
    pub fn random() -> Self                                      // Generate random key
    pub fn from_bytes(bytes: &[u8]) -> Result<Self>              // From 32 bytes
    pub fn from_hex(hex: &str) -> Result<Self>                   // From hex string
    pub fn public_key(&self) -> P256PublicKey                    // Derive public key
    pub fn sign(&self, message: &[u8]) -> P256Signature          // Sign message (SHA-256 hash)
    pub fn sign_hash(&self, hash: &[u8; 32]) -> P256Signature    // Sign pre-hashed data
    pub fn to_bytes(&self) -> [u8; 32]                           // Export as bytes
    pub fn to_hex(&self) -> String                               // Export as hex
}

pub struct P256PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self>              // From 33 or 65 bytes
    pub fn from_hex(hex: &str) -> Result<Self>                   // From hex string
    pub fn verify(&self, message: &[u8], signature: &P256Signature) -> bool  // Verify (SHA-256 hash)
    pub fn verify_hash(&self, hash: &[u8; 32], signature: &P256Signature) -> bool  // Verify pre-hashed
    pub fn to_compressed(&self) -> [u8; 33]                      // 02/03 prefix + X
    pub fn to_uncompressed(&self) -> [u8; 65]                    // 04 prefix + X + Y
    pub fn to_hex(&self) -> String                               // Compressed hex
    pub fn to_hex_uncompressed(&self) -> String                  // Uncompressed hex
    pub fn x(&self) -> [u8; 32]                                  // X coordinate
    pub fn y(&self) -> [u8; 32]                                  // Y coordinate
}

pub struct P256Signature {
    pub fn new(r: [u8; 32], s: [u8; 32]) -> Result<Self>         // Create from R, S
    pub fn from_der(der: &[u8]) -> Result<Self>                  // Parse DER format
    pub fn from_compact(data: &[u8; 64]) -> Result<Self>         // Parse 64-byte format
    pub fn from_compact_slice(data: &[u8]) -> Result<Self>       // Parse from slice
    pub fn r(&self) -> [u8; 32]                                  // R component
    pub fn s(&self) -> [u8; 32]                                  // S component
    pub fn to_der(&self) -> Vec<u8>                              // Encode as DER (low-S)
    pub fn to_compact(&self) -> [u8; 64]                         // Encode as 64 bytes
    pub fn is_low_s(&self) -> bool                               // Check low-S compliance
    pub fn to_low_s(&self) -> P256Signature                      // Convert to low-S form
}

// Convenience functions
pub fn generate_private_key_hex() -> String
pub fn public_key_from_private(private_key_hex: &str) -> Result<P256PublicKey>
pub fn sign(message: &[u8], private_key_hex: &str) -> Result<P256Signature>
pub fn verify(message: &[u8], signature: &P256Signature, public_key: &P256PublicKey) -> bool
```

**Key Features:**
- RFC 6979 deterministic nonce generation
- Low-S signature normalization (S <= n/2)
- Automatic SHA-256 hashing for message signing/verification
- Prehash variants for direct hash signing (`sign_hash`, `verify_hash`)
- Compressed and uncompressed point encoding
- Constant-time private key comparison

### Binary Reader/Writer
```rust
pub struct Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self
    pub fn remaining(&self) -> usize
    pub fn is_empty(&self) -> bool
    pub fn position(&self) -> usize
    pub fn read_u8(&mut self) -> Result<u8>
    pub fn read_u16_le(&mut self) -> Result<u16>
    pub fn read_u32_le(&mut self) -> Result<u32>
    pub fn read_u64_le(&mut self) -> Result<u64>
    pub fn read_i8(&mut self) -> Result<i8>
    pub fn read_i16_le(&mut self) -> Result<i16>
    pub fn read_i32_le(&mut self) -> Result<i32>
    pub fn read_i64_le(&mut self) -> Result<i64>
    pub fn read_var_int(&mut self) -> Result<u64>    // Bitcoin varint
    pub fn read_var_int_num(&mut self) -> Result<usize>
    pub fn read_bytes(&mut self, len: usize) -> Result<&'a [u8]>
    pub fn read_var_bytes(&mut self) -> Result<&'a [u8]>
    pub fn read_remaining(&mut self) -> &'a [u8]
}

pub struct Writer {
    pub fn new() -> Self
    pub fn with_capacity(capacity: usize) -> Self
    pub fn len(&self) -> usize
    pub fn is_empty(&self) -> bool
    pub fn as_bytes(&self) -> &[u8]
    pub fn into_bytes(self) -> Vec<u8>
    pub fn write_u8(&mut self, val: u8) -> &mut Self
    pub fn write_u16_le(&mut self, val: u16) -> &mut Self
    pub fn write_u32_le(&mut self, val: u32) -> &mut Self
    pub fn write_u64_le(&mut self, val: u64) -> &mut Self
    pub fn write_i8(&mut self, val: i8) -> &mut Self
    pub fn write_i16_le(&mut self, val: i16) -> &mut Self
    pub fn write_i32_le(&mut self, val: i32) -> &mut Self
    pub fn write_i64_le(&mut self, val: i64) -> &mut Self
    pub fn write_var_int(&mut self, val: u64) -> &mut Self
    pub fn write_bytes(&mut self, data: &[u8]) -> &mut Self
    pub fn write_var_bytes(&mut self, data: &[u8]) -> &mut Self
}
```

## Error Variants

The `Error` enum in `src/error.rs` provides specific error types for primitives (all implement `Clone`, `PartialEq`, `Eq`):

| Variant | Description |
|---------|-------------|
| `InvalidKeyLength { expected, actual }` | Key size mismatch |
| `InvalidDataLength { expected, actual }` | Data size mismatch for crypto operations |
| `InvalidHex(String)` | Malformed hexadecimal string |
| `InvalidBase58(String)` | Invalid Base58 characters or empty string |
| `InvalidBase64(String)` | Malformed Base64 encoding |
| `InvalidChecksum` | Base58Check checksum verification failed |
| `InvalidUtf8(String)` | Invalid UTF-8 byte sequence |
| `CryptoError(String)` | Generic cryptographic operation failure |
| `InvalidSignature(String)` | Invalid digital signature |
| `InvalidPublicKey(String)` | Invalid public key format |
| `InvalidPrivateKey(String)` | Invalid private key format |
| `PointAtInfinity` | EC point at infinity (invalid) |
| `DecryptionFailed` | AES-GCM decryption/authentication failed |
| `InvalidNonce(String)` | Invalid nonce for encryption |
| `InvalidTag` | Authentication tag mismatch |
| `ReaderUnderflow { needed, available }` | Not enough bytes to read |

A `Result<T>` type alias is provided for convenience.

## Usage

### Hashing

```rust
use bsv_sdk::primitives::{sha256, sha256d, hash160};

// Single SHA-256
let digest = sha256(b"hello world");

// Bitcoin double-SHA256 (transaction/block hashes)
let double_hash = sha256d(b"hello world");

// Bitcoin hash160 (address generation from pubkey)
let h160 = hash160(b"public_key_bytes");
```

### HMAC and Key Derivation

```rust
use bsv_sdk::primitives::{sha256_hmac, sha512_hmac, pbkdf2_sha512};

// HMAC-SHA256 for message authentication
let mac = sha256_hmac(b"secret_key", b"message");

// PBKDF2 for password-based key derivation (BIP-39 mnemonics)
let derived_key = pbkdf2_sha512(b"password", b"mnemonic", 2048, 64);
```

### Symmetric Encryption

```rust
use bsv_sdk::primitives::SymmetricKey;

// Create random key
let key = SymmetricKey::random();

// Encrypt
let ciphertext = key.encrypt(b"secret message")?;

// Decrypt
let plaintext = key.decrypt(&ciphertext)?;

// From existing bytes (31-byte keys are padded with leading zero)
let key = SymmetricKey::from_bytes(&key_bytes)?;
```

### Encoding

```rust
use bsv_sdk::primitives::{to_hex, from_hex, to_base58, from_base58, to_base58_check, from_base58_check};

// Hex encoding
let hex = to_hex(&[0xde, 0xad, 0xbe, 0xef]); // "deadbeef"
let bytes = from_hex("deadbeef")?;

// Base58 (Bitcoin alphabet, leading zeros become '1')
let b58 = to_base58(&[0x00, 0x00, 0x01]); // "112"
let bytes = from_base58("112")?;

// Base58Check (with version byte and checksum)
let address = to_base58_check(&pubkey_hash, &[0x00]); // P2PKH address
let (version, payload) = from_base58_check(&address)?;
```

### BigNumber

```rust
use bsv_sdk::primitives::BigNumber;

// Create from various sources
let n1 = BigNumber::from_hex("deadbeef").unwrap();
let n2 = BigNumber::from_i64(12345);
let n3 = BigNumber::from_bytes_be(&[0x12, 0x34]);

// Arithmetic
let sum = n1.add(&n2);
let product = n1.mul(&n2);

// Key derivation pattern (BRC-42)
let private_key = BigNumber::from_hex("0123...").unwrap();
let hmac_value = BigNumber::from_hex("fedc...").unwrap();
let order = BigNumber::secp256k1_order();
let new_key = private_key.add(&hmac_value).modulo(&order);
let key_bytes = new_key.to_bytes_be(32);  // 32-byte padded

// Modular arithmetic
let a = BigNumber::from_i64(3);
let m = BigNumber::from_i64(7);
let inv = a.mod_inverse(&m).unwrap();  // 3 * 5 = 1 (mod 7)
```

### Elliptic Curve Operations

```rust
use bsv_sdk::primitives::{PrivateKey, PublicKey, Signature};
use bsv_sdk::primitives::hash::sha256;

// Generate a random key pair
let private_key = PrivateKey::random();
let public_key = private_key.public_key();

// Sign a message
let msg_hash = sha256(b"Hello, BSV!");
let signature = private_key.sign(&msg_hash)?;

// Verify the signature
assert!(public_key.verify(&msg_hash, &signature));
assert!(signature.is_low_s()); // BIP 62 compliant

// WIF import/export
let wif = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";
let key = PrivateKey::from_wif(wif)?;
assert_eq!(key.to_wif(), wif);

// Address generation
let address = public_key.to_address(); // P2PKH mainnet address
```

### BRC-42 Key Derivation

```rust
use bsv_sdk::primitives::PrivateKey;

let alice = PrivateKey::random();
let bob = PrivateKey::random();

// Derive child keys
let alice_child = alice.derive_child(&bob.public_key(), "invoice-123")?;
let bob_derived = alice.public_key().derive_child(&bob, "invoice-123")?;

// They arrive at the same public key
assert_eq!(alice_child.public_key().to_compressed(), bob_derived.to_compressed());
```

### Shamir Secret Sharing

```rust
use bsv_sdk::primitives::bsv::shamir::{split_private_key, KeyShares};
use bsv_sdk::primitives::ec::PrivateKey;

// Generate a random private key
let key = PrivateKey::random();

// Split into 5 shares with threshold of 3
let shares = split_private_key(&key, 3, 5)?;

// Export to backup format for storage
let backup = shares.to_backup_format();
// Each share: "base58(x).base58(y).threshold.integrity"

// Later, recover from any 3 shares
let subset = KeyShares::from_backup_format(&backup[0..3])?;
let recovered = subset.recover_private_key()?;

assert_eq!(key.to_bytes(), recovered.to_bytes());
```

### P-256 Operations

```rust
use bsv_sdk::primitives::p256::{P256PrivateKey, P256PublicKey, P256Signature};

// Generate a P-256 key pair
let private_key = P256PrivateKey::random();
let public_key = private_key.public_key();

// Sign a message (automatically hashed with SHA-256)
let message = b"Hello, P-256!";
let signature = private_key.sign(message);

// Verify the signature
assert!(public_key.verify(message, &signature));

// Signature encoding
let der = signature.to_der();       // Variable-length DER format
let compact = signature.to_compact(); // Fixed 64-byte format

// Parse signatures
let sig_from_der = P256Signature::from_der(&der)?;
let sig_from_compact = P256Signature::from_compact(&compact)?;
```

### Binary Serialization

```rust
use bsv_sdk::primitives::{Reader, Writer};

// Writing Bitcoin-format data
let mut writer = Writer::new();
writer.write_u32_le(0x01000000);  // Version
writer.write_var_int(1);          // Input count
writer.write_var_bytes(b"data");  // Length-prefixed bytes
let bytes = writer.into_bytes();

// Reading Bitcoin-format data
let mut reader = Reader::new(&bytes);
let version = reader.read_u32_le()?;
let count = reader.read_var_int()?;
let data = reader.read_var_bytes()?;
```

## Bitcoin Varint Encoding

The Reader/Writer support Bitcoin's variable-length integer format:

| Value Range | Encoding |
|-------------|----------|
| 0x00-0xFC | 1 byte: value as-is |
| 0xFD-0xFFFF | 3 bytes: 0xFD + uint16 LE |
| 0x10000-0xFFFFFFFF | 5 bytes: 0xFE + uint32 LE |
| > 0xFFFFFFFF | 9 bytes: 0xFF + uint64 LE |

## Cross-SDK Compatibility Notes

### AES-256-GCM
- Uses non-standard 32-byte nonce (not 12-byte standard)
- Output format: `IV (32) || ciphertext || tag (16)`
- Keys shorter than 32 bytes get leading zero padding
- Critical for 31-byte keys from EC X coordinates

### Base58Check
- Uses Bitcoin alphabet (excludes 0, O, I, l)
- Checksum: first 4 bytes of SHA256(SHA256(version || payload))
- Used for addresses (version 0x00) and WIF keys (version 0x80)

### Test Vectors
- Test vectors are in `tests/vectors/symmetric_key.json`
- Cross-SDK compatibility verified against TypeScript and Go implementations

## Module Structure

### ec/ (Elliptic Curve Operations)
Fully implemented secp256k1 operations:
- `mod.rs` - Module re-exports
- `private_key.rs` - PrivateKey: random generation, WIF, signing, BRC-42 derivation
- `public_key.rs` - PublicKey: verification, addresses, BRC-42 derivation
- `signature.rs` - Signature: DER/compact encoding, low-S normalization
- `ecdsa.rs` - Core ECDSA sign/verify/recover functions

### bsv/ (BSV-Specific Operations)
Transaction signatures, sighash computation, Schnorr proofs, and Shamir secret sharing:
- `mod.rs` - Module re-exports
- `sighash.rs` - BIP-143 style sighash computation with 499 test vectors
- `tx_signature.rs` - Transaction signature encoding/decoding
- `schnorr.rs` - Schnorr zero-knowledge proofs for ECDH verification
- `polynomial.rs` - Polynomial operations for Shamir secret sharing
- `shamir.rs` - Shamir secret sharing for private key backup/recovery

## Dependencies

Key external crates used:
- `sha1`, `sha2`, `ripemd` - Hash algorithms (SHA-1, SHA-256, SHA-512, RIPEMD-160)
- `hmac`, `pbkdf2` - HMAC and PBKDF2 key derivation
- `aes-gcm` - AES-256-GCM authenticated encryption
- `k256` - secp256k1 elliptic curve operations (ECDSA, ECDH)
- `p256` - P-256 (secp256r1) elliptic curve operations
- `num-bigint`, `num-traits`, `num-integer` - Arbitrary-precision integers for BigNumber
- `hex`, `bs58`, `base64` - Encoding libraries
- `thiserror` - Error handling with derive macros
- `rand`, `getrandom` - Cryptographically secure random bytes
- `subtle` - Constant-time comparison for cryptographic secrets
- `serde`, `serde_json` - Test vector deserialization (test-only)

## Testing

Tests are extensive and include:
- Standard test vectors (NIST HMAC/PBKDF2, etc.)
- TypeScript SDK compatibility tests (Reader/Writer, encoding functions)
- Cross-SDK compatibility with Go implementation (SymmetricKey, sighash)
- Round-trip encoding/decoding tests (hex, base58, base64, DER signatures)
- Edge cases (empty inputs, key padding, Unicode, varint boundaries)
- Test vectors from JSON files (`tests/vectors/symmetric_key.json`)

Run tests with:
```bash
cargo test primitives
```
