# BSV Primitives Source
> Cryptographic primitives for the BSV blockchain in Rust

## Overview

This is the source directory for the `bsv-primitives` crate, providing cryptographic primitives compatible with the BSV TypeScript and Go SDKs. The library implements hash functions, symmetric encryption (AES-256-GCM), encoding utilities, binary serialization, and arbitrary-precision integers (BigNumber). Elliptic curve and BSV-specific modules are placeholders for future implementation phases.

## Files

| File | Purpose |
|------|---------|
| `lib.rs` | Crate root; module declarations and re-exports |
| `error.rs` | Error types using `thiserror` |
| `hash.rs` | SHA-1, SHA-256, SHA-512, RIPEMD-160, HMAC, PBKDF2 |
| `symmetric.rs` | AES-256-GCM encryption with BSV SDK compatibility |
| `encoding.rs` | Hex, Base58, Base58Check, Base64, UTF-8, Reader/Writer |
| `bignum.rs` | Arbitrary-precision integers for EC scalars and key derivation |
| `ec/` | Placeholder for secp256k1 elliptic curve (Phase 5) |
| `bsv/` | Placeholder for BSV-specific operations (Phase 6) |

## Key Exports

The crate re-exports commonly used items from `lib.rs`:

### Error Handling
- `Error` - Main error enum with variants for key length, data length, encoding, crypto operations, and checksums
- `Result<T>` - Type alias for `std::result::Result<T, Error>`

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

**Important**: Uses non-standard 32-byte nonce for BSV SDK compatibility. Output format: `IV (32 bytes) || ciphertext || auth_tag (16 bytes)`. Keys shorter than 32 bytes are padded with leading zeros.

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

// Base64
pub fn to_base64(data: &[u8]) -> String
pub fn from_base64(s: &str) -> Result<Vec<u8>>

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
}
```

**Design Note**: Following the Go SDK approach, this is a minimal compatibility layer wrapping `num-bigint`. It does NOT implement the full bn.js API (no word arrays, reduction contexts, or in-place mutation). It provides what's needed for EC scalar operations and BRC-42 key derivation.

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

The `Error` enum in `error.rs` provides specific error types:

| Variant | Description |
|---------|-------------|
| `InvalidKeyLength` | Key size mismatch (expected vs actual) |
| `InvalidDataLength` | Data size mismatch for crypto operations |
| `InvalidHex` | Malformed hexadecimal string |
| `InvalidBase58` | Invalid Base58 characters or empty string |
| `InvalidBase64` | Malformed Base64 encoding |
| `InvalidChecksum` | Base58Check checksum verification failed |
| `InvalidUtf8` | Invalid UTF-8 byte sequence |
| `CryptoError` | Generic cryptographic operation failure |
| `InvalidSignature` | Invalid digital signature |
| `InvalidPublicKey` | Invalid public key format |
| `InvalidPrivateKey` | Invalid private key format |
| `PointAtInfinity` | EC point at infinity (invalid) |
| `DecryptionFailed` | AES-GCM decryption/authentication failed |
| `InvalidNonce` | Invalid nonce for encryption |
| `InvalidTag` | Authentication tag mismatch |
| `ReaderUnderflow` | Not enough bytes to read |

## Usage

### Hashing

```rust
use bsv_primitives::{sha256, sha256d, hash160};

// Single SHA-256
let digest = sha256(b"hello world");

// Bitcoin double-SHA256 (transaction/block hashes)
let double_hash = sha256d(b"hello world");

// Bitcoin hash160 (address generation from pubkey)
let h160 = hash160(b"public_key_bytes");
```

### HMAC and Key Derivation

```rust
use bsv_primitives::{sha256_hmac, sha512_hmac, pbkdf2_sha512};

// HMAC-SHA256 for message authentication
let mac = sha256_hmac(b"secret_key", b"message");

// PBKDF2 for password-based key derivation (BIP-39 mnemonics)
let derived_key = pbkdf2_sha512(b"password", b"mnemonic", 2048, 64);
```

### Symmetric Encryption

```rust
use bsv_primitives::SymmetricKey;

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
use bsv_primitives::{to_hex, from_hex, to_base58, from_base58, to_base58_check, from_base58_check};

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
use bsv_primitives::BigNumber;

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

### Binary Serialization

```rust
use bsv_primitives::{Reader, Writer};

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

## Placeholder Modules

### ec/ (Phase 5)
Reserved for elliptic curve operations:
- `private_key.rs` - secp256k1 private key operations
- `public_key.rs` - secp256k1 public key operations
- `signature.rs` - ECDSA signature operations

### bsv/ (Phase 6)
Reserved for BSV-specific operations:
- `key_derivation.rs` - BRC-42 key derivation
- `tx_signature.rs` - Transaction signature operations

## Dependencies

Key external crates used:
- `sha1`, `sha2`, `ripemd` - Hash algorithms
- `hmac`, `pbkdf2` - HMAC and key derivation
- `aes-gcm` - AES-256-GCM encryption
- `num-bigint`, `num-traits`, `num-integer` - Arbitrary-precision integers
- `hex`, `bs58`, `base64` - Encoding
- `thiserror` - Error handling
- `getrandom` - Cryptographically secure random bytes
- `subtle` - Constant-time comparison
- `serde`, `serde_json` - Test vector deserialization

## Testing

Tests are extensive and include:
- Standard test vectors (NIST, etc.)
- TypeScript SDK compatibility tests
- Cross-SDK compatibility with Go implementation
- Round-trip encoding/decoding tests
- Edge cases (empty inputs, padding, Unicode)

Run tests with:
```bash
cargo test
```
