# Changelog

All notable changes to the BSV Primitives Rust library will be documented in this file.

## [0.1.0] - 2026-01-26

### Phase 0: Project Setup

#### Added
- **Cargo.toml** with all required dependencies:
  - Hashing: `sha2`, `sha1`, `ripemd`, `hmac`, `pbkdf2`
  - Elliptic curves (for later phases): `k256`, `p256`
  - Symmetric encryption (for later phases): `aes-gcm`
  - Big integers (for later phases): `num-bigint`, `num-traits`
  - Randomness: `rand`, `getrandom`
  - Encoding: `hex`, `bs58`, `base64`
  - Error handling: `thiserror`
  - Serialization: `serde`, `serde_json`

- **Module structure** with placeholder files:
  ```
  src/
  ├── lib.rs              # Public exports
  ├── error.rs            # Error types using thiserror
  ├── hash.rs             # Phase 1: Hash functions (implemented)
  ├── encoding.rs         # Phase 3: Encoding utilities (implemented)
  ├── symmetric.rs        # Phase 2: AES-GCM (implemented)
  ├── ec/                 # Phase 5: Elliptic curve (placeholders)
  │   ├── mod.rs
  │   ├── private_key.rs
  │   ├── public_key.rs
  │   └── signature.rs
  └── bsv/                # Phase 6: BSV-specific (placeholders)
      ├── mod.rs
      ├── key_derivation.rs
      └── tx_signature.rs
  ```

- **Test infrastructure**:
  - Created `tests/vectors/` directory
  - Copied JSON test vectors from Go SDK:
    - `tests/vectors/drbg.json` - DRBG test vectors
    - `tests/vectors/brc42_private.json` - BRC-42 private key derivation vectors
    - `tests/vectors/brc42_public.json` - BRC-42 public key derivation vectors
    - `tests/vectors/symmetric_key.json` - Symmetric encryption vectors

- **CI/CD setup**:
  - `.github/workflows/ci.yml` for automated testing
  - Runs on Ubuntu, macOS, and Windows
  - Tests with Rust stable and beta
  - Includes clippy linting and rustfmt checks
  - Builds documentation

- **Benchmark infrastructure**:
  - `benches/hash_bench.rs` using Criterion

---

### Phase 1: Hash Functions

#### Added
All hash functions implemented in `src/hash.rs`:

| Function | Signature | Description |
|----------|-----------|-------------|
| `sha1` | `fn sha1(data: &[u8]) -> [u8; 20]` | SHA-1 hash (legacy, for compatibility) |
| `sha256` | `fn sha256(data: &[u8]) -> [u8; 32]` | SHA-256 hash |
| `sha512` | `fn sha512(data: &[u8]) -> [u8; 64]` | SHA-512 hash |
| `ripemd160` | `fn ripemd160(data: &[u8]) -> [u8; 20]` | RIPEMD-160 hash |
| `sha256d` | `fn sha256d(data: &[u8]) -> [u8; 32]` | Double SHA-256 (Bitcoin hash256) |
| `hash160` | `fn hash160(data: &[u8]) -> [u8; 20]` | RIPEMD160(SHA256(x)) for Bitcoin addresses |
| `sha256_hmac` | `fn sha256_hmac(key: &[u8], data: &[u8]) -> [u8; 32]` | HMAC-SHA256 |
| `sha512_hmac` | `fn sha512_hmac(key: &[u8], data: &[u8]) -> [u8; 64]` | HMAC-SHA512 |
| `pbkdf2_sha512` | `fn pbkdf2_sha512(password: &[u8], salt: &[u8], iterations: u32, key_len: usize) -> Vec<u8>` | PBKDF2 key derivation with SHA-512 |

#### Tests
37 unit tests covering all hash functions with known test vectors:

- **SHA-1**: Empty string, "abc", long string, hex input
- **SHA-256**: "abc", long string, hex input
- **SHA-512**: "abc", long string
- **RIPEMD-160**: Empty string, "abc", "message digest", long string, alphanumeric
- **sha256d**: Verifies SHA256(SHA256(x)) composition
- **hash160**: Verifies RIPEMD160(SHA256(x)) composition
- **HMAC-SHA256**: 5 tests including NIST vectors and regression tests
- **PBKDF2-SHA512**: 12 tests from TypeScript SDK vectors including:
  - Basic usage (1 and 2 iterations)
  - Various output lengths (10, 32, 40, 64, 100 bytes)
  - 4096 iterations
  - Long password and salt
  - Null bytes in password/salt
  - Hex-encoded keys
  - Unicode salt
- **UTF-8 handling**: Tests for 1, 2, 3, and 4-byte UTF-8 characters

#### Documentation
- Comprehensive rustdoc comments on all public functions
- Module-level documentation with usage examples
- Doc-tests that serve as executable examples (13 doc-tests)

---

### Phase 2: Symmetric Encryption (AES-256-GCM)

#### Added
`SymmetricKey` struct in `src/symmetric.rs` with full cross-SDK compatibility:

| Method | Signature | Description |
|--------|-----------|-------------|
| `random` | `fn random() -> Self` | Create key from random bytes |
| `from_bytes` | `fn from_bytes(bytes: &[u8]) -> Result<Self, Error>` | Create from existing bytes (pads with leading zeros if < 32 bytes) |
| `encrypt` | `fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, Error>` | AES-256-GCM encrypt |
| `decrypt` | `fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Error>` | AES-256-GCM decrypt |
| `as_bytes` | `fn as_bytes(&self) -> &[u8; 32]` | Get raw key bytes |

#### Implementation Details
- **32-byte nonce**: Non-standard for AES-GCM (typically 12 bytes), but required for BSV SDK compatibility
- **Leading-zero padding**: Keys shorter than 32 bytes are padded with leading zeros (critical for 31-byte EC X-coordinate keys)
- **Output format**: `IV (32 bytes) || ciphertext || auth_tag (16 bytes)`
- **Security features**:
  - Constant-time key comparison using `subtle` crate
  - Key zeroing on drop
  - Debug output redaction (key bytes not exposed)

#### Tests
25 unit tests covering symmetric encryption:

| Test Category | Count | Description |
|--------------|-------|-------------|
| Basic operations | 10 | Encrypt/decrypt roundtrip, empty data, large data, ciphertext format |
| Key handling | 6 | 31-byte padding, 32-byte, empty, too long, short key padding |
| Security | 4 | Wrong key detection, tampered ciphertext/tag, constant-time comparison |
| Cross-SDK (TypeScript) | 2 | Decrypt TS-generated ciphertext with 31/32-byte keys |
| Cross-SDK (Go) | 2 | Decrypt Go-generated ciphertext with 31/32-byte keys |
| Test vectors | 1 | Decrypt from `tests/vectors/symmetric_key.json` |

#### Cross-SDK Compatibility
Successfully decrypts ciphertext generated by:
- **TypeScript SDK** - Both 31-byte and 32-byte key variants
- **Go SDK** - Both 31-byte and 32-byte key variants

Test keys derived from WIFs:
- 31-byte key: `L4B2postXdaP7TiUrUBYs53Fqzheu7WhSoQVPuY8qBdoBeEwbmZx` (public key X coordinate is 31 bytes)
- 32-byte key: `KyLGEhYicSoGchHKmVC2fUx2MRrHzWqvwBFLLT4DZB93Nv5DxVR9` (public key X coordinate is 32 bytes)

#### Documentation
- Comprehensive rustdoc comments on all public methods
- Module-level documentation with usage examples
- Doc-tests that serve as executable examples (6 doc-tests)

---

### Phase 3: Encoding Utilities

#### Added
All encoding functions implemented in `src/encoding.rs`:

**Hex Encoding:**

| Function | Signature | Description |
|----------|-----------|-------------|
| `to_hex` | `fn to_hex(data: &[u8]) -> String` | Convert bytes to lowercase hex string |
| `from_hex` | `fn from_hex(s: &str) -> Result<Vec<u8>>` | Decode hex string (case-insensitive) |

**Base58 (Bitcoin alphabet):**

| Function | Signature | Description |
|----------|-----------|-------------|
| `to_base58` | `fn to_base58(data: &[u8]) -> String` | Encode bytes to Base58 (leading zeros become '1's) |
| `from_base58` | `fn from_base58(s: &str) -> Result<Vec<u8>>` | Decode Base58 string |
| `BASE58_ALPHABET` | `const &str` | Bitcoin Base58 alphabet (excludes 0, O, I, l) |

**Base58Check (with version and checksum):**

| Function | Signature | Description |
|----------|-----------|-------------|
| `to_base58_check` | `fn to_base58_check(payload: &[u8], version: &[u8]) -> String` | Encode with version prefix and SHA256d checksum |
| `from_base58_check` | `fn from_base58_check(s: &str) -> Result<(Vec<u8>, Vec<u8>)>` | Decode and validate checksum, returns (version, payload) |
| `from_base58_check_with_prefix_length` | `fn from_base58_check_with_prefix_length(s: &str, prefix_length: usize) -> Result<(Vec<u8>, Vec<u8>)>` | Decode with custom version prefix length |

**Base64:**

| Function | Signature | Description |
|----------|-----------|-------------|
| `to_base64` | `fn to_base64(data: &[u8]) -> String` | Encode bytes to Base64 with padding |
| `from_base64` | `fn from_base64(s: &str) -> Result<Vec<u8>>` | Decode Base64 (supports padded, unpadded, URL-safe) |

**UTF-8:**

| Function | Signature | Description |
|----------|-----------|-------------|
| `to_utf8_bytes` | `fn to_utf8_bytes(s: &str) -> Vec<u8>` | Convert string to UTF-8 bytes |
| `from_utf8_bytes` | `fn from_utf8_bytes(data: &[u8]) -> Result<String>` | Convert UTF-8 bytes to string |

**Binary Reader (`Reader<'a>` struct):**

| Method | Signature | Description |
|--------|-----------|-------------|
| `new` | `fn new(data: &'a [u8]) -> Self` | Create reader over byte slice |
| `read_u8` | `fn read_u8(&mut self) -> Result<u8>` | Read unsigned 8-bit |
| `read_u16_le` | `fn read_u16_le(&mut self) -> Result<u16>` | Read unsigned 16-bit little-endian |
| `read_u32_le` | `fn read_u32_le(&mut self) -> Result<u32>` | Read unsigned 32-bit little-endian |
| `read_u64_le` | `fn read_u64_le(&mut self) -> Result<u64>` | Read unsigned 64-bit little-endian |
| `read_i8` | `fn read_i8(&mut self) -> Result<i8>` | Read signed 8-bit |
| `read_i16_le` | `fn read_i16_le(&mut self) -> Result<i16>` | Read signed 16-bit little-endian |
| `read_i32_le` | `fn read_i32_le(&mut self) -> Result<i32>` | Read signed 32-bit little-endian |
| `read_i64_le` | `fn read_i64_le(&mut self) -> Result<i64>` | Read signed 64-bit little-endian |
| `read_var_int` | `fn read_var_int(&mut self) -> Result<u64>` | Read Bitcoin varint |
| `read_var_int_num` | `fn read_var_int_num(&mut self) -> Result<usize>` | Read Bitcoin varint as usize |
| `read_bytes` | `fn read_bytes(&mut self, len: usize) -> Result<&'a [u8]>` | Read fixed number of bytes |
| `read_var_bytes` | `fn read_var_bytes(&mut self) -> Result<&'a [u8]>` | Read varint-prefixed bytes |
| `read_remaining` | `fn read_remaining(&mut self) -> &'a [u8]` | Read all remaining bytes |
| `remaining` | `fn remaining(&self) -> usize` | Bytes left to read |
| `is_empty` | `fn is_empty(&self) -> bool` | Check if no bytes remain |
| `position` | `fn position(&self) -> usize` | Current read position |

**Binary Writer (`Writer` struct):**

| Method | Signature | Description |
|--------|-----------|-------------|
| `new` | `fn new() -> Self` | Create empty writer |
| `with_capacity` | `fn with_capacity(capacity: usize) -> Self` | Create with pre-allocated capacity |
| `write_u8` | `fn write_u8(&mut self, val: u8) -> &mut Self` | Write unsigned 8-bit |
| `write_u16_le` | `fn write_u16_le(&mut self, val: u16) -> &mut Self` | Write unsigned 16-bit little-endian |
| `write_u32_le` | `fn write_u32_le(&mut self, val: u32) -> &mut Self` | Write unsigned 32-bit little-endian |
| `write_u64_le` | `fn write_u64_le(&mut self, val: u64) -> &mut Self` | Write unsigned 64-bit little-endian |
| `write_i8` | `fn write_i8(&mut self, val: i8) -> &mut Self` | Write signed 8-bit |
| `write_i16_le` | `fn write_i16_le(&mut self, val: i16) -> &mut Self` | Write signed 16-bit little-endian |
| `write_i32_le` | `fn write_i32_le(&mut self, val: i32) -> &mut Self` | Write signed 32-bit little-endian |
| `write_i64_le` | `fn write_i64_le(&mut self, val: i64) -> &mut Self` | Write signed 64-bit little-endian |
| `write_var_int` | `fn write_var_int(&mut self, val: u64) -> &mut Self` | Write Bitcoin varint |
| `write_bytes` | `fn write_bytes(&mut self, data: &[u8]) -> &mut Self` | Write raw bytes |
| `write_var_bytes` | `fn write_var_bytes(&mut self, data: &[u8]) -> &mut Self` | Write varint-prefixed bytes |
| `len` | `fn len(&self) -> usize` | Current length |
| `is_empty` | `fn is_empty(&self) -> bool` | Check if empty |
| `as_bytes` | `fn as_bytes(&self) -> &[u8]` | Get reference to written bytes |
| `into_bytes` | `fn into_bytes(self) -> Vec<u8>` | Consume writer, return bytes |

#### Bitcoin VarInt Format
Implemented exact Bitcoin varint encoding:
- `0x00-0xFC`: 1 byte, value as-is
- `0xFD`: 3 bytes total, `0xFD` prefix + 2 bytes little-endian uint16
- `0xFE`: 5 bytes total, `0xFE` prefix + 4 bytes little-endian uint32
- `0xFF`: 9 bytes total, `0xFF` prefix + 8 bytes little-endian uint64

#### Error Types Added
New error variants in `src/error.rs`:
- `InvalidUtf8(String)` - Invalid UTF-8 sequence
- `ReaderUnderflow { needed, available }` - Not enough bytes to read
- `InvalidChecksum` - Base58Check checksum validation failed

#### Tests
63 unit tests covering all encoding functionality:

| Test Category | Count | Description |
|--------------|-------|-------------|
| Hex encoding | 4 | Basic, case-insensitive, invalid input |
| Base58 | 7 | Leading zeros, known values, roundtrip, invalid chars |
| Base58Check | 5 | Addresses, WIF keys, compressed WIF, invalid checksum |
| Base64 | 6 | Padded, unpadded, URL-safe, whitespace, invalid |
| UTF-8 | 3 | Basic, Unicode, invalid sequences |
| Reader | 16 | All integer types, varints, bytes, underflow errors |
| Writer | 14 | All integer types, varints, bytes, chaining |
| Round-trip | 4 | Reader/Writer interop, varint edge cases |
| TypeScript compat | 9 | Tests using exact values from TS SDK test suite |

#### Cross-SDK Compatibility
Tests use identical test vectors from:
- **TypeScript SDK**: `utils.test.ts`, `Reader.test.ts`, `Writer.test.ts`
- **Go SDK**: `base58_test.go`

Example compatible values:
- Base58: `"6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV"` ↔ `02c0ded2bc1f1305fb...`
- Address: `"1PRTTaJesdNovgne6Ehcdu1fpEdX7913CK"` (version 0x00)
- WIF: `"5J3mBbAH58CpQ3Y5RNJpUKPE62SQ5tfcvU2JpbnkeyhfsYB1Jcn"` (version 0x80)

#### Documentation
- Comprehensive rustdoc comments on all public functions and types
- Module-level documentation with usage examples
- 17 doc-tests that serve as executable examples

---

## Reference Implementations

This library is being ported from two reference implementations:

- **TypeScript SDK**: `/Users/johncalhoun/bsv/ts-sdk/src/primitives/`
- **Go SDK**: `/Users/johncalhoun/bsv/go-sdk/primitives/`

Test vectors are shared across all three implementations to ensure byte-for-byte compatibility.

---

## Upcoming Phases

| Phase | Component | Status |
|-------|-----------|--------|
| Phase 0 | Project Setup | ✅ Complete |
| Phase 1 | Hash Functions | ✅ Complete |
| Phase 2 | Symmetric Encryption (AES-GCM) | ✅ Complete |
| Phase 3 | Encoding Utilities | ✅ Complete |
| Phase 4 | BigNumber Compatibility | 🔲 Pending |
| Phase 5 | Elliptic Curve Operations | 🔲 Pending |
| Phase 6 | BSV-Specific Components | 🔲 Pending |
| Phase 7 | P-256 Support | 🔲 Pending |
| Phase 8 | Integration Testing | 🔲 Pending |
