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
  ├── encoding.rs         # Phase 3: Encoding utilities (placeholder)
  ├── symmetric.rs        # Phase 2: AES-GCM (placeholder)
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
| Phase 2 | Symmetric Encryption (AES-GCM) | 🔲 Pending |
| Phase 3 | Encoding Utilities | 🔲 Pending |
| Phase 4 | BigNumber Compatibility | 🔲 Pending |
| Phase 5 | Elliptic Curve Operations | 🔲 Pending |
| Phase 6 | BSV-Specific Components | 🔲 Pending |
| Phase 7 | P-256 Support | 🔲 Pending |
| Phase 8 | Integration Testing | 🔲 Pending |
