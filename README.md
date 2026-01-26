# BSV Primitives

A Rust library providing cryptographic primitives for the BSV blockchain.

## Overview

This crate provides low-level cryptographic building blocks used in BSV (Bitcoin SV) applications:

- **Hash functions**: SHA-1, SHA-256, SHA-512, RIPEMD-160
- **Bitcoin-specific hashes**: hash256 (double SHA-256), hash160 (RIPEMD160(SHA256(x)))
- **HMAC**: HMAC-SHA256, HMAC-SHA512
- **Key derivation**: PBKDF2-SHA512
- **Symmetric encryption**: AES-256-GCM *(coming soon)*
- **Elliptic curve cryptography**: secp256k1, secp256r1 *(coming soon)*
- **BSV-specific**: Transaction signatures, BRC-42 key derivation *(coming soon)*

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
bsv-primitives = "0.1"
```

## Usage

### Hash Functions

```rust
use bsv_primitives::hash;

// SHA-256
let digest = hash::sha256(b"hello world");
assert_eq!(digest.len(), 32);

// Bitcoin double-SHA256 (used for txids, block hashes)
let txid_hash = hash::sha256d(b"transaction data");

// Bitcoin hash160 (used for addresses)
let address_hash = hash::hash160(b"public key bytes");
assert_eq!(address_hash.len(), 20);

// RIPEMD-160
let ripemd = hash::ripemd160(b"data");

// SHA-512
let sha512_hash = hash::sha512(b"data");
assert_eq!(sha512_hash.len(), 64);
```

### HMAC

```rust
use bsv_primitives::hash;

let key = b"secret key";
let message = b"message to authenticate";

// HMAC-SHA256
let mac = hash::sha256_hmac(key, message);
assert_eq!(mac.len(), 32);

// HMAC-SHA512
let mac512 = hash::sha512_hmac(key, message);
assert_eq!(mac512.len(), 64);
```

### PBKDF2 Key Derivation

```rust
use bsv_primitives::hash;

let password = b"user password";
let salt = b"random salt";
let iterations = 2048;
let key_length = 64; // bytes

let derived_key = hash::pbkdf2_sha512(password, salt, iterations, key_length);
assert_eq!(derived_key.len(), 64);
```

## API Reference

### Hash Functions

| Function | Output Size | Description |
|----------|-------------|-------------|
| `sha1(data)` | 20 bytes | SHA-1 (legacy, for compatibility only) |
| `sha256(data)` | 32 bytes | SHA-256 |
| `sha512(data)` | 64 bytes | SHA-512 |
| `ripemd160(data)` | 20 bytes | RIPEMD-160 |
| `sha256d(data)` | 32 bytes | SHA256(SHA256(data)) - Bitcoin "hash256" |
| `hash160(data)` | 20 bytes | RIPEMD160(SHA256(data)) - Bitcoin address hash |

### HMAC Functions

| Function | Output Size | Description |
|----------|-------------|-------------|
| `sha256_hmac(key, data)` | 32 bytes | HMAC using SHA-256 |
| `sha512_hmac(key, data)` | 64 bytes | HMAC using SHA-512 |

### Key Derivation

| Function | Description |
|----------|-------------|
| `pbkdf2_sha512(password, salt, iterations, key_len)` | PBKDF2 with HMAC-SHA512 |

## Compatibility

This library is designed to be byte-for-byte compatible with:

- [BSV TypeScript SDK](https://github.com/bitcoin-sv/ts-sdk) primitives module
- [BSV Go SDK](https://github.com/bitcoin-sv/go-sdk) primitives module

All implementations share the same test vectors to ensure cross-platform compatibility.

## Development

### Building

```bash
cargo build
```

### Running Tests

```bash
cargo test
```

### Running Clippy

```bash
cargo clippy --all-targets --all-features
```

### Formatting

```bash
cargo fmt
```

### Building Documentation

```bash
cargo doc --open
```

### Running Benchmarks

```bash
cargo bench
```

## Project Structure

```
bsv-primitives/
├── Cargo.toml              # Package manifest
├── src/
│   ├── lib.rs              # Library root, public exports
│   ├── error.rs            # Error types
│   ├── hash.rs             # Hash functions (implemented)
│   ├── encoding.rs         # Hex, base58, base64 (planned)
│   ├── symmetric.rs        # AES-GCM encryption (planned)
│   ├── ec/                 # Elliptic curve crypto (planned)
│   │   ├── mod.rs
│   │   ├── private_key.rs
│   │   ├── public_key.rs
│   │   └── signature.rs
│   └── bsv/                # BSV-specific (planned)
│       ├── mod.rs
│       ├── key_derivation.rs
│       └── tx_signature.rs
├── tests/
│   └── vectors/            # Test vectors from Go SDK
│       ├── brc42_private.json
│       ├── brc42_public.json
│       ├── drbg.json
│       └── symmetric_key.json
└── benches/
    └── hash_bench.rs       # Performance benchmarks
```

## Roadmap

- [x] **Phase 0**: Project setup
- [x] **Phase 1**: Hash functions (SHA-1, SHA-256, SHA-512, RIPEMD-160, HMAC, PBKDF2)
- [ ] **Phase 2**: Symmetric encryption (AES-256-GCM)
- [ ] **Phase 3**: Encoding utilities (hex, base58, base64)
- [ ] **Phase 4**: BigNumber compatibility layer
- [ ] **Phase 5**: Elliptic curve operations (secp256k1)
- [ ] **Phase 6**: BSV-specific components (BRC-42, transaction signatures)
- [ ] **Phase 7**: P-256 (secp256r1) support
- [ ] **Phase 8**: Integration testing and optimization

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contributing

Contributions are welcome! Please ensure that:

1. All tests pass (`cargo test`)
2. Code is formatted (`cargo fmt`)
3. Clippy is happy (`cargo clippy`)
4. New functionality includes tests and documentation
