# Benchmarks
> Performance measurement suite for BSV SDK cryptographic operations

## Overview

This module contains Criterion-based benchmarks for measuring the performance of cryptographic primitives in the BSV SDK. The benchmarks cover hash functions, key operations, signing/verification, encryption, encoding, and BSV-specific protocols like Schnorr proofs, Shamir secret sharing, and sighash computation.

## Files

| File | Purpose |
|------|---------|
| `hash_bench.rs` | Standalone hash function benchmarks |
| `primitives_bench.rs` | Comprehensive benchmarks for all primitives |

## Benchmark Groups

### hash_bench.rs

Focused benchmarks for core hash functions:

| Benchmark | Function |
|-----------|----------|
| `sha256` | `hash::sha256()` |
| `sha512` | `hash::sha512()` |
| `sha256d` | `hash::sha256d()` (double SHA256) |
| `hash160` | `hash::hash160()` (SHA256 + RIPEMD160) |
| `sha256_hmac` | `hash::sha256_hmac()` |

### primitives_bench.rs

Comprehensive benchmarks organized into 11 groups:

#### Key Generation
- `PrivateKey::random` - secp256k1 key generation
- `P256PrivateKey::random` - P-256/secp256r1 key generation
- `SymmetricKey::random` - AES key generation
- `PrivateKey::public_key` - secp256k1 public key derivation
- `P256PrivateKey::public_key` - P-256 public key derivation

#### Signing
- `PrivateKey::sign (secp256k1)` - ECDSA signing on secp256k1
- `P256PrivateKey::sign` - ECDSA signing on P-256
- `P256PrivateKey::sign_hash` - P-256 signing with pre-hashed message

#### Verification
- `PublicKey::verify (secp256k1)` - ECDSA verification on secp256k1
- `P256PublicKey::verify` - ECDSA verification on P-256

#### Key Derivation
- `PrivateKey::derive_child` - BRC-42 private key derivation
- `PublicKey::derive_child` - BRC-42 public key derivation
- `PrivateKey::derive_shared_secret` - ECDH shared secret computation
- `PublicKey::mul_scalar` - Scalar multiplication on public key

#### Symmetric Encryption
Throughput benchmarks at multiple payload sizes (64B, 256B, 1KB, 4KB, 16KB):
- `encrypt` - AES-GCM encryption
- `decrypt` - AES-GCM decryption

#### Hashing
Throughput benchmarks on 1KB payloads:
- `sha256`, `sha512`, `sha256d`, `hash160`, `ripemd160`, `sha1`
- `sha256_hmac`, `sha512_hmac`

#### Encoding
Throughput benchmarks on 1KB payloads:
- `to_hex`, `from_hex` - Hexadecimal encoding/decoding
- `to_base58`, `from_base58` - Base58 encoding/decoding

#### Schnorr Proofs
- `Schnorr::generate_proof` - Generate Schnorr zero-knowledge proof
- `Schnorr::verify_proof` - Verify Schnorr proof

#### Shamir Secret Sharing
- `split_private_key (3 of 5)` - Split key into 5 shares, 3 required
- `split_private_key (5 of 10)` - Split key into 10 shares, 5 required
- `recover_private_key (3 of 5)` - Recover key from 3 shares
- `to_backup_format` - Serialize shares to backup format
- `from_backup_format` - Deserialize shares from backup

#### Sighash
- `compute_sighash (5 inputs, 5 outputs)` - BSV transaction sighash computation

#### WIF and Address
- `PrivateKey::to_wif` - Encode private key to WIF format
- `PrivateKey::from_wif` - Decode WIF to private key
- `PublicKey::to_address` - Generate Bitcoin address from public key
- `PublicKey::hash160` - Compute hash160 of public key

## Running Benchmarks

```bash
# Run all benchmarks
cargo bench

# Run specific benchmark file
cargo bench --bench primitives_bench
cargo bench --bench hash_bench

# Run specific benchmark group
cargo bench -- "Key Generation"
cargo bench -- "Hashing"

# Run with detailed output
cargo bench -- --verbose

# Save baseline for comparison
cargo bench -- --save-baseline main

# Compare against baseline
cargo bench -- --baseline main
```

## Output

Criterion generates detailed HTML reports in `target/criterion/`. Each benchmark group has its own report showing:
- Execution time statistics (mean, median, std dev)
- Throughput (for sized operations)
- Historical comparison graphs
- Outlier detection

## Adding New Benchmarks

1. Add benchmark function following the existing pattern:
```rust
fn bench_new_feature(c: &mut Criterion) {
    let mut group = c.benchmark_group("New Feature");

    group.bench_function("operation_name", |b| {
        b.iter(|| black_box(operation_to_benchmark()))
    });

    group.finish();
}
```

2. Add the function to the `criterion_group!` macro at the end of the file.

3. For throughput benchmarks, set `group.throughput(Throughput::Bytes(size))`.

## Dependencies

The benchmarks use:
- `criterion` - Benchmarking framework
- `bsv_sdk::primitives` - All cryptographic primitives being measured

## Related Documentation

- `../CLAUDE.md` - Root SDK documentation
- `../src/primitives/CLAUDE.md` - Primitives module documentation
- `../src/primitives/ec/CLAUDE.md` - Elliptic curve module documentation
