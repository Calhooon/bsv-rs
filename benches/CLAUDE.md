# Benchmarks
> Performance measurement suite for BSV SDK cryptographic and script operations

## Overview

This module contains Criterion-based benchmarks for measuring the performance of cryptographic primitives and script operations in the BSV SDK. The benchmarks cover hash functions, key operations, signing/verification, encryption, encoding, BSV-specific protocols (Schnorr proofs, Shamir secret sharing, sighash computation), script parsing/serialization, template construction/signing, and script type detection.

## Files

| File | Purpose |
|------|---------|
| `hash_bench.rs` | Standalone hash function benchmarks |
| `primitives_bench.rs` | Comprehensive benchmarks for all primitives (11 groups) |
| `script_bench.rs` | Script parsing, templates, signing, and serialization benchmarks (5 groups) |
| `memory_bench.rs` | Performance benchmarks with RSS memory tracking (4 groups) |

All four are declared as `[[bench]]` in `Cargo.toml` with `harness = false` (Criterion provides its own main).

## Benchmark Groups

### hash_bench.rs

Focused benchmarks for core hash functions on a 36-byte payload:

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

### script_bench.rs

Benchmarks for script parsing, template construction, signing, and serialization, organized into 5 groups:

#### Script Parsing
- `Script::from_hex (P2PKH)` - Parse P2PKH script from hex string
- `Script::from_binary (P2PKH)` - Parse P2PKH script from binary
- `Script::from_asm (P2PKH)` - Parse P2PKH script from ASM string

#### Script Type Detection
- `is_p2pkh` - Detect P2PKH script type
- `is_p2pk` - Detect P2PK script type
- `is_multisig (2-of-3)` - Detect multisig script type

#### Template Lock
- `P2PKH::lock` - Construct P2PKH locking script from pubkey hash
- `P2PK::lock` - Construct P2PK locking script from compressed pubkey
- `Multisig::lock_from_keys (2-of-3)` - Construct 2-of-3 multisig locking script
- `PushDrop::lock (3 fields)` - Construct PushDrop script with 3 data fields

#### Template Sign
- `P2PKH::sign_with_sighash` - Sign P2PKH unlocking script
- `P2PK::sign_with_sighash` - Sign P2PK unlocking script
- `Multisig::sign_with_sighash (2 sigs)` - Sign multisig with 2 keys

#### Script Serialization
- `to_hex (P2PKH)` - Serialize P2PKH script to hex
- `to_binary (P2PKH)` - Serialize P2PKH script to binary
- `to_asm (P2PKH)` - Serialize P2PKH script to ASM
- `to_hex (PushDrop 10 fields)` - Serialize large PushDrop script to hex
- `to_binary (PushDrop 10 fields)` - Serialize large PushDrop script to binary

### memory_bench.rs

Performance benchmarks with RSS (Resident Set Size) memory tracking, organized into 4 groups:

| Benchmark Group | Operations |
|-----------------|------------|
| Memory/Encryption | AES-GCM encrypt/decrypt at 64B, 1KB, 16KB (with throughput) |
| Memory/KeyDerivation | BRC-42 derive_child (with counter-based unique invoice IDs), ECDH shared secret |
| Memory/Shamir | split 3-of-5, split 5-of-10, recover 3-of-5 |
| Memory/Signing | ECDSA sign, ECDSA verify |

These benchmarks provide:
- Standard Criterion timing measurements for performance regression detection
- RSS memory delta tracking printed after each benchmark group via `memory_stats::memory_stats()`
- Cross-platform support (Linux, macOS, Windows)
- Throughput measurements for encryption operations

## Running Benchmarks

```bash
# Run all benchmarks
cargo bench

# Run specific benchmark file
cargo bench --bench primitives_bench
cargo bench --bench hash_bench
cargo bench --bench memory_bench
cargo bench --bench script_bench

# Run specific benchmark group
cargo bench -- "Key Generation"
cargo bench -- "Hashing"
cargo bench -- "Template Lock"

# Run with detailed output
cargo bench -- --verbose

# Save baseline for comparison
cargo bench -- --save-baseline main

# Compare against baseline
cargo bench -- --baseline main
```

## CI Benchmark Regression Detection

The CI workflow performs relative benchmarking on pull requests:

1. Checks out the base branch (main) and runs benchmarks
2. Checks out the PR branch and runs benchmarks
3. Compares results using `critcmp`

This approach cancels out VM noise since both measurements happen on the same machine.

### Local Comparison

To compare benchmarks locally (e.g., before/after a change):

```bash
# Save baseline before changes
cargo bench -- --save-baseline before

# Make changes, then benchmark again
cargo bench -- --save-baseline after

# Compare results
cargo install critcmp
critcmp before after
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

## Memory Profiling (Development)

For detailed heap allocation analysis, use the dhat profiler tests in `tests/memory_profiling.rs`:

```bash
# Run dhat profiling tests (requires dhat-profiling feature)
cargo test --features dhat-profiling memory_profiling -- --nocapture --test-threads=1
```

These tests provide:
- Total allocations per operation
- Peak heap usage
- Bytes allocated per iteration
- Allocation hotspot identification

Covered operations:
- `test_encryption_allocations` - AES-GCM at 5 payload sizes
- `test_key_derivation_allocations` - BRC-42 and ECDH
- `test_shamir_allocations` - Secret sharing splits and recovery
- `test_signing_allocations` - ECDSA sign/verify cycles
- `test_hashing_allocations` - SHA-256 and Hash160

## Dependencies

The benchmarks use:
- `criterion` - Benchmarking framework (with `harness = false`)
- `memory-stats` - Cross-platform RSS memory tracking (memory_bench only)
- `bsv_sdk::primitives` - All cryptographic primitives being measured
- `bsv_sdk::script` - Script parsing, templates (P2PKH, P2PK, Multisig, PushDrop), and serialization

Optional:
- `dhat` - Detailed heap allocation profiling (via `dhat-profiling` feature)

## Related Documentation

- `../CLAUDE.md` - Root SDK documentation
- `../src/primitives/CLAUDE.md` - Primitives module documentation
- `../src/primitives/ec/CLAUDE.md` - Elliptic curve module documentation
- `../src/script/CLAUDE.md` - Script module documentation
- `../src/script/templates/CLAUDE.md` - Script templates documentation
