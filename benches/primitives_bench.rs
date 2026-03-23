//! Comprehensive benchmarks for BSV primitives.
//!
//! Run benchmarks with: cargo bench
//!
//! These benchmarks measure the performance of cryptographic operations
//! across all modules in the BSV primitives library.

use bsv_rs::primitives::bsv::schnorr::Schnorr;
use bsv_rs::primitives::bsv::shamir::split_private_key;
use bsv_rs::primitives::bsv::sighash::{
    compute_sighash, SighashParams, TxInput, TxOutput, SIGHASH_ALL, SIGHASH_FORKID,
};
use bsv_rs::primitives::ec::PrivateKey;
use bsv_rs::primitives::hash;
use bsv_rs::primitives::p256::P256PrivateKey;
use bsv_rs::primitives::symmetric::SymmetricKey;
use bsv_rs::primitives::{from_hex, to_base58, to_hex};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

// ============================================================================
// Key Generation Benchmarks
// ============================================================================

fn bench_key_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("Key Generation");

    group.bench_function("PrivateKey::random", |b| b.iter(PrivateKey::random));

    group.bench_function("P256PrivateKey::random", |b| b.iter(P256PrivateKey::random));

    group.bench_function("SymmetricKey::random", |b| b.iter(SymmetricKey::random));

    // Public key derivation
    let private_key = PrivateKey::random();
    group.bench_function("PrivateKey::public_key", |b| {
        b.iter(|| black_box(&private_key).public_key())
    });

    let p256_private_key = P256PrivateKey::random();
    group.bench_function("P256PrivateKey::public_key", |b| {
        b.iter(|| black_box(&p256_private_key).public_key())
    });

    group.finish();
}

// ============================================================================
// Signing Benchmarks
// ============================================================================

fn bench_signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("Signing");

    // secp256k1 ECDSA signing
    let key = PrivateKey::random();
    let msg_hash = hash::sha256(b"benchmark message for signing");

    group.bench_function("PrivateKey::sign (secp256k1)", |b| {
        b.iter(|| black_box(&key).sign(black_box(&msg_hash)))
    });

    // P-256 ECDSA signing
    let p256_key = P256PrivateKey::random();
    let message = b"benchmark message for signing";

    group.bench_function("P256PrivateKey::sign", |b| {
        b.iter(|| black_box(&p256_key).sign(black_box(message)))
    });

    // Pre-hashed P-256 signing
    let msg_hash_p256 = hash::sha256(message);
    group.bench_function("P256PrivateKey::sign_hash", |b| {
        b.iter(|| black_box(&p256_key).sign_hash(black_box(&msg_hash_p256)))
    });

    group.finish();
}

// ============================================================================
// Verification Benchmarks
// ============================================================================

fn bench_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("Verification");

    // secp256k1 verification
    let key = PrivateKey::random();
    let pubkey = key.public_key();
    let msg_hash = hash::sha256(b"benchmark message for verification");
    let sig = key.sign(&msg_hash).unwrap();

    group.bench_function("PublicKey::verify (secp256k1)", |b| {
        b.iter(|| black_box(&pubkey).verify(black_box(&msg_hash), black_box(&sig)))
    });

    // P-256 verification
    let p256_key = P256PrivateKey::random();
    let p256_pubkey = p256_key.public_key();
    let message = b"benchmark message for verification";
    let p256_sig = p256_key.sign(message);

    group.bench_function("P256PublicKey::verify", |b| {
        b.iter(|| black_box(&p256_pubkey).verify(black_box(message), black_box(&p256_sig)))
    });

    group.finish();
}

// ============================================================================
// Key Derivation Benchmarks
// ============================================================================

fn bench_key_derivation(c: &mut Criterion) {
    let mut group = c.benchmark_group("Key Derivation");

    let alice = PrivateKey::random();
    let bob = PrivateKey::random();
    let bob_pub = bob.public_key();
    let alice_pub = alice.public_key();

    // BRC-42 private key derivation
    group.bench_function("PrivateKey::derive_child", |b| {
        b.iter(|| black_box(&alice).derive_child(black_box(&bob_pub), black_box("invoice-123")))
    });

    // BRC-42 public key derivation
    group.bench_function("PublicKey::derive_child", |b| {
        b.iter(|| black_box(&bob_pub).derive_child(black_box(&alice), black_box("invoice-123")))
    });

    // ECDH shared secret
    group.bench_function("PrivateKey::derive_shared_secret", |b| {
        b.iter(|| black_box(&alice).derive_shared_secret(black_box(&bob_pub)))
    });

    // Scalar multiplication on public key
    let scalar = [0x42u8; 32];
    group.bench_function("PublicKey::mul_scalar", |b| {
        b.iter(|| black_box(&alice_pub).mul_scalar(black_box(&scalar)))
    });

    group.finish();
}

// ============================================================================
// Symmetric Encryption Benchmarks
// ============================================================================

fn bench_symmetric_encryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("Symmetric Encryption");

    let key = SymmetricKey::random();

    // Different payload sizes
    let sizes = [64, 256, 1024, 4096, 16384];

    for size in sizes {
        let plaintext = vec![0u8; size];

        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(
            BenchmarkId::new("encrypt", format!("{} bytes", size)),
            &plaintext,
            |b, pt| b.iter(|| black_box(&key).encrypt(black_box(pt))),
        );

        let ciphertext = key.encrypt(&plaintext).unwrap();
        group.bench_with_input(
            BenchmarkId::new("decrypt", format!("{} bytes", size)),
            &ciphertext,
            |b, ct| b.iter(|| black_box(&key).decrypt(black_box(ct))),
        );
    }

    group.finish();
}

// ============================================================================
// Hash Function Benchmarks
// ============================================================================

fn bench_hashing(c: &mut Criterion) {
    let mut group = c.benchmark_group("Hashing");

    let data = vec![0u8; 1024]; // 1KB

    group.throughput(Throughput::Bytes(1024));

    group.bench_function("sha256 (1KB)", |b| {
        b.iter(|| hash::sha256(black_box(&data)))
    });

    group.bench_function("sha512 (1KB)", |b| {
        b.iter(|| hash::sha512(black_box(&data)))
    });

    group.bench_function("sha256d (1KB)", |b| {
        b.iter(|| hash::sha256d(black_box(&data)))
    });

    group.bench_function("hash160 (1KB)", |b| {
        b.iter(|| hash::hash160(black_box(&data)))
    });

    group.bench_function("ripemd160 (1KB)", |b| {
        b.iter(|| hash::ripemd160(black_box(&data)))
    });

    group.bench_function("sha1 (1KB)", |b| b.iter(|| hash::sha1(black_box(&data))));

    // HMAC benchmarks
    let hmac_key = b"secret key for hmac benchmarking";
    group.bench_function("sha256_hmac (1KB)", |b| {
        b.iter(|| hash::sha256_hmac(black_box(hmac_key), black_box(&data)))
    });

    group.bench_function("sha512_hmac (1KB)", |b| {
        b.iter(|| hash::sha512_hmac(black_box(hmac_key), black_box(&data)))
    });

    group.finish();
}

// ============================================================================
// Encoding Benchmarks
// ============================================================================

fn bench_encoding(c: &mut Criterion) {
    let mut group = c.benchmark_group("Encoding");

    // Create 1KB of data by repeating a pattern
    let mut data = Vec::with_capacity(1024);
    for _ in 0..256 {
        data.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    }

    group.throughput(Throughput::Bytes(1024));

    // Hex encoding
    group.bench_function("to_hex (1KB)", |b| b.iter(|| to_hex(black_box(&data))));

    let hex_str = to_hex(&data);
    group.bench_function("from_hex (1KB)", |b| {
        b.iter(|| from_hex(black_box(&hex_str)))
    });

    // Base58 encoding
    group.bench_function("to_base58 (1KB)", |b| {
        b.iter(|| to_base58(black_box(&data)))
    });

    let b58_str = to_base58(&data);
    group.bench_function("from_base58 (1KB)", |b| {
        b.iter(|| bsv_rs::primitives::from_base58(black_box(&b58_str)))
    });

    group.finish();
}

// ============================================================================
// Schnorr Proof Benchmarks
// ============================================================================

fn bench_schnorr(c: &mut Criterion) {
    let mut group = c.benchmark_group("Schnorr Proofs");

    let alice = PrivateKey::random();
    let bob = PrivateKey::random();
    let shared = alice.derive_shared_secret(&bob.public_key()).unwrap();

    // Proof generation
    group.bench_function("Schnorr::generate_proof", |b| {
        b.iter(|| {
            Schnorr::generate_proof(
                black_box(&alice),
                black_box(&alice.public_key()),
                black_box(&bob.public_key()),
                black_box(&shared),
            )
        })
    });

    // Proof verification
    let proof =
        Schnorr::generate_proof(&alice, &alice.public_key(), &bob.public_key(), &shared).unwrap();

    group.bench_function("Schnorr::verify_proof", |b| {
        b.iter(|| {
            Schnorr::verify_proof(
                black_box(&alice.public_key()),
                black_box(&bob.public_key()),
                black_box(&shared),
                black_box(&proof),
            )
        })
    });

    group.finish();
}

// ============================================================================
// Shamir Secret Sharing Benchmarks
// ============================================================================

fn bench_shamir(c: &mut Criterion) {
    let mut group = c.benchmark_group("Shamir Secret Sharing");

    let key = PrivateKey::random();

    // Split key into shares
    group.bench_function("split_private_key (3 of 5)", |b| {
        b.iter(|| split_private_key(black_box(&key), 3, 5))
    });

    group.bench_function("split_private_key (5 of 10)", |b| {
        b.iter(|| split_private_key(black_box(&key), 5, 10))
    });

    // Recovery
    let shares = split_private_key(&key, 3, 5).unwrap();

    group.bench_function("recover_private_key (3 of 5)", |b| {
        b.iter(|| {
            let subset = bsv_rs::primitives::bsv::shamir::KeyShares::new(
                shares.points[0..3].to_vec(),
                3,
                shares.integrity.clone(),
            );
            black_box(subset.recover_private_key())
        })
    });

    // Backup format conversion
    group.bench_function("to_backup_format", |b| {
        b.iter(|| black_box(&shares).to_backup_format())
    });

    let backup = shares.to_backup_format();
    group.bench_function("from_backup_format", |b| {
        b.iter(|| {
            bsv_rs::primitives::bsv::shamir::KeyShares::from_backup_format(black_box(&backup))
        })
    });

    group.finish();
}

// ============================================================================
// Sighash Benchmarks
// ============================================================================

fn bench_sighash(c: &mut Criterion) {
    let mut group = c.benchmark_group("Sighash");

    // Create a transaction with multiple inputs/outputs
    let inputs: Vec<TxInput> = (0..5)
        .map(|i| TxInput {
            txid: [i as u8; 32],
            output_index: i as u32,
            script: vec![
                0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0xac,
            ], // 25-byte P2PKH script
            sequence: 0xffffffff,
        })
        .collect();

    let outputs: Vec<TxOutput> = (0..5)
        .map(|i| TxOutput {
            satoshis: 50000 * (i + 1) as u64,
            script: vec![
                0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0xac,
            ], // 25-byte P2PKH script
        })
        .collect();

    let subscript = vec![
        0x76, 0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0xac,
    ]; // 25-byte P2PKH script

    let params = SighashParams {
        version: 1,
        inputs: &inputs,
        outputs: &outputs,
        locktime: 0,
        input_index: 0,
        subscript: &subscript,
        satoshis: 100000,
        scope: SIGHASH_ALL | SIGHASH_FORKID,
    };

    group.bench_function("compute_sighash (5 inputs, 5 outputs)", |b| {
        b.iter(|| compute_sighash(black_box(&params)))
    });

    group.finish();
}

// ============================================================================
// WIF and Address Benchmarks
// ============================================================================

fn bench_wif_address(c: &mut Criterion) {
    let mut group = c.benchmark_group("WIF and Address");

    let key = PrivateKey::random();
    let pub_key = key.public_key();

    // WIF encoding/decoding
    group.bench_function("PrivateKey::to_wif", |b| {
        b.iter(|| black_box(&key).to_wif())
    });

    let wif = key.to_wif();
    group.bench_function("PrivateKey::from_wif", |b| {
        b.iter(|| PrivateKey::from_wif(black_box(&wif)))
    });

    // Address generation
    group.bench_function("PublicKey::to_address", |b| {
        b.iter(|| black_box(&pub_key).to_address())
    });

    // Hash160 (used in address generation)
    group.bench_function("PublicKey::hash160", |b| {
        b.iter(|| black_box(&pub_key).hash160())
    });

    group.finish();
}

// ============================================================================
// Criterion Groups
// ============================================================================

criterion_group!(
    benches,
    bench_key_generation,
    bench_signing,
    bench_verification,
    bench_key_derivation,
    bench_symmetric_encryption,
    bench_hashing,
    bench_encoding,
    bench_schnorr,
    bench_shamir,
    bench_sighash,
    bench_wif_address,
);
criterion_main!(benches);
