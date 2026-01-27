//! Lightweight memory benchmarks using RSS tracking.
//!
//! Run benchmarks with: cargo bench --bench memory_bench
//!
//! These benchmarks measure performance while tracking RSS (Resident Set Size)
//! memory usage for key cryptographic operations. Memory stats are printed
//! after each benchmark group.
//!
//! This provides:
//! - Performance timing via Criterion
//! - Memory usage awareness through RSS tracking
//! - Cross-platform support (Linux, macOS, Windows)

use bsv_sdk::primitives::bsv::shamir::split_private_key;
use bsv_sdk::primitives::ec::PrivateKey;
use bsv_sdk::primitives::symmetric::SymmetricKey;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use memory_stats::memory_stats;

/// Get current RSS memory in bytes, or 0 if unavailable
fn current_rss() -> usize {
    memory_stats().map(|s| s.physical_mem).unwrap_or(0)
}

/// Print memory delta for a benchmark
fn print_memory_delta(name: &str, start_rss: usize) {
    let end_rss = current_rss();
    let delta = end_rss.saturating_sub(start_rss);
    if delta > 0 {
        println!("  [Memory] {}: RSS delta = {} KB", name, delta / 1024);
    }
}

// ============================================================================
// AES-GCM Encryption Memory Benchmarks
// ============================================================================

fn bench_encryption_memory(c: &mut Criterion) {
    let mut group = c.benchmark_group("Memory/Encryption");

    let key = SymmetricKey::random();

    // Test different payload sizes
    let sizes: &[usize] = &[64, 1024, 16384];

    for &size in sizes {
        let plaintext = vec![0u8; size];

        group.throughput(Throughput::Bytes(size as u64));

        let start_rss = current_rss();
        group.bench_with_input(
            BenchmarkId::new("aes_gcm_encrypt", format!("{} bytes", size)),
            &plaintext,
            |b, pt| b.iter(|| black_box(&key).encrypt(black_box(pt))),
        );
        print_memory_delta(&format!("encrypt {} bytes", size), start_rss);

        let ciphertext = key.encrypt(&plaintext).unwrap();
        let start_rss = current_rss();
        group.bench_with_input(
            BenchmarkId::new("aes_gcm_decrypt", format!("{} bytes", size)),
            &ciphertext,
            |b, ct| b.iter(|| black_box(&key).decrypt(black_box(ct))),
        );
        print_memory_delta(&format!("decrypt {} bytes", size), start_rss);
    }

    group.finish();
}

// ============================================================================
// Key Derivation Memory Benchmarks
// ============================================================================

fn bench_key_derivation_memory(c: &mut Criterion) {
    let mut group = c.benchmark_group("Memory/KeyDerivation");

    let alice = PrivateKey::random();
    let bob = PrivateKey::random();
    let bob_pub = bob.public_key();

    // BRC-42 key derivation
    let start_rss = current_rss();
    group.bench_function("brc42_derive_child", |b| {
        let mut counter = 0u64;
        b.iter(|| {
            counter += 1;
            let invoice_id = format!("invoice-{}", counter);
            black_box(&alice).derive_child(black_box(&bob_pub), black_box(&invoice_id))
        })
    });
    print_memory_delta("brc42_derive_child", start_rss);

    // ECDH shared secret
    let start_rss = current_rss();
    group.bench_function("ecdh_shared_secret", |b| {
        b.iter(|| black_box(&alice).derive_shared_secret(black_box(&bob_pub)))
    });
    print_memory_delta("ecdh_shared_secret", start_rss);

    group.finish();
}

// ============================================================================
// Shamir Secret Sharing Memory Benchmarks
// ============================================================================

fn bench_shamir_memory(c: &mut Criterion) {
    let mut group = c.benchmark_group("Memory/Shamir");

    let key = PrivateKey::random();

    // 3-of-5 split
    let start_rss = current_rss();
    group.bench_function("split_3_of_5", |b| {
        b.iter(|| split_private_key(black_box(&key), 3, 5))
    });
    print_memory_delta("split_3_of_5", start_rss);

    // 5-of-10 split
    let start_rss = current_rss();
    group.bench_function("split_5_of_10", |b| {
        b.iter(|| split_private_key(black_box(&key), 5, 10))
    });
    print_memory_delta("split_5_of_10", start_rss);

    // Recovery
    let shares = split_private_key(&key, 3, 5).unwrap();
    let start_rss = current_rss();
    group.bench_function("recover_3_of_5", |b| {
        b.iter(|| {
            let subset = bsv_sdk::primitives::bsv::shamir::KeyShares::new(
                shares.points[0..3].to_vec(),
                3,
                shares.integrity.clone(),
            );
            black_box(subset.recover_private_key())
        })
    });
    print_memory_delta("recover_3_of_5", start_rss);

    group.finish();
}

// ============================================================================
// Signing Memory Benchmarks
// ============================================================================

fn bench_signing_memory(c: &mut Criterion) {
    let mut group = c.benchmark_group("Memory/Signing");

    let key = PrivateKey::random();
    let pubkey = key.public_key();
    let msg_hash = bsv_sdk::primitives::hash::sha256(b"benchmark message for signing");

    // ECDSA sign
    let start_rss = current_rss();
    group.bench_function("ecdsa_sign", |b| {
        b.iter(|| black_box(&key).sign(black_box(&msg_hash)))
    });
    print_memory_delta("ecdsa_sign", start_rss);

    // ECDSA verify
    let sig = key.sign(&msg_hash).unwrap();
    let start_rss = current_rss();
    group.bench_function("ecdsa_verify", |b| {
        b.iter(|| black_box(&pubkey).verify(black_box(&msg_hash), black_box(&sig)))
    });
    print_memory_delta("ecdsa_verify", start_rss);

    group.finish();
}

// ============================================================================
// Criterion Groups
// ============================================================================

criterion_group!(
    benches,
    bench_encryption_memory,
    bench_key_derivation_memory,
    bench_shamir_memory,
    bench_signing_memory,
);
criterion_main!(benches);
