//! Detailed heap analysis tests using dhat profiler.
//!
//! Run with: cargo test --features dhat-profiling memory_profiling -- --nocapture
//!
//! These tests provide detailed heap allocation tracking:
//! - Total allocations per operation
//! - Peak heap usage
//! - Allocation hotspot identification
//!
//! Note: Only one dhat profiler can be active at a time (a second one panics), so every test
//! here holds `PROFILER` for its whole body: the target is serial under any `--test-threads`.

#![cfg(feature = "dhat-profiling")]

#[cfg(feature = "transaction")]
#[path = "support/beef_chain.rs"]
mod beef_chain;

use bsv_rs::primitives::bsv::shamir::split_private_key;
use bsv_rs::primitives::ec::PrivateKey;
use bsv_rs::primitives::hash;
use bsv_rs::primitives::symmetric::SymmetricKey;

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

/// The one dhat profiler of this process: a test takes it before it creates a profiler.
static PROFILER: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Waits for the profiler. A test that failed while holding it poisons the lock; the next
/// test still runs alone, so its own result stands.
fn serial() -> std::sync::MutexGuard<'static, ()> {
    PROFILER.lock().unwrap_or_else(|e| e.into_inner())
}

/// Helper to run profiled operations and report stats
#[allow(dead_code)]
fn profile_operation<F>(name: &str, iterations: usize, mut op: F)
where
    F: FnMut(),
{
    let _profiler = dhat::Profiler::new_heap();

    for _ in 0..iterations {
        op();
    }

    let stats = dhat::HeapStats::get();
    println!("\n=== {} ({} iterations) ===", name, iterations);
    println!("  Total allocations: {}", stats.total_blocks);
    println!("  Total bytes allocated: {}", stats.total_bytes);
    println!("  Peak heap bytes: {}", stats.max_bytes);
    println!(
        "  Avg bytes per iteration: {}",
        stats.total_bytes / iterations as u64
    );
}

#[test]
fn test_encryption_allocations() {
    let _serial = serial();
    let key = SymmetricKey::random();

    // Test different payload sizes
    let sizes: &[usize] = &[64, 256, 1024, 4096, 16384];

    for &size in sizes {
        let plaintext = vec![0u8; size];

        let _profiler = dhat::Profiler::new_heap();

        for _ in 0..100 {
            let ciphertext = key.encrypt(&plaintext).unwrap();
            let _ = key.decrypt(&ciphertext).unwrap();
        }

        let stats = dhat::HeapStats::get();
        println!(
            "\n=== AES-GCM Encrypt/Decrypt {} bytes (100 cycles) ===",
            size
        );
        println!("  Total allocations: {}", stats.total_blocks);
        println!("  Total bytes allocated: {}", stats.total_bytes);
        println!("  Peak heap bytes: {}", stats.max_bytes);
        println!("  Avg bytes per cycle: {}", stats.total_bytes / 100);
    }
}

#[test]
fn test_key_derivation_allocations() {
    let _serial = serial();
    let alice = PrivateKey::random();
    let bob = PrivateKey::random();
    let bob_pub = bob.public_key();

    // BRC-42 key derivation
    {
        let _profiler = dhat::Profiler::new_heap();

        for i in 0..100 {
            let invoice_id = format!("invoice-{}", i);
            let _ = alice.derive_child(&bob_pub, &invoice_id);
        }

        let stats = dhat::HeapStats::get();
        println!("\n=== BRC-42 Key Derivation (100 iterations) ===");
        println!("  Total allocations: {}", stats.total_blocks);
        println!("  Total bytes allocated: {}", stats.total_bytes);
        println!("  Peak heap bytes: {}", stats.max_bytes);
        println!("  Avg bytes per derivation: {}", stats.total_bytes / 100);
    }

    // ECDH shared secret
    {
        let _profiler = dhat::Profiler::new_heap();

        for _ in 0..100 {
            let _ = alice.derive_shared_secret(&bob_pub);
        }

        let stats = dhat::HeapStats::get();
        println!("\n=== ECDH Shared Secret (100 iterations) ===");
        println!("  Total allocations: {}", stats.total_blocks);
        println!("  Total bytes allocated: {}", stats.total_bytes);
        println!("  Peak heap bytes: {}", stats.max_bytes);
        println!("  Avg bytes per derivation: {}", stats.total_bytes / 100);
    }
}

#[test]
fn test_shamir_allocations() {
    let _serial = serial();
    let key = PrivateKey::random();

    // 3-of-5 split
    {
        let _profiler = dhat::Profiler::new_heap();

        for _ in 0..50 {
            let _ = split_private_key(&key, 3, 5);
        }

        let stats = dhat::HeapStats::get();
        println!("\n=== Shamir Split 3-of-5 (50 iterations) ===");
        println!("  Total allocations: {}", stats.total_blocks);
        println!("  Total bytes allocated: {}", stats.total_bytes);
        println!("  Peak heap bytes: {}", stats.max_bytes);
        println!("  Avg bytes per split: {}", stats.total_bytes / 50);
    }

    // 5-of-10 split
    {
        let _profiler = dhat::Profiler::new_heap();

        for _ in 0..50 {
            let _ = split_private_key(&key, 5, 10);
        }

        let stats = dhat::HeapStats::get();
        println!("\n=== Shamir Split 5-of-10 (50 iterations) ===");
        println!("  Total allocations: {}", stats.total_blocks);
        println!("  Total bytes allocated: {}", stats.total_bytes);
        println!("  Peak heap bytes: {}", stats.max_bytes);
        println!("  Avg bytes per split: {}", stats.total_bytes / 50);
    }

    // Recovery
    {
        let shares = split_private_key(&key, 3, 5).unwrap();
        let _profiler = dhat::Profiler::new_heap();

        for _ in 0..50 {
            let subset = bsv_rs::primitives::bsv::shamir::KeyShares::new(
                shares.points[0..3].to_vec(),
                3,
                shares.integrity.clone(),
            );
            let _ = subset.recover_private_key();
        }

        let stats = dhat::HeapStats::get();
        println!("\n=== Shamir Recover 3-of-5 (50 iterations) ===");
        println!("  Total allocations: {}", stats.total_blocks);
        println!("  Total bytes allocated: {}", stats.total_bytes);
        println!("  Peak heap bytes: {}", stats.max_bytes);
        println!("  Avg bytes per recovery: {}", stats.total_bytes / 50);
    }
}

#[test]
fn test_signing_allocations() {
    let _serial = serial();
    let key = PrivateKey::random();
    let pubkey = key.public_key();
    let msg_hash = hash::sha256(b"benchmark message for signing");

    // Sign
    {
        let _profiler = dhat::Profiler::new_heap();

        for _ in 0..100 {
            let _ = key.sign(&msg_hash);
        }

        let stats = dhat::HeapStats::get();
        println!("\n=== ECDSA Sign (100 iterations) ===");
        println!("  Total allocations: {}", stats.total_blocks);
        println!("  Total bytes allocated: {}", stats.total_bytes);
        println!("  Peak heap bytes: {}", stats.max_bytes);
        println!("  Avg bytes per sign: {}", stats.total_bytes / 100);
    }

    // Verify
    {
        let sig = key.sign(&msg_hash).unwrap();
        let _profiler = dhat::Profiler::new_heap();

        for _ in 0..100 {
            let _ = pubkey.verify(&msg_hash, &sig);
        }

        let stats = dhat::HeapStats::get();
        println!("\n=== ECDSA Verify (100 iterations) ===");
        println!("  Total allocations: {}", stats.total_blocks);
        println!("  Total bytes allocated: {}", stats.total_bytes);
        println!("  Peak heap bytes: {}", stats.max_bytes);
        println!("  Avg bytes per verify: {}", stats.total_bytes / 100);
    }

    // Full sign+verify cycle
    {
        let _profiler = dhat::Profiler::new_heap();

        for _ in 0..100 {
            let sig = key.sign(&msg_hash).unwrap();
            let _ = pubkey.verify(&msg_hash, &sig);
        }

        let stats = dhat::HeapStats::get();
        println!("\n=== ECDSA Sign+Verify Cycle (100 iterations) ===");
        println!("  Total allocations: {}", stats.total_blocks);
        println!("  Total bytes allocated: {}", stats.total_bytes);
        println!("  Peak heap bytes: {}", stats.max_bytes);
        println!("  Avg bytes per cycle: {}", stats.total_bytes / 100);
    }
}

#[test]
fn test_hashing_allocations() {
    let _serial = serial();
    let data_1kb = vec![0u8; 1024];
    let data_16kb = vec![0u8; 16384];

    // SHA-256 on 1KB
    {
        let _profiler = dhat::Profiler::new_heap();

        for _ in 0..1000 {
            let _ = hash::sha256(&data_1kb);
        }

        let stats = dhat::HeapStats::get();
        println!("\n=== SHA-256 1KB (1000 iterations) ===");
        println!("  Total allocations: {}", stats.total_blocks);
        println!("  Total bytes allocated: {}", stats.total_bytes);
        println!("  Peak heap bytes: {}", stats.max_bytes);
    }

    // SHA-256 on 16KB
    {
        let _profiler = dhat::Profiler::new_heap();

        for _ in 0..100 {
            let _ = hash::sha256(&data_16kb);
        }

        let stats = dhat::HeapStats::get();
        println!("\n=== SHA-256 16KB (100 iterations) ===");
        println!("  Total allocations: {}", stats.total_blocks);
        println!("  Total bytes allocated: {}", stats.total_bytes);
        println!("  Peak heap bytes: {}", stats.max_bytes);
    }

    // Hash160
    {
        let _profiler = dhat::Profiler::new_heap();

        for _ in 0..1000 {
            let _ = hash::hash160(&data_1kb);
        }

        let stats = dhat::HeapStats::get();
        println!("\n=== Hash160 1KB (1000 iterations) ===");
        println!("  Total allocations: {}", stats.total_blocks);
        println!("  Total bytes allocated: {}", stats.total_bytes);
        println!("  Peak heap bytes: {}", stats.max_bytes);
    }
}

/// The streaming BEEF reader holds one element and its index (bsv-stack-lean,
/// the no-limits program NL-3; the Lean's `memory_bounded_per_element`).
///
/// The P0-5 deep chain is read at 1,000, 10,000 and 100,000 links from a
/// source that writes itself link by link, so the heap holds no BEEF and the
/// peak is the reader's own. Three readings at each depth:
///
/// - the stream alone, each element dropped as it is yielded: the peak does
///   not move with the depth at all (one chunk of the source and one
///   element);
/// - the structure verdict and the full verdict (scripts executed, each
///   parent output kept until it is spent): the peak over the stream's is
///   the index, a bounded number of bytes per element at every depth.
#[cfg(feature = "transaction")]
#[test]
fn test_beef_stream_memory_is_flat_per_element() {
    use beef_chain::{funding_root, subject, ChainSource, HEIGHT};
    use bsv_rs::transaction::{verify_stream, verify_stream_structure, BeefStream};
    use std::collections::HashMap;

    let _serial = serial();

    /// The peak heap of `f`, in bytes, counted from an empty profile.
    fn peak(f: impl FnOnce()) -> u64 {
        let _profiler = dhat::Profiler::builder().testing().build();
        f();
        dhat::HeapStats::get().max_bytes as u64
    }

    println!("\n=== BEEF stream, the P0-5 deep chain ===");
    let mut rows = Vec::new();
    for n in [1_000usize, 10_000, 100_000] {
        let tip = subject(n);
        let stream_only = peak(|| {
            let mut elements = 0usize;
            for element in BeefStream::new(ChainSource::new(n)) {
                element.expect("the chain reads");
                elements += 1;
            }
            assert_eq!(elements, n + 1);
        });
        let structure = peak(|| {
            let headers = HashMap::from([(HEIGHT, funding_root())]);
            let verdict = verify_stream_structure(ChainSource::new(n), &headers, Some(tip));
            assert!(verdict.expect("the source does not fail").is_valid());
        });
        let full = peak(|| {
            let headers = HashMap::from([(HEIGHT, funding_root())]);
            let verdict = verify_stream(ChainSource::new(n), &headers, Some(tip));
            assert!(verdict.expect("the source does not fail").is_valid());
        });
        let per = |total: u64| (total - stream_only.min(total)) as f64 / n as f64;
        println!(
            "  N={n}: stream alone {stream_only} B; structure {structure} B ({:.1} B per element); \
             scripts {full} B ({:.1} B per element)",
            per(structure),
            per(full)
        );
        rows.push((n, stream_only, per(structure), per(full)));
    }

    // The stream alone: one chunk and one element, at any depth.
    let (_, first, ..) = rows[0];
    for (n, stream_only, ..) in &rows {
        assert_eq!(
            *stream_only, first,
            "the stream's peak moved with the depth at N={n}"
        );
        assert!(
            *stream_only < 32 * 1024,
            "the stream holds more than a chunk"
        );
    }
    // The verdicts: the index is a bounded number of bytes per element (a
    // table slot is 65 bytes; a growing table holds old and new for a moment),
    // and the scripts add nothing that stays (each output goes when spent).
    for (n, _, structure, full) in &rows {
        assert!(*structure < 320.0, "N={n}: {structure} B per element");
        assert!(*full < 320.0, "N={n}: {full} B per element");
        assert!(
            (*full - *structure).abs() * (*n as f64) < 16.0 * 1024.0,
            "N={n}: the scripts kept {:.0} B more than the structure",
            (*full - *structure) * *n as f64
        );
    }
    // Flat: a hundred times the depth costs no more per element.
    let (_, _, at_1_000, _) = rows[0];
    let (_, _, at_100_000, _) = rows[2];
    assert!(
        at_100_000 <= at_1_000 * 1.25,
        "the bytes per element grew with the depth: {at_1_000} then {at_100_000}"
    );
}
