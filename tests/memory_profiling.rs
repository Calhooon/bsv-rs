//! Detailed heap analysis tests using dhat profiler.
//!
//! Run with: cargo test --features dhat-profiling memory_profiling -- --nocapture
//!
//! These tests provide detailed heap allocation tracking:
//! - Total allocations per operation
//! - Peak heap usage
//! - Allocation hotspot identification
//!
//! Note: Only one dhat profiler can be active at a time, so tests must run
//! sequentially (--test-threads=1) when using dhat features.

#![cfg(feature = "dhat-profiling")]

use bsv_rs::primitives::bsv::shamir::split_private_key;
use bsv_rs::primitives::ec::PrivateKey;
use bsv_rs::primitives::hash;
use bsv_rs::primitives::symmetric::SymmetricKey;

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

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
