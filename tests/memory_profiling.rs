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
    // table slot is the txid and its entry; a growing table holds old and new
    // for a moment; under the subject each link also keeps its one edge, 32
    // bytes and the entry's pointer to it, since 0.8.1), and the scripts add nothing that stays (each output goes when
    // spent).
    for (n, _, structure, full) in &rows {
        assert!(*structure < 400.0, "N={n}: {structure} B per element");
        assert!(*full < 400.0, "N={n}: {full} B per element");
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

/// The streaming reader on a BEEF made of proven transactions with many
/// inputs, their parents outside the BEEF (the shape of a BEEF of mined
/// ancestors). The index holds one entry per element; under a subject it
/// also holds, until the end, the txid each input names (0.8.1, the edges
/// the atomic walk follows, the Lean's `prevs`): 32 bytes per input, an
/// input being 41 bytes or more on the wire. Without a subject nothing walks
/// them, and the reader keeps none.
#[cfg(feature = "transaction")]
#[test]
fn test_beef_stream_memory_on_proven_transactions_with_many_inputs() {
    use bsv_rs::primitives::Writer;
    use bsv_rs::script::{LockingScript, UnlockingScript};
    use bsv_rs::transaction::beef_stream::Hash32;
    use bsv_rs::transaction::{
        verify_stream, verify_stream_structure, MerklePath, Transaction, TransactionInput,
        TransactionOutput, ATOMIC_BEEF, BEEF_V1,
    };
    use std::collections::HashMap;

    let _serial = serial();

    fn peak(f: impl FnOnce()) -> u64 {
        let _profiler = dhat::Profiler::builder().testing().build();
        f();
        dhat::HeapStats::get().max_bytes as u64
    }
    fn internal(txid: &str) -> Hash32 {
        let mut h: Hash32 = hex::decode(txid).unwrap().try_into().unwrap();
        h.reverse();
        h
    }

    const TXS: usize = 100;
    const INPUTS: usize = 1_000;
    // TXS proven transactions of INPUTS inputs each, every parent distinct
    // and outside the BEEF; one BUMP (its own block) per transaction.
    let mut bumps = Vec::new();
    let mut raws = Vec::new();
    let mut headers: HashMap<u64, Hash32> = HashMap::new();
    for t in 0..TXS {
        let mut tx = Transaction::new();
        for i in 0..INPUTS {
            let mut input = TransactionInput::new(format!("{:064x}", t * INPUTS + i + 1), 0);
            input.unlocking_script = Some(UnlockingScript::from_binary(&[]).unwrap());
            tx.inputs.push(input);
        }
        tx.outputs.push(TransactionOutput::new(
            1,
            LockingScript::from_binary(&[0x51]).unwrap(),
        ));
        let height = 980_000 + t as u32;
        let bump = MerklePath::from_coinbase_txid(&tx.id(), height);
        headers.insert(
            u64::from(height),
            internal(&bump.compute_root(None).unwrap()),
        );
        bumps.push(bump);
        raws.push(tx.to_binary());
    }
    let mut w = Writer::new();
    w.write_u32_le(BEEF_V1);
    w.write_var_int(TXS as u64);
    for bump in &bumps {
        w.write_bytes(&bump.to_binary());
    }
    w.write_var_int(TXS as u64);
    for (i, raw) in raws.iter().enumerate() {
        w.write_bytes(raw);
        w.write_u8(1);
        w.write_var_int(i as u64);
    }
    let plain = w.into_bytes();
    // The same behind an atomic prefix naming the last transaction (the
    // others are outside its graph: refused, after the whole read).
    let last = Transaction::from_binary(raws.last().unwrap()).unwrap().id();
    let mut atomic = Vec::with_capacity(36 + plain.len());
    atomic.extend_from_slice(&ATOMIC_BEEF.to_le_bytes());
    atomic.extend_from_slice(&internal(&last));
    atomic.extend_from_slice(&plain);

    let structure = peak(|| {
        let v = verify_stream_structure(plain.as_slice(), &headers, None).unwrap();
        assert!(v.is_valid(), "{v:?}");
    });
    let full = peak(|| {
        let v = verify_stream(plain.as_slice(), &headers, None).unwrap();
        assert!(v.is_valid(), "{v:?}");
    });
    let under_subject = peak(|| {
        let v = verify_stream_structure(atomic.as_slice(), &headers, None).unwrap();
        assert!(!v.is_valid(), "{v:?}");
    });
    let inputs = (TXS * INPUTS) as f64;
    let per_input = (under_subject.saturating_sub(structure)) as f64 / inputs;
    println!("\n=== BEEF stream, {TXS} proven transactions of {INPUTS} inputs ===");
    println!(
        "  BEEF {} B; no subject: structure {structure} B, scripts {full} B; \
         under a subject: {under_subject} B ({per_input:.1} B per input, its edge)",
        plain.len()
    );
    // Without a subject: the element in hand (one transaction of INPUTS
    // inputs) and a few entries per element, at any input count: well under
    // the 32 bytes per input the set would cost.
    let element = (raws[0].len() * 4) as u64;
    for (name, bytes) in [("structure", structure), ("scripts", full)] {
        assert!(
            bytes < element + TXS as u64 * 2_048,
            "{name}: {bytes} B with no subject"
        );
    }
    // Under a subject: the edge's 32 bytes per input (in the transaction's
    // entry, no table slot of its own), bounded.
    assert!(
        (28.0..160.0).contains(&per_input),
        "{per_input:.1} B per input, its edge"
    );
}

/// The #749 link bound refuses BEFORE the clone that would cross the budget
/// (rule 5: every refusal of the budget before the allocation it would need).
///
/// A parent of one 1 MiB output spent by many inputs re-materializes one stub
/// clone of that output per repeat. With the budget at 4 MiB, the correct
/// linker retains four clones and refuses on the fifth repeat's check — BEFORE
/// cloning it — so the declined link's peak carries four re-materialized copies.
/// Were the check moved AFTER the clone, the fifth would be cloned before the
/// refusal and the peak would carry five: this test's ceiling sits between the
/// two (4.5 copies), so it is RED if the refusal is moved after the allocation.
/// The gap is a whole 1 MiB stub, and dhat's accounting is exact, so the two
/// orders never tie.
#[cfg(feature = "transaction")]
#[test]
fn test_beef_link_bound_refuses_before_the_allocation() {
    use bsv_rs::script::{LockingScript, UnlockingScript};
    use bsv_rs::transaction::{
        Beef, BeefLinkLimits, MerklePath, Transaction, TransactionInput, TransactionOutput,
    };
    use bsv_rs::Error;

    const STUB: usize = 1024 * 1024; // one 1 MiB output
    const BUDGET: u64 = 4 * 1024 * 1024; // four clones fit; the fifth repeat trips
    const INPUTS: usize = 10; // one full link + nine repeats (the fifth trips)
                              // Measured on this fix: the correct linker (refuse before the clone) peaks
                              // at ~13.0 MiB (four 1 MiB outputs re-materialized, each held as raw cache
                              // plus parsed chunk ≈ 2×, over the answer and the memoized stub); the same
                              // linker with the clone moved before the check peaks at ~15.0 MiB (a fifth
                              // copy). The ceiling of 14 MiB sits between the two, so a reorder is RED.
    const CEILING: u64 = 14 * 1024 * 1024;

    fn peak(f: impl FnOnce()) -> u64 {
        let _profiler = dhat::Profiler::builder().testing().build();
        f();
        dhat::HeapStats::get().max_bytes as u64
    }

    let _serial = serial();

    // Build the BEEF, then drop every temporary but its bytes, so the measured
    // peak is the link's own — not the writers'.
    let bytes = {
        // A single PUSHDATA4 of STUB bytes: one script chunk holding one byte
        // vector, so its heap weight is its wire weight (a run of single-byte
        // opcodes would inflate per opcode and blur the +1-clone gap).
        let mut raw = vec![0x4e];
        raw.extend_from_slice(&u32::try_from(STUB).unwrap().to_le_bytes());
        raw.extend(std::iter::repeat_n(0u8, STUB));
        let big = LockingScript::from_binary(&raw).unwrap();
        let mut parent = Transaction::new();
        {
            let mut i = TransactionInput::new("aa".repeat(32), 0);
            i.unlocking_script = Some(UnlockingScript::new());
            parent.inputs.push(i);
        }
        parent.outputs.push(TransactionOutput::new(1_000, big));
        let ptxid = parent.id();
        let mut beef = Beef::new();
        let bump = beef.merge_bump(MerklePath::from_coinbase_txid(&ptxid, 800_000));
        beef.merge_raw_tx(parent.to_binary(), Some(bump));
        let mut child = Transaction::new();
        for _ in 0..INPUTS {
            let mut i = TransactionInput::new(ptxid.clone(), 0);
            i.unlocking_script = Some(UnlockingScript::new());
            child.inputs.push(i);
        }
        child.outputs.push(TransactionOutput::new(
            1_000,
            LockingScript::from_binary(&[0x51]).unwrap(),
        ));
        beef.merge_raw_tx(child.to_binary(), None);
        beef.to_binary()
    };

    let budget = BeefLinkLimits::default().with_max_link_bytes(Some(BUDGET));
    let declined = peak(|| {
        let err = Transaction::from_beef_with_limits(&bytes, None, &budget)
            .expect_err("over the byte budget");
        assert!(matches!(err, Error::BeefResourceLimit(_)), "{err:?}");
    });
    println!("\n=== #749 link bound, declined-link peak {declined} B; stub {STUB} B, budget {BUDGET} B ===");

    assert!(
        declined < CEILING,
        "the declined link carried an extra re-materialized copy ({declined} B > {CEILING} B): \
         the refusal was moved after the allocation it would need"
    );
}

/// #749 fold2 ruling 2: a SHARED link budget caps the peak heap of several
/// concurrent links against one pool, where independent per-link budgets let it
/// grow with the number of links held at once. Measures k = 2, 3, 5 retained
/// links with and without a shared pool and prints the peaks; asserts the
/// shared pool holds the k = 5 peak at or below the k = 2 peak (bounded by the
/// pool, not by k).
#[cfg(feature = "transaction")]
#[test]
fn test_749_shared_budget_caps_concurrent_peak() {
    use bsv_rs::script::{LockingScript, UnlockingScript};
    use bsv_rs::transaction::{
        Beef, BeefLinkBudget, MerklePath, Transaction, TransactionInput, TransactionOutput,
    };

    const STUB: usize = 1024 * 1024; // one 1 MiB output per parent
    const INPUTS: usize = 9; // one full link + 8 repeats => ~8 MiB re-materialized per link
    const POOL: u64 = 24 * 1024 * 1024; // shared pool: room for ~two links' worth

    // One BEEF: a 1 MiB parent spent by INPUTS inputs of one child.
    let bytes = {
        let mut raw = vec![0x4e];
        raw.extend_from_slice(&u32::try_from(STUB).unwrap().to_le_bytes());
        raw.extend(std::iter::repeat_n(0u8, STUB));
        let big = LockingScript::from_binary(&raw).unwrap();
        let mut parent = Transaction::new();
        let mut i = TransactionInput::new("aa".repeat(32), 0);
        i.unlocking_script = Some(UnlockingScript::new());
        parent.inputs.push(i);
        parent.outputs.push(TransactionOutput::new(1_000, big));
        let ptxid = parent.id();
        let mut beef = Beef::new();
        let bump = beef.merge_bump(MerklePath::from_coinbase_txid(&ptxid, 800_000));
        beef.merge_raw_tx(parent.to_binary(), Some(bump));
        let mut child = Transaction::new();
        for _ in 0..INPUTS {
            let mut i = TransactionInput::new(ptxid.clone(), 0);
            i.unlocking_script = Some(UnlockingScript::new());
            child.inputs.push(i);
        }
        child.outputs.push(TransactionOutput::new(
            1_000,
            LockingScript::from_binary(&[0x51]).unwrap(),
        ));
        beef.merge_raw_tx(child.to_binary(), None);
        beef.to_binary()
    };

    fn peak(f: impl FnOnce()) -> u64 {
        let _profiler = dhat::Profiler::builder().testing().build();
        f();
        dhat::HeapStats::get().max_bytes as u64
    }

    let _serial = serial();
    let mib = |b: u64| b as f64 / (1024.0 * 1024.0);

    println!("\n=== #749 fold2 shared-budget concurrent peak (stub {STUB} B, pool {POOL} B) ===");
    let ks = [2usize, 3, 5];
    let mut without_peaks = Vec::new();
    let mut with_peaks = Vec::new();
    for &k in &ks {
        // Independent per-link budgets: every link admitted, all held at once.
        let without = peak(|| {
            let mut held = Vec::new();
            for _ in 0..k {
                held.push(
                    Transaction::from_beef_with_budget(&bytes, None, &BeefLinkBudget::per_link())
                        .expect("per-link admits each link"),
                );
            }
            std::hint::black_box(&held);
        });
        // One shared pool: links past the pool are refused; the admitted ones held.
        let pool = BeefLinkBudget::shared(POOL);
        let mut held = Vec::new();
        let with = peak(|| {
            for _ in 0..k {
                if let Ok(linked) = Transaction::from_beef_with_budget(&bytes, None, &pool) {
                    held.push(linked);
                }
            }
            std::hint::black_box(&held);
        });
        println!(
            "k={k}: without-shared {:.1} MiB (all {k} held); with-shared {:.1} MiB ({} admitted)",
            mib(without),
            mib(with),
            held.len(),
        );
        without_peaks.push(without);
        with_peaks.push(with);
    }

    // Without a shared budget the peak grows with k; with one, the pool holds it
    // flat — the k=5 peak stays within one per-link link's worth of the k=3 peak
    // (the only growth is one in-flight refused attempt), and far below the
    // k=5 independent-budget peak.
    let per_link_heap = 2 * (INPUTS as u64) * STUB as u64; // generous one-link bound
    assert!(
        with_peaks[2] < without_peaks[2],
        "the shared pool must cap the k=5 peak ({} B) below the independent-budget k=5 peak ({} B)",
        with_peaks[2],
        without_peaks[2],
    );
    assert!(
        with_peaks[2] <= with_peaks[1] + per_link_heap,
        "the shared pool's k=5 peak ({} B) must not grow beyond the k=3 peak ({} B) by more than \
         one in-flight link",
        with_peaks[2],
        with_peaks[1],
    );
    assert!(
        without_peaks[2] > without_peaks[0] + per_link_heap,
        "without a shared budget the k=5 peak ({} B) must grow well past the k=2 peak ({} B)",
        without_peaks[2],
        without_peaks[0],
    );
}

// ============================================================================
// bsv-rs#374 (ported to the stable line, m1118b): the arithmetic room guard
// ============================================================================

/// The guard's own bookkeeping beside its probe (the operands' lengths, a few
/// bytes), with room to spare.
const STEP_SLACK: u64 = 4096;

/// A minimally encoded negative operand of `len` bytes.
fn step_operand(len: usize) -> Vec<u8> {
    let mut bytes = vec![0x5a; len];
    bytes[len - 1] = 0xd5;
    bytes
}

/// The heap's peak past the operands while `opcode` runs on them, measured by
/// dhat. The operands are pushed by the unlocking script, built before the
/// profiler starts, so the peak past their stack copies is the step's own.
fn arith_step_peak(opcode: u8, lens: &[usize]) -> u64 {
    use bsv_rs::script::op::{OP_1, OP_DROP};
    use bsv_rs::script::{LockingScript, Script, Spend, SpendParams, UnlockingScript};

    let mut unlock = Script::new();
    for &len in lens {
        unlock.write_bin(&step_operand(len));
    }
    let mut lock = Script::new();
    lock.write_opcode(opcode)
        .write_opcode(OP_DROP)
        .write_opcode(OP_1);
    let mut spend = Spend::new(SpendParams {
        source_txid: [0u8; 32],
        source_output_index: 0,
        source_satoshis: 1000,
        locking_script: LockingScript::from_script(lock),
        transaction_version: 2,
        other_inputs: vec![],
        outputs: vec![],
        input_index: 0,
        unlocking_script: UnlockingScript::from_script(unlock),
        input_sequence: 0xffff_ffff,
        lock_time: 0,
        memory_limit: None,
        work_limit: None,
    });
    let profiler = dhat::Profiler::new_heap();
    assert_eq!(spend.validate().map_err(|e| e.message), Ok(true));
    let peak = dhat::HeapStats::get().max_bytes as u64;
    drop(profiler);
    peak.saturating_sub(lens.iter().sum::<usize>() as u64)
}

/// Each guarded arithmetic step's measured heap peak is within the room its
/// guard asks of the allocator first (`src/script/spend/arithmetic_room.rs`,
/// `STEP_PEAK_*`): the operands' combined bytes times 8 for `OP_MUL`, 12 for
/// `OP_DIV`/`OP_MOD`, 6 for the linear kinds. The multiples are ceilings
/// measured on THIS line's `BigNumber` arithmetic (higher than the 0.9 line's
/// owned-arithmetic peaks, so the 0.9 line's 6/12/2 are NOT reused): `OP_MUL`
/// where the shorter operand is just over half the longer (~4.9 times the
/// operands), `OP_DIV`/`OP_MOD` a dividend just past a power of two over a
/// small divisor (~7.6 times), the linear kinds ~3.5 times. A step whose peak
/// ever grew past its declared room — so the probe would pass and the real
/// allocation abort — shows here as a failure.
#[test]
fn test_each_arithmetic_steps_peak_is_within_the_room_its_guard_asks() {
    use bsv_rs::script::op::{OP_1ADD, OP_ADD, OP_BIN2NUM, OP_DIV, OP_MOD, OP_MUL};

    let _serial = serial();
    let cases: [(u8, &str, &[usize], u64); 6] = [
        (OP_MUL, "OP_MUL", &[262_144, 144_000], 8),
        (OP_DIV, "OP_DIV", &[2_098_000, 513], 12),
        (OP_MOD, "OP_MOD", &[2_098_000, 513], 12),
        (OP_ADD, "OP_ADD", &[1 << 20, 1 << 20], 6),
        (OP_1ADD, "OP_1ADD", &[1 << 20], 6),
        (OP_BIN2NUM, "OP_BIN2NUM", &[1 << 20], 6),
    ];
    for (opcode, name, lens, multiple) in cases {
        let operands = lens.iter().sum::<usize>() as u64;
        let peak = arith_step_peak(opcode, lens);
        println!(
            "{name} of {lens:?}: the step's peak {peak} bytes, {:.3} times the operands; its guard asks {multiple} times",
            peak as f64 / operands as f64
        );
        assert!(
            peak <= multiple * operands + STEP_SLACK,
            "{name}: a peak of {peak} bytes past the {} its guard asks (the guard would under-reserve)",
            multiple * operands
        );
    }
}
