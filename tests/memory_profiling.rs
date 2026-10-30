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

/// The deep chain written newest first, the proven funding transaction last
/// (bsv-rs#240): every unproven link is read ahead of its parent and held
/// until the funding transaction arrives. A held link is held by its index
/// entry, never its raw bytes: its txid and offset; per input the outpoint,
/// the sequence and the input's offset; with spends checked, the unlocking
/// script, the version, the lock time and the outputs (the index retains
/// every output in one pass, and the original digest of a CHRONICLE-bit
/// signature hashes them after the scriptCode the parent supplies). The
/// whole-BEEF reader's judge holds the same entry beside the `Beef` it
/// collects, an index into the bytes the `Beef` already holds, never a
/// second copy of them.
///
/// `BEEF_REVERSED_DEPTHS` (comma-separated) replaces the depths measured
/// (CHANGELOG 0.9.0's numbers: `10000,100000,1000000`).
#[cfg(feature = "transaction")]
#[test]
fn test_beef_stream_memory_on_a_reversed_chain() {
    use beef_chain::{funding, funding_root, spend, varint, ChainSource, HEIGHT};
    use bsv_rs::primitives::sha256d;
    use bsv_rs::transaction::{verify_stream, verify_stream_structure, Beef};
    use std::collections::HashMap;
    use std::io::Read;
    use std::time::Instant;

    let _serial = serial();

    fn peak(f: impl FnOnce()) -> u64 {
        let _profiler = dhat::Profiler::builder().testing().build();
        f();
        dhat::HeapStats::get().max_bytes as u64
    }
    /// The chain of `n` written newest first: V2, the funding BUMP, the
    /// unproven links, then the funding transaction under BUMP 0.
    fn reversed(n: usize) -> Vec<u8> {
        let mut raws = Vec::with_capacity(n - 1);
        let mut prev = funding_root();
        for _ in 1..n {
            let raw = spend(&prev, 1);
            prev = sha256d(&raw);
            raws.push(raw);
        }
        let mut bytes = 0xEFBE_0002u32.to_le_bytes().to_vec();
        bytes.push(1);
        bytes.extend(varint(HEIGHT));
        bytes.extend_from_slice(&[1, 1, 0, 2]);
        bytes.extend_from_slice(&funding_root());
        bytes.extend(varint(n as u64));
        for raw in raws.iter().rev() {
            bytes.push(0);
            bytes.extend_from_slice(raw);
        }
        bytes.extend_from_slice(&[1, 0]);
        bytes.extend_from_slice(&funding());
        bytes
    }

    let depths: Vec<usize> = std::env::var("BEEF_REVERSED_DEPTHS")
        .map(|v| v.split(',').map(|d| d.trim().parse().unwrap()).collect())
        .unwrap_or_else(|_| vec![10_000]);
    let headers = HashMap::from([(HEIGHT, funding_root())]);
    println!("\n=== BEEF readers on the deep chain, parents first and newest first ===");
    let mut rows = Vec::new();
    for n in depths {
        let mut ordered = Vec::new();
        ChainSource::new(n).read_to_end(&mut ordered).unwrap();
        let newest_first = reversed(n);
        assert_eq!(ordered.len(), newest_first.len());
        let mut row = Vec::new();
        for (what, bytes) in [("parents first", &ordered), ("newest first", &newest_first)] {
            let t = Instant::now();
            let structure = peak(|| {
                let v = verify_stream_structure(bytes.as_slice(), &headers, None).unwrap();
                assert!(v.is_valid(), "{what}: {v:?}");
            });
            let t_structure = t.elapsed();
            let t = Instant::now();
            let scripts = peak(|| {
                let v = verify_stream(bytes.as_slice(), &headers, None).unwrap();
                assert!(v.is_valid(), "{what}: {v:?}");
            });
            let t_scripts = t.elapsed();
            let t = Instant::now();
            let whole = peak(|| {
                let mut beef = Beef::from_binary(bytes).unwrap();
                assert!(beef.verify_structure().is_ok(), "{what}");
            });
            let t_whole = t.elapsed();
            println!(
                "  N={n} {what} ({} B): stream structure {structure} B in {t_structure:?}, \
                 stream scripts {scripts} B in {t_scripts:?}, whole path {whole} B in {t_whole:?}",
                bytes.len()
            );
            row.push((structure, scripts, whole));
        }
        rows.push((n, row[0], row[1]));
    }
    for (n, (s0, f0, w0), (s1, f1, w1)) in rows {
        let held = (n - 1) as f64;
        let per = |reversed: u64, ordered: u64| reversed.saturating_sub(ordered) as f64 / held;
        let (structure, scripts, whole) = (per(s1, s0), per(f1, f0), per(w1, w0));
        println!(
            "  N={n}: held per link over parents first: structure {structure:.1} B, \
             scripts {scripts:.1} B, whole path {whole:.1} B (a link is {} B on the wire)",
            spend(&[0; 32], 1).len()
        );
        // The entry: 56 bytes for the txid, the offset and the wire length,
        // 48 for the one input; with spends checked 8 for the version and
        // the lock time, the empty unlock and the one output's 16 bytes and
        // its script; and the tables beside it (the held set by offset, the
        // txid waited on, the count). Holding the element as read (its raw
        // bytes and the places of its fields, 0.9.0-beta's earlier fold) was
        // 321 to 349 bytes a link.
        assert!(structure < 250.0, "N={n}: {structure:.1} B per held link");
        assert!(scripts < 290.0, "N={n}: {scripts:.1} B per held link");
        // The whole path's judge holds the entry, not a second copy of the
        // bytes the `Beef` holds: the peak is the parents-first peak.
        assert!(whole < 64.0, "N={n}: {whole:.1} B per held link");
    }
}

/// `HttpWalletJson` reads a createAction answer's `tx` in the array form at
/// the cost of the typed reading (#339): the byte reader's `Value` tree
/// (about 32 bytes a byte, 48 MB at its peak for a 1 MiB `tx`, the second
/// fold's) is built only for an answer the typed reading refuses (the
/// historical object form, a byte written `1.0`). The peak counts the
/// mock's copy of the body and the client's: the 1 MiB `tx` is about
/// 3.6 MB of text.
#[cfg(all(feature = "wallet", feature = "http"))]
#[test]
fn test_http_json_success_tx_in_the_array_form_costs_the_typed_reading() {
    use bsv_rs::wallet::substrates::HttpWalletJson;
    use bsv_rs::wallet::CreateActionArgs;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let _serial = serial();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    // Row R28 (#432) refuses a `tx` that is not a complete, exactly framed
    // BEEF transaction, and the evidence row asks every input of a completed
    // transaction for its source: the answer is a real transaction of 1 MiB
    // framed as the reference's atomic BEEF with its own txid, spending one
    // output of a proven funding transaction (the one transaction of its
    // block, as `examples/transaction.rs` builds it) into one OP_FALSE
    // OP_RETURN output pushing 1 MiB of `i % 256`.
    let (txid, tx) = {
        use bsv_rs::script::{LockingScript, UnlockingScript};
        use bsv_rs::transaction::{MerklePath, Transaction, TransactionInput, TransactionOutput};
        let mut funding = Transaction::new();
        let mut mined = TransactionInput::new("11".repeat(32), 0);
        mined.unlocking_script = Some(UnlockingScript::new());
        funding.add_input(mined).unwrap();
        funding
            .add_output(TransactionOutput::new(
                1_000,
                LockingScript::from_binary(&[0x51]).unwrap(),
            ))
            .unwrap();
        let funding_txid = funding.id();
        funding.merkle_path = Some(MerklePath::from_coinbase_txid(&funding_txid, 800_000));
        let mut spend = Transaction::new();
        let mut input = TransactionInput::with_source_transaction(funding, 0);
        input.unlocking_script = Some(UnlockingScript::new());
        spend.add_input(input).unwrap();
        let mut script = vec![0x00, 0x6a, 0x4e];
        script.extend_from_slice(&(1u32 << 20).to_le_bytes());
        script.extend((0..1usize << 20).map(|i| (i % 256) as u8));
        spend
            .add_output(TransactionOutput::new(
                0,
                LockingScript::from_binary(&script).unwrap(),
            ))
            .unwrap();
        (spend.id(), spend.to_atomic_beef(true).unwrap())
    };
    let answer = |tx: serde_json::Value| {
        serde_json::to_vec(&serde_json::json!({ "txid": txid, "tx": tx })).unwrap()
    };
    let array = answer(serde_json::json!(tx));
    let object = answer(serde_json::Value::Object(
        tx.iter()
            .enumerate()
            .map(|(i, b)| (i.to_string(), serde_json::json!(b)))
            .collect(),
    ));

    let peak = |body: &[u8]| -> u64 {
        runtime.block_on(async {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/createAction"))
                .respond_with(
                    ResponseTemplate::new(200).set_body_raw(body.to_vec(), "application/json"),
                )
                .mount(&server)
                .await;
            let wallet =
                HttpWalletJson::new(Some("example.com".into()), Some(server.uri())).unwrap();
            let args: CreateActionArgs =
                serde_json::from_value(serde_json::json!({ "description": "a 1 MiB tx" })).unwrap();
            let _profiler = dhat::Profiler::builder().testing().build();
            let result = wallet.create_action(args, None).await.unwrap();
            assert_eq!(result.tx.as_deref(), Some(&tx[..]));
            dhat::HeapStats::get().max_bytes as u64
        })
    };

    println!("\n=== HttpWalletJson, a createAction answer's 1 MiB tx ===");
    let array_peak = peak(&array);
    println!(
        "  array form ({} B of text): peak {array_peak} B",
        array.len()
    );
    let object_peak = peak(&object);
    println!(
        "  object form ({} B of text): peak {object_peak} B",
        object.len()
    );
    // The body's text twice (the mock's copy and the client's) and the
    // bytes read, with room for the client's buffers; the `Value` tree is
    // more than four times the text.
    assert!(
        array_peak < 4 * array.len() as u64,
        "array form: peak {array_peak} B for {} B of text",
        array.len()
    );
}

/// An executed push copies its bytes once, onto the stack (bsv-rs#331, the review of PR
/// #370's third note): each step cloned its chunk, the push's data with it, before the
/// fallible copy, an infallible allocation the size of the element that doubled the push's
/// peak. The spend is built before the profiler starts, so the peak is the evaluation's:
/// one 8,000,000-byte copy, not two.
#[test]
fn test_an_executed_push_copies_its_bytes_once() {
    use bsv_rs::script::op::{OP_1, OP_DROP};
    use bsv_rs::script::{LockingScript, Script, Spend, SpendParams, UnlockingScript};

    const ELEMENT: usize = 8_000_000;
    let _serial = serial();
    let mut unlock = Script::new();
    unlock.write_bin(&vec![0x01; ELEMENT]);
    let mut lock = Script::new();
    lock.write_opcode(OP_DROP).write_opcode(OP_1);
    let mut spend = Spend::new(SpendParams {
        source_txid: [0u8; 32],
        source_output_index: 0,
        source_satoshis: 1000,
        locking_script: LockingScript::from_script(lock),
        transaction_version: 1,
        other_inputs: vec![],
        outputs: vec![],
        input_index: 0,
        unlocking_script: UnlockingScript::from_script(unlock),
        input_sequence: 0xffff_ffff,
        lock_time: 0,
        memory_limit: None,
        work_limit: None,
    });
    let _profiler = dhat::Profiler::builder().testing().build();
    assert_eq!(spend.validate().map_err(|e| e.message), Ok(true));
    let peak = dhat::HeapStats::get().max_bytes;
    println!("\n=== an 8,000,000-byte push: peak {peak} bytes ===");
    assert!(
        (ELEMENT..ELEMENT + ELEMENT / 2).contains(&peak),
        "the evaluation's peak: {peak} bytes for a {ELEMENT}-byte push"
    );
}

/// #374: the guard's own bookkeeping beside its probe (the operands' lengths and
/// bits, 128 bytes for two), with room to spare.
const STEP_SLACK: u64 = 4096;

/// An operand of `len` bytes, negative, its magnitude `8 * len - 2` bits.
fn step_operand(len: usize) -> Vec<u8> {
    let mut bytes = vec![0x5a; len];
    bytes[len - 1] = 0xd5;
    bytes
}

/// The heap's peak past the operands while `opcode` runs on them.
fn step_peak(opcode: u8, lens: &[usize]) -> u64 {
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
    let profiler = dhat::Profiler::builder().testing().build();
    assert_eq!(spend.validate().map_err(|e| e.message), Ok(true));
    let peak = dhat::HeapStats::get().max_bytes as u64;
    drop(profiler);
    peak.saturating_sub(lens.iter().sum::<usize>() as u64)
}

/// An arithmetic step's peak of the heap against the room its guard asks of
/// the allocator first (bsv-rs#374, the review of PR #370's fold 2): the
/// operands' bytes times 6 for `OP_MUL`, 12 for `OP_DIV` and `OP_MOD`, 2 for
/// the rest (`src/script/spend/arithmetic_room.rs`, `STEP_PEAK_*`). Each case
/// is the worst shape found for its opcode: `OP_MUL` where the shorter operand
/// is just over half the longer (5.1 times the operands), `OP_DIV` a dividend
/// just past a power of two of digits over a divisor just past
/// Burnikel-Ziegler's 64 digits (10.0 times). The operands are pushed by the
/// unlocking script, built before the profiler starts, so the peak past the
/// operands' stack copies is the step's own: the guard's probe (the declared
/// room, held and released before the arithmetic, beside the guard's few
/// bytes of bookkeeping, `STEP_SLACK`) or the arithmetic after it, whichever
/// is higher. A step that passed its declared room would show here.
#[test]
fn test_each_arithmetic_steps_peak_is_within_the_room_its_guard_asks() {
    use bsv_rs::script::op::{OP_1ADD, OP_ADD, OP_DIV, OP_MOD, OP_MUL};

    let _serial = serial();
    let cases: [(u8, &str, &[usize], u64); 5] = [
        (OP_MUL, "OP_MUL", &[262_144, 131_098], 6),
        (OP_DIV, "OP_DIV", &[2_098_000, 513], 12),
        (OP_MOD, "OP_MOD", &[2_098_000, 513], 12),
        (OP_ADD, "OP_ADD", &[1 << 20, 1 << 20], 2),
        (OP_1ADD, "OP_1ADD", &[1 << 20], 2),
    ];
    for (opcode, name, lens, multiple) in cases {
        let operands = lens.iter().sum::<usize>() as u64;
        let peak = step_peak(opcode, lens);
        println!(
            "{name} of {lens:?}: the step's peak {peak} bytes, {:.3} times the operands; its guard asks {multiple} times",
            peak as f64 / operands as f64
        );
        assert!(
            peak <= multiple * operands + STEP_SLACK,
            "{name}: a peak of {peak} bytes past the {} its guard asks",
            multiple * operands
        );
    }
}

/// A minimal splice operand past 8 bytes is not decoded (bsv-rs#382, the cold review's
/// finding): the default mode reads its first 8 bytes (`ts-stack@edf6e03`
/// `Spend.ts:540-561`) and under MINIMALDATA judges its minimality from its last two bytes,
/// where the check decoded the whole operand, a second copy of it with no #374 room check.
/// A 64 MiB minimal `OP_LEFT` length (its first 8 bytes zero, its last `01`), the spend built
/// before the profiler starts: the peak is the operand's one copy onto the stack and 99 bytes
/// (67,108,963), where the decode made it 134,217,827. Until bsv-rs#401 the operand was
/// 800,000,000 bytes (800,000,099 and 1,600,000,099), about 4 GB resident for one proof
/// this size gives at a twelfth.
#[test]
fn test_issue_382_a_minimal_splice_operand_is_not_decoded() {
    use bsv_rs::script::{LockingScript, Spend, SpendParams, UnlockingScript};

    const OPERAND: usize = 64 << 20;
    let _serial = serial();
    // `aabbcc`, then an OP_PUSHDATA4 of the operand
    let mut unlock = vec![0x03, 0xaa, 0xbb, 0xcc, 0x4e];
    unlock.extend_from_slice(&(OPERAND as u32).to_le_bytes());
    unlock.resize(unlock.len() + OPERAND, 0);
    *unlock.last_mut().unwrap() = 0x01;
    let unlocking_script = UnlockingScript::from_binary(&unlock).unwrap();
    drop(unlock);
    let mut spend = Spend::new(SpendParams {
        source_txid: [0u8; 32],
        source_output_index: 0,
        source_satoshis: 1,
        // OP_LEFT OP_0 OP_EQUAL: the data's first 0 bytes are empty
        locking_script: LockingScript::from_binary(&[0xb4, 0x00, 0x87]).unwrap(),
        transaction_version: 1,
        other_inputs: vec![],
        outputs: vec![],
        input_index: 0,
        unlocking_script,
        input_sequence: 0xffff_ffff,
        lock_time: 0,
        memory_limit: None,
        work_limit: None,
    });
    // version 1 holds MINIMALDATA; the coin post-Chronicle runs 0xb4 as OP_LEFT
    spend.set_utxo_after_chronicle(true);
    let _profiler = dhat::Profiler::builder().testing().build();
    assert_eq!(spend.validate().map_err(|e| e.message), Ok(true));
    let peak = dhat::HeapStats::get().max_bytes;
    println!("\n=== an {OPERAND}-byte minimal OP_LEFT length: peak {peak} bytes ===");
    assert!(
        (OPERAND..OPERAND + (1 << 20)).contains(&peak),
        "the evaluation's peak: {peak} bytes for a {OPERAND}-byte operand (decoded past one copy)"
    );
}
