//! The big honest shapes through the streaming reader (bsv-stack-lean, the
//! no-limits program NL-3): the P0-5 deep chain at 1,000, 10,000 and 100,000
//! links and the P0-5c wide BUMP at 8,192 and 16,384 leaves. Each is a valid
//! BEEF and is accepted; nothing is refused for its size or its counts.
//!
//! The chain is read from a source that writes itself link by link
//! (`support/beef_chain.rs`), so the reading holds no BEEF, and it runs on a
//! thread with a 1 MiB stack, the order of a WASM stack in a Worker. The
//! peak memory is measured in `tests/memory_profiling.rs`.
//!
//! The Lean's own rows at these sizes (`lean/BeefOfAnySize/Scenarios.lean`)
//! are replayed with their counts: the elements, the bytes, the steps, the
//! cost model's work and the index's entries.
#![cfg(feature = "transaction")]

#[path = "support/beef_chain.rs"]
mod beef_chain;

use std::collections::HashMap;
use std::io::Read;
use std::time::{Duration, Instant};

use beef_chain::{funding_root, subject, varint, ChainSource, Hash32, HEIGHT};
use bsv_rs::primitives::{sha256, sha256d, to_hex};
use bsv_rs::script::{LockingScript, UnlockingScript};
use bsv_rs::transaction::beef_stream::display_hex;
use bsv_rs::transaction::{
    resume, verify_stream, verify_stream_structure, Beef, BeefStream, Cursor, Element, Kind,
    MerklePath, MerklePathLeaf, Progress, Reason, StreamVerifier, Transaction, TransactionInput,
    TransactionOutput, Verdict,
};

fn headers() -> HashMap<u64, Hash32> {
    HashMap::from([(HEIGHT, funding_root())])
}

fn on_small_stack<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(1 << 20)
        .spawn(f)
        .expect("spawn the thread")
        .join()
        .expect("the thread panicked")
}

// ---------------------------------------------------------------------------
// The P0-5 builder, copied from `tests/beef_deep_chain.rs`
// ---------------------------------------------------------------------------

fn op_true() -> LockingScript {
    LockingScript::from_binary(&[0x51]).expect("OP_TRUE")
}

fn spend(spends: &[(String, u32)], outputs: usize) -> Transaction {
    let mut tx = Transaction::new();
    for (txid, vout) in spends {
        let mut input = TransactionInput::new(txid.clone(), *vout);
        input.unlocking_script = Some(UnlockingScript::new());
        tx.inputs.push(input);
    }
    for _ in 0..outputs {
        tx.outputs
            .push(TransactionOutput::new(beef_chain::SATS, op_true()));
    }
    tx
}

fn funded_beef() -> (Beef, String) {
    let funding = spend(&[("aa".repeat(32), 0)], 2);
    let txid = funding.id();
    let mut beef = Beef::new();
    let bump = beef.merge_bump(MerklePath::from_coinbase_txid(&txid, 800_000));
    beef.merge_raw_tx(funding.to_binary(), Some(bump));
    (beef, txid)
}

fn chain_beef(n: usize) -> (Beef, String) {
    assert!(n >= 1);
    let (mut beef, mut prev) = funded_beef();
    for _ in 1..n {
        let tx = spend(&[(prev, 0)], 1);
        prev = tx.id();
        beef.merge_raw_tx(tx.to_binary(), None);
    }
    (beef, prev)
}

#[test]
fn the_source_writes_the_p0_5_chain() {
    let (mut beef, subject_hex) = chain_beef(50);
    let expected = beef.to_binary();
    let mut written = Vec::new();
    ChainSource::new(50).read_to_end(&mut written).unwrap();
    assert_eq!(to_hex(&written), to_hex(&expected));
    assert_eq!(display_hex(&subject(50)), subject_hex);
    assert!(beef.verify_valid(false).valid);
    assert_eq!(
        verify_stream(ChainSource::new(50), headers(), Some(subject(50))).unwrap(),
        Verdict::Valid {
            subject: Some(subject(50)),
            roots: vec![(HEIGHT, funding_root())]
        }
    );
}

// ---------------------------------------------------------------------------
// The deep chain
// ---------------------------------------------------------------------------

/// The chain of `n` transactions through `verify_stream`, scripts executed,
/// on a 1 MiB stack. Returns the time and the bytes read.
fn read_chain(n: usize) -> (Duration, u64) {
    on_small_stack(move || {
        let tip = subject(n);
        let mut reader = StreamVerifier::new(ChainSource::new(n), headers(), Some(tip));
        let started = Instant::now();
        let verdict = loop {
            if let Progress::Verdict(v) = reader.step().unwrap() {
                break v;
            }
        };
        let elapsed = started.elapsed();
        assert_eq!(
            verdict,
            Verdict::Valid {
                subject: Some(tip),
                roots: vec![(HEIGHT, funding_root())]
            }
        );
        // One step per element: the BUMP and the n transactions.
        assert_eq!(reader.index().steps(), n as u64 + 1);
        // One entry per element and one for the txid the BUMP carries.
        assert_eq!(reader.index().entries(), n as u64 + 2);
        // Every output but the tip's and the funding's second is spent and
        // gone: two outputs of one script byte each, at any depth.
        assert_eq!(reader.index().retained_outputs(), (2, 2));
        let bytes = reader.cursor().offset();
        (elapsed, bytes)
    })
}

#[test]
fn the_deep_chain_is_accepted_at_1_000_10_000_and_100_000_links() {
    let mut per_element = Vec::new();
    for n in [1_000usize, 10_000, 100_000] {
        let (elapsed, bytes) = read_chain(n);
        let each = elapsed.as_secs_f64() * 1e6 / n as f64;
        println!(
            "deep chain N={n} bytes={bytes} verify_stream={:.3}s ({each:.2} us per element)",
            elapsed.as_secs_f64()
        );
        per_element.push(each);
    }
    // Linear: the time per element at 100,000 is the time per element at
    // 1,000, give or take the machine. Ten times over is not linear.
    assert!(
        per_element[2] < per_element[0] * 10.0 + 50.0,
        "the time per element grew: {per_element:?}"
    );
}

#[test]
fn the_deep_chain_resumes_at_three_points() {
    let n = 100_000usize;
    let tip = subject(n);
    let whole = Verdict::Valid {
        subject: Some(tip),
        roots: vec![(HEIGHT, funding_root())],
    };
    for k in [25_000u64, 50_000, 75_000] {
        let stored = on_small_stack(move || {
            let mut reader = StreamVerifier::new(ChainSource::new(n), headers(), Some(tip));
            for _ in 0..k {
                assert_eq!(reader.step().unwrap(), Progress::Stepped);
            }
            reader.cursor().to_binary()
        });
        let cursor = Cursor::from_binary(&stored).unwrap();
        assert_eq!(cursor.elements_read(), k);
        let offset = cursor.offset();
        println!(
            "deep chain N={n} cursor at k={k}: offset {offset}, {} bytes stored",
            stored.len()
        );
        let verdict =
            on_small_stack(move || resume(cursor, ChainSource::from_offset(n, offset), headers()))
                .unwrap();
        assert_eq!(verdict, whole, "k = {k}");
    }
}

// ---------------------------------------------------------------------------
// The Lean's rows at their sizes
// ---------------------------------------------------------------------------

/// The Lean's `chain n`: an anchor with no input and two outputs, proven by a
/// BUMP of height 1 (the anchor at offset 0, the duplicate marker at 1), and
/// `n` links with empty scripts and outputs of one satoshi. V1.
fn lean_chain(n: usize, atomic: bool) -> (Vec<u8>, HashMap<u64, Hash32>) {
    let raw = |prev: Option<&Hash32>, n_out: usize| {
        let mut v = 1u32.to_le_bytes().to_vec();
        match prev {
            Some(prev) => {
                v.push(1);
                v.extend_from_slice(prev);
                v.extend_from_slice(&[0, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF]);
            }
            None => v.push(0),
        }
        v.push(n_out as u8);
        for _ in 0..n_out {
            v.extend_from_slice(&1u64.to_le_bytes());
            v.push(0);
        }
        v.extend_from_slice(&0u32.to_le_bytes());
        v
    };
    let anchor = raw(None, 2);
    let anchor_txid = sha256d(&anchor);
    let mut links = Vec::new();
    let mut prev = anchor_txid;
    for _ in 0..n {
        let link = raw(Some(&prev), 1);
        prev = sha256d(&link);
        links.push(link);
    }
    let mut bytes = Vec::new();
    if atomic {
        bytes.extend_from_slice(&0x0101_0101u32.to_le_bytes());
        bytes.extend_from_slice(&prev);
    }
    bytes.extend_from_slice(&0xEFBE_0001u32.to_le_bytes());
    bytes.push(1);
    bytes.extend(varint(800_000));
    bytes.extend_from_slice(&[1, 2, 0, 2]);
    bytes.extend_from_slice(&anchor_txid);
    bytes.extend_from_slice(&[1, 1]);
    bytes.extend(varint(n as u64 + 1));
    bytes.extend_from_slice(&anchor);
    bytes.extend_from_slice(&[1, 0]);
    for link in &links {
        bytes.extend_from_slice(link);
        bytes.push(0);
    }
    let root = sha256d(&[anchor_txid, anchor_txid].concat());
    (bytes, HashMap::from([(800_000, root)]))
}

/// The Lean's `summary`: elements, element bytes, steps, work, index
/// entries, accepted.
fn summary(bytes: &[u8], headers: &HashMap<u64, Hash32>) -> (u64, u64, u64, u64, u64, bool) {
    let mut elements = 0;
    let mut element_bytes = 0;
    for element in BeefStream::new(bytes) {
        elements += 1;
        element_bytes += element.unwrap().wire_len();
    }
    let mut reader = StreamVerifier::structure_only(bytes, headers, None);
    let verdict = loop {
        if let Progress::Verdict(v) = reader.step().unwrap() {
            break v;
        }
    };
    let index = reader.index();
    (
        elements,
        element_bytes,
        index.steps(),
        index.model_work(),
        index.spec_size(),
        verdict.is_valid(),
    )
}

#[test]
fn the_leans_deep_rows_have_the_leans_counts() {
    // `#eval summary (run stub chainHeaders (chain 100000))`.
    let (bytes, headers) = lean_chain(100_000, false);
    assert_eq!(
        summary(&bytes, &headers),
        (100_002, 6_000_071, 100_002, 6_700_089, 100_004, true)
    );
    // The same at 10,000 links, atomic on the last link.
    let (bytes, headers) = lean_chain(10_000, true);
    assert_eq!(
        summary(&bytes, &headers),
        (10_002, 600_071, 10_002, 680_090, 10_004, true)
    );
}

// ---------------------------------------------------------------------------
// The wide BUMP (the P0-5c builders, copied from `tests/merkle_path_cost.rs`)
// ---------------------------------------------------------------------------

fn leaf_hash(i: u64) -> [u8; 32] {
    sha256(&i.to_le_bytes())
}

fn parent(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut data = [0u8; 64];
    data[..32].copy_from_slice(left);
    data[32..].copy_from_slice(right);
    sha256d(&data)
}

fn display(hash: &[u8; 32]) -> String {
    let mut bytes = *hash;
    bytes.reverse();
    to_hex(&bytes)
}

fn full_tree(k: u32) -> Vec<Vec<[u8; 32]>> {
    let mut levels = vec![(0..1u64 << k).map(leaf_hash).collect::<Vec<_>>()];
    while levels.last().unwrap().len() > 1 {
        let below = levels.last().unwrap();
        let above = below
            .chunks(2)
            .map(|pair| parent(&pair[0], &pair[1]))
            .collect();
        levels.push(above);
    }
    levels
}

fn beef_of_bump(bump: &MerklePath) -> Vec<u8> {
    let mut bytes = 0xEFBE_0001u32.to_le_bytes().to_vec();
    bytes.push(1);
    bytes.extend_from_slice(&bump.to_binary());
    bytes.push(0);
    bytes
}

/// The probe: `2^k` flagged level-0 leaves, tree height `k`, levels 1 to
/// `k - 1` empty. Returns the BEEF and the root (wire order).
fn flat_probe(k: u32) -> (Vec<u8>, Hash32) {
    let tree = full_tree(k);
    let mut path = vec![Vec::new(); k as usize];
    path[0] = tree[0]
        .iter()
        .enumerate()
        .map(|(i, h)| MerklePathLeaf::new_txid(i as u64, display(h)))
        .collect();
    let bump = MerklePath {
        block_height: 800_000,
        path,
    };
    (beef_of_bump(&bump), tree[k as usize][0])
}

fn included(k: u32, count: usize, seed: u64) -> Vec<u64> {
    let mut state = seed;
    let mut chosen = std::collections::BTreeSet::new();
    while chosen.len() < count {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        chosen.insert((state >> 20) % (1u64 << k));
    }
    chosen.into_iter().collect()
}

/// The honest shape: the compound BUMP of `count` transactions out of a block
/// of `2^k`, every needed sibling stored, nothing computable stored.
fn compound_bump(k: u32, count: usize) -> (Vec<u8>, Hash32) {
    let tree = full_tree(k);
    let txs = included(k, count, 0x5c);
    let mut path = Vec::new();
    let mut nodes: std::collections::BTreeSet<u64> = txs.iter().copied().collect();
    for (h, level_hashes) in tree.iter().enumerate().take(k as usize) {
        let mut level = Vec::new();
        let needed: std::collections::BTreeSet<u64> = nodes.iter().map(|o| o ^ 1).collect();
        for o in nodes.union(&needed) {
            let hash = display(&level_hashes[*o as usize]);
            if h == 0 && nodes.contains(o) {
                level.push(MerklePathLeaf::new_txid(*o, hash));
            } else if !nodes.contains(o) {
                level.push(MerklePathLeaf::new(*o, hash));
            }
        }
        path.push(level);
        nodes = nodes.iter().map(|o| o >> 1).collect();
    }
    let bump = MerklePath {
        block_height: 800_000,
        path,
    };
    (beef_of_bump(&bump), tree[k as usize][0])
}

/// RED: the reading of a wide BUMP takes longer than this (the P0-5c bound).
fn bound() -> Duration {
    if cfg!(debug_assertions) {
        Duration::from_secs(10)
    } else {
        Duration::from_secs(1)
    }
}

/// Reads one wide BUMP: accepted when the headers carry its root, refused at
/// the BUMP's offset when they carry another.
fn read_wide(name: &str, leaves: u64, bytes: &[u8], root: Hash32) {
    let carried = HashMap::from([(800_000u64, root)]);
    let started = Instant::now();
    let verdict = verify_stream(bytes, &carried, None).unwrap();
    let elapsed = started.elapsed();
    println!(
        "{name} L={leaves} bytes={} verify_stream={:.3}s",
        bytes.len(),
        elapsed.as_secs_f64()
    );
    assert_eq!(
        verdict,
        Verdict::Valid {
            subject: None,
            roots: vec![(800_000, root)]
        }
    );
    assert!(
        elapsed < bound(),
        "RED: {leaves} leaves read in {elapsed:?}, over {:?}",
        bound()
    );

    let mut other = root;
    other[31] ^= 0x80;
    let wrong = HashMap::from([(800_000u64, other)]);
    assert_eq!(
        verify_stream(bytes, &wrong, None).unwrap(),
        Verdict::Invalid {
            offset: 5,
            kind: Kind::RootNotCarried,
            reason: Reason::RootNotCarried {
                height: 800_000,
                root
            }
        }
    );
}

#[test]
fn the_wide_bump_is_accepted_at_8_192_and_16_384_leaves_when_its_root_checks() {
    for k in [13u32, 14] {
        let (bytes, root) = flat_probe(k);
        read_wide("flat", 1 << k, &bytes, root);
        // The in-memory reader computes the same root.
        let beef = Beef::from_binary(&bytes).unwrap();
        assert_eq!(beef.bumps[0].compute_root(None).unwrap(), display(&root));
    }
    for count in [8_192usize, 16_384] {
        let k = if count == 16_384 { 15 } else { 14 };
        let (bytes, root) = compound_bump(k, count);
        read_wide("compound", count as u64, &bytes, root);
    }
}

#[test]
fn the_leans_wide_row_has_the_leans_counts() {
    // `#eval summary (run stub (wideHeaders 14) (wide 14))`: 16,384 leaves,
    // 589,340 bytes, one step, the index one BUMP entry and two per txid.
    let (bytes, root) = flat_probe(14);
    let carried = HashMap::from([(800_000u64, root)]);
    assert_eq!(
        summary(&bytes, &carried),
        (1, 589_340, 1, 2_031_133, 32_769, true)
    );
    let Some(Ok(Element::Bump(bump))) = BeefStream::new(bytes.as_slice()).next() else {
        panic!("a BUMP leads")
    };
    assert_eq!(bump.proven().count(), 16_384);
    assert!(verify_stream_structure(bytes.as_slice(), &carried, None)
        .unwrap()
        .is_valid());
}
