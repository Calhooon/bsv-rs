//! A stranger's BUMP that costs a parser minutes, a tree height that panics a
//! debug build, and `{:?}` of a linked chain (bsv-stack-lean #57, P0-5c).
//!
//! 1. The parse checks that every level-0 leaf computes the same root. At
//!    0.3.34 each check walked the tree again, scanning each level for the
//!    sibling and recomputing a missing one from level 0, so the cost grew
//!    about five times per doubling of the leaves. Two shapes are timed, the
//!    parse alone (`Beef::from_binary`):
//!    - the probe: a BEEF with no transactions and one BUMP of `L` flagged
//!      level-0 leaves under a tree of height `log2(L)` whose upper levels are
//!      empty, so every internal node is computed;
//!    - the honest shape: a compound BUMP as a block producer writes it, `L`
//!      included transactions out of a block of 2^14, every needed sibling
//!      stored and nothing computable stored.
//!
//!    RED is over 1 s at 8,192 leaves in a release build (10 s in a debug
//!    build); 8,192 leaves of a 2^13 tree is about 16,000 hashes. Set
//!    `BUMP_LEAVES_MAX=16384` to extend the probe, `BUMP_COMPOUND=1024` (a
//!    comma list) to time other counts of the honest shape.
//! 2. A tree-height byte over 64 shifted an offset by 64 or more: a panic in a
//!    debug build, a wrong error in a release one. It must be refused with a
//!    `MerklePathError` naming the height, in both profiles.
//! 3. `format!("{:?}", tx)` of a linked chain printed every ancestor, one
//!    recursion per link; on a 1 MiB thread (the order of a WASM stack) it
//!    aborts. An overflow aborts the process and cannot be caught, so that test
//!    is run alone: `BEEF_DEPTH=<n> cargo test --features transaction --test
//!    merkle_path_cost -- --exact <name>`, the exit code being the observation.
#![cfg(feature = "transaction")]

use std::time::{Duration, Instant};

use bsv_rs::primitives::{sha256, sha256d, to_hex};
use bsv_rs::script::{LockingScript, UnlockingScript};
use bsv_rs::transaction::{
    Beef, MerklePath, MerklePathLeaf, Transaction, TransactionInput, TransactionOutput,
};
use bsv_rs::Error;

/// RED: the parse of 8,192 leaves takes longer than this.
fn parse_bound() -> Duration {
    if cfg!(debug_assertions) {
        Duration::from_secs(10)
    } else {
        Duration::from_secs(1)
    }
}

// ---------------------------------------------------------------------------
// The bytes
// ---------------------------------------------------------------------------

/// A synthetic transaction id, in internal byte order.
fn leaf_hash(i: u64) -> [u8; 32] {
    sha256(&i.to_le_bytes())
}

/// The parent of two nodes, in internal byte order.
fn parent(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut data = [0u8; 64];
    data[..32].copy_from_slice(left);
    data[32..].copy_from_slice(right);
    sha256d(&data)
}

/// A hash in display order (the crate's hex convention for a txid).
fn display(hash: &[u8; 32]) -> String {
    let mut bytes = *hash;
    bytes.reverse();
    to_hex(&bytes)
}

/// Every level of the full tree over `2^k` synthetic leaves, level 0 first.
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

/// A BEEF with no transactions and the one BUMP.
fn beef_of_bump(bump: &MerklePath) -> Vec<u8> {
    let mut bytes = 0xEFBE_0001u32.to_le_bytes().to_vec();
    bytes.push(1);
    bytes.extend_from_slice(&bump.to_binary());
    bytes.push(0);
    bytes
}

/// The probe: `2^k` flagged level-0 leaves, tree height `k`, levels 1 to
/// `k - 1` empty. Returns the BEEF and the root (display order).
fn flat_probe(k: u32) -> (Vec<u8>, String) {
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
    (beef_of_bump(&bump), display(&tree[k as usize][0]))
}

/// `count` distinct indices below `2^k`, from a seeded generator.
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
/// of `2^k`, every needed sibling stored, nothing computable stored. Returns
/// the BEEF, the included txids and the root (display order).
fn compound_bump(k: u32, count: usize) -> (Vec<u8>, Vec<String>, String) {
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
    let txids = txs.iter().map(|i| display(&tree[0][*i as usize])).collect();
    (beef_of_bump(&bump), txids, display(&tree[k as usize][0]))
}

fn time_parse(bytes: &[u8]) -> (Beef, Duration) {
    let started = Instant::now();
    let beef = Beef::from_binary(bytes).expect("the BUMP parses");
    (beef, started.elapsed())
}

// ---------------------------------------------------------------------------
// 1. The parse cost
// ---------------------------------------------------------------------------

#[test]
fn a_flat_bump_of_8192_leaves_parses_in_under_the_bound() {
    let max: u64 = std::env::var("BUMP_LEAVES_MAX")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8192)
        .max(8192);
    let mut at_8192 = None;
    let mut k = 8;
    while (1u64 << k) <= max {
        let (bytes, root) = flat_probe(k);
        let (beef, elapsed) = time_parse(&bytes);
        let leaves = 1u64 << k;
        println!(
            "flat L={leaves} bytes={} parse={:.3}s",
            bytes.len(),
            elapsed.as_secs_f64()
        );
        assert_eq!(beef.bumps[0].compute_root(None).unwrap(), root);
        if leaves == 8192 {
            at_8192 = Some(elapsed);
        }
        k += 1;
    }
    let elapsed = at_8192.unwrap();
    assert!(
        elapsed < parse_bound(),
        "RED: 8,192 flat leaves parsed in {elapsed:?}, over {:?}",
        parse_bound()
    );
}

#[test]
fn a_compound_bump_from_a_block_parses_in_under_the_bound() {
    let counts: Vec<usize> = std::env::var("BUMP_COMPOUND")
        .ok()
        .map(|v| v.split(',').filter_map(|c| c.parse().ok()).collect())
        .unwrap_or_else(|| vec![1024, 8192]);
    for count in counts {
        let (bytes, txids, root) = compound_bump(14, count);
        let (beef, elapsed) = time_parse(&bytes);
        println!(
            "compound L={count} of 2^14 bytes={} parse={:.3}s",
            bytes.len(),
            elapsed.as_secs_f64()
        );
        let bump = &beef.bumps[0];
        for txid in txids.iter().step_by(97) {
            assert_eq!(bump.compute_root(Some(txid)).unwrap(), root);
        }
        if count == 8192 {
            assert!(
                elapsed < parse_bound(),
                "RED: 8,192 of 2^14 parsed in {elapsed:?}, over {:?}",
                parse_bound()
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 2. The tree height
// ---------------------------------------------------------------------------

/// A BUMP of tree height `height`: one txid at offset 0 and its sibling at
/// offset 1 of every level below `stored`, the other levels empty.
fn bump_of_height(height: u8, stored: u8) -> Vec<u8> {
    let mut bytes = vec![0x01, height];
    for level in 0..height {
        if level == 0 {
            bytes.push(if stored > 0 { 2 } else { 1 });
            bytes.extend_from_slice(&[0x00, 0x02]);
            bytes.extend_from_slice(&leaf_hash(0));
            if stored > 0 {
                bytes.extend_from_slice(&[0x01, 0x00]);
                bytes.extend_from_slice(&leaf_hash(1));
            }
        } else if level < stored {
            bytes.extend_from_slice(&[0x01, 0x01, 0x00]);
            bytes.extend_from_slice(&leaf_hash(u64::from(level) + 1));
        } else {
            bytes.push(0);
        }
    }
    bytes
}

#[test]
fn a_tree_height_over_64_is_refused_naming_it() {
    for height in [65u8, 255] {
        let result = MerklePath::from_binary(&bump_of_height(height, 0));
        println!("height {height}: {result:?}");
        match result {
            Err(Error::MerklePathError(message)) => assert!(
                message.contains(&height.to_string()) && message.contains("height"),
                "the refusal names the height: {message}"
            ),
            other => panic!("height {height}: expected a MerklePathError, got {other:?}"),
        }
    }
}

#[test]
fn a_tree_height_of_64_parses() {
    let path = MerklePath::from_binary(&bump_of_height(64, 64)).expect("64 levels parse");
    assert_eq!(path.path.len(), 64);
    let root = path.compute_root(None).unwrap();
    assert_eq!(root.len(), 64);
}

// ---------------------------------------------------------------------------
// 3. `Debug` of a linked chain (the chain builder is P0-5's, copied from
//    tests/beef_deep_chain.rs)
// ---------------------------------------------------------------------------

const SMALL_STACK: usize = 1 << 20;
const BIG_STACK: usize = 1 << 30;
const DEFAULT_DEPTH: usize = 100_000;
const SATS: u64 = 1_000;

fn depth(default: usize) -> usize {
    std::env::var("BEEF_DEPTH")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn on_stack<T: Send + 'static>(
    name: &str,
    size: usize,
    f: impl FnOnce() -> T + Send + 'static,
) -> T {
    std::thread::Builder::new()
        .name(name.to_string())
        .stack_size(size)
        .spawn(f)
        .expect("spawn the thread")
        .join()
        .expect("the thread panicked")
}

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
        tx.outputs.push(TransactionOutput::new(SATS, op_true()));
    }
    tx
}

/// `tx[0]` proven, `tx[i]` spending `tx[i-1]:0` unproven, the subject linked.
/// Returns the subject and its parent's txid.
fn linked_chain(n: usize) -> (Transaction, String) {
    on_stack("set-up", BIG_STACK, move || {
        let funding = spend(&[("aa".repeat(32), 0)], 2);
        let mut prev = funding.id();
        let mut beef = Beef::new();
        let bump = beef.merge_bump(MerklePath::from_coinbase_txid(&prev, 800_000));
        beef.merge_raw_tx(funding.to_binary(), Some(bump));
        let mut parent = prev.clone();
        for _ in 1..n {
            let tx = spend(&[(prev.clone(), 0)], 1);
            parent = prev;
            prev = tx.id();
            beef.merge_raw_tx(tx.to_binary(), None);
        }
        let tx = Transaction::from_beef(&beef.to_binary(), None).expect("the chain links");
        (tx, parent)
    })
}

#[test]
fn debug_of_a_deep_linked_chain_prints_each_source_as_its_txid() {
    let n = depth(DEFAULT_DEPTH);
    let (tx, parent) = linked_chain(n);
    let grandparent = tx.inputs[0]
        .source_transaction
        .as_ref()
        .and_then(|p| p.inputs[0].source_txid.clone())
        .expect("the parent spends the grandparent");
    let (printed, tx) = on_stack("debug", SMALL_STACK, move || {
        let started = Instant::now();
        let printed = format!("{:?}", tx);
        println!(
            "debug: N={n} in {:?}, {} bytes",
            started.elapsed(),
            printed.len()
        );
        (printed, tx)
    });
    assert!(
        printed.contains(&format!("source_transaction: Some({parent:?})")),
        "the linked source prints as its txid: {printed}"
    );
    assert!(
        !printed.contains(&grandparent),
        "the source's own ancestry is not printed"
    );
    assert!(printed.starts_with("Transaction { version: 1, inputs: [TransactionInput {"));
    on_stack("tear-down", BIG_STACK, move || drop(tx));
}
