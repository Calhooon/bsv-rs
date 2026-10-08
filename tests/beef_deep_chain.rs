//! A stranger's BEEF that is one long chain of unproven transactions
//! (bsv-stack-lean #57, P0-5).
//!
//! `tx[0]` carries a BUMP and every `tx[i]` spends `tx[i-1]:0` unproven, so the
//! subject's ancestry is `N - 1` links deep. Each walk over it runs ALONE on a
//! thread with a 1 MiB stack, the order of a WASM stack in a Worker: the parse
//! and link (`from_beef`, `from_atomic_beef`), `Beef::verify_valid`, the
//! serializers (`to_beef`, `to_atomic_beef`), `verify`, `Clone`, `Drop`, the
//! overlay's historians, and `id()` of a chain built by `add_input_from_tx`.
//! Whatever a test needs before or after its walk (building the chain, linking
//! it, dropping it) runs on a 1 GiB thread, so a test names exactly one walk.
//!
//! A walk that recurses once per link overflows the 1 MiB stack, and an
//! overflow aborts the process (it is not a panic and cannot be caught), so
//! each depth is probed in its own `cargo test` invocation:
//! `BEEF_DEPTH=<n> cargo test --features transaction --test beef_deep_chain --
//! --exact <name>`, the exit code being the observation.
//!
//! The scripts are `OP_TRUE` locks spent by empty unlocks, so `verify` executes
//! a real script per link without signing a hundred thousand transactions.
#![cfg(feature = "transaction")]

use std::time::{Duration, Instant};

use bsv_rs::script::{LockingScript, UnlockingScript};
use bsv_rs::transaction::{
    Beef, MerklePath, MockChainTracker, Transaction, TransactionInput, TransactionOutput,
};

/// The stack every walk under test runs on: 1 MiB.
const SMALL_STACK: usize = 1 << 20;

/// The stack the set-up and tear-down run on: 1 GiB, reserved, not touched.
const BIG_STACK: usize = 1 << 30;

/// The default depth: the brief's 100,000 chained transactions.
const DEFAULT_DEPTH: usize = 100_000;

const SATS: u64 = 1_000;

/// `BEEF_DEPTH` from the environment, else `default`.
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

/// Runs the walk under test on a fresh 1 MiB thread and returns its value
/// with the time the walk took.
fn on_small_stack<T: Send + 'static>(
    name: &str,
    f: impl FnOnce() -> T + Send + 'static,
) -> (T, Duration) {
    on_stack(name, SMALL_STACK, move || {
        let started = Instant::now();
        let value = f();
        (value, started.elapsed())
    })
}

/// Runs set-up or tear-down on a fresh 1 GiB thread.
fn on_big_stack<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    on_stack("set-up", BIG_STACK, f)
}

fn op_true() -> LockingScript {
    LockingScript::from_binary(&[0x51]).expect("OP_TRUE")
}

/// A transaction spending each of `spends` with an empty unlock, paying
/// `outputs` OP_TRUE outputs of `SATS` each.
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

/// The proven funding transaction and its BEEF.
fn funded_beef() -> (Beef, String) {
    let funding = spend(&[("aa".repeat(32), 0)], 2);
    let txid = funding.id();
    let mut beef = Beef::new();
    let bump = beef.merge_bump(MerklePath::from_coinbase_txid(&txid, 800_000));
    beef.merge_raw_tx(funding.to_binary(), Some(bump));
    (beef, txid)
}

/// A BEEF of `n` transactions: `tx[0]` proven, `tx[i]` spending `tx[i-1]:0`
/// unproven. Returns the BEEF, in dependency order, and the subject's txid.
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

/// A diamond of `levels` unproven levels over one proven funding transaction:
/// each level spends both outputs of the level below it (a wallet's change
/// chain, the 0.3.21 regression's shape).
fn diamond_beef(levels: usize) -> (Beef, String) {
    let (mut beef, mut prev) = funded_beef();
    for _ in 0..levels {
        let tx = spend(&[(prev.clone(), 0), (prev, 1)], 2);
        prev = tx.id();
        beef.merge_raw_tx(tx.to_binary(), None);
    }
    (beef, prev)
}

/// The BEEF's bytes in dependency order (oldest first).
fn chain_bytes(n: usize) -> (Vec<u8>, String) {
    let (mut beef, subject) = chain_beef(n);
    (beef.to_binary(), subject)
}

/// The subject of an `n`-deep chain, parsed and linked on the 1 GiB thread.
fn linked_chain(n: usize) -> Transaction {
    on_big_stack(move || {
        let (bytes, _) = chain_bytes(n);
        Transaction::from_beef(&bytes, None).expect("the chain parses and links")
    })
}

/// Drops `value` on the 1 GiB thread.
fn drop_on_big_stack<T: Send + 'static>(value: T) {
    on_big_stack(move || drop(value));
}

/// Walks input 0's `source_transaction` links from `tx` without recursion and
/// returns how many there are and whether the deepest carries a merkle path.
fn linked_depth(tx: &Transaction) -> (usize, bool) {
    let mut links = 0;
    let mut current = tx;
    while let Some(source) = current
        .inputs
        .first()
        .and_then(|i| i.source_transaction.as_deref())
    {
        links += 1;
        current = source;
    }
    (links, current.merkle_path.is_some())
}

#[test]
fn a_deep_chain_links_through_from_beef_on_a_small_stack() {
    let n = depth(DEFAULT_DEPTH);
    let (bytes, subject) = chain_bytes(n);
    let (tx, elapsed) = on_small_stack("from_beef", move || {
        Transaction::from_beef(&bytes, None).expect("the chain parses and links")
    });
    println!("from_beef: N={n} in {elapsed:?}");
    let (links, proven) = linked_depth(&tx);
    assert_eq!(tx.id(), subject);
    assert_eq!(links, n - 1, "every unproven ancestor is linked");
    assert!(proven, "the root of the chain carries its BUMP");
    drop_on_big_stack(tx);
}

#[test]
fn a_deep_chain_links_through_from_atomic_beef_on_a_small_stack() {
    let n = depth(DEFAULT_DEPTH);
    let (mut beef, subject) = chain_beef(n);
    let bytes = beef.to_binary_atomic(&subject).expect("atomic bytes");
    let (tx, elapsed) = on_small_stack("from_atomic_beef", move || {
        Transaction::from_atomic_beef(&bytes).expect("the chain parses and links")
    });
    println!("from_atomic_beef: N={n} in {elapsed:?}");
    let (links, proven) = linked_depth(&tx);
    assert_eq!(tx.id(), subject);
    assert_eq!(links, n - 1);
    assert!(proven);
    drop_on_big_stack(tx);
}

#[test]
fn a_deep_chain_verify_valid_on_a_small_stack() {
    let n = depth(DEFAULT_DEPTH);
    let (bytes, _) = chain_bytes(n);
    let ((valid, txs), elapsed) = on_small_stack("verify_valid", move || {
        let mut beef = Beef::from_binary(&bytes).expect("the chain parses");
        (beef.verify_valid(false).valid, beef.txs.len())
    });
    println!("verify_valid: N={n} valid={valid} in {elapsed:?}");
    assert!(
        valid,
        "a complete chain over a proven root is structurally valid"
    );
    assert_eq!(txs, n);
}

#[test]
fn a_deep_chain_round_trips_through_to_beef_on_a_small_stack() {
    let n = depth(DEFAULT_DEPTH);
    let (original, subject) = on_big_stack(move || chain_bytes(n));
    let tx = linked_chain(n);
    let ((tx, beef, atomic), elapsed) = on_small_stack("to_beef", move || {
        let beef = tx.to_beef(false).expect("to_beef");
        let atomic = tx.to_atomic_beef(false).expect("to_atomic_beef");
        (tx, beef, atomic)
    });
    println!("to_beef + to_atomic_beef: N={n} in {elapsed:?}");
    drop_on_big_stack(tx);
    assert_eq!(beef, original, "the round trip is byte-identical");
    let reparsed = Beef::from_binary(&atomic).expect("the atomic bytes parse");
    assert_eq!(reparsed.atomic_txid.as_deref(), Some(subject.as_str()));
    assert_eq!(reparsed.txs.len(), n);
}

#[test]
fn a_deep_chain_verifies_on_a_small_stack() {
    let n = depth(DEFAULT_DEPTH);
    let tx = linked_chain(n);
    let ((tx, verified), elapsed) = on_small_stack("verify", move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("a current-thread runtime");
        let verified = runtime
            .block_on(tx.verify(&MockChainTracker::always_valid(800_010), None))
            .map_err(|e| e.to_string());
        (tx, verified)
    });
    println!("verify: N={n} in {elapsed:?}");
    drop_on_big_stack(tx);
    assert_eq!(verified, Ok(true), "every link's script executes");
}

#[test]
fn a_deep_chain_clones_on_a_small_stack() {
    let n = depth(DEFAULT_DEPTH);
    let tx = linked_chain(n);
    let ((tx, copy), elapsed) = on_small_stack("clone", move || {
        let copy = tx.clone();
        (tx, copy)
    });
    println!("clone: N={n} in {elapsed:?}");
    assert_eq!(
        linked_depth(&copy),
        linked_depth(&tx),
        "a clone carries the whole ancestry"
    );
    assert_eq!(copy.id(), tx.id());
    drop_on_big_stack((tx, copy));
}

#[test]
fn a_deep_chain_drops_on_a_small_stack() {
    let n = depth(DEFAULT_DEPTH);
    let tx = linked_chain(n);
    let ((), elapsed) = on_small_stack("drop", move || drop(tx));
    println!("drop: N={n} in {elapsed:?}");
}

/// A chain a wallet builds in memory with `add_input_from_tx`: every input
/// carries its parent and no `source_txid`, so `id()` reads each parent's id
/// through the parent's own serialization.
#[test]
fn a_deep_chain_built_in_memory_hashes_and_serializes_on_a_small_stack() {
    let n = depth(DEFAULT_DEPTH);
    let (tx, original) = on_big_stack(move || {
        let (bytes, _) = chain_bytes(n);
        let mut linked = Transaction::from_beef(&bytes, None).expect("links");
        // Strip every source_txid: the shape `add_input_from_tx` builds.
        let mut current = &mut linked;
        loop {
            current.invalidate_caches();
            let Some(input) = current.inputs.first_mut() else {
                break;
            };
            if input.source_transaction.is_none() {
                break;
            }
            input.source_txid = None;
            current = input.source_transaction.as_deref_mut().expect("source");
        }
        (linked, bytes)
    });
    let ((tx, id, beef), elapsed) = on_small_stack("id", move || {
        let id = tx.id();
        let beef = tx.to_beef(false).expect("to_beef");
        (tx, id, beef)
    });
    println!("in-memory chain id + to_beef: N={n} in {elapsed:?}");
    drop_on_big_stack(tx);
    let subject = Beef::from_binary(&original)
        .expect("parses")
        .txs
        .last()
        .expect("a tx")
        .txid();
    assert_eq!(id, subject, "the same id as the parsed chain");
    assert_eq!(beef, original, "the same bytes as the parsed chain");
}

/// The overlay's historians walk a transaction's linked ancestry, the one
/// `from_beef` hands them from a lookup answer.
#[cfg(feature = "overlay")]
#[test]
fn a_deep_chain_history_builds_on_a_small_stack() {
    use bsv_rs::overlay::{Historian, HistorianConfig, InterpreterFn, SyncHistorian};

    let n = depth(DEFAULT_DEPTH);
    let tx = linked_chain(n);
    let ((tx, sync_len, async_len), elapsed) = on_small_stack("historian", move || {
        let sync = SyncHistorian::<u32, ()>::new(|_tx, vout, _ctx| Some(vout));
        let sync_len = sync.build_history(&tx, None).len();
        let interpreter: InterpreterFn<u32, ()> =
            Box::new(|_tx, vout, _ctx| Box::pin(async move { Some(vout) }));
        let historian = Historian::new(interpreter, HistorianConfig::default());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("a current-thread runtime");
        let async_len = runtime
            .block_on(historian.build_history(&tx, None))
            .expect("history")
            .len();
        (tx, sync_len, async_len)
    });
    println!("historians: N={n} in {elapsed:?}");
    drop_on_big_stack(tx);
    // The funding transaction has two outputs, every link one.
    assert_eq!(sync_len, n + 1);
    assert_eq!(async_len, n + 1);
}

/// The same chain written newest first: a sort that rescans the pending list
/// once per resolved link is quadratic here, so a stranger's byte order alone
/// would cost `N^2 / 2` lookups.
#[test]
fn a_reversed_deep_chain_sorts_in_linear_time_on_a_small_stack() {
    let n = depth(DEFAULT_DEPTH);
    let (mut beef, _) = chain_beef(n);
    beef.sort_txs();
    beef.txs.reverse();
    let mut writer = bsv_rs::primitives::Writer::new();
    beef.to_writer(&mut writer);
    let bytes = writer.into_bytes();
    let (valid, elapsed) = on_small_stack("reversed verify_valid", move || {
        let mut beef = Beef::from_binary(&bytes).expect("the chain parses");
        beef.verify_valid(false).valid
    });
    println!("reversed verify_valid: N={n} valid={valid} in {elapsed:?}");
    assert!(valid, "the order on the wire does not change the verdict");
    assert!(
        elapsed < Duration::from_secs(30),
        "sorting {n} reversed links must be linear, took {elapsed:?}"
    );
}

/// The 0.3.21 regression's shape (`a_deep_diamond_chain_links_and_verifies_in_linear_time`
/// in `src/transaction/beef.rs`): 24 levels, each spending both outputs of the
/// level below. Linking it by cloning every input in full is 2^24 subtrees.
#[test]
fn a_24_deep_diamond_parses_and_links_in_under_a_second_on_a_small_stack() {
    let (mut beef, subject) = diamond_beef(24);
    let bytes = beef.to_binary();
    let (id, elapsed) = on_small_stack("diamond", move || {
        let tx = Transaction::from_beef(&bytes, None).expect("the diamond parses and links");
        tx.id()
    });
    println!("24-deep diamond: from_beef in {elapsed:?}");
    assert_eq!(id, subject);
    assert!(elapsed < Duration::from_secs(1), "took {elapsed:?}");
}
