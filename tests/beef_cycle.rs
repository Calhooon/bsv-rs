//! A BEEF whose source links form a cycle is refused in bounded time (#160).
//!
//! CLAUDE.md's BEEF contract says "cycles terminate"; the linking memo was
//! pinned only through the diamond tests. A raw entry is named by the hash
//! of its bytes, and an input names its parent by a txid field, so on the
//! wire a ring of raw transactions (A spends B, B spends A) can be written
//! only by its fields: no transaction's hash can be in its own ancestry.
//! Such a ring names at least one entry that is not held ahead of it, which
//! BRC-62's order (`transactions/0062.md:172` step 2.4.1) and both readers
//! refuse as `InputNamesNoElement` before any walk. In memory a ring is
//! real: an entry read from bytes keeps the txid it was read with, and
//! `BeefTx::tx_mut` can point its input at its own descendant. There the
//! linker's memo (`Beef::add_input_proof`, a stub memoized before it
//! descends), `to_binary_atomic`'s closure and `sort_txs` must each stop.
//! The termination these mirror is the stack's: `BeefOfAnySize.lean`
//! `walk` (`:944`) takes one unit of fuel per txid and keeps a `seen` set,
//! `budget` (`:956`) bounds the fuel by the entries and the edges.
//!
//! The walk's counter is not public: the pins are the refusal and the time,
//! each reader on its own thread joined under `BOUND` (a loop fails the
//! test, it does not hang it) with `catch_unwind` for a panic.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use bsv_rs::primitives::{from_hex, Writer};
use bsv_rs::script::{LockingScript, UnlockingScript};
use bsv_rs::transaction::beef_stream::{verify_stream, verify_stream_structure, Kind, Verdict};
use bsv_rs::transaction::{
    Beef, MerklePath, MockChainTracker, Transaction, TransactionInput, TransactionOutput,
    ATOMIC_BEEF, BEEF_V1, BEEF_V2,
};

/// Each reader's bound: the deep-chain tests link 100,000 transactions in
/// a few seconds; a ring of three is read in microseconds.
const BOUND: Duration = Duration::from_secs(5);

/// Runs `f` on its own thread and returns its value and the time it took,
/// or fails the test when it panics or does not return within `BOUND`.
fn bounded<T: Send + 'static>(name: &str, f: impl FnOnce() -> T + Send + 'static) -> (T, Duration) {
    let (send, recv) = mpsc::channel();
    std::thread::Builder::new()
        .name(name.to_string())
        .spawn(move || {
            let started = Instant::now();
            let value = catch_unwind(AssertUnwindSafe(f));
            let _ = send.send(value.map(|v| (v, started.elapsed())));
        })
        .expect("spawn the thread");
    match recv.recv_timeout(BOUND) {
        Ok(Ok((value, elapsed))) => {
            println!("{name}: {elapsed:?}");
            (value, elapsed)
        }
        Ok(Err(_)) => panic!("{name} panicked"),
        Err(_) => panic!("{name} did not return within {BOUND:?}"),
    }
}

/// A transaction with one `OP_TRUE` output of 1,000 satoshis spending
/// output 0 of each txid in `spends`, with empty unlocking scripts.
fn tx(spends: &[&str]) -> Transaction {
    let mut t = Transaction::new();
    for txid in spends {
        let mut input = TransactionInput::new(txid.to_string(), 0);
        input.unlocking_script = Some(UnlockingScript::from_binary(&[]).unwrap());
        t.inputs.push(input);
    }
    t.outputs.push(TransactionOutput::new(
        1_000,
        LockingScript::from_binary(&[0x51]).unwrap(),
    ));
    t
}

/// Display hex to the wire's byte order.
fn internal(txid: &str) -> [u8; 32] {
    let mut h: [u8; 32] = from_hex(txid).unwrap().try_into().unwrap();
    h.reverse();
    h
}

/// The txid fields of a ring: `ring[i]` is the txid the ring calls
/// transaction `i`.
fn ring_names(n: usize) -> Vec<String> {
    ["a1", "b2", "c3"][..n]
        .iter()
        .map(|b| b.repeat(32))
        .collect()
}

/// A ring written by its fields: transaction `i` spends the txid the ring
/// calls transaction `i + 1` (mod `n`). The bytes' hashes are not the
/// names; that is the only way a ring can be written.
fn named_ring(n: usize) -> Vec<Vec<u8>> {
    let names = ring_names(n);
    (0..n)
        .map(|i| tx(&[&names[(i + 1) % n]]).to_binary())
        .collect()
}

/// A pair with one link real: `B` spends the hash of `A`'s bytes, and `A`'s
/// input names the txid the ring calls `B`, which `B`'s bytes cannot hash to.
fn half_real_pair() -> Vec<Vec<u8>> {
    let a = tx(&["b2".repeat(32).as_str()]);
    let b = tx(&[a.id().as_str()]);
    vec![a.to_binary(), b.to_binary()]
}

/// A BEEF V1 (atomic when `subject` is named) with `bumps` and the raw
/// `entries` in the order given, none proven, by the crate's own writer.
fn write(subject: Option<&str>, bumps: &[MerklePath], entries: &[&[u8]]) -> Vec<u8> {
    let mut w = Writer::new();
    if let Some(subject) = subject {
        w.write_u32_le(ATOMIC_BEEF);
        w.write_bytes(&internal(subject));
    }
    w.write_u32_le(BEEF_V1);
    w.write_var_int(bumps.len() as u64);
    for bump in bumps {
        w.write_bytes(&bump.to_binary());
    }
    w.write_var_int(entries.len() as u64);
    for raw in entries {
        w.write_bytes(raw);
        w.write_u8(0);
    }
    w.into_bytes()
}

/// A BUMP that proves none of the ring: a one-transaction block of a txid
/// no entry has.
fn unrelated_bump() -> MerklePath {
    MerklePath::from_coinbase_txid(&"d4".repeat(32), 900_000)
}

/// The headers for `bumps`: each root at its height.
fn roots(bumps: &[MerklePath]) -> HashMap<u64, [u8; 32]> {
    bumps
        .iter()
        .map(|b| {
            (
                u64::from(b.block_height),
                internal(&b.compute_root(None).unwrap()),
            )
        })
        .collect()
}

fn txid_of(raw: &[u8]) -> String {
    Transaction::from_binary(raw).unwrap().id()
}

/// What each reader answers on one written fixture.
#[derive(Debug, PartialEq, Eq)]
struct Answers {
    /// `Beef::from_binary`: parsed (it judges the frame, not the graph).
    parsed: bool,
    /// The stream's kind, structure only and with its spend checks.
    stream_structure: Option<Kind>,
    stream_full: Option<Kind>,
    /// `Beef::verify_structure`'s kind and `verify_valid`'s `valid`.
    whole: Option<Kind>,
    valid: bool,
}

fn kind(v: Verdict) -> Option<Kind> {
    match v {
        Verdict::Invalid { kind, .. } => Some(kind),
        Verdict::Valid { .. } => None,
        other => panic!("a verdict on the bytes expected, got {other:?}"),
    }
}

/// Every reader on `bytes`, each under the bound.
fn read_all(label: &str, bytes: Vec<u8>, bumps: Vec<MerklePath>) -> Answers {
    let headers = roots(&bumps);
    let (parsed, _) = bounded(&format!("{label}: from_binary"), {
        let bytes = bytes.clone();
        move || Beef::from_binary(&bytes).is_ok()
    });
    let (stream_structure, _) = bounded(&format!("{label}: verify_stream_structure"), {
        let (bytes, headers) = (bytes.clone(), headers.clone());
        move || kind(verify_stream_structure(bytes.as_slice(), &headers, None).unwrap())
    });
    let (stream_full, _) = bounded(&format!("{label}: verify_stream"), {
        let bytes = bytes.clone();
        move || kind(verify_stream(bytes.as_slice(), &headers, None).unwrap())
    });
    let ((whole, valid), _) = bounded(&format!("{label}: verify_valid"), move || {
        let whole = Beef::from_binary(&bytes).unwrap().verify_structure().err();
        let valid = Beef::from_binary(&bytes).unwrap().verify_valid(false).valid;
        (whole, valid)
    });
    Answers {
        parsed,
        stream_structure,
        stream_full,
        whole,
        valid,
    }
}

/// The refusal every reader gives a ring written by its fields: the parse
/// holds it, and each judge names the input that names no entry held ahead.
const REFUSED: Answers = Answers {
    parsed: true,
    stream_structure: Some(Kind::InputNamesNoElement),
    stream_full: Some(Kind::InputNamesNoElement),
    whole: Some(Kind::InputNamesNoElement),
    valid: false,
};

/// Every rotation and its reverse: each order a ring of `n` can be written
/// in, up to the names.
fn orders(n: usize) -> Vec<Vec<usize>> {
    let mut all = Vec::new();
    for start in 0..n {
        let forward: Vec<usize> = (0..n).map(|i| (start + i) % n).collect();
        let mut backward = forward.clone();
        backward.reverse();
        all.push(forward);
        all.push(backward);
    }
    all.sort();
    all.dedup();
    all
}

#[test]
fn a_ring_written_by_its_txid_fields_is_refused_by_every_reader_in_bounded_time() {
    for n in [2, 3] {
        let ring = named_ring(n);
        for bumps in [vec![], vec![unrelated_bump()]] {
            for order in orders(n) {
                let entries: Vec<&[u8]> = order.iter().map(|&i| ring[i].as_slice()).collect();
                let label = format!("ring of {n}, {} BUMP, order {order:?}", bumps.len());
                let bytes = write(None, &bumps, &entries);
                assert_eq!(read_all(&label, bytes, bumps.clone()), REFUSED, "{label}");
            }
        }
    }
}

#[test]
fn a_pair_with_one_real_link_and_one_named_link_is_refused_in_both_orders() {
    let pair = half_real_pair();
    for bumps in [vec![], vec![unrelated_bump()]] {
        for order in [[0, 1], [1, 0]] {
            let label = format!("half-real pair, {} BUMP, order {order:?}", bumps.len());
            let bytes = write(None, &bumps, &[&pair[order[0]], &pair[order[1]]]);
            assert_eq!(read_all(&label, bytes, bumps.clone()), REFUSED, "{label}");
        }
    }
}

#[test]
fn the_atomic_form_of_a_ring_is_refused_by_the_readers_and_from_atomic_beef_stops() {
    // `Transaction::from_atomic_beef` finds the subject and does not judge
    // the graph (CLAUDE.md's divergence list): it returns the subject with
    // the input that names no entry unlinked, and the transaction it
    // returns does not verify. The readers refuse the same bytes.
    for (label, ring) in [
        ("named pair", named_ring(2)),
        ("named ring of 3", named_ring(3)),
        ("half-real pair", half_real_pair()),
    ] {
        for bumps in [vec![], vec![unrelated_bump()]] {
            let n = ring.len();
            for order in orders(n) {
                let entries: Vec<&[u8]> = order.iter().map(|&i| ring[i].as_slice()).collect();
                let subject = txid_of(entries[n - 1]);
                let label = format!("atomic {label}, {} BUMP, order {order:?}", bumps.len());
                let bytes = write(Some(&subject), &bumps, &entries);
                assert_eq!(
                    read_all(&label, bytes.clone(), bumps.clone()),
                    REFUSED,
                    "{label}"
                );
                let (verified, _) = bounded(&format!("{label}: from_atomic_beef"), move || {
                    let tx = Transaction::from_atomic_beef(&bytes).unwrap();
                    assert_eq!(tx.id(), subject);
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .build()
                        .unwrap();
                    runtime
                        .block_on(tx.verify(&MockChainTracker::always_valid(900_010), None))
                        .is_ok_and(|v| v)
                });
                assert!(!verified, "{label}: the subject must not verify");
            }
        }
    }
}

/// An in-memory BEEF holding a real ring of `n`: a chain `T0 <- T1 <- ..`
/// read from bytes, then `T0`'s input pointed at the last link's txid.
/// Each entry keeps the txid it was read with, so the names form a cycle.
fn in_memory_ring(n: usize) -> (Beef, Vec<String>) {
    let mut chain = vec![tx(&["e5".repeat(32).as_str()])];
    for i in 1..n {
        let parent = chain[i - 1].id();
        chain.push(tx(&[parent.as_str()]));
    }
    let raws: Vec<Vec<u8>> = chain.iter().map(Transaction::to_binary).collect();
    let entries: Vec<&[u8]> = raws.iter().map(Vec::as_slice).collect();
    let ids: Vec<String> = chain.iter().map(Transaction::id).collect();
    let mut beef = Beef::from_binary(&write(None, &[], &entries)).unwrap();
    let last = ids[n - 1].clone();
    beef.find_txid_mut(&ids[0])
        .unwrap()
        .tx_mut()
        .unwrap()
        .inputs[0]
        .source_txid = Some(last);
    (beef, ids)
}

/// The links below `tx`, following each input's first source: the depth of
/// the linked shape.
fn linked_depth(tx: &Transaction) -> usize {
    let mut depth = 0;
    let mut at = tx;
    while let Some(src) = at
        .inputs
        .first()
        .and_then(|i| i.source_transaction.as_deref())
    {
        depth += 1;
        at = src;
    }
    depth
}

#[test]
fn a_ring_held_in_memory_links_each_entry_once_and_every_walk_stops() {
    for n in [1, 2, 3] {
        // `n = 1`: a transaction whose input names its own txid.
        let (beef, ids) = in_memory_ring(n);
        let subject = ids[n - 1].clone();
        // The linker: the subject's ancestry walks the ring once and meets
        // the subject's memoized stub, so the shape is `n` links deep.
        let (depth, _) = bounded(&format!("in-memory ring of {n}: link"), {
            let (beef, subject) = (beef.clone(), subject.clone());
            move || linked_depth(&beef.find_atomic_transaction(&subject).unwrap())
        });
        assert_eq!(
            depth,
            n + 1,
            "ring of {n}: each entry linked once, then the stub"
        );
        // The atomic closure and the sort stop; the sort holds nothing of
        // the ring valid, and the judge refuses it.
        let (closure, _) = bounded(&format!("in-memory ring of {n}: to_binary_atomic"), {
            let (mut beef, subject) = (beef.clone(), subject.clone());
            move || beef.to_binary_atomic(&subject).map(|b| b.len())
        });
        assert!(closure.is_ok(), "ring of {n}: the closure is written");
        let (sorted, _) = bounded(&format!("in-memory ring of {n}: sort_txs"), {
            let mut beef = beef.clone();
            move || {
                let sr = beef.sort_txs();
                sr.missing_inputs.len() + sr.not_valid.len() + sr.with_missing_inputs.len()
            }
        });
        assert!(
            sorted > 0,
            "ring of {n}: the sort holds the ring unresolved"
        );
        let (whole, _) = bounded(&format!("in-memory ring of {n}: verify_structure"), {
            let mut beef = beef.clone();
            move || beef.verify_structure().err()
        });
        assert_eq!(whole, Some(Kind::InputNamesNoElement), "ring of {n}");
        // Written out, the mutated entry hashes anew: the ring is broken on
        // the wire and the whole path refuses what it reads back.
        let (reread, _) = bounded(&format!("in-memory ring of {n}: round trip"), {
            let mut beef = beef.clone();
            move || {
                let bytes = beef.to_binary();
                Beef::from_binary(&bytes).unwrap().verify_structure().err()
            }
        });
        assert_eq!(reread, Some(Kind::InputNamesNoElement), "ring of {n}");
    }
}

#[test]
fn the_v2_form_of_a_ring_is_refused_as_the_v1_form_is() {
    // The same ring of three in BEEF V2 (format byte 0 per entry).
    let ring = named_ring(3);
    let mut w = Writer::new();
    w.write_u32_le(BEEF_V2);
    w.write_var_int(0);
    w.write_var_int(ring.len() as u64);
    for raw in &ring {
        w.write_u8(0);
        w.write_bytes(raw);
    }
    assert_eq!(read_all("V2 ring of 3", w.into_bytes(), vec![]), REFUSED);
}
