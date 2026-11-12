#![cfg(test)]
//! #621, after #817: `merge_beef`'s verdict from a pre-pass
//! (`Beef::snapshot_verdict`: the writers' check, then each BUMP read by the
//! reader's decoder at its place in the frame) proven equal to the literal
//! round trip it replaced (`Beef::snapshot_round_trip`, the oracle: the
//! source written in its merge order and read back by `Beef::from_binary`).
//! On every BEEF this tree's vectors hold, each under seventeen states (the
//! six of #817's differential, eight more a reader refuses or the merge
//! reads differently, and three holding an output of 2^53 satoshis, #844), and on every `writers` and `merge_door` state of
//! #817's recording: the same `Ok`, or the same `Err` (variant and words);
//! after an `Ok`, the target's written bytes equal those of merging the
//! oracle's snapshot, into an empty target and into one holding a raw entry.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

#[path = "../../../tests/support/beef_seeds_817.rs"]
mod seeds;
#[path = "../../../tests/support/beef_merge_states_817.rs"]
mod states;

use crate::transaction::{Beef, BeefTx, MerklePathLeaf, Transaction};
use states::{fixture, merge_source, vector, writer_state, Fixture, BAD_WORD, FRESH};

/// A change written into a source through its public fields.
type Change = Box<dyn Fn(&mut Beef)>;

/// What a comparison found: the pre-pass and the oracle agreed on `Ok`
/// (the merged bytes compared) or on an `Err`.
#[derive(Default)]
struct Counts {
    ok: usize,
    refused: usize,
    /// Of the refusals, the reader's (`invalid BEEF at byte N: ..`).
    by_reader: usize,
    /// Of those, the judge's `RootNotCarried` ahead of a later BUMP's.
    root_not_carried: usize,
}

/// The two targets every `Ok` is merged into: an empty one and one holding
/// the recording's parent raw.
fn targets(f: &Fixture) -> Vec<Beef> {
    let mut held = Beef::new();
    held.merge_raw_tx(f.parent_raw.clone(), None).unwrap();
    vec![Beef::new(), held]
}

/// The pre-pass against the oracle on `source`, `name` naming it.
fn compare(name: &str, source: &Beef, targets: &[Beef], counts: &mut Counts) {
    let order = source.written_order();
    let ours = source.snapshot_verdict(&order);
    let oracle = source.snapshot_round_trip(&order);
    match (ours, oracle) {
        (Ok(()), Ok(snapshot)) => {
            for (k, target) in targets.iter().enumerate() {
                let mut merged = target.clone();
                merged.merge_beef(source).unwrap();
                let mut by_snapshot = target.clone();
                by_snapshot.merge_beef(&snapshot).unwrap();
                assert_eq!(
                    merged.to_binary().unwrap(),
                    by_snapshot.to_binary().unwrap(),
                    "{name}, target {k}: the merged bytes are the snapshot's"
                );
            }
            counts.ok += 1;
        }
        (Err(ours), Err(oracle)) => {
            assert_eq!(ours, oracle, "{name}: the refusal");
            if let crate::Error::BeefError(words) = &oracle {
                if words.starts_with("invalid BEEF at byte ") {
                    counts.by_reader += 1;
                    counts.root_not_carried += usize::from(words.contains("RootNotCarried"));
                }
            }
            // The door gives the same refusal, the target untouched.
            let mut target = targets[1].clone();
            let before = target.to_binary().unwrap();
            assert_eq!(target.merge_beef(source).unwrap_err(), oracle, "{name}");
            assert_eq!(target.to_binary().unwrap(), before, "{name}: untouched");
            counts.refused += 1;
        }
        (ours, oracle) => panic!(
            "{name}: the pre-pass {ours:?}, the oracle {:?}",
            oracle.map(drop)
        ),
    }
}

/// A transaction with one output of 2^53 satoshis, built by hand (#844).
fn by_hand_53() -> Transaction {
    Transaction::with_params(
        1,
        vec![crate::transaction::TransactionInput::new(
            FRESH.to_string(),
            0,
        )],
        vec![crate::transaction::TransactionOutput::new(
            1 << 53,
            crate::script::LockingScript::new(),
        )],
        0,
    )
}

/// The seventeen states of a source: as read, and each change below.
fn changes() -> Vec<Change> {
    vec![
        Box::new(|_| {}),
        Box::new(|b| b.version = BAD_WORD),
        Box::new(|b| {
            b.merge_txid_only("ab".repeat(31));
        }),
        Box::new(|b| {
            b.merge_txid_only(FRESH.to_string());
        }),
        // A second leaf at an offset of the leading BUMP's level 0.
        Box::new(|b| {
            if let Some(level) = b.bumps.first_mut().and_then(|p| p.path.first_mut()) {
                if let Some(leaf) = level.first().cloned() {
                    level.push(leaf);
                }
            }
        }),
        // No levels in the leading BUMP.
        Box::new(|b| {
            if let Some(p) = b.bumps.first_mut() {
                p.path.clear();
            }
        }),
        // An empty level 0 in the last BUMP.
        Box::new(|b| {
            if let Some(p) = b.bumps.last_mut() {
                if let Some(level) = p.path.first_mut() {
                    level.clear();
                }
            }
        }),
        // 65 levels in the last BUMP (the writer writes up to 255).
        Box::new(|b| {
            if let Some(p) = b.bumps.last_mut() {
                while p.path.len() < 65 {
                    p.path.push(Vec::new());
                }
            }
        }),
        // A level-0 leaf at an offset outside the tree.
        Box::new(|b| {
            if let Some(leaf) = b
                .bumps
                .first_mut()
                .and_then(|p| p.path.first_mut())
                .and_then(|l| l.last_mut())
            {
                leaf.offset = u64::MAX >> 1;
            }
        }),
        // A BUMP at the leading BUMP's height with another root, then a BUMP
        // the decoder refuses: the reader names the earlier `RootNotCarried`.
        Box::new(|b| {
            if let Some(first) = b.bumps.first().cloned() {
                let mut other = first.clone();
                if let Some(leaf) = other.path[0].iter_mut().find(|l| l.hash.is_some()) {
                    leaf.hash = Some("11".repeat(32));
                }
                let mut broken = first;
                broken.path.clear();
                b.bumps.push(other);
                b.bumps.push(broken);
            }
        }),
        // The same contradicting BUMP alone: the reader returns the BEEF.
        Box::new(|b| {
            if let Some(first) = b.bumps.first().cloned() {
                let mut other = first;
                if let Some(leaf) = other.path[0].iter_mut().find(|l| l.hash.is_some()) {
                    leaf.hash = Some("11".repeat(32));
                }
                b.bumps.push(other);
            }
        }),
        // A carried node above level 0 changed (a contradicted node, where a
        // walk reads it).
        Box::new(|b| {
            if let Some(leaf) = b
                .bumps
                .first_mut()
                .and_then(|p| p.path.get_mut(1))
                .and_then(|l| l.first_mut())
            {
                if !leaf.duplicate {
                    leaf.hash = Some("22".repeat(32));
                }
            }
        }),
        // A level-0 sibling removed (a missing sibling, where a walk needs it).
        Box::new(|b| {
            if let Some(level) = b.bumps.first_mut().and_then(|p| p.path.first_mut()) {
                if level.len() > 1 {
                    let at = level.iter().position(|l| !l.txid).unwrap_or(0);
                    level.remove(at);
                }
            }
        }),
        // An entry edited through the deprecated door (its stale order read
        // by `written_order`) and a duplicate at an even offset of the last
        // BUMP's level 0.
        Box::new(|b| {
            if let Some(entry) = b.txs.iter_mut().rev().find(|t| !t.is_txid_only()) {
                #[allow(deprecated)]
                let tx = entry.tx_mut();
                if let Some(tx) = tx {
                    tx.set_lock_time(tx.lock_time() ^ 1);
                }
            }
            if let Some(level) = b.bumps.last_mut().and_then(|p| p.path.first_mut()) {
                let free = (0..)
                    .step_by(2)
                    .find(|o| level.iter().all(|l| l.offset != *o));
                if let Some(offset) = free {
                    level.push(MerklePathLeaf::new_duplicate(offset));
                }
            }
        }),
        // An output of 2^53 satoshis in each entry shape that can hold one
        // (#844): the last read entry edited through `edit_tx` (its bytes
        // rewritten from the fields) ...
        Box::new(|b| {
            let last = b
                .txs
                .iter()
                .rev()
                .find(|t| t.tx().is_some_and(|tx| !tx.outputs().is_empty()));
            if let Some(txid) = last.map(BeefTx::txid) {
                let _ = b.edit_tx(&txid, |tx| tx.outputs_mut()[0].satoshis = Some(1 << 53));
            }
        }),
        // ... a transaction built by hand merged by `merge_transaction` (its
        // txid computed, its bytes cached and scanned) ...
        Box::new(|b| {
            b.merge_transaction(by_hand_53());
        }),
        // ... and pushed by hand never hashed, so no bytes are cached: an
        // entry the writers' check takes from its fields (the state
        // `fuzz_beef_parser` found, where the check took the fields on
        // trust and the round trip refused it).
        Box::new(|b| b.txs.push(BeefTx::from_tx(by_hand_53(), None))),
    ]
}

#[test]
fn the_pre_pass_is_the_round_trip_on_every_vector_beef_621() {
    let f = fixture(&vector());
    let targets = targets(&f);
    let changes = changes();
    let mut counts = Counts::default();
    let mut read = 0;
    for (name, bytes) in seeds::seeds() {
        let Ok(beef) = Beef::from_binary(&bytes) else {
            continue;
        };
        read += 1;
        for (k, change) in changes.iter().enumerate() {
            let mut source = beef.clone();
            change(&mut source);
            compare(&format!("{name} state {k}"), &source, &targets, &mut counts);
        }
    }
    // The census of the sweep (#621's fold): `read` is the BEEFs of
    // `tests/support/beef_seeds_817.rs` that `Beef::from_binary` reads, and
    // the split below is what this test measured over them. A new vector
    // holding a BEEF moves these figures (#841's `transaction_trailing_data_
    // 840.json#0` moved 337 to 338): re-derive them by running this test,
    // whose failing assertion prints the new figures as `left`, and carry
    // them to the records that cite them (`CHANGELOG.md`'s #621 entry,
    // `src/transaction/CLAUDE.md`'s `beef/prepass_621_tests.rs` row,
    // `docs/lanes/fix-621.md`). A split that moves with no new vector is a
    // finding. The totals are derived, never pinned.
    assert_eq!(read, 361, "every BEEF the vectors hold that reads");
    assert_eq!(
        counts.ok + counts.refused,
        changes.len() * read,
        "every state of each"
    );
    // Both sides of the verdict are reached, and most states are refused.
    assert_eq!(
        (
            counts.ok,
            counts.refused,
            counts.by_reader,
            counts.root_not_carried
        ),
        (2443, 3694, 1789, 252)
    );
}

#[test]
fn the_pre_pass_is_the_round_trip_on_every_recorded_state_817_621() {
    let v = vector();
    let f = fixture(&v);
    let targets = targets(&f);
    let mut counts = Counts::default();
    for (group, build) in [
        (
            "writers",
            writer_state as fn(&str, &Fixture) -> Option<Beef>,
        ),
        ("merge_door", merge_source),
    ] {
        for c in v[group].as_array().unwrap() {
            let name = c["name"].as_str().unwrap();
            if let Some(source) = build(name, &f) {
                compare(&format!("{group} {name}"), &source, &targets, &mut counts);
            }
        }
    }
    assert_eq!(
        (
            counts.ok,
            counts.refused,
            counts.by_reader,
            counts.root_not_carried
        ),
        (4, 23, 2, 0)
    );
}

/// A parsed transaction whose cached serialization is `raw` followed by
/// `raw` again, the state `Transaction::from_binary` left on a doubled
/// buffer until #840 refused it: built through the crate's test door, the
/// one way left to reach it (no public door since #840).
fn parsed_with_trailing_cache(raw: &[u8]) -> Transaction {
    let doubled = [raw, raw].concat();
    assert!(
        Transaction::from_binary(&doubled).is_err(),
        "#840's reader refuses the doubled buffer"
    );
    Transaction::from_binary(raw)
        .unwrap()
        .with_cached_bytes_for_test(doubled)
}

/// The cold read's state (#621's fold): a parsed entry whose cached bytes
/// are a transaction and more, put in a source by `merge_transaction` and by
/// a hand push of `BeefTx::from_tx`. The writers' check judges the bytes the
/// writer writes for a parsed entry too, so the pre-pass and the oracle
/// refuse it alike, in the framing scan's words, and so does `to_binary`;
/// on `a7984877` the pre-pass answered `Ok` where the oracle refused
/// (`invalid BEEF at byte N: TrailingBytes`).
#[test]
fn a_parsed_entry_whose_cached_bytes_trail_its_transaction_is_refused_621() {
    let f = fixture(&vector());
    let targets = targets(&f);
    let words = format!(
        "Serialized transaction has {} bytes after its lock time",
        f.parent_raw.len()
    );
    let mut counts = Counts::default();
    let mut read = 0;
    for (name, bytes) in seeds::seeds() {
        let Ok(beef) = Beef::from_binary(&bytes) else {
            continue;
        };
        read += 1;
        for door in 0..2 {
            let mut source = beef.clone();
            let tx = parsed_with_trailing_cache(&f.parent_raw);
            if door == 0 {
                source.merge_transaction(tx);
            } else {
                source.txs.push(BeefTx::from_tx(tx, None));
            }
            let name = format!("{name} trailing cache, door {door}");
            compare(&name, &source, &targets, &mut counts);
            let order = source.written_order();
            let refusal = source.snapshot_verdict(&order).unwrap_err();
            assert_eq!(refusal, crate::Error::BeefError(words.clone()), "{name}");
            assert_eq!(
                source.clone().to_binary().unwrap_err(),
                refusal,
                "{name}: the writer"
            );
        }
    }
    // Every BEEF that reads, under both doors, refused alike: the figure is
    // derived from the sweep's own count (338 BEEFs, 676 states at `435dcd3e`
    // after #841's vector), never pinned.
    assert!(read > 0, "the sweep reads a BEEF");
    assert_eq!(
        (counts.ok, counts.refused, counts.by_reader),
        (0, 2 * read, 0)
    );
}
