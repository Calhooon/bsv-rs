#![cfg(test)]
//! #817, the atomic closures of one BEEF: the batch door
//! (`Beef::atomic_batch`) against the per-call door as it stood before the
//! batch (`oracle`, kept here verbatim: a refresh, an amount check and a
//! position map a call, every entry visited twice a closure). On every
//! BEEF this tree's vectors hold, each under nine states, for every txid
//! it holds and three it does not: the same bytes or the same refusal,
//! from the batch door and from today's per-call door alike. And the cost
//! as counts, never a time, each of the entries a loop visits, counted at
//! the loop's own turn (`cost`): the three whole-BEEF passes once a batch,
//! and a closure's two loops over the entries it keeps and no other.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use std::collections::{HashMap, HashSet};

use super::super::in_memory;
use super::super::prepass_621_tests::seeds;
use super::cost;
use crate::primitives::{from_hex, Writer};
use crate::script::{LockingScript, UnlockingScript};
use crate::transaction::beef_tx::ATOMIC_BEEF;
use crate::transaction::{
    Beef, BeefTx, MerklePath, MerklePathLeaf, Transaction, TransactionInput, TransactionOutput,
    BEEF_V1, BEEF_V2,
};
use crate::Result;

/// A txid no vector holds.
const ABSENT: &str = "8170000000000000000000000000000000000000000000000000000000000b06";

/// `Beef::to_binary_atomic` as it stood before the batch door, line for
/// line: the three passes over the whole BEEF a call.
fn oracle(beef: &mut Beef, txid: &str) -> Result<Vec<u8>> {
    beef.refresh_mutated();
    beef.refuse_unsafe_amount()?;
    if beef.find_txid(txid).is_none() {
        return Err(crate::Error::BeefError(format!(
            "{} does not exist in this Beef",
            txid
        )));
    }
    let closure = oracle_closure(beef, txid);
    closure.check_writable()?;
    let mut writer = Writer::new();
    writer.write_u32_le(ATOMIC_BEEF);
    let mut reversed = from_hex(txid)?;
    reversed.reverse();
    writer.write_bytes(&reversed);
    closure.write_checked(&mut writer);
    Ok(writer.into_bytes())
}

/// `atomic_closure` as it stood (the Beef-level door's: no move of the
/// subject).
fn oracle_closure(this: &Beef, subject: &str) -> Beef {
    let at: HashMap<String, usize> = this
        .txs
        .iter()
        .enumerate()
        .map(|(i, tx)| (tx.txid(), i))
        .collect();
    let mut included: HashSet<usize> = HashSet::new();
    let mut stack: Vec<usize> = at.get(subject).copied().into_iter().collect();
    while let Some(i) = stack.pop() {
        if !included.insert(i) {
            continue;
        }
        let tx = &this.txs[i];
        if tx.is_txid_only() || tx.has_proof() {
            continue;
        }
        stack.extend(in_memory::spent_txids(tx).iter().filter_map(|t| at.get(t)));
    }
    let mut beef = Beef::with_version(this.version);
    let mut renumbered: HashMap<usize, usize> = HashMap::new();
    for (i, tx) in this.txs.iter().enumerate() {
        if !included.contains(&i) || !this.proves(tx) {
            continue;
        }
        if let Some(index) = tx.bump_index() {
            renumbered.entry(index).or_insert_with(|| {
                beef.bumps.push(this.bumps[index].clone());
                beef.bumps.len() - 1
            });
        }
    }
    for (i, tx) in this.txs.iter().enumerate() {
        if !included.contains(&i) {
            continue;
        }
        let mut copy = tx.clone();
        copy.set_bump_index(tx.bump_index().and_then(|i| renumbered.get(&i).copied()));
        if tx.held_raw() {
            copy.input_txids = tx.input_txids.clone();
        }
        beef.txs.push(copy);
    }
    beef.sort_txs();
    beef
}

/// A change written into a BEEF through its public doors and fields.
type Change = Box<dyn Fn(&mut Beef)>;

/// The nine states: as read, and eight a writer refuses, a door repairs or
/// a hand edit leaves.
fn changes() -> Vec<Change> {
    vec![
        Box::new(|_| {}),
        // The other version word: a V1 BEEF holding a txid-only entry is
        // refused by the closure's check where the closure keeps one.
        Box::new(|b| {
            b.version = if b.version == BEEF_V1 {
                BEEF_V2
            } else {
                BEEF_V1
            }
        }),
        Box::new(|b| b.version = 0xEFBE_0003),
        Box::new(|b| {
            b.merge_txid_only(ABSENT.replace('b', "c"));
        }),
        // An entry edited through the deprecated door, which the refresh
        // re-keys.
        Box::new(|b| {
            if let Some(entry) = b.txs.iter_mut().rev().find(|t| !t.is_txid_only()) {
                #[allow(deprecated)]
                let tx = entry.tx_mut();
                if let Some(tx) = tx {
                    tx.set_lock_time(tx.lock_time() ^ 1);
                }
            }
        }),
        // An output of 2^53 satoshis: the amount refusal, ahead of any
        // subject.
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
        // A hand push of a held txid: two entries of one txid.
        Box::new(|b| {
            if let Some(entry) = b.txs.first().cloned() {
                b.txs.push(entry);
            }
        }),
        // A hand replacement inside the indexed prefix: a txid the index
        // was never given, which the position map still finds.
        Box::new(|b| {
            if b.txs.len() > 1 {
                b.txs[0] = b.txs[b.txs.len() - 1].clone();
            }
        }),
        // A hand drop of the leading entry: the entry count moved.
        Box::new(|b| {
            if !b.txs.is_empty() {
                b.txs.remove(0);
            }
        }),
    ]
}

/// The txids asked of a BEEF: each it holds, each `also` names, one no
/// vector holds, and two texts that are no txid.
fn asked(beef: &Beef, also: &[String]) -> Vec<String> {
    let mut txids: Vec<String> = beef.txs.iter().map(BeefTx::txid).collect();
    txids.extend(also.iter().cloned());
    txids.extend([ABSENT.to_string(), "zz".to_string(), String::new()]);
    let mut seen = HashSet::new();
    txids.retain(|t| seen.insert(t.clone()));
    txids
}

#[test]
fn the_batch_door_answers_as_the_per_call_door_on_every_vector_beef_817() {
    let changes = changes();
    let (mut read, mut bytes, mut refused, mut not_held, mut prepared_err) = (0, 0, 0, 0, 0);
    for (name, seed) in seeds::seeds() {
        let Ok(beef) = Beef::from_binary(&seed) else {
            continue;
        };
        read += 1;
        let held: Vec<String> = beef.txs.iter().map(BeefTx::txid).collect();
        for (k, change) in changes.iter().enumerate() {
            let mut state = beef.clone();
            change(&mut state);
            let txids = asked(&state, &held);

            // The per-call door as it stood, call after call on one BEEF,
            // as the lookup answer called it.
            let mut before = state.clone();
            let expected: Vec<Result<Vec<u8>>> =
                txids.iter().map(|t| oracle(&mut before, t)).collect();

            // Today's per-call door, the same way.
            let mut per_call = state.clone();
            for (txid, want) in txids.iter().zip(&expected) {
                assert_eq!(
                    &per_call.to_binary_atomic(txid),
                    want,
                    "{name} state {k}, per call, {txid}"
                );
            }

            // The batch door: one preparation, every txid.
            let mut batched = state.clone();
            match batched.atomic_batch() {
                Ok(batch) => {
                    for (txid, want) in txids.iter().zip(&expected) {
                        assert_eq!(
                            &batch.to_binary_atomic(txid),
                            want,
                            "{name} state {k}, batch, {txid}"
                        );
                    }
                }
                // A refused preparation is every call's refusal, a txid
                // the BEEF does not hold included.
                Err(e) => {
                    prepared_err += 1;
                    for (txid, want) in txids.iter().zip(&expected) {
                        assert_eq!(
                            want.as_ref().unwrap_err(),
                            &e,
                            "{name} state {k}, refused batch, {txid}"
                        );
                    }
                }
            }
            // Both doors leave the BEEF as the old door left it.
            assert_eq!(per_call.to_binary(), before.to_binary(), "{name} state {k}");
            assert_eq!(batched.to_binary(), before.to_binary(), "{name} state {k}");

            for want in &expected {
                match want {
                    Ok(_) => bytes += 1,
                    Err(crate::Error::BeefError(w))
                        if w.ends_with("does not exist in this Beef") =>
                    {
                        not_held += 1;
                    }
                    Err(_) => refused += 1,
                }
            }
        }
    }
    // Floors, not a census: every arm of the comparison is reached on the
    // BEEFs the vectors hold (372 read when this was written).
    assert!(read >= 372, "{read} BEEFs read");
    assert!(bytes >= 2 * read, "{bytes} closures written");
    assert!(
        refused >= read,
        "{refused} refusals of a held subject or an amount"
    );
    assert!(not_held >= 3 * read, "{not_held} subjects not held");
    assert!(
        prepared_err >= read / 2,
        "{prepared_err} batches refused whole"
    );
}

/// A transaction spending `source`:0 with one output.
fn spending(source: &str) -> Transaction {
    let mut input = TransactionInput::new(source.to_string(), 0);
    input.set_unlocking_script(UnlockingScript::from_hex("").unwrap());
    let mut tx = Transaction::new();
    tx.add_input(input).unwrap();
    tx.add_output(TransactionOutput::new(
        1,
        LockingScript::from_hex("51").unwrap(),
    ))
    .unwrap();
    tx
}

/// `n` proven transactions, each in a block of its own, then a chain of
/// three unproven ones resting on the leading proven one: the BEEF and the
/// txids, the chain's last.
fn many(n: u32) -> (Beef, Vec<String>, String) {
    let mut beef = Beef::new();
    let mut proven = Vec::new();
    for k in 0..n {
        let tx = spending(&format!("{:064x}", u64::from(k) + 1));
        let path =
            MerklePath::new(900 + k, vec![vec![MerklePathLeaf::new_txid(0, tx.id())]]).unwrap();
        let index = beef.merge_bump(path);
        beef.merge_raw_tx(tx.to_binary(), Some(index)).unwrap();
        proven.push(tx.id());
    }
    let mut tip = proven[0].clone();
    for _ in 0..3 {
        let tx = spending(&tip);
        beef.merge_raw_tx(tx.to_binary(), None).unwrap();
        tip = tx.id();
    }
    (beef, proven, tip)
}

/// One preparation for every closure of a batch, and each closure's loops
/// visit the entries it keeps alone. The counts are of entries VISITED,
/// taken at each loop's own turn: 64 proven subjects over 67 entries are
/// one pass of each of the three (67 entries refreshed, 67 checked for
/// their amounts, 67 mapped) and 64 turns of each closure loop, where a
/// loop over every entry is 64 * 67 = 4,288 turns and a preparation a
/// closure 64 * 67 of each pass. A closure's own BEEF is refreshed by its
/// sort and checked by its `check_writable`, so each closure adds the
/// entries it keeps to those two counts, and none to the map's.
#[test]
fn a_batch_prepares_once_and_each_closure_visits_only_what_it_keeps_817() {
    let (mut beef, proven, tip) = many(64);
    assert_eq!(beef.txs.len(), 67);
    cost::take();
    let batch = beef.atomic_batch().unwrap();
    let prepared = cost::take();
    assert_eq!(prepared.passes(), (67, 67, 67));
    assert_eq!(prepared.loops(), (0, 0));
    for txid in &proven {
        batch.to_binary_atomic(txid).unwrap();
    }
    let cut = cost::take();
    // No pass over the BEEF again: each closure's own one entry, at its
    // sort and at its `check_writable`, and no entry mapped.
    assert_eq!(cut.passes(), (64, 64, 0));
    assert_eq!(cut.loops(), (64, 64));
    // The chain's tip keeps itself, its two unproven parents and the proven
    // root: four of the 67.
    batch.to_binary_atomic(&tip).unwrap();
    let cut = cost::take();
    assert_eq!(cut.passes(), (4, 4, 0));
    assert_eq!(cut.loops(), (4, 4));
    // A subject not held prepares nothing and visits nothing.
    batch.to_binary_atomic(ABSENT).unwrap_err();
    assert_eq!(cost::take(), cost::Cost::default());
}

/// The per-call door is a batch of one: the three passes a call (67
/// entries each, and the closure's own entries refreshed by its sort and
/// checked for their amounts beside them), and its closure's loops visit
/// what it keeps (each of them
/// every entry of the BEEF until #817: 67 turns for a closure of one).
#[test]
fn the_per_call_door_visits_only_the_closure_it_keeps_817() {
    let (mut beef, proven, tip) = many(64);
    cost::take();
    beef.to_binary_atomic(&proven[7]).unwrap();
    let call = cost::take();
    assert_eq!(call.passes(), (67 + 1, 67 + 1, 67));
    assert_eq!(call.loops(), (1, 1));
    beef.to_binary_atomic(&tip).unwrap();
    let call = cost::take();
    assert_eq!(call.passes(), (67 + 4, 67 + 4, 67));
    assert_eq!(call.loops(), (4, 4));
}

/// The refusal order of both doors: an output of 2^53 satoshis anywhere in
/// the BEEF is refused ahead of a subject the BEEF does not hold, in the
/// writer's words; without it, the subject's own words.
#[test]
fn the_amount_refusal_stands_ahead_of_a_subject_not_held_on_both_doors_817() {
    let (mut beef, proven, _) = many(2);
    let not_held = crate::Error::BeefError(format!("{ABSENT} does not exist in this Beef"));
    assert_eq!(beef.to_binary_atomic(ABSENT).unwrap_err(), not_held);
    assert_eq!(
        beef.atomic_batch()
            .unwrap()
            .to_binary_atomic(ABSENT)
            .unwrap_err(),
        not_held
    );

    beef.edit_tx(&proven[1], |tx| {
        tx.outputs_mut()[0].satoshis = Some(1 << 53)
    })
    .unwrap();
    let amount = crate::Error::BeefError("The number is larger than 2 ^ 53 (unsafe)".to_string());
    assert_eq!(beef.to_binary_atomic(ABSENT).unwrap_err(), amount);
    assert_eq!(beef.to_binary_atomic(&proven[0]).unwrap_err(), amount);
    assert_eq!(beef.atomic_batch().map(drop).unwrap_err(), amount);
}

/// The closure's walk reads the entries by a map of their txids, never the
/// BEEF's index: a parent put into `txs` by hand, in the place of an entry
/// the index was built for, is a txid the index was never given (the stated
/// window of `beef/index.rs`), and the per-call door has always kept it in
/// its child's closure. Both doors keep it still.
#[test]
fn a_parent_the_index_was_never_given_stays_in_its_childs_closure_817() {
    let parent = spending(&"17".repeat(32));
    let child = spending(&parent.id());
    let other = spending(&"18".repeat(32));
    let mut beef = Beef::new();
    beef.merge_raw_tx(child.to_binary(), None).unwrap();
    beef.merge_raw_tx(other.to_binary(), None).unwrap();
    beef.txs[1] = BeefTx::from_raw_tx(parent.to_binary(), None).unwrap();
    assert!(beef.find_txid(&parent.id()).is_none(), "inside the window");

    let expected = oracle(&mut beef.clone(), &child.id()).unwrap();
    let closure = Beef::from_binary(&expected).unwrap();
    assert_eq!(closure.txs.len(), 2, "the child and its parent");
    assert_eq!(
        beef.clone().to_binary_atomic(&child.id()).unwrap(),
        expected
    );
    let batch = beef.atomic_batch().unwrap();
    assert_eq!(batch.to_binary_atomic(&child.id()).unwrap(), expected);
    // The parent as a subject is not found, by either door, as before.
    assert_eq!(
        batch.to_binary_atomic(&parent.id()).unwrap_err(),
        oracle(&mut beef.clone(), &parent.id()).unwrap_err()
    );
}
