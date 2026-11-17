//! The link bound must see the BUMP, not the transaction bytes alone
//! (bsv-rs #749 fold — the sibling of the shared-parent output amplification).
//!
//! Linking attaches a BEEF's proof (`MerklePath`) to every proven transaction
//! it links and to every stub a repeat input spends. A transaction's
//! `to_binary` serializes only its four fields, never the attached path, so the
//! #749 stub byte-meter — which charges `stub.to_binary().len()` — did not weigh
//! the BUMP at all. A BEEF of K proven parents sharing ONE K-leaf BUMP therefore
//! holds ~2K deep copies of that O(K) path (one per parent linked, one per
//! map-held stub), none of them charged: the default `from_beef` links it with
//! `Ok`, re-materializing O(K^2) heap from a small answer — the same
//! out-of-memory kill / wasm32 abort the parent bound was shipped to refuse,
//! reached through the overlay lookup resolver and every other door that parses
//! a stranger's BEEF.
//!
//! These fixtures are built by this crate's own writer and reader, so they
//! cannot drift from the wire format, and the BUMP is the exact shape a measured
//! probe reached quadratic heap on — K distinct proven parents at one BUMP's
//! level 0, a subject spending one output of each (no repeat inputs at all, so
//! the stub byte-meter charges nothing before the fix). Sized only to what each
//! test needs to cross or clear the bound, never a weaponized answer.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a failed expect is the test failing

use bsv_rs::script::{LockingScript, UnlockingScript};
use bsv_rs::transaction::{
    Beef, BeefLinkLimits, MerklePath, MerklePathLeaf, Transaction, TransactionInput,
    TransactionOutput,
};
use bsv_rs::Error;

const SATS: u64 = 1_000;

fn op_true() -> LockingScript {
    LockingScript::from_binary(&[0x51]).expect("OP_TRUE")
}

/// A BEEF whose `parents` distinct transactions are all proven by ONE BUMP
/// (each at its level 0), with an unproven subject spending output 0 of every
/// one of them — one input per parent, so no two inputs spend the same parent
/// and the repeat-input stub meter never fires. Returns the BEEF bytes and the
/// subject's txid. Built by this crate's own writer (`to_binary`) and parsed
/// back by `from_beef`, the BUMP assembled from the crate's own `MerklePath`.
fn shared_bump_beef(parents: usize) -> (Vec<u8>, String) {
    assert!(
        parents.is_power_of_two(),
        "the BUMP's tree height is log2(parents)"
    );
    // One tiny transaction per parent, each with a distinct txid (a distinct
    // prevout) and one spendable OP_TRUE output.
    let parents: Vec<Transaction> = (0..parents)
        .map(|i| {
            let mut p = Transaction::new();
            let mut input = TransactionInput::new(format!("{:064x}", i + 1), 0);
            input.unlocking_script = Some(UnlockingScript::new());
            p.inputs_mut().push(input);
            p.outputs_mut()
                .push(TransactionOutput::new(SATS, op_true()));
            p
        })
        .collect();

    // ONE BUMP proving all of them: every parent's txid is a level-0 leaf, the
    // higher levels empty up to the tree height, as a probe built it.
    let leaves: Vec<MerklePathLeaf> = parents
        .iter()
        .enumerate()
        .map(|(i, p)| MerklePathLeaf::new_txid(i as u64, p.id()))
        .collect();
    let height = parents.len().trailing_zeros() as usize;
    let mut path = vec![leaves];
    for _ in 1..height {
        path.push(Vec::new());
    }
    let bump = MerklePath::new(800_000, path).expect("one BUMP proving every parent");

    let mut beef = Beef::new();
    let bump_index = beef.merge_bump(bump);
    for p in &parents {
        beef.merge_raw_tx(p.to_binary(), Some(bump_index))
            .expect("each parent is one transaction");
    }

    // The subject spends output 0 of every parent: one input per parent, all
    // distinct, so every parent is linked exactly once (no repeat inputs).
    let mut subject = Transaction::new();
    for p in &parents {
        let mut input = TransactionInput::new(p.id(), 0);
        input.unlocking_script = Some(UnlockingScript::new());
        subject.inputs_mut().push(input);
    }
    subject
        .outputs_mut()
        .push(TransactionOutput::new(SATS, op_true()));
    let subject_txid = subject.id();
    beef.merge_raw_tx(subject.to_binary(), None)
        .expect("the subject is one transaction");

    (
        beef.to_binary().expect("the BEEF is writable"),
        subject_txid,
    )
}

#[test]
fn a_shared_bump_cloned_per_proven_parent_is_refused_by_the_byte_bound_749b() {
    // 64 proven parents sharing one 64-leaf BUMP (~2.3 KiB). The fix charges
    // the BUMP at each of the ~2*64 clones (~290 KiB), far past this explicit
    // 128 KiB budget. BEFORE the fix the stub meter weighs only the four
    // transaction fields — never the attached path — and these inputs never
    // repeat a parent, so NOTHING is charged and the BEEF links with `Ok`.
    let budget = BeefLinkLimits::default().with_max_link_bytes(Some(128 * 1024));
    let (bytes, subject) = shared_bump_beef(64);

    let err = Transaction::from_beef_with_limits(&bytes, Some(&subject), &budget)
        .expect_err("the BUMP cloned once per proven parent re-materializes past the byte budget");
    assert!(
        matches!(err, Error::BeefResourceLimit(_)),
        "the refusal is a resource limit of its own class, not {err:?}"
    );

    // Told apart from an absent txid (`Ok(None)`) and an invalid BEEF on the
    // Beef door too.
    let beef = Beef::from_binary(&bytes).expect("the BEEF parses");
    let trip = beef
        .find_atomic_transaction_limited(&subject, &budget)
        .expect_err("the Beef door refuses the same amplified BUMP");
    assert!(
        matches!(trip, Error::BeefResourceLimit(_)),
        "named resource class, not {trip:?}"
    );
    assert!(
        beef.find_atomic_transaction_limited("ab".repeat(32).as_str(), &budget)
            .expect("an absent txid is Ok(None), not the resource error")
            .is_none(),
        "an absent txid stays a told-apart Ok(None)"
    );
}

#[test]
fn the_refused_shared_bump_links_when_the_bound_is_lifted_749b() {
    // The same answer links in full for a caller that trusts its source and
    // opts out: the bound is a default, not a wall. (Every parent linked;
    // the subject's inputs each carry their source.)
    let (bytes, subject) = shared_bump_beef(64);
    let tx =
        Transaction::from_beef_with_limits(&bytes, Some(&subject), &BeefLinkLimits::unbounded())
            .expect("an unbounded link accepts the shared BUMP");
    assert_eq!(tx.id(), subject);
    assert_eq!(
        tx.inputs()
            .iter()
            .filter(|i| i.source_transaction.is_some())
            .count(),
        64,
        "every proven parent linked to the subject"
    );
}

#[test]
fn an_honest_single_proven_parent_links_under_the_default_bound_749b() {
    // The ordinary SPV shape — one proven ancestor under a small BUMP — carries
    // a few dozen proof bytes, far under the default 16 MiB, so charging the
    // BUMP refuses none of it. One parent, one two-leaf-shaped BUMP, the subject
    // spends its single output.
    let mut parent = Transaction::new();
    let mut pin = TransactionInput::new("11".repeat(32), 0);
    pin.unlocking_script = Some(UnlockingScript::new());
    parent.inputs_mut().push(pin);
    parent
        .outputs_mut()
        .push(TransactionOutput::new(SATS, op_true()));
    let parent_txid = parent.id();

    let mut beef = Beef::new();
    let bump_index = beef.merge_bump(MerklePath::from_coinbase_txid(&parent_txid, 800_000));
    beef.merge_raw_tx(parent.to_binary(), Some(bump_index))
        .expect("the parent is one transaction");

    let mut subject = Transaction::new();
    let mut sin = TransactionInput::new(parent_txid.clone(), 0);
    sin.unlocking_script = Some(UnlockingScript::new());
    subject.inputs_mut().push(sin);
    subject
        .outputs_mut()
        .push(TransactionOutput::new(SATS, op_true()));
    let subject_txid = subject.id();
    beef.merge_raw_tx(subject.to_binary(), None)
        .expect("the subject is one transaction");
    let bytes = beef.to_binary().expect("the BEEF is writable");

    let tx = Transaction::from_beef(&bytes, Some(&subject_txid))
        .expect("an honest single-proof BEEF links under the default bound");
    assert_eq!(tx.id(), subject_txid);
}
