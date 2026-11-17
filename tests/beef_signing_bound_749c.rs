//! `Beef::find_transaction_for_signing` hands every input that names a held
//! parent a FULL clone of that parent, unmetered until the #749 fold-c: a
//! parent of many outputs named by many inputs is cloned once per input, the
//! same shared-parent re-materialization `add_input_proof` bounds, reached
//! through the signing door too (a caller signing against an untrusted BEEF —
//! owner's standard, "row 6 is IN"). The fold meters the wire and heap each
//! clone holds under the default link bounds and yields `None` on a trip, as
//! `find_atomic_transaction` yields `None` when linking would overrun its
//! default bound. Built by this crate's own writer; hermetic.

use bsv_rs::script::LockingScript;
use bsv_rs::transaction::{Beef, Transaction, TransactionInput, TransactionOutput};

fn op_true() -> LockingScript {
    LockingScript::from_binary(&[0x51]).unwrap()
}

/// A parent of `outs` outputs, and a child whose `ins` inputs each NAME that
/// parent (by txid, with no source transaction) so the signing door links them.
/// The BEEF holds both.
fn signing_beef(outs: u32, ins: u32) -> (Vec<u8>, String) {
    let mut parent = Transaction::new();
    parent
        .add_input(TransactionInput::new(format!("{:064x}", 7u64), 0))
        .unwrap();
    for _ in 0..outs {
        parent
            .add_output(TransactionOutput::new(1, op_true()))
            .unwrap();
    }
    let pid = parent.id();

    let mut child = Transaction::new();
    for k in 0..ins {
        child
            .add_input(TransactionInput::new(pid.clone(), k))
            .unwrap();
    }
    child
        .add_output(TransactionOutput::new(1, op_true()))
        .unwrap();
    let cid = child.id();

    let mut beef = Beef::new();
    beef.merge_raw_tx(parent.to_binary(), None)
        .expect("the parent is one transaction");
    beef.merge_raw_tx(child.to_binary(), None)
        .expect("the child is one transaction");
    (beef.to_binary().expect("the BEEF is writable"), cid)
}

#[test]
fn find_transaction_for_signing_refuses_a_shared_parent_re_materialization_749c() {
    // A 700-output parent named by 600 inputs: ~600 full clones of all 700
    // outputs, ~62 MB of heap past the 56 MiB default. BEFORE the fold-c the
    // signing door clones each unmetered and answers `Some`. The fold meters
    // the clones and answers `None`, as linking a BEEF that would overrun the
    // default does.
    let (bytes, child) = signing_beef(700, 600);
    let beef = Beef::from_binary(&bytes).expect("the BEEF parses");
    assert!(
        beef.find_transaction_for_signing(&child).is_none(),
        "the signing door bounds the shared-parent re-materialization"
    );
}

#[test]
fn find_transaction_for_signing_still_links_an_honest_small_signing_beef_749c() {
    // The honest case the door exists for: a child with a few inputs naming a
    // small parent links every source and answers `Some`, unchanged.
    let (bytes, child) = signing_beef(2, 2);
    let beef = Beef::from_binary(&bytes).expect("the BEEF parses");
    let linked = beef
        .find_transaction_for_signing(&child)
        .expect("an honest small signing BEEF still links its sources");
    assert_eq!(linked.id(), child);
    assert!(
        linked
            .inputs()
            .iter()
            .all(|i| i.source_transaction.is_some()),
        "every named source was linked"
    );
}
