//! The link bound (bsv-rs #749).
//!
//! Linking a BEEF hands every repeat input that spends an already-linked parent
//! a clone of that parent (its outputs are what the input spends), so a shared
//! parent of N outputs spent by M separate inputs re-materializes M×N output
//! bytes — a cost that grows with the PRODUCT, not the sum. A small answer well
//! within a resolver's byte bound can therefore force multi-gigabyte heap, an
//! out-of-memory kill or an uncatchable wasm32 abort, reached through the
//! overlay lookup resolver and every other door that parses a stranger's BEEF.
//!
//! So `Transaction::from_beef` / `find_atomic_transaction` cap, in ABSOLUTE
//! BYTES, how far linking may re-materialize a shared parent beyond the BEEF's
//! own bytes (closed by default at 16 MiB) and refuse an answer that would blow
//! past it — BEFORE the clone that would cross the budget — with a resource
//! error of its own class (`Error::BeefResourceLimit`), never a silent "not
//! found". A byte budget (not a count of output slots) charges a parent of a
//! few large outputs its true weight, so a sub-megabyte BEEF of few large
//! outputs cannot slip a Worker-OOM re-materialization past the bound. An
//! honest BEEF re-materializes a few hundred KiB at most, so the default
//! refuses none of them; a caller that trusts the source opts out with
//! `BeefLinkLimits::unbounded`.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a failed expect is the test failing

use bsv_rs::script::{LockingScript, UnlockingScript};
use bsv_rs::transaction::{
    Beef, BeefLinkBudget, BeefLinkLimits, MerklePath, Transaction, TransactionInput,
    TransactionOutput,
};
use bsv_rs::Error;

const SATS: u64 = 1_000;

fn op_true() -> LockingScript {
    LockingScript::from_binary(&[0x51]).expect("OP_TRUE")
}

/// A locking script of `bytes` filler opcodes (`OP_0`), so an output can be
/// given a chosen wire weight — the byte budget charges its true size.
fn filler_script(bytes: usize) -> LockingScript {
    LockingScript::from_binary(&vec![0u8; bytes]).expect("filler locking script")
}

/// A transaction spending each `(txid, vout)` with an empty unlock and paying
/// `outputs` outputs of `SATS` each carrying `script`.
fn spend(spends: &[(String, u32)], outputs: usize, script: &LockingScript) -> Transaction {
    let mut tx = Transaction::new();
    for (txid, vout) in spends {
        let mut input = TransactionInput::new(txid.clone(), *vout);
        input.unlocking_script = Some(UnlockingScript::new());
        tx.inputs_mut().push(input);
    }
    for _ in 0..outputs {
        tx.outputs_mut()
            .push(TransactionOutput::new(SATS, script.clone()));
    }
    tx
}

/// A BEEF whose one proven parent carries `outputs` outputs each of
/// `output_script` bytes, the first `spends` of them each spent by a separate
/// input of one unproven child; the subject is the child. Built by this crate's
/// own writer, so it cannot drift from the wire format. This is the
/// shared-parent shape the bound guards, sized only to what a test needs to
/// cross or clear the bound — never a weaponized answer.
fn shared_parent_beef(
    outputs: usize,
    spends: usize,
    output_script: &LockingScript,
) -> (Vec<u8>, String) {
    let (beef, child, _parent_wire) = shared_parent_beef_wire(outputs, spends, output_script);
    (beef, child)
}

/// As [`shared_parent_beef`], also returning the parent's wire size — the exact
/// bytes each repeat input re-materializes, so a shared-pool test can size the
/// pool to hold precisely one link's worth and no more.
fn shared_parent_beef_wire(
    outputs: usize,
    spends: usize,
    output_script: &LockingScript,
) -> (Vec<u8>, String, u64) {
    assert!(spends <= outputs);
    let parent = spend(&[("aa".repeat(32), 0)], outputs, output_script);
    let parent_txid = parent.id();
    let parent_wire = parent.to_binary().len() as u64;
    let mut beef = Beef::new();
    let bump = beef.merge_bump(MerklePath::from_coinbase_txid(&parent_txid, 800_000));
    beef.merge_raw_tx(parent.to_binary(), Some(bump))
        .expect("the parent is one transaction");
    let outpoints: Vec<(String, u32)> = (0..spends)
        .map(|i| (parent_txid.clone(), i as u32))
        .collect();
    let child = spend(&outpoints, 1, &op_true());
    let child_txid = child.id();
    beef.merge_raw_tx(child.to_binary(), None)
        .expect("the child is one transaction");
    (
        beef.to_binary().expect("the BEEF is writable"),
        child_txid,
        parent_wire,
    )
}

/// How many of the subject's inputs linked to a source transaction.
fn linked_inputs(tx: &Transaction) -> usize {
    tx.inputs()
        .iter()
        .filter(|i| i.source_transaction.is_some())
        .count()
}

#[test]
fn a_shared_parent_of_large_outputs_is_refused_by_the_default_byte_bound() {
    // 160 outputs of ~2 KiB each spent by 160 inputs re-materializes ~160×2 KiB
    // × 159 ≈ 50 MB of stub clones, past the default 16 MiB byte budget. The
    // default `from_beef` refuses it rather than let a ~330 KiB answer force
    // tens of megabytes of heap. (The slot bound this folds over admitted a
    // few-large-output shape — 1 slot per output regardless of its bytes.)
    let (bytes, _child) = shared_parent_beef(160, 160, &filler_script(2 * 1024));
    let err = Transaction::from_beef(&bytes, None)
        .expect_err("the default bound refuses a shared parent amplified past its byte budget");
    assert!(
        matches!(err, Error::BeefResourceLimit(_)),
        "the refusal is a resource limit of its own class, not {err:?}"
    );
}

#[test]
fn the_refusal_is_a_resource_limit_not_an_absent_or_invalid_beef() {
    // A resource decline must read as neither "invalid BEEF" (`BeefError`) nor
    // "absent txid" (`Ok(None)`), on every door that can carry an error. An
    // explicit small budget keeps this fast.
    let small = BeefLinkLimits::default().with_max_link_bytes(Some(64 * 1024));
    let (bytes, child) = shared_parent_beef(20, 20, &filler_script(16 * 1024));

    let err =
        Transaction::from_beef_with_limits(&bytes, None, &small).expect_err("over the byte budget");
    assert!(
        matches!(err, Error::BeefResourceLimit(_)),
        "named resource class, not {err:?}"
    );

    let beef = Beef::from_binary(&bytes).expect("the BEEF parses");
    let trip = beef
        .find_atomic_transaction_limited(&child, &small)
        .unwrap_err();
    assert!(
        matches!(trip, Error::BeefResourceLimit(_)),
        "named resource class, not {trip:?}"
    );
    // An absent txid is a told-apart Ok(None), never the resource error.
    assert!(beef
        .find_atomic_transaction_limited("ab".repeat(32).as_str(), &small)
        .expect("an absent txid is Ok(None), not an error")
        .is_none());
}

#[test]
fn an_honest_full_sweep_consolidation_links_under_the_default_byte_bound() {
    // A child sweeping all 200 small outputs of one parent — an ordinary BSV
    // consolidation — links by default. The folded-over slot bound REFUSED a
    // full sweep at ≥105 outputs (64×N+4096 < N×N); the byte budget, charging
    // ~10 B per OP_TRUE output, admits this ~400 KiB of re-materialization with
    // room to spare, so a legitimate high-fan sweep is no longer refused.
    let (bytes, child) = shared_parent_beef(200, 200, &op_true());
    let tx = Transaction::from_beef(&bytes, None)
        .expect("an honest 200-output consolidation links under the default byte bound");
    assert_eq!(tx.id(), child);
    assert_eq!(
        linked_inputs(&tx),
        200,
        "every swept output linked to the parent"
    );
}

#[test]
fn a_few_large_outputs_the_slot_count_would_admit_are_refused_by_the_byte_budget() {
    // The strength read's byte-blind shape: a parent of a few large outputs
    // spent by a modest number of inputs. A SLOT count admits it (few slots,
    // under any floor); the BYTE budget charges each repeat its true weight and
    // refuses it. An explicit 256 KiB budget stands in for the proportionality
    // the default has at 16 MiB, kept small so the test is fast.
    let budget = BeefLinkLimits::default().with_max_link_bytes(Some(256 * 1024));
    // 8 outputs of 32 KiB spent by 8 inputs: 7 repeats × ~256 KiB ≈ 1.8 MiB of
    // re-materialization — far past 256 KiB — yet only 7 output slots.
    let (bytes, _child) = shared_parent_beef(8, 8, &filler_script(32 * 1024));
    let err = Transaction::from_beef_with_limits(&bytes, None, &budget)
        .expect_err("a few large outputs re-materialize past the byte budget");
    assert!(matches!(err, Error::BeefResourceLimit(_)), "not {err:?}");
}

#[test]
fn the_refused_shared_parent_links_when_the_bound_is_lifted() {
    // The same answer links in full for a caller that trusts its source and
    // opts out: the bound is a default, not a wall.
    let (bytes, child) = shared_parent_beef(20, 20, &filler_script(16 * 1024));
    let tx = Transaction::from_beef_with_limits(&bytes, None, &BeefLinkLimits::unbounded())
        .expect("an unbounded link accepts the shared parent");
    assert_eq!(tx.id(), child);
    assert_eq!(linked_inputs(&tx), 20, "every input linked to the parent");
}

#[test]
fn an_honest_two_input_covenant_plus_change_links_by_default() {
    // The ordinary wallet shape — a covenant output and that transaction's own
    // change, two inputs sourcing one parent — is far under the bound and links
    // by default, as it always has.
    let (bytes, child) = shared_parent_beef(2, 2, &op_true());
    let tx =
        Transaction::from_beef(&bytes, None).expect("an honest shared parent links by default");
    assert_eq!(tx.id(), child);
    assert_eq!(linked_inputs(&tx), 2);
}

#[test]
fn the_resolver_subject_door_links_nothing_and_is_never_refused() {
    // The overlay lookup resolver reads only a subject's txid / an output, never
    // the ancestry, so it takes `from_beef_subject` — which parses WITHOUT
    // linking. A shared-parent answer the default `from_beef` refuses is read
    // by the subject door at zero cost: the resolver links nothing on an
    // untrusted answer (the #749 door closed, not merely bounded).
    let (bytes, child) = shared_parent_beef(160, 160, &filler_script(2 * 1024));
    assert!(
        matches!(
            Transaction::from_beef(&bytes, None),
            Err(Error::BeefResourceLimit(_))
        ),
        "the linking door refuses the shared parent"
    );
    let subject = Transaction::from_beef_subject(&bytes, None)
        .expect("the subject door parses the same answer without linking");
    assert_eq!(subject.id(), child);
    assert_eq!(linked_inputs(&subject), 0, "the subject door links nothing");
}

#[test]
fn the_default_per_link_budget_is_16_mib_with_headroom_above_any_honest_input() {
    // Ruling 3 (fold2): the per-link default is 16 MiB, pinned exactly — one
    // named constant, so a change that moves it turns this red.
    assert_eq!(BeefLinkLimits::DEFAULT_MAX_LINK_BYTES, 16 * 1024 * 1024);
    assert_eq!(
        BeefLinkLimits::default().max_link_bytes,
        Some(16 * 1024 * 1024)
    );
    // The headroom it leaves: the largest shared-parent fan any real dependent
    // BEEF carries is 20, and the default admits a same-parent sweep far above
    // that. A 300-output OP_TRUE consolidation (15× the largest real fan) links
    // by default; a default low enough to refuse it would turn this red, so the
    // single-link headroom cannot be quietly erased. (The onset fell from 500+
    // when the #749 fold-c began charging the HEAP a repeat clone holds, not its
    // wire bytes — see `the_default_headroom_is_stated_per_output_size` — but it
    // stays well above any honest input.)
    let (bytes, child) = shared_parent_beef(300, 300, &op_true());
    let tx = Transaction::from_beef(&bytes, None)
        .expect("the default leaves headroom for a 300-output honest sweep");
    assert_eq!(tx.id(), child);
    assert_eq!(linked_inputs(&tx), 300);
}

#[test]
fn the_default_headroom_is_stated_per_output_size() {
    // Ruling 4 (fold2): the honest reach the per-link default admits is stated
    // by OUTPUT SIZE, not as one "general" figure — the onset of an honest
    // same-parent single-child sweep falls as the output grows, so no single
    // number reads as the general case. These cells — the largest N outputs of
    // one parent a single child can sweep before the link is refused — are
    // measured by this crate's own writer and pinned EXACTLY, so a metering
    // change that eroded any of them turns this red. The link.rs doc, the
    // CHANGELOG, the advisory and the relay figures state the same numbers.
    //
    // (output-script bytes, 16 MiB default onset, 32 MiB onset). 25 B is a
    // plain-payment (P2PKH) locking script's exact size; 256 B and 1 KiB are
    // data-carrying outputs.
    // The #749 fold-c meters the HEAP a repeat clone holds — the output and input
    // struct `Vec` backings, and the proof's leaf structs — not its wire bytes
    // alone, so the budget now bounds the heap the link re-materializes (it held
    // ~248 MB on a ~57 KB answer before, past the 128 MB Worker isolate; ~18 MB
    // now). A one-byte-locked output is ~10 wire bytes but ~150 heap bytes, so
    // the onsets fell well below their wire-meter values (P2PKH 701→313, 992→443)
    // — the honest reach is still ≥15× the largest shared-parent fan (20) any
    // real dependent BEEF carries, but the heap a hostile answer can hold is now
    // a small multiple of the budget, not hundreds of MB. These cells are
    // measured by this crate's own writer and pinned EXACTLY; the link.rs doc,
    // the CHANGELOG and the advisory state the same numbers.
    let cells: &[(usize, usize, usize)] = &[(25, 313, 443), (256, 203, 288), (1024, 119, 169)];
    for &(script_bytes, onset16, onset32) in cells {
        let script = filler_script(script_bytes);
        // The shipped default (16 MiB) admits exactly `onset16` and refuses one
        // more.
        assert_onset(&script, None, onset16);
        // An explicit 32 MiB budget admits exactly `onset32` and refuses one
        // more — the other column of the owner's 16-vs-32 table.
        assert_onset(&script, Some(32 * 1024 * 1024), onset32);
    }
}

/// Asserts the largest same-parent sweep that links is exactly `onset`: the
/// onset-wide sweep links, the next (`onset + 1`) is refused. `budget` is `None`
/// for the shipped default (`from_beef`) or `Some(bytes)` for an explicit limit.
fn assert_onset(script: &LockingScript, budget: Option<u64>, onset: usize) {
    let link = |n: usize| -> Result<Transaction, Error> {
        let (bytes, child) = shared_parent_beef(n, n, script);
        let tx = match budget {
            None => Transaction::from_beef(&bytes, None)?,
            Some(b) => {
                let limits = BeefLinkLimits::default().with_max_link_bytes(Some(b));
                Transaction::from_beef_with_limits(&bytes, None, &limits)?
            }
        };
        assert_eq!(tx.id(), child, "the linked subject is the child");
        Ok(tx)
    };
    let tx = link(onset)
        .unwrap_or_else(|e| panic!("the default admits an {onset}-output honest sweep, got {e:?}"));
    assert_eq!(
        linked_inputs(&tx),
        onset,
        "every swept output of the onset linked"
    );
    let err = link(onset + 1).expect_err("one output past the onset is refused");
    assert!(
        matches!(err, Error::BeefResourceLimit(_)),
        "the refusal past the onset is a resource limit, not {err:?}"
    );
}

#[test]
fn a_beef_link_budget_has_three_forms_per_link_shared_and_unbounded() {
    // Ruling 2 (fold2): one value, three forms. The per-link form (the default)
    // bounds each link on its own; the unbounded form lifts the bound; a hostile
    // shape the per-link default refuses links when unbounded.
    let (hostile, _child) = shared_parent_beef(160, 160, &filler_script(2 * 1024));
    assert!(
        matches!(
            Transaction::from_beef_with_budget(&hostile, None, &BeefLinkBudget::per_link()),
            Err(Error::BeefResourceLimit(_))
        ),
        "the per-link default refuses the hostile shared parent"
    );
    assert!(
        Transaction::from_beef_with_budget(&hostile, None, &BeefLinkBudget::unbounded()).is_ok(),
        "the unbounded form links the same answer"
    );
    // A caller that passes nothing keeps the per-link default: a plain from_beef
    // and the per-link budget agree.
    let (honest, child) = shared_parent_beef(2, 2, &op_true());
    assert_eq!(
        Transaction::from_beef_with_budget(&honest, None, &BeefLinkBudget::per_link())
            .expect("per-link admits an honest shape")
            .id(),
        child
    );
    assert!(BeefLinkBudget::per_link().remaining().is_none());
}

#[test]
fn a_shared_budget_caps_the_total_across_concurrent_links_and_refills_on_release() {
    // Ruling 2 (fold2): k near-budget links drawing on ONE shared pool. Each
    // link re-materializes `(spends - 1)` parent-wide stubs; the pool holds just
    // over one such link, so the first fits, the second — which would overdraw
    // it — is refused with the named resource error BEFORE it allocates, and the
    // first's share returns to the pool when it is dropped, admitting the next.
    let (bytes, subject, parent_wire) = shared_parent_beef_wire(20, 20, &filler_script(4 * 1024));
    // Measure one link's exact draw — its ~19 re-materialized parent-wide stubs
    // AND the proof the #749 fold now charges — from a default-sized pool, read
    // while the link is still alive (its reservation held), then released.
    let gauge = BeefLinkBudget::shared(BeefLinkLimits::DEFAULT_MAX_LINK_BYTES);
    let gauged = Transaction::from_beef_with_budget(&bytes, None, &gauge)
        .expect("one link fits a default-sized pool");
    let one_link = BeefLinkLimits::DEFAULT_MAX_LINK_BYTES
        - gauge
            .remaining()
            .expect("the shared pool reports its remaining bytes");
    drop(gauged);
    assert!(
        one_link < BeefLinkLimits::DEFAULT_MAX_LINK_BYTES,
        "one link stays under the per-link cap the shared budget also enforces"
    );
    assert!(
        parent_wire < one_link,
        "one parent's bytes are the slack, smaller than a whole link"
    );
    // Room for one link and no more (a second needs a whole link, past the slack).
    let pool = BeefLinkBudget::shared(one_link + parent_wire);

    let first = Transaction::from_beef_with_budget(&bytes, None, &pool)
        .expect("the first link fits the shared pool");
    assert_eq!(first.id(), subject);
    assert_eq!(
        pool.remaining(),
        Some(parent_wire),
        "the pool drew down by one link"
    );

    let err = Transaction::from_beef_with_budget(&bytes, None, &pool)
        .expect_err("a second concurrent link would overdraw the shared pool");
    assert!(matches!(err, Error::BeefResourceLimit(_)), "not {err:?}");
    assert_eq!(
        pool.remaining(),
        Some(parent_wire),
        "the refused link returned its partial reservation; the pool is unchanged"
    );

    drop(first); // the first link is done: its share returns to the pool
    assert_eq!(
        pool.remaining(),
        Some(one_link + parent_wire),
        "dropping a linked transaction refills the shared pool by exactly its share"
    );
    let second = Transaction::from_beef_with_budget(&bytes, None, &pool)
        .expect("after the first is dropped, the next link is admitted");
    assert_eq!(second.id(), subject);
}
