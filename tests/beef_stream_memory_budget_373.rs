//! The streaming reader takes the caller's memory budget for its scripts, as
//! `Transaction::verify` does since bsv-rs#331 (bsv-rs#373, the keeper's word
//! of 2026-10-27 under the owner's ruling (c)): `None` uncapped, `Some(n)` the
//! caller's local budget per input's stacks, a decline
//! (`SpendRefusal::Resource`) naming the transaction and the input, never a
//! verdict; local configuration, absent from the cursor; the structure-only
//! reader runs no script and spends none.
//!
//! The fixture is the crate's own writer's: a parent proven by a one-leaf
//! BUMP (its txid the root) and a version-2 subject (the default mode's
//! relaxed rules) whose unlocking script pushes 600 bytes and whose parent's
//! locking script duplicates them (1,200 bytes on the stack) before it
//! drops both and pushes its answer. Every outpoint is synthetic.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use std::collections::HashMap;

use bsv_rs::script::{LockingScript, Script, ScriptResource, ScriptResourceLimit, UnlockingScript};
use bsv_rs::transaction::beef_stream::{AsyncByteSource, Hash32, SpendRefusal};
use bsv_rs::transaction::{
    AsyncStreamVerifier, MerklePath, MockChainTracker, Progress, StreamVerifier, Transaction,
    TransactionInput, TransactionOutput, Verdict,
};

const HEIGHT: u32 = 800_000;
const PUSHED: usize = 600;
/// Above the push, below the duplicate: the push fits, `OP_DUP` does not.
const BUDGET: usize = 1_000;
const OP_DUP: u8 = 0x76;
const OP_2DROP: u8 = 0x6d;
const OP_0: u8 = 0x00;
const OP_1: u8 = 0x51;

struct Fixture {
    beef: Vec<u8>,
    headers: HashMap<u64, Hash32>,
    subject: Hash32,
}

/// The BEEF: the parent's output locked by `OP_DUP OP_2DROP <answer>`, the
/// subject spending it with a 600-byte push.
fn fixture(answer: u8) -> Fixture {
    let mut lock = Script::new();
    lock.write_opcode(OP_DUP)
        .write_opcode(OP_2DROP)
        .write_opcode(answer);
    let mut parent = Transaction::new();
    let mut phantom = TransactionInput::new("aa".repeat(32), 0);
    phantom.set_unlocking_script(UnlockingScript::new());
    parent.add_input(phantom).unwrap();
    parent
        .add_output(TransactionOutput::new(
            1_000,
            LockingScript::from_binary(&lock.to_binary()).unwrap(),
        ))
        .unwrap();
    parent.merkle_path = Some(MerklePath::from_coinbase_txid(&parent.id(), HEIGHT));
    let root = parent.hash();

    let mut unlock = Script::new();
    unlock.write_bin(&[0x5a; PUSHED]);
    let mut input = TransactionInput::with_source_transaction(parent, 0);
    input.set_unlocking_script(UnlockingScript::from_binary(&unlock.to_binary()).unwrap());
    let mut subject = Transaction::new();
    subject.version = 2;
    subject.add_input(input).unwrap();
    subject
        .add_output(TransactionOutput::new(
            900,
            LockingScript::from_binary(&[OP_1]).unwrap(),
        ))
        .unwrap();
    Fixture {
        beef: subject.to_beef(false).unwrap(),
        headers: HashMap::from([(u64::from(HEIGHT), root)]),
        subject: subject.hash(),
    }
}

/// The interpreter's figures for the subject's input under `BUDGET`: the
/// 600-byte push held, the duplicate asked for.
fn expected_limit() -> ScriptResourceLimit {
    ScriptResourceLimit {
        resource: ScriptResource::Stack,
        limit: BUDGET as u64,
        attempted: 2 * PUSHED as u64,
        work_spent: None,
    }
}

fn assert_declined(verdict: Verdict, subject: &Hash32) {
    match verdict {
        Verdict::SpendRefused {
            txid,
            input: Some(0),
            why: SpendRefusal::Resource(limit),
            ..
        } => {
            assert_eq!(&txid, subject, "the decline names the subject");
            assert_eq!(limit, expected_limit());
            assert_eq!(
                SpendRefusal::Resource(limit).to_string(),
                "Stack memory usage has exceeded 1000 bytes"
            );
        }
        other => panic!("expected the caller's memory budget's decline: {other:?}"),
    }
}

#[test]
fn a_stream_input_past_the_callers_memory_budget_declines_naming_the_transaction() {
    for answer in [OP_1, OP_0] {
        let f = fixture(answer);
        let mut reader = StreamVerifier::new(f.beef.as_slice(), &f.headers, None);
        reader.set_memory_limit(Some(BUDGET));
        assert_declined(reader.run().unwrap(), &f.subject);
    }
}

#[test]
fn a_stream_with_no_memory_budget_judges_the_script() {
    let valid = fixture(OP_1);
    let mut reader = StreamVerifier::new(valid.beef.as_slice(), &valid.headers, None);
    reader.set_memory_limit(None);
    assert!(reader.run().unwrap().is_valid());
    assert!(
        bsv_rs::transaction::verify_stream(valid.beef.as_slice(), &valid.headers, None)
            .unwrap()
            .is_valid(),
        "the default is uncapped"
    );
    // A budget the script fits under judges it as `None` does.
    let mut ample = StreamVerifier::new(valid.beef.as_slice(), &valid.headers, None);
    ample.set_memory_limit(Some(2 * PUSHED));
    assert!(ample.run().unwrap().is_valid());

    let invalid = fixture(OP_0);
    let verdict =
        bsv_rs::transaction::verify_stream(invalid.beef.as_slice(), &invalid.headers, None)
            .unwrap();
    match verdict {
        Verdict::SpendRefused {
            txid,
            input: Some(0),
            why: SpendRefusal::Script(_),
            ..
        } => assert_eq!(txid, invalid.subject),
        other => panic!("expected the script's verdict: {other:?}"),
    }
}

#[test]
fn the_structure_only_reader_is_unaffected_by_a_memory_budget() {
    for answer in [OP_1, OP_0] {
        let f = fixture(answer);
        let mut reader = StreamVerifier::structure_only(f.beef.as_slice(), &f.headers, None);
        reader.set_memory_limit(Some(1));
        assert!(reader.run().unwrap().is_valid());
    }
}

#[test]
fn a_resumed_reader_keeps_a_memory_budget_set_after_resumption() {
    let f = fixture(OP_1);
    let mut reader = StreamVerifier::new(f.beef.as_slice(), &f.headers, None);
    reader.set_memory_limit(Some(BUDGET));
    // The BUMP, then the parent: the cursor stands before the subject.
    assert_eq!(reader.step().unwrap(), Progress::Stepped);
    assert_eq!(reader.step().unwrap(), Progress::Stepped);
    let encoded = reader.cursor().to_binary();
    let cursor = bsv_rs::transaction::Cursor::from_binary(&encoded).unwrap();
    let rest = &f.beef[cursor.offset() as usize..];

    let mut resumed = StreamVerifier::resume(cursor.clone(), rest, &f.headers);
    resumed.set_memory_limit(Some(BUDGET));
    assert_declined(resumed.run().unwrap(), &f.subject);

    // The budget is not cursor state: a resumed reader without one is uncapped.
    let unbudgeted = StreamVerifier::resume(cursor, rest, &f.headers);
    assert!(unbudgeted.run().unwrap().is_valid());
}

struct Chunk(Option<Vec<u8>>);
impl AsyncByteSource for Chunk {
    async fn next_chunk(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        Ok(self.0.take())
    }
}

#[tokio::test]
async fn the_asynchronous_reader_names_the_same_memory_decline() {
    let f = fixture(OP_1);
    let mut tracker = MockChainTracker::new(HEIGHT);
    let mut root = f.headers[&u64::from(HEIGHT)];
    root.reverse();
    tracker.add_root(HEIGHT, bsv_rs::primitives::to_hex(&root));

    let mut reader = AsyncStreamVerifier::new(None);
    reader.set_memory_limit(Some(BUDGET));
    let verdict = reader
        .run(&mut Chunk(Some(f.beef.clone())), &tracker)
        .await
        .unwrap();
    assert_declined(verdict, &f.subject);

    let mut uncapped = AsyncStreamVerifier::new(None);
    uncapped.set_memory_limit(None);
    let verdict = uncapped
        .run(&mut Chunk(Some(f.beef.clone())), &tracker)
        .await
        .unwrap();
    assert!(verdict.is_valid(), "{verdict:?}");
}
