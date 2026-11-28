//! The streaming readers take the caller's memory budget for their scripts on
//! the stable line (bsv-rs#1043, a port of beta's #373): `set_memory_limit`
//! beside `set_work_limit` on `AsyncStreamVerifier` and `StreamVerifier`.
//! `Some(n)` is the caller's LOCAL budget of `n` bytes per stack for every
//! input the reading runs; an input that passes it is the existing decline,
//! `Verdict::SpendRefused` with `SpendRefusal::Resource`, never a verdict.
//! `None` on this line is the default mode's own figure, 32,000,000 bytes per
//! stack, as before the setter (`tests/beef_stream_memory_budget_1043_pins.rs`
//! pins that a reader which never calls it answers as 0.8.11 does).
//!
//! The async reader is driven first: it is the door `bsv-middleware-core`
//! calls (`AsyncStreamVerifier::new(None)`, then the two setters, then `run`).
//!
//! Every fixture is the crate's own writer's: a parent proven by a one-leaf
//! BUMP (its txid the root) and version-2 spends (the default mode's relaxed
//! rules). A spend pushes `PUSHED` bytes and its coin's locking script
//! duplicates them (`2 * PUSHED` bytes on the stack) before it drops both and
//! answers. Every outpoint is synthetic.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use std::collections::HashMap;

use bsv_rs::script::{LockingScript, Script, ScriptResource, ScriptResourceLimit, UnlockingScript};
use bsv_rs::transaction::beef_stream::{AsyncByteSource, Hash32, SpendRefusal};
use bsv_rs::transaction::{
    AsyncStreamVerifier, Cursor, MerklePath, MockChainTracker, Progress, StreamVerifier,
    Transaction, TransactionInput, TransactionOutput, Verdict,
};

const HEIGHT: u32 = 800_000;
const PUSHED: usize = 600;
/// What the duplicating spend needs: the push and its copy, one stack.
const NEEDED: usize = 2 * PUSHED;
/// Above the push, below the duplicate: the push fits, `OP_DUP` does not.
const BUDGET: usize = 1_000;
const OP_DUP: u8 = 0x76;
const OP_2DROP: u8 = 0x6d;
const OP_DROP: u8 = 0x75;
const OP_1: u8 = 0x51;

/// The duplicating lock: `OP_DUP OP_2DROP OP_1`, `2 * PUSHED` bytes at its peak.
fn dup_lock() -> LockingScript {
    let mut lock = Script::new();
    lock.write_opcode(OP_DUP)
        .write_opcode(OP_2DROP)
        .write_opcode(OP_1);
    LockingScript::from_binary(&lock.to_binary()).unwrap()
}

/// A lock that holds only what was pushed: `OP_DROP OP_1`, `PUSHED` bytes.
fn drop_lock() -> LockingScript {
    let mut lock = Script::new();
    lock.write_opcode(OP_DROP).write_opcode(OP_1);
    LockingScript::from_binary(&lock.to_binary()).unwrap()
}

fn push_unlock() -> UnlockingScript {
    let mut unlock = Script::new();
    unlock.write_bin(&[0x5a; PUSHED]);
    UnlockingScript::from_binary(&unlock.to_binary()).unwrap()
}

/// A parent proven by a one-leaf BUMP, one output per lock.
fn proven_parent(locks: Vec<LockingScript>) -> Transaction {
    let mut parent = Transaction::new();
    let mut phantom = TransactionInput::new("aa".repeat(32), 0);
    phantom.set_unlocking_script(UnlockingScript::new());
    parent.add_input(phantom).unwrap();
    for lock in locks {
        parent
            .add_output(TransactionOutput::new(1_000, lock))
            .unwrap();
    }
    parent.merkle_path = Some(MerklePath::from_coinbase_txid(&parent.id(), HEIGHT));
    parent
}

/// A version-2 spend of `inputs` (each a source and its output index), with
/// one output of `satoshis` locked by `lock`.
fn spend(inputs: Vec<(Transaction, u32)>, satoshis: u64, lock: LockingScript) -> Transaction {
    let mut tx = Transaction::new();
    tx.version = 2;
    for (source, vout) in inputs {
        let mut input = TransactionInput::with_source_transaction(source, vout);
        input.set_unlocking_script(push_unlock());
        tx.add_input(input).unwrap();
    }
    tx.add_output(TransactionOutput::new(satoshis, lock))
        .unwrap();
    tx
}

struct Fixture {
    beef: Vec<u8>,
    headers: HashMap<u64, Hash32>,
    tracker: MockChainTracker,
    /// The transaction the decline names.
    named: Hash32,
}

impl Fixture {
    fn of(parent_root: Hash32, subject: &Transaction, named: Hash32) -> Self {
        let mut tracker = MockChainTracker::new(HEIGHT);
        let mut display = parent_root;
        display.reverse();
        tracker.add_root(HEIGHT, bsv_rs::primitives::to_hex(&display));
        Fixture {
            beef: subject.to_beef(false).unwrap(),
            headers: HashMap::from([(u64::from(HEIGHT), parent_root)]),
            tracker,
            named,
        }
    }

    fn blocking(&self, limit: Option<usize>) -> Verdict {
        let mut reader = StreamVerifier::new(self.beef.as_slice(), &self.headers, None);
        reader.set_memory_limit(limit);
        reader.run().unwrap()
    }

    async fn asynchronous(&self, limit: Option<usize>) -> Verdict {
        let mut reader = AsyncStreamVerifier::new(None);
        reader.set_work_limit(None);
        reader.set_memory_limit(limit);
        reader
            .run(&mut Chunk(Some(self.beef.clone())), &self.tracker)
            .await
            .unwrap()
    }
}

/// One spend whose one script needs `NEEDED` bytes on one stack.
fn one_spend() -> Fixture {
    let parent = proven_parent(vec![dup_lock()]);
    let root = parent.hash();
    let subject = spend(
        vec![(parent, 0)],
        900,
        LockingScript::from_binary(&[OP_1]).unwrap(),
    );
    let named = subject.hash();
    Fixture::of(root, &subject, named)
}

/// One transaction of two inputs: input 0 holds `PUSHED` bytes (within the
/// budget), input 1 duplicates them (past it).
fn two_inputs() -> Fixture {
    let parent = proven_parent(vec![drop_lock(), dup_lock()]);
    let root = parent.hash();
    let subject = spend(
        vec![(parent.clone(), 0), (parent, 1)],
        1_900,
        LockingScript::from_binary(&[OP_1]).unwrap(),
    );
    let named = subject.hash();
    Fixture::of(root, &subject, named)
}

/// Two unproven transactions in a chain: the middle one's input holds
/// `PUSHED` bytes (within the budget); the subject's, spending the middle
/// one's output, duplicates them (past it).
fn two_transactions() -> Fixture {
    let parent = proven_parent(vec![drop_lock()]);
    let root = parent.hash();
    let middle = spend(vec![(parent, 0)], 950, dup_lock());
    let subject = spend(
        vec![(middle, 0)],
        900,
        LockingScript::from_binary(&[OP_1]).unwrap(),
    );
    let named = subject.hash();
    Fixture::of(root, &subject, named)
}

fn expected_limit() -> ScriptResourceLimit {
    ScriptResourceLimit {
        resource: ScriptResource::Stack,
        limit: BUDGET as u64,
        attempted: NEEDED as u64,
        work_spent: None,
    }
}

fn assert_declined(verdict: Verdict, named: &Hash32, input: u32) {
    match verdict {
        Verdict::SpendRefused {
            txid,
            input: Some(at),
            why: SpendRefusal::Resource(limit),
            ..
        } => {
            assert_eq!(&txid, named, "the decline names the transaction");
            assert_eq!(at, input, "the decline names the input");
            assert_eq!(limit, expected_limit());
        }
        other => panic!("expected the caller's memory budget's decline: {other:?}"),
    }
}

struct Chunk(Option<Vec<u8>>);
impl AsyncByteSource for Chunk {
    async fn next_chunk(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        Ok(self.0.take())
    }
}

// --- The async reader (the middleware core's door) ---------------------------

#[tokio::test]
async fn the_async_reader_declines_a_script_past_the_callers_memory_budget_1043() {
    let f = one_spend();
    assert_declined(f.asynchronous(Some(BUDGET)).await, &f.named, 0);
}

#[tokio::test]
async fn the_async_reader_accepts_the_script_at_exactly_the_budget_it_needs_1043() {
    let f = one_spend();
    let at = f.asynchronous(Some(NEEDED)).await;
    assert!(at.is_valid(), "{at:?}");
    assert_declined_at(f.asynchronous(Some(NEEDED - 1)).await, &f, NEEDED - 1);
}

#[tokio::test]
async fn the_async_readers_memory_budget_applies_to_every_input_of_a_transaction_1043() {
    let f = two_inputs();
    assert_declined(f.asynchronous(Some(BUDGET)).await, &f.named, 1);
    assert!(f.asynchronous(Some(NEEDED)).await.is_valid());
}

#[tokio::test]
async fn the_async_readers_memory_budget_applies_to_every_transaction_it_verifies_1043() {
    let f = two_transactions();
    assert_declined(f.asynchronous(Some(BUDGET)).await, &f.named, 0);
    assert!(f.asynchronous(Some(NEEDED)).await.is_valid());
}

#[tokio::test]
async fn an_async_reader_resumed_from_a_cursor_takes_a_budget_set_after_resumption_1043() {
    let f = one_spend();
    let cursor = cursor_before_the_subject(&f);
    let rest = f.beef[cursor.offset() as usize..].to_vec();

    let mut resumed = AsyncStreamVerifier::resume(cursor.clone());
    resumed.set_memory_limit(Some(BUDGET));
    let verdict = resumed
        .run(&mut Chunk(Some(rest.clone())), &f.tracker)
        .await
        .unwrap();
    assert_declined(verdict, &f.named, 0);

    // Not cursor state: a resumed reader not given one has this line's default.
    let mut unbudgeted = AsyncStreamVerifier::resume(cursor);
    let verdict = unbudgeted
        .run(&mut Chunk(Some(rest)), &f.tracker)
        .await
        .unwrap();
    assert!(verdict.is_valid(), "{verdict:?}");
}

// --- The blocking reader -------------------------------------------------------

#[test]
fn the_blocking_reader_declines_a_script_past_the_callers_memory_budget_1043() {
    let f = one_spend();
    assert_declined(f.blocking(Some(BUDGET)), &f.named, 0);
}

#[test]
fn the_blocking_reader_accepts_the_script_at_exactly_the_budget_it_needs_1043() {
    let f = one_spend();
    assert!(f.blocking(Some(NEEDED)).is_valid());
    assert_declined_at(f.blocking(Some(NEEDED - 1)), &f, NEEDED - 1);
}

#[test]
fn the_blocking_readers_memory_budget_applies_to_every_input_and_transaction_1043() {
    let f = two_inputs();
    assert_declined(f.blocking(Some(BUDGET)), &f.named, 1);
    assert!(f.blocking(Some(NEEDED)).is_valid());
    let f = two_transactions();
    assert_declined(f.blocking(Some(BUDGET)), &f.named, 0);
    assert!(f.blocking(Some(NEEDED)).is_valid());
}

#[test]
fn a_budget_set_after_the_blocking_reader_has_begun_applies_to_the_inputs_after_it_1043() {
    let f = one_spend();
    let mut reader = StreamVerifier::new(f.beef.as_slice(), &f.headers, None);
    // The BUMP, then the proven parent: nothing has run a script yet.
    assert_eq!(reader.step().unwrap(), Progress::Stepped);
    assert_eq!(reader.step().unwrap(), Progress::Stepped);
    reader.set_memory_limit(Some(BUDGET));
    assert_declined(reader.run().unwrap(), &f.named, 0);
}

#[test]
fn a_blocking_reader_resumed_from_a_cursor_takes_a_budget_set_after_resumption_1043() {
    let f = one_spend();
    let cursor = cursor_before_the_subject(&f);
    let rest = &f.beef[cursor.offset() as usize..];

    let mut resumed = StreamVerifier::resume(cursor.clone(), rest, &f.headers);
    resumed.set_memory_limit(Some(BUDGET));
    assert_declined(resumed.run().unwrap(), &f.named, 0);

    let unbudgeted = StreamVerifier::resume(cursor, rest, &f.headers);
    assert!(unbudgeted.run().unwrap().is_valid());
}

#[test]
fn the_structure_only_reader_is_unaffected_by_a_memory_budget_1043() {
    let f = one_spend();
    let mut reader = StreamVerifier::structure_only(f.beef.as_slice(), &f.headers, None);
    reader.set_memory_limit(Some(1));
    assert!(reader.run().unwrap().is_valid());
}

/// The cursor after the BUMP and the proven parent, encoded and decoded (a
/// reader with a budget took it: the budget is not in it).
fn cursor_before_the_subject(f: &Fixture) -> Cursor {
    let mut reader = StreamVerifier::new(f.beef.as_slice(), &f.headers, None);
    reader.set_memory_limit(Some(BUDGET));
    assert_eq!(reader.step().unwrap(), Progress::Stepped);
    assert_eq!(reader.step().unwrap(), Progress::Stepped);
    Cursor::from_binary(&reader.cursor().to_binary()).unwrap()
}

fn assert_declined_at(verdict: Verdict, f: &Fixture, limit: usize) {
    match verdict {
        Verdict::SpendRefused {
            txid,
            input: Some(0),
            why: SpendRefusal::Resource(got),
            ..
        } => {
            assert_eq!(txid, f.named);
            assert_eq!(got.resource, ScriptResource::Stack);
            assert_eq!(got.limit, limit as u64);
            assert_eq!(got.attempted, NEEDED as u64);
        }
        other => panic!("expected a decline one byte under the need: {other:?}"),
    }
}
