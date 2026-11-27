//! What bsv-rs#1043 must NOT move on the stable line, green on the base
//! (`a6b7da07`, 0.8.11) and after: a streaming reader that never calls
//! `set_memory_limit` answers as 0.8.11 does, and `set_work_limit` behaves as
//! before. This file calls no item #1043 adds, so it compiles on the base.
//!
//! On this line a spend's `memory_limit: None` is the default mode's own
//! figure, 32,000,000 bytes per stack (`src/script/spend.rs`,
//! `DEFAULT_MEMORY_LIMIT`); on the 0.9 line it is uncapped (beta's #331). The
//! script `between()` needs 33,554,432 bytes on one stack, between the two:
//! on this line a reader with no budget set declines it, as 0.8.11 does.
//!
//! The recorded BEEF vectors the suite replays through the readers
//! (`tests/beef_stream*.rs`, `tests/conformance_beef.rs`, `tests/p2sh_redeem_step.rs`,
//! `tests/pre_genesis_coin_rules.rs`, `tests/script_work_budget.rs`) never
//! call the setter and are the rest of this pin.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use std::collections::HashMap;

use bsv_rs::script::{LockingScript, Script, ScriptResource, ScriptResourceLimit, UnlockingScript};
use bsv_rs::transaction::beef_stream::{AsyncByteSource, Hash32, SpendRefusal};
use bsv_rs::transaction::{
    verify_stream, verify_stream_async, AsyncStreamVerifier, MerklePath, MockChainTracker,
    StreamVerifier, Transaction, TransactionInput, TransactionOutput, Verdict,
};

const HEIGHT: u32 = 800_000;
const OP_DUP: u8 = 0x76;
const OP_CAT: u8 = 0x7e;
const OP_2DROP: u8 = 0x6d;
const OP_0: u8 = 0x00;
const OP_1: u8 = 0x51;
/// This line's default-mode budget per stack when `memory_limit` is `None`.
const LINE_DEFAULT: u64 = 32_000_000;
/// The doubled element: 2^24 bytes; its duplicate takes the stack to 2^25.
const ELEMENT: u64 = 1 << 24;

struct Fixture {
    beef: Vec<u8>,
    headers: HashMap<u64, Hash32>,
    tracker: MockChainTracker,
    subject: Hash32,
}

/// A version-2 spend of a proven parent's one output locked by `lock`, its
/// unlocking script pushing `push`.
fn fixture(lock: Script, push: &[u8]) -> Fixture {
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
    unlock.write_bin(push);
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
    let mut tracker = MockChainTracker::new(HEIGHT);
    let mut display = root;
    display.reverse();
    tracker.add_root(HEIGHT, bsv_rs::primitives::to_hex(&display));
    Fixture {
        beef: subject.to_beef(false).unwrap(),
        headers: HashMap::from([(u64::from(HEIGHT), root)]),
        tracker,
        subject: subject.hash(),
    }
}

/// A script needing 2^25 bytes on one stack: one byte doubled 24 times by
/// `OP_DUP OP_CAT`, then duplicated. Above this line's default, below none.
fn between() -> Fixture {
    let mut lock = Script::new();
    for _ in 0..24 {
        lock.write_opcode(OP_DUP).write_opcode(OP_CAT);
    }
    lock.write_opcode(OP_DUP)
        .write_opcode(OP_2DROP)
        .write_opcode(OP_1);
    fixture(lock, &[0x5a])
}

/// The small duplicating script of beta's #373 test: 1,200 bytes at its peak.
fn small(answer: u8) -> Fixture {
    let mut lock = Script::new();
    lock.write_opcode(OP_DUP)
        .write_opcode(OP_2DROP)
        .write_opcode(answer);
    fixture(lock, &[0x5a; 600])
}

/// What 0.8.11 answers for `between()` with no budget set, its offset left
/// at 0 (compared through `without_offset`; the readers' offsets are compared
/// with each other): this line's default declines at the duplicate.
fn line_default_decline(subject: Hash32) -> Verdict {
    Verdict::SpendRefused {
        offset: 0,
        txid: subject,
        input: Some(0),
        why: SpendRefusal::Resource(ScriptResourceLimit {
            resource: ScriptResource::Stack,
            limit: LINE_DEFAULT,
            attempted: 2 * ELEMENT,
            work_spent: None,
        }),
    }
}

fn without_offset(verdict: Verdict) -> Verdict {
    match verdict {
        Verdict::SpendRefused {
            txid, input, why, ..
        } => Verdict::SpendRefused {
            offset: 0,
            txid,
            input,
            why,
        },
        other => other,
    }
}

struct Chunk(Option<Vec<u8>>);
impl AsyncByteSource for Chunk {
    async fn next_chunk(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        Ok(self.0.take())
    }
}

async fn async_verdict(f: &Fixture, work: Option<Option<u64>>) -> Verdict {
    let mut reader = AsyncStreamVerifier::new(None);
    if let Some(limit) = work {
        reader.set_work_limit(limit);
    }
    reader
        .run(&mut Chunk(Some(f.beef.clone())), &f.tracker)
        .await
        .unwrap()
}

fn blocking_verdict(f: &Fixture, work: Option<Option<u64>>) -> Verdict {
    let mut reader = StreamVerifier::new(f.beef.as_slice(), &f.headers, None);
    if let Some(limit) = work {
        reader.set_work_limit(limit);
    }
    reader.run().unwrap()
}

#[tokio::test]
async fn an_async_reader_without_a_memory_budget_declines_past_the_lines_default_as_0_8_11_1043() {
    let f = between();
    let expected = line_default_decline(f.subject);
    let reader = async_verdict(&f, None).await;
    assert_eq!(without_offset(reader.clone()), expected, "{reader:?}");
    // With the work budget set as the middleware core sets it, the same.
    let worked = async_verdict(&f, Some(Some(u64::MAX))).await;
    assert_eq!(worked, reader);
    let function = verify_stream_async(&mut Chunk(Some(f.beef.clone())), &f.tracker, None)
        .await
        .unwrap();
    assert_eq!(function, reader);
    // The blocking reader and its function form agree, offset and all.
    assert_eq!(blocking_verdict(&f, None), reader);
    assert_eq!(
        verify_stream(f.beef.as_slice(), &f.headers, None).unwrap(),
        reader
    );
}

#[tokio::test]
async fn readers_without_a_memory_budget_judge_a_small_script_as_0_8_11_1043() {
    let valid = small(OP_1);
    assert!(async_verdict(&valid, None).await.is_valid());
    assert!(blocking_verdict(&valid, None).is_valid());
    let invalid = small(OP_0);
    for verdict in [
        async_verdict(&invalid, None).await,
        blocking_verdict(&invalid, None),
    ] {
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
}

#[tokio::test]
async fn set_work_limit_declines_and_accepts_as_0_8_11_1043() {
    let f = small(OP_1);
    for verdict in [
        async_verdict(&f, Some(Some(1))).await,
        blocking_verdict(&f, Some(Some(1))),
    ] {
        match verdict {
            Verdict::SpendRefused {
                txid,
                input: Some(0),
                why: SpendRefusal::Resource(limit),
                ..
            } => {
                assert_eq!(txid, f.subject);
                assert_eq!(limit.resource, ScriptResource::Work);
                assert_eq!(limit.limit, 1);
                assert!(limit.work_spent.unwrap() <= 1, "{limit:?}");
            }
            other => panic!("expected the work budget's decline: {other:?}"),
        }
    }
    assert!(async_verdict(&f, Some(Some(1_000_000))).await.is_valid());
    assert!(blocking_verdict(&f, Some(Some(1_000_000))).is_valid());
    assert!(async_verdict(&f, Some(None)).await.is_valid());
    assert!(blocking_verdict(&f, Some(None)).is_valid());
}
