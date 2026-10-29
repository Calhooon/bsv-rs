//! #378: one per-input work counter, three verification paths, no validity judgment on exhaustion.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::block::ChainParams;
use bsv_rs::primitives::Writer;
use bsv_rs::script::{LockingScript, NotJudgedCause, Script, Spend, SpendParams, UnlockingScript};
use bsv_rs::transaction::beef_stream::SpendRefusal;
use bsv_rs::transaction::{
    AsyncByteSource, AsyncStreamVerifier, Beef, Cursor, MerklePath, MockChainTracker, Progress,
    StreamVerifier, Transaction, TransactionInput, TransactionOutput, Verdict, BEEF_V1,
};
use bsv_rs::Error;

const WORK: u64 = 68; // push + SHA256 + 64 bytes hashed + DROP + final opcode.
const LOW: u64 = 65; // The hash would take the counter from 2 to 66.

#[test]
#[cfg(target_pointer_width = "64")]
fn a_work_budget_cause_keeps_the_unified_error_at_56_bytes_378() {
    let sizes = (
        std::mem::size_of::<NotJudgedCause>(),
        std::mem::size_of::<Error>(),
    );
    println!("size_of: NotJudgedCause = {}, Error = {}", sizes.0, sizes.1);
    assert_eq!(sizes, (24, 56));
}

struct Fixture {
    tx: Transaction,
    tracker: MockChainTracker,
}

impl Fixture {
    fn new(answer: bool, inputs: usize, cheap_leading: bool) -> Self {
        let mut parent = Transaction::new();
        let mut dummy = TransactionInput::new("aa".repeat(32), 0);
        dummy.set_unlocking_script(UnlockingScript::new());
        parent.add_input(dummy).unwrap();
        for vin in 0..inputs {
            let lock = if cheap_leading && vin == 0 {
                "OP_1"
            } else if answer {
                "OP_SHA256 OP_DROP OP_1"
            } else {
                "OP_SHA256 OP_DROP OP_0"
            };
            parent
                .add_output(TransactionOutput::new(
                    1_000,
                    LockingScript::from_script(Script::from_asm(lock).unwrap()),
                ))
                .unwrap();
        }
        let height = 800_000;
        parent.merkle_path = Some(MerklePath::from_coinbase_txid(&parent.id(), height));
        let mut tracker = MockChainTracker::new(height);
        tracker.add_root(height, parent.id());
        let mut tx = Transaction::new();
        tx.version = 2;
        for vin in 0..inputs {
            let mut input = TransactionInput::with_source_transaction(parent.clone(), vin as u32);
            let mut unlock = Script::new();
            if !(cheap_leading && vin == 0) {
                unlock.write_bin(&[7; 64]);
            }
            input.set_unlocking_script(UnlockingScript::from_script(unlock));
            tx.add_input(input).unwrap();
        }
        tx.add_output(TransactionOutput::new(
            900,
            LockingScript::from_hex("51").unwrap(),
        ))
        .unwrap();
        Self { tx, tracker }
    }

    fn bytes(&self, deferred: bool) -> Vec<u8> {
        let bytes = self.tx.to_beef(false).unwrap();
        if !deferred {
            return bytes;
        }
        let beef = Beef::from_binary(&bytes).unwrap();
        let mut writer = Writer::new();
        writer
            .write_u32_le(BEEF_V1)
            .write_var_int(beef.bumps.len() as u64);
        for bump in &beef.bumps {
            writer.write_bytes(&bump.to_binary());
        }
        writer.write_var_int(beef.txs.len() as u64);
        for tx in beef.txs.iter().rev() {
            tx.to_writer(&mut writer, BEEF_V1);
        }
        writer.into_bytes()
    }

    async fn whole(&self, limit: Option<u64>, word: bool) -> bsv_rs::Result<bool> {
        if word {
            self.tx
                .verify_with_chain_params_and_work_budget(
                    &self.tracker,
                    None,
                    None,
                    limit,
                    &ChainParams::mainnet(),
                )
                .await
        } else {
            self.tx
                .verify_with_work_budget(&self.tracker, None, None, limit)
                .await
        }
    }

    fn sync(&self, bytes: &[u8], limit: Option<u64>, word: bool) -> Verdict {
        let mut reader = StreamVerifier::new(bytes, &self.tracker, None).with_work_budget(limit);
        if word {
            reader = reader.with_chain_params(ChainParams::mainnet());
        }
        reader.run().unwrap()
    }

    async fn asynchronous(&self, bytes: Vec<u8>, limit: Option<u64>, word: bool) -> Verdict {
        let mut reader = AsyncStreamVerifier::new(None).with_work_budget(limit);
        if word {
            reader = reader.with_chain_params(ChainParams::mainnet());
        }
        reader
            .run(&mut Chunk(Some(bytes)), &self.tracker)
            .await
            .unwrap()
    }
}

struct Chunk(Option<Vec<u8>>);
impl AsyncByteSource for Chunk {
    async fn next_chunk(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        Ok(self.0.take())
    }
}

fn cause(input: usize, budget: u64, work_done: u64) -> NotJudgedCause {
    NotJudgedCause::WorkBudgetExceeded {
        input: input as u32,
        budget,
        work_done,
    }
}

fn sentence(input: usize, budget: u64, work_done: u64) -> String {
    format!("input {input} not judged: exceeded work budget {budget} units after {work_done} units of work.")
}

fn assert_stream(f: &Fixture, verdict: Verdict, input: usize, budget: u64, work_done: u64) {
    assert!(!verdict.is_valid());
    match verdict {
        Verdict::NotJudged {
            txid,
            input: actual,
            offset,
            cause: actual_cause,
        } => {
            assert_eq!(txid, f.tx.hash());
            assert_eq!(actual as usize, input);
            assert!(offset > 0);
            assert_eq!(actual_cause, cause(input, budget, work_done));
            let refusal = SpendRefusal::NotJudged {
                input: actual,
                cause: actual_cause,
            };
            assert_eq!(refusal.to_string(), sentence(input, budget, work_done));
            assert!(!refusal.to_string().contains("Script validation failed"));
        }
        other => panic!("expected a typed NotJudged work refusal, got {other:?}"),
    }
}

fn assert_whole(f: &Fixture, error: Error, input: usize, budget: u64, work_done: u64) {
    assert_eq!(
        error,
        Error::TransactionNotJudged {
            txid: f.tx.id(),
            input_index: input,
            cause: cause(input, budget, work_done),
        }
    );
    assert_eq!(
        error.to_string(),
        format!(
            "transaction {} {}",
            f.tx.id(),
            sentence(input, budget, work_done)
        )
    );
    assert!(!error.to_string().contains("Script validation failed"));
}

#[tokio::test]
async fn whole_transaction_work_exhaustion_is_not_judged_378() {
    let f = Fixture::new(true, 2, true);
    for word in [false, true] {
        assert!(f.whole(Some(WORK), word).await.unwrap());
        assert_whole(&f, f.whole(Some(LOW), word).await.unwrap_err(), 1, LOW, 2);
        assert_whole(&f, f.whole(Some(0), word).await.unwrap_err(), 0, 0, 0);
        assert_whole(
            &f,
            f.whole(Some(WORK - 1), word).await.unwrap_err(),
            1,
            WORK - 1,
            WORK - 1,
        );
    }
}

#[test]
fn synchronous_stream_work_exhaustion_is_not_judged_378() {
    let f = Fixture::new(true, 2, true);
    for deferred in [false, true] {
        let bytes = f.bytes(deferred);
        for word in [false, true] {
            assert!(f.sync(&bytes, Some(WORK), word).is_valid());
            assert_stream(&f, f.sync(&bytes, Some(LOW), word), 1, LOW, 2);
            assert_stream(&f, f.sync(&bytes, Some(0), word), 0, 0, 0);
            assert_stream(
                &f,
                f.sync(&bytes, Some(WORK - 1), word),
                1,
                WORK - 1,
                WORK - 1,
            );
        }
    }
}

#[tokio::test]
async fn asynchronous_stream_work_exhaustion_is_not_judged_378() {
    let f = Fixture::new(true, 2, true);
    for deferred in [false, true] {
        for word in [false, true] {
            assert!(f
                .asynchronous(f.bytes(deferred), Some(WORK), word)
                .await
                .is_valid());
            assert_stream(
                &f,
                f.asynchronous(f.bytes(deferred), Some(LOW), word).await,
                1,
                LOW,
                2,
            );
            assert_stream(
                &f,
                f.asynchronous(f.bytes(deferred), Some(0), word).await,
                0,
                0,
                0,
            );
        }
    }
}

#[tokio::test]
async fn every_input_gets_the_budget_and_in_budget_verdicts_are_unchanged_378() {
    for answer in [true, false] {
        let f = Fixture::new(answer, 2, false);
        for word in [false, true] {
            let unbounded = f.whole(None, word).await;
            for limit in [None, Some(WORK), Some(WORK + 1)] {
                assert_eq!(f.whole(limit, word).await, unbounded);
                for deferred in [false, true] {
                    let bytes = f.bytes(deferred);
                    let expected = f.sync(&bytes, None, word);
                    assert_eq!(f.sync(&bytes, limit, word), expected);
                    assert_eq!(f.asynchronous(bytes, limit, word).await, expected);
                }
            }
            assert_eq!(unbounded.is_ok(), answer);
        }
    }
}

#[tokio::test]
async fn none_preserves_the_existing_verifier_entry_points_378() {
    for answer in [true, false] {
        let f = Fixture::new(answer, 1, false);
        assert_eq!(
            f.whole(None, false).await,
            f.tx.verify(&f.tracker, None, None).await
        );
        assert_eq!(
            f.whole(None, true).await,
            f.tx.verify_with_chain_params(&f.tracker, None, None, &ChainParams::mainnet())
                .await
        );
        let bytes = f.bytes(false);
        assert_eq!(
            f.sync(&bytes, None, false),
            StreamVerifier::new(bytes.as_slice(), &f.tracker, None)
                .run()
                .unwrap()
        );
        assert_eq!(
            f.asynchronous(bytes.clone(), None, false).await,
            AsyncStreamVerifier::new(None)
                .run(&mut Chunk(Some(bytes)), &f.tracker)
                .await
                .unwrap()
        );
    }
}

#[test]
fn the_standalone_counter_is_the_verifiers_counter_378() {
    let f = Fixture::new(true, 1, false);
    let input = &f.tx.inputs[0];
    let source = input.source_transaction.as_ref().unwrap();
    for (limit, spent) in [(LOW, 2), (WORK, WORK)] {
        let mut spend = Spend::new(SpendParams {
            source_txid: source.hash(),
            source_output_index: 0,
            source_satoshis: 1_000,
            locking_script: source.outputs[0].locking_script.clone(),
            transaction_version: 2,
            other_inputs: vec![],
            outputs: vec![],
            input_index: 0,
            unlocking_script: input.unlocking_script.clone().unwrap(),
            input_sequence: input.sequence,
            lock_time: 0,
            memory_limit: None,
            work_limit: Some(limit),
        });
        let result = spend.validate();
        assert_eq!(spend.work_spent(), spent);
        if limit == LOW {
            let resource = result.unwrap_err().resource_limit.unwrap();
            assert_eq!(resource.work_spent, Some(spent));
            assert_eq!(resource.attempted, 66);
            assert_stream(
                &f,
                f.sync(&f.bytes(false), Some(limit), false),
                0,
                limit,
                spent,
            );
        } else {
            assert!(result.unwrap());
        }
    }
}

#[tokio::test]
async fn proven_and_structure_only_transactions_spend_no_work_378() {
    let mut f = Fixture::new(false, 1, false);
    let bytes = f.bytes(false);
    assert!(
        StreamVerifier::structure_only(bytes.as_slice(), &f.tracker, None)
            .with_work_budget(Some(0))
            .run()
            .unwrap()
            .is_valid()
    );
    assert!(AsyncStreamVerifier::structure_only(None)
        .with_work_budget(Some(0))
        .run(&mut Chunk(Some(bytes)), &f.tracker)
        .await
        .unwrap()
        .is_valid());
    f.tx.merkle_path = Some(MerklePath::from_coinbase_txid(&f.tx.id(), 800_001));
    f.tracker.add_root(800_001, f.tx.id());
    for word in [false, true] {
        assert!(f.whole(Some(0), word).await.unwrap());
        let bytes = f.bytes(false);
        assert!(f.sync(&bytes, Some(0), word).is_valid());
        assert!(f.asynchronous(bytes, Some(0), word).await.is_valid());
    }
}

#[test]
fn a_resumed_stream_reapplies_its_local_work_policy_378() {
    let f = Fixture::new(true, 1, false);
    let bytes = f.bytes(false);
    let mut reader =
        StreamVerifier::new(bytes.as_slice(), &f.tracker, None).with_work_budget(Some(LOW));
    assert_eq!(reader.step().unwrap(), Progress::Stepped); // BUMP.
    assert_eq!(reader.step().unwrap(), Progress::Stepped); // Proven parent.
    let cursor = Cursor::from_binary(&reader.cursor().to_binary()).unwrap();
    let rest = &bytes[cursor.offset() as usize..];
    let resumed =
        StreamVerifier::resume(cursor.clone(), rest, &f.tracker).with_work_budget(Some(LOW));
    assert_stream(&f, resumed.run().unwrap(), 0, LOW, 2);
    assert!(StreamVerifier::resume(cursor, rest, &f.tracker)
        .run()
        .unwrap()
        .is_valid());
    let mut cleared =
        StreamVerifier::new(bytes.as_slice(), &f.tracker, None).with_work_budget(Some(LOW));
    cleared.set_work_limit(None);
    assert!(cleared.run().unwrap().is_valid());
}

#[tokio::test]
async fn a_resumed_async_stream_reapplies_its_local_work_policy_378() {
    let f = Fixture::new(true, 1, false);
    let bytes = f.bytes(false);
    let mut reader = StreamVerifier::new(bytes.as_slice(), &f.tracker, None);
    reader.step().unwrap();
    reader.step().unwrap();
    let cursor = Cursor::from_binary(&reader.cursor().to_binary()).unwrap();
    let rest = bytes[cursor.offset() as usize..].to_vec();
    let verdict = AsyncStreamVerifier::resume(cursor.clone())
        .with_work_budget(Some(LOW))
        .run(&mut Chunk(Some(rest.clone())), &f.tracker)
        .await
        .unwrap();
    assert_stream(&f, verdict, 0, LOW, 2);
    assert!(AsyncStreamVerifier::resume(cursor)
        .run(&mut Chunk(Some(rest)), &f.tracker)
        .await
        .unwrap()
        .is_valid());
    let mut cleared = AsyncStreamVerifier::new(None).with_work_budget(Some(LOW));
    cleared.set_work_limit(None);
    assert!(cleared
        .run(&mut Chunk(Some(bytes)), &f.tracker)
        .await
        .unwrap()
        .is_valid());
}

#[tokio::test]
async fn an_unproven_ancestor_gets_the_same_work_budget_378() {
    let f = Fixture::new(true, 1, false);
    let mut root = Transaction::new();
    let mut input = TransactionInput::with_source_transaction(f.tx.clone(), 0);
    input.set_unlocking_script(UnlockingScript::new());
    root.add_input(input).unwrap();
    root.add_output(TransactionOutput::new(
        800,
        LockingScript::from_hex("51").unwrap(),
    ))
    .unwrap();
    let error = root
        .verify_with_work_budget(&f.tracker, None, None, Some(LOW))
        .await
        .unwrap_err();
    assert_whole(&f, error, 0, LOW, 2);
}
