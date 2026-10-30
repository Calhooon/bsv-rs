//! #519: transaction work is charged in input order, independently of the input bound.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::block::ChainParams;
use bsv_rs::primitives::Writer;
use bsv_rs::script::{LockingScript, NotJudgedCause, Script, Spend, SpendParams, UnlockingScript};
use bsv_rs::transaction::beef_stream::SpendRefusal;
use bsv_rs::transaction::{
    AsyncByteSource, AsyncStreamVerifier, Beef, Cursor, MerklePath, MockChainTracker, Progress,
    StreamVerifier, Timed, Transaction, TransactionInput, TransactionOutput, Verdict, WorkBudget,
    BEEF_V1,
};
use bsv_rs::Error;

struct Fixture {
    tx: Transaction,
    tracker: MockChainTracker,
}

impl Fixture {
    fn new() -> Self {
        let mut parent = Transaction::new();
        let mut dummy = TransactionInput::new("aa".repeat(32), 0);
        dummy.set_unlocking_script(UnlockingScript::new());
        parent.add_input(dummy).unwrap();
        for _ in 0..3 {
            parent
                .add_output(TransactionOutput::new(
                    1_000,
                    LockingScript::from_asm("OP_SHA256 OP_DROP OP_1").unwrap(),
                ))
                .unwrap();
        }
        let mut tracker = MockChainTracker::new(800_000);
        tracker.add_root(800_000, parent.id());
        parent.merkle_path = Some(MerklePath::from_coinbase_txid(&parent.id(), 800_000));
        let mut tx = Transaction::new();
        tx.version = 2;
        for (vin, bytes) in [64, 2, 4].into_iter().enumerate() {
            let mut input = TransactionInput::with_source_transaction(parent.clone(), vin as u32);
            let mut unlock = Script::new();
            unlock.write_bin(&vec![7; bytes]);
            input.set_unlocking_script(UnlockingScript::from_script(unlock));
            tx.add_input(input).unwrap();
        }
        tx.add_output(TransactionOutput::new(
            900,
            LockingScript::from_asm("OP_1").unwrap(),
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

    async fn whole(&self, budget: WorkBudget, word: bool) -> bsv_rs::Result<bool> {
        if word {
            self.tx
                .verify_with_chain_params_and_work_budgets(
                    &self.tracker,
                    None,
                    None,
                    budget,
                    &ChainParams::mainnet(),
                )
                .await
        } else {
            self.tx
                .verify_with_work_budgets(&self.tracker, None, None, budget)
                .await
        }
    }

    fn sync(&self, bytes: &[u8], budget: WorkBudget, word: bool) -> (Verdict, u64) {
        let mut reader = StreamVerifier::new(bytes, &self.tracker, None)
            .with_work_budget(budget.per_input)
            .with_transaction_work_budget(budget.per_transaction);
        if word {
            reader = reader.with_chain_params(ChainParams::mainnet());
        }
        finish(reader)
    }

    async fn asynchronous(&self, bytes: Vec<u8>, budget: WorkBudget, word: bool) -> (Verdict, u64) {
        let mut reader = AsyncStreamVerifier::new(None)
            .with_work_budget(budget.per_input)
            .with_transaction_work_budget(budget.per_transaction);
        if word {
            reader = reader.with_chain_params(ChainParams::mainnet());
        }
        let verdict = reader
            .run(&mut Chunk(Some(bytes)), &self.tracker)
            .await
            .unwrap();
        (verdict, reader.work_spent())
    }
}

struct Chunk(Option<Vec<u8>>);
impl AsyncByteSource for Chunk {
    async fn next_chunk(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        Ok(self.0.take())
    }
}

fn budget(input: Option<u64>, transaction: Option<u64>) -> WorkBudget {
    WorkBudget::default()
        .with_work_budget(input)
        .with_transaction_work_budget(transaction)
}

fn cause() -> NotJudgedCause {
    NotJudgedCause::TransactionWorkBudgetExceeded {
        input: 1,
        limit: 70,
        total: 74,
    }
}

fn finish(mut reader: StreamVerifier<&[u8], &MockChainTracker>) -> (Verdict, u64) {
    loop {
        if let Progress::Verdict(verdict) = reader.step().unwrap() {
            return (verdict, reader.work_spent());
        }
    }
}

fn assert_stream(f: &Fixture, result: (Verdict, u64)) {
    assert_eq!(result.1, 74);
    assert_eq!(result.0.work_spent(), Some(74));
    assert!(!result.0.is_valid());
    match result.0 {
        Verdict::NotJudged {
            txid,
            input,
            offset,
            cause: actual,
        } => {
            assert_eq!(txid, f.tx.hash());
            assert_eq!(input, 1);
            assert!(offset > 0);
            assert_eq!(actual, cause());
        }
        other => panic!("expected transaction work refusal, got {other:?}"),
    }
}

fn assert_whole(f: &Fixture, error: Error) {
    assert_eq!(
        error,
        Error::TransactionNotJudged {
            txid: f.tx.id(),
            input_index: 1,
            cause: cause(),
        }
    );
    assert_eq!(error, error.clone());
    assert_eq!(error.to_string(), format!(
        "transaction {} input 1 not judged: exceeded transaction work budget 70 units after 74 units of work.", f.tx.id(),
    ));
}

#[tokio::test]
async fn individually_green_inputs_cross_the_transaction_budget_in_order_519() {
    let f = Fixture::new();
    for word in [false, true] {
        assert_whole(
            &f,
            f.whole(budget(Some(68), Some(70)), word).await.unwrap_err(),
        );
        for deferred in [false, true] {
            let bytes = f.bytes(deferred);
            assert_stream(&f, f.sync(&bytes, budget(Some(68), Some(70)), word));
            assert_stream(
                &f,
                f.asynchronous(bytes, budget(Some(68), Some(70)), word)
                    .await,
            );
        }
    }
    // The heaviest input is input 0; the crossing input is input 1.
    let measured: Vec<_> =
        f.tx.inputs
            .iter()
            .enumerate()
            .map(|(vin, input)| {
                let source = input.source_transaction.as_ref().unwrap();
                let mut spend = Spend::new(SpendParams {
                    source_txid: source.hash(),
                    source_output_index: vin as u32,
                    source_satoshis: 1_000,
                    locking_script: source.outputs[vin].locking_script.clone(),
                    transaction_version: 2,
                    other_inputs: vec![],
                    outputs: vec![],
                    input_index: vin,
                    unlocking_script: input.unlocking_script.clone().unwrap(),
                    input_sequence: u32::MAX,
                    lock_time: 0,
                    memory_limit: None,
                    work_limit: Some(68),
                });
                assert!(spend.validate().unwrap());
                spend.work_spent()
            })
            .collect();
    assert_eq!(measured, [68, 6, 8]);
}

#[tokio::test]
async fn exact_and_higher_totals_preserve_the_verdict_on_every_path_519() {
    let f = Fixture::new();
    for word in [false, true] {
        for total in [Some(82), Some(83), Some(u64::MAX), None] {
            let policy = budget(Some(68), total);
            assert!(f.whole(policy, word).await.unwrap());
            for deferred in [false, true] {
                let bytes = f.bytes(deferred);
                let expected = f.sync(&bytes, WorkBudget::default(), word).0;
                let sync = f.sync(&bytes, policy, word);
                assert_eq!(sync.0, expected);
                assert_eq!(sync.1, 82);
                let asynchronous = f.asynchronous(bytes, policy, word).await;
                assert_eq!(asynchronous.0, expected);
                assert_eq!(asynchronous.1, 82);
            }
        }
    }
}

#[tokio::test]
async fn a_transaction_only_budget_enables_the_same_input_counter_519() {
    let f = Fixture::new();
    for word in [false, true] {
        assert_whole(&f, f.whole(budget(None, Some(70)), word).await.unwrap_err());
        for deferred in [false, true] {
            let bytes = f.bytes(deferred);
            assert_stream(&f, f.sync(&bytes, budget(None, Some(70)), word));
            assert_stream(
                &f,
                f.asynchronous(bytes, budget(None, Some(70)), word).await,
            );
        }
    }
}

#[tokio::test]
async fn the_per_input_refusal_keeps_its_cause_when_both_limits_are_exceeded_519() {
    let f = Fixture::new();
    let expected = NotJudgedCause::WorkBudgetExceeded {
        input: 0,
        budget: 65,
        work_done: 2,
    };
    for word in [false, true] {
        assert_eq!(
            f.whole(budget(Some(65), Some(1)), word).await.unwrap_err(),
            Error::TransactionNotJudged {
                txid: f.tx.id(),
                input_index: 0,
                cause: expected
            }
        );
        for deferred in [false, true] {
            let bytes = f.bytes(deferred);
            for (verdict, spent) in [
                f.sync(&bytes, budget(Some(65), Some(1)), word),
                f.asynchronous(bytes, budget(Some(65), Some(1)), word).await,
            ] {
                assert_eq!(spent, 2);
                assert!(
                    matches!(verdict, Verdict::NotJudged { input: 0, cause, .. } if cause == expected)
                );
            }
        }
    }
}

#[tokio::test]
async fn zero_transaction_budget_charges_the_crossing_input_before_declining_519() {
    let f = Fixture::new();
    let expected = NotJudgedCause::TransactionWorkBudgetExceeded {
        input: 0,
        limit: 0,
        total: 68,
    };
    assert!(matches!(f.whole(budget(None, Some(0)), false).await,
        Err(Error::TransactionNotJudged { cause, .. }) if cause == expected));
    let (verdict, total) = f.sync(&f.bytes(false), budget(None, Some(0)), false);
    assert_eq!(total, 68);
    assert!(matches!(verdict, Verdict::NotJudged { cause, .. } if cause == expected));
}

#[tokio::test]
async fn charged_work_survives_pauses_and_both_cursor_resume_paths_519() {
    let f = Fixture::new();
    for deferred in [false, true] {
        let bytes = f.bytes(deferred);
        let mut reader = StreamVerifier::new(bytes.as_slice(), &f.tracker, None)
            .with_work_budget(Some(68))
            .with_transaction_work_budget(Some(70));
        while reader.work_spent() == 0 {
            if reader.step_until(&mut || true).unwrap() == Timed::Paused {
                break;
            }
        }
        assert_eq!(reader.work_spent(), 68);
        let saved = reader.cursor();
        assert_eq!(saved.input_reached(), Some(1));
        let encoded = saved.to_binary();
        assert_eq!(&encoded[..4], b"BSC5");
        for cursor in [saved, Cursor::from_binary(&encoded).unwrap()] {
            let rest = &bytes[cursor.offset() as usize..];
            let resumed = StreamVerifier::resume(cursor.clone(), rest, &f.tracker)
                .with_work_budget(Some(68))
                .with_transaction_work_budget(Some(70));
            assert_eq!(resumed.work_spent(), 68);
            assert_stream(&f, finish(resumed));
            let mut asynchronous = AsyncStreamVerifier::resume(cursor)
                .with_work_budget(Some(68))
                .with_transaction_work_budget(Some(70));
            let verdict = asynchronous
                .run(&mut Chunk(Some(rest.to_vec())), &f.tracker)
                .await
                .unwrap();
            assert_stream(&f, (verdict, asynchronous.work_spent()));
        }
        assert_stream(&f, finish(reader));
    }
}

#[test]
fn applying_a_budget_to_an_old_unmetered_cursor_replays_its_prefix_519() {
    let f = Fixture::new();
    let bytes = f.bytes(false);
    let mut reader = StreamVerifier::new(bytes.as_slice(), &f.tracker, None);
    while reader.cursor().input_reached().is_none() {
        reader.step_until(&mut || true).unwrap();
    }
    let encoded = reader.cursor().to_binary();
    assert_eq!(&encoded[..4], b"BSC3");
    let cursor = Cursor::from_binary(&encoded).unwrap();
    let resumed = StreamVerifier::resume(
        cursor.clone(),
        &bytes[cursor.offset() as usize..],
        &f.tracker,
    )
    .with_transaction_work_budget(Some(70));
    assert_stream(&f, finish(resumed));
}

#[tokio::test]
async fn each_transaction_gets_its_own_total_including_unproven_ancestors_519() {
    let mut f = Fixture::new();
    let ancestor = f.tx.clone();
    let mut root = Transaction::new();
    let mut input = TransactionInput::with_source_transaction(ancestor.clone(), 0);
    input.set_unlocking_script(UnlockingScript::new());
    root.add_input(input).unwrap();
    root.add_output(TransactionOutput::new(
        800,
        LockingScript::from_asm("OP_1").unwrap(),
    ))
    .unwrap();
    f.tx = root;
    for word in [false, true] {
        assert!(f.whole(budget(Some(68), Some(82)), word).await.unwrap());
        assert_eq!(
            f.whole(budget(Some(68), Some(70)), word).await.unwrap_err(),
            Error::TransactionNotJudged {
                txid: ancestor.id(),
                input_index: 1,
                cause: cause()
            }
        );
        let bytes = f.bytes(false);
        let (verdict, total) = f.sync(&bytes, budget(Some(68), Some(82)), word);
        assert!(verdict.is_valid());
        assert_eq!(total, 1);
    }
}

#[tokio::test]
async fn proven_and_structure_only_transactions_still_spend_no_work_519() {
    let mut f = Fixture::new();
    f.tx.merkle_path = Some(MerklePath::from_coinbase_txid(&f.tx.id(), 800_001));
    f.tracker.add_root(800_001, f.tx.id());
    for word in [false, true] {
        assert!(f.whole(budget(Some(0), Some(0)), word).await.unwrap());
        let bytes = f.bytes(false);
        let (verdict, total) = f.sync(&bytes, budget(Some(0), Some(0)), word);
        assert!(verdict.is_valid());
        assert_eq!(total, 0);
    }
    let f = Fixture::new();
    let bytes = f.bytes(false);
    let reader = StreamVerifier::structure_only(bytes.as_slice(), &f.tracker, None)
        .with_work_budget(Some(0))
        .with_transaction_work_budget(Some(0));
    let (verdict, total) = finish(reader);
    assert!(verdict.is_valid());
    assert_eq!(total, 0);
}

#[test]
fn the_cause_keeps_the_error_size_and_the_existing_display_words_519() {
    #[cfg(target_pointer_width = "64")]
    {
        assert_eq!(std::mem::size_of::<NotJudgedCause>(), 24);
        assert_eq!(std::mem::size_of::<Error>(), 56);
    }
    assert_eq!(
        budget(Some(68), Some(70)),
        WorkBudget {
            per_input: Some(68),
            per_transaction: Some(70)
        }
    );
    let refusal = SpendRefusal::NotJudged {
        input: 1,
        cause: cause(),
    };
    assert_eq!(
        refusal.to_string(),
        "input 1 not judged: exceeded transaction work budget 70 units after 74 units of work."
    );
    println!(
        "size_of: NotJudgedCause = {}, Error = {}",
        std::mem::size_of::<NotJudgedCause>(),
        std::mem::size_of::<Error>()
    );
}
