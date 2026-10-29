//! #452: scope refusals carry an input and typed cause, never a script failure.
//! #451: the sole Genesis authority is ChainParams, including the P2SH check.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Cursor;

use bsv_rs::block::{ActivationHeightsError, ChainParams};
use bsv_rs::primitives::Writer;
use bsv_rs::script::{LockingScript, NotJudgedCause, UnlockingScript};
use bsv_rs::transaction::beef_stream::{ChainTip, SpendRefusal};
use bsv_rs::transaction::{
    verify_stream_two_pass_with_chain_params, AsyncByteSource, AsyncStreamVerifier, Beef,
    MerklePath, MockChainTracker, StreamVerifier, Transaction, TransactionInput, TransactionOutput,
    Verdict, BEEF_V1,
};
use bsv_rs::Error;

const GENESIS: u32 = 620_538;
const CHRONICLE: u32 = 943_816;

#[derive(Clone, Copy, Debug)]
enum Case {
    Coin,
    Tip,
    ZeroGenesis,
    ZeroChronicle,
}

impl Case {
    fn input(self) -> u32 {
        if matches!(self, Self::Coin) {
            1
        } else {
            0
        }
    }

    fn sentence(self) -> &'static str {
        match self {
            Self::Coin => "input 1 not judged: coin height 620537 is before Genesis height 620538.",
            Self::Tip => "input 0 not judged: tip height 4294967295 cannot produce a spend height within u32 (maximum 4294967295).",
            Self::ZeroGenesis => "input 0 not judged: Genesis activation height 0 is outside the supported range 1..=4294967295.",
            Self::ZeroChronicle => "input 0 not judged: Chronicle activation height 0 is outside the supported range 1..=4294967295.",
        }
    }
}

fn assert_cause(case: Case, cause: NotJudgedCause) {
    match (case, cause) {
        (
            Case::Coin,
            NotJudgedCause::PreGenesisCoin {
                height,
                genesis_height,
            },
        ) => {
            assert_eq!((height, genesis_height), (GENESIS - 1, GENESIS));
        }
        (Case::Tip, NotJudgedCause::TipHeightOverflow { tip }) => assert_eq!(tip, u32::MAX),
        (Case::ZeroGenesis, NotJudgedCause::ZeroActivationHeight(which)) => {
            assert_eq!(which, ActivationHeightsError::ZeroGenesis);
        }
        (Case::ZeroChronicle, NotJudgedCause::ZeroActivationHeight(which)) => {
            assert_eq!(which, ActivationHeightsError::ZeroChronicle);
        }
        other => panic!("wrong typed cause: {other:?}"),
    }
}

fn assert_stream(case: Case, verdict: Verdict, tx: &Transaction) {
    assert!(!verdict.is_valid());
    match verdict {
        Verdict::NotJudged {
            txid,
            input,
            offset,
            cause,
        } => {
            assert_eq!(txid, tx.hash());
            assert_eq!(input, case.input());
            assert!(offset > 0);
            assert_cause(case, cause);
            let sentence = format!("input {input} not judged: {cause}");
            assert_eq!(sentence, case.sentence());
            assert!(!sentence.contains("Script validation failed"));
        }
        other => panic!("expected NotJudged for {case:?}, got {other:?}"),
    }
}

fn assert_whole(case: Case, error: Error) {
    match &error {
        Error::TransactionNotJudged { input_index, cause } => {
            assert_eq!(*input_index, case.input() as usize);
            assert_cause(case, *cause);
        }
        other => panic!("expected TransactionNotJudged for {case:?}, got {other:?}"),
    }
    assert_eq!(error.to_string(), case.sentence());
    assert!(!error.to_string().contains("Script validation failed"));
}

fn source(height: u32) -> Transaction {
    let mut tx = Transaction::new();
    let mut input = TransactionInput::new("aa".repeat(32), 0);
    input.set_unlocking_script(UnlockingScript::new());
    tx.add_input(input).unwrap();
    tx.add_output(TransactionOutput::new(
        1_000,
        LockingScript::from_hex("51").unwrap(),
    ))
    .unwrap();
    tx.lock_time = height;
    tx.merkle_path = Some(MerklePath::from_coinbase_txid(&tx.id(), height));
    tx
}

fn spending(case: Case) -> Transaction {
    let mut tx = Transaction::new();
    let heights = if matches!(case, Case::Coin) {
        vec![GENESIS, GENESIS - 1]
    } else {
        vec![GENESIS]
    };
    for height in heights {
        let mut input = TransactionInput::with_source_transaction(source(height), 0);
        input.set_unlocking_script(UnlockingScript::new());
        tx.add_input(input).unwrap();
    }
    tx.add_output(TransactionOutput::new(
        900,
        LockingScript::from_hex("51").unwrap(),
    ))
    .unwrap();
    tx
}

#[allow(deprecated)] // Set the compatibility field deliberately; no verifier may read it (#451).
fn tip(height: u32, obsolete_genesis: u32) -> ChainTip {
    ChainTip {
        height,
        median_time_past: 0,
        genesis_height: obsolete_genesis,
        csv_height: 0,
        next_block_time: None,
    }
}

fn chain(case: Case) -> ChainParams {
    let mut chain = ChainParams::mainnet();
    match case {
        Case::ZeroGenesis => chain.genesis_height = 0,
        Case::ZeroChronicle => chain.chronicle_height = 0,
        _ => {}
    }
    chain
}

fn tracker(tx: &Transaction, tip: Option<ChainTip>) -> MockChainTracker {
    let mut tracker = MockChainTracker::new(CHRONICLE).with_mining_tip(tip);
    for input in &tx.inputs {
        let source = input.source_transaction.as_ref().unwrap();
        let proof = source.merkle_path.as_ref().unwrap();
        tracker.add_root(
            proof.block_height,
            proof.compute_root(Some(&source.id())).unwrap(),
        );
    }
    tracker
}

fn bytes(tx: &Transaction, deferred: bool) -> Vec<u8> {
    let bytes = tx.to_beef(false).unwrap();
    if !deferred {
        return bytes;
    }
    let beef = Beef::from_binary(&bytes).unwrap();
    let mut writer = Writer::new();
    writer.write_u32_le(BEEF_V1);
    writer.write_var_int(beef.bumps.len() as u64);
    for bump in &beef.bumps {
        writer.write_bytes(&bump.to_binary());
    }
    writer.write_var_int(beef.txs.len() as u64);
    for entry in beef.txs.iter().rev() {
        entry.to_writer(&mut writer, BEEF_V1);
    }
    writer.into_bytes()
}

struct Chunk(Option<Vec<u8>>);
impl AsyncByteSource for Chunk {
    async fn next_chunk(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        Ok(self.0.take())
    }
}

async fn stream_case(case: Case) {
    let tx = spending(case);
    let height = if matches!(case, Case::Tip) {
        u32::MAX
    } else {
        CHRONICLE
    };
    for tip in [Some(tip(height, GENESIS)), None] {
        if matches!(case, Case::Tip) && tip.is_none() {
            continue;
        }
        let tracker = tracker(&tx, tip);
        for deferred in [false, true] {
            let bytes = bytes(&tx, deferred);
            let reader = StreamVerifier::new(bytes.as_slice(), &tracker, Some(tx.hash()))
                .with_chain_params(chain(case));
            assert_stream(case, reader.run().unwrap(), &tx);
            assert_stream(
                case,
                verify_stream_two_pass_with_chain_params(
                    Cursor::new(&bytes),
                    &tracker,
                    Some(tx.hash()),
                    &chain(case),
                )
                .unwrap(),
                &tx,
            );
            let mut reader =
                AsyncStreamVerifier::new(Some(tx.hash())).with_chain_params(chain(case));
            assert_stream(
                case,
                reader.run(&mut Chunk(Some(bytes)), &tracker).await.unwrap(),
                &tx,
            );
        }
    }
}

async fn whole_case(case: Case) {
    let tx = spending(case);
    let height = if matches!(case, Case::Tip) {
        u32::MAX
    } else {
        CHRONICLE
    };
    for tip in [Some(tip(height, GENESIS)), None] {
        if matches!(case, Case::Tip) && tip.is_none() {
            continue;
        }
        let tracker = tracker(&tx, tip);
        assert_whole(
            case,
            tx.verify_with_chain_params(&tracker, None, None, &chain(case))
                .await
                .unwrap_err(),
        );
    }
}

#[tokio::test]
async fn a_pre_genesis_coin_is_not_judged_by_the_stream_452() {
    stream_case(Case::Coin).await;
}

#[tokio::test]
async fn an_overflowing_tip_is_not_judged_by_the_stream_452() {
    stream_case(Case::Tip).await;
}

#[tokio::test]
async fn a_zero_activation_is_not_judged_by_the_stream_452() {
    stream_case(Case::ZeroGenesis).await;
    stream_case(Case::ZeroChronicle).await;
}

#[tokio::test]
async fn a_pre_genesis_coin_is_not_judged_by_the_whole_path_452() {
    whole_case(Case::Coin).await;
}

#[tokio::test]
async fn an_overflowing_tip_is_not_judged_by_the_whole_path_452() {
    whole_case(Case::Tip).await;
}

#[tokio::test]
async fn a_zero_activation_is_not_judged_by_the_whole_path_452() {
    whole_case(Case::ZeroGenesis).await;
    whole_case(Case::ZeroChronicle).await;
}

#[tokio::test]
async fn chain_params_alone_decide_when_the_tip_disagrees_451() {
    let tx = spending(Case::Tip);
    let tracker = tracker(&tx, Some(tip(CHRONICLE, u32::MAX)));
    assert!(tx
        .verify_with_chain_params(&tracker, None, None, &ChainParams::mainnet())
        .await
        .unwrap());
    assert!(
        StreamVerifier::new(tx.to_beef(false).unwrap().as_slice(), &tracker, None)
            .with_chain_params(ChainParams::mainnet())
            .run()
            .unwrap()
            .is_valid()
    );

    // P2SH output rejection previously read the obsolete field, even though
    // the input's word already read ChainParams. Exercise that distinct site.
    let mut p2sh = tx.clone();
    p2sh.outputs[0].locking_script =
        LockingScript::from_hex("a914000000000000000000000000000000000000000087").unwrap();
    p2sh.invalidate_caches();
    for (height, obsolete, refused) in [(GENESIS - 1, u32::MAX, true), (GENESIS - 2, 1, false)] {
        let tracker = tracker_for_p2sh(&p2sh, height, obsolete);
        let verdict = StreamVerifier::new(p2sh.to_beef(false).unwrap().as_slice(), &tracker, None)
            .with_chain_params(ChainParams::mainnet())
            .run()
            .unwrap();
        assert_eq!(
            matches!(
                &verdict,
                Verdict::SpendRefused {
                    why: SpendRefusal::P2shOutput { .. },
                    ..
                }
            ),
            refused,
            "{verdict:?}"
        );
    }
}

fn tracker_for_p2sh(tx: &Transaction, height: u32, obsolete: u32) -> MockChainTracker {
    tracker(tx, Some(tip(height, obsolete)))
}
