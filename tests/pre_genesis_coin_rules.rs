//! A coin created before Genesis is judged by the rules of its era at every
//! default door that proves its height (GHSA-h4m7-c6p8-725m).
//!
//! A coin is judged by the era of the block that created it (bitcoin-sv
//! v1.2.3 `src/script/interpreter.cpp:411`): for a coin from before Genesis,
//! the post-Genesis rules plus the refusals of `src/script/spend/pre_genesis.rs`.
//! `Transaction::verify` and the streaming reader prove a coin's height (the
//! parent's merkle path, the BUMP that proves the parent), and until this fix
//! judged every coin by the post-Genesis rules alone, so a spend that breaks
//! one of the older rules was answered valid. `Spend` and the one-input door
//! (`verify_input`), given no height, are unchanged; chain parameters decline
//! a coin from before Genesis, as before.
//!
//! The fixtures are this crate's writer's: a parent proven at height 600,000
//! (below mainnet's Genesis, 620,538) paying the coin, and an unproven child
//! spending it, read at a tip whose next block is 900,100. Each refused cell
//! breaks one rule of the table and keeps every other; its answer is typed
//! from the rule, never computed from the code under test.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Cursor;

use bsv_rs::block::ChainParams;
use bsv_rs::primitives::{hash160, PrivateKey};
use bsv_rs::script::{LockingScript, ProtocolEra, Script, SigningContext, UnlockingScript};
use bsv_rs::transaction::beef_stream::{ChainTip, SpendRefusal};
use bsv_rs::transaction::{
    verify_input, verify_stream, verify_stream_two_pass, verify_stream_two_pass_with_chain_params,
    AsyncByteSource, AsyncStreamVerifier, InputRules, MerklePath, MockChainTracker, StreamVerifier,
    Transaction, TransactionInput, TransactionOutput, Verdict, WorkBudget,
};

const COIN_HEIGHT: u32 = 600_000;
const NEXT_BLOCK: u32 = 900_100;
const COIN_VALUE: u64 = 10_000;
const FORKID_ALL: u32 = 0x41;
const MAINNET_GENESIS: u32 = 620_538;

fn key() -> PrivateKey {
    PrivateKey::from_hex("7e57000000000000000000000000000000000000000000000000000000000002")
        .unwrap()
}

fn public_key() -> Vec<u8> {
    key().public_key().to_compressed().to_vec()
}

fn push(data: &[u8]) -> Vec<u8> {
    let mut script = Script::new();
    script.write_bin(data);
    script.to_binary()
}

fn p2pkh() -> Vec<u8> {
    let mut lock = vec![0x76, 0xa9, 0x14];
    lock.extend(hash160(&public_key()));
    lock.extend([0x88, 0xac]);
    lock
}

fn p2sh(redeem: &[u8]) -> Vec<u8> {
    let mut lock = vec![0xa9, 0x14];
    lock.extend(hash160(redeem));
    lock.push(0x87);
    lock
}

/// `<lock time> OP_CHECKLOCKTIMEVERIFY OP_DROP <key> OP_CHECKSIG`.
fn cltv(lock_time: &[u8]) -> Vec<u8> {
    let mut lock = push(lock_time);
    lock.extend([0xb1, 0x75]);
    lock.extend(push(&public_key()));
    lock.push(0xac);
    lock
}

/// `OP_10 OP_CHECKSEQUENCEVERIFY OP_DROP <key> OP_CHECKSIG`.
fn csv() -> Vec<u8> {
    let mut lock = vec![0x5a, 0xb2, 0x75];
    lock.extend(push(&public_key()));
    lock.push(0xac);
    lock
}

/// A spend: the coin's locking script, the redeem script when the coin is a
/// P2SH, what the payer pushes below the signature, the child's version, lock
/// time and sequence, and whether the coin's script (or its redeem) is signed.
#[derive(Clone)]
struct Cell {
    name: &'static str,
    lock: Vec<u8>,
    redeem: Option<Vec<u8>>,
    below: Vec<u8>,
    version: u32,
    lock_time: u32,
    sequence: u32,
    signed: bool,
}

fn cell(name: &'static str, lock: Vec<u8>, version: u32) -> Cell {
    Cell {
        name,
        lock,
        redeem: None,
        below: Vec::new(),
        version,
        lock_time: 0,
        sequence: 0xffff_ffff,
        signed: false,
    }
}

fn signed(name: &'static str, lock: Vec<u8>, version: u32, below: Vec<u8>) -> Cell {
    Cell {
        below,
        signed: true,
        ..cell(name, lock, version)
    }
}

fn parent(lock: &[u8], height: u32) -> Transaction {
    let mut tx = Transaction::new();
    let mut input = TransactionInput::new("ab".repeat(32), 0);
    input.set_unlocking_script(UnlockingScript::new());
    tx.add_input(input).unwrap();
    tx.add_output(TransactionOutput::new(
        COIN_VALUE,
        LockingScript::from_binary(lock).unwrap(),
    ))
    .unwrap();
    tx.merkle_path = Some(MerklePath::from_coinbase_txid(&tx.id(), height));
    tx
}

fn child(cell: &Cell, parent: Transaction, unlocking: &[u8]) -> Transaction {
    let mut tx = Transaction::new();
    tx.set_version(cell.version);
    tx.set_lock_time(cell.lock_time);
    let mut input = TransactionInput::with_source_transaction(parent, 0);
    input.sequence = cell.sequence;
    input.set_unlocking_script(UnlockingScript::from_binary(unlocking).unwrap());
    tx.add_input(input).unwrap();
    tx.add_output(TransactionOutput::new(
        9_000,
        LockingScript::from_binary(&[0x51]).unwrap(),
    ))
    .unwrap();
    tx
}

fn signature(tx: &Transaction, script_code: &[u8]) -> Vec<u8> {
    let code = Script::from_binary(script_code).unwrap();
    let digest = SigningContext::new(&tx.to_binary(), 0, COIN_VALUE, &code)
        .compute_sighash(FORKID_ALL)
        .unwrap();
    let mut signature = key().sign(&digest).unwrap().to_der();
    signature.push(FORKID_ALL as u8);
    signature
}

/// The child of `cell` spending a coin proven at `height`.
fn spend_at(cell: &Cell, height: u32) -> Transaction {
    spend_of(cell, parent(&cell.lock, height))
}

/// The child of `cell` spending output 0 of `coin`.
fn spend_of(cell: &Cell, coin: Transaction) -> Transaction {
    let code = cell.redeem.clone().unwrap_or_else(|| cell.lock.clone());
    let mut unlocking = cell.below.clone();
    if cell.signed {
        let unsigned = child(cell, coin.clone(), &[]);
        unlocking.extend(push(&signature(&unsigned, &code)));
        if code == p2pkh() {
            unlocking.extend(push(&public_key()));
        }
    }
    if let Some(redeem) = &cell.redeem {
        unlocking.extend(push(redeem));
    }
    child(cell, coin, &unlocking)
}

fn spend(cell: &Cell) -> Transaction {
    spend_at(cell, COIN_HEIGHT)
}

/// One cell for each rule of the era (`pre_genesis.rs`'s table): the node
/// refuses each for a coin from before Genesis; the default mode's
/// post-Genesis rules accept each.
fn refused_by_the_rules_of_the_era() -> Vec<Cell> {
    let mut many_ops = vec![0x61; 501];
    many_ops.push(0x51);
    // 481 opcodes, then a 0-of-20 OP_CHECKMULTISIG (one opcode, 20 keys).
    let mut keys_counted = vec![0x61; 481];
    keys_counted.extend([0x00, 0x00]);
    for _ in 0..20 {
        keys_counted.extend(push(&public_key()));
    }
    keys_counted.extend([0x01, 20, 0xae]);
    let mut twenty_one = vec![0x00, 0x00];
    for _ in 0..21 {
        twenty_one.extend(push(&public_key()));
    }
    twenty_one.extend([0x01, 21, 0xae]);
    let mut wide_cat = push(&[7u8; 300]);
    wide_cat.extend(push(&[8u8; 300]));
    wide_cat.extend([0x7e, 0x75, 0x51]);
    let mut wide_operand = push(&[0, 0, 0, 0, 1]);
    wide_operand.extend([0x8b, 0x75, 0x51]);
    let mut wide_bin2num = push(&[0, 0, 0, 0, 1]);
    wide_bin2num.extend([0x81, 0x75, 0x51]);
    let mut substr = push(b"abc");
    substr.extend([0x51, 0x51, 0xb3]);
    substr.extend(push(b"b"));
    substr.push(0x87);
    let deep = vec![0x00; 1_001];
    let mut big = Vec::new();
    for _ in 0..20 {
        big.extend(push(&[9u8; 500]));
    }
    let two_mul = vec![0x52, 0x8d, 0x54, 0x87];
    vec![
        signed("a push above 520 bytes", p2pkh(), 2, push(&[7u8; 521])),
        // 997 below the signature and key: 1,001 elements once the lock
        // pushes its hash, one past the bound.
        signed("exactly 1,001 stack elements", p2pkh(), 2, vec![0x00; 997]),
        unlocking_of(10_001),
        signed("more than 1,000 stack elements", p2pkh(), 2, deep),
        signed("an unlocking script above 10,000 bytes", p2pkh(), 2, big),
        cell("more than 500 opcodes", many_ops, 2),
        cell(
            "OP_CHECKMULTISIG's keys counted as opcodes",
            keys_counted,
            2,
        ),
        cell("more than 20 keys", twenty_one, 2),
        cell("OP_2MUL executed", two_mul.clone(), 2),
        cell(
            "OP_2MUL in an unexecuted branch",
            vec![0x00, 0x63, 0x8d, 0x68, 0x51],
            1,
        ),
        cell(
            "OP_VERIF in an unexecuted branch",
            // The default mode runs the Chronicle opcodes at every version on
            // this line: an unexecuted OP_VERIF opens a branch of its own.
            vec![0x00, 0x63, 0x65, 0x68, 0x68, 0x51],
            1,
        ),
        cell("OP_VER executed", vec![0x62, 0x75, 0x51], 2),
        cell("OP_SUBSTR read as OP_NOP4", substr, 2),
        cell("an executed OP_RETURN", vec![0x51, 0x6a], 2),
        cell("a number operand of 5 bytes", wide_operand, 2),
        cell("OP_BIN2NUM's result of 5 bytes", wide_bin2num, 2),
        cell("OP_CAT's result above 520 bytes", wide_cat, 2),
        cell(
            "OP_NUM2BIN's size above 520 bytes",
            vec![0x51, 0x02, 0x09, 0x02, 0x80, 0x75, 0x51],
            2,
        ),
        signed(
            "OP_CHECKLOCKTIMEVERIFY before its lock time",
            cltv(&[0xa0, 0xbb, 0x0d]),
            2,
            vec![],
        ),
        signed(
            "OP_CHECKSEQUENCEVERIFY on a final sequence",
            csv(),
            2,
            vec![],
        ),
        Cell {
            redeem: Some(p2pkh()),
            ..signed(
                "a P2SH's redeem step with a push above 520 bytes",
                p2sh(&p2pkh()),
                2,
                push(&[7u8; 521]),
            )
        },
        Cell {
            redeem: Some(cltv(&[0xa0, 0xbb, 0x0d])),
            ..signed(
                "a P2SH's redeem step before its lock time",
                p2sh(&cltv(&[0xa0, 0xbb, 0x0d])),
                2,
                vec![],
            )
        },
        Cell {
            redeem: Some(two_mul.clone()),
            ..cell("a P2SH's redeem step executing OP_2MUL", p2sh(&two_mul), 2)
        },
    ]
}

/// Spends the node accepts for a coin from before Genesis.
fn accepted_by_the_rules_of_the_era() -> Vec<Cell> {
    let lock = cltv(&[0xa0, 0xbb, 0x0d]);
    // 4-byte operands, an 8-byte product: the era bounds operands, not results.
    let mut wide_result = push(&[0xff, 0xff, 0xff, 0x7f]);
    wide_result.extend(push(&[0xff, 0xff, 0xff, 0x7f]));
    wide_result.push(0x95);
    wide_result.extend(push(&[0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x3f]));
    wide_result.push(0x87);
    let stack_at_the_bound = vec![0x00; 996];
    vec![
        signed("a P2PKH spend, version 1", p2pkh(), 1, vec![]),
        signed("a P2PKH spend, version 2", p2pkh(), 2, vec![]),
        signed(
            "a push of 520 bytes below the signature",
            p2pkh(),
            2,
            push(&[7u8; 520]),
        ),
        signed(
            "1,000 stack elements at the most",
            p2pkh(),
            2,
            stack_at_the_bound,
        ),
        Cell {
            redeem: Some(p2pkh()),
            ..signed("a P2SH(P2PKH) spend", p2sh(&p2pkh()), 2, vec![])
        },
        Cell {
            lock_time: 900_000,
            sequence: 0xffff_fffe,
            ..signed(
                "OP_CHECKLOCKTIMEVERIFY after its lock time",
                lock.clone(),
                1,
                vec![],
            )
        },
        Cell {
            sequence: 10,
            ..signed("OP_CHECKSEQUENCEVERIFY after its delay", csv(), 2, vec![])
        },
        Cell {
            redeem: Some(lock.clone()),
            lock_time: 900_000,
            sequence: 0xffff_fffe,
            ..signed(
                "a P2SH's redeem step after its lock time",
                p2sh(&lock),
                2,
                vec![],
            )
        },
        cell("a product of 8 bytes from operands of 4", wide_result, 2),
        cell("OP_MUL executed", vec![0x52, 0x53, 0x95, 0x56, 0x87], 2),
        unlocking_of(10_000),
    ]
}

/// A spend whose unlocking script is exactly `size` bytes (10,000 or
/// 10,001): twenty pushes of 497 bytes (500 bytes each), and for 10,001 an
/// `OP_0` after them; the lock drops every element and leaves `OP_1`.
fn unlocking_of(size: usize) -> Cell {
    let mut below = Vec::new();
    for _ in 0..20 {
        below.extend(push(&[9u8; 497]));
    }
    let mut lock = vec![0x6d; 10];
    if size == 10_001 {
        below.push(0x00);
        lock.push(0x75);
    }
    lock.push(0x51);
    assert_eq!(below.len(), size);
    let name = if size == 10_001 {
        "an unlocking script of exactly 10,001 bytes"
    } else {
        "an unlocking script of exactly 10,000 bytes"
    };
    Cell {
        below,
        ..cell(name, lock, 2)
    }
}

/// The tip of every door given one: its next block is `NEXT_BLOCK`. A tip
/// names no Genesis height (the field deprecated on the 0.9.0 line is
/// removed, #843): the default doors judge by mainnet's.
fn tip() -> ChainTip {
    ChainTip::new(NEXT_BLOCK - 1, 1_700_000_000)
}

/// The first transaction up the chain of first inputs that carries a proof.
fn parent_of(tx: &Transaction) -> &Transaction {
    let mut parent = tx.inputs()[0].source_transaction.as_ref().unwrap();
    while parent.merkle_path.is_none() {
        parent = parent.inputs()[0].source_transaction.as_ref().unwrap();
    }
    parent
}

/// The tracker and headers of every door: the parent's root, and the tip
/// named (none: no tip). The way out for a caller on a test chain is its
/// chain parameters, at a door that takes them (the migration line of the
/// CHANGELOG, compiled in `chain_answer`).
fn tracker(tx: &Transaction, tip: Option<ChainTip>) -> MockChainTracker {
    let parent = parent_of(tx);
    let proof = parent.merkle_path.as_ref().unwrap();
    let mut tracker = MockChainTracker::new(NEXT_BLOCK - 1).with_mining_tip(tip);
    tracker.add_root(
        proof.block_height,
        proof.compute_root(Some(&parent.id())).unwrap(),
    );
    tracker
}

struct Chunk(Option<Vec<u8>>);
impl AsyncByteSource for Chunk {
    async fn next_chunk(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        Ok(self.0.take())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Answer {
    Valid,
    Refused,
    /// A coin outside the chain parameters' scope (a door given them alone).
    NotJudged,
    Other(String),
}

fn stream_answer(verdict: &Verdict, tx: &Transaction) -> Answer {
    match verdict {
        Verdict::Valid { .. } => Answer::Valid,
        Verdict::SpendRefused {
            txid,
            input: Some(0),
            why: SpendRefusal::Script(_),
            ..
        } if *txid == tx.hash() => Answer::Refused,
        other => Answer::Other(format!("{other:?}")),
    }
}

fn whole_answer(result: bsv_rs::Result<bool>) -> Answer {
    match result {
        Ok(true) => Answer::Valid,
        Err(bsv_rs::Error::TransactionError(text))
            if text.starts_with("Script validation failed for input 0: ") =>
        {
            Answer::Refused
        }
        other => Answer::Other(format!("{other:?}")),
    }
}

/// The seven default doors of this line that prove a coin's height.
#[derive(Clone, Copy, Debug)]
enum Door {
    Verify,
    Budget,
    Budgets,
    Stream,
    TwoPass,
    Stepping,
    Async,
}

const DOORS: [Door; 7] = [
    Door::Verify,
    Door::Budget,
    Door::Budgets,
    Door::Stream,
    Door::TwoPass,
    Door::Stepping,
    Door::Async,
];

/// `door`'s answer on `tx`, the chain named by `tip` (none: no tip).
async fn answer(door: Door, tx: &Transaction, tip: Option<ChainTip>) -> Answer {
    answer_on(door, tx, tip, tx.to_beef(false).unwrap()).await
}

/// `door`'s answer on `tx` read from `beef` (the stream doors read it).
async fn answer_on(door: Door, tx: &Transaction, tip: Option<ChainTip>, beef: Vec<u8>) -> Answer {
    let headers = tracker(tx, tip);
    match door {
        Door::Verify => whole_answer(tx.verify(&headers, None, None).await),
        Door::Budget => whole_answer(
            tx.verify_with_work_budget(&headers, None, None, Some(u64::MAX))
                .await,
        ),
        Door::Budgets => whole_answer(
            tx.verify_with_work_budgets(&headers, None, None, WorkBudget::new())
                .await,
        ),
        Door::Stream => stream_answer(&verify_stream(beef.as_slice(), &headers, None).unwrap(), tx),
        Door::TwoPass => stream_answer(
            &verify_stream_two_pass(Cursor::new(&beef), &headers, None).unwrap(),
            tx,
        ),
        Door::Stepping => stream_answer(
            &StreamVerifier::new(beef.as_slice(), &headers, None)
                .run()
                .unwrap(),
            tx,
        ),
        Door::Async => {
            let mut verifier = AsyncStreamVerifier::new(None);
            let verdict = verifier
                .run(&mut Chunk(Some(beef)), &headers)
                .await
                .unwrap();
            stream_answer(&verdict, tx)
        }
    }
}

/// Every refused cell through `door` at mainnet's tip: refused.
async fn the_rules_of_the_era_hold_at(door: Door) {
    let mut wrong = Vec::new();
    for cell in refused_by_the_rules_of_the_era() {
        let tx = spend(&cell);
        let got = answer(door, &tx, Some(tip())).await;
        if got != Answer::Refused {
            wrong.push(format!("{} through {door:?}: {got:?}", cell.name));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[tokio::test]
async fn a_coin_from_before_genesis_is_judged_by_its_eras_rules_at_verify_h4m7() {
    the_rules_of_the_era_hold_at(Door::Verify).await;
}

#[tokio::test]
async fn a_coin_from_before_genesis_is_judged_by_its_eras_rules_at_the_budgeted_verify_h4m7() {
    the_rules_of_the_era_hold_at(Door::Budget).await;
}

#[tokio::test]
async fn a_coin_from_before_genesis_is_judged_by_its_eras_rules_at_the_budgets_verify_h4m7() {
    the_rules_of_the_era_hold_at(Door::Budgets).await;
}

#[tokio::test]
async fn a_coin_from_before_genesis_is_judged_by_its_eras_rules_at_verify_stream_h4m7() {
    the_rules_of_the_era_hold_at(Door::Stream).await;
}

#[tokio::test]
async fn a_coin_from_before_genesis_is_judged_by_its_eras_rules_at_the_two_pass_reader_h4m7() {
    the_rules_of_the_era_hold_at(Door::TwoPass).await;
}

#[tokio::test]
async fn a_coin_from_before_genesis_is_judged_by_its_eras_rules_at_the_stepping_reader_h4m7() {
    the_rules_of_the_era_hold_at(Door::Stepping).await;
}

#[tokio::test]
async fn a_coin_from_before_genesis_is_judged_by_its_eras_rules_at_the_async_reader_h4m7() {
    the_rules_of_the_era_hold_at(Door::Async).await;
}

/// The same refused cells spending a coin from after Genesis keep the
/// default mode's answer (valid) at every door: the rules are the coin's era's.
#[tokio::test]
async fn a_coin_from_after_genesis_keeps_the_default_answer_at_every_door_h4m7() {
    let mut wrong = Vec::new();
    // A P2SH output is refused after Genesis (`validation.cpp:611-622`): no
    // such coin of that era exists, and the redeem step runs by shape.
    for cell in refused_by_the_rules_of_the_era()
        .into_iter()
        .filter(|cell| cell.redeem.is_none())
    {
        let tx = spend_at(&cell, MAINNET_GENESIS);
        for door in DOORS {
            let got = answer(door, &tx, Some(tip())).await;
            if got != Answer::Valid {
                wrong.push(format!("{} through {door:?}: {got:?}", cell.name));
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// Spends the node accepts for a coin from before Genesis stay valid at every
/// door, with mainnet's tip and with none (a lock time needs the tip).
#[tokio::test]
async fn an_honest_spend_of_a_coin_from_before_genesis_stays_valid_at_every_door_h4m7() {
    let mut wrong = Vec::new();
    for cell in accepted_by_the_rules_of_the_era() {
        let tx = spend(&cell);
        for door in DOORS {
            for named in [Some(tip()), None] {
                // Without a tip a lock time is not judged final: the streaming
                // doors decline it (`MiningCheck::Finality`), on every line.
                if named.is_none() && cell.lock_time != 0 {
                    continue;
                }
                let got = answer(door, &tx, named).await;
                if got != Answer::Valid {
                    wrong.push(format!(
                        "{} through {door:?} ({named:?}): {got:?}",
                        cell.name
                    ));
                }
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// A door given no tip judges a coin's era by mainnet's Genesis height.
#[tokio::test]
async fn without_a_tip_the_doors_take_mainnets_genesis_height_h4m7() {
    let cell = signed("a push above 520 bytes", p2pkh(), 2, push(&[7u8; 521]));
    let mut wrong = Vec::new();
    for (height, expected) in [
        (MAINNET_GENESIS - 1, Answer::Refused),
        (MAINNET_GENESIS, Answer::Valid),
    ] {
        let tx = spend_at(&cell, height);
        for door in DOORS {
            let got = answer(door, &tx, None).await;
            if got != expected {
                wrong.push(format!("coin at {height} through {door:?}: {got:?}"));
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// The six doors that take chain parameters: the three whole-transaction
/// forms and the three readers that are built (the one-shot `verify_stream`
/// takes none).
const CHAIN_DOORS: [Door; 6] = [
    Door::Verify,
    Door::Budget,
    Door::Budgets,
    Door::TwoPass,
    Door::Stepping,
    Door::Async,
];

/// A test chain's parameters: Genesis at `genesis`, Chronicle the block
/// after it.
fn chain(genesis: u32) -> ChainParams {
    ChainParams::regtest()
        .with_activation_heights(genesis, genesis + 1)
        .unwrap()
}

fn chain_stream_answer(verdict: &Verdict, tx: &Transaction) -> Answer {
    match verdict {
        Verdict::NotJudged { .. } => Answer::NotJudged,
        other => stream_answer(other, tx),
    }
}

/// `door`'s answer on `tx` read from `beef`, under `chain` and the tip.
async fn chain_answer(door: Door, tx: &Transaction, chain: &ChainParams, beef: Vec<u8>) -> Answer {
    let headers = tracker(tx, Some(tip()));
    let whole = |result: bsv_rs::Result<bool>| match result {
        Err(bsv_rs::Error::TransactionNotJudged { .. }) => Answer::NotJudged,
        other => whole_answer(other),
    };
    match door {
        Door::Verify => whole(
            tx.verify_with_chain_params(&headers, None, None, chain)
                .await,
        ),
        Door::Budget => whole(
            tx.verify_with_chain_params_and_work_budget(
                &headers,
                None,
                None,
                Some(u64::MAX),
                chain,
            )
            .await,
        ),
        Door::Budgets => whole(
            tx.verify_with_chain_params_and_work_budgets(
                &headers,
                None,
                None,
                WorkBudget::new(),
                chain,
            )
            .await,
        ),
        Door::TwoPass => chain_stream_answer(
            &verify_stream_two_pass_with_chain_params(Cursor::new(&beef), &headers, None, chain)
                .unwrap(),
            tx,
        ),
        Door::Stepping => chain_stream_answer(
            &StreamVerifier::new(beef.as_slice(), &headers, None)
                .with_chain_params(chain.clone())
                .run()
                .unwrap(),
            tx,
        ),
        Door::Async => {
            let mut verifier = AsyncStreamVerifier::new(None).with_chain_params(chain.clone());
            let verdict = verifier
                .run(&mut Chunk(Some(beef)), &headers)
                .await
                .unwrap();
            chain_stream_answer(&verdict, tx)
        }
        Door::Stream => unreachable!("the one-shot reader takes no chain parameters"),
    }
}

/// A test chain: a coin proven at a low height that uses a post-Genesis size.
/// The default doors judge by mainnet's heights, with a tip or with none (a
/// tip names no Genesis height since #843; until then a tip naming the
/// chain's own was the way out), so they judge the coin by the older rules
/// and refuse its spend. The way out is the chain's parameters, at a door
/// that takes them: with Genesis at 1 (a regtest run with
/// `-genesisactivationheight=1`) or at the coin's own height the spend is
/// judged under the chain's word and valid; with Genesis one block above the
/// coin the parameters decline it, a coin from before Genesis being outside
/// their scope.
#[tokio::test]
async fn a_test_chain_names_its_genesis_height_by_its_chain_parameters_h4m7() {
    let cell = signed(
        "a 521-byte field on a test chain",
        p2pkh(),
        2,
        push(&[7u8; 521]),
    );
    let tx = spend_at(&cell, 800);
    let mut wrong = Vec::new();
    for door in DOORS {
        for named in [None, Some(tip())] {
            let got = answer(door, &tx, named).await;
            if got != Answer::Refused {
                wrong.push(format!("{door:?} ({named:?}): {got:?}"));
            }
        }
    }
    for door in CHAIN_DOORS {
        for (genesis, expected) in [
            (1, Answer::Valid),
            (800, Answer::Valid),
            (801, Answer::NotJudged),
        ] {
            let got = chain_answer(door, &tx, &chain(genesis), tx.to_beef(false).unwrap()).await;
            if got != expected {
                wrong.push(format!("{door:?} (Genesis at {genesis}): {got:?}"));
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// The close reaches a coin whose creating transaction is proven: a coin
/// created by a transaction presented unproven (its own ancestor proven
/// below Genesis) carries no era, and every door judges its spend by the
/// post-Genesis rules, as before the fix. A verifier of outside BEEFs that
/// must hold such a coin to the older rules asks for the coin's own proof
/// (the advisory's workaround). The same spend of the same coin, proven, is
/// refused.
#[tokio::test]
async fn a_coin_whose_creating_transaction_is_unproven_is_judged_by_the_post_genesis_rules_h4m7() {
    let cell = signed("a push above 520 bytes", p2pkh(), 2, push(&[7u8; 521]));
    let ancestor = parent(&[0x51], COIN_HEIGHT);
    let mut coin = Transaction::new();
    let mut input = TransactionInput::with_source_transaction(ancestor, 0);
    input.set_unlocking_script(UnlockingScript::new());
    coin.add_input(input).unwrap();
    coin.add_output(TransactionOutput::new(
        COIN_VALUE,
        LockingScript::from_binary(&p2pkh()).unwrap(),
    ))
    .unwrap();
    let unproven = spend_of(&cell, coin);
    let proven = spend(&cell);
    let mut wrong = Vec::new();
    for door in DOORS {
        for (tx, expected) in [(&unproven, Answer::Valid), (&proven, Answer::Refused)] {
            let got = answer(door, tx, Some(tip())).await;
            if got != expected {
                wrong.push(format!("{door:?} (expected {expected:?}): {got:?}"));
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// `tx`'s BEEF (V2, this crate's writer) with the child's entry written ahead
/// of its parent's: the reader holds the child until the parent arrives.
fn held_order(tx: &Transaction) -> Vec<u8> {
    let beef = tx.to_beef(false).unwrap();
    let (parent, child) = (parent_of(tx).to_binary(), tx.to_binary());
    let at = |raw: &[u8]| beef.windows(raw.len()).position(|w| w == raw).unwrap();
    let (p, c) = (at(&parent), at(&child));
    assert_eq!(beef[..4], [0x02, 0x00, 0xbe, 0xef]);
    // The parent's entry is `01 <bump index 0> <raw>`, the child's `00 <raw>`.
    assert_eq!((beef[p - 2], beef[p - 1], beef[c - 1]), (1, 0, 0));
    assert_eq!(c, p + parent.len() + 1);
    let held = [&beef[..p - 2], &beef[c - 1..], &beef[p - 2..c - 1]].concat();
    assert_eq!(held.len(), beef.len());
    held
}

/// A child written ahead of the parent that proves its coin is judged when
/// the parent arrives, by its coin's era: refused at the four stream doors
/// with mainnet's tip and with none. The way out reaches the held path too:
/// under a test chain's parameters naming Genesis at 1, the 521-byte push
/// written the same way is judged under the chain's word and valid at the
/// three readers that take them (a tip naming Genesis at 1 until #843).
#[tokio::test]
async fn a_child_held_for_its_parent_is_judged_by_its_coins_era_h4m7() {
    let mut wrong = Vec::new();
    for cell in refused_by_the_rules_of_the_era()
        .into_iter()
        .filter(|cell| cell.redeem.is_none())
    {
        let tx = spend(&cell);
        for door in [Door::Stream, Door::TwoPass, Door::Stepping, Door::Async] {
            for (named, expected) in [(Some(tip()), Answer::Refused), (None, Answer::Refused)] {
                let got = answer_on(door, &tx, named, held_order(&tx)).await;
                if got != expected {
                    wrong.push(format!(
                        "{} through {door:?} ({named:?}): {got:?}",
                        cell.name
                    ));
                }
            }
        }
    }
    let cell = signed("a push above 520 bytes", p2pkh(), 2, push(&[7u8; 521]));
    let tx = spend(&cell);
    for door in [Door::TwoPass, Door::Stepping, Door::Async] {
        let got = chain_answer(door, &tx, &chain(1), held_order(&tx)).await;
        if got != Answer::Valid {
            wrong.push(format!(
                "the held child under Genesis at 1, {door:?}: {got:?}"
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// The doors given no height (the one-input door, `Spend` used directly)
/// still judge every coin by the post-Genesis rules: a caller who knows the
/// coin's height screens it first, and `ProtocolEra::at_height` (`None` below
/// the chain's Genesis height, `ChainParams::genesis_height`) is the screen:
/// such a coin is not judged by this interpreter. The whole-transaction door
/// with chain parameters declines it, as before.
#[tokio::test]
async fn a_caller_of_the_doors_given_no_height_screens_a_coin_from_before_genesis_h4m7() {
    let cell = signed("a push above 520 bytes", p2pkh(), 2, push(&[7u8; 521]));
    let tx = spend(&cell);
    let coin_height = parent_of(&tx).merkle_path.as_ref().unwrap().block_height;
    let main = ChainParams::mainnet();
    assert_eq!(
        ProtocolEra::at_height(coin_height, main.genesis_height, main.chronicle_height),
        None
    );
    assert_eq!(ProtocolEra::mainnet(coin_height), None);
    assert!(ProtocolEra::mainnet(MAINNET_GENESIS).is_some());
    // Given no height, the one-input door answers by the post-Genesis rules.
    let output = &parent_of(&tx).outputs()[0];
    let answered = verify_input(
        &output.locking_script.to_binary(),
        output.satoshis.unwrap(),
        &tx.to_binary(),
        0,
        &InputRules::reference_default(),
    );
    assert!(answered.is_ok(), "{answered:?}");
    // Chain parameters decline the coin at the whole-transaction door.
    let tracker = tracker(&tx, Some(tip()));
    let declined = tx
        .verify_with_chain_params(&tracker, None, None, &main)
        .await;
    assert!(
        matches!(declined, Err(bsv_rs::Error::TransactionNotJudged { .. })),
        "{declined:?}"
    );
}
