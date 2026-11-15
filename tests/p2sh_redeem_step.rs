//! The default mode's redeem step for a coin of the pay-to-script-hash shape
//! (GHSA-fr33-7jw7-mwwh).
//!
//! bitcoin-sv v1.2.2 `src/script/interpreter.cpp:2380-2420`: a coin created
//! before Genesis whose locking script is `OP_HASH160 <20 bytes> OP_EQUAL` is
//! spent only when the unlocking script is push-only and its last push, run as
//! a script on the stack the other pushes leave, succeeds. `Transaction::verify`
//! and the streaming reader now run that step; until this fix neither did, and
//! a spend the node refuses was answered valid. `Spend` itself is unchanged.
//!
//! The fixtures are this crate's writer's: a parent proven at height 600,000
//! (below mainnet's Genesis, 620,538) paying the coin, and an unproven child
//! spending it, read at a tip whose next block is 900,100. The cells' answers
//! are typed from the node's rule, never computed from the code under test.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Cursor;

use bsv_rs::primitives::{hash160, to_hex, PrivateKey};
use bsv_rs::script::{LockingScript, Script, SigningContext, UnlockingScript};
use bsv_rs::transaction::beef_stream::{ChainTip, Hash32, Headers, SpendRefusal};
use bsv_rs::transaction::{
    verify_stream, verify_stream_two_pass, AsyncByteSource, AsyncStreamVerifier, MerklePath,
    MockChainTracker, StreamVerifier, Transaction, TransactionInput, TransactionOutput, Verdict,
};

const COIN_HEIGHT: u32 = 600_000;
const NEXT_BLOCK: u32 = 900_100;
const COIN_VALUE: u64 = 10_000;
const FORKID_ALL: u32 = 0x41;

fn key() -> PrivateKey {
    PrivateKey::from_hex("7e57000000000000000000000000000000000000000000000000000000000001")
        .unwrap()
}

/// `<33-byte key> OP_CHECKSIG`.
fn checksig_redeem(key: &PrivateKey) -> Vec<u8> {
    let mut redeem = vec![0x21];
    redeem.extend(key.public_key().to_compressed());
    redeem.push(0xac);
    redeem
}

fn p2sh_of(redeem: &[u8]) -> String {
    format!("a914{}87", to_hex(&hash160(redeem)))
}

fn push(data: &[u8]) -> Vec<u8> {
    let mut script = Script::new();
    script.write_bin(data);
    script.to_binary()
}

/// The parent, proven at `COIN_HEIGHT`, its one output `lock`.
fn parent(lock: &str) -> Transaction {
    let mut tx = Transaction::new();
    let mut input = TransactionInput::new("ab".repeat(32), 0);
    input.set_unlocking_script(UnlockingScript::new());
    tx.add_input(input).unwrap();
    tx.add_output(TransactionOutput::new(
        COIN_VALUE,
        LockingScript::from_hex(lock).unwrap(),
    ))
    .unwrap();
    tx.merkle_path = Some(MerklePath::from_coinbase_txid(&tx.id(), COIN_HEIGHT));
    tx
}

/// The unproven child of `version` spending `parent:0` with `unlocking`.
fn child(parent: Transaction, version: u32, unlocking: &[u8]) -> Transaction {
    let mut tx = Transaction::new();
    tx.version = version;
    let mut input = TransactionInput::with_source_transaction(parent, 0);
    input.set_unlocking_script(UnlockingScript::from_binary(unlocking).unwrap());
    tx.add_input(input).unwrap();
    tx.add_output(TransactionOutput::new(
        9_000,
        LockingScript::from_hex("51").unwrap(),
    ))
    .unwrap();
    tx
}

/// The same child, built anew with `unlocking` (this line's transaction
/// keeps the bytes it serialized first; the signature never reads them).
fn relocked(tx: &Transaction, unlocking: &[u8]) -> Transaction {
    let parent = tx.inputs[0].source_transaction.as_ref().unwrap();
    child(parent.as_ref().clone(), tx.version, unlocking)
}

/// A FORKID-ALL signature by `key` over input 0 of `tx` with `script_code`.
fn signature(tx: &Transaction, key: &PrivateKey, script_code: &[u8]) -> Vec<u8> {
    let raw = tx.to_binary();
    let code = Script::from_binary(script_code).unwrap();
    let digest = SigningContext::new(&raw, 0, COIN_VALUE, &code)
        .compute_sighash(FORKID_ALL)
        .unwrap();
    let mut signature = key.sign(&digest).unwrap().to_der();
    signature.push(FORKID_ALL as u8);
    signature
}

/// The child spending a P2SH coin of `redeem`, signed over `redeem` by `key`
/// when `signer` is `Some`, the signature's pushes before the redeem push.
fn p2sh_spend(version: u32, redeem: &[u8], signer: Option<&PrivateKey>) -> Transaction {
    let coin = parent(&p2sh_of(redeem));
    let mut tx = child(coin, version, &push(redeem));
    if let Some(signer) = signer {
        let mut unlocking = push(&signature(&tx, signer, redeem));
        unlocking.extend(push(redeem));
        tx = relocked(&tx, &unlocking);
    }
    tx
}

/// The node refuses each: the attack cells.
fn refused_by_the_node() -> Vec<(&'static str, Transaction)> {
    // The redeem script alone: `<key> OP_CHECKSIG` on an empty stack.
    let alone = p2sh_spend(1, &checksig_redeem(&key()), None);
    // A signature by another key before the redeem script, version 2.
    let other = PrivateKey::from_hex(&"11".repeat(32)).unwrap();
    let mut wrong = p2sh_spend(2, &checksig_redeem(&key()), None);
    let redeem = checksig_redeem(&key());
    let mut unlocking = push(&signature(&wrong, &other, &redeem));
    unlocking.extend(push(&redeem));
    wrong = relocked(&wrong, &unlocking);
    // An unlocking script that is not push-only, version 2 (the default mode
    // waives push-only above version 1; the step does not): `OP_NOP <51>`.
    let mut nop = vec![0x61];
    nop.extend(push(&[0x51]));
    let not_push_only = child(parent(&p2sh_of(&[0x51])), 2, &nop);
    vec![
        ("the redeem script alone", alone),
        ("another key's signature", wrong),
        ("an unlocking script that is not push-only", not_push_only),
    ]
}

/// The node accepts each: the controls.
fn accepted_by_the_node() -> Vec<(&'static str, Transaction)> {
    let signed = p2sh_spend(2, &checksig_redeem(&key()), Some(&key()));
    // P2SH of `OP_1`, spent by pushing it: the step runs `51` on no stack.
    let anyone = child(parent(&p2sh_of(&[0x51])), 1, &push(&[0x51]));
    // A P2PKH coin of the same era: no step.
    let pkh = to_hex(&hash160(&key().public_key().to_compressed()));
    let lock = format!("76a914{pkh}88ac");
    let mut p2pkh = child(parent(&lock), 1, &[]);
    let code = LockingScript::from_hex(&lock).unwrap().to_binary();
    let mut unlocking = push(&signature(&p2pkh, &key(), &code));
    unlocking.extend(push(&key().public_key().to_compressed()));
    p2pkh = relocked(&p2pkh, &unlocking);
    vec![
        ("a signed P2SH spend, version 2", signed),
        ("a P2SH of OP_1 spent by its push", anyone),
        ("a P2PKH coin of the same era", p2pkh),
    ]
}

/// The parent's proof, read by the streaming doors, with a tip.
struct Facts {
    height: u64,
    root: Hash32,
}

impl Headers for Facts {
    fn carries(&self, height: u64, root: &Hash32) -> bool {
        height == self.height && *root == self.root
    }
    fn mining_tip(&self) -> Option<ChainTip> {
        Some(ChainTip {
            height: NEXT_BLOCK - 1,
            median_time_past: 1_700_000_000,
            genesis_height: 620_538,
            csv_height: 419_328,
            next_block_time: None,
        })
    }
}

fn parent_of(tx: &Transaction) -> &Transaction {
    tx.inputs[0].source_transaction.as_ref().unwrap()
}

fn root_hex(tx: &Transaction) -> String {
    let parent = parent_of(tx);
    let proof = parent.merkle_path.as_ref().unwrap();
    proof.compute_root(Some(&parent.id())).unwrap()
}

fn facts(tx: &Transaction) -> Facts {
    let mut root: Hash32 = bsv_rs::primitives::from_hex(&root_hex(tx))
        .unwrap()
        .try_into()
        .unwrap();
    root.reverse();
    Facts {
        height: u64::from(COIN_HEIGHT),
        root,
    }
}

fn tracker(tx: &Transaction) -> MockChainTracker {
    let mut tracker = MockChainTracker::new(NEXT_BLOCK - 1);
    tracker.add_root(COIN_HEIGHT, root_hex(tx));
    tracker
}

struct Chunk(Option<Vec<u8>>);
impl AsyncByteSource for Chunk {
    async fn next_chunk(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        Ok(self.0.take())
    }
}

/// What a door answered: valid, refused by the child's input 0's scripts, or
/// anything else (named).
#[derive(Clone, Debug, PartialEq, Eq)]
enum Answer {
    Valid,
    Refused,
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

/// Every default-mode door of this line, named, on `tx`.
async fn every_default_door(tx: &Transaction) -> Vec<(&'static str, Answer)> {
    let beef = tx.to_beef(false).unwrap();
    let headers = facts(tx);
    let mut verifier = AsyncStreamVerifier::new(None);
    let streamed = verifier
        .run(&mut Chunk(Some(beef.clone())), &tracker(tx))
        .await;
    vec![
        ("verify", whole_answer(tx.verify(&tracker(tx), None).await)),
        (
            "verify_stream",
            stream_answer(&verify_stream(beef.as_slice(), &headers, None).unwrap(), tx),
        ),
        (
            "verify_stream_two_pass",
            stream_answer(
                &verify_stream_two_pass(Cursor::new(&beef), &headers, None).unwrap(),
                tx,
            ),
        ),
        (
            "StreamVerifier",
            stream_answer(
                &StreamVerifier::new(beef.as_slice(), &headers, None)
                    .run()
                    .unwrap(),
                tx,
            ),
        ),
        ("AsyncStreamVerifier", stream_answer(&streamed.unwrap(), tx)),
    ]
}

#[tokio::test]
async fn a_pre_genesis_p2sh_spend_the_node_refuses_is_refused_at_every_default_door_fr33() {
    let mut wrong = Vec::new();
    for (cell, tx) in refused_by_the_node() {
        for (door, answer) in every_default_door(&tx).await {
            if answer != Answer::Refused {
                wrong.push(format!("{cell} through {door}: {answer:?}"));
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[tokio::test]
async fn a_pre_genesis_p2sh_spend_the_node_accepts_stays_valid_at_every_default_door_fr33() {
    let mut wrong = Vec::new();
    for (cell, tx) in accepted_by_the_node() {
        for (door, answer) in every_default_door(&tx).await {
            if answer != Answer::Valid {
                wrong.push(format!("{cell} through {door}: {answer:?}"));
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// The step runs the redeem script as a coin from before Chronicle (a coin
/// from before Genesis is one), whatever the child's version: `OP_VER` is
/// disabled there, so a version-2 spend of a P2SH coin whose redeem script
/// is `OP_VER` alone is refused at every door, as the node refuses it.
#[tokio::test]
async fn a_redeem_script_runs_without_the_chronicle_opcodes_at_every_default_door_fr33() {
    let tx = child(parent(&p2sh_of(&[0x62])), 2, &push(&[0x62]));
    let mut wrong = Vec::new();
    for (door, answer) in every_default_door(&tx).await {
        if answer != Answer::Refused {
            wrong.push(format!("OP_VER through {door}: {answer:?}"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// The least work bound per input under which the stream judges `tx` valid.
fn least_bound(tx: &Transaction) -> u64 {
    let beef = tx.to_beef(false).unwrap();
    let headers = facts(tx);
    let run = |limit: u64| {
        let mut verifier = StreamVerifier::new(beef.as_slice(), &headers, None);
        verifier.set_work_limit(Some(limit));
        verifier.run().unwrap()
    };
    let (mut low, mut high) = (1u64, 1_000_000u64);
    assert_eq!(stream_answer(&run(high), tx), Answer::Valid);
    while low < high {
        let mid = low + (high - low) / 2;
        if stream_answer(&run(mid), tx) == Answer::Valid {
            high = mid;
        } else {
            low = mid + 1;
        }
    }
    let short = run(low - 1);
    assert!(
        matches!(
            short,
            Verdict::SpendRefused {
                why: SpendRefusal::Resource(_),
                ..
            }
        ),
        "one unit short of the least bound: {short:?}"
    );
    low
}

/// The step is charged to the stream's work bound per input: the least bound
/// that judges the signed spend valid covers the first evaluation and the
/// step's signature check together, and one unit less is a decline, never a
/// verdict. The step runs on what the first evaluation left of the bound: the
/// least bound is more than a coin locked by the redeem script itself needs.
#[test]
fn the_redeem_step_is_charged_to_the_inputs_work_budget_fr33() {
    let redeem = checksig_redeem(&key());
    let low = least_bound(&p2sh_spend(2, &redeem, Some(&key())));
    // The step's checksig alone hashes a preimage: the first evaluation
    // (a push, OP_HASH160 of 35 bytes, a push, OP_EQUAL) spends far less.
    assert!(low > 200, "the step's signature check is counted: {low}");
    // The same signature check as the whole of a spend: a coin locked by
    // the redeem script, signed by its key over it.
    let bare = child(parent(&to_hex(&redeem)), 2, &[]);
    let bare = relocked(&bare, &push(&signature(&bare, &key(), &redeem)));
    let alone = least_bound(&bare);
    assert!(
        low > alone,
        "the first evaluation and the step share one bound: {low} against {alone}"
    );
}
