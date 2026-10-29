//! #440: real signatures and the node's two eras through the live verifier.
//! Synthetic transactions/BUMPs are made by this crate's writer. No network.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;
use std::io::Cursor;

use bsv_rs::block::ChainParams;
use bsv_rs::primitives::{PrivateKey, Writer};
use bsv_rs::script::{LockingScript, Script, SigningContext, UnlockingScript};
use bsv_rs::transaction::beef_stream::{ChainTip, Hash32, Headers, SpendRefusal};
use bsv_rs::transaction::{
    verify_stream_two_pass, verify_stream_two_pass_with_chain_params, AsyncStreamVerifier,
    MerklePath, MockChainTracker, Progress, StreamVerifier, Transaction, TransactionInput,
    TransactionOutput, Verdict, BEEF_V1,
};

const GENESIS: u32 = 620_538;
const CHRONICLE: u32 = 943_816;
const PRE_GENESIS: &str =
    "The source output was created before Genesis; its script era is unsupported.";
const FORKID: &str = "The signature must use SIGHASH_FORKID.";
const HASH_GATE: &str = "The signature must not use SIGHASH_CHRONICLE before Chronicle.";

struct HeaderFacts {
    roots: HashMap<u64, Hash32>,
    tip: Option<ChainTip>,
}

impl Headers for HeaderFacts {
    fn carries(&self, height: u64, root: &Hash32) -> bool {
        self.roots.get(&height) == Some(root)
    }
    fn mining_tip(&self) -> Option<ChainTip> {
        self.tip
    }
}

fn tip(height: u32) -> ChainTip {
    ChainTip {
        height,
        median_time_past: 0,
        genesis_height: GENESIS,
        csv_height: 419_328,
        next_block_time: None,
    }
}

fn key() -> PrivateKey {
    PrivateKey::from_hex(&format!("{:064x}", 42)).unwrap()
}

fn p2pk() -> LockingScript {
    let mut script = Script::new();
    script
        .write_bin(&key().public_key().to_compressed())
        .write_opcode(0xac);
    LockingScript::from_script(script)
}

fn parent(lock: LockingScript, proven: Option<u32>) -> Transaction {
    let mut source = Transaction::new();
    let mut input = if proven.is_some() {
        TransactionInput::new("aa".repeat(32), 0)
    } else {
        TransactionInput::with_source_transaction(
            parent(LockingScript::from_hex("51").unwrap(), Some(GENESIS)),
            0,
        )
    };
    input.set_unlocking_script(UnlockingScript::new());
    source.lock_time = proven.unwrap_or(0);
    source.add_input(input).unwrap();
    source
        .add_output(TransactionOutput::new(1_000, lock))
        .unwrap();
    source.merkle_path = proven.map(|height| MerklePath::from_coinbase_txid(&source.id(), height));
    source
}

fn transaction(lock: LockingScript, source_height: Option<u32>) -> Transaction {
    let mut tx = Transaction::new();
    let mut input = TransactionInput::with_source_transaction(parent(lock, source_height), 0);
    input.set_unlocking_script(UnlockingScript::new());
    tx.add_input(input).unwrap();
    tx.add_output(TransactionOutput::new(
        900,
        LockingScript::from_hex("51").unwrap(),
    ))
    .unwrap();
    tx
}

fn sign(tx: &mut Transaction, vin: usize, scope: u32) {
    let source = tx.inputs[vin].source_transaction.as_ref().unwrap();
    let lock = &source.outputs[0].locking_script;
    let raw = tx.to_binary();
    let digest = SigningContext::new(&raw, vin, 1_000, lock.as_script())
        .compute_sighash(scope)
        .unwrap();
    let mut signature = key().sign(&digest).unwrap().to_der();
    signature.push(scope as u8);
    let mut unlock = Script::new();
    unlock.write_bin(&signature);
    tx.inputs[vin].set_unlocking_script(UnlockingScript::from_script(unlock));
    tx.invalidate_caches();
}

fn signed(scope: u32, source_height: Option<u32>) -> Transaction {
    let mut tx = transaction(p2pk(), source_height);
    sign(&mut tx, 0, scope);
    tx
}

fn facts(tx: &Transaction, height: Option<u32>) -> HeaderFacts {
    let bytes = tx.to_beef(false).unwrap();
    let roots = bsv_rs::transaction::BeefStream::new(bytes.as_slice())
        .filter_map(|e| match e.unwrap() {
            bsv_rs::transaction::Element::Bump(b) => Some((b.block_height, b.root)),
            _ => None,
        })
        .collect();
    HeaderFacts {
        roots,
        tip: height.map(tip),
    }
}

fn verdict(tx: &Transaction, height: Option<u32>, node: bool) -> Verdict {
    let bytes = tx.to_beef(false).unwrap();
    let headers = facts(tx, height);
    if node {
        let two = verify_stream_two_pass_with_chain_params(
            Cursor::new(&bytes),
            &headers,
            Some(tx.hash()),
            &ChainParams::mainnet(),
        )
        .unwrap();
        let one = StreamVerifier::new(bytes.as_slice(), &headers, Some(tx.hash()))
            .with_chain_params(ChainParams::mainnet())
            .run()
            .unwrap();
        assert_eq!(one, two);
        two
    } else {
        verify_stream_two_pass(Cursor::new(&bytes), &headers, Some(tx.hash())).unwrap()
    }
}

fn refused(verdict: Verdict, tx: &Transaction, message: &str) {
    match verdict {
        Verdict::SpendRefused {
            txid,
            input: Some(0),
            why: SpendRefusal::Script(got),
            ..
        } => {
            assert_eq!(txid, tx.hash());
            assert_eq!(got, message);
        }
        other => panic!("expected {message}, got {other:?}"),
    }
}

#[test]
fn original_digest_01_passes_default_but_the_live_door_requires_forkid() {
    for source_height in [Some(CHRONICLE - 1), None] {
        let tx = signed(0x01, source_height);
        for tip_height in [Some(CHRONICLE), None] {
            assert!(verdict(&tx, tip_height, false).is_valid());
            refused(verdict(&tx, tip_height, true), &tx, FORKID);
        }
    }
}

#[test]
fn version_1_chronicle_signature_spends_a_proven_pre_chronicle_coin() {
    let tx = signed(0x61, Some(CHRONICLE - 1));
    refused(
        verdict(&tx, Some(CHRONICLE), false),
        &tx,
        "The signature format is invalid.",
    );
    // Chronicle's activation block is tip + 1, even for a proven parent.
    assert!(verdict(&tx, Some(CHRONICLE - 1), true).is_valid());
    // A chain context between Genesis and Chronicle rejects that hash type.
    refused(verdict(&tx, Some(CHRONICLE - 2), true), &tx, HASH_GATE);
}

#[test]
fn version_1_substr_passes_default_and_the_post_chronicle_word() {
    let mut tx = transaction(
        LockingScript::from_hex("b301bb87").unwrap(),
        Some(CHRONICLE),
    );
    tx.inputs[0].set_unlocking_script(UnlockingScript::from_hex("03aabbcc5151").unwrap());
    assert!(verdict(&tx, Some(CHRONICLE), false).is_valid());
    assert!(verdict(&tx, Some(CHRONICLE), true).is_valid());
}

#[test]
fn unproven_parent_takes_the_spend_era_including_without_a_tip() {
    let mut tx = transaction(LockingScript::from_hex("b301bb87").unwrap(), None);
    tx.inputs[0].set_unlocking_script(UnlockingScript::from_hex("03aabbcc5151").unwrap());
    assert!(verdict(&tx, Some(CHRONICLE - 1), true).is_valid());
    assert!(verdict(&tx, None, true).is_valid());
    let signed = signed(0x61, None);
    assert!(verdict(&signed, Some(CHRONICLE - 1), true).is_valid());
    assert!(verdict(&signed, None, true).is_valid());
    refused(
        verdict(&signed, Some(CHRONICLE - 2), true),
        &signed,
        HASH_GATE,
    );
}

#[test]
fn pre_genesis_coin_is_explicitly_refused_at_the_live_door() {
    let tx = signed(0x61, Some(GENESIS - 1));
    refused(verdict(&tx, Some(CHRONICLE), true), &tx, PRE_GENESIS);
    refused(verdict(&tx, None, true), &tx, PRE_GENESIS);
}

#[test]
fn no_tip_uses_latest_transaction_era_but_keeps_a_proven_coins_era() {
    let tx = signed(0x61, Some(CHRONICLE - 1));
    assert!(verdict(&tx, None, true).is_valid());
    // OP_NOP4 is discouraged on this old coin, even with no mining tip.
    let tx = transaction(
        LockingScript::from_hex("b351").unwrap(),
        Some(CHRONICLE - 1),
    );
    match verdict(&tx, None, true) {
        Verdict::SpendRefused {
            why: SpendRefusal::Script(s),
            ..
        } => assert!(s.contains("discouraged"), "{s}"),
        other => panic!("old coin must retain its opcode gate: {other:?}"),
    }
}

#[test]
fn each_input_uses_its_own_bump_height() {
    let mut tx = signed(0x61, Some(CHRONICLE - 1));
    let mut input = TransactionInput::with_source_transaction(parent(p2pk(), Some(CHRONICLE)), 0);
    input.set_unlocking_script(UnlockingScript::new());
    tx.add_input(input).unwrap();
    sign(&mut tx, 0, 0x61);
    sign(&mut tx, 1, 0x61);
    assert!(verdict(&tx, Some(CHRONICLE), true).is_valid());
}

fn reversed(tx: &Transaction, duplicate: bool) -> Vec<u8> {
    let source = tx.inputs[0].source_transaction.as_ref().unwrap();
    let proof = source.merkle_path.as_ref().unwrap();
    let mut w = Writer::new();
    w.write_u32_le(BEEF_V1);
    w.write_var_int(1);
    w.write_bytes(&proof.to_binary());
    w.write_var_int(if duplicate { 3 } else { 2 });
    for (tx, proven) in [(tx, false), (source.as_ref(), true)]
        .into_iter()
        .chain(duplicate.then_some((tx, false)))
    {
        w.write_bytes(&tx.to_binary());
        w.write_u8(u8::from(proven));
        if proven {
            w.write_var_int(0);
        }
    }
    w.into_bytes()
}

#[test]
fn deferred_duplicate_and_decoded_cursor_keep_the_word_and_output_retention() {
    let tx = signed(0x61, Some(CHRONICLE - 1));
    for duplicate in [false, true] {
        let bytes = reversed(&tx, duplicate);
        let headers = facts(&tx, Some(CHRONICLE));
        let referenced = bsv_rs::transaction::referenced_outpoints(bytes.as_slice()).unwrap();
        let mut reader =
            StreamVerifier::retaining(bytes.as_slice(), &headers, Some(tx.hash()), referenced)
                .with_chain_params(ChainParams::mainnet());
        assert_eq!(reader.step().unwrap(), Progress::Stepped); // BUMP
        assert_eq!(reader.step().unwrap(), Progress::Stepped); // held child
        assert_eq!(reader.index().deferred().0, 1);
        let cursor =
            bsv_rs::transaction::Cursor::from_binary(&reader.cursor().to_binary()).unwrap();
        let offset = cursor.offset() as usize;
        let resumed = StreamVerifier::resume(cursor, &bytes[offset..], &headers)
            .with_chain_params(ChainParams::mainnet());
        assert!(resumed.run().unwrap().is_valid());
    }
}

#[tokio::test]
async fn whole_transaction_and_async_reader_use_the_same_height_facts() {
    for (scope, accepted) in [(0x01, false), (0x61, true)] {
        let tx = signed(scope, Some(CHRONICLE - 1));
        let bytes = tx.to_beef(false).unwrap();
        let headers = facts(&tx, Some(CHRONICLE));
        let mut tracker = MockChainTracker::new(CHRONICLE).with_mining_tip(headers.tip);
        for (height, root) in headers.roots {
            tracker.add_root(
                height as u32,
                bsv_rs::transaction::beef_stream::display_hex(&root),
            );
        }
        assert_eq!(
            tx.verify_with_chain_params(&tracker, None, None, &ChainParams::mainnet())
                .await
                .is_ok(),
            accepted
        );
        let mut reader =
            AsyncStreamVerifier::new(Some(tx.hash())).with_chain_params(ChainParams::mainnet());
        assert_eq!(
            reader
                .run(&mut Chunk(Some(bytes)), &tracker)
                .await
                .unwrap()
                .is_valid(),
            accepted
        );
    }
}

struct Chunk(Option<Vec<u8>>);
impl bsv_rs::transaction::AsyncByteSource for Chunk {
    async fn next_chunk(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        Ok(self.0.take())
    }
}

#[test]
fn a_second_inputs_older_coin_keeps_its_opcode_gate() {
    let lock = LockingScript::from_hex("b301bb87").unwrap();
    let unlock = UnlockingScript::from_hex("03aabbcc5151").unwrap();
    let mut tx = transaction(lock.clone(), Some(CHRONICLE));
    tx.inputs[0].set_unlocking_script(unlock.clone());
    let mut input = TransactionInput::with_source_transaction(parent(lock, Some(CHRONICLE - 1)), 0);
    input.set_unlocking_script(unlock);
    tx.add_input(input).unwrap();
    assert!(verdict(&tx, Some(CHRONICLE), false).is_valid());
    match verdict(&tx, Some(CHRONICLE), true) {
        Verdict::SpendRefused {
            input: Some(1),
            why: SpendRefusal::Script(s),
            ..
        } => assert!(s.contains("discouraged"), "{s}"),
        other => panic!("second input must use its older coin's opcode gate: {other:?}"),
    }
}

#[test]
fn pause_inside_a_transaction_reapplies_chain_facts_after_decoding_the_cursor() {
    let mut tx = signed(0x61, Some(CHRONICLE - 1));
    let mut input = TransactionInput::with_source_transaction(parent(p2pk(), Some(CHRONICLE)), 0);
    input.set_unlocking_script(UnlockingScript::new());
    tx.add_input(input).unwrap();
    sign(&mut tx, 0, 0x61);
    sign(&mut tx, 1, 0x61);
    let bytes = tx.to_beef(false).unwrap();
    let headers = facts(&tx, None);
    let mut reader = StreamVerifier::new(bytes.as_slice(), &headers, None)
        .with_chain_params(ChainParams::mainnet());
    loop {
        match reader.step_until(&mut || true).unwrap() {
            bsv_rs::transaction::Timed::Paused => break,
            bsv_rs::transaction::Timed::Progress(Progress::Stepped) => {}
            other => panic!("expected an input pause: {other:?}"),
        }
    }
    let cursor = bsv_rs::transaction::Cursor::from_binary(&reader.cursor().to_binary()).unwrap();
    let at = cursor.offset() as usize;
    assert!(StreamVerifier::resume(cursor, &bytes[at..], &headers)
        .with_chain_params(ChainParams::mainnet())
        .run()
        .unwrap()
        .is_valid());
}

#[test]
fn a_word_keeps_resource_declines_distinct_and_only_referenced_scripts() {
    let tx = signed(0x61, Some(CHRONICLE - 1));
    let bytes = tx.to_beef(false).unwrap();
    let headers = facts(&tx, None);
    let referenced = bsv_rs::transaction::referenced_outpoints(bytes.as_slice()).unwrap();
    let mut reader = StreamVerifier::retaining(bytes.as_slice(), &headers, None, referenced)
        .with_chain_params(ChainParams::mainnet());
    reader.set_memory_limit(Some(0));
    assert!(matches!(
        reader.run().unwrap(),
        Verdict::SpendRefused {
            input: Some(0),
            why: SpendRefusal::Resource(_),
            ..
        }
    ));
}

#[test]
fn regtest_activation_defaults_and_tip_overflow_are_used_without_network_guessing() {
    let tx = signed(0x61, Some(14_999));
    let bytes = tx.to_beef(false).unwrap();
    let before = facts(&tx, Some(14_998));
    let word = verify_stream_two_pass_with_chain_params(
        Cursor::new(&bytes),
        &before,
        None,
        &ChainParams::regtest(),
    )
    .unwrap();
    refused(word, &tx, HASH_GATE);
    let at = facts(&tx, Some(14_999));
    assert!(verify_stream_two_pass_with_chain_params(
        Cursor::new(&bytes),
        &at,
        None,
        &ChainParams::regtest()
    )
    .unwrap()
    .is_valid());
    refused(
        verdict(&tx, Some(u32::MAX), true),
        &tx,
        "The mining tip has no next block height in u32.",
    );
}
