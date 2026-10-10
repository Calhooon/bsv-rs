//! The spend of a wide transaction is linear in its inputs (bsv-low #591,
//! LOW's R400-H1 and R403-H1 on the relay's payment door over bsv-rs 0.4.3).
//!
//! The shape of LOW's harness: a proven parent with `n` `OP_TRUE` outputs and
//! a subject spending all `n` with empty unlocks. At 0.4.3 the reader cloned
//! the other inputs and the outputs for every input
//! (`BeefIndex::check_spends_of`, `src/transaction/beef_stream.rs:2131-2148`),
//! and every `OP_CHECKSIG` rebuilt the input list and recomputed
//! hashPrevouts, hashSequence and hashOutputs over all of it
//! (`src/script/spend.rs:2250-2265`): the work grew with `n` squared. The
//! timing witness is release-only and `#[ignore]`d:
//!
//! ```text
//! cargo test --release --all-features --test beef_stream_linear_spend -- --ignored --nocapture
//! ```
//!
//! The signed witness spends 1,000 P2PKH outputs, each signature made over
//! the digest 0.4.3's free function computes
//! (`compute_sighash_dispatched_for_signing` over the whole input list), under
//! six scopes: a verdict of valid is the digest the reader computes equal to
//! 0.4.3's for every input.
//!
//! Every outpoint is synthetic; nothing here was ever on a chain.
#![cfg(feature = "transaction")]

use std::collections::HashMap;
use std::time::{Duration, Instant};

use bsv_rs::primitives::bsv::sighash::{
    compute_sighash_dispatched_for_signing, SighashParams, TxInput, TxOutput, SIGHASH_ALL,
    SIGHASH_ANYONECANPAY, SIGHASH_FORKID, SIGHASH_NONE, SIGHASH_SINGLE,
};
use bsv_rs::primitives::bsv::tx_signature::TransactionSignature;
use bsv_rs::primitives::ec::PrivateKey;
use bsv_rs::primitives::sha256d;
use bsv_rs::transaction::beef_stream::{Hash32, SpendRefusal};
use bsv_rs::transaction::{verify_stream, Verdict};

const HEIGHT: u64 = 800_000;
const OP_TRUE: u8 = 0x51;

fn varint(n: u64) -> Vec<u8> {
    if n < 0xFD {
        vec![n as u8]
    } else if n < 0x1_0000 {
        let mut v = vec![0xFD];
        v.extend_from_slice(&(n as u16).to_le_bytes());
        v
    } else if n < 0x1_0000_0000 {
        let mut v = vec![0xFE];
        v.extend_from_slice(&(n as u32).to_le_bytes());
        v
    } else {
        let mut v = vec![0xFF];
        v.extend_from_slice(&n.to_le_bytes());
        v
    }
}

/// A raw transaction: version 1, the inputs `(prev, vout, unlock, sequence)`,
/// the outputs `(satoshis, script)`, lock time 0.
fn raw_tx(inputs: &[(Hash32, u32, Vec<u8>, u32)], outputs: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut v = 1u32.to_le_bytes().to_vec();
    v.extend(varint(inputs.len() as u64));
    for (prev, vout, unlock, sequence) in inputs {
        v.extend_from_slice(prev);
        v.extend_from_slice(&vout.to_le_bytes());
        v.extend(varint(unlock.len() as u64));
        v.extend_from_slice(unlock);
        v.extend_from_slice(&sequence.to_le_bytes());
    }
    v.extend(varint(outputs.len() as u64));
    for (satoshis, script) in outputs {
        v.extend_from_slice(&satoshis.to_le_bytes());
        v.extend(varint(script.len() as u64));
        v.extend_from_slice(script);
    }
    v.extend_from_slice(&0u32.to_le_bytes());
    v
}

/// A BEEF V2 of a parent proven by a one-leaf BUMP (its txid is the root, the
/// coinbase shape) and an unproven subject; the headers carry the root.
fn beef(parent: &[u8], subject: &[u8]) -> (Vec<u8>, HashMap<u64, Hash32>) {
    let root = sha256d(parent);
    let mut v = 0xEFBE_0002u32.to_le_bytes().to_vec();
    v.push(1);
    v.extend(varint(HEIGHT));
    v.extend_from_slice(&[1, 1, 0, 2]);
    v.extend_from_slice(&root);
    v.push(2);
    v.extend_from_slice(&[1, 0]);
    v.extend_from_slice(parent);
    v.push(0);
    v.extend_from_slice(subject);
    (v, HashMap::from([(HEIGHT, root)]))
}

/// LOW's shape: a proven parent with `n` `OP_TRUE` outputs, a subject
/// spending all `n` with empty unlocks and paying one `OP_TRUE` output.
fn wide(n: usize) -> (Vec<u8>, HashMap<u64, Hash32>, Hash32) {
    let parent = raw_tx(
        &[([0xAA; 32], 0, vec![], 0xFFFF_FFFF)],
        &vec![(1_000, vec![OP_TRUE]); n],
    );
    let prev = sha256d(&parent);
    let inputs: Vec<_> = (0..n as u32)
        .map(|vout| (prev, vout, vec![], 0xFFFF_FFFF))
        .collect();
    let subject = raw_tx(&inputs, &[(1, vec![OP_TRUE])]);
    let txid = sha256d(&subject);
    let (bytes, headers) = beef(&parent, &subject);
    (bytes, headers, txid)
}

fn timed(n: usize) -> Duration {
    let (bytes, headers, txid) = wide(n);
    let started = Instant::now();
    let verdict = verify_stream(&bytes[..], &headers, Some(txid)).unwrap();
    let took = started.elapsed();
    assert!(verdict.is_valid(), "n = {n}: {verdict:?}");
    took
}

#[test]
fn a_wide_spend_of_op_true_outputs_is_valid() {
    let (bytes, headers, txid) = wide(4_000);
    let verdict = verify_stream(&bytes[..], &headers, Some(txid)).unwrap();
    assert!(
        matches!(&verdict, Verdict::Valid { subject: Some(s), roots } if *s == txid && roots.len() == 1),
        "{verdict:?}"
    );
}

/// Release only: `n` = 4,000, 16,000 and 64,000, timed. Quadruple the inputs,
/// at most eight times the time (linear is four, the 0.4.3 growth sixteen).
#[test]
#[ignore = "a timing, release only"]
fn a_wide_spend_is_linear_in_its_inputs() {
    let _warm = timed(1_000);
    let t4 = timed(4_000);
    let t16 = timed(16_000);
    let t64 = timed(64_000);
    println!(
        "linear-spend timings: n=4000 {:.3} s; n=16000 {:.3} s; n=64000 {:.3} s",
        t4.as_secs_f64(),
        t16.as_secs_f64(),
        t64.as_secs_f64()
    );
    let ratio = t64.as_secs_f64() / t16.as_secs_f64();
    println!("linear-spend ratio t(64000)/t(16000) = {ratio:.2}");
    assert!(
        ratio < 8.0,
        "quadruple the inputs, {ratio:.2} times the time"
    );
}

// ---------------------------------------------------------------------------
// The signed witness: 1,000 P2PKH spends, six scopes
// ---------------------------------------------------------------------------

const SIGNED: usize = 1_000;

const SCOPES: [u32; 6] = [
    SIGHASH_ALL | SIGHASH_FORKID,
    SIGHASH_NONE | SIGHASH_FORKID,
    SIGHASH_SINGLE | SIGHASH_FORKID,
    SIGHASH_ALL | SIGHASH_ANYONECANPAY | SIGHASH_FORKID,
    SIGHASH_NONE | SIGHASH_ANYONECANPAY | SIGHASH_FORKID,
    SIGHASH_SINGLE | SIGHASH_ANYONECANPAY | SIGHASH_FORKID,
];

fn key() -> PrivateKey {
    PrivateKey::from_bytes(&[0x11; 32]).unwrap()
}

fn p2pkh(key: &PrivateKey) -> Vec<u8> {
    let mut script = vec![0x76, 0xA9, 0x14];
    script.extend_from_slice(&key.public_key().hash160());
    script.extend_from_slice(&[0x88, 0xAC]);
    script
}

fn push(data: &[u8]) -> Vec<u8> {
    assert!(data.len() < 0x4C);
    let mut v = vec![data.len() as u8];
    v.extend_from_slice(data);
    v
}

/// The parent with `SIGNED` P2PKH outputs and the subject spending all of
/// them, each input signed over 0.4.3's digest under `SCOPES[i % 6]`. The
/// subject pays `SIGNED` outputs, so every SINGLE input has its output.
/// `tamper` flips a bit of the digest one input's signature is made over.
fn signed(tamper: Option<usize>) -> (Vec<u8>, HashMap<u64, Hash32>, Hash32) {
    let key = key();
    let lock = p2pkh(&key);
    let parent = raw_tx(
        &[([0xBB; 32], 0, vec![], 0xFFFF_FFFF)],
        &vec![(1_000, lock.clone()); SIGNED],
    );
    let prev = sha256d(&parent);
    let inputs: Vec<TxInput> = (0..SIGNED as u32)
        .map(|vout| TxInput {
            txid: prev,
            output_index: vout,
            script: vec![],
            sequence: 0xFFFF_FFFF - vout % 3,
        })
        .collect();
    let outputs: Vec<TxOutput> = (0..SIGNED)
        .map(|_| TxOutput {
            satoshis: 900,
            script: lock.clone(),
        })
        .collect();
    let unlocks: Vec<Vec<u8>> = (0..SIGNED)
        .map(|i| {
            let scope = SCOPES[i % SCOPES.len()];
            let mut digest = compute_sighash_dispatched_for_signing(&SighashParams {
                version: 1,
                inputs: &inputs,
                outputs: &outputs,
                locktime: 0,
                input_index: i,
                subscript: &lock,
                satoshis: 1_000,
                scope,
            });
            if tamper == Some(i) {
                digest[0] ^= 1;
            }
            let sig = TransactionSignature::new(key.sign(&digest).unwrap(), scope).to_low_s();
            let mut unlock = push(&sig.to_checksig_format());
            unlock.extend(push(&key.public_key().to_compressed()));
            unlock
        })
        .collect();
    let subject_inputs: Vec<_> = inputs
        .iter()
        .zip(unlocks)
        .map(|(i, unlock)| (i.txid, i.output_index, unlock, i.sequence))
        .collect();
    let subject_outputs: Vec<_> = outputs
        .iter()
        .map(|o| (o.satoshis, o.script.clone()))
        .collect();
    let subject = raw_tx(&subject_inputs, &subject_outputs);
    let txid = sha256d(&subject);
    let (bytes, headers) = beef(&parent, &subject);
    (bytes, headers, txid)
}

#[test]
fn a_thousand_signatures_over_the_old_digest_verify() {
    let (bytes, headers, txid) = signed(None);
    let verdict = verify_stream(&bytes[..], &headers, Some(txid)).unwrap();
    assert!(verdict.is_valid(), "{verdict:?}");
}

#[test]
fn a_signature_over_another_digest_is_refused_at_its_input() {
    let (bytes, headers, txid) = signed(Some(777));
    match verify_stream(&bytes[..], &headers, Some(txid)).unwrap() {
        Verdict::SpendRefused {
            txid: refused,
            input: Some(777),
            why: SpendRefusal::Script(_),
            ..
        } => assert_eq!(refused, txid),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_shared_spend_of_an_input_the_transaction_has_not_is_an_error() {
    use bsv_rs::primitives::bsv::sighash::TxSighashCache;
    use bsv_rs::script::{LockingScript, Spend, TxSpendParams, UnlockingScript};
    use std::sync::Arc;
    let input = TxInput {
        txid: [0xCC; 32],
        output_index: 0,
        script: vec![],
        sequence: 0xFFFF_FFFF,
    };
    let output = TxOutput {
        satoshis: 1,
        script: vec![OP_TRUE],
    };
    let shared = Arc::new(TxSighashCache::new(1, vec![input], vec![output], 0));
    let spend = |input_index| {
        Spend::with_transaction(TxSpendParams {
            transaction: shared.clone(),
            input_index,
            source_satoshis: 1,
            locking_script: LockingScript::from_binary(&[OP_TRUE]).unwrap(),
            unlocking_script: UnlockingScript::from_binary(&[]).unwrap(),
            memory_limit: None,
        })
    };
    assert!(spend(0).unwrap().validate().unwrap());
    assert!(spend(1).is_err());
}
