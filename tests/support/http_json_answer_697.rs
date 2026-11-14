//! A createAction answer whose `tx` is a 128 KiB atomic BEEF, in the array
//! form and the historical object form, built by the crate's own writers
//! (moved out of `memory_profiling.rs` by #697, both its HTTP wallet tests
//! reading it).
#![allow(clippy::unwrap_used)] // Fixed writer inputs in test fixtures (#134).

use bsv_rs::script::{LockingScript, UnlockingScript};
use bsv_rs::transaction::{MerklePath, Transaction, TransactionInput, TransactionOutput};

/// The pushed bytes of the answer's `tx`: 128 KiB (speed loop two, #670;
/// 1 MiB until then). The bound is a ratio to the text, so a smaller `tx`
/// asks the same: at 1 MiB the array form peaked at 2.25 times its text and
/// the object form at 19 times it, at 128 KiB at 2.86 and 20.6 times, under
/// the bound of 4 at both (through the mock server, #339's measurement).
pub const TX_PUSH: usize = 1 << 17;

/// The answer's `tx` and its two bodies.
pub struct Answer {
    /// The atomic BEEF the answer carries.
    pub tx: Vec<u8>,
    /// `{"txid", "tx": [b, ...]}`, the form the typed reading takes.
    pub array: Vec<u8>,
    /// `{"txid", "tx": {"0": b, ...}}`, the form only #365's fallback takes.
    pub object: Vec<u8>,
}

/// Row R28 (#432) refuses a `tx` that is not a complete, exactly framed BEEF
/// transaction, and the evidence row asks every input of a completed
/// transaction for its source: the answer is a real transaction of 128 KiB
/// framed as the reference's atomic BEEF with its own txid, spending one
/// output of a proven funding transaction (the one transaction of its block,
/// as `examples/transaction.rs` builds it) into one OP_FALSE OP_RETURN output
/// pushing `TX_PUSH` bytes of `i % 256`.
pub fn answer() -> Answer {
    let mut funding = Transaction::new();
    let mut mined = TransactionInput::new("11".repeat(32).parse().unwrap(), 0);
    mined.unlocking_script = Some(UnlockingScript::new());
    funding.add_input(mined).unwrap();
    funding
        .add_output(TransactionOutput::new(
            1_000,
            LockingScript::from_binary(&[0x51]).unwrap(),
        ))
        .unwrap();
    let funding_txid = funding.id();
    funding.merkle_path = Some(MerklePath::from_coinbase_txid(&funding_txid, 800_000));
    let mut spend = Transaction::new();
    let mut input = TransactionInput::with_source_transaction(funding, 0);
    input.unlocking_script = Some(UnlockingScript::new());
    spend.add_input(input).unwrap();
    let mut script = vec![0x00, 0x6a, 0x4e];
    script.extend_from_slice(&(TX_PUSH as u32).to_le_bytes());
    script.extend((0..TX_PUSH).map(|i| (i % 256) as u8));
    spend
        .add_output(TransactionOutput::new(
            0,
            LockingScript::from_binary(&script).unwrap(),
        ))
        .unwrap();
    let (txid, tx) = (spend.id(), spend.to_atomic_beef(true).unwrap());
    let body = |tx: serde_json::Value| {
        serde_json::to_vec(&serde_json::json!({ "txid": txid, "tx": tx })).unwrap()
    };
    let array = body(serde_json::json!(tx));
    let object = body(serde_json::Value::Object(
        tx.iter()
            .enumerate()
            .map(|(i, b)| (i.to_string(), serde_json::json!(b)))
            .collect(),
    ));
    Answer { tx, array, object }
}
