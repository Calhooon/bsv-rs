//! The count bound for doors that want one: `Beef::from_binary_with_limits`
//! (bsv-stack-lean #57, P0-5). Each limit admits a BEEF at its count and
//! refuses one over it with a `BeefError` naming the limit and the count,
//! checked on the count prefix before anything of that kind is read.
#![cfg(feature = "transaction")]

use bsv_rs::script::{LockingScript, UnlockingScript};
use bsv_rs::transaction::{
    Beef, BeefLimits, MerklePath, Transaction, TransactionInput, TransactionOutput,
};

/// A BEEF of `n` transactions: `tx[0]` proven, `tx[i]` spending `tx[i-1]:0`.
fn chain_beef(n: usize) -> (Beef, String) {
    let lock = LockingScript::from_binary(&[0x51]).expect("OP_TRUE");
    let mut funding = Transaction::new();
    let mut input = TransactionInput::new("aa".repeat(32), 0);
    input.unlocking_script = Some(UnlockingScript::new());
    funding.inputs.push(input);
    funding
        .outputs
        .push(TransactionOutput::new(1_000, lock.clone()));
    let mut prev = funding.id();
    let mut beef = Beef::new();
    let bump = beef.merge_bump(MerklePath::from_coinbase_txid(&prev, 800_000));
    beef.merge_raw_tx(funding.to_binary(), Some(bump));
    for _ in 1..n {
        let mut tx = Transaction::new();
        let mut input = TransactionInput::new(prev, 0);
        input.unlocking_script = Some(UnlockingScript::new());
        tx.inputs.push(input);
        tx.outputs.push(TransactionOutput::new(1_000, lock.clone()));
        prev = tx.id();
        beef.merge_raw_tx(tx.to_binary(), None);
    }
    (beef, prev)
}

fn chain_bytes(n: usize) -> (Vec<u8>, String) {
    let (mut beef, subject) = chain_beef(n);
    (beef.to_binary(), subject)
}

fn limits(max_txs: usize, max_bumps: usize, max_bytes: usize) -> BeefLimits {
    BeefLimits {
        max_txs,
        max_bumps,
        max_bytes,
    }
}

fn refusal(bytes: &[u8], limits: &BeefLimits) -> String {
    match Beef::from_binary_with_limits(bytes, limits) {
        Err(bsv_rs::Error::BeefError(message)) => message,
        Err(other) => panic!("expected a BeefError, got {other:?}"),
        Ok(beef) => panic!("expected a refusal, parsed {} txs", beef.txs.len()),
    }
}

#[test]
fn the_limits_admit_a_beef_at_every_count() {
    let (bytes, _) = chain_bytes(10);
    let beef = Beef::from_binary_with_limits(&bytes, &limits(10, 1, bytes.len()))
        .expect("10 txs, 1 bump and the exact byte count are within the limits");
    assert_eq!(beef.txs.len(), 10);
    assert_eq!(beef.bumps.len(), 1);
}

#[test]
fn the_limits_refuse_one_transaction_too_many() {
    let (bytes, _) = chain_bytes(10);
    let message = refusal(&bytes, &limits(9, 1, usize::MAX));
    assert!(message.contains("max_txs 9"), "{message}");
    assert!(message.contains("10"), "names the count: {message}");
}

#[test]
fn the_limits_refuse_one_bump_too_many() {
    let (bytes, _) = chain_bytes(10);
    let message = refusal(&bytes, &limits(usize::MAX, 0, usize::MAX));
    assert!(message.contains("max_bumps 0"), "{message}");
    assert!(message.contains("1"), "names the count: {message}");
}

#[test]
fn the_limits_refuse_one_byte_too_many() {
    let (bytes, _) = chain_bytes(10);
    let message = refusal(&bytes, &limits(usize::MAX, usize::MAX, bytes.len() - 1));
    assert!(
        message.contains(&format!("max_bytes {}", bytes.len() - 1)),
        "{message}"
    );
    assert!(
        message.contains(&bytes.len().to_string()),
        "names the count: {message}"
    );
}

/// A count prefix that claims more transactions than the limit is refused on
/// the prefix, before one transaction is read or one slot reserved.
#[test]
fn the_limits_refuse_a_claimed_count_before_reading_it() {
    let (bytes, _) = chain_bytes(2);
    let mut beef = Beef::from_binary(&bytes).expect("parses");
    beef.txs.clear();
    let mut writer = bsv_rs::primitives::Writer::new();
    beef.to_writer(&mut writer);
    let mut hostile = writer.into_bytes();
    // The last byte is the tx count (0); claim 0xFFFFFFFF transactions instead.
    hostile.pop();
    hostile.extend_from_slice(&[0xfe, 0xff, 0xff, 0xff, 0xff]);
    let message = refusal(&hostile, &limits(1_000, 10, usize::MAX));
    assert!(message.contains("max_txs 1000"), "{message}");
    assert!(
        message.contains("4294967295"),
        "names the claimed count: {message}"
    );
}

/// The limits are checked on an Atomic BEEF's inner counts too, and
/// `from_binary` stays unbounded.
#[test]
fn the_limits_apply_to_atomic_beef_and_from_binary_stays_unbounded() {
    let (mut beef, subject) = chain_beef(5);
    let atomic = beef.to_binary_atomic(&subject).expect("atomic");
    let message = refusal(&atomic, &limits(4, 1, usize::MAX));
    assert!(message.contains("max_txs 4"), "{message}");
    assert_eq!(Beef::from_binary(&atomic).expect("unbounded").txs.len(), 5);
}
