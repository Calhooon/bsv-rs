//! `BeefLimits` without a verdict (bsv-stack-lean, the no-limits program
//! NL-3; bsv-rs 0.4.0). Through 0.3 `Beef::from_binary_with_limits` refused a
//! BEEF over a byte length, a BUMP count or a transaction count (P0-5, #57).
//! A valid BEEF is never refused for its size or its counts: the limits are
//! memory hints now, a BEEF over every one of them is read, and a count the
//! bytes cannot honor is refused where the bytes run out, never for the
//! count.
#![allow(deprecated)]
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

fn hints(max_txs: usize, max_bumps: usize) -> BeefLimits {
    BeefLimits { max_txs, max_bumps }
}

#[test]
fn a_beef_at_its_hints_is_read() {
    let (bytes, _) = chain_bytes(10);
    let beef = Beef::from_binary_with_limits(&bytes, &hints(10, 1)).expect("reads");
    assert_eq!(beef.txs.len(), 10);
    assert_eq!(beef.bumps.len(), 1);
}

/// What 0.3.35 refused as `over max_txs 9` and `over max_bumps 0`.
#[test]
fn a_beef_over_every_hint_is_read_all_the_same() {
    let (bytes, _) = chain_bytes(10);
    for limits in [hints(9, 1), hints(usize::MAX, 0), hints(0, 0)] {
        let mut beef = Beef::from_binary_with_limits(&bytes, &limits)
            .expect("a valid BEEF is not refused for its counts");
        assert_eq!(beef.txs.len(), 10);
        assert_eq!(beef.bumps.len(), 1);
        assert_eq!(beef.to_binary(), bytes);
    }
}

/// A count prefix that claims 4,294,967,295 transactions over no bytes: the
/// count is read, nothing is reserved for it, and the refusal is for the
/// bytes that are not there. 0.3.35 answered `over max_txs 1000`.
#[test]
fn a_claimed_count_is_refused_for_the_bytes_and_reserves_nothing() {
    let (bytes, _) = chain_bytes(2);
    let mut beef = Beef::from_binary(&bytes).expect("parses");
    beef.txs.clear();
    let mut writer = bsv_rs::primitives::Writer::new();
    beef.to_writer(&mut writer);
    let mut claimed = writer.into_bytes();
    // The last byte is the tx count (0); claim 0xFFFFFFFF transactions instead.
    claimed.pop();
    claimed.extend_from_slice(&[0xfe, 0xff, 0xff, 0xff, 0xff]);
    for limits in [hints(1_000, 10), hints(usize::MAX, usize::MAX)] {
        let error = Beef::from_binary_with_limits(&claimed, &limits).expect_err("no bytes");
        assert!(
            matches!(error, bsv_rs::Error::ReaderUnderflow { .. }),
            "the refusal is the bytes running out: {error:?}"
        );
        let message = error.to_string();
        assert!(!message.contains("max_"), "no limit is named: {message}");
    }
    let plain = Beef::from_binary(&claimed).expect_err("no bytes");
    assert!(matches!(plain, bsv_rs::Error::ReaderUnderflow { .. }));
}

/// An Atomic BEEF over its hints is read too, and with or without hints the
/// parse is the same parse.
#[test]
fn the_hints_change_nothing_that_is_read() {
    let (mut beef, subject) = chain_beef(5);
    let atomic = beef.to_binary_atomic(&subject).expect("atomic");
    let hinted = Beef::from_binary_with_limits(&atomic, &hints(4, 0)).expect("reads");
    let plain = Beef::from_binary(&atomic).expect("reads");
    assert_eq!(hinted.txs.len(), 5);
    assert_eq!(hinted.atomic_txid, plain.atomic_txid);
    assert_eq!(
        hinted.txs.iter().map(|t| t.txid()).collect::<Vec<_>>(),
        plain.txs.iter().map(|t| t.txid()).collect::<Vec<_>>()
    );
}
