//! Regression (bsv-rs #843): `primitives::bsv::sighash::parse_transaction` must
//! consume the whole buffer or refuse. A transaction followed by a trailing
//! byte was silently read as the prefix and the extra bytes ignored; it is now
//! refused, as the sibling transaction readers already refuse trailing bytes.
//!
//! `..._refuses_a_trailing_byte_843` is RED on the pre-fix door (the extra byte
//! was accepted) and GREEN after; `..._reads_an_exact_transaction_843` guards
//! that an honest, exact transaction still parses (refused 0). The fixture is
//! built by this crate's own transaction writer, so it cannot drift from the
//! wire format.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used)]

use bsv_rs::primitives::bsv::sighash::parse_transaction;
use bsv_rs::script::LockingScript;
use bsv_rs::transaction::{Transaction, TransactionInput, TransactionOutput};

fn a_transaction_bytes() -> Vec<u8> {
    let mut tx = Transaction::new();
    tx.add_input(TransactionInput::new("11".repeat(32), 0))
        .unwrap();
    tx.add_output(TransactionOutput::new(
        1000,
        LockingScript::from_asm(
            "OP_DUP OP_HASH160 0000000000000000000000000000000000000000 OP_EQUALVERIFY OP_CHECKSIG",
        )
        .unwrap(),
    ))
    .unwrap();
    tx.to_binary()
}

#[test]
fn parse_transaction_reads_an_exact_transaction_843() {
    let bytes = a_transaction_bytes();
    let parsed = parse_transaction(&bytes).unwrap();
    assert_eq!(parsed.inputs.len(), 1);
    assert_eq!(parsed.outputs.len(), 1);
}

/// Drives both one trailing byte AND many (bsv-rs #843 fold): a refusal that
/// fired only for a single extra byte would slip the many case.
#[test]
fn parse_transaction_refuses_a_trailing_byte_843() {
    let base = a_transaction_bytes();
    for n in [1usize, 2, 17, 64] {
        let mut bytes = base.clone();
        bytes.resize(bytes.len() + n, 0xAB);
        assert!(
            parse_transaction(&bytes).is_err(),
            "a transaction followed by {n} trailing byte(s) must be refused"
        );
    }
}
