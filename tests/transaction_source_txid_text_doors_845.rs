//! #845, the doors that take a source txid as text and that the base has
//! too (`add_input_from`, `add_inputs_from_utxos`, `to_json`): this file
//! compiles on both trees, so its RED is a run of the base.
//!
//! Until #845 the two builders checked the text (hex of 32 bytes) and then
//! held it as given, so one txid in upper case was another string than its
//! lower-case twin (a BEEF's index keys on the text) and `to_json` wrote it
//! in the case given. They hold a `Txid` now: the same input whatever the
//! case, read back in lower case, as the reference's `addInput` lower-cases
//! (`ts-stack@edf6e03` `Transaction.ts:708-709`, `:99`). Every text they
//! refused is refused in the same words.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code

use bsv_rs::primitives::PrivateKey;
use bsv_rs::script::templates::P2PKH;
use bsv_rs::script::{LockingScript, SignOutputs};
use bsv_rs::transaction::{Transaction, Utxo};
use serde_json::Value;

fn lock() -> LockingScript {
    LockingScript::from_hex("51").unwrap()
}

fn from(text: &str) -> bsv_rs::Result<Transaction> {
    let mut tx = Transaction::new();
    let template = P2PKH::unlock(
        &PrivateKey::from_hex(&"01".repeat(32)).unwrap(),
        SignOutputs::All,
        false,
    );
    tx.add_input_from(text, 0, &lock(), 5, template)?;
    Ok(tx)
}

fn from_utxo(text: &str) -> bsv_rs::Result<Transaction> {
    let mut tx = Transaction::new();
    tx.add_inputs_from_utxos(&[Utxo {
        txid: text.to_string(),
        vout: 0,
        satoshis: 5,
        locking_script: lock(),
    }])?;
    Ok(tx)
}

#[test]
fn add_input_from_holds_an_upper_or_mixed_case_txid_in_lower_case_845() {
    let lower = "ab".repeat(32);
    for text in [lower.clone(), "AB".repeat(32), "aB".repeat(32)] {
        let tx = from(&text).unwrap();
        assert_eq!(tx.inputs()[0].get_source_txid().unwrap(), lower, "{text}");
        assert_eq!(tx.to_binary(), from(&lower).unwrap().to_binary(), "{text}");
    }
}

#[test]
fn add_inputs_from_utxos_holds_an_upper_or_mixed_case_txid_in_lower_case_845() {
    let lower = "cd".repeat(32);
    for text in [lower.clone(), "CD".repeat(32), "cD".repeat(32)] {
        let tx = from_utxo(&text).unwrap();
        assert_eq!(tx.inputs()[0].get_source_txid().unwrap(), lower, "{text}");
        assert_eq!(
            tx.to_binary(),
            from_utxo(&lower).unwrap().to_binary(),
            "{text}"
        );
    }
}

#[test]
fn to_json_writes_a_txid_given_in_upper_case_in_lower_case_845() {
    for tx in [
        from(&"EF".repeat(32)).unwrap(),
        from_utxo(&"EF".repeat(32)).unwrap(),
    ] {
        let json: Value = serde_json::from_str(&tx.to_json().unwrap()).unwrap();
        assert_eq!(json["inputs"][0]["txid"], "ef".repeat(32));
    }
}

/// The texts the two builders refuse, and their words, are the base's.
#[test]
fn the_builders_refuse_every_text_that_is_not_64_hex_digits_in_their_words_845() {
    let words = |text: &str| {
        (
            from(text).map(|_| ()).map_err(|e| e.to_string()),
            from_utxo(text).map(|_| ()).map_err(|e| e.to_string()),
        )
    };
    let length = |door: &str, n: usize| {
        Err(format!(
            "transaction error: Invalid {door}TXID length: expected 32 bytes (64 hex chars), got {n} bytes"
        ))
    };
    assert_eq!(words("abcd"), (length("", 2), length("UTXO ", 2)));
    assert_eq!(
        words(&"aa".repeat(33)),
        (length("", 33), length("UTXO ", 33))
    );
    assert_eq!(
        words(""),
        (
            Err("transaction error: Previous TXID must not be empty".to_string()),
            Err("transaction error: UTXO TXID must not be empty".to_string())
        )
    );
    for text in [
        "zz".repeat(32),
        "a".repeat(63),
        format!(" {} ", "a".repeat(62)),
    ] {
        let (a, b) = words(&text);
        assert!(a.is_err() && b.is_err(), "{text:?}");
    }
}
