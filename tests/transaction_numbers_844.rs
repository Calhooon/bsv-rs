//! The reader half of #845 (cherry-picked from beta `29d8c366`, which also
//! carries #844's amount refusals: those are beta's, not this line's, and
//! this line's copy of the file holds the #845 tests alone).
//! `Transaction::from_json`, for a document with no `hex` member, refuses an
//! input's `txid` member that is not exactly 64 hex digits, naming the input's
//! index and none of the text, and holds one in upper or mixed case in lower
//! case; until #845 it held the text as given, and the writer wrote a text it
//! could not read as 32 zero bytes, so `"zz"`, `"abcd"` and `""` were one
//! transaction. No TypeScript twin.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::transaction::Transaction;
use bsv_rs::Error;
use serde_json::Value;

const TX_170: &str = "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000";

/// A field-built document with one input per `txids`.
fn json_with_txids(txids: &[&str]) -> String {
    let inputs: Vec<String> = txids
        .iter()
        .map(|t| format!(r#"{{"unlockingScript":"","txid":"{t}","vout":0,"sequence":4294967295}}"#))
        .collect();
    format!(
        r#"{{"inputs":[{}],"outputs":[{{"satoshis":1,"lockingScript":"51"}}],"version":1,"lockTime":0}}"#,
        inputs.join(",")
    )
}

const GOOD: &str = "3c8edde27cb9a9132c22038dac4391496be9db16fd21351565cc1006966fdad5";

#[test]
fn a_json_input_txid_that_is_not_64_hex_digits_is_refused_845() {
    let sixty_three = &GOOD[..63];
    let sixty_five = format!("{GOOD}0");
    let non_hex = format!("{}g", &GOOD[..63]);
    let spaced = format!(" {}", &GOOD[..63]);
    for bad in [
        "zz",
        "abcd",
        "",
        sixty_three,
        &sixty_five,
        &non_hex,
        &spaced,
    ] {
        let err = Transaction::from_json(&json_with_txids(&[GOOD, bad])).unwrap_err();
        assert_eq!(
            err,
            Error::TransactionError("Invalid txid of input 1: expected 64 hex digits".into()),
            "{bad:?}"
        );
        if !bad.is_empty() {
            assert!(!err.to_string().contains(bad), "the text is not echoed");
        }
    }
    // The captain's three documents were one transaction; each is refused.
    for bad in ["zz", "abcd", ""] {
        assert!(Transaction::from_json(&json_with_txids(&[bad])).is_err());
    }
}

#[test]
fn a_json_input_txid_in_upper_case_is_held_in_lower_case_845() {
    let lower = Transaction::from_json(&json_with_txids(&[GOOD])).unwrap();
    let mixed: String = GOOD
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if i % 2 == 0 {
                c.to_ascii_uppercase()
            } else {
                c
            }
        })
        .collect();
    for text in [GOOD.to_uppercase(), mixed] {
        let tx = Transaction::from_json(&json_with_txids(&[&text])).unwrap();
        assert_eq!(tx.inputs[0].source_txid.as_deref(), Some(GOOD));
        assert_eq!(tx.id(), lower.id());
        assert_eq!(tx.to_binary(), lower.to_binary());
        let json: Value = serde_json::from_str(&tx.to_json().unwrap()).unwrap();
        assert_eq!(json["inputs"][0]["txid"], GOOD);
    }
}

#[test]
fn a_json_txid_member_beside_its_hex_is_unread_stated_845() {
    // The top-level `txid` member is not read: with `hex` the transaction is
    // the hex's whatever the member says (Go's `UnmarshalJSON` the same,
    // `txjson.go:49-66`). Reported, not changed here.
    let json = format!(r#"{{"txid":"{}","hex":"{TX_170}"}}"#, "00".repeat(32));
    let tx = Transaction::from_json(&json).unwrap();
    assert_eq!(
        tx.id(),
        "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"
    );
}
