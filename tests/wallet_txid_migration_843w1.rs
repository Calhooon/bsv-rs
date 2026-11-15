//! #843, W1: the Migration lines of the CHANGELOG entry, run.
//!
//! Each test is one line of the entry's Migration block as code: the value a
//! dependent held before (a display-order `[u8; 32]`, the wallet's `TxId`,
//! or its hex text) goes in, and the same text and the same wire bytes come
//! out. As `primitives_bignumber_migration_843d23.rs` does for its entry.

#![cfg(feature = "wallet")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use bsv_rs::script::LockingScript;
use bsv_rs::transaction::{Transaction, TransactionOutput};
use bsv_rs::wallet::validation::ValidCreateActionOptions;
use bsv_rs::wallet::wire::WireWriter;
use bsv_rs::wallet::{
    ActionStatus, CreateActionOptions, CreateActionResult, Outpoint, ReviewActionResult,
    ReviewActionResultStatus, ReviewActionsRefusal, SendWithResult, SendWithResultStatus,
    SignActionOptions, SignActionResult, Txid, WalletAction,
};

const TEXT: &str = "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16";

/// What a dependent held as `wallet::TxId`: the text's bytes, display order.
fn old() -> [u8; 32] {
    hex::decode(TEXT).unwrap().try_into().unwrap()
}

fn outpoint_wire(outpoint: &Outpoint) -> Vec<u8> {
    let mut writer = WireWriter::new();
    writer.write_outpoint(outpoint);
    writer.as_bytes().to_vec()
}

/// `wallet::TxId` becomes `wallet::Txid`, the crate's one `Txid`.
#[test]
fn wallet_txid_is_the_crates_txid_843w1() {
    let wallet: Txid = Txid::from_hex(TEXT).unwrap();
    let transaction: bsv_rs::transaction::Txid = wallet;
    let root: bsv_rs::Txid = transaction;
    assert_eq!(root.to_string(), TEXT);
}

/// A display-order `[u8; 32]` becomes `Txid::from_display_bytes(bytes)`, and
/// back `txid.to_display_bytes()`.
#[test]
fn a_display_order_array_goes_through_the_named_byte_doors_843w1() {
    let txid = Txid::from_display_bytes(old());
    assert_eq!(txid.to_string(), TEXT);
    assert_eq!(txid.to_display_bytes(), old());
}

/// Hex text becomes `Txid::from_hex(&text)?` or `text.parse()?`; to text,
/// `txid.to_string()` where it was `hex::encode(txid)`.
#[test]
fn hex_text_goes_through_from_hex_and_to_string_843w1() {
    let text = TEXT.to_string();
    let txid = Txid::from_hex(&text).unwrap();
    let parsed: Txid = text.parse().unwrap();
    assert_eq!(txid, parsed);
    assert_eq!(txid, Txid::from_display_bytes(old()));
    assert_eq!(txid.to_string(), hex::encode(old()));
}

/// With a transaction in hand, `tx.txid()`.
#[test]
fn a_transactions_id_is_tx_txid_843w1() {
    let mut tx = Transaction::new();
    tx.add_output(TransactionOutput::new(
        1,
        LockingScript::from_binary(&[0x51]).unwrap(),
    ))
    .unwrap();
    // Before: `Outpoint::from_string(&format!("{}.0", tx.id()))?.txid`.
    let before = Outpoint::from_string(&format!("{}.0", tx.id()))
        .unwrap()
        .txid;
    assert_eq!(tx.txid(), before);
    assert_eq!(tx.txid().to_string(), tx.id());
}

/// `Outpoint::new(bytes, vout)` becomes
/// `Outpoint::new(Txid::from_display_bytes(bytes), vout)`, a literal the same.
#[test]
fn an_outpoint_takes_the_typed_id_843w1() {
    let built = Outpoint::new(Txid::from_display_bytes(old()), 5);
    let literal = Outpoint {
        txid: Txid::from_display_bytes(old()),
        vout: 5,
    };
    assert_eq!(built, literal);
    assert_eq!(built.to_string(), format!("{TEXT}.5"));
    let mut wire = old().to_vec();
    wire.push(5);
    assert_eq!(outpoint_wire(&built), wire);
    assert_eq!(built, Outpoint::from_string(&format!("{TEXT}.5")).unwrap());
}

/// `txid == [0u8; 32]` becomes `txid.is_null()`.
#[test]
fn the_null_txid_is_asked_by_is_null_843w1() {
    assert!(Txid::from_display_bytes([0u8; 32]).is_null());
    assert!(!Txid::from_display_bytes(old()).is_null());
    let sentinel = Outpoint::from_string(&format!("{}.0", "00".repeat(32))).unwrap();
    assert!(sentinel.txid.is_null());
}

/// The fields by name: each holds a `Txid` and writes the text it wrote.
#[test]
fn every_named_field_holds_a_txid_and_writes_the_same_text_843w1() {
    let id = Txid::from_display_bytes(old());
    let quoted = format!("\"{TEXT}\"");

    let send_with = SendWithResult {
        txid: id,
        status: SendWithResultStatus::Unproven,
    };
    assert!(serde_json::to_string(&send_with).unwrap().contains(&quoted));

    let review = ReviewActionResult {
        txid: id,
        status: ReviewActionResultStatus::DoubleSpend,
        competing_txs: Some(vec![id]),
        competing_beef: None,
    };
    assert_eq!(
        serde_json::to_string(&review)
            .unwrap()
            .matches(&quoted)
            .count(),
        2
    );

    let created = CreateActionResult {
        txid: Some(id),
        ..Default::default()
    };
    assert_eq!(
        serde_json::to_string(&created).unwrap(),
        format!("{{\"txid\":{quoted}}}")
    );

    let signed = SignActionResult {
        txid: Some(id),
        tx: None,
        send_with_results: None,
    };
    assert!(serde_json::to_string(&signed).unwrap().contains(&quoted));

    let action = WalletAction {
        txid: id,
        satoshis: 1,
        status: ActionStatus::Completed,
        is_outgoing: true,
        description: "an action".into(),
        labels: None,
        version: 1,
        lock_time: 0,
        inputs: None,
        outputs: None,
    };
    assert!(serde_json::to_string(&action).unwrap().contains(&quoted));
    let mut writer = WireWriter::new();
    writer.write_wallet_action(&action);
    assert_eq!(&writer.as_bytes()[..32], &old()[..]);

    let create_options = CreateActionOptions {
        known_txids: Some(vec![id]),
        send_with: Some(vec![id]),
        ..Default::default()
    };
    assert_eq!(
        serde_json::to_string(&create_options).unwrap(),
        format!("{{\"knownTxids\":[{quoted}],\"sendWith\":[{quoted}]}}")
    );

    let sign_options = SignActionOptions {
        send_with: Some(vec![id]),
        ..Default::default()
    };
    assert_eq!(
        serde_json::to_string(&sign_options).unwrap(),
        format!("{{\"sendWith\":[{quoted}]}}")
    );

    let refusal =
        ReviewActionsRefusal::with_members(vec![review], vec![send_with], Some(id), None, None);
    assert_eq!(refusal.txid, Some(id));

    let valid = ValidCreateActionOptions {
        known_txids: vec![id],
        send_with: vec![id],
        ..Default::default()
    };
    assert_eq!(valid.known_txids, valid.send_with);
}

/// `wallet::types::hex_txid` and `hex_txid_vec_option` take and return `Txid`.
#[test]
fn the_two_public_serde_helpers_take_and_return_a_txid_843w1() {
    #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
    struct Mine {
        #[serde(with = "bsv_rs::wallet::types::hex_txid")]
        one: Txid,
        #[serde(with = "bsv_rs::wallet::types::hex_txid_vec_option", default)]
        many: Option<Vec<Txid>>,
    }
    let id = Txid::from_display_bytes(old());
    let mine = Mine {
        one: id,
        many: Some(vec![id, id]),
    };
    let text = serde_json::to_string(&mine).unwrap();
    assert_eq!(
        text,
        format!("{{\"one\":\"{TEXT}\",\"many\":[\"{TEXT}\",\"{TEXT}\"]}}")
    );
    assert_eq!(serde_json::from_str::<Mine>(&text).unwrap(), mine);
    let upper = text.replace(TEXT, &TEXT.to_uppercase());
    assert_eq!(serde_json::from_str::<Mine>(&upper).unwrap(), mine);
    // The refusal is the helpers' sentence, as before the type.
    let short = format!("{{\"one\":\"{}\"}}", &TEXT[..62]);
    let error = serde_json::from_str::<Mine>(&short)
        .unwrap_err()
        .to_string();
    assert!(
        error.starts_with("expected 32 bytes for txid, got 31"),
        "{error}"
    );
}

/// `Debug` of a holder prints `Txid(<digits>)` where it printed 32 numbers.
#[test]
fn a_holders_debug_prints_the_digits_843w1() {
    let outpoint = Outpoint::new(Txid::from_display_bytes(old()), 0);
    assert_eq!(
        format!("{outpoint:?}"),
        format!("Outpoint {{ txid: Txid({TEXT}), vout: 0 }}")
    );
}
