//! #590: a sendWithResults entry's status byte is BRC-100's and the
//! reference's, 1 `unproven`, 2 `sending`, 3 `failed` (`wallet/0100.md:1726`
//! at `5119a9b`; `WalletWireProcessor.ts:151-156` and
//! `WalletWireTransceiver.ts:1226-1234` at `ts-stack@edf6e03`), replayed from
//! `vectors/wallet_wire/send_with_status_590.json` (the #338 recorder's
//! `--send-with-status-590` mode, Node v22.18.0).
#![cfg(feature = "wallet")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::wallet::wire::{WalletWire, WalletWireTransceiver, WireWriter};
use bsv_rs::wallet::{CreateActionArgs, SendWithResult, SignActionArgs};
use bsv_rs::Error;
use serde_json::Value;

struct Response(Vec<u8>);

#[async_trait::async_trait]
impl WalletWire for Response {
    async fn transmit_to_wallet(&self, _: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.0.clone())
    }
}

fn vector() -> Value {
    let vector: Value = serde_json::from_str(include_str!(
        "vectors/wallet_wire/send_with_status_590.json"
    ))
    .unwrap();
    assert_eq!(vector["reference"], "ts-stack@edf6e03 (unmodified)");
    assert_eq!(vector["node"], "v22.18.0");
    vector
}

fn rows(group: &str, count: usize) -> Vec<Value> {
    let rows = vector()[group].as_array().unwrap().clone();
    assert_eq!(rows.len(), count, "{group}");
    rows
}

/// The transceiver's reading of a recorded response for the row's call and
/// args: the result's JSON (`txid` and `sendWithResults`) or the refusal.
async fn read(row: &Value) -> Result<Value, Error> {
    let client = WalletWireTransceiver::new(Response(
        hex::decode(row["response_hex"].as_str().unwrap()).unwrap(),
    ));
    let args = vector()["reference_rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|reference| reference["call"] == row["call"])
        .unwrap()["args"]
        .clone();
    let mut value = match row["call"].as_str().unwrap() {
        "createAction" => {
            let args: CreateActionArgs = serde_json::from_value(args).unwrap();
            serde_json::to_value(client.create_action(args, None).await?).unwrap()
        }
        "signAction" => {
            let args: SignActionArgs = serde_json::from_value(args).unwrap();
            serde_json::to_value(client.sign_action(args, None).await?).unwrap()
        }
        other => panic!("unknown recorded call {other}"),
    };
    value
        .as_object_mut()
        .unwrap()
        .retain(|key, field| (key == "txid" || key == "sendWithResults") && !field.is_null());
    Ok(value)
}

#[tokio::test]
async fn a_reference_sending_and_failed_status_reads_as_its_name_590() {
    for row in rows("reference_rows", 2) {
        assert!(row["message"].is_null(), "{}", row["name"]);
        let actual = read(&row)
            .await
            .unwrap_or_else(|error| panic!("{}: {error}", row["name"]));
        assert_eq!(actual, row["value"], "{}", row["name"]);
    }
}

#[test]
fn this_crate_writes_the_reference_status_bytes_590() {
    for row in rows("reference_rows", 2) {
        let answered = &row["answered"];
        let entries: Vec<SendWithResult> =
            serde_json::from_value(answered["sendWithResults"].clone()).unwrap();
        let mut w = WireWriter::new();
        w.write_u8(0);
        if row["call"] == "createAction" {
            w.write_i8(0).write_i8(0).write_var_int(u64::MAX);
            w.write_send_with_result_array(Some(&entries));
            w.write_i8(0);
        } else {
            let txid = hex::decode(answered["txid"].as_str().unwrap()).unwrap();
            w.write_i8(1).write_bytes(&txid).write_i8(0);
            w.write_send_with_result_array(Some(&entries));
        }
        assert_eq!(
            hex::encode(w.as_bytes()),
            row["response_hex"].as_str().unwrap(),
            "{}",
            row["name"]
        );
    }
}

#[tokio::test]
async fn an_unknown_status_byte_is_refused_in_the_reference_words_590() {
    for row in rows("unknown_rows", 5) {
        assert!(row["value"].is_null(), "{}", row["name"]);
        assert_eq!(
            read(&row).await,
            Err(Error::WalletError(row["message"].as_str().unwrap().into())),
            "{}",
            row["name"]
        );
    }
}

/// The bytes this crate wrote before #590 (0/1/2) read here as the reference
/// reads them: 0 refused, 1 `unproven`, 2 `sending`.
#[tokio::test]
async fn the_old_status_bytes_read_here_as_the_reference_reads_them_590() {
    for row in rows("crate_base_rows", 8) {
        let actual = read(&row).await;
        if row["message"].is_null() {
            assert_eq!(actual.unwrap(), row["value"], "{}", row["name"]);
        } else {
            assert_eq!(
                actual,
                Err(Error::WalletError(row["message"].as_str().unwrap().into())),
                "{}",
                row["name"]
            );
        }
    }
}
