//! What the wallet's wires, JSON forms and text doors answer for a
//! transaction id (#843, W1), computed through TEXT doors alone
//! (`Outpoint::from_string`, `serde_json` on the wallet types, the
//! validators, a certificate from its JSON), so this source compiles on the
//! tree before the wallet's `TxId` alias went (`471bdaf6`) and on every tree
//! after. `tests/vectors/wallet_txid_wires_843w1.json` is `compute()` as that
//! base answered it, recorded once and never edited; the tests replay it.

#![allow(dead_code)]

use bsv_rs::auth::Certificate as AuthCertificate;
use bsv_rs::primitives::{from_hex, sha256, to_hex};
use bsv_rs::wallet::validation::{
    parse_wallet_outpoint, validate_create_action_options, CreateActionOptionsRaw,
};
use bsv_rs::wallet::wire::{WalletWire, WalletWireTransceiver, WireReader, WireWriter};
use bsv_rs::wallet::*;
use bsv_rs::Error;
use serde_json::{json, Map, Value};
use std::sync::Mutex;

pub const VECTOR: &str = "tests/vectors/wallet_txid_wires_843w1.json";
pub const IDS: u32 = 64;

/// The id of a counter: the crate's SHA-256 of its four little-endian bytes,
/// as hex text. Never its own reverse (asserted), so an order moved is seen.
pub fn id(counter: u32) -> String {
    let text = to_hex(&sha256(&counter.to_le_bytes()));
    let mut reversed = from_hex(&text).unwrap();
    reversed.reverse();
    assert_ne!(to_hex(&reversed), text, "id {counter} is its own reverse");
    text
}

pub fn vout(counter: u32) -> u32 {
    counter * 37 + 1
}

/// A wire double: keeps the frame sent and answers the reply given.
pub struct Tape {
    reply: Vec<u8>,
    sent: Mutex<Vec<u8>>,
}

#[async_trait::async_trait]
impl WalletWire for Tape {
    async fn transmit_to_wallet(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        *self.sent.lock().unwrap() = message.to_vec();
        Ok(self.reply.clone())
    }
}

fn transceiver(reply: Vec<u8>) -> WalletWireTransceiver<Tape> {
    WalletWireTransceiver::new(Tape {
        reply,
        sent: Mutex::new(Vec::new()),
    })
}

fn sent(transceiver: &WalletWireTransceiver<Tape>) -> String {
    to_hex(&transceiver.wire().sent.lock().unwrap())
}

fn answer<T: serde::Serialize>(result: Result<T, Error>) -> Value {
    match result {
        Ok(value) => json!({ "ok": serde_json::to_value(value).unwrap() }),
        Err(error) => json!({ "err": error.to_string() }),
    }
}

fn read<T: serde::de::DeserializeOwned + serde::Serialize>(text: Value) -> Value {
    match serde_json::from_value::<T>(text) {
        Ok(value) => json!({ "ok": serde_json::to_string(&value).unwrap() }),
        Err(error) => json!({ "err": error.to_string() }),
    }
}

fn typed<T: serde::de::DeserializeOwned>(value: Value) -> T {
    serde_json::from_value(value).unwrap()
}

/// Asserts that `frame` carries `id`'s decoded text, unreversed.
fn carries(frame: &[u8], id: &str, what: &str) {
    let decoded = from_hex(id).unwrap();
    assert!(
        frame.windows(32).any(|window| window == decoded),
        "{what}: the frame does not carry hex::decode({id})"
    );
}

fn action_json(id: &str, other: &str, n: u32) -> Value {
    json!({
        "txid": id, "satoshis": 1000, "status": "completed", "isOutgoing": true,
        "description": "an action of the wallet", "version": 1, "lockTime": 0,
        "labels": ["label"],
        "inputs": [{
            "sourceOutpoint": format!("{other}.{n}"), "sourceSatoshis": 5,
            "inputDescription": "an input of it", "sequenceNumber": 7
        }],
        "outputs": []
    })
}

fn output_json(id: &str, n: u32) -> Value {
    json!({ "satoshis": 1, "spendable": true, "outpoint": format!("{id}.{n}") })
}

const KEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

fn auth_certificate_json(outpoint: Value) -> Value {
    json!({
        "type": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
        "serialNumber": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
        "subject": KEY, "certifier": KEY,
        "revocationOutpoint": outpoint,
        "fields": { "email": "ZW1haWw=" }
    })
}

fn wallet_certificate_json(outpoint: Value) -> Value {
    json!({
        "certificateType": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
        "serialNumber": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
        "subject": KEY, "certifier": KEY,
        "revocationOutpoint": outpoint,
        "fields": { "email": "ZW1haWw=" }
    })
}

/// Every wire door's bytes for one id.
async fn wires(counter: u32) -> Value {
    let (id, other, n) = (id(counter), id(counter + 1000), vout(counter));
    let outpoint = format!("{id}.{n}");
    let mut out = Map::new();

    let mut w = WireWriter::new();
    w.write_outpoint_string(&outpoint).unwrap();
    carries(w.as_bytes(), &id, "write_outpoint_string");
    out.insert("outpoint_string".into(), to_hex(w.as_bytes()).into());

    let mut w = WireWriter::new();
    w.write_outpoint(&Outpoint::from_string(&outpoint).unwrap());
    carries(w.as_bytes(), &id, "write_outpoint");
    let read_back = WireReader::new(w.as_bytes()).read_outpoint().unwrap();
    out.insert("outpoint".into(), to_hex(w.as_bytes()).into());
    out.insert("outpoint_read".into(), read_back.to_string().into());

    let mut w = WireWriter::new();
    w.write_txid_hex(&id).unwrap();
    assert_eq!(w.as_bytes(), from_hex(&id).unwrap(), "write_txid_hex");
    let text = WireReader::new(w.as_bytes()).read_txid_hex().unwrap();
    out.insert("txid_hex".into(), to_hex(w.as_bytes()).into());
    out.insert("txid_hex_read".into(), text.into());

    let result: SendWithResult = typed(json!({ "txid": id, "status": "sending" }));
    let mut w = WireWriter::new();
    w.write_send_with_result(&result);
    carries(w.as_bytes(), &id, "write_send_with_result");
    let read_back = WireReader::new(w.as_bytes())
        .read_send_with_result()
        .unwrap();
    out.insert("send_with_result".into(), to_hex(w.as_bytes()).into());
    out.insert(
        "send_with_result_read".into(),
        serde_json::to_string(&read_back).unwrap().into(),
    );

    let action: WalletAction = typed(action_json(&id, &other, n));
    let mut w = WireWriter::new();
    w.write_wallet_action(&action);
    carries(w.as_bytes(), &id, "write_wallet_action");
    carries(w.as_bytes(), &other, "write_wallet_action's input");
    let read_back = WireReader::new(w.as_bytes()).read_wallet_action().unwrap();
    out.insert("wallet_action".into(), to_hex(w.as_bytes()).into());
    out.insert(
        "wallet_action_read".into(),
        serde_json::to_string(&read_back).unwrap().into(),
    );

    let output: WalletOutput = typed(output_json(&id, n));
    let mut w = WireWriter::new();
    w.write_wallet_output(&output);
    carries(w.as_bytes(), &id, "write_wallet_output");
    out.insert("wallet_output".into(), to_hex(w.as_bytes()).into());

    // The createAction request frame and the typed reading of a hand-built
    // result frame: the txid, a change outpoint and a send-with result.
    let args: CreateActionArgs = typed(json!({
        "description": "an action to create",
        "outputs": [{ "lockingScript": "51", "satoshis": 1, "outputDescription": "an output" }],
        "options": {
            "knownTxids": [other], "sendWith": [id], "returnTXIDOnly": true, "noSend": true,
            "noSendChange": [format!("{other}.{n}")]
        }
    }));
    let decoded = from_hex(&id).unwrap();
    let mut reply = vec![0u8, 1];
    reply.extend_from_slice(&decoded); // the txid
    reply.push(0); // no tx
    reply.push(1); // one change outpoint
    reply.extend_from_slice(&decoded);
    reply.push(0);
    reply.push(1); // one send-with result
    reply.extend_from_slice(&decoded);
    reply.push(2);
    reply.push(0); // no signable transaction
    let t = transceiver(reply);
    let result = t.create_action(args, None).await;
    let frame = from_hex(&sent(&t)).unwrap();
    carries(&frame, &id, "createAction's sendWith");
    carries(&frame, &other, "createAction's knownTxids and noSendChange");
    out.insert("create_action_frame".into(), sent(&t).into());
    out.insert("create_action_result".into(), answer(result));

    // signAction: sendWith on the request, the txid and a result read back.
    let args: SignActionArgs = typed(json!({
        "spends": { "0": { "unlockingScript": "51" } },
        "reference": "AQID",
        "options": { "sendWith": [id, other], "returnTXIDOnly": true }
    }));
    let mut reply = vec![0u8, 1];
    reply.extend_from_slice(&decoded);
    reply.push(0);
    reply.push(1);
    reply.extend_from_slice(&decoded);
    reply.push(1);
    let t = transceiver(reply);
    let result = t.sign_action(args, None).await;
    let frame = from_hex(&sent(&t)).unwrap();
    carries(&frame, &id, "signAction's sendWith");
    carries(&frame, &other, "signAction's sendWith");
    out.insert("sign_action_frame".into(), sent(&t).into());
    out.insert("sign_action_result".into(), answer(result));

    let args: RelinquishOutputArgs = typed(json!({ "basket": "a basket", "output": outpoint }));
    let t = transceiver(vec![0]);
    let result = t.relinquish_output(args, None).await;
    carries(&from_hex(&sent(&t)).unwrap(), &id, "relinquishOutput");
    out.insert("relinquish_output_frame".into(), sent(&t).into());
    out.insert("relinquish_output_result".into(), answer(result));

    // A listed action and a listed output, each on a hand-built page.
    let mut page = WireWriter::new();
    page.write_u8(0).write_var_int(1);
    page.write_wallet_action(&action);
    let t = transceiver(page.into_bytes());
    let args: ListActionsArgs = typed(
        json!({ "labels": ["label"], "includeLabels": true, "includeInputs": true, "includeOutputs": true }),
    );
    out.insert(
        "list_actions_result".into(),
        answer(t.list_actions(args, None).await),
    );

    let mut page = WireWriter::new();
    page.write_u8(0).write_var_int(1).write_var_int(u64::MAX);
    page.write_wallet_output(&output);
    let t = transceiver(page.into_bytes());
    let args: ListOutputsArgs = typed(json!({ "basket": "a basket" }));
    out.insert(
        "list_outputs_result".into(),
        answer(t.list_outputs(args, None).await),
    );

    // The certificate binary.
    let certificate: AuthCertificate = typed(auth_certificate_json(outpoint.clone().into()));
    let binary = certificate.to_binary(false).unwrap();
    carries(&binary, &id, "Certificate::to_binary");
    let back = AuthCertificate::from_binary(&binary).unwrap();
    out.insert("certificate_binary".into(), to_hex(&binary).into());
    out.insert(
        "certificate_binary_read".into(),
        serde_json::to_string(&back).unwrap().into(),
    );
    Value::Object(out)
}

/// The JSON text of every type that holds an id, read from `text` (which may
/// be in upper case) and written back.
pub fn json_forms(text: &str, n: u32) -> Value {
    let outpoint = format!("{text}.{n}");
    json!({
        "Outpoint (string)": read::<Outpoint>(outpoint.clone().into()),
        "Outpoint (object)": read::<Outpoint>(json!({ "txid": text, "vout": n })),
        "CreateActionOptions.knownTxids": read::<CreateActionOptions>(json!({ "knownTxids": [text, text] })),
        "CreateActionOptions.sendWith": read::<CreateActionOptions>(json!({ "sendWith": [text] })),
        "CreateActionOptions.noSendChange": read::<CreateActionOptions>(json!({ "noSendChange": [outpoint] })),
        "SendWithResult.txid": read::<SendWithResult>(json!({ "txid": text, "status": "unproven" })),
        "ReviewActionResult.txid": read::<ReviewActionResult>(json!({ "txid": text, "status": "success" })),
        "ReviewActionResult.competingTxs": read::<ReviewActionResult>(json!({ "txid": text, "status": "doubleSpend", "competingTxs": [text] })),
        "CreateActionResult.txid": read::<CreateActionResult>(json!({ "txid": text })),
        "CreateActionResult.noSendChange": read::<CreateActionResult>(json!({ "noSendChange": [outpoint] })),
        "WalletAction.txid": read::<WalletAction>(action_json(text, text, n)),
        "SignActionOptions.sendWith": read::<SignActionOptions>(json!({ "sendWith": [text] })),
        "SignActionResult.txid": read::<SignActionResult>(json!({ "txid": text })),
        "CreateActionInput.outpoint": read::<CreateActionInput>(json!({ "outpoint": outpoint, "inputDescription": "an input" })),
        "wallet Certificate.revocationOutpoint": read::<bsv_rs::wallet::types::Certificate>(wallet_certificate_json(outpoint.clone().into())),
        "WalletActionInput.sourceOutpoint": read::<WalletActionInput>(json!({ "sourceOutpoint": outpoint, "sourceSatoshis": 5, "inputDescription": "an input", "sequenceNumber": 7 })),
        "WalletOutput.outpoint": read::<WalletOutput>(output_json(text, n)),
        "RelinquishOutputArgs.output": read::<RelinquishOutputArgs>(json!({ "basket": "a basket", "output": outpoint })),
        "auth Certificate.revocationOutpoint": read::<AuthCertificate>(auth_certificate_json(outpoint.clone().into())),
        "auth Certificate.revocationOutpoint (txid alone)": read::<AuthCertificate>(auth_certificate_json(text.into())),
        "auth Certificate.revocationOutpoint (object)": read::<AuthCertificate>(auth_certificate_json(json!({ "txid": text, "vout": n }))),
    })
}

/// The texts every reader and text door is asked: a txid in lower, upper
/// and mixed case, and the texts that are none.
pub fn cells() -> Vec<(&'static str, String)> {
    let good = id(7);
    let mixed: String = good
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
    vec![
        ("lower", good.clone()),
        ("upper", good.to_uppercase()),
        ("mixed", mixed),
        ("odd length (63)", good[..63].to_string()),
        ("62 digits", good[..62].to_string()),
        ("66 digits", format!("{good}ab")),
        ("not hex", format!("zz{}", &good[2..])),
        ("empty", String::new()),
        ("space-padded", format!(" {good} ")),
        ("leading space, 64 bytes", format!(" {}", &good[..63])),
        ("0x prefix, 64 bytes", format!("0x{}", &good[..62])),
        (
            "a two-byte character, 64 bytes",
            format!("é{}", &good[..62]),
        ),
        ("null txid", "00".repeat(32)),
    ]
}

/// What each JSON reader answers for one cell: the text written back, or
/// the refusal's sentence.
pub fn json_cells(text: &str) -> Value {
    let outpoint = format!("{text}.3");
    json!({
        "hex_txid (SendWithResult.txid)": read::<SendWithResult>(json!({ "txid": text, "status": "unproven" })),
        "hex_txid (WalletAction.txid)": read::<WalletAction>(action_json(text, &id(8), 3)),
        "hex_txid (ReviewActionResult.txid)": read::<ReviewActionResult>(json!({ "txid": text, "status": "success" })),
        "hex_txid_vec_option (knownTxids)": read::<CreateActionOptions>(json!({ "knownTxids": [id(8), text] })),
        "hex_txid_vec_option (sendWith)": read::<SignActionOptions>(json!({ "sendWith": [text] })),
        "hex_txid_vec_option (competingTxs)": read::<ReviewActionResult>(json!({ "txid": id(8), "status": "doubleSpend", "competingTxs": [text] })),
        "hex_txid_option (CreateActionResult.txid)": read::<CreateActionResult>(json!({ "txid": text })),
        "hex_txid_option (SignActionResult.txid)": read::<SignActionResult>(json!({ "txid": text })),
        "Outpoint (string)": read::<Outpoint>(outpoint.clone().into()),
        "Outpoint (object)": read::<Outpoint>(json!({ "txid": text, "vout": 3 })),
        "Outpoint in a holder (WalletOutput)": read::<WalletOutput>(output_json(text, 3)),
        "auth Certificate.revocationOutpoint": read::<AuthCertificate>(auth_certificate_json(outpoint.clone().into())),
        "auth Certificate.revocationOutpoint (txid alone)": read::<AuthCertificate>(auth_certificate_json(text.into())),
        "auth Certificate.revocationOutpoint (object)": read::<AuthCertificate>(auth_certificate_json(json!({ "txid": text, "vout": 3 }))),
        "wallet Certificate.revocationOutpoint": read::<bsv_rs::wallet::types::Certificate>(wallet_certificate_json(outpoint.into())),
    })
}

fn said<T>(result: Result<T, Error>, show: impl FnOnce(T) -> String) -> Value {
    match result {
        Ok(value) => json!({ "ok": show(value) }),
        Err(error) => json!({ "err": error.to_string() }),
    }
}

/// What each text door answers for one cell. A validated id is shown by a
/// wire writer's bytes, since `ValidCreateActionOptions` has no JSON form.
pub fn door_cells(text: &str) -> Value {
    let outpoint = format!("{text}.3");
    let options = |raw: CreateActionOptionsRaw| {
        said(validate_create_action_options(Some(&raw)), |valid| {
            let mut w = WireWriter::new();
            w.write_optional_string_array(Some(
                &valid
                    .no_send_change
                    .iter()
                    .map(|o| o.to_string())
                    .collect::<Vec<_>>(),
            ));
            let mut options: CreateActionOptions = typed(json!({}));
            options.known_txids = Some(valid.known_txids);
            options.send_with = Some(valid.send_with);
            format!(
                "{} {}",
                serde_json::to_string(&options).unwrap(),
                to_hex(w.as_bytes())
            )
        })
    };
    let wire = |write: &dyn Fn(&mut WireWriter) -> Result<(), Error>| {
        let mut w = WireWriter::new();
        said(write(&mut w), |()| to_hex(w.as_bytes()))
    };
    json!({
        "Outpoint::from_string": said(Outpoint::from_string(&outpoint), |o| o.to_string()),
        "parse_wallet_outpoint": said(parse_wallet_outpoint(&outpoint), |o| o.to_string()),
        "validate_create_action_options (knownTxids)": options(CreateActionOptionsRaw { known_txids: vec![text.to_string()], ..Default::default() }),
        "validate_create_action_options (sendWith)": options(CreateActionOptionsRaw { send_with: vec![text.to_string()], ..Default::default() }),
        "validate_create_action_options (noSendChange)": options(CreateActionOptionsRaw { no_send_change: vec![outpoint.clone()], ..Default::default() }),
        "WireWriter::write_txid_hex": wire(&|w| w.write_txid_hex(text).map(|_| ())),
        "WireWriter::write_outpoint_string": wire(&|w| w.write_outpoint_string(&outpoint).map(|_| ())),
    })
}

/// Everything, as one JSON value: the vector's whole content.
pub async fn compute() -> Value {
    let mut ids = Vec::new();
    for counter in 0..IDS {
        let text = id(counter);
        ids.push(json!({
            "id": text,
            "vout": vout(counter),
            "wires": wires(counter).await,
            "json": json_forms(&text, vout(counter)),
            "json_upper": json_forms(&text.to_uppercase(), vout(counter)),
        }));
    }
    let cells: Vec<Value> = cells()
        .into_iter()
        .map(|(name, text)| {
            json!({ "cell": name, "text": text, "json": json_cells(&text), "doors": door_cells(&text) })
        })
        .collect();
    json!({
        "source": "tests/support/wallet_txid_843w1.rs: compute() on bsv-rs at 471bdaf640334151b172e6b84708e55b44e1aeca, the tree before the wallet's TxId alias went",
        "ids": ids,
        "cells": cells,
    })
}

pub fn recorded() -> Value {
    serde_json::from_str(&std::fs::read_to_string(VECTOR).expect("the recorded vector")).unwrap()
}
