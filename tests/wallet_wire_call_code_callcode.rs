//! #914: the wallet wire refuses an unknown call code in the reference's
//! words, `Invalid call code: N`, code 1 (`ts-stack@edf6e03`
//! `WalletWireProcessor.ts:276-283`, `HTTPWalletWire.ts:33-40`; the same
//! sentence at `5226d0c7`, `WalletWireProcessor.ts:287-294`, whose client
//! falls back to the plain call on exactly this text,
//! `WalletWireTransceiver.ts:142-147`). Against
//! `vectors/wallet_wire/call_code_callcode.json`, recorded by
//! `support/wire_call_code_callcode.mjs` under Node v22.18.0 from both
//! commits' bundles; the base's frames beside it
//! (`support/wire_call_code_callcode_base_frames.json`) were written by this
//! file's ignored test on the scratch base.
#![cfg(all(feature = "wallet", feature = "http"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[allow(dead_code)]
#[path = "support/fixtures/mod.rs"]
mod fixtures;

use bsv_rs::wallet::substrates::HttpWalletWire;
use bsv_rs::wallet::wire::{WalletCall, WalletWire, WalletWireProcessor, WireWriter};
use bsv_rs::Error;
use fixtures::wallet::Stub;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

const CODES: [u8; 5] = [0, 29, 30, 99, 255];

fn vector() -> Value {
    serde_json::from_str(include_str!("vectors/wallet_wire/call_code_callcode.json")).unwrap()
}

/// The five request shapes of the recording, built here.
fn shapes(code: u8) -> Vec<Vec<u8>> {
    let build = |tail: &[u8]| {
        let mut w = WireWriter::new();
        w.write_u8(code).write_bytes(tail);
        w.into_bytes()
    };
    vec![
        build(&[]),
        build(&[0]),
        build(&[0, 0, 1]),
        build(&[251]),
        build(&[3, b'a', b'.', b'b', 1]),
    ]
}

/// The probe the head's client sends with no originator: call 29, originator
/// length 0, then `[0, CERTIFICATE_COMPATIBILITY_VERSION]`.
fn probe() -> Vec<u8> {
    let mut w = WireWriter::new();
    w.write_u8(29).write_u8(0).write_u8(0).write_u8(1);
    w.into_bytes()
}

fn wallet() -> Stub {
    Stub::new(json!({"totalCertificates": 0, "certificates": []}))
}

async fn answer(request: &[u8]) -> (Vec<u8>, bool) {
    let wallet = wallet();
    let response = WalletWireProcessor::new(wallet.clone())
        .process_message(request)
        .await
        .unwrap();
    let called = wallet.observed.lock().unwrap().is_some();
    (response, called)
}

fn sentence_frame(code: u8) -> String {
    let words = format!("Invalid call code: {code}");
    let mut w = WireWriter::new();
    w.write_u8(1)
        .write_var_int(words.len() as u64)
        .write_bytes(words.as_bytes())
        .write_var_int(0);
    hex::encode(w.into_bytes())
}

#[tokio::test]
async fn every_recorded_processor_frame_but_the_heads_29_is_this_crates_callcode() {
    let vector = vector();
    let cells = vector["processor"].as_array().unwrap();
    assert_eq!(cells.len(), 2 * CODES.len() * 5, "processor cell census");
    let mut compared = 0;
    for code in CODES {
        for request in shapes(code) {
            let request_hex = hex::encode(&request);
            for side in ["pin", "head"] {
                let cell = cells
                    .iter()
                    .find(|c| c["side"] == side && c["request_hex"] == request_hex.as_str())
                    .unwrap_or_else(|| panic!("{side} {request_hex}: recorded"));
                if side == "head" && code == 29 {
                    continue; // the head serves 29: the certificate profile, not this lane's
                }
                assert_eq!(
                    cell["called"],
                    json!([]),
                    "{side} {request_hex}: wallet called"
                );
                let (response, called) = answer(&request).await;
                assert_eq!(
                    hex::encode(&response),
                    cell["response_hex"],
                    "{side} {request_hex}"
                );
                assert!(!called, "{request_hex}: the wallet was called");
                compared += 1;
            }
        }
    }
    assert_eq!(compared, 45);
}

#[tokio::test]
async fn every_byte_outside_1_to_28_is_refused_in_the_reference_words_callcode() {
    let mut refused = 0;
    for code in 0..=255u8 {
        if (1..=28).contains(&code) {
            assert_eq!(WalletCall::try_from(code).unwrap().as_u8(), code);
            continue;
        }
        assert_eq!(
            WalletCall::try_from(code),
            Err(Error::WalletError(format!("Invalid call code: {code}"))),
        );
        let (response, called) = answer(&[code, 0, 0, 1]).await;
        assert_eq!(hex::encode(response), sentence_frame(code), "code {code}");
        assert!(!called);
        refused += 1;
    }
    assert_eq!(refused, 228);
}

fn client_row<'a>(vector: &'a Value, call: &str, wire: &str) -> &'a Value {
    vector["client"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["call"] == call && r["wire"] == wire)
        .unwrap_or_else(|| panic!("{call} {wire}: recorded"))
}

#[tokio::test]
async fn the_heads_client_falls_back_on_this_crates_answer_to_its_probe_callcode() {
    let vector = vector();
    let probe_hex = hex::encode(probe());
    let (ours, called) = answer(&probe()).await;
    assert!(!called);
    let ours = hex::encode(ours);
    for call in ["discoverByIdentityKey", "listCertificates"] {
        let rows: Vec<&Value> = vector["client"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["call"] == call)
            .collect();
        for row in &rows {
            assert_eq!(row["requests"][0], probe_hex.as_str(), "{call}: the probe");
        }
        let found = rows
            .iter()
            .find(|r| r["probe_response_hex"] == ours.as_str())
            .unwrap_or_else(|| panic!("{call}: no recorded row answered the probe {ours}"));
        assert_eq!(
            found["fell_back"], true,
            "{call}: the head's client on this crate's answer {ours} (row {}): {}",
            found["wire"], found["thrown"]
        );
        let plain = WalletCall::try_from(if call == "listCertificates" { 18 } else { 21 }).unwrap();
        let next = hex::decode(found["requests"][1].as_str().unwrap()).unwrap();
        assert_eq!(
            next[0],
            plain.as_u8(),
            "{call}: the next request is the plain call"
        );
    }
    // The base's frame is the row the head's client refused.
    let base = client_row(&vector, "discoverByIdentityKey", "base_frame");
    assert_eq!(base["fell_back"], false);
    assert_ne!(base["probe_response_hex"], ours.as_str());
}

#[tokio::test]
async fn the_plain_call_after_the_fallback_is_this_crates_stub_not_the_sentence_callcode() {
    let vector = vector();
    for call in ["discoverByIdentityKey", "listCertificates"] {
        let row = client_row(&vector, call, "pin_processor");
        assert_eq!(row["fell_back"], true);
        let next = hex::decode(row["requests"][1].as_str().unwrap()).unwrap();
        let (response, _) = answer(&next).await;
        assert_eq!(response[0], 1, "{call}: code 1");
        let length = response[1] as usize;
        let words = std::str::from_utf8(&response[2..2 + length]).unwrap();
        assert!(!words.starts_with("Invalid call code"), "{call}: {words}");
    }
    // Where the recorder drove this crate's tip, its row says the same.
    for row in vector["client"].as_array().unwrap() {
        if row["wire"] == "tip_live" {
            assert_eq!(row["fell_back"], true, "{}", row["call"]);
            let message = row["thrown"]["message"].as_str().unwrap();
            assert!(!message.contains("Invalid call code"), "{message}");
        }
    }
}

#[tokio::test]
async fn http_wallet_wire_refuses_call_29_unsent_in_the_pin_words_callcode() {
    let vector = vector();
    let pin = vector["http"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["side"] == "pin" && c["request_hex"] == "1d000001")
        .unwrap();
    assert_eq!(pin["requests_sent"], 0);
    let server = wiremock::MockServer::start().await;
    let wire = HttpWalletWire::new(None, Some(server.uri())).unwrap();
    for (request, code) in [(probe(), 29u8), (vec![99, 0], 99)] {
        let error = wire.transmit_to_wallet(&request).await.unwrap_err();
        assert_eq!(
            error,
            Error::WalletError(format!("Invalid call code: {code}"))
        );
    }
    let words = pin["thrown"]["message"].as_str().unwrap();
    let error = wire.transmit_to_wallet(&probe()).await.unwrap_err();
    assert_eq!(error, Error::WalletError(words.to_string()));
    assert!(server.received_requests().await.unwrap().is_empty());
}

/// Writes this crate's answers to the requests named by `CALLCODE_REQUESTS`
/// (comma-separated hex; the recorder's default set when absent) as a JSON
/// object of request hex to response hex at `CALLCODE_OUT`. Run on the
/// scratch base it wrote `support/wire_call_code_callcode_base_frames.json`;
/// the recorder drives it on the tip for the live row.
#[tokio::test]
#[ignore]
async fn this_crates_answers_callcode() {
    let requests: Vec<Vec<u8>> = match std::env::var("CALLCODE_REQUESTS") {
        Ok(list) => list.split(',').map(|h| hex::decode(h).unwrap()).collect(),
        Err(_) => {
            let mut all: Vec<Vec<u8>> = CODES.iter().flat_map(|&c| shapes(c)).collect();
            all.push(probe());
            all
        }
    };
    let mut out = BTreeMap::new();
    for request in requests {
        let (response, _) = answer(&request).await;
        out.insert(hex::encode(request), Value::String(hex::encode(response)));
    }
    let out: Map<String, Value> = out.into_iter().collect();
    let path = std::env::var("CALLCODE_OUT").expect("CALLCODE_OUT");
    std::fs::write(path, serde_json::to_string_pretty(&out).unwrap() + "\n").unwrap();
}
