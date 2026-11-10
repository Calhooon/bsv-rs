//! #603: `boundary.rs`'s request snapshot bounds and the wire response cap,
//! each at the reference's edge (`ts-stack@edf6e03`), against
//! `tests/vectors/http_json_boundary_603.json` (Node v22.18.0,
//! `tests/support/http_json_boundary_603.mjs`, the reference's
//! `snapshotWalletResultRequest`). The HTTP body bounds are the integration
//! file `tests/wallet_http_json_boundary_603.rs`.
#![cfg(test)]

use super::boundary::{request, wire_response_length, MAX_BYTES};
use crate::Error;
use serde_json::Value;

const VECTOR: &str = include_str!("../../../../tests/vectors/http_json_boundary_603.json");

/// The recorded case `name`: its `reference` member, the error words or `None`
/// for an accepted request.
fn reference(name: &str) -> (Value, Option<String>) {
    let vector: Value = serde_json::from_str(VECTOR).unwrap();
    assert_eq!(vector["source"], "ts-stack@edf6e03");
    let case = vector["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("no recorded case {name}"))
        .clone();
    let reference = &case["reference"];
    let words = reference["error"].as_str().map(str::to_owned);
    if words.is_none() {
        assert_eq!(reference["accepted"], true, "{name}");
    }
    (case, words)
}

fn words(result: Result<Value, Error>) -> Option<String> {
    match result {
        Ok(_) => None,
        Err(Error::WalletError(words)) => Some(words),
        Err(other) => panic!("not a WalletError: {other:?}"),
    }
}

/// The request a `requestArray` recipe names, as the recorder builds it.
fn array_request(case: &Value) -> (String, Vec<u8>) {
    let recipe = &case["requestArray"];
    let length = usize::try_from(recipe["length"].as_u64().unwrap()).unwrap();
    let item = recipe["item"].to_string();
    let mut body = format!("{{\"{}\":[", recipe["field"].as_str().unwrap());
    for index in 0..length {
        if index > 0 {
            body.push(',');
        }
        body.push_str(&item);
    }
    body.push_str("]}");
    (case["call"].as_str().unwrap().to_owned(), body.into_bytes())
}

/// `WalletResultValidation.ts:363-372`: createAction's `outputs` items go
/// through `requestRecord`, which refuses an unsafe key (`:1560-1561`,
/// `Wallet result request records must contain only safe string keys`). The
/// key sits inside an array, so the walk must descend arrays to see it
/// (`boundary.rs:113:13`'s arm). Unit-level: no typed argument holds a
/// user-keyed object in an array (`http_json.rs:161-163` serializes the types).
#[test]
fn an_unsafe_key_inside_a_request_array_is_refused_603() {
    let (case, expected) = reference("unsafe_key_in_outputs");
    let body = case["requestText"].as_str().unwrap().as_bytes();
    let call = case["call"].as_str().unwrap();
    assert_eq!(
        expected.as_deref(),
        Some("Wallet result request records must contain only safe string keys")
    );
    assert_eq!(words(request(call, body)), expected);
}

/// `WalletResultValidation.ts:215,241-244`: `maxObjectGraphNodes =
/// 1_000_000`, a request array refused when `length > maxObjectGraphNodes`
/// (`Wallet request arrays must have a bounded own length`): 1,000,000 labels
/// accepted, 1,000,001 refused (`boundary.rs:121:5`, `121:49`).
#[test]
fn a_request_array_is_bounded_at_one_million_entries_603() {
    for name in ["labels_at_bound", "labels_past_bound"] {
        let (case, expected) = reference(name);
        let (call, body) = array_request(&case);
        assert_eq!(words(request(&call, &body)), expected, "{name}");
    }
    assert!(reference("labels_at_bound").1.is_none());
    assert_eq!(
        reference("labels_past_bound").1.as_deref(),
        Some("Wallet request arrays must have a bounded own length")
    );
}

/// `WalletWireTransceiver.ts:111-112,126-131` at `ts-stack@edf6e03`: a
/// response is refused when `length > MAX_WALLET_WIRE_FRAME_BYTES`
/// (`WalletWire.ts:9`, `256 * 1024 * 1024`), in `Wallet Wire response exceeds
/// the maximum permitted size`; a response of exactly the cap passes
/// (`boundary.rs:213:15`). A pure bound: no frame is allocated.
#[test]
fn a_wire_response_of_exactly_the_cap_passes_and_one_more_is_refused_603() {
    assert_eq!(MAX_BYTES, 256 * 1024 * 1024);
    assert!(wire_response_length(MAX_BYTES).is_ok());
    assert_eq!(
        wire_response_length(MAX_BYTES + 1),
        Err(Error::WalletError(
            "Wallet Wire response exceeds the maximum permitted size".into()
        ))
    );
}
