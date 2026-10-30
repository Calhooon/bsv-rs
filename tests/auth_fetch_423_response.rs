//! The new answer parser: every refusal comes from the Node 22 recorder.
#![cfg(feature = "auth")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test assertions.
use bsv_rs::auth::clients::{parse_known_txids_header, Response};
use bsv_rs::Error;
use serde_json::{json, Value};

fn vector() -> Value {
    serde_json::from_str(include_str!("vectors/auth_fetch_423.json")).unwrap()
}

#[test]
fn all_recorded_response_bytes_and_error_texts_423() {
    let v = vector();
    for row in v["parsing"].as_array().unwrap() {
        let payload = hex::decode(row["payload_hex"].as_str().unwrap()).unwrap();
        let parsed = Response::from_authenticated_payload(
            &payload,
            &[7; 32],
            v["identities"]["server"].as_str().unwrap(),
            8,
        );
        let actual = match parsed {
            Ok(Some(response)) => {
                json!({"result": { "status": response.status, "headers": response.headers, "body_hex": hex::encode(response.body) }})
            }
            Ok(None) => json!({"result": null}),
            Err(Error::AuthError(error)) => json!({"error":error}),
            Err(error) => panic!("unexpected error: {error}"),
        };
        let expected = if row.get("error").is_some() {
            json!({"error":row["error"]})
        } else {
            json!({"result":row["result"]})
        };
        assert_eq!(actual, expected, "{}", row["name"]);
    }
}

#[test]
fn mismatched_id_precedes_status_and_body_parsing_423() {
    let mut payload = vec![9; 32];
    payload.push(0);
    assert_eq!(
        Response::from_authenticated_payload(&payload, &[7; 32], "sender", 8).unwrap(),
        None
    );
}

#[test]
fn known_txids_are_lenient_ordered_unique_and_bounded_423() {
    for row in vector()["known_txids"].as_array().unwrap() {
        assert_eq!(
            serde_json::to_value(parse_known_txids_header(row["input"].as_str())).unwrap(),
            row["output"]
        );
    }
}

#[test]
fn payment_label_conversion_keeps_reference_base64_rules_423() {
    for row in vector()["labels"].as_array().unwrap() {
        let options = bsv_rs::auth::AuthFetchOptions {
            labels: vec!["App".into()],
            ..Default::default()
        };
        let result = options.payment_labels(
            row["prefix"].as_str().unwrap(),
            row["suffix"].as_str().unwrap(),
        );
        match result {
            Ok(labels) => assert_eq!(serde_json::to_value(labels).unwrap(), row["result"]),
            Err(Error::AuthError(error)) => assert_eq!(error, row["error"]),
            Err(error) => panic!("unexpected {error}"),
        }
    }
}

#[test]
fn response_headers_iterate_in_fetch_name_order_423() {
    let payload = bsv_rs::auth::transports::HttpResponse {
        request_id: [7; 32],
        status: 200,
        headers: vec![
            ("z-last".into(), "z".into()),
            ("a-first".into(), "a".into()),
        ],
        body: vec![],
    }
    .to_payload();
    let response = Response::from_authenticated_payload(&payload, &[7; 32], "sender", 8)
        .unwrap()
        .unwrap();
    assert_eq!(
        response
            .headers
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["a-first", "x-bsv-auth-identity-key", "z-last"]
    );
}
