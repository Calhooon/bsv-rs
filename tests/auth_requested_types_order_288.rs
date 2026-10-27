//! A requested certificate set's `types` in insertion order (#288): the
//! reference holds `types` as a `Record<string, string[]>` (`ts-stack@edf6e03`
//! `packages/sdk/src/auth/types.ts:21-23`), writes it back in the order it
//! was built or read, and signs a certificateRequest over the UTF-8 bytes of
//! `JSON.stringify(policy)` (`Peer.ts:451-453`). Until #288 `types` was a
//! `HashMap`: two encodings of one set wrote the keys in different orders.
//!
//! The witness is `tests/vectors/auth_requested_types_order_288.json`, written
//! by `tests/support/requested_types_order_288.mjs` under Node v22.18.0: the
//! reference's `JSON.stringify` of a three-type policy, the certificateRequest
//! two reference `Peer`s exchanged with it, and the certificateRequest this
//! crate wrote (the ignored `record_this_crates_request_for_the_reference`)
//! with the reference `Peer`'s verdict on it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(feature = "auth")]

use bsv_rs::auth::{AuthMessage, MessageType, RequestedCertificateSet, AUTH_PROTOCOL_ID};
use bsv_rs::primitives::{to_base64, PrivateKey, PublicKey};
use bsv_rs::wallet::{Counterparty, CreateSignatureArgs, ProtoWallet, Protocol, SecurityLevel};
use serde_json::value::RawValue;
use serde_json::Value;

const VECTOR: &str = include_str!("vectors/auth_requested_types_order_288.json");

fn vector() -> Value {
    serde_json::from_str(VECTOR).unwrap()
}

fn key(vector: &Value, name: &str) -> PrivateKey {
    PrivateKey::from_hex(vector["keys"][name].as_str().unwrap()).unwrap()
}

fn b64(byte: u8) -> String {
    to_base64(&[byte; 32])
}

/// The reference's policy: three types, in an order no sort gives
fn policy(certifier: &PublicKey) -> RequestedCertificateSet {
    let mut policy = RequestedCertificateSet::new();
    policy.add_certifier(certifier.to_hex());
    policy.add_type(b64(7), vec!["nickname".into()]);
    policy.add_type(b64(2), vec!["name".into(), "email".into()]);
    policy.add_type(b64(5), vec!["z".into(), "a".into()]);
    policy
}

/// The `requestedCertificates` member's text inside a message's text
fn member_text(text: &str) -> String {
    #[derive(serde::Deserialize)]
    struct Members<'a> {
        #[serde(borrow, rename = "requestedCertificates")]
        requested_certificates: &'a RawValue,
    }
    let members: Members = serde_json::from_str(text).unwrap();
    members.requested_certificates.get().to_string()
}

/// This crate's certificateRequest to the reference's verifier, on the
/// session the reference's wallet made
fn this_crates_request(vector: &Value) -> AuthMessage {
    let sender = key(vector, "this_crate");
    let receiver = key(vector, "verifier").public_key();
    let reference_session = vector["reference_session_nonce"].as_str().unwrap();
    let mut message = AuthMessage::new(MessageType::CertificateRequest, sender.public_key());
    message.set_requested_certificates(policy(&key(vector, "certifier").public_key()));
    message.nonce = Some(b64(57));
    message.initial_nonce = Some(
        vector["this_crate_session_nonce"]
            .as_str()
            .unwrap()
            .to_string(),
    );
    message.your_nonce = Some(reference_session.to_string());
    let key_id = message.get_key_id(Some(reference_session));
    message.signature = Some(
        ProtoWallet::new(Some(sender))
            .create_signature(CreateSignatureArgs {
                data: Some(message.signing_data()),
                protocol_id: Protocol::new(SecurityLevel::Counterparty, AUTH_PROTOCOL_ID),
                key_id,
                counterparty: Some(Counterparty::Other(receiver)),
                ..Default::default()
            })
            .unwrap()
            .signature,
    );
    message
}

#[test]
fn three_requested_types_encode_in_the_order_given_and_re_encode_identically() {
    let certifier = PrivateKey::from_hex(&"17".repeat(32)).unwrap().public_key();
    // A hash map's order is its own per instance: many sets, so one that
    // happens to iterate in the given order proves nothing
    for _ in 0..32 {
        let set = policy(&certifier);
        let keys: Vec<&String> = set.types.keys().collect();
        assert_eq!(keys, [&b64(7), &b64(2), &b64(5)]);

        let text = serde_json::to_string(&set).unwrap();
        let at = |k: &str| text.find(k).unwrap();
        assert!(
            at(&b64(7)) < at(&b64(2)) && at(&b64(2)) < at(&b64(5)),
            "{text}"
        );

        // The fixed point: read and written again, the same bytes
        let again: RequestedCertificateSet = serde_json::from_str(&text).unwrap();
        assert_eq!(serde_json::to_string(&again).unwrap(), text);

        // A message built here sends and signs that text
        let mut message = AuthMessage::new(MessageType::CertificateRequest, certifier.clone());
        message.set_requested_certificates(set);
        let sent = serde_json::to_string(&message).unwrap();
        assert_eq!(member_text(&sent), text);
        assert_eq!(message.signing_data(), text.as_bytes());
    }
}

#[test]
fn a_json_read_keeps_the_texts_order_of_types() {
    let text = format!(
        r#"{{"certifiers":[],"types":{{"{}":["c"],"{}":["a"],"{}":["b"]}}}}"#,
        b64(9),
        b64(1),
        b64(4)
    );
    for _ in 0..32 {
        let set: RequestedCertificateSet = serde_json::from_str(&text).unwrap();
        let keys: Vec<&String> = set.types.keys().collect();
        assert_eq!(keys, [&b64(9), &b64(1), &b64(4)]);
        assert_eq!(serde_json::to_string(&set).unwrap(), text);
        // A type added after the read goes last, as a `Record`'s new key does
        let mut set = set;
        set.add_type(b64(0), vec!["d".into()]);
        assert_eq!(set.types.keys().last(), Some(&b64(0)));
    }
}

#[test]
fn this_crates_policy_text_is_the_references_json_stringify_byte_for_byte() {
    let vector = vector();
    let reference = vector["policy_text"].as_str().unwrap();
    // The reference signs that text (`Peer.ts:451-453`) and sends it as is
    let request = &vector["reference_request"];
    assert_eq!(request["signed"].as_str().unwrap(), reference);
    assert_eq!(member_text(request["text"].as_str().unwrap()), reference);
    assert_eq!(request["holder_verified"], serde_json::json!([true]));

    let set = policy(&key(&vector, "certifier").public_key());
    assert_eq!(serde_json::to_string(&set).unwrap(), reference);
    let mut message = AuthMessage::new(
        MessageType::CertificateRequest,
        key(&vector, "this_crate").public_key(),
    );
    message.set_requested_certificates(set);
    assert_eq!(message.signing_data(), reference.as_bytes());

    // The reference's message read here: the same order, the same bytes signed
    let read: AuthMessage = serde_json::from_str(request["text"].as_str().unwrap()).unwrap();
    let keys: Vec<&String> = read
        .requested_certificates
        .as_ref()
        .unwrap()
        .types
        .keys()
        .collect();
    assert_eq!(keys, [&b64(7), &b64(2), &b64(5)]);
    assert_eq!(
        serde_json::to_string(read.requested_certificates.as_ref().unwrap()).unwrap(),
        reference
    );
}

#[test]
fn the_reference_peer_verifies_this_crates_certificate_request_over_its_text() {
    let vector = vector();
    let reference = vector["policy_text"].as_str().unwrap();
    let messages = vector["this_crate_messages"].as_array().unwrap();
    assert_eq!(messages.len(), 1);
    let m = &messages[0];
    // The recorded text is the one this crate writes today
    let text = serde_json::to_string(&this_crates_request(&vector)).unwrap();
    assert_eq!(m["text"].as_str().unwrap(), text);
    assert_eq!(m["member_text"].as_str().unwrap(), reference);
    assert_eq!(m["reference_verified_bytes"].as_str().unwrap(), reference);
    assert_eq!(m["reference_signature_valid"], true);
    assert_eq!(m["reference_error"], Value::Null);
    // The reference's listener holds the policy in this crate's order
    assert_eq!(
        m["reference_received_policy_text"].as_str().unwrap(),
        reference
    );
}

/// Writes this crate's certificateRequest for
/// `requested_types_order_288.mjs verify` (`AUTH_288_REFERENCE`: the script's
/// `record` output; `AUTH_288_CRATE_OUT`: the file to write)
#[test]
#[ignore]
fn record_this_crates_request_for_the_reference() {
    let reference: Value = serde_json::from_str(
        &std::fs::read_to_string(std::env::var("AUTH_288_REFERENCE").unwrap()).unwrap(),
    )
    .unwrap();
    let text = serde_json::to_string(&this_crates_request(&reference)).unwrap();
    let messages = vec![serde_json::json!({
        "messageType": "certificateRequest",
        "member": "requestedCertificates",
        "member_text": member_text(&text),
        "text": text,
    })];
    std::fs::write(
        std::env::var("AUTH_288_CRATE_OUT").unwrap(),
        serde_json::to_string_pretty(&serde_json::json!({ "messages": messages })).unwrap(),
    )
    .unwrap();
}
