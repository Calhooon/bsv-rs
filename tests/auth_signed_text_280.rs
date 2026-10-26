//! BRC-103's signed certificate texts (#280): a certificateRequest's
//! signature covers the UTF-8 bytes of its `requestedCertificates` JSON text
//! and a certificateResponse's those of its `certificates` text, the text as
//! transmitted. BRC-103 at `5119a9b` names no serialization
//! (`peer-to-peer/0103.md:133-137`, `:172`); the reference signs
//! `JSON.stringify` of what it sends and verifies `JSON.stringify` of what it
//! parsed (`ts-stack@edf6e03` `Peer.ts:453`, `:1068`, `:1140`, `:1203`).
//!
//! The witnesses are `tests/vectors/auth_signed_text_280.json`, written by
//! `tests/support/auth_signed_text_280.mjs` under Node v22.18.0: two
//! reference `Peer`s' exchange over a transport carrying `JSON.stringify`
//! text with the bytes each wallet signed and verified, and the texts this
//! crate wrote (the ignored `record_this_crates_texts_for_the_reference`)
//! with the reference `Peer`'s verdict on each.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(feature = "auth")]

use bsv_rs::auth::certificates::{Certificate, VerifiableCertificate};
use bsv_rs::auth::{AuthMessage, MessageType, RequestedCertificateSet, AUTH_PROTOCOL_ID};
use bsv_rs::primitives::{to_base64, PrivateKey, PublicKey};
use bsv_rs::wallet::{
    Counterparty, CreateSignatureArgs, ProtoWallet, Protocol, SecurityLevel, VerifySignatureArgs,
};
use serde_json::value::RawValue;
use serde_json::Value;
use std::collections::HashMap;

const VECTOR: &str = include_str!("vectors/auth_signed_text_280.json");

fn vector() -> Value {
    serde_json::from_str(VECTOR).unwrap()
}

fn key(vector: &Value, name: &str) -> PrivateKey {
    PrivateKey::from_hex(vector["keys"][name].as_str().unwrap()).unwrap()
}

fn b64(byte: u8) -> String {
    to_base64(&[byte; 32])
}

/// The reference exchange's message of this type
fn reference_text(vector: &Value, message_type: &str) -> String {
    vector["reference_exchange"]["messages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["messageType"] == message_type)
        .unwrap()["text"]
        .as_str()
        .unwrap()
        .to_string()
}

/// The bytes the reference's wallet signed under this key ID
fn reference_signed(vector: &Value, key_id: &str) -> String {
    vector["reference_exchange"]["signed"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["keyID"] == key_id)
        .unwrap()["data"]
        .as_str()
        .unwrap()
        .to_string()
}

fn protocol() -> Protocol {
    Protocol::new(SecurityLevel::Counterparty, AUTH_PROTOCOL_ID)
}

fn sign(sender: &PrivateKey, receiver: &PublicKey, key_id: &str, data: &[u8]) -> Vec<u8> {
    ProtoWallet::new(Some(sender.clone()))
        .create_signature(CreateSignatureArgs {
            data: Some(data.to_vec()),
            protocol_id: protocol(),
            key_id: key_id.to_string(),
            counterparty: Some(Counterparty::Other(receiver.clone())),
            ..Default::default()
        })
        .unwrap()
        .signature
}

/// What `Peer::verify_message_signature` asks: the receiver's wallet over
/// `signing_data`, key ID `"<nonce> <the receiver's session nonce>"`
fn verifies(receiver: &PrivateKey, message: &AuthMessage, data: &[u8]) -> bool {
    let key_id = message.get_key_id(message.your_nonce.as_deref());
    ProtoWallet::new(Some(receiver.clone()))
        .verify_signature(VerifySignatureArgs {
            data: Some(data.to_vec()),
            signature: message.signature.clone().unwrap(),
            protocol_id: protocol(),
            key_id,
            counterparty: Some(Counterparty::Other(message.identity_key.clone())),
            ..Default::default()
        })
        .map(|r| r.valid)
        .unwrap_or(false)
}

/// A member's text inside a message's text
fn member_text(text: &str, member: &str) -> String {
    #[derive(serde::Deserialize)]
    struct Members<'a> {
        #[serde(borrow, rename = "certificates")]
        certificates: Option<&'a RawValue>,
        #[serde(borrow, rename = "requestedCertificates")]
        requested_certificates: Option<&'a RawValue>,
    }
    let members: Members = serde_json::from_str(text).unwrap();
    match member {
        "certificates" => members.certificates,
        "requestedCertificates" => members.requested_certificates,
        _ => None,
    }
    .unwrap()
    .get()
    .to_string()
}

/// The reference's policy: five types, in an order no sort gives
fn policy(certifier: &PublicKey) -> RequestedCertificateSet {
    let mut policy = RequestedCertificateSet::new();
    policy.add_certifier(certifier.to_hex());
    policy.add_type(b64(8), vec!["nickname".into()]);
    policy.add_type(
        b64(3),
        vec!["name".into(), "email".into(), "country".into()],
    );
    policy.add_type(b64(6), vec!["b".into(), "a".into()]);
    policy.add_type(b64(1), vec!["phone".into()]);
    policy.add_type(b64(4), vec!["z".into(), "y".into(), "x".into()]);
    policy
}

/// A certificate built here with three fields and a three-key keyring
fn certificate(subject: &PublicKey, certifier: &PrivateKey) -> VerifiableCertificate {
    let names = ["name", "email", "country"];
    let fields: HashMap<String, String> = names
        .iter()
        .enumerate()
        .map(|(i, n)| {
            (
                n.to_string(),
                bsv_rs::primitives::to_base64(&[i as u8 + 1; 40]),
            )
        })
        .collect();
    let mut certificate =
        Certificate::new([3; 32], [9; 32], subject.clone(), certifier.public_key())
            .with_fields(fields);
    certificate.sign(certifier).unwrap();
    let keyring = names
        .iter()
        .enumerate()
        .map(|(i, n)| (n.to_string(), vec![i as u8 + 0x40; 48]))
        .collect();
    VerifiableCertificate::new(certificate, keyring)
}

/// This crate's certificateRequest and certificateResponse to the
/// reference's verifier, on the session the reference's wallet made
fn this_crates_messages(vector: &Value) -> Vec<AuthMessage> {
    let sender = key(vector, "this_crate");
    let receiver = key(vector, "verifier").public_key();
    let certifier = key(vector, "certifier");
    let reference_session = vector["reference_session_nonce"].as_str().unwrap();
    let own_session = vector["this_crate_session_nonce"].as_str().unwrap();

    let mut request = AuthMessage::new(MessageType::CertificateRequest, sender.public_key());
    request.set_requested_certificates(policy(&certifier.public_key()));
    let mut response = AuthMessage::new(MessageType::CertificateResponse, sender.public_key());
    response.set_certificates(vec![certificate(&sender.public_key(), &certifier)]);

    [(request, 55), (response, 56)]
        .into_iter()
        .map(|(mut message, nonce)| {
            message.nonce = Some(b64(nonce));
            message.initial_nonce = Some(own_session.to_string());
            message.your_nonce = Some(reference_session.to_string());
            let key_id = message.get_key_id(Some(reference_session));
            message.signature = Some(sign(&sender, &receiver, &key_id, &message.signing_data()));
            message
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The reference's texts, read here
// ---------------------------------------------------------------------------

#[test]
fn a_reference_certificate_request_with_five_types_verifies_over_its_received_text() {
    let vector = vector();
    let text = reference_text(&vector, "certificateRequest");
    let message: AuthMessage = serde_json::from_str(&text).unwrap();
    let key_id = message.get_key_id(message.your_nonce.as_deref());

    // The bytes the reference signed are the member's text in the message
    let signed = reference_signed(&vector, &key_id);
    assert_eq!(signed, member_text(&text, "requestedCertificates"));
    assert_eq!(String::from_utf8(message.signing_data()).unwrap(), signed);
    assert_eq!(
        message.requested_certificates.as_ref().unwrap().types.len(),
        5
    );
    assert!(verifies(
        &key(&vector, "holder"),
        &message,
        &message.signing_data()
    ));
}

#[test]
fn a_reference_certificate_response_signs_the_certificates_text_it_sends() {
    let vector = vector();
    let text = reference_text(&vector, "certificateResponse");
    let certificates = member_text(&text, "certificates");
    let nonces: Value = serde_json::from_str(&text).unwrap();
    let key_id = format!(
        "{} {}",
        nonces["nonce"].as_str().unwrap(),
        nonces["yourNonce"].as_str().unwrap()
    );
    assert_eq!(reference_signed(&vector, &key_id), certificates);

    // The receiver's wallet verifies the reference's signature over that text
    let mut message = AuthMessage::new(
        MessageType::CertificateResponse,
        PublicKey::from_hex(nonces["identityKey"].as_str().unwrap()).unwrap(),
    );
    message.nonce = Some(nonces["nonce"].as_str().unwrap().to_string());
    message.your_nonce = Some(nonces["yourNonce"].as_str().unwrap().to_string());
    message.signature = Some(serde_json::from_value(nonces["signature"].clone()).unwrap());
    assert!(verifies(
        &key(&vector, "verifier"),
        &message,
        certificates.as_bytes()
    ));
}

#[test]
fn a_reference_certificate_response_is_refused_by_its_certificate_shape_until_268() {
    // The reference writes `type`, base64 field values, a hex signature and
    // base64 keyrings; this crate's certificate JSON is #261's and #268's to
    // change. When they land this test turns red: the message then parses,
    // and verifies over its text as the certificateRequest does.
    let vector = vector();
    let text = reference_text(&vector, "certificateResponse");
    let error = serde_json::from_str::<AuthMessage>(&text).unwrap_err();
    assert!(
        error
            .to_string()
            .starts_with("certificates: invalid type: string"),
        "{error}"
    );
}

// ---------------------------------------------------------------------------
// Texts received here
// ---------------------------------------------------------------------------

#[test]
fn a_received_certificate_response_with_decrypted_fields_verifies_over_its_text() {
    let sender = PrivateKey::from_hex(&"0b".repeat(32)).unwrap();
    let receiver = PrivateKey::from_hex(&"0c".repeat(32)).unwrap();
    let certifier = PrivateKey::from_hex(&"0d".repeat(32)).unwrap();

    // The certificates in sorted key order, a `decryptedFields` member added:
    // no serializer here writes these bytes
    let mut value =
        serde_json::to_value(vec![certificate(&sender.public_key(), &certifier)]).unwrap();
    value[0]["decryptedFields"] = serde_json::json!({"name": "Alice", "email": "a@b.c"});
    let certificates = serde_json::to_string(&value).unwrap();
    let (nonce, your_nonce) = (b64(1), b64(2));
    let signature = sign(
        &sender,
        &receiver.public_key(),
        &format!("{nonce} {your_nonce}"),
        certificates.as_bytes(),
    );
    let text = format!(
        r#"{{"version":"0.1","messageType":"certificateResponse","identityKey":"{}","nonce":"{nonce}","yourNonce":"{your_nonce}","certificates":{certificates},"signature":{}}}"#,
        sender.public_key().to_hex(),
        serde_json::to_string(&signature).unwrap()
    );

    let message: AuthMessage = serde_json::from_str(&text).unwrap();
    assert_eq!(
        String::from_utf8(message.signing_data()).unwrap(),
        certificates
    );
    assert!(verifies(&receiver, &message, &message.signing_data()));
    // Sent on, the text goes as received
    assert_eq!(
        member_text(&serde_json::to_string(&message).unwrap(), "certificates"),
        certificates
    );
}

#[test]
fn a_member_changed_after_receipt_is_signed_as_serialized_afresh() {
    let vector = vector();
    let mut message: AuthMessage =
        serde_json::from_str(&reference_text(&vector, "certificateRequest")).unwrap();
    let received = message.signing_data();
    message
        .requested_certificates
        .as_mut()
        .unwrap()
        .add_type(b64(2), vec!["f".into()]);

    let fresh = serde_json::to_vec(message.requested_certificates.as_ref().unwrap()).unwrap();
    assert_ne!(message.signing_data(), received);
    assert_eq!(message.signing_data(), fresh);
    let sent = serde_json::to_string(&message).unwrap();
    assert_eq!(
        member_text(&sent, "requestedCertificates").as_bytes(),
        fresh
    );
}

#[test]
fn a_null_member_reads_as_absent() {
    let key = PrivateKey::from_hex(&"0e".repeat(32)).unwrap().public_key();
    let text = format!(
        r#"{{"version":"0.1","messageType":"general","identityKey":"{}","certificates":null,"requestedCertificates":null}}"#,
        key.to_hex()
    );
    let message: AuthMessage = serde_json::from_str(&text).unwrap();
    assert!(message.certificates.is_none() && message.certificates_text.is_none());
    assert!(message.requested_certificates.is_none());
}

// ---------------------------------------------------------------------------
// Texts written here, read by the reference
// ---------------------------------------------------------------------------

#[test]
fn a_message_built_here_sends_the_compact_text_it_signs() {
    for message in this_crates_messages(&vector()) {
        let sent = serde_json::to_string(&message).unwrap();
        let member = match message.message_type {
            MessageType::CertificateRequest => "requestedCertificates",
            _ => "certificates",
        };
        let text = member_text(&sent, member);
        assert_eq!(message.signing_data(), text.as_bytes());
        assert!(!text.contains(' ') && !text.contains('\n'));
        // A reference `JSON.stringify` of the parsed text is the text: no
        // whitespace, and no key a JavaScript object would move (an
        // integer-like key goes first there)
        let read: AuthMessage = serde_json::from_str(&sent).unwrap();
        assert_eq!(read.signing_data(), message.signing_data());
    }
}

#[test]
fn this_crates_texts_carry_the_reference_peers_verdicts() {
    let vector = vector();
    let receiver = key(&vector, "this_crate");
    let messages = vector["this_crate_messages"].as_array().unwrap();
    assert_eq!(messages.len(), 2);
    for m in messages {
        let text = m["text"].as_str().unwrap();
        let message: AuthMessage = serde_json::from_str(text).unwrap();
        let member = m["member"].as_str().unwrap();
        assert_eq!(
            member_text(text, member),
            m["member_text"].as_str().unwrap()
        );
        assert_eq!(
            message.signing_data(),
            m["member_text"].as_str().unwrap().as_bytes()
        );
        assert_eq!(message.identity_key, receiver.public_key());
        match m["messageType"].as_str().unwrap() {
            // The reference verified this crate's text as sent, and its signature
            "certificateRequest" => {
                assert_eq!(m["reference_verified_bytes_equal_member_text"], true);
                assert_eq!(m["reference_signature_valid"], true);
                assert_eq!(m["reference_error"], Value::Null);
            }
            // The reference rebuilds each certificate as its class before it
            // verifies (`Peer.ts:341-357`, `:768`): this crate's `certType`
            // is no member of it, so it verifies other bytes, the text
            // without `certType` (#268's shape; the inner order is kept)
            "certificateResponse" => {
                let verified = m["reference_verified_bytes"].as_str().unwrap();
                let mut sent: Value =
                    serde_json::from_str(m["member_text"].as_str().unwrap()).unwrap();
                sent[0].as_object_mut().unwrap().remove("certType");
                assert_eq!(serde_json::from_str::<Value>(verified).unwrap(), sent);
                assert!(!verified.contains("certType"));
                assert_eq!(m["reference_signature_valid"], false);
                assert_eq!(
                    m["reference_error"],
                    format!(
                        "Unable to verify certificate response signature for peer: {}",
                        receiver.public_key().to_hex()
                    )
                );
            }
            other => panic!("unexpected {other}"),
        }
    }
}

/// Writes this crate's texts for `auth_signed_text_280.mjs verify`
/// (`AUTH_280_REFERENCE`: the script's `record` output; `AUTH_280_CRATE_OUT`:
/// the file to write)
#[test]
#[ignore]
fn record_this_crates_texts_for_the_reference() {
    let reference: Value = serde_json::from_str(
        &std::fs::read_to_string(std::env::var("AUTH_280_REFERENCE").unwrap()).unwrap(),
    )
    .unwrap();
    let messages: Vec<Value> = this_crates_messages(&reference)
        .iter()
        .map(|message| {
            let text = serde_json::to_string(message).unwrap();
            let member = match message.message_type {
                MessageType::CertificateRequest => "requestedCertificates",
                _ => "certificates",
            };
            serde_json::json!({
                "messageType": message.message_type.as_str(),
                "member": member,
                "member_text": member_text(&text, member),
                "text": text,
            })
        })
        .collect();
    std::fs::write(
        std::env::var("AUTH_280_CRATE_OUT").unwrap(),
        serde_json::to_string_pretty(&serde_json::json!({ "messages": messages })).unwrap(),
    )
    .unwrap();
}
