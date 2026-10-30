//! #375: certificate-response signatures use the reference's property order,
//! while go-sdk v1.7.2 re-marshals the fields/keyring maps in byte order.
#![cfg(feature = "auth")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: witness assertions

use async_trait::async_trait;
use bsv_rs::auth::certificates::CERTIFICATE_FIELD_ENCRYPTION_PROTOCOL;
use bsv_rs::auth::transports::{Transport, TransportCallback};
use bsv_rs::auth::utils::create_nonce;
use bsv_rs::auth::{
    AuthMessage, Certificate, Peer, PeerOptions, PeerSession, RequestedCertificateSet,
    SessionManager, VerifiableCertificate,
};
use bsv_rs::primitives::{to_base64, PrivateKey, SymmetricKey};
use bsv_rs::wallet::types::Outpoint;
use bsv_rs::wallet::{Counterparty, KeyDeriver, ProtoWallet, Protocol, SecurityLevel};
use bsv_rs::Result;
use serde::Serialize;
use serde_json::{value::RawValue, Value};
use std::sync::{Arc, Mutex};

fn deterministic_test_key(scalar: u8) -> PrivateKey {
    let mut bytes = [0; 32];
    bytes[31] = scalar;
    PrivateKey::from_bytes(&bytes).unwrap()
}

fn certificate(names: &[&str]) -> VerifiableCertificate {
    let sender = deterministic_test_key(42);
    let receiver = deterministic_test_key(69);
    let certifier = deterministic_test_key(23);
    let mut cert = Certificate::new(
        [1; 32],
        [2; 32],
        sender.public_key(),
        certifier.public_key(),
    );
    cert.set_revocation_outpoint(Some(Outpoint::new([0; 32], 0)));
    let deriver = KeyDeriver::new(Some(sender));
    let protocol = Protocol::new(
        SecurityLevel::Counterparty,
        CERTIFICATE_FIELD_ENCRYPTION_PROTOCOL,
    );
    let mut keyring = indexmap::IndexMap::new();
    for (index, name) in (0u8..).zip(names) {
        // Fixed test-only keys and IVs make the writer's certificate repeatable.
        let field_key = SymmetricKey::from_bytes(&[7 + index; 32]).unwrap();
        let ciphertext = field_key
            .encrypt_with_iv(&[17 + index; 32], name.as_bytes())
            .unwrap();
        cert.set_field(*name, to_base64(&ciphertext));
        let key_id = Certificate::get_field_encryption_key_id_verifiable(name, &cert.serial_number);
        let wrapping_key = deriver
            .derive_symmetric_key(
                &protocol,
                &key_id,
                &Counterparty::Other(receiver.public_key()),
            )
            .unwrap();
        let wrapped = wrapping_key
            .encrypt_with_iv(&[27 + index; 32], field_key.as_bytes())
            .unwrap();
        keyring.insert((*name).to_owned(), to_base64(&wrapped));
    }
    cert.sign(&certifier).unwrap();
    VerifiableCertificate::new(cert, keyring)
}

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Option<AuthMessage>>>);

#[async_trait]
impl Transport for Capture {
    async fn send(&self, message: &AuthMessage) -> Result<()> {
        *self.0.lock().unwrap() = Some(message.clone());
        Ok(())
    }
    fn set_callback(&self, _: Box<TransportCallback>) {}
    fn clear_callback(&self) {}
}

fn session(own_nonce: String, peer_nonce: String, peer: u8) -> SessionManager {
    let mut sessions = SessionManager::new();
    let mut session = PeerSession::with_nonce(own_nonce);
    session.is_authenticated = true;
    session.certificates_validated = true;
    session.peer_nonce = Some(peer_nonce);
    session.peer_identity_key = Some(deterministic_test_key(peer).public_key());
    sessions.add_session(session).unwrap();
    sessions
}

async fn receive(message: AuthMessage) -> Result<()> {
    let cert = &message.certificates.as_ref().unwrap()[0];
    let mut policy = RequestedCertificateSet::new();
    policy.add_certifier(cert.certificate.certifier.to_hex());
    policy.add_type(
        to_base64(&cert.certificate.cert_type),
        cert.keyring.keys().cloned().collect(),
    );
    let sessions = session(
        message.your_nonce.clone().unwrap(),
        message.initial_nonce.clone().unwrap(),
        42,
    );
    let peer = Peer::new(PeerOptions {
        wallet: ProtoWallet::new(Some(deterministic_test_key(69))),
        transport: Capture::default(),
        certificates_to_request: Some(policy),
        session_manager: Some(sessions),
        auto_persist_last_session: false,
        originator: None,
    });
    peer.handle_incoming_message(message).await
}

async fn response(names: &[&str]) -> AuthMessage {
    let sender_wallet = ProtoWallet::new(Some(deterministic_test_key(42)));
    let receiver_wallet = ProtoWallet::new(Some(deterministic_test_key(69)));
    let sender_nonce = create_nonce(&sender_wallet, None, None).await.unwrap();
    let receiver_nonce = create_nonce(&receiver_wallet, None, None).await.unwrap();
    let capture = Capture::default();
    let peer = Peer::new(PeerOptions {
        wallet: sender_wallet,
        transport: capture.clone(),
        certificates_to_request: None,
        session_manager: Some(session(sender_nonce, receiver_nonce, 69)),
        auto_persist_last_session: false,
        originator: None,
    });
    peer.send_certificate_response(
        &deterministic_test_key(69).public_key().to_hex(),
        vec![certificate(names)],
    )
    .await
    .unwrap();
    let message = capture.0.lock().unwrap().take().unwrap();
    receive(message.clone()).await.unwrap();
    message
}

fn vector() -> Value {
    serde_json::from_str(include_str!("vectors/auth_certificate_preimage_375.json")).unwrap()
}

fn cases() -> [(&'static str, [&'static str; 4]); 2] {
    [
        ("out_of_order", ["zeta", "alpha", "10", "2"]),
        ("byte_order_control", ["alpha", "beta", "gamma", "zeta"]),
    ]
}

#[tokio::test]
async fn crate_writer_and_peer_sign_a_response_that_this_crate_verifies() {
    for (_, names) in cases() {
        let message = response(&names).await;
        assert_eq!(
            message.certificates.as_ref().unwrap()[0]
                .certificate
                .verify(),
            Ok(true)
        );
    }
}

#[tokio::test]
async fn reference_order_response_verifies_here_and_in_reference_but_fails_go() {
    let v = vector();
    assert_eq!(
        v["referenceSdk"],
        "ts-stack@edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9"
    );
    assert_eq!(v["nodeVersion"], "v22.18.0");
    assert_eq!(
        v["goSdk"],
        "v1.7.2 (2ca481c5931b987a0c8f48bb341c70b7477b6b07)"
    );
    assert_eq!(v["goVersion"], "go1.27.0");
    assert_eq!(v["cases"].as_array().unwrap().len(), 2);
    for (case, (name, names)) in v["cases"].as_array().unwrap().iter().zip(cases()) {
        assert_eq!(case["name"], name);
        let message: AuthMessage =
            serde_json::from_str(case["responseText"].as_str().unwrap()).unwrap();
        assert_eq!(
            serde_json::to_value(certificate(&names)).unwrap(),
            case["certificate"]
        );
        assert_eq!(
            serde_json::to_value(&message.certificates.as_ref().unwrap()[0]).unwrap(),
            case["certificate"]
        );
        assert_eq!(
            message.signing_data(),
            case["signedText"].as_str().unwrap().as_bytes()
        );
        assert_eq!(
            hex::encode(message.signature.as_ref().unwrap()),
            case["signatureHex"]
        );
        receive(message.clone()).await.unwrap();
        assert_eq!(case["rust"]["verify"], true);
        assert_eq!(case["reference"]["verify"], true);
        assert_eq!(case["reference"]["preimage"], case["signedText"]);
        assert_eq!(case["go"]["verify"], name == "byte_order_control");
        if name == "out_of_order" {
            assert_ne!(case["go"]["preimage"], case["signedText"]);
            assert_eq!(case["go"]["error"], "signature is not valid");
        } else {
            assert_eq!(case["go"]["preimage"], case["signedText"]);
        }
        // A sorted Value loses nonnumeric insertion order; the signature must
        // actually bind it. This negative control fails at the Peer's verifier.
        let mut tampered = message;
        tampered.certificates.as_mut().unwrap()[0].keyring.reverse();
        tampered.certificates_text = None;
        assert!(receive(tampered).await.is_err());
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecordedCase {
    name: &'static str,
    certificate: Box<RawValue>,
    response_text: String,
    signed_text: String,
    signature_hex: String,
    rust: Value,
}

#[tokio::test]
#[ignore = "recorder input: capture the marked JSON line, then run the Node and Go recorders"]
async fn print_certificate_preimage_inputs_375() {
    let mut recorded = Vec::new();
    for (name, names) in cases() {
        let message = response(&names).await;
        recorded.push(RecordedCase {
            name,
            certificate: serde_json::value::to_raw_value(&certificate(&names)).unwrap(),
            response_text: serde_json::to_string(&message).unwrap(),
            signed_text: String::from_utf8(message.signing_data()).unwrap(),
            signature_hex: hex::encode(message.signature.as_ref().unwrap()),
            rust: serde_json::json!({"verify": true}),
        });
    }
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Input {
        input_writer: &'static str,
        deterministic_test_keys: Value,
        cases: Vec<RecordedCase>,
    }
    let input = Input {
        input_writer: "bsv-rs Certificate::sign, SymmetricKey::encrypt_with_iv and Peer::send_certificate_response (#400 signing site)",
        deterministic_test_keys: serde_json::json!({"senderScalar":42,"receiverScalar":69,"certifierScalar":23}),
        cases: recorded,
    };
    println!(
        "CERTIFICATE_PREIMAGE_375_INPUT={}",
        serde_json::to_string(&input).unwrap()
    );
}
