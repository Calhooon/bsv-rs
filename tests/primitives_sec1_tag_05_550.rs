//! #550: a SEC 1 tag `05` key (the compact form k256 reads as `02 || x`) is
//! refused as the reference's `Point.fromDER` refuses it (`ts-stack@edf6e03`
//! `Point.ts:303-325`), at the parser and at the sites that read a key through
//! `PublicKey::from_bytes`. Against `tests/vectors/sec1_tag_05_550.json`
//! (`tests/support/sec1_tag_05_550.mjs`, Node v22.18.0): each site's input
//! with its tag set to `05` and the reference's outcome; the reference's
//! words where the site forwards them (the wire's error frame; the two
//! messages' recipient mismatch carries the reference's hex, not its words),
//! this crate's error class elsewhere.
#![cfg(all(
    feature = "kvstore",
    feature = "messages",
    feature = "compat",
    feature = "auth"
))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::auth::{validate_requested_certificate_set, Certificate, RequestedCertificateSet};
use bsv_rs::compat::ecies;
use bsv_rs::kvstore::{KVStoreContext, KVStoreInterpreter};
use bsv_rs::primitives::{from_hex, PrivateKey, PublicKey};
use bsv_rs::script::templates::PushDrop;
use bsv_rs::script::LockingScript;
use bsv_rs::transaction::{Transaction, TransactionInput, TransactionOutput};
use bsv_rs::wallet::wire::WalletWireProcessor;
use bsv_rs::wallet::{
    Counterparty, CreateSignatureArgs, KeyDeriver, ProtoWallet, Protocol, SecurityLevel,
};
use bsv_rs::Error;
use serde_json::Value;

const GX: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const MESSAGE: &[u8] = b"hello #550";

fn case(name: &str) -> Value {
    let v: Value = serde_json::from_str(include_str!("vectors/sec1_tag_05_550.json")).unwrap();
    v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("no case {name}"))
        .clone()
}

fn input(name: &str) -> Vec<u8> {
    from_hex(case(name)["input"].as_str().unwrap()).unwrap()
}

fn refused_as_unknown_point_format(result: Result<impl std::fmt::Debug, Error>) {
    match result {
        Err(Error::InvalidPublicKey(words)) => {
            assert_eq!(words, "Invalid public key encoding: unknown point format")
        }
        other => panic!("expected the unknown point format refusal, got {other:?}"),
    }
}

fn key(scalar: u8) -> PrivateKey {
    let mut bytes = [0u8; 32];
    bytes[31] = scalar;
    PrivateKey::from_bytes(&bytes).unwrap()
}

#[test]
fn a_sec1_tag_05_is_refused_by_from_bytes_and_from_hex_550() {
    for name in ["from_bytes", "from_hex"] {
        assert_eq!(case(name)["words"], "Unknown point format");
    }
    // k256 reads `05 || Gx` as the compact point `02 || Gx`.
    refused_as_unknown_point_format(PublicKey::from_bytes(&input("from_bytes")));
    refused_as_unknown_point_format(PublicKey::from_hex(&format!("05{GX}")));
    // The forms the reference reads still parse.
    assert!(PublicKey::from_bytes(&from_hex(&format!("02{GX}")).unwrap()).is_ok());
    assert!(PublicKey::from_hex(&format!("02{GX}")).is_ok());
}

#[test]
fn a_pushdrop_token_locked_with_a_tag_05_key_is_refused_in_both_positions_550() {
    for name in ["pushdrop_lock_before", "pushdrop_lock_after"] {
        assert_eq!(case(name)["words"], "Unknown point format", "{name}");
        let script = LockingScript::from_binary(&input(name)).unwrap();
        assert!(PushDrop::decode(&script).is_err(), "{name}");
    }
}

/// A raw-protocol token signed by the controller whose key is `02 || x`, its
/// controller field written `05 || x`: k256 read the field as that key, so
/// the signature verified; the reference's `validateKVStoreController`
/// refuses the field (`kvStoreTokenValidation.ts:76-81`).
#[test]
fn a_kvstore_token_whose_controller_field_is_tag_05_reads_no_value_550() {
    assert_eq!(case("kvstore_controller")["words"], "Unknown point format");
    let controller = (1u8..)
        .map(key)
        .find(|k| k.public_key().to_compressed()[0] == 2)
        .unwrap();
    let mut field = controller.public_key().to_compressed().to_vec();
    field[0] = 5;
    let protocol = Protocol::new(SecurityLevel::App, "kvstore");
    let mut fields = vec![
        serde_json::to_vec(&(1, "kvstore")).unwrap(),
        b"alpha".to_vec(),
        b"one".to_vec(),
        field,
    ];
    let signature = ProtoWallet::new(Some(controller.clone()))
        .create_signature(CreateSignatureArgs {
            data: Some(fields.concat()),
            protocol_id: protocol.clone(),
            key_id: "alpha".into(),
            counterparty: Some(Counterparty::Anyone),
            ..Default::default()
        })
        .unwrap()
        .signature;
    fields.push(signature);
    let lock = KeyDeriver::new(Some(controller))
        .derive_public_key(&protocol, "alpha", &Counterparty::Anyone, true)
        .unwrap();
    let script = PushDrop::new(lock, fields).lock();

    let read = KVStoreInterpreter::extract_fields(&script).unwrap();
    assert!(!KVStoreInterpreter::verify_signature(&read, "kvstore"));
    let mut tx = Transaction::new();
    tx.add_input(TransactionInput::new("11".repeat(32), 0))
        .unwrap();
    tx.add_output(TransactionOutput::new(1, script)).unwrap();
    let ctx = KVStoreContext::new("alpha", "kvstore");
    assert!(KVStoreInterpreter::interpret(&tx, 0, Some(&ctx)).is_none());
}

#[test]
fn the_reference_kvstore_token_with_a_tag_05_key_reads_no_value_550() {
    for name in ["kvstore_lock_key", "kvstore_controller"] {
        assert_eq!(case(name)["words"], "Unknown point format", "{name}");
        let script = LockingScript::from_binary(&input(name)).unwrap();
        let mut tx = Transaction::new();
        tx.add_input(TransactionInput::new("11".repeat(32), 0))
            .unwrap();
        tx.add_output(TransactionOutput::new(1, script)).unwrap();
        let ctx = KVStoreContext::new("alpha", "kvstore");
        assert!(
            KVStoreInterpreter::interpret(&tx, 0, Some(&ctx)).is_none(),
            "{name}"
        );
    }
}

#[test]
fn a_signed_message_naming_a_tag_05_key_is_refused_550() {
    assert_eq!(case("signed_sender")["words"], "Unknown point format");
    refused_as_unknown_point_format(bsv_rs::messages::verify(
        MESSAGE,
        &input("signed_sender"),
        None,
    ));
    // The recipient compared as bytes, as the reference compares its hex: a
    // mismatch naming the `05` bytes, not the compact point read as `02`.
    let recipient = key(9);
    let expected = format!("05{}", &recipient.public_key().to_hex()[2..]);
    let words = case("signed_recipient")["words"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(words.ends_with(&expected), "{words}");
    match bsv_rs::messages::verify(MESSAGE, &input("signed_recipient"), Some(&recipient)) {
        Err(Error::MessageRecipientMismatch {
            expected: named,
            actual,
        }) => {
            assert_eq!(named, expected);
            assert_eq!(actual, recipient.public_key().to_hex());
        }
        other => panic!("expected the recipient mismatch, got {other:?}"),
    }
}

#[test]
fn an_encrypted_message_naming_a_tag_05_key_is_refused_550() {
    let recipient = key(9);
    assert_eq!(case("encrypted_sender")["words"], "Unknown point format");
    refused_as_unknown_point_format(bsv_rs::messages::decrypt(
        &input("encrypted_sender"),
        &recipient,
    ));
    let expected = format!("05{}", &recipient.public_key().to_hex()[2..]);
    let words = case("encrypted_recipient")["words"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(words.contains(&expected), "{words}");
    match bsv_rs::messages::decrypt(&input("encrypted_recipient"), &recipient) {
        Err(Error::MessageRecipientMismatch {
            expected: named,
            actual,
        }) => {
            assert_eq!(named, expected);
            assert_eq!(actual, recipient.public_key().to_hex());
        }
        other => panic!("expected the recipient mismatch, got {other:?}"),
    }
}

#[test]
fn a_certificate_whose_subject_or_certifier_is_tag_05_is_refused_550() {
    for (name, field) in [
        ("certificate_subject", "subject"),
        ("certificate_certifier", "certifier"),
    ] {
        assert_eq!(
            case(name)["words"],
            format!("Invalid certificate {field}: expected a compressed secp256k1 public key")
        );
        refused_as_unknown_point_format(Certificate::from_binary(&input(name)));
    }
}

#[test]
fn a_bitcore_envelope_whose_sender_key_is_tag_05_is_refused_550() {
    assert_eq!(
        case("ecies_bitcore_sender")["words"],
        "Unknown point format"
    );
    refused_as_unknown_point_format(ecies::bitcore_decrypt(
        &input("ecies_bitcore_sender"),
        &key(9),
    ));
}

#[test]
fn a_requested_certifier_text_with_tag_05_is_refused_550() {
    let mut set = RequestedCertificateSet::new();
    set.add_type("dHlwZQ==", vec!["name".into()]);
    set.add_certifier(format!("05{GX}"));
    assert!(matches!(
        validate_requested_certificate_set(&set),
        Err(Error::CertificateValidationError(words)) if words.ends_with("is not a valid public key")
    ));
}

/// The processor answers the reference's error frame byte for byte: code 1,
/// `Unknown point format`, an empty stack (`WalletWireProcessor.ts:2459-2460`).
#[tokio::test]
async fn a_wire_counterparty_with_tag_05_is_the_reference_error_frame_550() {
    let recorded = case("wire_counterparty");
    assert_eq!(recorded["words"], "Unknown point format");
    assert_eq!(recorded["code"], 1);
    let processor = WalletWireProcessor::new(ProtoWallet::new(Some(key(9))));
    let answer = processor
        .process_message(&input("wire_counterparty"))
        .await
        .unwrap();
    assert_eq!(
        bsv_rs::primitives::to_hex(&answer),
        recorded["answer"].as_str().unwrap()
    );
}
