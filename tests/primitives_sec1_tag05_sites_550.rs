//! #550 further pins: the sites that read a key through `PublicKey::from_bytes`
//! refuse a SEC 1 tag `05` at the one root — the kvstore token controller/lock
//! key, the auth requested-certifier text, and the wallet wire counterparty —
//! doors the stable line's `primitives_sec1_tag05_witness.rs` does not already
//! cover. Carried verbatim from the sibling private secp256k1-root fix's
//! `primitives_sec1_tag_05_550.rs`, against the shared vector
//! `tests/vectors/sec1_tag_05_550.json` (reference-recorded by
//! `tests/support/sec1_tag_05_550.mjs`, Node v22.18.0; #550).
//!
//! The two `messages` recipient doors are covered in
//! `primitives_sec1_tag05_witness.rs`: on this stable line they refuse a forged
//! `05` recipient at the root (`Error::InvalidPublicKey`), not at the 0.9 line's
//! raw-bytes recipient compare, so the sibling fix's two messages tests (which
//! pin `Error::MessageRecipientMismatch`) are deliberately not carried here.
#![cfg(all(
    feature = "kvstore",
    feature = "messages",
    feature = "compat",
    feature = "auth"
))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::auth::{validate_requested_certificate_set, RequestedCertificateSet};
use bsv_rs::kvstore::{KVStoreContext, KVStoreInterpreter};
use bsv_rs::primitives::{from_hex, PrivateKey};
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

fn key(scalar: u8) -> PrivateKey {
    let mut bytes = [0u8; 32];
    bytes[31] = scalar;
    PrivateKey::from_bytes(&bytes).unwrap()
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
            hash_to_directly_sign: None,
            protocol_id: protocol.clone(),
            key_id: "alpha".into(),
            counterparty: Some(Counterparty::Anyone),
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
fn a_requested_certifier_text_with_tag_05_is_refused_550() {
    let mut set = RequestedCertificateSet::new();
    set.add_type("dHlwZQ==", vec!["name".into()]);
    set.add_certifier(format!("05{GX}"));
    assert!(matches!(
        validate_requested_certificate_set(&set),
        Err(Error::CertificateValidationError(words)) if words.ends_with("is not a valid public key")
    ));
}

/// The processor refuses the `05` counterparty with an error frame: code 1 and
/// an empty stack, as the reference refuses it (`WalletWireProcessor.ts:2459-2460`,
/// `#decodeCounterparty`'s `Point.fromDER`). The door is closed by the root
/// `PublicKey::from_bytes` guard; this stable line has no explicit tag check at
/// the reader (the 0.9 line's #550 added one, left out here so the 2560-line
/// `wire/encoding.rs` is not grown past its ratchet ceiling), and the processor
/// frames the error's `Display` (`processor.rs:232`), so the frame carries this
/// crate's `from_bytes` words (`invalid public key: Invalid public key encoding:
/// unknown point format`) where the reference writes `Unknown point format`. The
/// vector's `words`/`code` are the reference's; its `answer` is not asserted.
#[tokio::test]
async fn a_wire_counterparty_with_tag_05_is_refused_code_1_550() {
    let recorded = case("wire_counterparty");
    assert_eq!(recorded["words"], "Unknown point format");
    assert_eq!(recorded["code"], 1);
    let processor = WalletWireProcessor::new(ProtoWallet::new(Some(key(9))));
    let answer = processor
        .process_message(&input("wire_counterparty"))
        .await
        .unwrap();
    // Error frame: code 1, then a length-prefixed message, then an empty stack.
    assert_eq!(answer.first().copied(), Some(1u8), "error frame code 1");
    assert_eq!(answer.last().copied(), Some(0u8), "empty stack trace");
    // The frame carries this crate's `from_bytes` refusal words.
    let message = "invalid public key: Invalid public key encoding: unknown point format";
    let mut expected = vec![1u8];
    expected.push(message.len() as u8);
    expected.extend_from_slice(message.as_bytes());
    expected.push(0u8);
    assert_eq!(answer, expected, "the stable error frame");
}
