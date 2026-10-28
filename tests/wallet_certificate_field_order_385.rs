//! The wallet types' certificate field and keyring maps keep the order they
//! were given in, the reference's `Record` order (#385; the toolbox's #311
//! lane, the keeper's reading of 2026-10-28 00:5xZ): the reference walks a
//! certificate's fields and a keyring in `Object.keys` order
//! (`ts-stack@edf6e03` `packages/sdk/src/wallet/validationHelpers.ts:1236`,
//! `:1254`; `identity/IdentityClient.ts:485`, `:492`), writes every wire map
//! in `Object.entries` order (`WalletWireTransceiver.ts:1389`, `:1416`,
//! `:1583`, `:1815`; `WalletWireProcessor.ts:2075`, `:2202`, `:2523`,
//! `:2542`) and publishes the identity token's `{ ...certificate, keyring }`
//! in its objects' order (`IdentityClient.ts:502`). Its signer is the one
//! walk that does not follow the map: `Certificate.toBinary` sorts the names
//! by `localeCompare` (`Certificate.ts:282`), so a certificate's signed
//! preimage is the same whatever order its fields were given in, here as
//! there.
//!
//! The maps here are built with `collect()`, so the file compiles against
//! the `HashMap` shape before #385 and the `IndexMap` shape after it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(feature = "identity")]

use bsv_rs::auth::certificates::Certificate;
use bsv_rs::error::WalletRefusalClass;
use bsv_rs::identity::{IdentityClient, IdentityClientConfig};
use bsv_rs::primitives::{from_base64, to_base64};
use bsv_rs::script::templates::PushDrop;
use bsv_rs::script::LockingScript;
use bsv_rs::wallet::validation::validate_certificate_fields;
use bsv_rs::wallet::wire::{WalletWire, WalletWireTransceiver, WireWriter};
use bsv_rs::wallet::*;
use bsv_rs::Error;
use std::sync::{Arc, Mutex};

#[path = "support/identity_reveal_wallet.rs"]
mod identity_reveal_wallet;
use identity_reveal_wallet::Counting;

const G: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const TWO_G: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";

/// Twelve names in an order neither sorted nor any hash's: a map that keeps
/// no order gives them back in this order once in 12! runs.
const NAMES: [&str; 12] = [
    "role", "name", "zeta", "alpha", "Mike", "bravo", "x9", "delta", "echo", "Kilo", "golf",
    "hotel",
];

fn pairs(names: &[&str], value: impl Fn(&str) -> String) -> Vec<(String, String)> {
    names.iter().map(|n| (n.to_string(), value(n))).collect()
}

/// The JSON object of `entries`, in their order.
fn object_text(entries: &[(String, String)]) -> String {
    let members: Vec<String> = entries
        .iter()
        .map(|(k, v)| format!("{}:{}", serde_json::json!(k), serde_json::json!(v)))
        .collect();
    format!("{{{}}}", members.join(","))
}

fn keys<'a>(map: impl IntoIterator<Item = (&'a String, &'a String)>) -> Vec<String> {
    map.into_iter().map(|(k, _)| k.clone()).collect()
}

fn names(entries: &[(String, String)]) -> Vec<String> {
    entries.iter().map(|(k, _)| k.clone()).collect()
}

// ---------------------------------------------------------------------------
// The validators' walks
// ---------------------------------------------------------------------------

/// Of several field names the validator refuses, the first refused is the
/// first given, as the reference's `Object.keys` walk refuses it
/// (`validationHelpers.ts:1236-1238`); a map that keeps no order refused
/// whichever its hash put first.
#[test]
fn a_certificates_first_bad_field_name_in_insertion_order_is_the_one_refused() {
    // 26 names over 50 bytes, each its own length, given longest first
    let fields = (51..=76usize)
        .rev()
        .map(|len| ("n".repeat(len), "v".to_string()))
        .collect();
    let refused = validate_certificate_fields(&fields).unwrap_err();
    assert_eq!(
        refused,
        Error::WalletError("Invalid field name: must be no more than 50 bytes, got 76".into())
    );
    let accepted = (0..NAMES.len())
        .map(|i| (NAMES[i].to_string(), i.to_string()))
        .collect();
    let kept = validate_certificate_fields(&accepted).unwrap();
    assert_eq!(keys(&kept), NAMES.map(String::from));
}

/// The identity reveal judges the wallet's keyring in the wallet's key
/// order (`IdentityClient.ts:485`, `:492-499`): of two values it refuses,
/// the one named is the wallet's first, not the first name asked.
#[tokio::test]
async fn a_reveal_refuses_the_wallets_first_bad_keyring_value() {
    let mut wallet = Counting::new();
    wallet.keyring = Some(
        [("name", "!!!!"), ("email", "####")]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
    );
    let result = reveal(&wallet, signed_certificate(), &["email", "name"]).await;
    match result {
        Err(Error::WalletRefusal { class, message }) => {
            assert_eq!(class, WalletRefusalClass::InvalidParameter);
            assert_eq!(
                message,
                "The keyringForVerifier.name parameter must be valid base64 string"
            );
        }
        other => panic!("expected the keyring value refusal, got {other:?}"),
    }
    assert_eq!(wallet.calls(), ["prove_certificate"]);
}

/// The identity token carries `JSON.stringify({ ...certificate, keyring })`
/// (`IdentityClient.ts:502`): the certificate's fields in the order it holds
/// them and the keyring in the wallet's order, each the reference's object
/// order; before #385 the fields were written by name and the keyring in the
/// order asked.
#[tokio::test]
async fn the_identity_token_publishes_the_fields_and_keyring_in_their_order() {
    let mut wallet = Counting::new();
    let keyring = [("name", "AAAA"), ("email", "BBBB")];
    wallet.keyring = Some(
        keyring
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
    );
    let certificate = signed_certificate();
    let _ = reveal(&wallet, certificate.clone(), &["email", "name"]).await;
    let created = wallet.created.lock().unwrap().clone();
    let outputs = created.expect("createAction reached").outputs.unwrap();
    let script = LockingScript::from_binary(&outputs[0].locking_script).unwrap();
    let published = PushDrop::decode(&script).unwrap().fields[0].clone();
    let expected = format!(
        concat!(
            r#"{{"type":"{}","subject":"{}","serialNumber":"{}","certifier":"{}","#,
            r#""revocationOutpoint":"{}","signature":"{}","#,
            r#""fields":{{"name":"di1uYW1l","email":"di1lbWFpbA=="}},"#,
            r#""keyring":{{"name":"AAAA","email":"BBBB"}}}}"#
        ),
        certificate.certificate_type,
        certificate.subject,
        certificate.serial_number,
        certificate.certifier,
        certificate.revocation_outpoint,
        certificate.signature,
    );
    assert_eq!(String::from_utf8(published).unwrap(), expected);
}

/// The #307 vector's certificate signed by the certifier (`new
/// PrivateKey(7)`), its fields given name first: the signature is over the
/// `localeCompare` order, so it verifies whatever order the JSON gives.
fn signed_certificate() -> WalletCertificate {
    serde_json::from_str(concat!(
        r#"{"type":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","#,
        r#""subject":"03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe","#,
        r#""serialNumber":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","#,
        r#""certifier":"025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc","#,
        r#""revocationOutpoint":"0000000000000000000000000000000000000000000000000000000000000000.0","#,
        r#""signature":"304402202d816fbce212a51da6146401c68d39909e386081063bd0f52b4073f0b31113ef022019277a1021c5957461d1c6aeea0f2fd2ad1f7beebca5df0de81a30f6be27389c","#,
        r#""fields":{"name":"di1uYW1l","email":"di1lbWFpbA=="}}"#
    ))
    .unwrap()
}

async fn reveal(
    wallet: &Counting,
    certificate: WalletCertificate,
    fields: &[&str],
) -> bsv_rs::Result<bsv_rs::identity::BroadcastResult> {
    let client = IdentityClient::new(wallet.clone(), IdentityClientConfig::default());
    let fields = fields.iter().map(|f| f.to_string()).collect();
    client.publicly_reveal_attributes(certificate, fields).await
}

// ---------------------------------------------------------------------------
// The signer: the reference's sorted preimage, not the map's order
// ---------------------------------------------------------------------------

/// `Certificate.toBinary` writes the fields in `localeCompare` order
/// (`Certificate.ts:282-284`), the order signed and verified, whatever order
/// the fields were given in: the wallet's frame of a certificate whose map
/// holds them in another order is the sorted preimage, and the signature
/// over it verifies when the frame is read back.
#[test]
fn a_certificates_fields_are_signed_in_the_references_order_not_the_maps() {
    let given = pairs(&NAMES, |n| to_base64(n.as_bytes()));
    // JSON text, not a `serde_json::Value`: this build's `Value` sorts keys
    let members = format!(
        r#""type":"{}","subject":"{G}","serialNumber":"{}","certifier":"{TWO_G}","revocationOutpoint":"{}.1","fields":{}"#,
        to_base64(&[0x11; 32]),
        to_base64(&[0x22; 32]),
        "33".repeat(32),
        object_text(&given),
    );
    let mut certificate: Certificate = serde_json::from_str(&format!("{{{members}}}")).unwrap();
    let mut scalar = [0u8; 32];
    scalar[31] = 2; // the certifier, 2G
    let certifier = bsv_rs::primitives::PrivateKey::from_bytes(&scalar).unwrap();
    certificate.sign(&certifier).unwrap();
    let signature = bsv_rs::primitives::to_hex(certificate.signature.as_ref().unwrap());
    let wallet: WalletCertificate =
        serde_json::from_str(&format!(r#"{{{members},"signature":"{signature}"}}"#)).unwrap();
    assert_eq!(keys(&wallet.fields), names(&given));

    // localeCompare under ICU root: case folded at the first level
    let signed_order = [
        "alpha", "bravo", "delta", "echo", "golf", "hotel", "Kilo", "Mike", "name", "role", "x9",
        "zeta",
    ];
    let mut preimage = WireWriter::new();
    preimage.write_wallet_certificate(&wallet).unwrap();
    let frame = preimage.into_bytes();
    let mut walked = Vec::new();
    let mut at = 32 + 32 + 33 + 33 + 32 + 1;
    assert_eq!(frame[at] as usize, NAMES.len());
    at += 1;
    for _ in 0..NAMES.len() {
        let len = frame[at] as usize;
        walked.push(String::from_utf8(frame[at + 1..at + 1 + len].to_vec()).unwrap());
        at += 1 + len;
        at += 1 + frame[at] as usize;
    }
    assert_eq!(walked, signed_order);
    assert_eq!(
        frame[..at],
        certificate.to_binary(false).unwrap()[..],
        "the wallet's frame is the signed preimage"
    );
    assert!(Certificate::from_binary(&frame).unwrap().verify().unwrap());
}

// ---------------------------------------------------------------------------
// JSON: each of the nine maps read and written in the order given
// ---------------------------------------------------------------------------

/// Each of the nine maps read from JSON keeps the order of the text and is
/// written back in it, as `JSON.parse` and `JSON.stringify` keep a record's.
#[test]
fn every_certificate_map_keeps_its_json_order_on_read_and_write() {
    let fields = pairs(&NAMES, |n| format!("value of {n}"));
    let keyring = pairs(&NAMES, |n| to_base64(n.as_bytes()));
    let f = object_text(&fields);
    let k = object_text(&keyring);
    let certificate = format!(
        concat!(
            r#""type":"{t}","subject":"{G}","serialNumber":"{s}","certifier":"{G2}","#,
            r#""revocationOutpoint":"{o}.0","signature":"3006020101020101","fields":{f}"#
        ),
        t = to_base64(&[1; 32]),
        s = to_base64(&[2; 32]),
        o = "00".repeat(32),
        G = G,
        G2 = TWO_G,
        f = f,
    );

    let wallet: WalletCertificate = serde_json::from_str(&format!("{{{certificate}}}")).unwrap();
    assert_eq!(keys(&wallet.fields), names(&fields));
    assert_eq!(serde_json::to_string(&wallet.fields).unwrap(), f);

    let acquire: AcquireCertificateArgs = serde_json::from_str(&format!(
        r#"{{"type":"{}","certifier":"{TWO_G}","acquisitionProtocol":"direct","fields":{f},"keyringForSubject":{k}}}"#,
        to_base64(&[1; 32]),
    ))
    .unwrap();
    assert_eq!(serde_json::to_string(&acquire.fields).unwrap(), f);
    let subject_keyring = acquire.keyring_for_subject.as_ref().unwrap();
    assert_eq!(serde_json::to_string(subject_keyring).unwrap(), k);

    let listed: CertificateResult =
        serde_json::from_str(&format!(r#"{{{certificate},"keyring":{k}}}"#)).unwrap();
    assert_eq!(keys(&listed.certificate.fields), names(&fields));
    assert_eq!(
        serde_json::to_string(listed.keyring.as_ref().unwrap()).unwrap(),
        k
    );

    let proved: ProveCertificateResult =
        serde_json::from_str(&format!(r#"{{"keyringForVerifier":{k}}}"#)).unwrap();
    assert_eq!(
        serde_json::to_string(&proved.keyring_for_verifier).unwrap(),
        k
    );

    let discovered: IdentityCertificate = serde_json::from_str(&format!(
        concat!(
            r#"{{{c},"certifierInfo":{{"name":"n","iconUrl":"i","description":"d","trust":5}},"#,
            r#""publiclyRevealedKeyring":{k},"decryptedFields":{f}}}"#
        ),
        c = certificate,
        k = k,
        f = f,
    ))
    .unwrap();
    assert_eq!(keys(&discovered.certificate.fields), names(&fields));
    let text = serde_json::to_string(&discovered).unwrap();
    assert!(
        text.contains(&format!(r#""publiclyRevealedKeyring":{k}"#)),
        "{text}"
    );
    assert!(
        text.contains(&format!(r#""decryptedFields":{f}"#)),
        "{text}"
    );

    let by_attributes: DiscoverByAttributesArgs =
        serde_json::from_str(&format!(r#"{{"attributes":{f}}}"#)).unwrap();
    assert_eq!(serde_json::to_string(&by_attributes.attributes).unwrap(), f);

    let plain: bsv_rs::wallet::Certificate = serde_json::from_str(&format!(
        r#"{{"certificateType":"t","subject":"{G}","serialNumber":"s","certifier":"{TWO_G}","fields":{f}}}"#
    ))
    .unwrap();
    assert_eq!(serde_json::to_string(&plain.fields).unwrap(), f);
}

// ---------------------------------------------------------------------------
// The binary wire: the reference's `Object.entries` order both ways
// ---------------------------------------------------------------------------

/// Answers every call with the success byte and `body`, keeping the request.
struct RecordingWire {
    body: Vec<u8>,
    sent: Arc<Mutex<Vec<u8>>>,
}

#[async_trait::async_trait]
impl WalletWire for RecordingWire {
    async fn transmit_to_wallet(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        *self.sent.lock().unwrap() = message.to_vec();
        let mut answer = vec![0u8];
        answer.extend_from_slice(&self.body);
        Ok(answer)
    }
}

fn transceiver(body: Vec<u8>) -> (WalletWireTransceiver<RecordingWire>, Arc<Mutex<Vec<u8>>>) {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let wire = RecordingWire {
        body,
        sent: sent.clone(),
    };
    (WalletWireTransceiver::new(wire), sent)
}

/// `entries` as the wire writes a record: varint-length key, then the value
/// as `value` gives its bytes, varint-length.
fn record_bytes(entries: &[(String, String)], value: impl Fn(&str) -> Vec<u8>) -> Vec<u8> {
    let mut w = WireWriter::new();
    for (k, v) in entries {
        let bytes = value(v);
        w.write_string(k)
            .write_var_int(bytes.len() as u64)
            .write_bytes(&bytes);
    }
    w.into_bytes()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// acquireCertificate's request writes the fields and the subject's keyring
/// in the order given (`WalletWireTransceiver.ts:1389-1400`, `:1416-1425`).
#[tokio::test]
async fn an_acquire_request_writes_the_fields_and_keyring_in_their_order() {
    let fields = pairs(&NAMES, |n| format!("value of {n}"));
    let keyring = pairs(&NAMES, |n| to_base64(n.as_bytes()));
    let (client, sent) = transceiver(Vec::new());
    let _ = client
        .acquire_certificate(
            AcquireCertificateArgs {
                certificate_type: to_base64(&[1; 32]),
                certifier: TWO_G.to_string(),
                acquisition_protocol: AcquisitionProtocol::Direct,
                fields: fields.iter().cloned().collect(),
                serial_number: Some(to_base64(&[2; 32])),
                revocation_outpoint: Some(format!("{}.0", "00".repeat(32))),
                signature: Some("3006020101020101".to_string()),
                certifier_url: None,
                keyring_revealer: Some(KeyringRevealer::Certifier),
                keyring_for_subject: Some(keyring.iter().cloned().collect()),
                privileged: None,
                privileged_reason: None,
            },
            None,
        )
        .await;
    let sent = sent.lock().unwrap().clone();
    let field_bytes = record_bytes(&fields, |v| v.as_bytes().to_vec());
    let keyring_bytes = record_bytes(&keyring, |v| from_base64(v).unwrap());
    assert!(contains(&sent, &field_bytes), "the fields in order");
    assert!(contains(&sent, &keyring_bytes), "the keyring in order");
}

/// proveCertificate's result keyring is read in the order it arrives
/// (`WalletWireTransceiver.ts`'s record reading; the reference's processor
/// writes it in `#recordEntries` order, `WalletWireProcessor.ts:2202`).
#[tokio::test]
async fn a_prove_result_keyring_is_read_in_the_order_it_arrives() {
    let keyring = pairs(&NAMES, |n| to_base64(n.as_bytes()));
    let mut body = WireWriter::new();
    body.write_var_int(keyring.len() as u64);
    body.write_bytes(&record_bytes(&keyring, |v| from_base64(v).unwrap()));
    let (client, _) = transceiver(body.into_bytes());
    let proved = client
        .prove_certificate(
            ProveCertificateArgs {
                certificate: WalletCertificate {
                    certificate_type: to_base64(&[1; 32]),
                    subject: G.to_string(),
                    serial_number: to_base64(&[2; 32]),
                    certifier: TWO_G.to_string(),
                    revocation_outpoint: format!("{}.0", "00".repeat(32)),
                    signature: "3006020101020101".to_string(),
                    fields: pairs(&NAMES, |n| n.to_string()).into_iter().collect(),
                },
                fields_to_reveal: NAMES.iter().map(|n| n.to_string()).collect(),
                verifier: G.to_string(),
                privileged: None,
                privileged_reason: None,
            },
            None,
        )
        .await
        .unwrap();
    assert_eq!(keys(&proved.keyring_for_verifier), names(&keyring));
}

/// A discovery entry's public keyring and decrypted fields are written in
/// the order held (`#recordEntries`, `WalletWireProcessor.ts:2523`, `:2542`)
/// and read back in the order they arrive; the certificate's own fields
/// cross in the signed order, as the reference's `Certificate.fromBinary`
/// reads the frame `toBinary` wrote.
#[tokio::test]
async fn a_discovery_entry_crosses_the_wire_in_its_maps_order() {
    let fields = pairs(&NAMES, |n| format!("value of {n}"));
    let keyring = pairs(&NAMES, |n| to_base64(n.as_bytes()));
    let entry = IdentityCertificate {
        certificate: WalletCertificate {
            certificate_type: to_base64(&[0x11; 32]),
            subject: G.to_string(),
            serial_number: to_base64(&[0x22; 32]),
            certifier: TWO_G.to_string(),
            revocation_outpoint: format!("{}.1", "33".repeat(32)),
            signature: "3006020101020101".to_string(),
            fields: fields.iter().cloned().collect(),
        },
        certifier_info: IdentityCertifier {
            name: "Fixture Certifier".into(),
            icon_url: "https://certifier.invalid/icon".into(),
            description: "fixture only".into(),
            trust: 5,
        },
        publicly_revealed_keyring: keyring.iter().cloned().collect(),
        decrypted_fields: fields.iter().cloned().collect(),
    };
    let mut w = WireWriter::new();
    w.write_identity_certificate(&entry).unwrap();
    let written = w.into_bytes();
    assert!(contains(
        &written,
        &record_bytes(&keyring, |v| from_base64(v).unwrap())
    ));
    assert!(contains(
        &written,
        &record_bytes(&fields, |v| v.as_bytes().to_vec())
    ));

    let mut body = vec![1];
    body.extend_from_slice(&written);
    let (client, _) = transceiver(body);
    let read = client
        .discover_by_identity_key(
            DiscoverByIdentityKeyArgs {
                identity_key: G.to_string(),
                limit: None,
                offset: None,
                seek_permission: None,
            },
            None,
        )
        .await
        .unwrap();
    let entry = &read.certificates[0];
    assert_eq!(keys(&entry.publicly_revealed_keyring), names(&keyring));
    assert_eq!(keys(&entry.decrypted_fields), names(&fields));
    let signed_order = [
        "alpha", "bravo", "delta", "echo", "golf", "hotel", "Kilo", "Mike", "name", "role", "x9",
        "zeta",
    ];
    assert_eq!(keys(&entry.certificate.fields), signed_order);
}
