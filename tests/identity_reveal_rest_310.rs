//! The identity token `publicly_reveal_attributes` builds is the reference's
//! (`ts-stack@edf6e03` `packages/sdk/src/identity/IdentityClient.ts:501-509`,
//! `PushDrop.ts:146-202`; #310): the subject's key for `[1, 'identity']` key
//! `1`, counterparty `anyone`, `forSelf: true`, the certificate JSON and the
//! subject's signature over it pushed and dropped, byte for byte the
//! reference's for the same certificate and keyring; and createAction's
//! empty answer is refused in the reference's words (`:537`). The reference's
//! witnesses (`vectors/identity_reveal_rest_310.json`, Node v22.18.0,
//! `tests/support/identity_reveal_rest_310.mjs`) carry its wallet calls, its
//! locking script and the verdict of the overlay's identity reader
//! (`packages/overlays/topics/src/identity/identityTokenValidation.ts:92-154`)
//! on it; the reader's checks are run here too on this crate's token.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(feature = "identity")]

use bsv_rs::auth::VerifiableCertificate;
use bsv_rs::identity::{BroadcastResult, IdentityClient, IdentityClientConfig};
use bsv_rs::primitives::{to_hex, PublicKey};
use bsv_rs::script::templates::PushDrop;
use bsv_rs::script::LockingScript;
use bsv_rs::wallet::*;
use bsv_rs::Error;
use indexmap::IndexMap;
use serde::Deserialize;

#[path = "support/identity_reveal_wallet.rs"]
mod identity_reveal_wallet;
use identity_reveal_wallet::Counting;

#[derive(Deserialize)]
struct Vector {
    certificate: WalletCertificate,
    witnesses: Vec<Witness>,
    unsigned_token: UnsignedToken,
}

#[derive(Deserialize)]
struct Witness {
    name: String,
    fields_to_reveal: Vec<String>,
    keyring: IndexMap<String, String>,
    wallet_calls: Vec<serde_json::Value>,
    locking_script: String,
    published_json: String,
    signature: String,
    refusal: String,
    refusal_name: String,
    reader: Reader,
}

#[derive(Deserialize)]
struct Reader {
    admitted: bool,
    #[serde(default)]
    decrypted_fields: std::collections::HashMap<String, String>,
    #[serde(default)]
    refusal: Option<String>,
}

#[derive(Deserialize)]
struct UnsignedToken {
    locking_script: String,
    reader: Reader,
}

fn vector() -> Vector {
    let text = include_str!("vectors/identity_reveal_rest_310.json");
    serde_json::from_str(text).unwrap()
}

/// The subject's wallet (key 9, as the reference's script) revealing the
/// witness's names, proveCertificate answering the witness's keyring.
async fn reveal(
    certificate: &WalletCertificate,
    w: &Witness,
) -> (Counting, bsv_rs::Result<BroadcastResult>) {
    let mut wallet = Counting::of_scalar(9);
    wallet.keyring = Some(w.keyring.clone());
    let client = IdentityClient::new(wallet.clone(), IdentityClientConfig::default());
    let result = client
        .publicly_reveal_attributes(certificate.clone(), w.fields_to_reveal.clone())
        .await;
    (wallet, result)
}

fn created_script(wallet: &Counting) -> LockingScript {
    let created = wallet.created.lock().unwrap().clone().unwrap();
    LockingScript::from_binary(&created.outputs.unwrap()[0].locking_script).unwrap()
}

fn identity_protocol() -> Protocol {
    Protocol::from_tuple((1, "identity")).unwrap()
}

#[tokio::test]
async fn the_identity_token_is_the_references_byte_for_byte() {
    let v = vector();
    assert_eq!(v.witnesses.len(), 3);
    for w in &v.witnesses {
        let (wallet, _) = reveal(&v.certificate, w).await;
        let script = created_script(&wallet);
        let fields = PushDrop::decode(&script).unwrap().fields;
        assert_eq!(
            String::from_utf8(fields[0].clone()).unwrap(),
            w.published_json,
            "{}",
            w.name
        );
        assert_eq!(to_hex(&fields[1]), w.signature, "{}", w.name);
        assert_eq!(script.to_hex(), w.locking_script, "{}", w.name);
    }
}

#[tokio::test]
async fn the_token_key_and_signature_are_asked_with_the_references_arguments() {
    let v = vector();
    for w in &v.witnesses {
        let (wallet, _) = reveal(&v.certificate, w).await;
        let methods: Vec<&str> = w
            .wallet_calls
            .iter()
            .map(|c| c["method"].as_str().unwrap())
            .collect();
        assert_eq!(
            methods,
            [
                "proveCertificate",
                "getPublicKey",
                "createSignature",
                "createAction"
            ]
        );
        assert_eq!(
            wallet.calls(),
            [
                "prove_certificate",
                "get_public_key",
                "create_signature",
                "create_action"
            ],
            "{}",
            w.name
        );
        let asked = &w.wallet_calls[1]["args"];
        assert_eq!(asked["protocolID"], serde_json::json!([1, "identity"]));
        assert_eq!(asked["keyID"], "1");
        assert_eq!(asked["counterparty"], "anyone");
        assert_eq!(asked["forSelf"], true);
        let key = wallet.public_key_args.lock().unwrap()[0].clone();
        assert_eq!(key.protocol_id, Some(identity_protocol()), "{}", w.name);
        assert_eq!(key.key_id.as_deref(), Some("1"), "{}", w.name);
        assert_eq!(key.counterparty, Some(Counterparty::Anyone), "{}", w.name);
        assert_eq!(key.for_self, Some(true), "{}", w.name);

        let signed = &w.wallet_calls[2]["args"];
        assert_eq!(signed["protocolID"], serde_json::json!([1, "identity"]));
        assert_eq!(signed["keyID"], "1");
        assert_eq!(signed["counterparty"], "anyone");
        assert_eq!(
            signed.get("forSelf"),
            None,
            "createSignature carries no forSelf"
        );
        let signature = wallet.signature_args.lock().unwrap()[0].clone();
        assert_eq!(signature.protocol_id, identity_protocol(), "{}", w.name);
        assert_eq!(signature.key_id, "1", "{}", w.name);
        assert_eq!(
            signature.counterparty,
            Some(Counterparty::Anyone),
            "{}",
            w.name
        );
        assert_eq!(
            to_hex(signature.data.as_deref().unwrap()),
            signed["data"].as_str().unwrap(),
            "{}",
            w.name
        );
    }
}

/// The overlay's identity reader on a token (`identityTokenValidation.ts:92-154`):
/// two fields in the canonical signed shape, the key the subject's under
/// `[1, 'identity']` key `1` for anyone, the signature the subject's over
/// the JSON, the certificate verifying, the fields decrypted by anyone.
async fn read_as_the_overlay_reads(
    script: &LockingScript,
) -> std::collections::HashMap<String, String> {
    let decoded = PushDrop::decode(script).unwrap();
    assert_eq!(decoded.fields.len(), 2);
    let chunks = script.chunks();
    let ops: Vec<u8> = chunks.iter().map(|c| c.op).collect();
    assert_eq!(ops.len(), 5);
    assert_eq!((ops[0], ops[1], ops[4]), (33, 0xac, 0x6d));
    let json: serde_json::Value = serde_json::from_slice(&decoded.fields[0]).unwrap();
    let subject = PublicKey::from_hex(json["subject"].as_str().unwrap()).unwrap();
    let anyone = ProtoWallet::anyone();
    let expected = anyone
        .get_public_key(GetPublicKeyArgs {
            protocol_id: Some(identity_protocol()),
            key_id: Some("1".to_string()),
            counterparty: Some(Counterparty::Other(subject.clone())),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(
        decoded.locking_public_key.to_hex(),
        expected.public_key,
        "the token's key the subject's"
    );
    let verdict = anyone
        .verify_signature(VerifySignatureArgs {
            data: Some(decoded.fields[0].clone()),
            signature: decoded.fields[1].clone(),
            protocol_id: identity_protocol(),
            key_id: "1".to_string(),
            counterparty: Some(Counterparty::Other(subject)),
            ..Default::default()
        })
        .unwrap();
    assert!(verdict.valid, "the subject's signature over the JSON");
    let mut certificate: VerifiableCertificate = serde_json::from_value(json).unwrap();
    assert!(certificate.verify().unwrap());
    certificate
        .decrypt_fields(&anyone, None, None, Some("identity-client"))
        .await
        .unwrap()
}

#[tokio::test]
async fn the_token_is_admitted_as_the_overlay_identity_reader_admits_it() {
    let v = vector();
    for w in &v.witnesses {
        assert!(w.reader.admitted, "{}: {:?}", w.name, w.reader.refusal);
        let (wallet, _) = reveal(&v.certificate, w).await;
        let script = created_script(&wallet);
        // The reader admitted the reference's bytes; these are those bytes
        assert_eq!(script.to_hex(), w.locking_script, "{}", w.name);
        let decrypted = read_as_the_overlay_reads(&script).await;
        assert_eq!(decrypted, w.reader.decrypted_fields, "{}", w.name);
    }
}

#[tokio::test]
async fn the_unsigned_token_built_before_310_is_refused_by_the_overlay_reader() {
    let v = vector();
    assert!(!v.unsigned_token.reader.admitted);
    assert_eq!(
        v.unsigned_token.reader.refusal.as_deref(),
        Some("Identity token must contain exactly two fields")
    );
    let w = &v.witnesses[0];
    let (wallet, _) = reveal(&v.certificate, w).await;
    let script = created_script(&wallet);
    assert_ne!(script.to_hex(), v.unsigned_token.locking_script);
    let old = LockingScript::from_hex(&v.unsigned_token.locking_script).unwrap();
    assert_eq!(PushDrop::decode(&old).unwrap().fields.len(), 1);
}

#[tokio::test]
async fn a_create_action_with_no_transaction_is_refused_in_the_reference_words() {
    let v = vector();
    for w in &v.witnesses {
        assert_eq!(w.refusal, "Public reveal failed: failed to create action!");
        assert_eq!(w.refusal_name, "Error");
        let (wallet, result) = reveal(&v.certificate, w).await;
        match result {
            Err(Error::IdentityError(words)) => assert_eq!(words, w.refusal, "{}", w.name),
            other => panic!("{}: expected the refusal, got {other:?}", w.name),
        }
        assert_eq!(wallet.calls().last(), Some(&"create_action"), "{}", w.name);
    }
}

/// The key `revoke_certificate_revelation` signs under (createSignature for
/// anyone, the reference's `revelationLockingKey` at `IdentityClient.ts:722-728`).
fn revocation_key(wallet: &ProtoWallet, for_self: bool) -> String {
    let anyone = Counterparty::Anyone;
    let args = GetPublicKeyArgs {
        protocol_id: Some(identity_protocol()),
        key_id: Some("1".to_string()),
        counterparty: Some(anyone),
        for_self: Some(for_self),
        ..Default::default()
    };
    wallet.get_public_key(args).unwrap().public_key
}

#[tokio::test]
async fn the_token_is_locked_to_the_subjects_key_and_not_to_anyones() {
    let v = vector();
    let (wallet, _) = reveal(&v.certificate, &v.witnesses[0]).await;
    let key = PushDrop::decode(&created_script(&wallet))
        .unwrap()
        .locking_public_key
        .to_hex();
    let mut scalar = [0u8; 32];
    scalar[31] = 9;
    let subject = ProtoWallet::new(Some(
        bsv_rs::primitives::PrivateKey::from_bytes(&scalar).unwrap(),
    ));
    assert_eq!(key, revocation_key(&subject, true));
    // Before #310 the key was `for_self: false`'s: the child the anyone
    // wallet derives for itself, so any wallet could spend the token
    let old = LockingScript::from_hex(&v.unsigned_token.locking_script).unwrap();
    let old_key = PushDrop::decode(&old).unwrap().locking_public_key.to_hex();
    assert_eq!(old_key, revocation_key(&subject, false));
    let anyones = ProtoWallet::anyone()
        .get_public_key(GetPublicKeyArgs {
            protocol_id: Some(identity_protocol()),
            key_id: Some("1".to_string()),
            counterparty: Some(Counterparty::Other(
                PublicKey::from_hex(&v.certificate.subject).unwrap(),
            )),
            for_self: Some(true),
            ..Default::default()
        })
        .unwrap()
        .public_key;
    assert_eq!(old_key, anyones);
    assert_ne!(key, anyones);
}
