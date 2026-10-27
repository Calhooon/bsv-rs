//! `publicly_reveal_attributes` checks the certificate's fields and the
//! names to reveal, then verifies the master certificate, before it calls
//! the wallet, as the reference's `publiclyRevealAttributes` does
//! (`ts-stack@edf6e03` `packages/sdk/src/identity/IdentityClient.ts:420-467`;
//! #307). The reference's verdicts on twenty witnesses
//! (`vectors/identity_reveal_verifies_307.json`, Node v22.18.0,
//! `tests/support/identity_reveal_verifies_307.mjs`) are this crate's: the
//! same words, no wallet call before a refusal, createAction reached where
//! the reference reaches it. A wallet that counts its calls answers
//! proveCertificate with a keyring of the names asked and createAction
//! with no transaction, so nothing is broadcast.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(feature = "identity")]

use bsv_rs::auth::certificates::Certificate;
use bsv_rs::identity::{BroadcastResult, IdentityClient, IdentityClientConfig};
use bsv_rs::primitives::{to_hex, PrivateKey};
use bsv_rs::script::templates::PushDrop;
use bsv_rs::script::LockingScript;
use bsv_rs::wallet::*;
use bsv_rs::Error;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Deserialize)]
struct Vector {
    witnesses: Vec<Witness>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Witness {
    name: String,
    certificate: WalletCertificate,
    fields_to_reveal: Vec<String>,
    refusal: Option<String>,
    #[serde(rename = "wallet_calls")]
    wallet_calls: usize,
}

fn vector() -> Vector {
    let text = include_str!("vectors/identity_reveal_verifies_307.json");
    serde_json::from_str(text).unwrap()
}

fn witness(name: &str) -> Witness {
    let found = vector().witnesses.into_iter().find(|w| w.name == name);
    found.unwrap_or_else(|| panic!("no witness {name}"))
}

/// A ProtoWallet that records each call by name; proveCertificate answers
/// a keyring of the names asked (or of `keyring` when set), createAction
/// no transaction.
#[derive(Clone)]
struct Counting {
    inner: Arc<ProtoWallet>,
    calls: Arc<Mutex<Vec<&'static str>>>,
    keyring: Option<HashMap<String, String>>,
    created: Arc<Mutex<Option<CreateActionArgs>>>,
}

impl Counting {
    fn new() -> Self {
        let key = PrivateKey::from_bytes(&[5u8; 32]).unwrap();
        Self {
            inner: Arc::new(ProtoWallet::new(Some(key))),
            calls: Arc::default(),
            keyring: None,
            created: Arc::default(),
        }
    }

    fn calls(&self) -> Vec<&'static str> {
        self.calls.lock().unwrap().clone()
    }

    fn note(&self, name: &'static str) {
        self.calls.lock().unwrap().push(name);
    }
}

// async_trait rewrites the impl it is applied to, so the macro writes the
// whole impl rather than methods inside one.
macro_rules! counting {
    ($(($method:ident, $args:ty, $result:ty)),* $(,)?) => {
        #[async_trait::async_trait]
        impl WalletInterface for Counting {
            $(async fn $method(&self, args: $args, o: &str) -> bsv_rs::Result<$result> {
                self.note(stringify!($method));
                WalletInterface::$method(&*self.inner, args, o).await
            })*

            async fn prove_certificate(
                &self,
                args: ProveCertificateArgs,
                _o: &str,
            ) -> bsv_rs::Result<ProveCertificateResult> {
                self.note("prove_certificate");
                let asked = args.fields_to_reveal.iter().map(|f| (f.clone(), "AAAA".to_string()));
                Ok(ProveCertificateResult {
                    keyring_for_verifier: self.keyring.clone().unwrap_or_else(|| asked.collect()),
                    certificate: None,
                    verifier: None,
                })
            }
            async fn create_action(
                &self,
                args: CreateActionArgs,
                _o: &str,
            ) -> bsv_rs::Result<CreateActionResult> {
                self.note("create_action");
                *self.created.lock().unwrap() = Some(args);
                Ok(CreateActionResult::default())
            }
            async fn is_authenticated(&self, o: &str) -> bsv_rs::Result<AuthenticatedResult> {
                self.note("is_authenticated");
                WalletInterface::is_authenticated(&*self.inner, o).await
            }
            async fn wait_for_authentication(
                &self,
                o: &str,
            ) -> bsv_rs::Result<AuthenticatedResult> {
                self.note("wait_for_authentication");
                WalletInterface::wait_for_authentication(&*self.inner, o).await
            }
            async fn get_height(&self, o: &str) -> bsv_rs::Result<GetHeightResult> {
                self.note("get_height");
                WalletInterface::get_height(&*self.inner, o).await
            }
            async fn get_network(&self, o: &str) -> bsv_rs::Result<GetNetworkResult> {
                self.note("get_network");
                WalletInterface::get_network(&*self.inner, o).await
            }
            async fn get_version(&self, o: &str) -> bsv_rs::Result<GetVersionResult> {
                self.note("get_version");
                WalletInterface::get_version(&*self.inner, o).await
            }
        }
    };
}

counting! {
    (get_public_key, GetPublicKeyArgs, GetPublicKeyResult),
    (encrypt, EncryptArgs, EncryptResult),
    (decrypt, DecryptArgs, DecryptResult),
    (create_hmac, CreateHmacArgs, CreateHmacResult),
    (verify_hmac, VerifyHmacArgs, VerifyHmacResult),
    (create_signature, CreateSignatureArgs, CreateSignatureResult),
    (verify_signature, VerifySignatureArgs, VerifySignatureResult),
    (reveal_counterparty_key_linkage, WalletRevealCounterpartyArgs, RevealCounterpartyKeyLinkageResult),
    (reveal_specific_key_linkage, WalletRevealSpecificArgs, RevealSpecificKeyLinkageResult),
    (sign_action, SignActionArgs, SignActionResult),
    (abort_action, AbortActionArgs, AbortActionResult),
    (list_actions, ListActionsArgs, ListActionsResult),
    (internalize_action, InternalizeActionArgs, InternalizeActionResult),
    (list_outputs, ListOutputsArgs, ListOutputsResult),
    (relinquish_output, RelinquishOutputArgs, RelinquishOutputResult),
    (acquire_certificate, AcquireCertificateArgs, WalletCertificate),
    (list_certificates, ListCertificatesArgs, ListCertificatesResult),
    (relinquish_certificate, RelinquishCertificateArgs, RelinquishCertificateResult),
    (discover_by_identity_key, DiscoverByIdentityKeyArgs, DiscoverCertificatesResult),
    (discover_by_attributes, DiscoverByAttributesArgs, DiscoverCertificatesResult),
    (get_header_for_height, GetHeaderArgs, GetHeaderResult),
}

/// The client's answer to one witness and the wallet's calls before it.
async fn reveal(
    wallet: &Counting,
    certificate: WalletCertificate,
    fields: Vec<String>,
) -> bsv_rs::Result<BroadcastResult> {
    let client = IdentityClient::new(wallet.clone(), IdentityClientConfig::default());
    client.publicly_reveal_attributes(certificate, fields).await
}

fn assert_refused_before_the_wallet(
    result: bsv_rs::Result<BroadcastResult>,
    wallet: &Counting,
    words: &str,
) {
    match result {
        Err(Error::IdentityError(found)) => assert_eq!(found, words),
        other => panic!("expected the refusal {words:?}, got {other:?}"),
    }
    assert_eq!(
        wallet.calls(),
        Vec::<&str>::new(),
        "a wallet call before {words:?}"
    );
}

#[tokio::test]
async fn every_reference_verdict_on_the_reveal_is_this_crates() {
    let witnesses = vector().witnesses;
    assert_eq!(witnesses.len(), 20);
    for w in witnesses {
        let wallet = Counting::new();
        let result = reveal(&wallet, w.certificate, w.fields_to_reveal).await;
        match w.refusal {
            Some(words) => {
                assert_eq!(
                    w.wallet_calls, 0,
                    "{}: the reference called the wallet",
                    w.name
                );
                match result {
                    Err(Error::IdentityError(found)) => assert_eq!(found, words, "{}", w.name),
                    other => panic!("{}: expected {words:?}, got {other:?}", w.name),
                }
                assert!(
                    wallet.calls().is_empty(),
                    "{}: {:?}",
                    w.name,
                    wallet.calls()
                );
            }
            None => {
                assert!(result.is_ok(), "{}: {result:?}", w.name);
                assert_eq!(wallet.calls().last(), Some(&"create_action"), "{}", w.name);
            }
        }
    }
}

#[tokio::test]
async fn an_unsigned_master_certificate_is_refused_before_any_wallet_call() {
    let w = witness("unsigned");
    let wallet = Counting::new();
    let result = reveal(&wallet, w.certificate, w.fields_to_reveal).await;
    let words = "Public reveal failed: Certificate verification failed!";
    assert_refused_before_the_wallet(result, &wallet, words);
}

#[tokio::test]
async fn a_wrongly_signed_master_certificate_is_refused_before_any_wallet_call() {
    for name in ["other_key", "field_changed", "not_der", "empty_subject"] {
        let w = witness(name);
        let wallet = Counting::new();
        let result = reveal(&wallet, w.certificate, w.fields_to_reveal).await;
        let words = "Public reveal failed: Certificate verification failed!";
        assert_refused_before_the_wallet(result, &wallet, words);
    }
}

#[tokio::test]
async fn a_name_is_judged_before_the_signature_as_the_reference_orders_them() {
    let w = witness("unsigned_absent_name");
    let wallet = Counting::new();
    let result = reveal(&wallet, w.certificate, w.fields_to_reveal).await;
    let words = "Public reveal failed: requested field is not present in the certificate!";
    assert_refused_before_the_wallet(result, &wallet, words);
}

#[tokio::test]
async fn a_signed_master_certificate_is_published_as_before() {
    let w = witness("signed");
    let wallet = Counting::new();
    let result = reveal(&wallet, w.certificate.clone(), w.fields_to_reveal).await;
    match result.unwrap() {
        BroadcastResult::Failure(f) => assert_eq!(f.code, "CREATE_ACTION_FAILED"),
        other => panic!("expected the wallet's empty createAction, got {other:?}"),
    }
    let calls = wallet.calls();
    assert_eq!(
        calls,
        ["prove_certificate", "get_public_key", "create_action"]
    );
    let created = wallet.created.lock().unwrap().clone().unwrap();
    let outputs = created.outputs.unwrap();
    let script = LockingScript::from_binary(&outputs[0].locking_script).unwrap();
    let published: serde_json::Value =
        serde_json::from_slice(&PushDrop::decode(&script).unwrap().fields[0]).unwrap();
    assert_eq!(published["signature"], w.certificate.signature.as_str());
    assert_eq!(published["keyring"], serde_json::json!({ "email": "AAAA" }));
}

#[tokio::test]
async fn a_keyring_for_another_field_is_refused_before_create_action() {
    let w = witness("signed");
    let mut wallet = Counting::new();
    wallet.keyring = Some(HashMap::from([
        ("email".to_string(), "AAAA".to_string()),
        ("name".to_string(), "AAAA".to_string()),
    ]));
    let result = reveal(&wallet, w.certificate, w.fields_to_reveal).await;
    match result {
        Err(Error::IdentityError(found)) => assert_eq!(
            found,
            "Public reveal failed: wallet returned a keyring for unrequested fields!"
        ),
        other => panic!("expected the keyring refusal, got {other:?}"),
    }
    assert_eq!(wallet.calls(), ["prove_certificate"]);
}

#[test]
fn the_vectors_signature_is_this_crates_own() {
    let w = witness("signed");
    let mut json = serde_json::to_value(&w.certificate).unwrap();
    json.as_object_mut().unwrap().remove("signature");
    let mut certificate: Certificate = serde_json::from_value(json).unwrap();
    let mut scalar = [0u8; 32];
    scalar[31] = 7; // the script's `new PrivateKey(7)`
    certificate
        .sign(&PrivateKey::from_bytes(&scalar).unwrap())
        .unwrap();
    assert_eq!(
        to_hex(certificate.signature.as_ref().unwrap()),
        w.certificate.signature
    );
}
