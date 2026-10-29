//! The identity client's wallet calls send what the reference sends (#318;
//! `ts-stack@edf6e03` `packages/sdk/src/identity/IdentityClient.ts`): no
//! originator unless one is configured (`:369-377`, the constructor's third
//! argument, passed as given to every `wallet.*` call), the configured one
//! when it is; `revoke_certificate_revelation`'s createAction with no label
//! and no `signAndProcess` (`:845-863`), its signAction with
//! `returnTXIDOnly: false` and the reference as createAction answered it
//! (`:896-911`). The reference's witnesses
//! (`vectors/identity_wallet_calls_318.json`, Node v22.18.0,
//! `tests/support/identity_wallet_calls_318.mjs`) carry the calls and the
//! arguments its wallet received (the revocation's once, the same for both
//! clients; bytes as hex text); the revocation is answered here with the
//! reference's lookup BEEF and signable transaction, so the two signAction
//! calls carry the same unlocking script. Since #327 the revocation makes
//! the reference's calls in its order (the two keys, the token's
//! verifySignature, createAction, createSignature, signAction, abortAction)
//! and stops in its words, the action aborted with its reference.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(feature = "identity")]

use bsv_rs::identity::{IdentityClient, IdentityClientConfig};
use bsv_rs::overlay::{
    LookupAnswer, LookupQuestion, LookupResolver, LookupResolverConfig, NetworkPreset,
    OutputListItem, OverlayLookupFacilitator,
};
use bsv_rs::primitives::{from_base64, from_hex};
use bsv_rs::wallet::*;
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

#[path = "support/identity_reveal_wallet.rs"]
mod identity_reveal_wallet;
use identity_reveal_wallet::Counting;
#[path = "support/signaction_reference_326.rs"]
mod signaction_reference_326;

#[derive(Deserialize)]
struct Vector {
    certificate: WalletCertificate,
    fields_to_reveal: Vec<String>,
    keyring: indexmap::IndexMap<String, String>,
    revocation: Revocation,
    witnesses: Vec<Witness>,
}

#[derive(Deserialize)]
struct Call {
    name: String,
    originator: Option<String>,
}

#[derive(Deserialize)]
struct Witness {
    name: String,
    configured_originator: Option<String>,
    reveal_calls: Vec<Call>,
    revoke_calls: Vec<Call>,
}

/// The revocation's answers and arguments, the same for both witnesses.
#[derive(Deserialize)]
struct Revocation {
    create_signature_json: Vec<String>,
    #[serde(deserialize_with = "hex")]
    lookup_beef: Vec<u8>,
    #[serde(deserialize_with = "hex")]
    signable_tx: Vec<u8>,
    signable_reference: String,
    stopped: String,
    abort_action: Value,
    create_action: Value,
    create_action_members: Vec<String>,
    create_action_input_members: Vec<String>,
    create_action_option_members: Vec<String>,
    sign_action: Value,
    sign_action_members: Vec<String>,
    sign_action_option_members: Vec<String>,
}

#[tokio::test]
async fn revocation_pushdrop_sends_the_recorded_data_request_454() {
    let v = vector();
    for witness in &v.witnesses {
        let wallet = revoked(&v, witness).await;
        let expected: Vec<Value> = v
            .revocation
            .create_signature_json
            .iter()
            .map(|text| serde_json::from_str(text).unwrap())
            .collect();
        assert_eq!(
            signaction_reference_326::signature_requests(&wallet.signature_args.lock().unwrap()),
            Value::Array(expected),
            "#454: the wallet sees data, protocol, key and counterparty"
        );
    }
}

fn hex<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    from_hex(&String::deserialize(d)?).map_err(serde::de::Error::custom)
}

fn vector() -> Vector {
    let text = include_str!("vectors/identity_wallet_calls_318.json");
    let mut v: Vector = serde_json::from_str(text).unwrap();
    // `inputBEEF` is recorded as hex; this crate's arguments write its bytes
    let beef = &mut v.revocation.create_action["inputBEEF"];
    *beef = serde_json::to_value(from_hex(beef.as_str().unwrap()).unwrap()).unwrap();
    v
}

fn config(w: &Witness) -> IdentityClientConfig {
    match &w.configured_originator {
        Some(o) => IdentityClientConfig::with_originator(o.clone()),
        None => IdentityClientConfig::default(),
    }
}

/// The originator the reference passed: `null` (absent) is this crate's
/// `None` (#329).
fn sent(call: &Call) -> Option<String> {
    call.originator.clone()
}

/// Answers every lookup with the reference's BEEF at output 0.
struct Lookup {
    beef: Vec<u8>,
}

#[async_trait::async_trait(?Send)]
impl OverlayLookupFacilitator for Lookup {
    async fn lookup(
        &self,
        _url: &str,
        _question: &LookupQuestion,
        _timeout_ms: Option<u64>,
    ) -> bsv_rs::Result<LookupAnswer> {
        Ok(LookupAnswer::OutputList {
            outputs: vec![OutputListItem {
                beef: self.beef.clone(),
                output_index: 0,
                context: None,
            }],
        })
    }
}

/// The subject's wallet (key 9) revoking the witness's revelation: the
/// lookup answers the reference's BEEF, createAction the reference's
/// signable transaction, signAction no transaction, so the call stops
/// before its broadcast.
async fn revoked(v: &Vector, w: &Witness) -> Counting {
    let mut wallet = Counting::of_scalar(9);
    wallet.signable = Some(SignableTransaction {
        tx: v.revocation.signable_tx.clone(),
        reference: from_base64(&v.revocation.signable_reference).unwrap(),
    });
    let mut host_overrides = HashMap::new();
    host_overrides.insert(
        "ls_identity".to_string(),
        vec!["http://identity-lookup.invalid".to_string()],
    );
    let resolver = Arc::new(LookupResolver::new(LookupResolverConfig {
        network_preset: NetworkPreset::Local,
        facilitator: Some(Arc::new(Lookup {
            beef: v.revocation.lookup_beef.clone(),
        }) as Arc<dyn OverlayLookupFacilitator>),
        slap_trackers: Some(vec![]),
        host_overrides: Some(host_overrides),
        ..Default::default()
    }));
    let client = IdentityClient::with_resolver(wallet.clone(), config(w), resolver);
    let stopped = client
        .revoke_certificate_revelation(&v.certificate.serial_number)
        .await;
    assert_eq!(
        stopped,
        Err(bsv_rs::Error::IdentityError(v.revocation.stopped.clone())),
        "{}",
        w.name
    );
    // the action aborted with the reference createAction answered (#327)
    let aborts = serde_json::to_value(wallet.aborts.lock().unwrap().clone()).unwrap();
    assert_eq!(
        aborts,
        Value::Array(vec![v.revocation.abort_action.clone()]),
        "{}",
        w.name
    );
    wallet
}

/// The subject's wallet revealing `email`, createAction answering nothing.
async fn revealed(v: &Vector, w: &Witness) -> Counting {
    let mut wallet = Counting::of_scalar(9);
    wallet.keyring = Some(v.keyring.clone());
    let client = IdentityClient::new(wallet.clone(), config(w));
    let _ = client
        .publicly_reveal_attributes(v.certificate.clone(), v.fields_to_reveal.clone())
        .await;
    wallet
}

/// Every member of either object equal, named by its path when it is not.
fn same_members(path: &str, ours: &Value, reference: &Value) {
    let (ours, reference): (&Map<String, Value>, &Map<String, Value>) =
        (ours.as_object().unwrap(), reference.as_object().unwrap());
    let names: BTreeSet<&String> = ours.keys().chain(reference.keys()).collect();
    for name in names {
        let at = format!("{path}.{name}");
        match (ours.get(name), reference.get(name)) {
            (Some(a @ Value::Object(_)), Some(b @ Value::Object(_))) => same_members(&at, a, b),
            (Some(Value::Array(a)), Some(Value::Array(b)))
                if a.first().is_some_and(Value::is_object) =>
            {
                assert_eq!(a.len(), b.len(), "{at}: this crate's, then the reference's");
                for (i, (x, y)) in a.iter().zip(b).enumerate() {
                    same_members(&format!("{at}[{i}]"), x, y);
                }
            }
            (a, b) => assert_eq!(a, b, "{at}: this crate's, then the reference's"),
        }
    }
}

fn keys(o: &Value) -> BTreeSet<String> {
    o.as_object().unwrap().keys().cloned().collect()
}

fn set(names: &[String]) -> BTreeSet<String> {
    names.iter().cloned().collect()
}

#[tokio::test]
async fn the_revocation_create_action_sends_the_references_arguments_member_by_member() {
    let v = vector();
    let r = &v.revocation;
    assert_eq!(v.witnesses.len(), 2);
    for w in &v.witnesses {
        let wallet = revoked(&v, w).await;
        let ours = serde_json::to_value(wallet.created.lock().unwrap().clone().unwrap()).unwrap();
        same_members(&w.name, &ours, &r.create_action);
        assert_eq!(keys(&ours), set(&r.create_action_members), "{}", w.name);
        assert_eq!(
            keys(&ours["inputs"][0]),
            set(&r.create_action_input_members),
            "{}",
            w.name
        );
        assert_eq!(
            keys(&ours["options"]),
            set(&r.create_action_option_members),
            "{}",
            w.name
        );
    }
}

#[tokio::test]
async fn the_revocation_sends_no_label_and_leaves_sign_and_process_to_the_wallet() {
    let v = vector();
    let r = &v.revocation;
    for w in &v.witnesses {
        assert_eq!(
            r.create_action_members,
            ["description", "inputBEEF", "inputs", "options"],
            "{}",
            w.name
        );
        assert_eq!(
            r.create_action_option_members,
            ["randomizeOutputs", "acceptDelayedBroadcast", "noSend"],
            "{}",
            w.name
        );
        let wallet = revoked(&v, w).await;
        let args = wallet.created.lock().unwrap().clone().unwrap();
        assert_eq!(args.labels, None, "{}", w.name);
        let options = args.options.unwrap();
        assert_eq!(options.sign_and_process, None, "{}", w.name);
        assert_eq!(options.accept_delayed_broadcast, Some(false), "{}", w.name);
        assert_eq!(options.no_send, Some(true), "{}", w.name);
        assert_eq!(options.randomize_outputs, Some(false), "{}", w.name);
    }
}

#[tokio::test]
async fn the_revocation_sign_action_sends_the_references_arguments_and_reference() {
    let v = vector();
    let r = &v.revocation;
    for w in &v.witnesses {
        assert_eq!(
            r.sign_action_option_members,
            ["acceptDelayedBroadcast", "returnTXIDOnly", "noSend"],
            "{}",
            w.name
        );
        let wallet = revoked(&v, w).await;
        let args = wallet.signed.lock().unwrap().clone().unwrap();
        // the reference as createAction answered it, not re-encoded
        assert_eq!(args.reference, r.signable_reference, "{}", w.name);
        let options = args.options.clone().unwrap();
        assert_eq!(options.return_txid_only, Some(false), "{}", w.name);
        let ours = serde_json::to_value(args).unwrap();
        same_members(&w.name, &ours, &r.sign_action);
        assert_eq!(keys(&ours), set(&r.sign_action_members), "{}", w.name);
        assert_eq!(
            keys(&ours["options"]),
            set(&r.sign_action_option_members),
            "{}",
            w.name
        );
    }
}

#[tokio::test]
async fn no_originator_is_sent_unless_one_is_configured() {
    let v = vector();
    assert_eq!(v.witnesses[0].configured_originator, None);
    assert_eq!(
        v.witnesses[1].configured_originator.as_deref(),
        Some("identity-client")
    );
    for w in &v.witnesses {
        let expected = w.configured_originator.clone();
        // the reference passes the configured originator, or none, on every call
        for call in w.reveal_calls.iter().chain(&w.revoke_calls) {
            assert_eq!(sent(call), expected, "{}: {}", w.name, call.name);
        }

        // the reveal: the reference's calls in its order, each with its originator
        let wallet = revealed(&v, w).await;
        let reference: Vec<&str> = w.reveal_calls.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(
            wallet.calls(),
            reference.iter().map(|n| snake(n)).collect::<Vec<_>>(),
            "{}",
            w.name
        );
        let reference_sent: Vec<Option<String>> = w.reveal_calls.iter().map(sent).collect();
        assert_eq!(wallet.originators(), reference_sent, "{}", w.name);

        // the revocation: each call this crate makes is one the reference
        // makes, in its order, with the reference's originator
        let wallet = revoked(&v, w).await;
        let mut theirs = w.revoke_calls.iter();
        for (name, originator) in wallet.calls().iter().zip(wallet.originators()) {
            let call = theirs
                .find(|c| snake(&c.name) == *name)
                .unwrap_or_else(|| panic!("{}: {name} is not the reference's next call", w.name));
            assert_eq!(originator, sent(call), "{}: {name}", w.name);
        }
        let reference: Vec<&str> = w.revoke_calls.iter().map(|c| snake(&c.name)).collect();
        assert_eq!(wallet.calls(), reference, "{}", w.name);

        // the identity key and the contacts, outside the vector: the same rule
        let wallet = Counting::of_scalar(9);
        let client = IdentityClient::new(wallet.clone(), config(w));
        client.get_identity_key().await.unwrap();
        let _ = client.get_contacts(true).await;
        assert!(
            wallet.calls().len() >= 2,
            "{}: {:?}",
            w.name,
            wallet.calls()
        );
        for (name, originator) in wallet.calls().iter().zip(wallet.originators()) {
            assert_eq!(originator, expected, "{}: {name}", w.name);
        }
    }
}

/// The reference's method name as this crate's.
fn snake(name: &str) -> &'static str {
    match name {
        "proveCertificate" => "prove_certificate",
        "getPublicKey" => "get_public_key",
        "createSignature" => "create_signature",
        "verifySignature" => "verify_signature",
        "createAction" => "create_action",
        "signAction" => "sign_action",
        "abortAction" => "abort_action",
        other => panic!("no name for {other}"),
    }
}
