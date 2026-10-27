//! The createAction `publicly_reveal_attributes` calls sends the reference's
//! arguments and no others (#315; `ts-stack@edf6e03`
//! `packages/sdk/src/identity/IdentityClient.ts:513-528`): the description,
//! one output of satoshis, locking script and output description, and
//! `options: { randomizeOutputs: false }`; no label, no output tag or basket,
//! no `signAndProcess`, no `acceptDelayedBroadcast`, so the wallet applies its
//! own defaults (the reference's validation reads the two options as `true`,
//! `validationHelpers.ts:659-660`). The reference's witnesses
//! (`vectors/identity_reveal_create_action_315.json`, Node v22.18.0,
//! `tests/support/identity_reveal_create_action_315.mjs`) carry the arguments
//! its wallet received, compared here member by member with the arguments
//! this crate's call writes as JSON.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(feature = "identity")]

use bsv_rs::identity::{IdentityClient, IdentityClientConfig};
use bsv_rs::wallet::*;
use serde::Deserialize;
use serde_json::{Map, Value};
use std::collections::{BTreeSet, HashMap};

#[path = "support/identity_reveal_wallet.rs"]
mod identity_reveal_wallet;
use identity_reveal_wallet::Counting;

#[derive(Deserialize)]
struct Vector {
    certificate: WalletCertificate,
    witnesses: Vec<Witness>,
}

#[derive(Deserialize)]
struct Witness {
    name: String,
    fields_to_reveal: Vec<String>,
    keyring: HashMap<String, String>,
    originator: String,
    create_action: Value,
    members: Vec<String>,
    output_members: Vec<String>,
    option_members: Vec<String>,
    validated_options: Value,
}

fn vector() -> Vector {
    let text = include_str!("vectors/identity_reveal_create_action_315.json");
    serde_json::from_str(text).unwrap()
}

/// The subject's wallet (key 9) revealing the witness's names; the
/// createAction arguments it received, as JSON, and the originator.
async fn created(certificate: &WalletCertificate, w: &Witness) -> (Value, String) {
    let mut wallet = Counting::of_scalar(9);
    wallet.keyring = Some(w.keyring.clone());
    let client = IdentityClient::new(wallet.clone(), IdentityClientConfig::default());
    let _ = client
        .publicly_reveal_attributes(certificate.clone(), w.fields_to_reveal.clone())
        .await;
    assert_eq!(wallet.calls().last(), Some(&"create_action"), "{}", w.name);
    let args = wallet.created.lock().unwrap().clone().unwrap();
    let originator = wallet.created_originator.lock().unwrap().clone().unwrap();
    (serde_json::to_value(args).unwrap(), originator)
}

/// Every member of either object equal, named by its path when it is not.
fn same_members(path: &str, ours: &Map<String, Value>, reference: &Map<String, Value>) {
    let names: BTreeSet<&String> = ours.keys().chain(reference.keys()).collect();
    for name in names {
        let at = format!("{path}.{name}");
        match (ours.get(name), reference.get(name)) {
            (Some(Value::Object(a)), Some(Value::Object(b))) => same_members(&at, a, b),
            (a, b) => assert_eq!(a, b, "{at}: this crate's, then the reference's"),
        }
    }
}

#[tokio::test]
async fn the_reveal_create_action_sends_the_references_arguments_member_by_member() {
    let v = vector();
    assert_eq!(v.witnesses.len(), 2);
    for w in &v.witnesses {
        let (ours, originator) = created(&v.certificate, w).await;
        assert_eq!(originator, w.originator, "{}", w.name);
        let (ours, reference) = (
            ours.as_object().unwrap(),
            w.create_action.as_object().unwrap(),
        );
        let outputs = |o: &Map<String, Value>| o["outputs"].as_array().unwrap().clone();
        assert_eq!(outputs(ours).len(), 1, "{}", w.name);
        assert_eq!(outputs(reference).len(), 1, "{}", w.name);
        let mut ours = ours.clone();
        let mut reference = reference.clone();
        let (a, b) = (
            ours.remove("outputs").unwrap(),
            reference.remove("outputs").unwrap(),
        );
        same_members(&w.name, &ours, &reference);
        same_members(
            &format!("{}.outputs[0]", w.name),
            a[0].as_object().unwrap(),
            b[0].as_object().unwrap(),
        );
    }
}

#[tokio::test]
async fn the_reveal_create_action_carries_no_member_the_reference_leaves_out() {
    let v = vector();
    for w in &v.witnesses {
        assert_eq!(
            w.members,
            ["description", "outputs", "options"],
            "{}",
            w.name
        );
        assert_eq!(
            w.output_members,
            ["satoshis", "lockingScript", "outputDescription"],
            "{}",
            w.name
        );
        assert_eq!(w.option_members, ["randomizeOutputs"], "{}", w.name);
        let (ours, _) = created(&v.certificate, w).await;
        let keys =
            |o: &Value| -> BTreeSet<String> { o.as_object().unwrap().keys().cloned().collect() };
        let set = |names: &[String]| -> BTreeSet<String> { names.iter().cloned().collect() };
        assert_eq!(keys(&ours), set(&w.members), "{}", w.name);
        assert_eq!(
            keys(&ours["outputs"][0]),
            set(&w.output_members),
            "{}",
            w.name
        );
        assert_eq!(keys(&ours["options"]), set(&w.option_members), "{}", w.name);
    }
}

#[tokio::test]
async fn the_left_out_options_are_the_wallets_to_decide() {
    // The reference's validation of its own call: what a reference wallet
    // does with the options left out (`validationHelpers.ts:659-660`, `:804`)
    let v = vector();
    for w in &v.witnesses {
        let read = &w.validated_options;
        assert_eq!(read["signAndProcess"], true, "{}", w.name);
        assert_eq!(read["acceptDelayedBroadcast"], true, "{}", w.name);
        assert_eq!(read["isDelayed"], true, "{}", w.name);
        assert_eq!(read["randomizeOutputs"], false, "{}", w.name);
        assert_eq!(read["labels"], serde_json::json!([]), "{}", w.name);
        assert_eq!(read["output_tags"], serde_json::json!([]), "{}", w.name);
        let mut wallet = Counting::of_scalar(9);
        wallet.keyring = Some(w.keyring.clone());
        let client = IdentityClient::new(wallet.clone(), IdentityClientConfig::default());
        let _ = client
            .publicly_reveal_attributes(v.certificate.clone(), w.fields_to_reveal.clone())
            .await;
        let args = wallet.created.lock().unwrap().clone().unwrap();
        let options = args.options.unwrap();
        assert_eq!(options.sign_and_process, None, "{}", w.name);
        assert_eq!(options.accept_delayed_broadcast, None, "{}", w.name);
        assert_eq!(options.randomize_outputs, Some(false), "{}", w.name);
        assert_eq!(args.labels, None, "{}", w.name);
        let output = &args.outputs.unwrap()[0];
        assert_eq!((&output.tags, &output.basket), (&None, &None), "{}", w.name);
    }
}
