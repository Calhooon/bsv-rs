//! #818b (#905): the identity client's by-key, attribute and discovery doors
//! refuse, before any host is asked, what the reference's wallet door
//! refuses. The reference's `IdentityClient` hands its arguments to its
//! wallet (`ts-stack@edf6e03` `packages/sdk/src/identity/IdentityClient.ts:569`,
//! `:614`), whose `WalletClient` validates them before it connects
//! (`packages/sdk/src/wallet/WalletClient.ts:509-511`, `:524`); with contacts,
//! `getContacts` judges the key by the contacts manager's own rule ahead of the wallet
//! (`IdentityClient.ts:575`, `ContactsManager.ts:316-317`, `:83-94`). Until
//! #818b these doors sent the argument, the overlay refused the whole
//! question, the resolver read that as an empty answer and charged the host.
//!
//! Against `vectors/identity_door_args_818b.json`
//! (`support/identity_door_args_818b.mjs`: the reference's `IdentityClient`
//! over `new WalletClient(double)`, the double counting every call, Node
//! v22.18.0): each refused cell is refused here in the recorded words with NO
//! question sent, each accepted cell sends exactly one question, the key's
//! text as given (`Wallet.ts:1004`; the double received it so). #752's
//! recording facilitator over an injected `.invalid` resolver; no network.
//! The by-type door's type, which no reference door takes, is judged by
//! `query`'s rule (#756's fold) on `vectors/identity_query_bounds_756.json`'s
//! type cases. The subject is compared with the key the text names
//! (`Wallet.ts:1012`, `filterCertificatesByIdentityKey`): on #553's reference
//! token (#737's builder), a space-padded asked key keeps its subject's
//! certificate. RED on `5a87392e`: every refused cell `Ok([])` with one
//! question sent, and the padded key's certificate dropped.
#![cfg(feature = "identity")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::identity::{IdentityClient, IdentityQuery};
use bsv_rs::overlay::{
    LookupAnswer, LookupQuestion, LookupResolver, LookupResolverConfig, OutputListItem,
    OverlayLookupFacilitator,
};
use bsv_rs::script::{LockingScript, UnlockingScript};
use bsv_rs::transaction::{
    Beef, MerklePath, MerklePathLeaf, Transaction, TransactionInput, TransactionOutput,
};
use bsv_rs::wallet::ProtoWallet;
use bsv_rs::Error;
use indexmap::IndexMap;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// A valid type for the by-type door's key cells: base64 of 32 bytes.
const TYPE: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

fn vector() -> Value {
    serde_json::from_str(include_str!("vectors/identity_door_args_818b.json")).unwrap()
}

fn cases(prefix: &str) -> Vec<Value> {
    vector()["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["name"].as_str().unwrap().starts_with(prefix))
        .cloned()
        .collect()
}

/// A facilitator recording each question's query and answering `outputs`.
struct Recording(Arc<Mutex<Vec<Value>>>, Vec<OutputListItem>);

#[async_trait::async_trait(?Send)]
impl OverlayLookupFacilitator for Recording {
    async fn lookup(
        &self,
        _url: &str,
        question: &LookupQuestion,
        _timeout_ms: Option<u64>,
    ) -> bsv_rs::Result<LookupAnswer> {
        self.0.lock().unwrap().push(question.query.clone());
        Ok(LookupAnswer::OutputList {
            outputs: self.1.clone(),
        })
    }
}

type Asked = Arc<Mutex<Vec<Value>>>;

fn client_answering(outputs: Vec<OutputListItem>) -> (IdentityClient<ProtoWallet>, Asked) {
    let asked = Arc::new(Mutex::new(Vec::new()));
    let resolver = Arc::new(LookupResolver::new(LookupResolverConfig {
        facilitator: Some(Arc::new(Recording(asked.clone(), outputs))),
        slap_trackers: Some(vec![]),
        host_overrides: Some(HashMap::from([(
            "ls_identity".to_string(),
            vec!["https://ls_identity.invalid".to_string()],
        )])),
        ..Default::default()
    }));
    (
        IdentityClient::with_resolver(ProtoWallet::new(None), Default::default(), resolver),
        asked,
    )
}

fn client() -> (IdentityClient<ProtoWallet>, Asked) {
    client_answering(vec![])
}

/// A case's attribute map in insertion order (see the wallet file's twin).
fn attributes_of(case: &Value) -> IndexMap<String, String> {
    match &case["attributes"] {
        Value::Array(pairs) => pairs
            .iter()
            .map(|p| (p[0].as_str().unwrap().into(), p[1].as_str().unwrap().into()))
            .collect(),
        recorded => (0..recorded["count"].as_u64().unwrap())
            .map(|i| (format!("f{i}"), "v".to_string()))
            .collect(),
    }
}

/// `got` and the questions sent against the recorded door outcome: refused
/// in its words (`WERR_INVALID_PARAMETER` a `WalletRefusal` of that class,
/// a plain `Error` the contacts manager's `IdentityError`) with nothing sent;
/// accepted with exactly one question.
fn agrees<T: std::fmt::Debug>(
    got: &bsv_rs::Result<T>,
    sent: usize,
    outcome: &Value,
) -> Result<(), String> {
    let ok = match (got, outcome.get("refused")) {
        (Err(Error::WalletRefusal { class, message }), Some(refused)) => {
            refused["name"] == class.name() && refused["message"] == message.as_str() && sent == 0
        }
        (Err(Error::IdentityError(message)), Some(refused)) => {
            refused["name"] == "Error" && refused["message"] == message.as_str() && sent == 0
        }
        (Ok(_), None) => sent == 1,
        _ => false,
    };
    if ok {
        Ok(())
    } else {
        Err(format!("{got:?}, {sent} sent; {outcome}"))
    }
}

/// Each key cell through `door` against the recorded column `column`.
async fn key_door<F, Fut, T>(column: &str, door: F) -> usize
where
    F: Fn(IdentityClient<ProtoWallet>, String) -> Fut,
    Fut: std::future::Future<Output = bsv_rs::Result<T>>,
    T: std::fmt::Debug,
{
    let cases = cases("key_");
    let mut differ = Vec::new();
    for case in &cases {
        let subject = case["subject"].as_str().unwrap().to_string();
        let (client, asked) = client();
        let got = door(client, subject.clone()).await;
        let asked = asked.lock().unwrap().clone();
        if let Err(why) = agrees(&got, asked.len(), &case[column]) {
            differ.push(format!("{}: {why}", case["name"]));
        } else if let Some(question) = asked.first() {
            // The question carries the text as given, as the double received it
            let received = &case[column]["received"]["discoverByIdentityKey"]["subject"];
            if question["identityKey"] != *received || *received != subject.as_str() {
                differ.push(format!(
                    "{}: sent {}",
                    case["name"], question["identityKey"]
                ));
            }
        }
    }
    assert!(differ.is_empty(), "{differ:#?}");
    cases.len()
}

#[tokio::test]
async fn resolve_by_identity_key_refuses_a_key_the_wallet_door_refuses_before_any_host_818b() {
    let n = key_door("resolve", |client, key| async move {
        client.resolve_by_identity_key(&key, false).await
    })
    .await;
    assert_eq!(n, 17);
}

/// With contacts the contacts manager's rule comes ahead, in its words:
/// an upper-case or padded key the wallet admits is refused there.
#[tokio::test]
async fn with_contacts_the_contact_rule_refuses_ahead_in_its_words_818b() {
    let n = key_door("resolve_with_contacts", |client, key| async move {
        client.resolve_by_identity_key(&key, true).await
    })
    .await;
    assert_eq!(n, 17);
}

/// `discover_certificates` is the wallet's `discoverByIdentityKey` door: the
/// recorded wallet-door verdicts (the `resolve` column, which reaches it).
#[tokio::test]
async fn discover_certificates_refuses_a_key_the_wallet_door_refuses_before_any_host_818b() {
    let n = key_door("resolve", |client, key| async move {
        client.discover_certificates(&key).await
    })
    .await;
    assert_eq!(n, 17);
}

/// The by-type door judges the key as `discover_certificates` does (a valid
/// type beside it).
#[tokio::test]
async fn discover_certificates_by_type_refuses_a_key_the_wallet_door_refuses_818b() {
    let n = key_door("resolve", |client, key| async move {
        client.discover_certificates_by_type(&key, TYPE).await
    })
    .await;
    assert_eq!(n, 17);
}

/// The by-type door's type, which no reference door takes, by `query`'s rule
/// in the overlay's words (#756's fold), after a valid key: this crate's own.
#[tokio::test]
async fn discover_certificates_by_type_refuses_a_type_query_refuses_818b() {
    let v: Value =
        serde_json::from_str(include_str!("vectors/identity_query_bounds_756.json")).unwrap();
    let key = vector()["generator"].as_str().unwrap().to_string();
    let mut judged = 0;
    for case in v["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        // The type cases whose key, if any, is the generator's or absent
        if !name.starts_with("type_") || name == "type_beside_attributes" {
            continue;
        }
        let Some(cert_type) = case["certificateType"].as_str() else {
            continue;
        };
        let (client, asked) = client();
        let got = client.discover_certificates_by_type(&key, cert_type).await;
        let sent = asked.lock().unwrap().len();
        match case["outcome"]["refused"].as_str() {
            Some(words) => assert_eq!(
                (got.unwrap_err(), sent),
                (Error::IdentityError(words.into()), 0),
                "{name}"
            ),
            None => assert!(got.is_ok() && sent == 1, "{name}: {got:?}, {sent} sent"),
        }
        judged += 1;
    }
    assert_eq!(judged, 8);
}

#[tokio::test]
async fn resolve_by_attributes_refuses_a_map_the_wallet_door_refuses_before_any_host_818b() {
    let mut cases = Vec::new();
    for prefix in ["attributes_", "name_", "value_", "unsafe_", "two_faults_"] {
        cases.extend(self::cases(prefix));
    }
    assert_eq!(cases.len(), 25);
    let mut differ = Vec::new();
    for case in &cases {
        for contacts in [false, true] {
            let (client, asked) = client();
            let attributes = attributes_of(case);
            let got = client
                .resolve_by_attributes(attributes.clone(), contacts)
                .await;
            let asked = asked.lock().unwrap().clone();
            // With contacts the reference loads them (one `listOutputs`, recorded)
            // and then refuses in the same words; here the map is judged before them
            let column = if contacts {
                "resolve_with_contacts"
            } else {
                "resolve"
            };
            if let Err(why) = agrees(&got, asked.len(), &case[column]) {
                differ.push(format!("{} (contacts {contacts}): {why}", case["name"]));
            } else if let (Some(question), true) = (asked.first(), attributes.len() > 1) {
                // Several attributes sent as given (a lone one as `any`, #394)
                let sent: Vec<_> = question["attributes"].as_object().unwrap().keys().collect();
                if sent.len() != attributes.len() {
                    differ.push(format!("{}: sent {}", case["name"], question));
                }
            }
        }
    }
    assert!(differ.is_empty(), "{differ:#?}");
}

/// #553's token named `name`.
fn token_of(name: &str) -> LockingScript {
    let v: Value =
        serde_json::from_str(include_str!("vectors/identity_certificate_record_553.json")).unwrap();
    let case = v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap();
    LockingScript::from_hex(case["locking_script"].as_str().unwrap()).unwrap()
}

/// #737's `proven_spend`: a proven transaction spending `<byte>`x32:0 into
/// `lock`, its BUMP a lone leaf at offset 0 at 900, by this crate's writer.
fn proven_spend(byte: &str, lock: LockingScript) -> Vec<u8> {
    let mut input = TransactionInput::new(byte.repeat(32).parse().unwrap(), 0);
    input.set_unlocking_script(UnlockingScript::from_hex("").unwrap());
    let mut tx = Transaction::new();
    tx.add_input(input).unwrap();
    tx.add_output(TransactionOutput::new(1, lock)).unwrap();
    let path = MerklePath::new(900, vec![vec![MerklePathLeaf::new_txid(0, tx.id())]]).unwrap();
    let mut beef = Beef::new();
    let index = beef.merge_bump(path);
    beef.merge_raw_tx(tx.to_binary(), Some(index))
        .expect("the bytes are one transaction");
    beef.to_binary().expect("the BEEF is writable")
}

/// `Wallet.ts:1012` filters by the validated key: a padded or upper-case
/// asked key keeps its subject's certificate at both by-key doors, the
/// question carrying the text as given; until #818b the padded key dropped it.
#[tokio::test]
async fn a_padded_or_upper_case_key_keeps_its_subjects_certificate_818b() {
    let output = || OutputListItem {
        beef: proven_spend("11", token_of("reference")),
        output_index: 0,
        context: None,
        txid: None,
    };
    let (client, _) = client_answering(vec![output()]);
    let all = client.query(IdentityQuery::default()).await.unwrap();
    assert_eq!(all.len(), 1);
    let subject = all[0].identity.identity_key.clone();
    let vector = vector();
    for cell in vector["subjects"].as_array().unwrap() {
        // The recorded cell's form of the token's own subject
        let asked = match cell["name"].as_str().unwrap() {
            "subject_padded_spaces" => format!("  {subject}  "),
            "subject_upper_case" => subject.to_uppercase(),
            other => panic!("no cell {other}"),
        };
        assert_eq!(cell["kept"], 1);
        let (client, sent) = client_answering(vec![output()]);
        let found = client.resolve_by_identity_key(&asked, false).await.unwrap();
        assert_eq!(found.len(), 1, "{}: resolve_by_identity_key", cell["name"]);
        assert_eq!(found[0].identity_key, subject);
        assert_eq!(sent.lock().unwrap()[0]["identityKey"], asked.as_str());
        let (client, _) = client_answering(vec![output()]);
        let certificates = client.discover_certificates(&asked).await.unwrap();
        assert_eq!(
            certificates.len(),
            1,
            "{}: discover_certificates",
            cell["name"]
        );
    }
}
