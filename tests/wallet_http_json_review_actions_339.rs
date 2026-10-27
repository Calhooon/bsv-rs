//! `HttpWalletJson` reads a wallet's code-5 body as the reference's
//! `HTTPWalletJSON` does (#339; `ts-stack@edf6e03`
//! `packages/sdk/src/wallet/substrates/HTTPWalletJSON.ts:117-241`): a 400
//! body with its `reviewActionResults` is `Error::WalletReviewActions`
//! carrying the reference's five members, each member validated and a
//! malformed one refused in the reference's words, against
//! `wallet_http_json_review_actions_339.json` (41 bodies, Node v22.18.0,
//! `tests/support/wallet_http_json_review_actions_339.mjs`), each served
//! through wiremock to the call the reference was asked; two are 200
//! answers whose `tx` the success path reads as the error path does. A body without
//! results is the `WalletRefusal` of before; the identity revocation's
//! double-spend retry runs over the substrate, #327's recording wallet
//! answering signAction through it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(all(feature = "identity", feature = "http"))]

use bsv_rs::identity::{IdentityClient, IdentityClientConfig};
use bsv_rs::overlay::{
    AdmittanceInstructions, LookupAnswer, LookupQuestion, LookupResolver, LookupResolverConfig,
    NetworkPreset, OutputListItem, OverlayBroadcastFacilitator, OverlayLookupFacilitator, Steak,
    TaggedBEEF,
};
use bsv_rs::primitives::{from_hex, to_hex};
use bsv_rs::transaction::Transaction;
use bsv_rs::wallet::substrates::HttpWalletJson;
use bsv_rs::wallet::*;
use bsv_rs::{Error, WalletRefusalClass};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[path = "support/identity_reveal_wallet.rs"]
mod identity_reveal_wallet;
use identity_reveal_wallet::Counting;

#[derive(Deserialize)]
struct Vector {
    cases: Vec<Case>,
}

#[derive(Deserialize, Clone)]
struct Case {
    name: String,
    call: String,
    args: Value,
    status: u16,
    body: Value,
    reference: Value,
}

fn vector() -> Vector {
    serde_json::from_str(include_str!(
        "vectors/wallet_http_json_review_actions_339.json"
    ))
    .unwrap()
}

fn case(name: &str) -> Case {
    let v = vector();
    v.cases.into_iter().find(|c| c.name == name).unwrap()
}

/// #327's revocation witnesses: the competing transaction and its BEEF.
fn revocation() -> Value {
    serde_json::from_str(include_str!("vectors/identity_revocation_checks_327.json")).unwrap()
}

fn competing_beef() -> Vec<u8> {
    from_hex(revocation()["competing"]["beef"].as_str().unwrap()).unwrap()
}

/// The body with the competing BEEF where it holds `$BEEF`, in the
/// historical object form (`{"0": .., "1": ..}`) where it holds
/// `$BEEF_OBJECT`, and each byte an integral float (`1.0`) where it holds
/// `$BEEF_FLOAT`.
fn with_beef(body: &Value, beef: &[u8]) -> Value {
    match body {
        Value::String(s) if s == "$BEEF" => json!(beef),
        Value::String(s) if s == "$BEEF_OBJECT" => Value::Object(
            (beef.iter().enumerate())
                .map(|(i, b)| (i.to_string(), json!(b)))
                .collect(),
        ),
        Value::String(s) if s == "$BEEF_FLOAT" => {
            Value::Array(beef.iter().map(|b| json!(f64::from(*b))).collect())
        }
        Value::Array(items) => Value::Array(items.iter().map(|v| with_beef(v, beef)).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), with_beef(v, beef)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// The cases where this crate reads otherwise, each with its reason; the
/// count is pinned.
const DIVERGENT: [(&str, &str); 3] = [
    (
        "create_tx_outputs_not_requested",
        "the reference's checks of a returned tx against the request \
         (validateCreateActionTransaction) are not ported; the success path makes none either",
    ),
    (
        "review_at_status_500",
        "a class's body is WalletRefusal at any status (#137); the reference types a 400 alone",
    ),
    (
        "no_results",
        "a code-5 body without results is the class refusal of before; the reference \
         refuses it as a malformed envelope",
    ),
];

/// The substrate's answer to the case's call, as the vector writes the
/// reference's: the review's five members and message, a refusal's words,
/// or anything else by its debug form.
async fn answer(c: &Case) -> Value {
    let server = MockServer::start().await;
    let body = with_beef(&c.body, &competing_beef());
    Mock::given(method("POST"))
        .and(path(format!("/{}", c.call)))
        .respond_with(ResponseTemplate::new(c.status).set_body_json(body))
        .expect(1)
        .mount(&server)
        .await;
    let wallet = HttpWalletJson::new(Some("example.com".into()), Some(server.uri())).unwrap();
    let outcome = match c.call.as_str() {
        "signAction" => wallet
            .sign_action(serde_json::from_value(c.args.clone()).unwrap(), None)
            .await
            .map(|r| (r.txid, r.tx)),
        "createAction" => wallet
            .create_action(serde_json::from_value(c.args.clone()).unwrap(), None)
            .await
            .map(|r| (r.txid, r.tx)),
        "listActions" => wallet
            .list_actions(serde_json::from_value(c.args.clone()).unwrap(), None)
            .await
            .map(|_| (None, None)),
        other => panic!("no call {other}"),
    };
    match outcome {
        Ok((txid, tx)) => json!({ "answered": {
            "txid": txid.map(|t| to_hex(&t)),
            "tx": tx.map(|t| to_hex(&t)),
        } }),
        Err(Error::WalletReviewActions(review)) => json!({ "review": review_json(&review) }),
        Err(Error::WalletError(words)) => json!({ "error": words }),
        Err(other) => json!({ "other": format!("{other:?}") }),
    }
}

/// The refusal as the script writes the reference's `WERR_REVIEW_ACTIONS`.
fn review_json(r: &ReviewActionsRefusal) -> Value {
    let results: Vec<Value> = r
        .review_action_results
        .iter()
        .map(|x| {
            let mut v = json!({
                "txid": to_hex(&x.txid),
                "status": serde_json::to_value(x.status).unwrap(),
            });
            if let Some(txs) = &x.competing_txs {
                v["competingTxs"] = json!(txs.iter().map(|t| to_hex(t)).collect::<Vec<_>>());
            }
            if let Some(beef) = &x.competing_beef {
                v["competingBeef"] = json!(to_hex(beef));
            }
            v
        })
        .collect();
    json!({
        "message": r.message,
        "reviewActionResults": results,
        "sendWithResults": serde_json::to_value(&r.send_with_results).unwrap(),
        "txid": r.txid.map(|t| to_hex(&t)),
        "tx": r.tx.as_ref().map(|t| to_hex(t)),
        "noSendChange": r.no_send_change.as_ref().map(|o| {
            o.iter().map(|o| format!("{}.{}", to_hex(&o.txid), o.vout)).collect::<Vec<_>>()
        }),
    })
}

#[tokio::test]
async fn each_code_5_body_is_read_as_the_reference_reads_it() {
    let v = vector();
    assert_eq!(v.cases.len(), 41);
    let mut divergent = 0;
    for c in &v.cases {
        let ours = answer(c).await;
        if let Some((_, reason)) = DIVERGENT.iter().find(|(n, _)| *n == c.name) {
            divergent += 1;
            assert_ne!(
                ours, c.reference,
                "{}: no longer divergent ({reason})",
                c.name
            );
            continue;
        }
        assert_eq!(ours, c.reference, "{}", c.name);
    }
    assert_eq!(divergent, DIVERGENT.len());
}

#[tokio::test]
async fn a_review_body_answered_to_sign_action_carries_its_five_members() {
    let c = case("sign_double_spend");
    let competing = revocation()["competing"]["txid"]
        .as_str()
        .unwrap()
        .to_string();
    let Value::Object(ours) = answer(&c).await else {
        panic!()
    };
    let review = &ours["review"];
    assert_eq!(
        review["message"],
        "Undelayed createAction or signAction results require review."
    );
    assert_eq!(review["txid"], "aa".repeat(32));
    assert_eq!(review["reviewActionResults"][0]["status"], "doubleSpend");
    assert_eq!(
        review["reviewActionResults"][0]["competingTxs"],
        json!([competing])
    );
    assert_eq!(
        review["reviewActionResults"][0]["competingBeef"],
        json!(to_hex(&competing_beef()))
    );
    assert_eq!(review["reviewActionResults"][1]["status"], "serviceError");
    assert_eq!(
        review["sendWithResults"],
        json!([
            { "txid": "bb".repeat(32), "status": "failed" },
            { "txid": "aa".repeat(32), "status": "sending" },
        ])
    );
    // all five on createAction: the txid, its BEEF and a change outpoint
    let c = case("create_five_members");
    let ours = answer(&c).await;
    assert_eq!(ours["review"]["tx"], json!(to_hex(&competing_beef())));
    assert_eq!(
        ours["review"]["noSendChange"],
        json!([format!("{competing}.0")])
    );
    assert_eq!(ours, c.reference);
}

/// The review's finding: a `tx` and a `competingBeef` in the historical
/// object form are read as their bytes, as the reference's
/// `normalizeBRC100WalletByteFields` reads them before the error is read
/// (`BRC100ByteEncoding.ts:52-71`, `HTTPWalletJSON.ts:326-328`).
#[tokio::test]
async fn a_byte_field_in_the_historical_object_form_is_read_as_its_bytes() {
    let beef = json!(to_hex(&competing_beef()));
    let mut wrong = Vec::new();
    for (name, read) in [
        ("create_tx_object_form", "/review/tx"),
        (
            "competing_beef_object_form",
            "/review/reviewActionResults/0/competingBeef",
        ),
    ] {
        let c = case(name);
        assert_eq!(c.reference.pointer(read), Some(&beef), "{name}");
        let ours = answer(&c).await;
        if ours != c.reference {
            wrong.push(format!("{name}: {ours}"));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// The re-review's finding: a 200 createAction or signAction answer's `tx`
/// in the historical object form, or with its bytes written as integral
/// floats (`1.0`), is read as its bytes, as the reference's success path
/// normalizes it before `validateWalletResult` (`HTTPWalletJSON.ts:322-341`,
/// `BRC100ByteEncoding.ts:52-86`): one reader for both paths.
#[tokio::test]
async fn a_success_tx_in_the_object_form_or_integral_floats_is_read_as_its_bytes() {
    let competing = revocation()["competing"]["txid"].clone();
    let beef = json!(to_hex(&competing_beef()));
    let mut wrong = Vec::new();
    for name in [
        "create_success_tx_object_form",
        "sign_success_tx_integral_floats",
    ] {
        let c = case(name);
        assert_eq!(c.status, 200, "{name}");
        assert_eq!(
            c.reference,
            json!({ "answered": { "txid": competing, "tx": beef } }),
            "{name}"
        );
        let ours = answer(&c).await;
        if ours != c.reference {
            wrong.push(format!("{name}: {ours}"));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

#[tokio::test]
async fn a_malformed_member_is_refused_in_the_references_words() {
    for (name, words) in [
        ("review_result_txid_unknown", "Invalid wallet error reviewActionResults[0].txid"),
        ("competing_beef_without_the_txid", "Invalid wallet error reviewActionResults[0].competingBeef"),
        ("send_with_results_absent", "Invalid wallet error sendWithResults"),
        ("sign_txid_absent", "Invalid signAction result txid: expected the completed signed transaction"),
        ("no_send_change_of_another_tx", "Invalid createAction result noSendChange[0]: expected an outpoint of the returned transaction"),
    ] {
        let c = case(name);
        assert_eq!(c.reference, json!({ "error": words }), "{name}");
        assert_eq!(answer(&c).await, json!({ "error": words }), "{name}");
    }
}

#[tokio::test]
async fn a_code_5_body_without_results_is_the_class_refusal_of_before() {
    let c = case("no_results");
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/signAction"))
        .respond_with(ResponseTemplate::new(400).set_body_json(&c.body))
        .mount(&server)
        .await;
    let wallet = HttpWalletJson::new(Some("example.com".into()), Some(server.uri())).unwrap();
    let error = wallet
        .sign_action(serde_json::from_value(c.args).unwrap(), None)
        .await
        .unwrap_err();
    assert_eq!(
        error,
        Error::WalletRefusal {
            class: WalletRefusalClass::ReviewActions,
            message: "Undelayed createAction or signAction results require review.".to_string(),
        }
    );
}

/// The stated divergence of the parity note: a 400 body whose `code` is
/// absent, `"5"` or `5.5` is read by #137's rule (its class by `name`),
/// where the reference answers `Invalid wallet error envelope`
/// (`HTTPWalletJSON.ts:204-206`).
#[tokio::test]
async fn a_review_body_whose_code_is_not_a_safe_integer_is_the_class_refusal() {
    let c = case("sign_double_spend");
    for code in [None, Some(json!("5")), Some(json!(5.5))] {
        let mut body = with_beef(&c.body, &competing_beef());
        match &code {
            None => drop(body.as_object_mut().unwrap().remove("code")),
            Some(code) => body["code"] = code.clone(),
        }
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/signAction"))
            .respond_with(ResponseTemplate::new(400).set_body_json(&body))
            .mount(&server)
            .await;
        let wallet = HttpWalletJson::new(Some("example.com".into()), Some(server.uri())).unwrap();
        let error = wallet
            .sign_action(serde_json::from_value(c.args.clone()).unwrap(), None)
            .await
            .unwrap_err();
        assert_eq!(
            error,
            Error::WalletRefusal {
                class: WalletRefusalClass::ReviewActions,
                message: "Undelayed createAction or signAction results require review.".to_string(),
            },
            "{code:?}"
        );
    }
}

// The revocation over the substrate: #327's run `double_spend_then_accepted`

struct Lookup(LookupAnswer);

#[async_trait::async_trait(?Send)]
impl OverlayLookupFacilitator for Lookup {
    async fn lookup(
        &self,
        _url: &str,
        _question: &LookupQuestion,
        _timeout_ms: Option<u64>,
    ) -> bsv_rs::Result<LookupAnswer> {
        Ok(self.0.clone())
    }
}

/// Records the txid of each transaction broadcast and admits its spend.
#[derive(Clone, Default)]
struct Ship(Arc<Mutex<Vec<String>>>);

#[async_trait::async_trait(?Send)]
impl OverlayBroadcastFacilitator for Ship {
    async fn send(&self, _url: &str, tagged: &TaggedBEEF) -> bsv_rs::Result<Steak> {
        let tx = Transaction::from_beef(&tagged.beef, None).unwrap();
        self.0.lock().unwrap().push(tx.id());
        let mut steak = HashMap::new();
        steak.insert(
            "tm_identity".to_string(),
            AdmittanceInstructions {
                outputs_to_admit: vec![],
                coins_to_retain: vec![],
                coins_removed: Some(vec![0]),
            },
        );
        Ok(steak)
    }
}

fn hex_of(v: &Value) -> Vec<u8> {
    from_hex(v.as_str().unwrap()).unwrap()
}

#[tokio::test]
async fn the_revocation_retries_a_double_spend_answered_over_the_json_substrate() {
    let v = revocation();
    let r = v["runs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "double_spend_then_accepted")
        .unwrap()
        .clone();
    let competing = v["competing"]["txid"].as_str().unwrap();
    let signed = hex_of(&r["signed_tx"]);
    let spend = Transaction::from_beef(&signed, None).unwrap().id();

    // signAction answered first by the wallet's code-5 body with the
    // competing transaction, then by the signed transaction
    let server = MockServer::start().await;
    let review = json!({
        "isError": true,
        "code": 5,
        "name": "WERR_REVIEW_ACTIONS",
        "message": "Undelayed createAction or signAction results require review.",
        "txid": spend,
        "sendWithResults": [],
        "reviewActionResults": [{
            "txid": spend,
            "status": "doubleSpend",
            "competingTxs": [competing],
            "competingBeef": competing_beef(),
        }],
    });
    Mock::given(method("POST"))
        .and(path("/signAction"))
        .respond_with(ResponseTemplate::new(400).set_body_json(review))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/signAction"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "tx": signed })))
        .with_priority(2)
        .mount(&server)
        .await;

    let mut wallet = Counting::of_scalar(9);
    wallet.signable = Some(SignableTransaction {
        tx: hex_of(&r["signable_tx"]),
        reference: vec![0x52; 8],
    });
    let json = HttpWalletJson::new(Some("example.com".into()), Some(server.uri())).unwrap();
    wallet.sign_via = Some(Arc::new(json));

    let lookup = hex_of(&v["lookups"]["single"]);
    let mut host_overrides = HashMap::new();
    host_overrides.insert(
        "ls_identity".to_string(),
        vec!["http://identity-lookup.invalid".to_string()],
    );
    let resolver = Arc::new(LookupResolver::new(LookupResolverConfig {
        network_preset: NetworkPreset::Local,
        facilitator: Some(Arc::new(Lookup(LookupAnswer::OutputList {
            outputs: vec![OutputListItem {
                beef: lookup,
                output_index: 0,
                context: None,
            }],
        })) as Arc<dyn OverlayLookupFacilitator>),
        slap_trackers: Some(vec![]),
        host_overrides: Some(host_overrides),
        ..Default::default()
    }));
    let ship = Ship::default();
    let config = IdentityClientConfig::default().with_network(NetworkPreset::Local);
    let client = IdentityClient::with_resolver(wallet.clone(), config, resolver)
        .with_broadcast_facilitator(Arc::new(ship.clone()));
    let verdict = client
        .revoke_certificate_revelation(v["serial_number"].as_str().unwrap())
        .await;

    assert_eq!(verdict, Ok(()));
    // the action aborted, the competing transaction broadcast, then the
    // spend made again and broadcast: the reference's calls and broadcasts
    let calls: Vec<&str> = r["calls"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| match c.as_str().unwrap() {
            "getPublicKey" => "get_public_key",
            "createSignature" => "create_signature",
            "verifySignature" => "verify_signature",
            "createAction" => "create_action",
            "signAction" => "sign_action",
            "abortAction" => "abort_action",
            other => panic!("no name for {other}"),
        })
        .collect();
    assert_eq!(wallet.calls(), calls);
    assert_eq!(
        *ship.0.lock().unwrap(),
        r["broadcasts"].as_array().unwrap().clone()
    );
    // both signActions sent over the substrate, each the reference's arguments
    let sent: Vec<Value> = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|q| serde_json::from_slice(&q.body).unwrap())
        .collect();
    assert_eq!(Value::Array(sent), r["signAction"]);
}
