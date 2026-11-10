//! #603: the accepting edges of a wallet's code-5 body
//! (`src/wallet/substrates/http_json/review_actions.rs`), read as the
//! reference's `HTTPWalletJSON` reads them (`ts-stack@edf6e03`
//! `packages/sdk/src/wallet/substrates/HTTPWalletJSON.ts:126-130`,
//! `:156-170`, `:204-242`; `WalletResultValidation.ts:211-214`, `:971-976`,
//! `:1013-1031`), against `wallet_http_json_review_actions_603.json` (nine
//! bodies, Node v22.18.0, `tests/support/wallet_http_json_review_actions_603.mjs`),
//! each served through wiremock on its own port to the call the reference
//! was asked. The shared result validator (`result_values::review`) runs
//! before the module's own decoding and refuses in the same words, so only
//! an accepting edge tells the module's bounds apart: 1001 send results,
//! 1001 review results, a send result `unproven`, 100000 change outpoints,
//! and a competing txid of 64 non-hex or of short hex.
//!
//! A large list is a marker both sides expand alike (`expand`), and every
//! array longer than four entries in an outcome is compared as
//! `{length, head, tail}` (`project`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(all(feature = "wallet", feature = "http"))]

use bsv_rs::primitives::{from_hex, to_hex};
use bsv_rs::wallet::substrates::HttpWalletJson;
use bsv_rs::wallet::*;
use bsv_rs::Error;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[derive(Deserialize)]
struct Vector {
    source: String,
    node: String,
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
        "vectors/wallet_http_json_review_actions_603.json"
    ))
    .unwrap()
}

fn case(name: &str) -> Case {
    vector().cases.into_iter().find(|c| c.name == name).unwrap()
}

/// #327's competing transaction and its BEEF.
fn competing() -> (String, Vec<u8>) {
    let v: Value =
        serde_json::from_str(include_str!("vectors/identity_revocation_checks_327.json")).unwrap();
    let c = &v["competing"];
    (
        c["txid"].as_str().unwrap().to_string(),
        from_hex(c["beef"].as_str().unwrap()).unwrap(),
    )
}

const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// `T(i)`: `i + 1` as 64 hex digits, zero padded.
fn t(i: usize) -> String {
    format!("{:064x}", i + 1)
}

/// The recorder's markers, expanded as it expands them.
fn expand(value: &Value) -> Value {
    let (x, beef) = competing();
    match value {
        Value::String(s) => {
            let count = |prefix: &str| s.strip_prefix(prefix).map(|n| n.parse::<usize>().unwrap());
            if let Some(n) = count("@sendwith:") {
                json!((0..n).map(t).collect::<Vec<_>>())
            } else if let Some(n) = count("@sends:") {
                let mut txids: Vec<String> = (0..n - 1).map(t).collect();
                txids.push(A.to_string());
                json!(txids
                    .iter()
                    .map(|txid| json!({ "txid": txid, "status": "failed" }))
                    .collect::<Vec<_>>())
            } else if let Some(n) = count("@reviews:") {
                let mut txids: Vec<String> = (0..n - 1).map(t).collect();
                txids.push(A.to_string());
                json!(txids
                    .iter()
                    .map(|txid| json!({ "txid": txid, "status": "success" }))
                    .collect::<Vec<_>>())
            } else if let Some(n) = count("@change:X:") {
                json!((0..n).map(|i| format!("{x}.{i}")).collect::<Vec<_>>())
            } else if s == "$BEEF" {
                json!(beef)
            } else {
                value.clone()
            }
        }
        Value::Array(items) => Value::Array(items.iter().map(expand).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), expand(v)))
                .collect::<Map<_, _>>(),
        ),
        other => other.clone(),
    }
}

/// An array longer than four entries as `{length, head, tail}`.
fn project(value: &Value) -> Value {
    match value {
        Value::Array(items) => {
            let items: Vec<Value> = items.iter().map(project).collect();
            if items.len() > 4 {
                json!({
                    "length": items.len(),
                    "head": items[..2],
                    "tail": items[items.len() - 2..],
                })
            } else {
                Value::Array(items)
            }
        }
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), project(v)))
                .collect::<Map<_, _>>(),
        ),
        other => other.clone(),
    }
}

/// The refusal as the recorder writes the reference's `WERR_REVIEW_ACTIONS`.
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

/// The substrate's answer to the case's call, projected as the recorder
/// projects the reference's.
async fn answer(c: &Case) -> Value {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/{}", c.call)))
        .respond_with(ResponseTemplate::new(c.status).set_body_json(expand(&c.body)))
        .expect(1)
        .mount(&server)
        .await;
    let wallet = HttpWalletJson::new(Some("example.com".into()), Some(server.uri())).unwrap();
    let args = expand(&c.args);
    let outcome = match c.call.as_str() {
        "signAction" => wallet
            .sign_action(serde_json::from_value(args).unwrap(), None)
            .await
            .map(|r| (r.txid, r.tx)),
        "createAction" => wallet
            .create_action(serde_json::from_value(args).unwrap(), None)
            .await
            .map(|r| (r.txid, r.tx)),
        other => panic!("no call {other}"),
    };
    project(&match outcome {
        Ok((txid, tx)) => json!({ "answered": {
            "txid": txid.map(|t| to_hex(&t)),
            "tx": tx.map(|t| to_hex(&t)),
        } }),
        Err(Error::WalletReviewActions(review)) => json!({ "review": review_json(&review) }),
        Err(Error::WalletError(words)) => json!({ "error": words }),
        Err(other) => json!({ "other": format!("{other:?}") }),
    })
}

/// Each named case answered as the reference answered it; `read` the cases
/// the reference reads, `refused` with the words it refuses in.
async fn the_references(read: &[&str], refused: &[(&str, &str)]) {
    let mut wrong = Vec::new();
    for name in read {
        let c = case(name);
        assert!(
            c.reference.get("review").is_some(),
            "{name}: {}",
            c.reference
        );
        let ours = answer(&c).await;
        if ours != c.reference {
            wrong.push(format!("{name}: {ours}"));
        }
    }
    for (name, words) in refused {
        let c = case(name);
        assert_eq!(c.reference, json!({ "error": words }), "{name}");
        let ours = answer(&c).await;
        if ours != c.reference {
            wrong.push(format!("{name}: {ours}"));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// A: `:247`'s bound (`> MAXIMUM_SEND_WITH_TRANSACTIONS + 1`): 1001 send
/// results read (`validateSendWithResults`, `WalletResultValidation.ts:1013-1031`),
/// 1002 refused before any entry.
#[tokio::test]
async fn a_page_of_1001_send_with_results_is_read_and_1002_refused_603() {
    let c = case("send_with_results_1001");
    assert_eq!(
        c.reference["review"]["sendWithResults"]["length"],
        json!(1001)
    );
    the_references(
        &["send_with_results_1001"],
        &[(
            "send_with_results_1002",
            "Invalid createAction result sendWithResults: expected at most 1001 transaction results",
        )],
    )
    .await;
}

/// B: `:292`'s bound: 1001 review results read (`HTTPWalletJSON.ts:128`),
/// 1002 refused before any entry.
#[tokio::test]
async fn a_page_of_1001_review_results_is_read_and_1002_refused_603() {
    let c = case("review_results_1001");
    assert_eq!(
        c.reference["review"]["reviewActionResults"]["length"],
        json!(1001)
    );
    the_references(
        &["review_results_1001"],
        &[(
            "review_results_1002",
            "Invalid wallet error reviewActionResults",
        )],
    )
    .await;
}

/// C: `:269`'s arm: a send result `unproven` is read
/// (`WalletResultValidation.ts:211-214`, BRC-100 `0100.md:1726`).
#[tokio::test]
async fn a_send_with_result_unproven_is_read_603() {
    let c = case("send_with_unproven");
    assert_eq!(
        c.reference["review"]["sendWithResults"][0]["status"],
        json!("unproven")
    );
    the_references(&["send_with_unproven"], &[]).await;
}

/// D: `:180`'s bound (`optionalArray`, `WalletResultValidation.ts:971-976`):
/// 100000 change outpoints read, 100001 refused.
#[tokio::test]
async fn a_no_send_change_of_100000_outpoints_is_read_and_100001_refused_603() {
    let c = case("no_send_change_100000");
    assert_eq!(
        c.reference["review"]["noSendChange"]["length"],
        json!(100_000)
    );
    the_references(
        &["no_send_change_100000"],
        &[(
            "no_send_change_100001",
            "Invalid createAction result noSendChange: expected at most 100000 entries",
        )],
    )
    .await;
}

/// E: `:385`'s `&&`: a competing txid of 64 non-hex characters, or of short
/// hex, refused at its index (`HTTPWalletJSON.ts:166-170`).
#[tokio::test]
async fn a_competing_txid_of_64_non_hex_or_short_hex_is_refused_at_its_index_603() {
    let words = "Invalid wallet error reviewActionResults[0].competingTxs[0]";
    the_references(
        &[],
        &[
            ("competing_txid_64_non_hex", words),
            ("competing_txid_short_hex", words),
        ],
    )
    .await;
}

#[tokio::test]
async fn the_603_vector_is_the_references_and_its_count_is_pinned() {
    let v = vector();
    assert_eq!(v.source, "ts-stack@edf6e03");
    assert_eq!(v.node, "v22.18.0");
    assert_eq!(v.cases.len(), 9);
    let mut wrong = Vec::new();
    for c in &v.cases {
        let ours = answer(c).await;
        if ours != c.reference {
            wrong.push(format!("{}: {ours}", c.name));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}
