//! #408's four classes, recorded from HTTPWalletJSON at ts-stack@edf6e03
//! under Node 22. The fixture owns the reference's words. Every request
//! goes to a wiremock ephemeral port. Large bounds expand a saved recipe.
#![cfg(all(feature = "wallet", feature = "http"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: tests

#[allow(dead_code)]
#[path = "support/fixtures/wallet_json.rs"]
mod wallet_json;

use bsv_rs::wallet::substrates::HttpWalletJson;
use bsv_rs::Error;
use serde::Deserialize;
use serde_json::Value;
use wallet_json::FixtureJson;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Case {
    name: String,
    group: String,
    call: String,
    args: Value,
    body_text: String,
    expansion: Option<Expansion>,
    reference: Value,
}

#[derive(Deserialize)]
struct Expansion {
    marker: String,
    length: usize,
    #[serde(default)]
    array: bool,
    item: Option<Value>,
}

impl Expansion {
    fn text(&self) -> String {
        if self.array {
            serde_json::to_string(&vec![self.item.clone().unwrap(); self.length]).unwrap()
        } else {
            "x".repeat(self.length)
        }
    }
}

fn cases() -> Vec<Case> {
    #[derive(Deserialize)]
    struct Vector {
        source: String,
        node: String,
        cases: Vec<Case>,
    }
    let vector =
        serde_json::from_str::<Vector>(include_str!("vectors/http_json_result_values_408.json"))
            .unwrap();
    assert_eq!(vector.source, "ts-stack@edf6e03");
    assert!(vector.node.starts_with("v22."));
    vector.cases
}

async fn call(wallet: &HttpWalletJson, c: &Case) -> Result<(), Error> {
    macro_rules! invoke {
        ($method:ident) => {
            wallet
                .$method(FixtureJson::from_fixture(c.args.clone()), None)
                .await
                .map(|_| ())
        };
    }
    match c.call.as_str() {
        "createAction" => invoke!(create_action),
        "signAction" => invoke!(sign_action),
        "abortAction" => invoke!(abort_action),
        "listActions" => invoke!(list_actions),
        "internalizeAction" => invoke!(internalize_action),
        "listOutputs" => invoke!(list_outputs),
        "relinquishOutput" => invoke!(relinquish_output),
        "acquireCertificate" => invoke!(acquire_certificate),
        "listCertificates" => invoke!(list_certificates),
        "proveCertificate" => invoke!(prove_certificate),
        "relinquishCertificate" => invoke!(relinquish_certificate),
        "discoverByIdentityKey" => invoke!(discover_by_identity_key),
        "discoverByAttributes" => invoke!(discover_by_attributes),
        "getPublicKey" => invoke!(get_public_key),
        "encrypt" => invoke!(encrypt),
        "decrypt" => invoke!(decrypt),
        "createHmac" => invoke!(create_hmac),
        "verifyHmac" => invoke!(verify_hmac),
        "createSignature" => invoke!(create_signature),
        "verifySignature" => invoke!(verify_signature),
        "revealCounterpartyKeyLinkage" => invoke!(reveal_counterparty_key_linkage),
        "revealSpecificKeyLinkage" => invoke!(reveal_specific_key_linkage),
        "getHeaderForHeight" => invoke!(get_header),
        "getHeight" => wallet.get_height(None).await.map(|_| ()),
        "getNetwork" => wallet.get_network(None).await.map(|_| ()),
        "getVersion" => wallet.get_version(None).await.map(|_| ()),
        "isAuthenticated" => wallet.is_authenticated(None).await.map(|_| ()),
        "waitForAuthentication" => wallet.wait_for_authentication(None).await.map(|_| ()),
        other => panic!("unknown call {other}"),
    }
}

async fn answer(c: &Case) -> Result<(), Error> {
    let body = match &c.expansion {
        Some(e) => c.body_text.replace(&e.marker, &e.text()),
        None => c.body_text.clone(),
    };
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/{}", c.call)))
        .respond_with(ResponseTemplate::new(200).set_body_raw(body, "application/json"))
        .expect(1)
        .mount(&server)
        .await;
    let wallet = HttpWalletJson::new(Some("fixtures.invalid".into()), Some(server.uri())).unwrap();
    call(&wallet, c).await
}

async fn check(group: &str) {
    let cases: Vec<_> = cases().into_iter().filter(|c| c.group == group).collect();
    let (count, accepted) = match group {
        "hmac" => (6, 1),
        "signature" => (19, 4),
        "containers" => (249, 29),
        "certificate" => (113, 22),
        _ => panic!("unknown group {group}"),
    };
    assert_eq!(cases.len(), count);
    assert_eq!(
        cases
            .iter()
            .filter(|c| c.reference["accepted"] == true)
            .count(),
        accepted
    );
    let mut mismatches = Vec::new();
    for c in cases {
        let ours = answer(&c).await;
        let matches = match &ours {
            Ok(()) => c.reference["accepted"] == true,
            Err(Error::WalletError(words)) => c.reference["error"].as_str() == Some(words),
            _ => false,
        };
        if !matches {
            mismatches.push(format!("{}: {ours:?}; reference {}", c.name, c.reference));
        }
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}

#[tokio::test]
async fn hmac_lengths_are_refused_in_the_references_words() {
    check("hmac").await;
}

#[tokio::test]
async fn signatures_require_canonical_der_and_at_most_72_bytes() {
    check("signature").await;
}

#[tokio::test]
async fn null_and_wrong_containers_are_never_absent_optional_fields() {
    check("containers").await;
}

#[tokio::test]
async fn every_certificate_result_requires_canonical_encoding_and_the_size_bound() {
    check("certificate").await;
}

fn case_491(name: &str) -> Case {
    let name = format!("listActions_{name}");
    cases()
        .into_iter()
        .find(|c| c.group == "unsigned_491" && c.name == name)
        .unwrap_or_else(|| panic!("no recorded case {name}"))
}

const STRICT_491: &str = "Invalid listActions result actions[1].inputs[0].unlockingScript: \
                          expected the explicitly requested unlocking script";

#[tokio::test]
async fn an_unsigned_actions_input_may_omit_its_unlocking_script_as_the_reference_wallet_answers() {
    // #491, bsv-wallet-cli#371's fixture 145: the reference wallet answers an
    // unsigned action's input with no unlockingScript (listActionsIdb.ts:77-91
    // at ts-stack edf6e03) and the reference validator refuses its own wallet's
    // page (WalletResultValidation.ts:2027-2035): the divergence, stated. The
    // vector keeps the reference's refusal; this crate accepts the page.
    let c = case_491("unsigned_without_unlocking_script");
    assert_eq!(c.reference["error"], STRICT_491);
    assert_eq!(answer(&c).await, Ok(()));
    // The fixture's own one-byte inputDescription stays R51's refusal here:
    // the reference's second refusal, recorded where a script is supplied.
    let c = case_491("unsigned_fixture_145_description");
    assert_eq!(c.reference["error"], STRICT_491);
    let r51 = case_491("unsigned_fixture_145_description_with_script");
    let words = r51.reference["error"].as_str().unwrap();
    assert!(words.ends_with("inputs[0].inputDescription: expected 5\u{2013}2000 UTF-8 bytes"));
    assert_eq!(answer(&c).await, Err(Error::WalletError(words.into())));
}

#[tokio::test]
async fn the_strict_rule_stays_for_every_other_status_and_returns_on_the_upstreams_answer() {
    // #491 relaxes R56 for an unsigned action's input alone; ts-stack #1451
    // asks the reference which side moves, and strictness returns on the
    // upstream's answer: the unsigned case is then judged with the rest below.
    // The signed statuses unprocessed, nonfinal and failed are the [D] residue.
    let cases: Vec<_> = cases()
        .into_iter()
        .filter(|c| c.group == "unsigned_491")
        .collect();
    assert_eq!(cases.len(), 13);
    let mut mismatches = Vec::new();
    for c in &cases {
        if c.name.ends_with("unsigned_without_unlocking_script")
            || c.name.ends_with("unsigned_fixture_145_description")
        {
            continue;
        }
        let ours = answer(c).await;
        let matches = match &ours {
            Ok(()) => c.reference["accepted"] == true,
            Err(Error::WalletError(words)) => c.reference["error"].as_str() == Some(words),
            _ => false,
        };
        if !matches {
            mismatches.push(format!("{}: {ours:?}; reference {}", c.name, c.reference));
        }
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}
