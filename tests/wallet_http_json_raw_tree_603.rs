//! #603: `src/wallet/substrates/result_values/raw_tree.rs`'s survivors of the
//! complete run of 2026-11-04, against the pinned reference's `HTTPWalletJSON`
//! (`ts-stack@edf6e03`, `HTTPWalletJSON.ts:318-335`; the snapshot budgets of
//! `WalletResultValidation.ts:215-219,664-743,765-831`, the byte forms of
//! `BRC100ByteEncoding.ts:32-34` and `WalletResultValidation.ts:524-621`)
//! recorded under Node 22 by `support/http_json_raw_tree_603.mjs` into
//! `vectors/http_json_raw_tree_603.json`.
//! The fixture owns the reference's verdicts, values and words; every request
//! goes to a wiremock ephemeral port. Large bodies expand a saved recipe.
#![cfg(all(feature = "wallet", feature = "http"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: tests

#[allow(dead_code)]
#[path = "support/fixtures/wallet_json.rs"]
mod wallet_json;

use base64::{engine::general_purpose, Engine};
use bsv_rs::wallet::substrates::HttpWalletJson;
use bsv_rs::Error;
use serde::Deserialize;
use serde_json::Value;
use std::sync::{mpsc, LazyLock};
use std::time::Duration;
use wallet_json::FixtureJson;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Case {
    name: String,
    call: String,
    args: Value,
    body_text: String,
    expansion: Option<Expansion>,
    reference: Value,
}

#[derive(Deserialize)]
struct Expansion {
    marker: String,
    kind: String,
    length: usize,
    item: Value,
}

impl Case {
    /// The recipe expanded as the recorder expands it: `array` the item
    /// `length` times, `index_object` `{"0":item,..,"N-1":item}`.
    fn body(&self) -> String {
        let Some(e) = &self.expansion else {
            return self.body_text.clone();
        };
        let item = serde_json::to_string(&e.item).unwrap();
        let entries: Vec<String> = match e.kind.as_str() {
            "array" => vec![item; e.length],
            "index_object" => (0..e.length).map(|i| format!("\"{i}\":{item}")).collect(),
            other => panic!("unknown expansion {other}"),
        };
        let (open, close) = if e.kind == "array" {
            ("[", "]")
        } else {
            ("{", "}")
        };
        self.body_text
            .replace(&e.marker, &format!("{open}{}{close}", entries.join(",")))
    }
}

static CASES: LazyLock<Vec<Case>> = LazyLock::new(|| {
    #[derive(Deserialize)]
    struct Vector {
        source: String,
        node: String,
        cases: Vec<Case>,
    }
    let vector: Vector =
        serde_json::from_str(include_str!("vectors/http_json_raw_tree_603.json")).unwrap();
    assert_eq!(vector.source, "ts-stack@edf6e03");
    assert!(vector.node.starts_with("v22."));
    assert_eq!(vector.cases.len(), 11);
    vector.cases
});

fn case(name: &str) -> &'static Case {
    CASES
        .iter()
        .find(|c| c.name == name)
        .unwrap_or_else(|| panic!("no recorded case {name}"))
}

/// The liveness bound on one answer. Every honest call here answers in
/// milliseconds; a mutant of the raw tree's cursor that never advances spins,
/// and a spinning call would hold its test binary open, so the case runs on a
/// thread of its own and no answer within the bound is a failure (the process
/// exit ends the thread).
const ANSWER_BOUND: Duration = Duration::from_secs(20);

/// This crate's answer to the case, as the value the recorder picked.
fn answer(c: &'static Case) -> Result<Value, Error> {
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _ = sender.send(runtime.block_on(ask(c)));
    });
    receiver
        .recv_timeout(ANSWER_BOUND)
        .unwrap_or_else(|_| panic!("{}: no answer within {ANSWER_BOUND:?}", c.name))
}

async fn ask(c: &Case) -> Result<Value, Error> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/{}", c.call)))
        .respond_with(ResponseTemplate::new(200).set_body_raw(c.body(), "application/json"))
        .expect(1)
        .mount(&server)
        .await;
    let wallet = HttpWalletJson::new(Some("fixtures.invalid".into()), Some(server.uri())).unwrap();
    match c.call.as_str() {
        "getHeight" => wallet.get_height(None).await.map(Value::from),
        "getVersion" => wallet.get_version(None).await.map(Value::from),
        "encrypt" => wallet
            .encrypt(FixtureJson::from_fixture(c.args.clone()), None)
            .await
            .map(|r| Value::from(r.ciphertext)),
        "createAction" => wallet
            .create_action(FixtureJson::from_fixture(c.args.clone()), None)
            .await
            .map(|r| Value::from(r.signable_transaction.unwrap().reference)),
        other => panic!("unknown call {other}"),
    }
}

/// The recorded verdict: an accepted case's value, a refused case's words.
fn agrees(name: &str) {
    let c = case(name);
    let ours = answer(c);
    match (&ours, c.reference["accepted"] == true) {
        (Ok(value), true) => assert_eq!(value, &c.reference["value"], "{name}"),
        (Err(Error::WalletError(words)), false) => {
            assert_eq!(
                Some(words.as_str()),
                c.reference["error"].as_str(),
                "{name}"
            )
        }
        _ => panic!("{name}: {ours:?}; reference {}", c.reference),
    }
}

// C1. A dense array of bytes is counted as copied bytes, not nodes
// (`WalletResultValidation.ts:726-740` precede `:741-743`), so 1,000,001 of
// them pass the 1,000,000-entry bound.
#[test]
fn a_dense_byte_array_past_the_node_limit_is_bytes_not_nodes() {
    agrees("c1_dense_byte_array_past_the_node_limit");
}

// C2. 300 is no byte (`isByte`, `BRC100ByteEncoding.ts:32-34`): the array is
// walked as values and refused by its length.
#[test]
fn an_integral_value_above_255_is_not_a_byte() {
    agrees("c2_integral_value_above_255");
}

// C3. 4 + 999,999 properties pass 1,000,002 (`:770-772`); 999,997 entries,
// one fewer, are the bound itself.
#[test]
fn a_non_byte_array_one_property_past_the_budget_is_refused() {
    agrees("c3_non_byte_array_one_property_past");
    agrees("c3_non_byte_array_at_the_property_bound");
}

// C4. An index-keyed object under a name that is not one of the seventeen
// byte names counts its keys (`:813-814`).
#[test]
fn an_index_keyed_object_outside_the_byte_names_counts_its_keys() {
    agrees("c4_index_keyed_object_outside_the_byte_names");
}

// C5. An escaped quote does not end the string token.
#[test]
fn an_escaped_quote_does_not_end_a_string() {
    agrees("c5_escaped_quote");
}

// C6. The historical byte object `{"0":1,"1":2}` under a byte name, beside a
// nonfinite extra (so the typed and the `Value` readings both fail and the
// raw tree is written), is read as the array `[1, 2]`.
#[test]
fn a_historical_byte_object_is_written_as_an_array_on_the_raw_path() {
    agrees("c6_historical_byte_object_raw_path");
}

// C7. A byte field's name does not exempt its object from the unsafe-key
// check (`:578`, then `:818`).
#[test]
fn a_byte_field_name_does_not_shield_an_unsafe_key() {
    agrees("c7_byte_field_name_unsafe_key");
}

// C8. On the raw path a nested array keeps its brackets and the integral
// float `1000.0` is read as the integer 1000.
#[test]
fn nested_arrays_keep_their_brackets_on_the_raw_path() {
    agrees("c8_nested_arrays_raw_path");
}

// C10. A signable reference with trailing bits (`AR==`) passes the
// reference's base64 grammar (`WalletResultValidation.ts:1443-1449`); on the
// raw path this crate re-encodes it, and the bytes are the reference's text's.
#[test]
fn a_trailing_bits_signable_reference_is_reencoded_on_the_raw_path() {
    let c = case("c10_trailing_bits_reference_raw_path");
    assert_eq!(c.reference["accepted"], true);
    let text = c.reference["value"].as_str().unwrap();
    let lenient = general_purpose::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        general_purpose::GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
    );
    let expected = lenient.decode(text).unwrap();
    assert_eq!(expected, vec![1]);
    let ours = answer(c).unwrap();
    assert_eq!(ours, Value::from(expected));
}

// C11. `-0` is a byte (`Number.isInteger(-0)`), written 0 on the raw path.
#[test]
fn a_negative_zero_byte_is_written_as_zero_on_the_raw_path() {
    agrees("c11_negative_zero_byte_raw_path");
}
