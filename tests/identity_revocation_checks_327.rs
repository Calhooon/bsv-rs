//! The identity revocation authenticates the lookup output, spends the
//! matching one at its index, aborts a failed action and retries a double
//! spend as the reference does (#327; `ts-stack@edf6e03`
//! `packages/sdk/src/identity/IdentityClient.ts:705-950`,
//! `overlay-tools/withDoubleSpendRetry.ts`). The reference's witnesses
//! (`vectors/identity_revocation_checks_327.json`, Node v22.18.0,
//! `tests/support/identity_wallet_calls_318.mjs revocation-checks`) carry,
//! for each lookup the script answered, the verdict, the wallet calls in
//! order, the createAction, signAction and abortAction arguments and the
//! txids broadcast; here the same lookups are answered by the test, the
//! recording wallet (#318's) answers createAction with the reference's
//! signable transaction and signAction from the run's answers, and the
//! `tm_identity` broadcasts go through a facilitator that records them.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(feature = "identity")]

use bsv_rs::identity::{IdentityClient, IdentityClientConfig};
use bsv_rs::overlay::{
    AdmittanceInstructions, LookupAnswer, LookupQuestion, LookupResolver, LookupResolverConfig,
    NetworkPreset, OutputListItem, OverlayBroadcastFacilitator, OverlayLookupFacilitator, Steak,
    TaggedBEEF,
};
use bsv_rs::primitives::from_hex;
use bsv_rs::script::{LockingScript, UnlockingScript};
use bsv_rs::transaction::{Transaction, TransactionInput, TransactionOutput};
use bsv_rs::wallet::*;
use bsv_rs::{Error, WalletRefusalClass};
use serde::{Deserialize, Deserializer};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[path = "support/identity_reveal_wallet.rs"]
mod identity_reveal_wallet;
use identity_reveal_wallet::Counting;

#[derive(Deserialize)]
struct Vector {
    serial_number: String,
    other_serial_number: String,
    lookups: Lookups,
    competing: Competing,
    runs: Vec<Run>,
}

#[derive(Deserialize)]
struct Lookups {
    #[serde(deserialize_with = "hex")]
    single: Vec<u8>,
    #[serde(deserialize_with = "hex")]
    other_only: Vec<u8>,
    #[serde(deserialize_with = "hex")]
    both: Vec<u8>,
}

#[derive(Deserialize)]
struct Competing {
    txid: String,
    #[serde(deserialize_with = "hex")]
    beef: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Run {
    name: String,
    verdict: Option<String>,
    calls: Vec<String>,
    create_action: Vec<Value>,
    sign_action: Vec<Value>,
    abort_action: Vec<Value>,
    broadcasts: Vec<String>,
    #[serde(default, rename = "signable_tx", deserialize_with = "hex_opt")]
    signable_tx: Option<Vec<u8>>,
    #[serde(default, rename = "signed_tx", deserialize_with = "hex_opt")]
    signed_tx: Option<Vec<u8>>,
}

fn hex<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    from_hex(&String::deserialize(d)?).map_err(serde::de::Error::custom)
}

fn hex_opt<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
    hex(d).map(Some)
}

fn vector() -> Vector {
    serde_json::from_str(include_str!("vectors/identity_revocation_checks_327.json")).unwrap()
}

fn run<'a>(v: &'a Vector, name: &str) -> &'a Run {
    v.runs.iter().find(|r| r.name == name).unwrap()
}

/// Answers every lookup with the answer given.
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
        assert_eq!(tagged.topics, ["tm_identity"]);
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

fn outputs(beef: &[u8], indexes: &[u32]) -> LookupAnswer {
    LookupAnswer::OutputList {
        outputs: indexes
            .iter()
            .map(|&output_index| OutputListItem {
                beef: beef.to_vec(),
                output_index,
                context: None,
            })
            .collect(),
    }
}

/// The subject's wallet (key 9) revoking `serial`: the lookup answered as
/// given, createAction with the run's signable transaction, signAction from
/// `answers`; the verdict and the txids broadcast.
async fn revoke(
    serial: &str,
    answer: LookupAnswer,
    signable: Option<&[u8]>,
    answers: Vec<bsv_rs::Result<SignActionResult>>,
) -> (Counting, bsv_rs::Result<()>, Vec<String>) {
    let mut wallet = Counting::of_scalar(9);
    wallet.signable = signable.map(|tx| SignableTransaction {
        tx: tx.to_vec(),
        reference: vec![0x52; 8],
    });
    wallet.sign_answers.lock().unwrap().extend(answers);
    let mut host_overrides = HashMap::new();
    host_overrides.insert(
        "ls_identity".to_string(),
        vec!["http://identity-lookup.invalid".to_string()],
    );
    let resolver = Arc::new(LookupResolver::new(LookupResolverConfig {
        network_preset: NetworkPreset::Local,
        facilitator: Some(Arc::new(Lookup(answer)) as Arc<dyn OverlayLookupFacilitator>),
        slap_trackers: Some(vec![]),
        host_overrides: Some(host_overrides),
        ..Default::default()
    }));
    let ship = Ship::default();
    let config = IdentityClientConfig::default().with_network(NetworkPreset::Local);
    let client = IdentityClient::with_resolver(wallet.clone(), config, resolver)
        .with_broadcast_facilitator(Arc::new(ship.clone()));
    let verdict = client.revoke_certificate_revelation(serial).await;
    let sent = ship.0.lock().unwrap().clone();
    (wallet, verdict, sent)
}

fn signed(r: &Run) -> bsv_rs::Result<SignActionResult> {
    Ok(SignActionResult {
        txid: None,
        tx: Some(r.signed_tx.clone().unwrap()),
        send_with_results: None,
    })
}

/// The double-spend evidence of the reference's run: one result, the
/// competing transaction's txid and BEEF, or neither.
fn review(competing: Option<&Competing>) -> Error {
    Error::WalletReviewActions(Box::new(ReviewActionsRefusal::new(vec![
        ReviewActionResult {
            txid: [0x22; 32],
            status: ReviewActionResultStatus::DoubleSpend,
            competing_txs: competing.map(|c| vec![from_hex(&c.txid).unwrap().try_into().unwrap()]),
            competing_beef: competing.map(|c| c.beef.clone()),
        },
    ])))
}

/// The run's wallet calls, arguments and broadcasts equal to the reference's.
fn same_calls(r: &Run, wallet: &Counting, sent: &[String]) {
    let reference: Vec<String> = r.calls.iter().map(|c| snake(c).to_string()).collect();
    assert_eq!(wallet.calls(), reference, "{}", r.name);
    let creates: Vec<Value> = wallet
        .creates
        .lock()
        .unwrap()
        .iter()
        .map(|a| serde_json::to_value(a).unwrap())
        .collect();
    let reference: Vec<Value> = r
        .create_action
        .iter()
        .map(|a| {
            let mut a = a.clone();
            let beef = from_hex(a["inputBEEF"].as_str().unwrap()).unwrap();
            a["inputBEEF"] = serde_json::to_value(beef).unwrap();
            a
        })
        .collect();
    assert_eq!(creates, reference, "{}: createAction", r.name);
    let signs = serde_json::to_value(wallet.signs.lock().unwrap().clone()).unwrap();
    assert_eq!(
        signs,
        Value::Array(r.sign_action.clone()),
        "{}: signAction",
        r.name
    );
    let aborts = serde_json::to_value(wallet.aborts.lock().unwrap().clone()).unwrap();
    assert_eq!(
        aborts,
        Value::Array(r.abort_action.clone()),
        "{}: abortAction",
        r.name
    );
    assert_eq!(sent, r.broadcasts, "{}: broadcasts", r.name);
}

#[tokio::test]
async fn an_absent_lookup_result_is_refused_in_the_references_words() {
    let v = vector();
    for (name, answer) in [
        ("lookup_empty", LookupAnswer::OutputList { outputs: vec![] }),
        (
            "lookup_freeform",
            LookupAnswer::Freeform {
                result: serde_json::json!({}),
            },
        ),
    ] {
        let r = run(&v, name);
        let (wallet, verdict, sent) = revoke(&v.serial_number, answer, None, vec![]).await;
        let words = r.verdict.clone().unwrap();
        assert_eq!(words, "Failed to get lookup result");
        assert_eq!(verdict, Err(Error::IdentityError(words)), "{name}");
        same_calls(r, &wallet, &sent);
    }
}

/// A BEEF of one transaction whose output carries `size` bytes of
/// `OP_FALSE OP_RETURN` data, this crate's writer's.
fn beef_of(size: usize) -> Vec<u8> {
    let mut tx = Transaction::new();
    tx.add_input(TransactionInput::new("11".repeat(32), 0))
        .unwrap();
    tx.inputs[0].unlocking_script = Some(UnlockingScript::from_hex("51").unwrap());
    let mut script = vec![0x00, 0x6a, 0x4e];
    script.extend_from_slice(&(size as u32).to_le_bytes());
    script.resize(script.len() + size, 0xcc);
    tx.add_output(TransactionOutput::new(
        0,
        LockingScript::from_binary(&script).unwrap(),
    ))
    .unwrap();
    tx.to_beef(true).unwrap()
}

/// The resolver keeps one output per `<txid>.<index>` and none whose BEEF
/// does not parse, so the answers here are distinct outputs of a real BEEF
/// where the reference's were copies (`LookupResolver.query` replaced).
#[tokio::test]
async fn a_lookup_past_the_references_bounds_is_refused_before_any_token_is_read() {
    let v = vector();
    let r = run(&v, "too_many_results");
    let indexes: Vec<u32> = (0..10001).collect();
    let answer = outputs(&v.lookups.single, &indexes);
    let (wallet, verdict, sent) = revoke(&v.serial_number, answer, None, vec![]).await;
    let words = r.verdict.clone().unwrap();
    assert_eq!(words, "Identity revelation lookup exceeded 10000 results");
    assert_eq!(verdict, Err(Error::IdentityError(words)));
    same_calls(r, &wallet, &sent);

    // 17 outputs of a BEEF over 1 MiB: past the 16 MiB across the answer
    let r = run(&v, "beef_bytes_bound");
    let beef = beef_of(1 << 20);
    let indexes: Vec<u32> = (0..17).collect();
    let (wallet, verdict, sent) =
        revoke(&v.serial_number, outputs(&beef, &indexes), None, vec![]).await;
    let words = r.verdict.clone().unwrap();
    assert_eq!(
        words,
        "Identity revelation lookup exceeded 16777216 BEEF bytes"
    );
    assert_eq!(verdict, Err(Error::IdentityError(words)));
    same_calls(r, &wallet, &sent);
    // 15 of them are within it: the tokens are read (none is one)
    let indexes: Vec<u32> = (0..15).collect();
    let (_, verdict, _) = revoke(&v.serial_number, outputs(&beef, &indexes), None, vec![]).await;
    assert_eq!(
        verdict,
        Err(Error::IdentityError(
            "No authenticated revelation output matches the requested certificate.".to_string()
        ))
    );
}

#[tokio::test]
async fn a_serial_number_not_of_32_bytes_is_refused_before_any_wallet_call() {
    let v = vector();
    let r = run(&v, "serial_number_short");
    let answer = outputs(&v.lookups.single, &[0]);
    let (wallet, verdict, sent) = revoke("AAAA", answer, None, vec![]).await;
    let words = r.verdict.clone().unwrap();
    assert_eq!(
        words,
        "The serialNumber parameter must be at least 32 bytes"
    );
    assert_eq!(
        verdict,
        Err(Error::WalletRefusal {
            class: WalletRefusalClass::InvalidParameter,
            message: words
        })
    );
    same_calls(r, &wallet, &sent);
}

#[tokio::test]
async fn a_token_for_another_certificate_is_refused_in_the_references_words() {
    let v = vector();
    assert_ne!(v.other_serial_number, v.serial_number);
    let r = run(&v, "another_certificate");
    let answer = outputs(&v.lookups.other_only, &[0]);
    let (wallet, verdict, sent) = revoke(&v.serial_number, answer, None, vec![]).await;
    let words = r.verdict.clone().unwrap();
    assert_eq!(
        words,
        "No authenticated revelation output matches the requested certificate."
    );
    assert_eq!(verdict, Err(Error::IdentityError(words)));
    same_calls(r, &wallet, &sent);

    // the same token asked for by its own serial number is spent: the
    // refusal is the serial number's, not the token's shape
    let answer = outputs(&v.lookups.other_only, &[0]);
    let (wallet, verdict, _) = revoke(&v.other_serial_number, answer, None, vec![]).await;
    assert_eq!(
        verdict,
        Err(Error::IdentityError(
            "Failed to create signable transaction".to_string()
        ))
    );
    assert_eq!(wallet.calls()[2..4], ["verify_signature", "create_action"]);
}

#[tokio::test]
async fn of_two_outputs_the_matching_second_is_spent_at_its_index() {
    let v = vector();
    let r = run(&v, "second_output_matches");
    assert_eq!(r.verdict, None);
    let outpoint = r.create_action[0]["inputs"][0]["outpoint"]
        .as_str()
        .unwrap();
    assert!(outpoint.ends_with(".1"), "{outpoint}");
    let answer = outputs(&v.lookups.both, &[0, 1]);
    let (wallet, verdict, sent) = revoke(
        &v.serial_number,
        answer,
        r.signable_tx.as_deref(),
        vec![signed(r)],
    )
    .await;
    assert_eq!(verdict, Ok(()));
    same_calls(r, &wallet, &sent);
    // the first output (another certificate's token) is never spent
    assert_eq!(wallet.creates.lock().unwrap().len(), 1);
    assert_eq!(
        sent,
        [Transaction::from_atomic_beef(&r.signed_tx.clone().unwrap())
            .unwrap()
            .id()]
    );
}

#[tokio::test]
async fn a_sign_action_failure_aborts_the_action_and_keeps_the_failure() {
    let v = vector();
    let r = run(&v, "sign_action_fails");
    let words = r.verdict.clone().unwrap();
    let refused = Error::WalletError(words.clone());
    let answer = outputs(&v.lookups.single, &[0]);
    let (wallet, verdict, sent) = revoke(
        &v.serial_number,
        answer,
        r.signable_tx.as_deref(),
        vec![Err(refused.clone())],
    )
    .await;
    assert_eq!(verdict, Err(refused));
    same_calls(r, &wallet, &sent);
    assert_eq!(
        r.abort_action,
        [serde_json::json!({ "reference": "UlJSUlJSUlI=" })]
    );
}

#[tokio::test]
async fn a_double_spend_answered_once_is_synchronized_then_retried() {
    let v = vector();
    let r = run(&v, "double_spend_then_accepted");
    assert_eq!(r.verdict, None);
    assert_eq!(r.broadcasts[0], v.competing.txid);
    let answer = outputs(&v.lookups.single, &[0]);
    let (wallet, verdict, sent) = revoke(
        &v.serial_number,
        answer,
        r.signable_tx.as_deref(),
        vec![Err(review(Some(&v.competing))), signed(r)],
    )
    .await;
    assert_eq!(verdict, Ok(()));
    // the action aborted, the competing transaction broadcast, then the
    // spend made again and broadcast
    same_calls(r, &wallet, &sent);
}

#[tokio::test]
async fn a_review_without_double_spend_evidence_is_not_retried() {
    let v = vector();
    let r = run(&v, "review_without_evidence");
    let answer = outputs(&v.lookups.single, &[0]);
    let (wallet, verdict, sent) = revoke(
        &v.serial_number,
        answer,
        r.signable_tx.as_deref(),
        vec![Err(review(None))],
    )
    .await;
    assert_eq!(verdict.unwrap_err().to_string(), r.verdict.clone().unwrap());
    same_calls(r, &wallet, &sent);

    // the reference retries a WERR_REVIEW_ACTIONS with evidence only: a
    // refusal of its class without results, or words naming a double spend
    // (the overlay helper's rule), is one attempt
    for refused in [
        Error::WalletRefusal {
            class: WalletRefusalClass::ReviewActions,
            message: "double spend".to_string(),
        },
        Error::WalletError("txn-mempool-conflict: double spend".to_string()),
    ] {
        let answer = outputs(&v.lookups.single, &[0]);
        let (wallet, verdict, sent) = revoke(
            &v.serial_number,
            answer,
            r.signable_tx.as_deref(),
            vec![Err(refused.clone())],
        )
        .await;
        assert_eq!(verdict, Err(refused));
        assert_eq!(wallet.creates.lock().unwrap().len(), 1);
        assert!(sent.is_empty());
    }
}

#[tokio::test]
async fn a_double_spend_on_every_attempt_ends_after_five() {
    // `MAX_DOUBLE_SPEND_RETRIES` (`withDoubleSpendRetry.ts:8`): the fifth
    // attempt's failure is the answer, unsynchronized (`:157`)
    let v = vector();
    let r = run(&v, "double_spend_then_accepted");
    let answer = outputs(&v.lookups.single, &[0]);
    let answers = (0..6).map(|_| Err(review(Some(&v.competing)))).collect();
    let (wallet, verdict, sent) =
        revoke(&v.serial_number, answer, r.signable_tx.as_deref(), answers).await;
    assert_eq!(verdict, Err(review(Some(&v.competing))));
    assert_eq!(wallet.creates.lock().unwrap().len(), 5);
    assert_eq!(wallet.aborts.lock().unwrap().len(), 5);
    assert_eq!(sent, vec![v.competing.txid.clone(); 4]);
}

/// The reference's method name as this crate's.
fn snake(name: &str) -> &'static str {
    match name {
        "getPublicKey" => "get_public_key",
        "createSignature" => "create_signature",
        "verifySignature" => "verify_signature",
        "createAction" => "create_action",
        "signAction" => "sign_action",
        "abortAction" => "abort_action",
        other => panic!("no name for {other}"),
    }
}
