//! #393: null is present, and the validator makes the wire fallbacks unreachable.
#![cfg(feature = "wallet")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::error::WalletRefusalClass;
use bsv_rs::wallet::validation::validate_internalize_action_args;
use bsv_rs::wallet::wire::{WalletWire, WalletWireTransceiver};
use bsv_rs::wallet::{InternalizeActionArgs, InternalizeOutput};
use bsv_rs::Error;
use serde_json::Value;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

fn case(name: &str) -> Value {
    let vector: Value =
        serde_json::from_str(include_str!("vectors/internalize_null_remittance_393.json")).unwrap();
    vector["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == name)
        .unwrap()
        .clone()
}

fn args(output: InternalizeOutput) -> InternalizeActionArgs {
    InternalizeActionArgs {
        tx: vec![1],
        outputs: vec![output],
        description: "fixture action".into(),
        labels: None,
        seek_permission: None,
    }
}

fn invalid_parameter(message: &str) -> Error {
    Error::WalletRefusal {
        class: WalletRefusalClass::InvalidParameter,
        message: message.into(),
    }
}

fn refuses_null(name: &str) {
    let case = case(name);
    assert_eq!(case["expected"]["accepted"], false, "{name}");
    assert_eq!(case["expected"]["code"], 6, "{name}");
    let error = serde_json::from_value::<InternalizeOutput>(case["output"].clone())
        .expect_err("a JSON null remittance must be refused, never erased as absent");
    assert_eq!(error.to_string(), case["expected"]["message"], "{name}");
}

#[test]
fn a_null_insertion_beside_a_payment_is_present_and_refused() {
    refuses_null("wallet_payment_other_null");
}

#[test]
fn a_null_payment_beside_an_insertion_is_present_and_refused() {
    refuses_null("basket_insertion_other_null");
}

#[test]
fn a_null_payment_alone_reaches_the_plain_object_refusal() {
    refuses_null("wallet_payment_own_null");
}

#[test]
fn a_null_insertion_alone_reaches_the_plain_object_refusal() {
    refuses_null("basket_insertion_own_null");
}

#[test]
fn two_null_remittances_are_present_and_refused_for_either_protocol() {
    refuses_null("wallet_payment_both_null");
    refuses_null("basket_insertion_both_null");
}

#[test]
fn a_lone_null_of_the_other_protocol_is_present_and_refused() {
    refuses_null("wallet_payment_other_null_alone");
    refuses_null("basket_insertion_other_null_alone");
}

#[test]
fn an_undefined_other_remittance_stays_absent_and_accepted() {
    for protocol in ["wallet_payment", "basket_insertion"] {
        let case = case(&format!("{protocol}_other_undefined"));
        assert_eq!(case["expected"]["accepted"], true);
        let output: InternalizeOutput = serde_json::from_value(case["output"].clone()).unwrap();
        assert_eq!(serde_json::to_value(&output).unwrap(), case["output"]);
        assert_eq!(validate_internalize_action_args(&args(output)), Ok(()));
    }
}

#[test]
fn an_undefined_own_remittance_stays_absent_and_is_refused_by_validation() {
    for protocol in ["wallet_payment", "basket_insertion"] {
        let case = case(&format!("{protocol}_own_undefined"));
        let output: InternalizeOutput = serde_json::from_value(case["output"].clone()).unwrap();
        assert_eq!(
            validate_internalize_action_args(&args(output)),
            Err(invalid_parameter(
                case["expected"]["message"].as_str().unwrap()
            ))
        );
    }
}

struct CountingWire(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl WalletWire for CountingWire {
    async fn transmit_to_wallet(&self, _: &[u8]) -> Result<Vec<u8>, Error> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(vec![0])
    }
}

async fn guard_precedes_encoding(protocol: &str, other: &str) {
    let sent = Arc::new(AtomicUsize::new(0));
    let wallet = WalletWireTransceiver::new(CountingWire(sent.clone()));
    let missing = case(&format!("{protocol}_own_undefined"));
    let valid = case(&format!("{protocol}_other_undefined"));
    let other = case(&format!("{other}_other_undefined"));
    let mut crossed = valid["output"].clone();
    crossed.as_object_mut().unwrap().extend(
        other["output"]
            .as_object()
            .unwrap()
            .iter()
            .filter(|(key, _)| key.ends_with("Remittance"))
            .map(|(key, value)| (key.clone(), value.clone())),
    );
    // If encoding ran, this would fail its hex read with different words.
    crossed["paymentRemittance"]["senderIdentityKey"] = "not hex".into();
    let mut mismatched = crossed.clone();
    let own = if protocol == "wallet_payment" {
        "paymentRemittance"
    } else {
        "insertionRemittance"
    };
    mismatched.as_object_mut().unwrap().remove(own);
    for output in [missing["output"].clone(), mismatched, crossed] {
        let args = args(serde_json::from_value(output).unwrap());
        let refusal = invalid_parameter(missing["expected"]["message"].as_str().unwrap());
        assert_eq!(
            validate_internalize_action_args(&args),
            Err(refusal.clone())
        );
        assert_eq!(
            wallet.internalize_action(args, None).await.unwrap_err(),
            refusal
        );
        assert_eq!(sent.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn payment_remittance_guard_precedes_encoding_and_sending() {
    guard_precedes_encoding("wallet_payment", "basket_insertion").await;
}

#[tokio::test]
async fn insertion_remittance_guard_precedes_encoding_and_sending() {
    guard_precedes_encoding("basket_insertion", "wallet_payment").await;
}
