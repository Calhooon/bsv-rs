//! internalizeAction judges each output's protocol and its one remittance
//! before the remittances' fields, as the reference's
//! `validateInternalizeOutput` does (bsv-rs#384; `ts-stack@edf6e03`
//! `packages/sdk/src/wallet/validationHelpers.ts:968-977` ahead of `:981-982`):
//! a wallet payment carrying an insertion remittance, or a basket insertion
//! carrying a payment remittance, is refused in the reference's words even
//! when the other remittance's fields are themselves refused. The toolbox's
//! #337 lane found it.
//!
//! Run with: `cargo test --features "wallet,http" --test wallet_internalize_one_remittance_384`
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(feature = "wallet")]

use bsv_rs::error::WalletRefusalClass;
use bsv_rs::wallet::validation::validate_internalize_action_args;
use bsv_rs::wallet::wire::{WalletWire, WalletWireTransceiver};
use bsv_rs::wallet::{
    BasketInsertion, InternalizeActionArgs, InternalizeOutput, ProtoWallet, WalletInterface,
    WalletPayment,
};
use bsv_rs::Error;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

const ONLY_PAYMENT: &str =
    "The output remittance parameter must be only paymentRemittance for wallet payment";
const ONLY_INSERTION: &str =
    "The output remittance parameter must be only insertionRemittance for basket insertion";
const PROTOCOL: &str = "The protocol parameter must be 'basket insertion' or 'wallet payment'";

fn payment_remittance() -> WalletPayment {
    WalletPayment {
        derivation_prefix: "cHJlZml4".into(),
        derivation_suffix: "c3VmZml4".into(),
        sender_identity_key: "02".to_string() + &"11".repeat(32),
    }
}

fn insertion_remittance(custom_instructions: &str) -> BasketInsertion {
    BasketInsertion {
        basket: "fixtures".into(),
        custom_instructions: Some(custom_instructions.into()),
        tags: None,
    }
}

fn output(
    protocol: &str,
    payment: Option<WalletPayment>,
    insertion: Option<BasketInsertion>,
) -> InternalizeOutput {
    InternalizeOutput {
        output_index: 0,
        protocol: protocol.into(),
        payment_remittance: payment,
        insertion_remittance: insertion,
    }
}

fn args(outputs: Vec<InternalizeOutput>) -> InternalizeActionArgs {
    InternalizeActionArgs {
        tx: vec![0x01, 0x01, 0x01, 0x01],
        outputs,
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

fn custom_instructions_refusal(index: usize, bytes: usize) -> Error {
    Error::WalletError(format!(
        "Invalid outputs[{index}].insertionRemittance.customInstructions: \
         must be no more than 1000 bytes, got {bytes}"
    ))
}

/// A wallet payment that also carries an over-long insertion remittance.
fn payment_with_overlong_insertion() -> InternalizeActionArgs {
    args(vec![output(
        "wallet payment",
        Some(payment_remittance()),
        Some(insertion_remittance(&"a".repeat(1001))),
    )])
}

/// A basket insertion with an over-long customInstructions that also carries
/// a payment remittance.
fn insertion_with_payment() -> InternalizeActionArgs {
    args(vec![output(
        "basket insertion",
        Some(payment_remittance()),
        Some(insertion_remittance(&"a".repeat(1001))),
    )])
}

#[test]
fn a_wallet_payment_carrying_an_overlong_insertion_answers_the_one_remittance_text() {
    assert_eq!(
        validate_internalize_action_args(&payment_with_overlong_insertion()),
        Err(invalid_parameter(ONLY_PAYMENT))
    );
}

#[test]
fn a_basket_insertion_carrying_a_payment_answers_the_one_remittance_text() {
    assert_eq!(
        validate_internalize_action_args(&insertion_with_payment()),
        Err(invalid_parameter(ONLY_INSERTION))
    );
}

#[test]
fn a_protocol_without_its_remittance_is_refused_in_the_reference_words() {
    let bare_payment = args(vec![output("wallet payment", None, None)]);
    assert_eq!(
        validate_internalize_action_args(&bare_payment),
        Err(invalid_parameter(ONLY_PAYMENT))
    );
    let bare_insertion = args(vec![output("basket insertion", None, None)]);
    assert_eq!(
        validate_internalize_action_args(&bare_insertion),
        Err(invalid_parameter(ONLY_INSERTION))
    );
    // The insertion's own fields are not read ahead of the protocol's rule.
    let crossed = args(vec![output(
        "wallet payment",
        None,
        Some(insertion_remittance(&"a".repeat(1001))),
    )]);
    assert_eq!(
        validate_internalize_action_args(&crossed),
        Err(invalid_parameter(ONLY_PAYMENT))
    );
}

#[test]
fn an_unknown_protocol_is_refused_before_its_remittances() {
    let unknown = args(vec![output(
        "token transfer",
        None,
        Some(insertion_remittance(&"a".repeat(1001))),
    )]);
    assert_eq!(
        validate_internalize_action_args(&unknown),
        Err(invalid_parameter(PROTOCOL))
    );
}

#[test]
fn the_field_checks_are_still_reached_when_the_protocol_matches() {
    let insertion = args(vec![
        output("wallet payment", Some(payment_remittance()), None),
        output(
            "basket insertion",
            None,
            Some(insertion_remittance(&"a".repeat(1001))),
        ),
    ]);
    assert_eq!(
        validate_internalize_action_args(&insertion),
        Err(custom_instructions_refusal(1, 1001))
    );
    let within = args(vec![
        output("wallet payment", Some(payment_remittance()), None),
        output(
            "basket insertion",
            None,
            Some(insertion_remittance(&"a".repeat(1000))),
        ),
    ]);
    assert_eq!(validate_internalize_action_args(&within), Ok(()));
}

#[test]
fn an_earlier_outputs_crossed_remittance_is_named_before_a_later_outputs_field() {
    let a = args(vec![
        output(
            "basket insertion",
            None,
            Some(insertion_remittance(&"a".repeat(1001))),
        ),
        output(
            "wallet payment",
            Some(payment_remittance()),
            Some(insertion_remittance("keep")),
        ),
    ]);
    // Output 0's field is judged with output 0, before output 1 is read.
    assert_eq!(
        validate_internalize_action_args(&a),
        Err(custom_instructions_refusal(0, 1001))
    );
}

#[tokio::test]
async fn proto_wallet_internalize_answers_the_one_remittance_text() {
    let wallet = ProtoWallet::anyone();
    let refused = wallet
        .internalize_action(payment_with_overlong_insertion(), Some("app.example"))
        .await;
    assert_eq!(refused.unwrap_err(), invalid_parameter(ONLY_PAYMENT));
}

/// Counts every frame and answers each with the success byte.
struct CountingWire(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl WalletWire for CountingWire {
    async fn transmit_to_wallet(&self, _: &[u8]) -> Result<Vec<u8>, Error> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(vec![0u8])
    }
}

#[tokio::test]
async fn the_wire_transceiver_refuses_a_crossed_remittance_before_sending() {
    let sent = Arc::new(AtomicUsize::new(0));
    let wallet = WalletWireTransceiver::new(CountingWire(sent.clone()));
    let payment = wallet
        .internalize_action(payment_with_overlong_insertion(), None)
        .await;
    assert_eq!(payment.unwrap_err(), invalid_parameter(ONLY_PAYMENT));
    let insertion = wallet
        .internalize_action(insertion_with_payment(), None)
        .await;
    assert_eq!(insertion.unwrap_err(), invalid_parameter(ONLY_INSERTION));
    assert_eq!(sent.load(Ordering::SeqCst), 0);
}

#[cfg(feature = "http")]
mod http_json_door {
    use super::*;
    use bsv_rs::wallet::substrates::HttpWalletJson;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn the_http_json_door_answers_the_one_remittance_text_before_sending() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/internalizeAction"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"accepted":true}"#))
            .expect(0)
            .mount(&server)
            .await;
        let wallet = HttpWalletJson::new(Some("app.example.com".into()), Some(server.uri()))
            .expect("the substrate is configured");
        let payment = wallet
            .internalize_action(payment_with_overlong_insertion(), Some("app.example"))
            .await;
        assert_eq!(payment.unwrap_err(), invalid_parameter(ONLY_PAYMENT));
        let insertion = wallet
            .internalize_action(insertion_with_payment(), Some("app.example"))
            .await;
        assert_eq!(insertion.unwrap_err(), invalid_parameter(ONLY_INSERTION));
    }
}
