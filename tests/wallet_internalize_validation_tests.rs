//! internalizeAction refuses a basket insertion's `customInstructions` over
//! 1,000 UTF-8 bytes (Calhooon/bsv-rs#117; BRC-100 at `5119a9b`
//! `wallet/0100.md:867`, the TypeScript SDK's `validateBasketInsertion`). The
//! bound counts bytes, not characters; the createAction output's
//! `customInstructions` stays unbounded, as in the reference.
//!
//! Run with: `cargo test --features "wallet,http" --test wallet_internalize_validation_tests`
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(feature = "wallet")]

use bsv_rs::wallet::validation::{
    validate_create_action_output, validate_internalize_action_args, CreateActionOutputRaw,
};
use bsv_rs::wallet::{
    BasketInsertion, InternalizeActionArgs, InternalizeOutput, ProtoWallet, WalletInterface,
    WalletPayment,
};
use bsv_rs::Error;

fn insertion(custom_instructions: Option<String>) -> InternalizeOutput {
    InternalizeOutput {
        output_index: 0,
        protocol: "basket insertion".into(),
        payment_remittance: None,
        insertion_remittance: Some(BasketInsertion {
            basket: "fixtures".into(),
            custom_instructions,
            tags: None,
        }),
    }
}

fn payment() -> InternalizeOutput {
    InternalizeOutput {
        output_index: 1,
        protocol: "wallet payment".into(),
        payment_remittance: Some(WalletPayment {
            derivation_prefix: "cHJlZml4".into(),
            derivation_suffix: "c3VmZml4".into(),
            sender_identity_key: "02".to_string() + &"11".repeat(32),
        }),
        insertion_remittance: None,
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

fn refusal(index: usize, bytes: usize) -> Error {
    Error::WalletError(format!(
        "Invalid outputs[{index}].insertionRemittance.customInstructions: \
         must be no more than 1000 bytes, got {bytes}"
    ))
}

#[test]
fn custom_instructions_of_1000_utf8_bytes_are_accepted() {
    let a = args(vec![insertion(Some("a".repeat(1000)))]);
    assert_eq!(validate_internalize_action_args(&a), Ok(()));
}

#[test]
fn custom_instructions_of_1001_utf8_bytes_are_refused_with_the_field_and_the_count() {
    let a = args(vec![insertion(Some("a".repeat(1001)))]);
    assert_eq!(validate_internalize_action_args(&a), Err(refusal(0, 1001)));
}

#[test]
fn the_custom_instructions_bound_counts_utf8_bytes_not_characters() {
    // U+1F600 is four UTF-8 bytes: 250 of them are 1,000 bytes, 251 are 1,004.
    let at_bound = args(vec![insertion(Some("\u{1F600}".repeat(250)))]);
    assert_eq!(validate_internalize_action_args(&at_bound), Ok(()));
    let past_bound = args(vec![insertion(Some("\u{1F600}".repeat(251)))]);
    assert_eq!(
        validate_internalize_action_args(&past_bound),
        Err(refusal(0, 1004))
    );
}

#[test]
fn absent_custom_instructions_and_a_payment_output_are_accepted() {
    let a = args(vec![insertion(None), payment()]);
    assert_eq!(validate_internalize_action_args(&a), Ok(()));
}

#[test]
fn a_second_outputs_overlong_custom_instructions_is_named_with_its_index() {
    let a = args(vec![
        insertion(Some("a".repeat(1000))),
        insertion(Some("b".repeat(1001))),
    ]);
    assert_eq!(validate_internalize_action_args(&a), Err(refusal(1, 1001)));
}

#[test]
fn a_create_action_outputs_custom_instructions_stay_unbounded() {
    let output = CreateActionOutputRaw {
        locking_script: "76a914".to_string() + &"00".repeat(20) + "88ac",
        satoshis: 1,
        output_description: "a fixture output".into(),
        basket: None,
        custom_instructions: Some("a".repeat(1001)),
        tags: vec![],
    };
    let valid = validate_create_action_output(&output).expect("no bound on createAction's copy");
    assert_eq!(valid.custom_instructions.map(|c| c.len()), Some(1001));
}

#[tokio::test]
async fn proto_wallet_internalize_refuses_overlong_custom_instructions_before_acting() {
    let wallet = ProtoWallet::anyone();
    let refused = wallet
        .internalize_action(args(vec![insertion(Some("a".repeat(1001)))]), "app.example")
        .await;
    assert_eq!(refused.unwrap_err(), refusal(0, 1001));
}

#[cfg(feature = "http")]
mod http_json_door {
    use super::*;
    use bsv_rs::wallet::substrates::HttpWalletJson;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn internalize_against(custom_instructions: String, sends: u64) -> bsv_rs::Result<bool> {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/internalizeAction"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"accepted":true}"#))
            .expect(sends)
            .mount(&server)
            .await;
        let wallet = HttpWalletJson::new(Some("app.example.com".into()), Some(server.uri()))
            .expect("the substrate is configured");
        wallet
            .internalize_action(
                args(vec![insertion(Some(custom_instructions))]),
                "app.example",
            )
            .await
            .map(|r| r.accepted)
    }

    #[tokio::test]
    async fn the_http_json_door_refuses_overlong_custom_instructions_before_sending() {
        assert_eq!(
            internalize_against("a".repeat(1001), 0).await,
            Err(refusal(0, 1001))
        );
        assert_eq!(internalize_against("a".repeat(1000), 1).await, Ok(true));
    }
}
