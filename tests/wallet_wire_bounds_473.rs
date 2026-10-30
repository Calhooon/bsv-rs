//! #473: replay the #338 recorder's pre-entry limits and numeric bounds.
//! Boundary collection frames intentionally omit their entries: the maximum
//! reaches the availability guard, maximum + 1 the size guard, before parsing.
#![cfg(feature = "wallet")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::wallet::wire::{WalletWire, WalletWireTransceiver, WireReader};
use bsv_rs::wallet::{
    CreateActionArgs, ListActionsArgs, ListOutputsArgs, ProveCertificateArgs, SignActionArgs,
};
use bsv_rs::Error;
use serde_json::{json, Value};

struct Response(Vec<u8>);

#[async_trait::async_trait]
impl WalletWire for Response {
    async fn transmit_to_wallet(&self, _: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.0.clone())
    }
}

fn cases() -> Vec<Value> {
    let vector: Value =
        serde_json::from_str(include_str!("vectors/wallet_wire/bounds_473.json")).unwrap();
    assert_eq!(vector["reference"], "ts-stack@edf6e03 (unmodified)");
    assert_eq!(vector["node"], "v22.18.0");
    let rows = vector["rows"].as_array().unwrap().clone();
    assert_eq!(rows.len(), 73);
    rows
}

async fn replay(name: &str) {
    let case = cases().into_iter().find(|row| row["name"] == name).unwrap();
    let bytes = hex::decode(case["payload_hex"].as_str().unwrap()).unwrap();
    let mut reader = WireReader::new(&bytes);
    let client = WalletWireTransceiver::new(Response(
        hex::decode(case["response_hex"].as_str().unwrap()).unwrap(),
    ));
    let result = match case["reader"].as_str().unwrap() {
        "wallet_action" => reader.read_wallet_action().map(|_| Value::Null),
        "action_input" => reader
            .read_wallet_action_input()
            .map(|r| json!(r.source_satoshis)),
        "action_output" => reader
            .read_wallet_action_output()
            .map(|r| json!(r.satoshis)),
        "wallet_output" => reader.read_wallet_output().map(|r| json!(r.satoshis)),
        "spends" => reader.read_sign_action_spends().map(|_| Value::Null),
        "basket" => reader.read_basket_insertion().map(|_| Value::Null),
        "client_height" => client
            .get_height(None)
            .await
            .map(|height| json!({"height": height})),
        "client_create" => {
            let args: CreateActionArgs =
                serde_json::from_value(json!({"description":"bound test"})).unwrap();
            client.create_action(args, None).await.map(|_| Value::Null)
        }
        "client_sign" => {
            let args: SignActionArgs =
                serde_json::from_value(json!({"spends":{},"reference":"AQ=="})).unwrap();
            client.sign_action(args, None).await.map(|_| Value::Null)
        }
        "client_prove" => {
            let args: ProveCertificateArgs = serde_json::from_value(case["args"].clone()).unwrap();
            client
                .prove_certificate(args, None)
                .await
                .map(|_| Value::Null)
        }
        "client_actions" => {
            let args: ListActionsArgs = serde_json::from_value(case["args"].clone()).unwrap();
            client
                .list_actions(args, None)
                .await
                .map(|r| json!(r.actions.len()))
        }
        "client_outputs" => {
            let args: ListOutputsArgs = serde_json::from_value(case["args"].clone()).unwrap();
            client
                .list_outputs(args, None)
                .await
                .map(|r| json!(r.outputs.len()))
        }
        other => panic!("unknown recorded reader {other}"),
    };
    if case["code"] == 0 {
        let actual = result.unwrap_or_else(|error| panic!("{name}: {error}"));
        if name.starts_with("height_") {
            assert_eq!(actual, case["value"], "{name}");
        } else if name.ends_with("range_at") {
            assert_eq!(actual, 2_100_000_000_000_000u64, "{name}");
        } else if case["reader"] == "client_actions" {
            assert_eq!(
                actual,
                case["value"]["actions"].as_array().unwrap().len(),
                "{name}"
            );
        } else {
            assert_eq!(
                actual,
                case["value"]["outputs"].as_array().unwrap().len(),
                "{name}"
            );
        }
    } else {
        assert_eq!(
            result,
            Err(Error::WalletError(case["message"].as_str().unwrap().into())),
            "{name}"
        );
    }
}

async fn collection(name: &str) {
    // Past first: the base must fail on the recorded size refusal, not setup.
    for edge in ["past", "at", "short"] {
        replay(&format!("{name}_{edge}")).await;
    }
}

macro_rules! collections {
    ($($size:ident, $remaining:ident => $name:literal);* $(;)?) => { $(
        #[tokio::test]
        async fn $size() { collection($name).await; }
        #[tokio::test]
        async fn $remaining() { replay(concat!($name, "_short")).await; }
    )* };
}

collections!(
    create_no_send_change_size_473, create_no_send_change_remaining_473 => "create_no_send_change";
    create_send_with_results_size_473, create_send_with_results_remaining_473 => "create_send_with_results";
    sign_send_with_results_size_473, sign_send_with_results_remaining_473 => "sign_send_with_results";
    action_labels_size_473, action_labels_remaining_473 => "action_labels";
    action_inputs_size_473, action_inputs_remaining_473 => "action_inputs";
    action_outputs_size_473, action_outputs_remaining_473 => "action_outputs";
    action_output_tags_size_473, action_output_tags_remaining_473 => "action_output_tags";
    output_tags_size_473, output_tags_remaining_473 => "output_tags";
    output_labels_size_473, output_labels_remaining_473 => "output_labels";
    prove_keyring_size_473, prove_keyring_remaining_473 => "prove_keyring";
    spends_size_473, spends_remaining_473 => "spends";
    insertion_tags_size_473, insertion_tags_remaining_473 => "insertion_tags";
);

macro_rules! amounts {
    ($($name:ident: $site:literal => $edge:literal),* $(,)?) => { $(
        #[tokio::test]
        async fn $name() {
            replay(concat!($site, "_", $edge, "_past")).await;
            replay(concat!($site, "_", $edge, "_at")).await;
        }
    )* };
}

amounts!(
    height_lower_bound_473: "height" => "lower",
    height_upper_bound_473: "height" => "range",
    height_precision_473: "height" => "precision",
    input_satoshi_range_473: "input_satoshis" => "range",
    input_satoshi_precision_473: "input_satoshis" => "precision",
    action_output_satoshi_range_473: "action_output_satoshis" => "range",
    action_output_satoshi_precision_473: "action_output_satoshis" => "precision",
    output_satoshi_range_473: "output_satoshis" => "range",
    output_satoshi_precision_473: "output_satoshis" => "precision",
);

#[tokio::test]
async fn unsigned_numbers_refuse_the_signed_sentinel_473() {
    for name in [
        "height",
        "input_satoshis",
        "action_output_satoshis",
        "output_satoshis",
    ] {
        replay(&format!("{name}_sentinel")).await;
    }
}

#[tokio::test]
async fn height_trailing_data_precedes_range_473() {
    replay("height_trailing").await;
}

#[tokio::test]
async fn actions_page_bound_473() {
    replay("listActions_page_11").await;
    replay("listActions_page_10").await;
    replay("listActions_limit_past").await;
    replay("listActions_limit_at").await;
}

#[tokio::test]
async fn outputs_page_bound_473() {
    replay("listOutputs_page_11").await;
    replay("listOutputs_page_10").await;
    replay("listOutputs_limit_past").await;
    replay("listOutputs_limit_at").await;
}

#[tokio::test]
async fn actions_total_bounds_the_page_not_the_read_loop_473() {
    replay("listActions_over_total").await;
    replay("listActions_partial_total").await;
    replay("listActions_empty_total").await;
}

#[tokio::test]
async fn outputs_total_bounds_the_page_not_the_read_loop_473() {
    replay("listOutputs_over_total").await;
    replay("listOutputs_partial_total").await;
    replay("listOutputs_empty_total").await;
}
