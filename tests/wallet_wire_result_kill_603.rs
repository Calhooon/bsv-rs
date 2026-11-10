//! #603, kill lane rv-wire: `result_values/wire.rs`'s listOutputs projection
//! hands the typed outputs to the shared rows (`wire.rs:193`), so a present
//! script the BEEF commits at that outpoint is compared by its own bytes and
//! accepted, as the reference's `WalletWireTransceiver.listOutputs` accepts it
//! (`WalletResultValidation.ts:2109-2130` at `ts-stack@edf6e03`, through
//! `WalletWireTransceiver.ts:650-665`). Against
//! `vectors/rv_wire_kill_603.json`'s `list_outputs_matching_script`
//! (`support/rv_wire_kill_603.mjs`, Node v22.18.0): #487's `listOutputs_valid`
//! frame with the script present, `51`, written by #487's writer.
#![cfg(feature = "wallet")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: tests

#[allow(dead_code)]
#[path = "support/fixtures/wallet_json.rs"]
mod wallet_json;

use async_trait::async_trait;
use bsv_rs::wallet::wire::{WalletWire, WalletWireTransceiver};
use bsv_rs::Error;
use serde_json::Value;
use wallet_json::FixtureJson;

const RECORDING: &str = include_str!("vectors/rv_wire_kill_603.json");

struct RecordedWire {
    request: Vec<u8>,
    response: Vec<u8>,
}

#[async_trait]
impl WalletWire for RecordedWire {
    async fn transmit_to_wallet(&self, request: &[u8]) -> Result<Vec<u8>, Error> {
        assert_eq!(
            hex::encode(request),
            hex::encode(&self.request),
            "the request bytes are the reference transceiver's"
        );
        Ok(self.response.clone())
    }
}

#[tokio::test]
async fn a_listed_output_whose_script_matches_its_beef_is_accepted_603() {
    let recording: Value = serde_json::from_str(RECORDING).unwrap();
    assert_eq!(recording["source"], "ts-stack@edf6e03");
    assert_eq!(recording["node"], "v22.18.0");
    let case = recording["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "list_outputs_matching_script")
        .unwrap();
    assert_eq!(case["reference"]["accepted"], true);
    assert_eq!(case["reference"]["locking_script"], "51");
    let hex_of = |name: &str| hex::decode(case[name].as_str().unwrap()).unwrap();
    let wallet = WalletWireTransceiver::new(RecordedWire {
        request: hex_of("request_hex"),
        response: hex_of("response_hex"),
    });
    let listed = wallet
        .list_outputs(
            FixtureJson::from_fixture(case["args"].clone()),
            Some("fixtures.invalid"),
        )
        .await;
    match listed {
        Ok(result) => {
            assert_eq!(result.outputs.len(), 1);
            assert_eq!(
                result.outputs[0].locking_script.as_deref(),
                Some(&[0x51u8][..])
            );
        }
        Err(e) => panic!("the reference accepts this answer; refused: {e:?}"),
    }
}
