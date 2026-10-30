//! #467: the four result totals carry every safe integer without narrowing.
#![cfg(feature = "wallet")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[allow(dead_code)]
#[path = "support/fixtures/wallet.rs"]
mod wallet;
#[allow(dead_code)]
#[path = "support/fixtures/wallet_json.rs"]
mod wallet_json;

use bsv_rs::wallet::wire::{WalletCall, WalletWire, WalletWireTransceiver, WireWriter};
use bsv_rs::wallet::{
    DiscoverCertificatesResult, ListActionsResult, ListCertificatesResult, ListOutputsResult,
};
use bsv_rs::Error;
use serde_json::{json, Value};

const WIDE: u64 = 1 << 32;
const MAX_SAFE: u64 = (1 << 53) - 1;
const PRECISION: &str = "number too large to retain precision - use readVarIntBn";

struct Response(Vec<u8>);

#[async_trait::async_trait]
impl WalletWire for Response {
    async fn transmit_to_wallet(&self, _: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.0.clone())
    }
}

fn args(call: WalletCall) -> Value {
    match call {
        WalletCall::ListActions => json!({"labels": []}),
        WalletCall::ListOutputs => json!({"basket": "totals"}),
        WalletCall::ListCertificates => json!({"certifiers": [], "types": []}),
        WalletCall::DiscoverByAttributes => json!({"attributes": {"name": "Fixture"}}),
        WalletCall::DiscoverByIdentityKey => json!({"identityKey":
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"}),
        _ => unreachable!(),
    }
}

fn frame(call: WalletCall, total: u64) -> Vec<u8> {
    let mut writer = WireWriter::new();
    writer.write_u8(0).write_var_int(total);
    if call == WalletCall::ListOutputs {
        writer.write_optional_bytes(None);
    }
    writer.into_bytes()
}

// The generic keeps this test compilable on the u32 base as well as the u64 tip.
fn write_total<T: Into<u64>>(writer: &mut WireWriter, total: T) {
    writer.write_var_int(total.into());
}

fn typed_frame(call: WalletCall, total: u64) -> Vec<u8> {
    let mut writer = WireWriter::new();
    writer.write_u8(0);
    match call {
        WalletCall::ListActions => {
            let r: ListActionsResult =
                serde_json::from_value(json!({"totalActions": total, "actions": []})).unwrap();
            write_total(&mut writer, r.total_actions);
        }
        WalletCall::ListOutputs => {
            let r: ListOutputsResult =
                serde_json::from_value(json!({"totalOutputs": total, "outputs": []})).unwrap();
            write_total(&mut writer, r.total_outputs);
            writer.write_optional_bytes(r.beef.as_deref());
        }
        WalletCall::ListCertificates => {
            let r: ListCertificatesResult =
                serde_json::from_value(json!({"totalCertificates": total, "certificates": []}))
                    .unwrap();
            write_total(&mut writer, r.total_certificates);
        }
        _ => {
            let r: DiscoverCertificatesResult =
                serde_json::from_value(json!({"totalCertificates": total, "certificates": []}))
                    .unwrap();
            write_total(&mut writer, r.total_certificates);
        }
    }
    writer.into_bytes()
}

async fn check(call: WalletCall, field: &str) {
    for total in [WIDE, MAX_SAFE, 0, u64::from(u32::MAX)] {
        let bytes = frame(call, total);
        let client = wallet::WireWallet(WalletWireTransceiver::new(Response(bytes.clone())));
        let result = wallet::invoke(&client, call, args(call)).await.unwrap();
        assert_eq!(result[field].as_u64(), Some(total));
        assert_eq!(typed_frame(call, total), bytes);
    }
    // All four reference sites explicitly pass false: nine FF is no sentinel.
    for total in [MAX_SAFE + 1, u64::MAX] {
        let client = wallet::WireWallet(WalletWireTransceiver::new(Response(frame(call, total))));
        assert_eq!(
            wallet::invoke(&client, call, args(call)).await.unwrap_err(),
            Error::WalletError(PRECISION.into())
        );
    }
}

#[tokio::test]
async fn list_actions_total_u64_467() {
    check(WalletCall::ListActions, "totalActions").await;
}

#[tokio::test]
async fn list_outputs_total_u64_467() {
    check(WalletCall::ListOutputs, "totalOutputs").await;
}

#[tokio::test]
async fn list_certificates_total_u64_467() {
    check(WalletCall::ListCertificates, "totalCertificates").await;
}

#[tokio::test]
async fn discovery_total_u64_467() {
    check(WalletCall::DiscoverByIdentityKey, "totalCertificates").await;
    check(WalletCall::DiscoverByAttributes, "totalCertificates").await;
}
