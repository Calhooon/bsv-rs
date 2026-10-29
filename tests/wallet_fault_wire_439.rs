//! #439: typed wallet metadata preserves the legacy error frames and enum size.
#![cfg(all(feature = "wallet", feature = "http"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: fixture assertions.

#[allow(dead_code)]
#[path = "support/fixtures/mod.rs"]
mod fixtures;

use bsv_rs::wallet::wire::{WalletCall, WalletWireProcessor, WireWriter};
use bsv_rs::{AbortAcceptance, Error, WalletFault, WalletFaultFamily, WalletRefusalClass};
use fixtures::wallet::Stub;
use serde_json::json;

async fn abort_frame(error: Error) -> Vec<u8> {
    let mut stub = Stub::new(json!({}));
    stub.error = Some(error);
    let mut request = WireWriter::new();
    request
        .write_u8(WalletCall::AbortAction.as_u8())
        .write_u8(0)
        .write_bytes(b"reference");
    WalletWireProcessor::new(stub)
        .process_message(&request.into_bytes())
        .await
        .unwrap()
}

#[tokio::test]
async fn an_accepted_abort_keeps_every_refusal_class_frame() {
    let messages = [
        "Invalid transaction status: cannot abort action: action with status 'unproven' records an acceptance and cannot be aborted",
        "Invalid transaction status: cannot abort action: transaction aa has a recorded acceptance (tracker word 'seen'); only a transaction never accepted can be retired",
        "Invalid transaction status: stored acceptance\0é\n\t",
    ];
    let mut mismatches = Vec::new();
    for class in WalletRefusalClass::ALL {
        for message in messages {
            let refusal = abort_frame(Error::WalletRefusal {
                class,
                message: message.into(),
            })
            .await;
            let mut acceptance = AbortAcceptance::new("reference", class, message);
            acceptance.txid = Some("aa".into());
            acceptance.status = Some("unproven".into());
            acceptance.accepting_word = Some("seen".into());
            let accepted = abort_frame(Error::AbortAccepted(Box::new(acceptance))).await;
            let (code, words) = match class.wire_code() {
                Some(code) => (code, message),
                None => (1, "Wallet operation failed"),
            };
            let mut expected = WireWriter::new();
            expected.write_u8(code).write_string(words).write_var_int(0);
            assert_eq!(refusal, expected.into_bytes(), "legacy frame for {class}");
            if accepted != refusal {
                mismatches.push(format!(
                    "{class}: accepted code {}, expected {code}; message {message:?}",
                    accepted[0]
                ));
            }
        }
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}

#[tokio::test]
async fn every_wallet_fault_family_keeps_the_wallet_error_frame() {
    let message = "storage at private/path failed\0é\n\t";
    let legacy = abort_frame(Error::WalletError(message.into())).await;
    let mut expected = WireWriter::new();
    expected
        .write_u8(1)
        .write_string("Wallet operation failed")
        .write_var_int(0);
    assert_eq!(legacy, expected.into_bytes());
    for family in [
        WalletFaultFamily::Transport,
        WalletFaultFamily::Service,
        WalletFaultFamily::Storage,
        WalletFaultFamily::Internal,
    ] {
        assert_eq!(
            abort_frame(Error::WalletFault(WalletFault::new(family, message))).await,
            legacy,
            "{family:?}"
        );
    }
}

#[test]
#[cfg(target_pointer_width = "64")]
fn an_accepted_abort_does_not_grow_the_unified_error() {
    // Measured on 964adff0 before either #439 variant, with all features.
    assert_eq!(std::mem::size_of::<Error>(), 56);
}
