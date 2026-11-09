//! #604: `AbortAcceptance` carries a typed `kind`, so a host tells the
//! abort-on-chain refusal by type, not by its text; the wire frame, the
//! display text, the class and the size of `Error` stay unchanged.
#![cfg(all(feature = "wallet", feature = "http"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: fixture assertions.

#[allow(dead_code)]
#[path = "support/fixtures/mod.rs"]
mod fixtures;

use bsv_rs::wallet::wire::{WalletCall, WalletWireProcessor, WireWriter};
use bsv_rs::{AbortAcceptance, AbortKind, Error, WalletRefusalClass};
use fixtures::wallet::Stub;
use serde_json::json;

const ON_CHAIN: &str = "Invalid transaction status: cannot abort action: transaction aa is mined";
const KINDS: [AbortKind; 3] = [
    AbortKind::OnChain,
    AbortKind::AcceptedInStore,
    AbortKind::Other,
];

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

fn record(class: WalletRefusalClass, kind: AbortKind) -> AbortAcceptance {
    let mut record = AbortAcceptance::new("reference", class, ON_CHAIN);
    record.txid = Some("aa".into());
    record.status = Some("unproven".into());
    record.kind = kind;
    record
}

/// How a host reads the record: by the kind alone.
fn is_on_chain(error: &Error) -> bool {
    matches!(error, Error::AbortAccepted(a) if a.kind == AbortKind::OnChain)
}

#[test]
fn a_new_record_leaves_the_kind_at_other_604() {
    let record = AbortAcceptance::new("reference", WalletRefusalClass::InvalidOperation, ON_CHAIN);
    assert_eq!(record.kind, AbortKind::Other);
    assert_eq!(AbortKind::default(), AbortKind::Other);
    assert!(!is_on_chain(&Error::AbortAccepted(Box::new(record))));
}

#[test]
fn an_abort_of_a_mined_transaction_is_told_by_kind_not_text_604() {
    let on_chain = Error::AbortAccepted(Box::new(record(
        WalletRefusalClass::InvalidOperation,
        AbortKind::OnChain,
    )));
    assert!(is_on_chain(&on_chain));
    assert_eq!(on_chain.to_string().as_bytes(), ON_CHAIN.as_bytes());
    // The same text under another kind is not on chain: the text decides nothing.
    for kind in [AbortKind::AcceptedInStore, AbortKind::Other] {
        let other =
            Error::AbortAccepted(Box::new(record(WalletRefusalClass::InvalidOperation, kind)));
        assert!(!is_on_chain(&other), "{kind:?}");
        assert_eq!(other.to_string(), on_chain.to_string());
    }
}

#[tokio::test]
async fn the_kind_moves_no_wire_byte_604() {
    for class in [
        WalletRefusalClass::InvalidOperation,
        WalletRefusalClass::InvalidParameter,
    ] {
        let refusal = abort_frame(Error::WalletRefusal {
            class,
            message: ON_CHAIN.into(),
        })
        .await;
        let other = abort_frame(Error::AbortAccepted(Box::new(record(
            class,
            AbortKind::Other,
        ))))
        .await;
        assert_eq!(other, refusal, "{class}");
        for kind in KINDS {
            let frame = abort_frame(Error::AbortAccepted(Box::new(record(class, kind)))).await;
            assert_eq!(frame, other, "{class} {kind:?}");
        }
    }
}

#[test]
fn the_kind_is_part_of_equality_604() {
    for a in KINDS {
        let left = record(WalletRefusalClass::InvalidOperation, a);
        assert_eq!(left, left.clone());
        for b in KINDS {
            let right = record(WalletRefusalClass::InvalidOperation, b);
            assert_eq!(left == right, a == b, "{a:?} {b:?}");
            assert_eq!(
                Error::AbortAccepted(Box::new(left.clone()))
                    == Error::AbortAccepted(Box::new(right)),
                a == b
            );
        }
    }
    #[cfg(target_pointer_width = "64")]
    assert_eq!(std::mem::size_of::<Error>(), 56);
}
