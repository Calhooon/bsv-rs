//! The `tracing` sink at the processor's wrapper (bsv-rs#212).
//!
//! The keeper's division on #202: an un-coded wallet error is framed as the
//! reference's `Wallet operation failed` (`WalletWireProcessor.ts:2417` at
//! `ts-stack@edf6e03`), so the wallet's words leave the wire; with the
//! `tracing` feature they go to one `warn` event at `invoke_wallet`, with the
//! call's name. The reference's processor logs nothing there; the frame is
//! the same bytes with the feature on or off (`tests/wire_error_frames.rs`
//! pins them without it). The collector below is the test's own
//! `tracing::Subscriber`: no `tracing-subscriber` dev-dependency.
#![cfg(all(feature = "wallet", feature = "http", feature = "tracing"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

#[allow(dead_code)]
#[path = "support/fixtures/mod.rs"]
mod fixtures;

use bsv_rs::wallet::wire::{WalletCall, WalletWireProcessor};
use bsv_rs::{Error, WalletRefusalClass};
use fixtures::wallet::Stub;
use serde_json::json;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::sync::{Arc, Mutex};
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Level, Metadata, Subscriber};

/// One event as the collector saw it: its level and its fields as text.
#[derive(Debug, Clone)]
struct Seen {
    level: Level,
    fields: BTreeMap<String, String>,
}

/// Collects every event; spans are not this sink's concern.
#[derive(Clone, Default)]
struct Collector(Arc<Mutex<Vec<Seen>>>);

struct Fields<'a>(&'a mut BTreeMap<String, String>);

impl Visit for Fields<'_> {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().to_string(), value.to_string());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        self.0
            .insert(field.name().to_string(), format!("{value:?}"));
    }
}

impl Subscriber for Collector {
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _span: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _span: &Id, _values: &Record<'_>) {}

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut fields = BTreeMap::new();
        event.record(&mut Fields(&mut fields));
        self.0.lock().unwrap().push(Seen {
            level: *event.metadata().level(),
            fields,
        });
    }

    fn enter(&self, _span: &Id) {}

    fn exit(&self, _span: &Id) {}
}

/// The frame for every un-coded wallet error (`:2417`, framed by
/// `:2379-2396`): `01`, `0x17`, `Wallet operation failed`, `00`.
const WALLET_OPERATION_FAILED_FRAME: &str = "011757616c6c6574206f7065726174696f6e206661696c656400";

/// A request of `call` with no arguments from the fixtures' originator.
fn request(call: WalletCall) -> Vec<u8> {
    let originator = fixtures::wallet::ORIGINATOR.as_bytes();
    let mut request = vec![call.as_u8(), originator.len() as u8];
    request.extend(originator);
    request
}

/// The frame the processor writes for `message`, and the events it raised.
async fn frame_and_events(stub: Stub, message: &[u8]) -> (Vec<u8>, Vec<Seen>) {
    let collector = Collector::default();
    let seen = collector.0.clone();
    let _guard = tracing::dispatcher::set_default(&tracing::Dispatch::new(collector));
    let frame = WalletWireProcessor::new(stub)
        .process_message(message)
        .await
        .unwrap();
    let events = seen.lock().unwrap().clone();
    (frame, events)
}

fn refusing(error: Error) -> Stub {
    let mut stub = Stub::new(json!({}));
    stub.error = Some(error);
    stub
}

/// #212: an un-coded wallet error raises exactly one `warn` event carrying
/// the call's name and the wallet's `Display`, the words the frame drops.
#[tokio::test]
async fn an_uncoded_wallet_error_raises_one_event_with_the_call_and_the_wallets_words() {
    let error = Error::WalletError("store at /home/wallet/keys.db is locked".into());
    let (frame, events) =
        frame_and_events(refusing(error.clone()), &request(WalletCall::GetHeight)).await;
    assert_eq!(hex::encode(&frame), WALLET_OPERATION_FAILED_FRAME);
    assert_eq!(events.len(), 1, "{events:?}");
    let event = &events[0];
    assert_eq!(event.level, Level::WARN);
    assert_eq!(event.fields["call"], "getHeight");
    assert_eq!(event.fields["error"], error.to_string());
    assert_eq!(
        event.fields["message"],
        "wallet error framed as Wallet operation failed"
    );
    assert_eq!(event.fields.len(), 3, "{:?}", event.fields);
}

/// #212: the call named is the call made (a second call, a second variant).
#[tokio::test]
async fn the_event_names_the_call_whose_wallet_refused() {
    let error = Error::WalletBusy {
        detail: "store held".into(),
        retry_after_ms: Some(5),
    };
    let (frame, events) = frame_and_events(
        refusing(error.clone()),
        &request(WalletCall::IsAuthenticated),
    )
    .await;
    assert_eq!(hex::encode(&frame), WALLET_OPERATION_FAILED_FRAME);
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].fields["call"], "isAuthenticated");
    assert_eq!(events[0].fields["error"], error.to_string());
}

/// #212: the processor's own refusal (a truncated frame, raised outside the
/// wrapper, framed in its own words) raises no event; the wallet is never
/// called.
#[tokio::test]
async fn the_processors_own_refusal_raises_no_event() {
    let stub = Stub::new(json!({}));
    let observed = stub.observed.clone();
    let (frame, events) = frame_and_events(stub, &[WalletCall::GetHeight.as_u8()]).await;
    assert!(observed.lock().unwrap().is_none());
    assert_eq!(frame[0], 1);
    assert!(events.is_empty(), "{events:?}");
}

/// #212: a success raises no event.
#[tokio::test]
async fn a_success_raises_no_event() {
    let (frame, events) = frame_and_events(
        Stub::new(json!({ "height": 850000 })),
        &request(WalletCall::GetHeight),
    )
    .await;
    assert_eq!(frame[0], 0);
    assert!(events.is_empty(), "{events:?}");
}

/// #212: the wire bytes are the same with a collector listening and with
/// none (the frame `tests/wire_error_frames.rs` pins with the feature off).
#[tokio::test]
async fn the_frame_is_the_same_with_and_without_a_listener() {
    let error = Error::WalletError("anything".into());
    let (heard, _) =
        frame_and_events(refusing(error.clone()), &request(WalletCall::GetHeight)).await;
    let unheard = WalletWireProcessor::new(refusing(error))
        .process_message(&request(WalletCall::GetHeight))
        .await
        .unwrap();
    assert_eq!(heard, unheard);
    assert_eq!(hex::encode(&unheard), WALLET_OPERATION_FAILED_FRAME);
}

/// #137: a wallet's refusal keeps its words and its class's code on the wire,
/// so the event carries no words: the call's name and the class's reference
/// name, one `warn` event; the frame the coded one (`07`, the words, `00`).
#[tokio::test]
async fn a_wallet_refusal_raises_one_event_with_the_call_and_its_class() {
    let error = Error::WalletRefusal {
        class: WalletRefusalClass::InsufficientFunds,
        message: "short".into(),
    };
    let (frame, events) = frame_and_events(refusing(error), &request(WalletCall::GetHeight)).await;
    assert_eq!(hex::encode(&frame), "070573686f727400");
    assert_eq!(events.len(), 1, "{events:?}");
    let event = &events[0];
    assert_eq!(event.level, Level::WARN);
    assert_eq!(event.fields["call"], "getHeight");
    assert_eq!(event.fields["class"], "WERR_INSUFFICIENT_FUNDS");
    assert_eq!(
        event.fields["message"],
        "wallet refusal framed with its code"
    );
    assert_eq!(event.fields.len(), 3, "{:?}", event.fields);
}

/// #137: a refusal whose class has no SDK code is framed as `Wallet operation
/// failed` (`:2417`), so its class and its words go to the one `warn` event
/// beside the call's name.
#[tokio::test]
async fn an_uncoded_refusal_raises_one_event_with_its_class_and_words() {
    let error = Error::WalletRefusal {
        class: WalletRefusalClass::Unauthorized,
        message: "Access is denied due to an authorization error.".into(),
    };
    let (frame, events) = frame_and_events(refusing(error), &request(WalletCall::GetHeight)).await;
    assert_eq!(hex::encode(&frame), WALLET_OPERATION_FAILED_FRAME);
    assert_eq!(events.len(), 1, "{events:?}");
    let event = &events[0];
    assert_eq!(event.level, Level::WARN);
    assert_eq!(event.fields["call"], "getHeight");
    assert_eq!(event.fields["class"], "WERR_UNAUTHORIZED");
    assert_eq!(
        event.fields["error"],
        "Access is denied due to an authorization error."
    );
    assert_eq!(
        event.fields["message"],
        "wallet error framed as Wallet operation failed"
    );
    assert_eq!(event.fields.len(), 4, "{:?}", event.fields);
}
