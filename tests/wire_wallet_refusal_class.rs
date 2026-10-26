//! A wallet's refusal carries its class (bsv-rs#137).
//!
//! The reference's `WalletError` carries a code beside its words
//! (`ts-stack@edf6e03` `packages/sdk/src/wallet/WalletError.ts:3-8`), its
//! table `walletErrors` (`:71-80`); its wire processor keeps a wallet's code
//! 2 to 8 and its words (`#invokeWallet`, `WalletWireProcessor.ts:2407-2416`,
//! framed by `:2379-2396`), and its transceiver throws a `WalletError` with
//! the frame's code (`WalletWireTransceiver.ts:153`). `Error::WalletRefusal`
//! is that error here: the frame carries the class's code and the message,
//! and the transceiver reads a frame coded 2 to 8 back as the typed class.
#![cfg(all(feature = "wallet", feature = "http"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

#[allow(dead_code)]
#[path = "support/fixtures/mod.rs"]
mod fixtures;

use bsv_rs::wallet::wire::{WalletCall, WalletWire, WalletWireProcessor, WalletWireTransceiver};
use bsv_rs::{Error, WalletRefusalClass};
use fixtures::wallet::Stub;
use serde_json::json;

/// `walletErrors` at `ts-stack@edf6e03` `WalletError.ts:72-79`, line by line,
/// code 1 (`unknownError`, `:72`) left out: it is `Error::WalletError`.
const REFERENCE_TABLE: [(&str, u8); 7] = [
    ("unsupportedAction", 2),
    ("invalidHmac", 3),
    ("invalidSignature", 4),
    ("reviewActions", 5),
    ("invalidParameter", 6),
    ("insufficientFunds", 7),
    ("abortRefused", 8),
];

fn refusal(class: WalletRefusalClass) -> Error {
    Error::WalletRefusal {
        class,
        message: format!("refused as {class}"),
    }
}

/// `:2379-2396`: the code, the message's length and bytes, the stack's 0.
fn reference_frame(code: u8, message: &[u8]) -> Vec<u8> {
    let mut frame = vec![code, message.len() as u8];
    frame.extend(message);
    frame.push(0);
    frame
}

fn get_height_request() -> Vec<u8> {
    let originator = fixtures::wallet::ORIGINATOR.as_bytes();
    let mut request = vec![WalletCall::GetHeight.as_u8(), originator.len() as u8];
    request.extend(originator);
    request
}

fn refusing(error: Error) -> WalletWireProcessor<Stub> {
    let mut stub = Stub::new(json!({}));
    stub.error = Some(error);
    WalletWireProcessor::new(stub)
}

/// The transceiver over the processor, in memory.
struct Loop(WalletWireProcessor<Stub>);

#[async_trait::async_trait]
impl WalletWire for Loop {
    async fn transmit_to_wallet(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        self.0.process_message(message).await
    }
}

/// A wire answering every message with one frame.
struct ReplyWire(Vec<u8>);

#[async_trait::async_trait]
impl WalletWire for ReplyWire {
    async fn transmit_to_wallet(&self, _message: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.0.clone())
    }
}

/// The class table is the reference's: each class's code and name, in the
/// order of the code, and `from_code` its inverse on 2 to 8 only.
#[test]
fn each_class_carries_the_references_code_and_name() {
    let classes: Vec<_> = WalletRefusalClass::ALL
        .iter()
        .map(|class| (class.name(), class.code()))
        .collect();
    assert_eq!(classes, REFERENCE_TABLE);
    for class in WalletRefusalClass::ALL {
        assert_eq!(WalletRefusalClass::from_code(class.code()), Some(class));
        assert_eq!(class.to_string(), class.name());
    }
    for code in [0, 1, 9, 20, 255] {
        assert_eq!(WalletRefusalClass::from_code(code), None, "{code}");
    }
}

/// `Display` is the message alone, the class the typed field; `Clone` and
/// `Eq` as the enum's, the class part of equality.
#[test]
fn a_refusal_displays_its_words_and_compares_by_class_and_words() {
    let error = Error::WalletRefusal {
        class: WalletRefusalClass::InsufficientFunds,
        message: "Insufficient funds in the available inputs".into(),
    };
    assert_eq!(
        error.to_string(),
        "Insufficient funds in the available inputs"
    );
    assert_eq!(error.clone(), error);
    assert_ne!(
        error,
        Error::WalletRefusal {
            class: WalletRefusalClass::InvalidParameter,
            message: "Insufficient funds in the available inputs".into(),
        }
    );
    assert_ne!(
        error,
        Error::WalletError("Insufficient funds in the available inputs".into())
    );
    assert_eq!(error.transport_fault(), None);
}

/// #137: a wallet's refusal reaches the frame with its class's code and its
/// words, byte for byte the reference's (`#invokeWallet` keeps it,
/// `:2407-2416`; the catch writes it, `:2379-2396`).
#[tokio::test]
async fn a_wallet_refusal_is_framed_with_its_class_code_and_words() {
    for class in WalletRefusalClass::ALL {
        let message = format!("refused as {class}");
        let frame = refusing(refusal(class))
            .process_message(&get_height_request())
            .await
            .unwrap();
        assert_eq!(
            hex::encode(&frame),
            hex::encode(reference_frame(class.code(), message.as_bytes())),
            "{class}"
        );
    }
}

/// #137: the transceiver reads a frame coded 2 to 8 back as the typed class
/// and the words (`WalletWireTransceiver.ts:153`), end to end through the
/// processor.
#[tokio::test]
async fn the_transceiver_reads_a_coded_frame_back_as_its_class() {
    for class in WalletRefusalClass::ALL {
        let result = WalletWireTransceiver::new(Loop(refusing(refusal(class))))
            .get_height("test")
            .await;
        assert_eq!(result, Err(refusal(class)), "{class}");
    }
}

/// Code 1 and a code no class of the reference's names stay the un-coded
/// error, its code in the words, as before #137.
#[tokio::test]
async fn an_unclassed_code_is_read_back_as_before() {
    for code in [1u8, 9, 255] {
        let result = WalletWireTransceiver::new(ReplyWire(reference_frame(code, b"words")))
            .get_height("test")
            .await;
        assert_eq!(
            result,
            Err(Error::WalletError(format!(
                "wallet error (code {code}): words"
            ))),
            "{code}"
        );
    }
}

/// A refusal's words are cut at 4096 bytes as every frame's are (`:2387-2393`).
#[tokio::test]
async fn a_long_refusal_is_cut_at_4096_bytes() {
    let frame = refusing(Error::WalletRefusal {
        class: WalletRefusalClass::InvalidParameter,
        message: "a".repeat(5000),
    })
    .process_message(&get_height_request())
    .await
    .unwrap();
    assert_eq!(&frame[..4], &[6, 0xfd, 0x00, 0x10]);
    assert_eq!(frame.len(), 4 + 4096 + 1);
}
