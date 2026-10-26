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

/// One row: the name, the SDK key, the reference's code, the wire code.
type Row = (&'static str, Option<&'static str>, Option<u8>, Option<u8>);

/// The class table at `ts-stack@edf6e03`: the SDK's `walletErrors`
/// (`packages/sdk/src/wallet/WalletError.ts:73-79`, code 1 `unknownError` at
/// `:72` left out: it is `Error::WalletError`), its `WERR_*` names for 5, 6, 7
/// (`WERR_REVIEW_ACTIONS.ts:8`, `WERR_INVALID_PARAMETER.ts:6`,
/// `WERR_INSUFFICIENT_FUNDS.ts:7`), then every class of the wallet-toolbox's
/// `packages/wallet/wallet-toolbox/src/sdk/WERR_errors.ts` in its file's
/// order, each row under its line.
const REFERENCE_TABLE: [Row; 20] = [
    // WalletError.ts:73
    (
        "unsupportedAction",
        Some("unsupportedAction"),
        Some(2),
        Some(2),
    ),
    // :74
    ("invalidHmac", Some("invalidHmac"), Some(3), Some(3)),
    // :75
    (
        "invalidSignature",
        Some("invalidSignature"),
        Some(4),
        Some(4),
    ),
    // :76; WERR_errors.ts:260,278
    (
        "WERR_REVIEW_ACTIONS",
        Some("reviewActions"),
        Some(5),
        Some(5),
    ),
    // :77; WERR_errors.ts:100,110
    (
        "WERR_INVALID_PARAMETER",
        Some("invalidParameter"),
        Some(6),
        Some(6),
    ),
    // :78; WERR_errors.ts:208,225
    (
        "WERR_INSUFFICIENT_FUNDS",
        Some("insufficientFunds"),
        Some(7),
        Some(7),
    ),
    // :79
    ("abortRefused", Some("abortRefused"), Some(8), Some(8)),
    // WERR_errors.ts:8
    ("WERR_NOT_IMPLEMENTED", None, None, None),
    // :19
    ("WERR_INTERNAL", None, None, None),
    // :30
    ("WERR_INVALID_OPERATION", None, None, None),
    // :41
    ("WERR_UTXO_REVIEW_INCONCLUSIVE", None, None, None),
    // :68, exported at :84
    ("WERR_ACTION_BATCH_STATE", None, None, None),
    // :89
    ("WERR_BROADCAST_UNAVAILABLE", None, None, None),
    // :121, the code at :136
    ("WERR_INVALID_MERKLE_ROOT", None, Some(8), None),
    // :150
    ("WERR_MISSING_PARAMETER", None, None, None),
    // :165
    ("WERR_BAD_REQUEST", None, None, None),
    // :174
    ("WERR_NETWORK_CHAIN", None, None, None),
    // :183
    ("WERR_UNAUTHORIZED", None, None, None),
    // :192
    ("WERR_NOT_ACTIVE", None, None, None),
    // :232
    ("WERR_INVALID_PUBLIC_KEY", None, None, None),
];

/// `Wallet operation failed`, code 1 (`WalletWireProcessor.ts:2417`).
const WALLET_OPERATION_FAILED: &[u8] = b"Wallet operation failed";

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

/// The class table is the reference's: each class's name, SDK key, code and
/// wire code, in the table's order; `from_name` the inverse of the name and
/// the key, `from_code` the SDK's 2 to 8 only (8 `abortRefused`).
#[test]
fn each_class_carries_the_references_name_and_code() {
    let classes: Vec<_> = WalletRefusalClass::ALL
        .iter()
        .map(|class| {
            (
                class.name(),
                class.code_name(),
                class.code(),
                class.wire_code(),
            )
        })
        .collect();
    assert_eq!(classes, REFERENCE_TABLE);
    for class in WalletRefusalClass::ALL {
        assert_eq!(WalletRefusalClass::from_name(class.name()), Some(class));
        if let Some(key) = class.code_name() {
            assert_eq!(WalletRefusalClass::from_name(key), Some(class));
        }
        if let Some(code) = class.wire_code() {
            assert_eq!(WalletRefusalClass::from_code(code), Some(class));
        }
        assert_eq!(class.to_string(), class.name());
    }
    // The collision is the reference's: the toolbox's merkle-root 8 reads
    // back as the SDK's abortRefused
    assert_eq!(
        WalletRefusalClass::from_code(8),
        Some(WalletRefusalClass::AbortRefused)
    );
    for code in [0, 1, 9, 20, 255] {
        assert_eq!(WalletRefusalClass::from_code(code), None, "{code}");
    }
    for name in [
        "",
        "WERR_UNKNOWN",
        "unknownError",
        "werr_internal",
        "INSUFFICIENT_FUNDS",
    ] {
        assert_eq!(WalletRefusalClass::from_name(name), None, "{name}");
    }
}

/// The toolbox's table read as data, when the `ts-stack` tree is beside the
/// crate (`$BSV_CONFORMANCE_DIR/..`, default `../ts-stack`): every `WERR_*`
/// name a constructor passes to `super` is a class, and every class named
/// `WERR_*` is in the file. Skipped loudly without the tree.
#[test]
fn every_werr_class_of_the_toolbox_file_is_a_class() {
    let root = std::env::var("BSV_CONFORMANCE_DIR")
        .map(|dir| std::path::PathBuf::from(dir).join(".."))
        .unwrap_or_else(|_| {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../ts-stack")
        });
    let file = root.join("packages/wallet/wallet-toolbox/src/sdk/WERR_errors.ts");
    let Ok(source) = std::fs::read_to_string(&file) else {
        eprintln!(
            "SKIP: {} not found; set BSV_CONFORMANCE_DIR",
            file.display()
        );
        return;
    };
    let mut names: Vec<&str> = source
        .split("super(")
        .skip(1)
        .filter_map(|call| {
            let call = call.trim_start().strip_prefix('\'')?;
            Some(&call[..call.find('\'')?])
        })
        .collect();
    names.sort_unstable();
    let mut ours: Vec<&str> = WalletRefusalClass::ALL
        .iter()
        .map(|class| class.name())
        .filter(|name| name.starts_with("WERR_"))
        .collect();
    ours.sort_unstable();
    assert_eq!(names, ours);
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

/// #137: a wallet's refusal with an SDK code reaches the frame with that
/// code and its words, byte for byte the reference's (`#invokeWallet` keeps
/// it, `:2407-2416`; the catch writes it, `:2379-2396`); a class with no SDK
/// code is framed as the reference frames a toolbox `WERR_*` (its `code` its
/// name, no integer): `Wallet operation failed`, code 1 (`:2417`), the
/// toolbox's merkle-root 8 among them.
#[tokio::test]
async fn a_wallet_refusal_is_framed_with_its_sdk_code_or_as_wallet_operation_failed() {
    for class in WalletRefusalClass::ALL {
        let message = format!("refused as {class}");
        let frame = refusing(refusal(class))
            .process_message(&get_height_request())
            .await
            .unwrap();
        let expected = match class.wire_code() {
            Some(code) => reference_frame(code, message.as_bytes()),
            None => reference_frame(1, WALLET_OPERATION_FAILED),
        };
        assert_eq!(hex::encode(&frame), hex::encode(expected), "{class}");
    }
}

/// #137: the transceiver reads a frame coded 2 to 8 back as the typed class
/// and the words (`WalletWireTransceiver.ts:153`), end to end through the
/// processor; a class with no SDK code comes back as the un-coded error.
#[tokio::test]
async fn the_transceiver_reads_a_coded_frame_back_as_its_class() {
    for class in WalletRefusalClass::ALL {
        let result = WalletWireTransceiver::new(Loop(refusing(refusal(class))))
            .get_height("test")
            .await;
        let expected = match class.wire_code() {
            Some(_) => refusal(class),
            None => Error::WalletError("wallet error (code 1): Wallet operation failed".into()),
        };
        assert_eq!(result, Err(expected), "{class}");
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
