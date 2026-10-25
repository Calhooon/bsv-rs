//! The processor's error frame, byte for byte the reference's (bsv-rs#202).
//!
//! `WalletWireProcessor.ts:2370-2396` at `ts-stack@edf6e03`: the error byte
//! is the error's own code when it lies in unsupportedAction to abortRefused
//! (2 to 8), else unknownError (1, `WalletError.ts:72`; `:2379-2384`); the
//! message is `error.message`, cut at `MAX_WIRE_ERROR_MESSAGE_BYTES` = 4096
//! (`:25`, `:2387-2393`); the stack an empty string, a varint 0 (`:2395-2396`).
//! This crate's `Error` carries no wallet code, so every frame is 1. Every
//! frame below is hand-assembled to those lines.
#![cfg(all(feature = "wallet", feature = "http"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

#[allow(dead_code)]
#[path = "support/fixtures/mod.rs"]
mod fixtures;

use bsv_rs::primitives::PrivateKey;
use bsv_rs::wallet::wire::{WalletCall, WalletWire, WalletWireProcessor, WalletWireTransceiver};
use bsv_rs::wallet::{Counterparty, Protocol, SecurityLevel, VerifyHmacArgs, VerifySignatureArgs};
use bsv_rs::{Error, TransportFault};
use fixtures::wallet::Stub;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

/// `:2379-2396`: the code, the message's length and bytes, the stack's 0.
fn reference_frame(code: u8, message: &[u8]) -> Vec<u8> {
    let mut frame = vec![code];
    match message.len() {
        n if n < 0xfd => frame.push(n as u8),
        n => {
            frame.push(0xfd);
            frame.extend((n as u16).to_le_bytes());
        }
    }
    frame.extend(message);
    frame.push(0);
    frame
}

/// A getHeight request from the fixtures' originator.
fn get_height_request() -> Vec<u8> {
    let originator = fixtures::wallet::ORIGINATOR.as_bytes();
    let mut request = vec![WalletCall::GetHeight.as_u8(), originator.len() as u8];
    request.extend(originator);
    request
}

/// The frame the processor writes when its wallet refuses getHeight.
async fn refusal_frame(error: Error) -> Vec<u8> {
    let mut stub = Stub::new(json!({}));
    stub.error = Some(error);
    WalletWireProcessor::new(stub)
        .process_message(&get_height_request())
        .await
        .unwrap()
}

/// A wire answering every message with one frame.
struct ReplyWire(Vec<u8>);

#[async_trait::async_trait]
impl WalletWire for ReplyWire {
    async fn transmit_to_wallet(&self, _message: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.0.clone())
    }
}

/// What this crate's transceiver reads from a frame (its reader unchanged).
async fn read_back(frame: Vec<u8>) -> Result<u64, Error> {
    WalletWireTransceiver::new(ReplyWire(frame))
        .get_height("test")
        .await
}

/// #202: a wallet's plain refusal is framed with unknownError (1) and its
/// bare words, never `wallet error: ` ahead of them; the transceiver reads
/// it back as the code and the words.
#[tokio::test]
async fn a_wallet_refusal_is_framed_with_code_one_and_its_bare_words() {
    let frame = refusal_frame(Error::WalletError("fixture refusal".into())).await;
    assert_eq!(
        hex::encode(&frame),
        hex::encode(reference_frame(1, b"fixture refusal"))
    );
    assert_eq!(
        read_back(frame).await,
        Err(Error::WalletError(
            "wallet error (code 1): fixture refusal".into()
        ))
    );
}

/// #202: this crate's `Error` carries no wallet code, so no refusal is framed
/// 2 to 8: the words that once chose 6 and 7 (`invalid parameter`,
/// `insufficient funds`) are a plain Error's words to the reference, framed 1.
/// A busy or transport answer writes its detail; another variant is this
/// crate's own sentence, its `Display`.
#[tokio::test]
async fn every_wallet_error_is_framed_as_unknown_error_in_its_own_words() {
    for (error, words) in [
        (
            Error::WalletError("invalid parameter: fixture".into()),
            "invalid parameter: fixture",
        ),
        (
            Error::WalletError("insufficient funds: fixture".into()),
            "insufficient funds: fixture",
        ),
        (
            Error::WalletBusy {
                detail: "store held".into(),
                retry_after_ms: Some(5),
            },
            "store held",
        ),
        (
            Error::WalletTransport {
                status: Some(503),
                detail: "no answer".into(),
            },
            "no answer",
        ),
        (
            Error::TransportFault {
                fault: TransportFault::NeverSent,
                status: None,
                detail: "connection refused".into(),
            },
            "connection refused",
        ),
        (
            Error::InvalidHex("zz".into()),
            "invalid hex string: zz",
        ),
        (
            Error::HmacMinimalLengthKey {
                leading_zero_bytes: 1,
            },
            "HMAC is not valid: the tag was made under a minimal-length key (the sender drops the 1 leading zero byte(s) of the 32-byte X coordinate; BRC-56)",
        ),
    ] {
        let frame = refusal_frame(error.clone()).await;
        assert_eq!(
            hex::encode(&frame),
            hex::encode(reference_frame(1, words.as_bytes())),
            "{error:?}"
        );
        assert_eq!(
            read_back(frame).await,
            Err(Error::WalletError(format!("wallet error (code 1): {words}"))),
            "{error:?}"
        );
    }
}

/// #202: the processor's own refusal of a request (a truncated frame) is its
/// sentence, framed 1, the wallet never called.
#[tokio::test]
async fn the_processors_own_refusal_is_framed_with_code_one() {
    let stub = Stub::new(json!({}));
    let observed = stub.observed.clone();
    let frame = WalletWireProcessor::new(stub)
        .process_message(&[WalletCall::GetHeight.as_u8()])
        .await
        .unwrap();
    assert!(observed.lock().unwrap().is_none());
    assert_eq!(
        hex::encode(&frame),
        hex::encode(reference_frame(
            1,
            b"reader underflow: need 1 bytes, only 0 available"
        ))
    );
}

/// Records the processor's last frame on its way to the transceiver.
struct TapeWire {
    processor: WalletWireProcessor<Stub>,
    tape: Arc<Mutex<Vec<u8>>>,
}

#[async_trait::async_trait]
impl WalletWire for TapeWire {
    async fn transmit_to_wallet(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let frame = self.processor.process_message(message).await?;
        *self.tape.lock().unwrap() = frame.clone();
        Ok(frame)
    }
}

fn taped(reply: Value) -> (WalletWireTransceiver<TapeWire>, Arc<Mutex<Vec<u8>>>) {
    let tape = Arc::default();
    let wire = TapeWire {
        processor: WalletWireProcessor::new(Stub::new(reply)),
        tape: Arc::clone(&tape),
    };
    (WalletWireTransceiver::new(wire), tape)
}

fn protocol() -> Protocol {
    Protocol::new(SecurityLevel::App, "error frames")
}

/// #202: the three false verdicts are the reference's throws, bare: `HMAC is
/// not valid` (`WalletWireProcessor.ts:1520`), `Signature is not valid`
/// (`:1597`), `Wallet did not affirmatively authenticate` (`:1637`), plain
/// Errors framed 1; the transceiver reads each back as the code and the words.
#[tokio::test]
async fn the_three_false_verdicts_are_framed_in_the_references_words() {
    let (client, tape) = taped(json!({"valid": false}));
    let hmac = client
        .verify_hmac(
            VerifyHmacArgs {
                data: vec![1, 2, 3],
                hmac: [7; 32],
                protocol_id: protocol(),
                key_id: "frame-1".into(),
                counterparty: Some(Counterparty::Self_),
            },
            "test",
        )
        .await
        .map(|r| r.valid);
    let hmac_frame = tape.lock().unwrap().clone();

    let signature_der = PrivateKey::random().sign(&[9; 32]).unwrap().to_der();
    let signature = client
        .verify_signature(
            VerifySignatureArgs {
                data: Some(vec![1, 2, 3]),
                hash_to_directly_verify: None,
                signature: signature_der,
                protocol_id: protocol(),
                key_id: "frame-2".into(),
                counterparty: Some(Counterparty::Self_),
                for_self: None,
            },
            "test",
        )
        .await
        .map(|r| r.valid);
    let signature_frame = tape.lock().unwrap().clone();

    let (client, tape) = taped(json!({"authenticated": false}));
    let authenticated = client.wait_for_authentication("test").await;
    let authenticated_frame = tape.lock().unwrap().clone();

    for (result, frame, words) in [
        (hmac, hmac_frame, "HMAC is not valid"),
        (signature, signature_frame, "Signature is not valid"),
        (
            authenticated,
            authenticated_frame,
            "Wallet did not affirmatively authenticate",
        ),
    ] {
        assert_eq!(
            hex::encode(&frame),
            hex::encode(reference_frame(1, words.as_bytes())),
            "{words}"
        );
        assert_eq!(
            result,
            Err(Error::WalletError(format!(
                "wallet error (code 1): {words}"
            ))),
            "{words}"
        );
    }
}

/// #202: a message past 4096 bytes is cut at 4096 (`:2388-2391`), its length
/// `fd 00 10`; the transceiver reads the 4096 bytes back.
#[tokio::test]
async fn a_message_past_4096_bytes_is_cut_at_4096() {
    let long = "a".repeat(5000);
    let frame = refusal_frame(Error::WalletError(long.clone())).await;
    assert_eq!(&frame[..4], &[1, 0xfd, 0x00, 0x10]);
    assert_eq!(
        hex::encode(&frame),
        hex::encode(reference_frame(1, &long.as_bytes()[..4096]))
    );
    assert_eq!(
        read_back(frame).await,
        Err(Error::WalletError(format!(
            "wallet error (code 1): {}",
            &long[..4096]
        )))
    );
}

/// #202: the cut is at the byte, as the reference's `subarray` cuts it, even
/// inside a character: `é` at bytes 4095-4096 leaves `c3` last, and the
/// transceiver refuses the frame's invalid UTF-8 as the reference's client
/// does (`toUTF8Strict`, `WalletWireTransceiver.ts:143`).
#[tokio::test]
async fn the_cut_is_at_the_byte_inside_a_character() {
    let long = format!("{}é", "a".repeat(4095));
    let frame = refusal_frame(Error::WalletError(long.clone())).await;
    assert_eq!(
        hex::encode(&frame),
        hex::encode(reference_frame(1, &long.as_bytes()[..4096]))
    );
    assert_eq!(frame[frame.len() - 2..], [0xc3, 0]);
    assert!(read_back(frame).await.is_err());
}

/// #202: the stack field is an empty string, a varint 0 and nothing after it
/// (`:2395-2396`): an empty message is framed `01 00 00`.
#[tokio::test]
async fn the_stack_field_is_a_varint_zero() {
    let frame = refusal_frame(Error::WalletError(String::new())).await;
    assert_eq!(frame, [1, 0, 0]);
    assert_eq!(
        read_back(frame).await,
        Err(Error::WalletError("wallet error (code 1): ".into()))
    );
}
