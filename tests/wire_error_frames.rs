//! The processor's error frame, byte for byte the reference's (bsv-rs#202).
//!
//! `WalletWireProcessor.ts:2370-2396` at `ts-stack@edf6e03`: the error byte
//! is the error's own code when it lies in unsupportedAction to abortRefused
//! (2 to 8), else unknownError (1, `WalletError.ts:72`; `:2379-2384`); the
//! message is `error.message`, cut at `MAX_WIRE_ERROR_MESSAGE_BYTES` = 4096
//! (`:25`, `:2387-2393`); the stack an empty string, a varint 0 (`:2395-2396`).
//! A wallet's error passes through `#invokeWallet` ahead of the catch (`:2402-2418`): an
//! explicit wallet error with a code 2 to 8 keeps its words and code, every
//! other is replaced by `Wallet operation failed`, code 1 (`:2417`). This
//! crate's `Error` carries no wallet code (#137), so every frame is 1 and
//! every wallet error the constant; the processor's own errors (its reading,
//! the three false verdicts, raised outside the wrapper) keep their words. A
//! wallet's `aborted: false` is the reference's refusal, code 8 (`:797-804`),
//! read back as `aborted: false` (`WalletWireTransceiver.ts:337`; #206).
//! Every frame below is hand-assembled to those lines.
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

/// The reference's frame for every un-coded wallet error (`:2417`, framed
/// by `:2379-2396`): `01`, `0x17`, `Wallet operation failed`, `00`.
const WALLET_OPERATION_FAILED_FRAME: &str = "011757616c6c6574206f7065726174696f6e206661696c656400";

/// #202, the keeper's division: an un-coded wallet error is the reference's
/// constant, `Wallet operation failed`, code 1 (`#invokeWallet`, `:2417`);
/// the wallet's own words never reach the wire. The transceiver reads it back
/// as the code and the constant.
#[tokio::test]
async fn an_uncoded_wallet_error_is_framed_as_wallet_operation_failed() {
    assert_eq!(
        hex::encode(reference_frame(1, b"Wallet operation failed")),
        WALLET_OPERATION_FAILED_FRAME
    );
    let frame = refusal_frame(Error::WalletError("anything".into())).await;
    assert_eq!(hex::encode(&frame), WALLET_OPERATION_FAILED_FRAME);
    assert_eq!(
        read_back(frame).await,
        Err(Error::WalletError(
            "wallet error (code 1): Wallet operation failed".into()
        ))
    );
}

/// #202: every variant a wallet returns is the same constant: the words that
/// once chose 6 and 7, a busy or transport answer, a crate sentence, a
/// validation refusal raised inside the wallet, a 5000-byte message. None
/// carries a code 2 to 8 (#137), so none is explicit.
#[tokio::test]
async fn every_wallet_error_variant_is_framed_as_the_same_constant() {
    for error in [
        Error::WalletError("invalid parameter: fixture".into()),
        Error::WalletError("insufficient funds: fixture".into()),
        Error::WalletError("a".repeat(5000)),
        Error::WalletError(String::new()),
        Error::WalletBusy {
            detail: "store held".into(),
            retry_after_ms: Some(5),
        },
        Error::WalletTransport {
            status: Some(503),
            detail: "no answer".into(),
        },
        Error::TransportFault {
            fault: TransportFault::NeverSent,
            status: None,
            detail: "connection refused".into(),
        },
        Error::InvalidHex("zz".into()),
        Error::ProtocolValidationError("/home/wallet/keys.db".into()),
        Error::InvalidCounterparty("fixture".into()),
        Error::HmacMinimalLengthKey {
            leading_zero_bytes: 1,
        },
    ] {
        let frame = refusal_frame(error.clone()).await;
        assert_eq!(
            hex::encode(&frame),
            WALLET_OPERATION_FAILED_FRAME,
            "{error:?}"
        );
    }
}

/// #202: a wallet erring on verifyHmac (an `Err`, not a false verdict) is
/// inside the wrapper (`:1517-1519`): the constant, where its false verdict
/// below is the processor's own throw.
#[tokio::test]
async fn a_wallet_erring_on_a_verdict_call_is_the_constant() {
    let mut stub = Stub::new(json!({}));
    stub.error = Some(Error::WalletError("key store locked".into()));
    let client = WalletWireTransceiver::new(TapeWire {
        processor: WalletWireProcessor::new(stub),
        tape: Arc::default(),
    });
    let tape = Arc::clone(&client.wire().tape);
    let result = client
        .verify_hmac(
            VerifyHmacArgs {
                data: vec![1, 2, 3],
                hmac: [7; 32],
                protocol_id: protocol(),
                key_id: "frame-0".into(),
                counterparty: Some(Counterparty::Self_),
                ..Default::default()
            },
            "test",
        )
        .await
        .map(|r| r.valid);
    assert_eq!(
        hex::encode(&*tape.lock().unwrap()),
        WALLET_OPERATION_FAILED_FRAME
    );
    assert_eq!(
        result,
        Err(Error::WalletError(
            "wallet error (code 1): Wallet operation failed".into()
        ))
    );
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
/// Errors framed 1. Each is thrown after `#invokeWallet` has returned the
/// wallet's answer (`:1517-1519`, `:1594-1596`, `:1633-1635`), outside the
/// wrapper, so the words are the processor's and stay; the transceiver reads
/// each back as the code and the words.
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
                ..Default::default()
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
                ..Default::default()
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

/// An abortAction request from the fixtures' originator: the reference's
/// bytes, the rest of the frame (`WalletWireProcessor.ts:785-786`).
fn abort_request(reference: &[u8]) -> Vec<u8> {
    let originator = fixtures::wallet::ORIGINATOR.as_bytes();
    let mut request = vec![WalletCall::AbortAction.as_u8(), originator.len() as u8];
    request.extend(originator);
    request.extend(reference);
    request
}

/// The reference's frame for a refused abort (`WalletWireProcessor.ts:797-804`
/// at `ts-stack@edf6e03`, framed by `:2379-2396`): `08` (`abortRefused`,
/// `WalletError.ts:79`), `0x4d`, the 77 bytes of its words, `00`.
const ABORT_REFUSED_FRAME: &str = "084d5468652077616c6c6574207265667573656420746f2061626f7274207468697320616374696f6e20626563617573652069742068617320616c7265616479206265656e2062726f61646361737400";

/// #206: a wallet answering `aborted: false` is framed as the reference frames
/// its own (`WalletWireProcessor.ts:797-804`): code 8, `abortRefused`, the
/// reference's words, thrown after `#invokeValidatedWallet` returns and so
/// outside the wrapper. The wallet is called with the reference's bytes as
/// base64 (`:786`).
#[tokio::test]
async fn a_wallets_refused_abort_is_framed_code_8_in_the_references_words() {
    assert_eq!(
        hex::encode(reference_frame(
            8,
            b"The wallet refused to abort this action because it has already been broadcast"
        )),
        ABORT_REFUSED_FRAME
    );
    let stub = Stub::new(json!({"aborted": false}));
    let observed = stub.observed.clone();
    let frame = WalletWireProcessor::new(stub)
        .process_message(&abort_request(b"fixture"))
        .await
        .unwrap();
    assert_eq!(hex::encode(&frame), ABORT_REFUSED_FRAME);
    let seen = observed
        .lock()
        .unwrap()
        .take()
        .expect("the wallet is called");
    assert_eq!(seen["method"], "abort_action");
    assert_eq!(seen["args"]["reference"], "Zml4dHVyZQ==");
}

/// #206: a wallet answering `aborted: true` is the reference's success frame,
/// the error byte alone (`WalletWireProcessor.ts:806-809`), and the
/// transceiver reads it as `aborted: true` (`WalletWireTransceiver.ts:334-335`).
#[tokio::test]
async fn an_aborted_action_is_the_success_frame_and_reads_aborted_true() {
    let (client, tape) = taped(json!({"aborted": true}));
    let result = client
        .abort_action(
            bsv_rs::wallet::AbortActionArgs {
                reference: "Zml4dHVyZQ==".into(),
            },
            "test",
        )
        .await
        .map(|r| r.aborted);
    assert_eq!(hex::encode(tape.lock().unwrap().as_slice()), "00");
    assert_eq!(result, Ok(true));
}

/// #206: an empty reference is refused ahead of the wallet as the reference
/// refuses it (`validateAbortActionArgs`, `validationHelpers.ts:893-899`;
/// `validateBase64String`, `:488-498`, `invalidBase64`, `:439-441`): code 6,
/// the wallet not called; a wallet error on abortAction is the constant.
#[tokio::test]
async fn an_empty_abort_reference_is_refused_code_6() {
    let stub = Stub::new(json!({"aborted": true}));
    let observed = stub.observed.clone();
    let frame = WalletWireProcessor::new(stub)
        .process_message(&abort_request(b""))
        .await
        .unwrap();
    assert!(observed.lock().unwrap().is_none());
    assert_eq!(
        hex::encode(&frame),
        hex::encode(reference_frame(
            6,
            b"The reference parameter must be valid base64 string"
        ))
    );

    let mut stub = Stub::new(json!({}));
    stub.error = Some(Error::WalletError("no such action".into()));
    let frame = WalletWireProcessor::new(stub)
        .process_message(&abort_request(b"fixture"))
        .await
        .unwrap();
    assert_eq!(hex::encode(&frame), WALLET_OPERATION_FAILED_FRAME);
}

/// #206: the transceiver reads code 8 as `aborted: false`, as the reference's
/// client does (`WalletWireTransceiver.ts:336-339`, on the code alone), and
/// the processor's refusal reaches a consumer as that verdict end to end.
#[tokio::test]
async fn the_transceiver_reads_code_8_as_aborted_false() {
    let args = || bsv_rs::wallet::AbortActionArgs {
        reference: "Zml4dHVyZQ==".into(),
    };
    for frame in [
        hex::decode(ABORT_REFUSED_FRAME).unwrap(),
        reference_frame(8, b"any words"),
    ] {
        let result = WalletWireTransceiver::new(ReplyWire(frame.clone()))
            .abort_action(args(), "test")
            .await
            .map(|r| r.aborted);
        assert_eq!(result, Ok(false), "{}", hex::encode(&frame));
    }

    let (client, tape) = taped(json!({"aborted": false}));
    let result = client.abort_action(args(), "test").await.map(|r| r.aborted);
    assert_eq!(
        hex::encode(tape.lock().unwrap().as_slice()),
        ABORT_REFUSED_FRAME
    );
    assert_eq!(result, Ok(false));
}

/// #206: every other error frame on abortAction is the error it was
/// (`WalletWireTransceiver.ts:340`), and a byte after a success frame's error
/// byte is refused (`#requireEmptyResponse`, `:334`, `:2027-2035`).
#[tokio::test]
async fn every_other_abort_frame_is_the_error_it_was() {
    let args = || bsv_rs::wallet::AbortActionArgs {
        reference: "Zml4dHVyZQ==".into(),
    };
    for (frame, words) in [
        (
            hex::decode(WALLET_OPERATION_FAILED_FRAME).unwrap(),
            "wallet error (code 1): Wallet operation failed",
        ),
        (
            reference_frame(7, b"insufficient"),
            "wallet error (code 7): insufficient",
        ),
        (
            vec![0, 1],
            "Wallet Wire abortAction response has an invalid length",
        ),
    ] {
        let result = WalletWireTransceiver::new(ReplyWire(frame))
            .abort_action(args(), "test")
            .await
            .map(|r| r.aborted);
        assert_eq!(result, Err(Error::WalletError(words.into())), "{words}");
    }
}
