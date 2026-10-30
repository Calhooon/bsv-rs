//! #496: the complete request frame is bounded before the transport is called.
//! Frames and the refusal are recorded by #487's compact-byte recorder; the
//! oversized candidate uses its SDK writer because the transceiver never sends it.
#![cfg(feature = "wallet")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: tests

use bsv_rs::primitives::{sha256, to_hex};
use bsv_rs::wallet::wire::{WalletWire, WalletWireProcessor, WalletWireTransceiver};
use bsv_rs::wallet::*;
use bsv_rs::Error;
use serde::Deserialize;
use serde_json::Value;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

// Keep the two 256 MiB witnesses from holding their frames simultaneously.
static FRAME_CASE: Mutex<()> = Mutex::new(());

#[derive(Deserialize)]
struct Recording {
    source: String,
    cap: usize,
    originator: String,
    args: Value,
    response_hex: String,
    rows: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    frame_bytes: usize,
    request_parts: Vec<Part>,
    frame_sha256: String,
    plaintext_length: usize,
    transmissions: usize,
    reference: Value,
}

#[derive(Deserialize)]
struct Part {
    hex: String,
    repeat: usize,
}

struct CountingWallet {
    calls: Arc<AtomicUsize>,
    plaintext_length: usize,
    originator: String,
    ciphertext: Vec<u8>,
}

impl CountingWallet {
    fn unexpected<T>(&self) -> bsv_rs::Result<T> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(Error::WalletError("unexpected wallet call".into()))
    }
}

macro_rules! counting_wallet {
    ($(($method:ident, $args:ty, $result:ty)),* $(,)?) => {
        #[async_trait::async_trait]
        impl WalletInterface for CountingWallet {
            $(async fn $method(&self, _: $args, _: Option<&str>) -> bsv_rs::Result<$result> {
                self.unexpected()
            })*

            async fn encrypt(&self, args: EncryptArgs, originator: Option<&str>) -> bsv_rs::Result<EncryptResult> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                assert_eq!(originator, Some(self.originator.as_str()));
                assert_eq!(args.plaintext.len(), self.plaintext_length);
                Ok(EncryptResult { ciphertext: self.ciphertext.clone() })
            }

            async fn is_authenticated(&self, _: Option<&str>) -> bsv_rs::Result<AuthenticatedResult> { self.unexpected() }
            async fn wait_for_authentication(&self, _: Option<&str>) -> bsv_rs::Result<AuthenticatedResult> { self.unexpected() }
            async fn get_height(&self, _: Option<&str>) -> bsv_rs::Result<GetHeightResult> { self.unexpected() }
            async fn get_network(&self, _: Option<&str>) -> bsv_rs::Result<GetNetworkResult> { self.unexpected() }
            async fn get_version(&self, _: Option<&str>) -> bsv_rs::Result<GetVersionResult> { self.unexpected() }
        }
    };
}

counting_wallet! {
    (get_public_key, GetPublicKeyArgs, GetPublicKeyResult),
    (decrypt, DecryptArgs, DecryptResult),
    (create_hmac, CreateHmacArgs, CreateHmacResult),
    (verify_hmac, VerifyHmacArgs, VerifyHmacResult),
    (create_signature, CreateSignatureArgs, CreateSignatureResult),
    (verify_signature, VerifySignatureArgs, VerifySignatureResult),
    (reveal_counterparty_key_linkage, WalletRevealCounterpartyArgs, RevealCounterpartyKeyLinkageResult),
    (reveal_specific_key_linkage, WalletRevealSpecificArgs, RevealSpecificKeyLinkageResult),
    (create_action, CreateActionArgs, CreateActionResult),
    (sign_action, SignActionArgs, SignActionResult),
    (abort_action, AbortActionArgs, AbortActionResult),
    (list_actions, ListActionsArgs, ListActionsResult),
    (internalize_action, InternalizeActionArgs, InternalizeActionResult),
    (list_outputs, ListOutputsArgs, ListOutputsResult),
    (relinquish_output, RelinquishOutputArgs, RelinquishOutputResult),
    (acquire_certificate, AcquireCertificateArgs, WalletCertificate),
    (list_certificates, ListCertificatesArgs, ListCertificatesResult),
    (prove_certificate, ProveCertificateArgs, ProveCertificateResult),
    (relinquish_certificate, RelinquishCertificateArgs, RelinquishCertificateResult),
    (discover_by_identity_key, DiscoverByIdentityKeyArgs, DiscoverCertificatesResult),
    (discover_by_attributes, DiscoverByAttributesArgs, DiscoverCertificatesResult),
    (get_header_for_height, GetHeaderArgs, GetHeaderResult),
}

struct Loopback {
    processor: WalletWireProcessor<CountingWallet>,
    transmissions: AtomicUsize,
    frame_bytes: usize,
    frame_sha256: String,
}

#[async_trait::async_trait]
impl WalletWire for Loopback {
    async fn transmit_to_wallet(&self, frame: &[u8]) -> bsv_rs::Result<Vec<u8>> {
        self.transmissions.fetch_add(1, Ordering::SeqCst);
        assert_eq!(frame.len(), self.frame_bytes);
        assert_eq!(to_hex(&sha256(frame)), self.frame_sha256);
        self.processor.process_message(frame).await
    }
}

fn replay(name: &str) {
    let _serial = FRAME_CASE.lock().unwrap();
    let recording: Recording = serde_json::from_str(include_str!(
        "vectors/wallet_wire/request_frame_cap_496.json"
    ))
    .unwrap();
    assert_eq!(recording.source, "ts-stack@edf6e03");
    assert_eq!(recording.cap, 256 * 1024 * 1024);
    let case = recording.rows.into_iter().find(|c| c.name == name).unwrap();
    let parts = &case.request_parts;
    assert_eq!(parts.len(), 3);
    assert_eq!(parts[1].repeat, case.plaintext_length);
    assert_eq!(
        parts
            .iter()
            .map(|p| hex::decode(&p.hex).unwrap().len() * p.repeat)
            .sum::<usize>(),
        case.frame_bytes
    );
    // The byte field itself fits; only the complete frame crosses the bound.
    assert!(case.plaintext_length < recording.cap);
    assert_eq!(
        case.frame_bytes,
        recording.cap + usize::from(name == "above_cap")
    );
    let response = hex::decode(recording.response_hex).unwrap();
    assert_eq!(response[0], 0);
    let calls = Arc::new(AtomicUsize::new(0));
    let client = WalletWireTransceiver::new(Loopback {
        processor: WalletWireProcessor::new(CountingWallet {
            calls: calls.clone(),
            plaintext_length: case.plaintext_length,
            originator: recording.originator.clone(),
            ciphertext: response[1..].to_vec(),
        }),
        transmissions: AtomicUsize::new(0),
        frame_bytes: case.frame_bytes,
        frame_sha256: case.frame_sha256,
    });
    let fill = hex::decode(&parts[1].hex).unwrap();
    assert_eq!(fill.len(), 1);
    let result = futures::executor::block_on(client.encrypt(
        EncryptArgs {
            plaintext: vec![fill[0]; case.plaintext_length],
            protocol_id: Protocol::new(
                SecurityLevel::Silent,
                recording.args["protocolID"][1].as_str().unwrap(),
            ),
            key_id: recording.args["keyID"].as_str().unwrap().into(),
            ..Default::default()
        },
        Some(&recording.originator),
    ))
    .map(|r| r.ciphertext);
    assert_eq!(
        (
            client.wire().transmissions.load(Ordering::SeqCst),
            calls.load(Ordering::SeqCst)
        ),
        (case.transmissions, case.transmissions),
        "#496 transport and wallet call counts"
    );
    if name == "above_cap" {
        assert!(case.reference["code"].is_null());
        assert_eq!(
            result,
            Err(Error::WalletError(
                case.reference["message"].as_str().unwrap().into()
            ))
        );
    } else {
        assert_eq!(case.reference["accepted"], true);
        assert_eq!(result, Ok(response[1..].to_vec()));
    }
}

#[test]
fn request_frame_above_cap_is_refused_before_any_wallet_call_496() {
    replay("above_cap");
}

#[test]
fn request_frame_at_cap_is_sent_and_answered_496() {
    replay("at_cap");
}
