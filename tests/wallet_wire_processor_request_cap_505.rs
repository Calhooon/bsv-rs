//! #505: bound the complete request before decoding or calling the wallet.
//! The reference's two transport guards are WalletWireProcessor.ts:248-250
//! and :265-269 at ts-stack@edf6e03. They throw an uncoded Error before
//! #processMessage's try (:274), so no error frame is written: here
//! process_message returns Err(WalletError) in the same words.
#![cfg(feature = "wallet")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: tests

use bsv_rs::wallet::wire::{WalletCall, WalletWireProcessor, WireWriter};
use bsv_rs::wallet::*;
use bsv_rs::Error;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

const CAP: usize = 256 * 1024 * 1024;
const ORIGINATOR: &str = "cap.test";
const REFUSAL: &str = "Wallet Wire request exceeds the maximum permitted size";
const CIPHERTEXT: [u8; 3] = [1, 2, 3];

// Keep the two large frames from being held simultaneously.
static FRAME_CASE: Mutex<()> = Mutex::new(());

struct CountingWallet {
    calls: Arc<AtomicUsize>,
    plaintext_length: usize,
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
                assert_eq!(originator, Some(ORIGINATOR));
                assert_eq!(args.protocol_id, Protocol::new(SecurityLevel::Silent, "cap test"));
                assert_eq!(args.key_id, "key");
                assert_eq!(args.plaintext.len(), self.plaintext_length);
                assert!(args.plaintext.iter().all(|byte| *byte == 0x5a));
                Ok(EncryptResult { ciphertext: CIPHERTEXT.to_vec() })
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

/// Use the crate's writer directly: the transceiver correctly refuses an
/// oversized frame itself (#496), so it cannot deliver this processor probe.
/// Encrypt's order is the key parameters, length-prefixed plaintext and seek
/// permission (transceiver.rs; WalletWireTransceiver.ts:938-953).
fn encrypt_frame(frame_length: usize) -> (Vec<u8>, usize) {
    let mut writer = WireWriter::with_capacity(frame_length);
    writer.write_u8(WalletCall::Encrypt.as_u8());
    writer.write_u8(ORIGINATOR.len().try_into().unwrap());
    writer.write_bytes(ORIGINATOR.as_bytes());
    writer.write_protocol_id(&Protocol::new(SecurityLevel::Silent, "cap test"));
    writer.write_string("key");
    writer.write_counterparty(None);
    writer.write_optional_bool(None); // privileged
    writer.write_i8(-1); // absent privileged reason

    let mut length_writer = WireWriter::new();
    length_writer.write_var_int(frame_length as u64);
    let plaintext_length = frame_length - writer.len() - length_writer.len() - 1;
    assert!(plaintext_length < CAP); // Only the whole frame crosses the cap.
    let plaintext = vec![0x5a; plaintext_length];
    writer.write_var_int(plaintext.len() as u64);
    writer.write_bytes(&plaintext);
    writer.write_optional_bool(None); // seekPermission
    assert_eq!(writer.len(), frame_length);
    (writer.into_bytes(), plaintext_length)
}

fn process(frame_length: usize) -> (bsv_rs::Result<Vec<u8>>, usize) {
    let (frame, plaintext_length) = encrypt_frame(frame_length);
    let calls = Arc::new(AtomicUsize::new(0));
    let processor = WalletWireProcessor::new(CountingWallet {
        calls: Arc::clone(&calls),
        plaintext_length,
    });
    let response = futures::executor::block_on(processor.process_message(&frame));
    (response, calls.load(Ordering::SeqCst))
}

#[test]
fn request_frame_above_cap_is_an_error_before_decoding_or_wallet_dispatch_505() {
    let _serial = FRAME_CASE.lock().unwrap();
    let (response, calls) = process(CAP + 1);
    assert_eq!(calls, 0, "#505: oversized frame reached the wallet");
    // Thrown out of transmitToWallet in the reference, never framed.
    assert_eq!(response, Err(Error::WalletError(REFUSAL.into())));
}

#[test]
fn request_frame_exactly_at_cap_reaches_the_wallet_and_returns_its_answer_505() {
    // Recover a poisoned lock so both base observations run after the RED case.
    let _serial = FRAME_CASE.lock().unwrap_or_else(|error| error.into_inner());
    let (response, calls) = process(CAP);
    assert_eq!(calls, 1);
    let response = response.unwrap();
    let mut expected = WireWriter::new();
    expected.write_u8(0);
    expected.write_bytes(&CIPHERTEXT);
    assert_eq!(response, expected.into_bytes());
}
