//! #498's re-review: the Peer's identity pin and `get_verifiable_certificates`
//! read a key strictly, though `PublicKey::from_hex` reads the reference's
//! lenient forms (the keeper's word of 2026-10-30 05:1xZ).
//!
//! Neither reference site parses the key: `Peer.initiateHandshake` keeps the
//! pin's text and refuses an initial response whose (canonical) identity key
//! is another text (`ts-stack@edf6e03` `Peer.ts:627-637,903-908`), and
//! `getVerifiableCertificates` refuses a wallet certificate whose certifier
//! text is none of the requested set's (`getVerifiableCertificates.ts:76-81`),
//! each of which `assertAuthIdentityKey` holds canonical
//! (`AuthMessageValidation.ts:123-124`), and keeps the subject's text, which
//! `Certificate.toBinary` refuses unless it is `02`/`03` and 64 hex digits
//! (`Certificate.ts:240-246`). The reference throws where this crate skips the
//! certificate, a difference older than #498.
//! Read leniently, a hybrid or odd-length form reduces to the canonical point:
//! a pinned handshake the reference refuses authenticated, and a wallet's
//! certificate the reference cannot serialize forwarded under the canonical key.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg(feature = "auth")]

use async_trait::async_trait;
use bsv_rs::auth::transports::{Transport, TransportCallback};
use bsv_rs::auth::types::RequestedCertificateSet;
use bsv_rs::auth::utils::get_verifiable_certificates;
use bsv_rs::auth::{AuthMessage, Peer, PeerOptions};
use bsv_rs::primitives::{to_base64, to_hex, PrivateKey, PublicKey};
use bsv_rs::wallet::*;
use bsv_rs::{Error, Result};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

/// p + 1: x = 1 once reduced.
const X_ABOVE_P: &str = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30";

/// `key`'s forms `from_hex` reads since #498 and `from_bytes` refuses: the
/// hybrid, the odd length, and (another point) a compressed x above p.
fn lenient_forms(key: &PublicKey) -> Vec<(&'static str, String)> {
    let uncompressed = to_hex(&key.to_uncompressed());
    let odd = uncompressed.ends_with(['1', '3', '5', '7', '9', 'b', 'd', 'f']);
    let hybrid = format!("{}{}", if odd { "07" } else { "06" }, &uncompressed[2..]);
    let compressed = key.to_hex();
    for form in [&hybrid, &compressed[1..].to_string()] {
        assert_eq!(&PublicKey::from_hex(form).unwrap(), key, "{form}");
    }
    vec![
        ("hybrid", hybrid),
        ("odd_length", compressed[1..].to_string()),
        ("x_above_p", format!("02{X_ABOVE_P}")),
    ]
}

fn strict_refusal(error: &Error) -> bool {
    matches!(error, Error::InvalidPublicKey(_) | Error::InvalidHex(_))
}

// ---------------------------------------------------------------------------
// A ProtoWallet that lists one given certificate and proves it with an empty
// keyring, and answers its identity key in the text given
// ---------------------------------------------------------------------------

struct TestWallet {
    inner: ProtoWallet,
    listed: Option<WalletCertificate>,
    identity: Option<String>,
}

macro_rules! test_wallet {
    ($(($method:ident, $args:ty, $result:ty)),* $(,)?) => {
        #[async_trait]
        impl WalletInterface for TestWallet {
            $(async fn $method(&self, args: $args, o: Option<&str>) -> Result<$result> {
                WalletInterface::$method(&self.inner, args, o).await
            })*

            async fn get_public_key(
                &self,
                args: GetPublicKeyArgs,
                o: Option<&str>,
            ) -> Result<GetPublicKeyResult> {
                match &self.identity {
                    Some(text) if args.identity_key => Ok(GetPublicKeyResult {
                        public_key: text.clone(),
                    }),
                    _ => WalletInterface::get_public_key(&self.inner, args, o).await,
                }
            }

            async fn list_certificates(
                &self,
                _: ListCertificatesArgs,
                _: Option<&str>,
            ) -> Result<ListCertificatesResult> {
                let certificates: Vec<_> = self.listed.iter().map(|certificate| CertificateResult {
                    certificate: certificate.clone(),
                    keyring: None,
                    verifier: None,
                }).collect();
                Ok(ListCertificatesResult {
                    total_certificates: certificates.len() as u32,
                    certificates,
                })
            }
            async fn prove_certificate(
                &self,
                args: ProveCertificateArgs,
                _: Option<&str>,
            ) -> Result<ProveCertificateResult> {
                Ok(ProveCertificateResult {
                    keyring_for_verifier: Default::default(),
                    certificate: None,
                    verifier: Some(args.verifier),
                })
            }
            async fn is_authenticated(&self, o: Option<&str>) -> Result<AuthenticatedResult> {
                WalletInterface::is_authenticated(&self.inner, o).await
            }
            async fn wait_for_authentication(&self, o: Option<&str>) -> Result<AuthenticatedResult> {
                WalletInterface::wait_for_authentication(&self.inner, o).await
            }
            async fn get_height(&self, o: Option<&str>) -> Result<GetHeightResult> {
                WalletInterface::get_height(&self.inner, o).await
            }
            async fn get_network(&self, o: Option<&str>) -> Result<GetNetworkResult> {
                WalletInterface::get_network(&self.inner, o).await
            }
            async fn get_version(&self, o: Option<&str>) -> Result<GetVersionResult> {
                WalletInterface::get_version(&self.inner, o).await
            }
        }
    };
}

test_wallet! {
    (encrypt, EncryptArgs, EncryptResult),
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
    (relinquish_certificate, RelinquishCertificateArgs, RelinquishCertificateResult),
    (discover_by_identity_key, DiscoverByIdentityKeyArgs, DiscoverCertificatesResult),
    (discover_by_attributes, DiscoverByAttributesArgs, DiscoverCertificatesResult),
    (get_header_for_height, GetHeaderArgs, GetHeaderResult),
}

fn wallet(key: &PrivateKey, listed: Option<WalletCertificate>) -> TestWallet {
    TestWallet {
        inner: ProtoWallet::new(Some(key.clone())),
        listed,
        identity: None,
    }
}

fn key(scalar: u8) -> PrivateKey {
    PrivateKey::from_bytes(&[scalar; 32]).unwrap()
}

// ---------------------------------------------------------------------------
// Two peers over an in-process transport
// ---------------------------------------------------------------------------

type Callback = Arc<Mutex<Option<Box<TransportCallback>>>>;

struct Wire {
    out: mpsc::UnboundedSender<AuthMessage>,
    callback: Callback,
}

#[async_trait]
impl Transport for Wire {
    async fn send(&self, message: &AuthMessage) -> Result<()> {
        self.out
            .send(message.clone())
            .map_err(|e| Error::AuthError(format!("closed: {e}")))
    }

    fn set_callback(&self, callback: Box<TransportCallback>) {
        *self.callback.lock().unwrap() = Some(callback);
    }

    fn clear_callback(&self) {
        *self.callback.lock().unwrap() = None;
    }
}

type End = (
    Arc<Peer<TestWallet, Wire>>,
    Callback,
    mpsc::UnboundedReceiver<AuthMessage>,
);

fn end(key: &PrivateKey, server: bool) -> End {
    let (out, sent) = mpsc::unbounded_channel();
    let callback: Callback = Arc::new(Mutex::new(None));
    let peer = Arc::new(Peer::new(PeerOptions {
        wallet: wallet(key, None),
        transport: Wire {
            out,
            callback: callback.clone(),
        },
        certificates_to_request: None,
        session_manager: None,
        auto_persist_last_session: false,
        originator: Some("test".into()),
    }));
    if server {
        peer.start_server();
    } else {
        peer.start();
    }
    (peer, callback, sent)
}

/// Carries each message `sent` holds to `to`'s callback.
fn route(mut sent: mpsc::UnboundedReceiver<AuthMessage>, to: Callback) {
    tokio::spawn(async move {
        while let Some(message) = sent.recv().await {
            let verdict = {
                let callback = to.lock().unwrap();
                callback.as_ref().expect("the peer is started")(message)
            };
            let _ = verdict.await;
        }
    });
}

/// A client pinned to `pin` against the server of scalar 42: the verdict.
async fn pinned_handshake(pin: &str) -> Result<bsv_rs::auth::PeerSession> {
    let (client, client_callback, client_sent) = end(&key(41), false);
    let (_server, server_callback, server_sent) = end(&key(42), true);
    route(client_sent, server_callback);
    route(server_sent, client_callback);
    client
        .get_authenticated_session(Some(pin), Some(2_000))
        .await
}

#[tokio::test]
async fn a_peer_pin_in_a_lenient_form_is_refused_before_the_handshake_498() {
    let server = key(42).public_key();
    let session = pinned_handshake(&server.to_hex()).await.unwrap();
    assert!(session.is_authenticated);
    assert_eq!(session.peer_identity_key, Some(server.clone()));
    for (name, pin) in lenient_forms(&server) {
        match pinned_handshake(&pin).await {
            Err(error) if strict_refusal(&error) => {}
            other => panic!("{name}: a pin read leniently: {other:?}"),
        }
    }
}

/// A certificate from the wallet, its subject or certifier written as `form`.
fn listed(subject: &str, certifier: &str) -> WalletCertificate {
    WalletCertificate {
        certificate_type: to_base64(&[1; 32]),
        subject: subject.to_string(),
        serial_number: to_base64(&[2; 32]),
        certifier: certifier.to_string(),
        revocation_outpoint: format!("{}.0", "00".repeat(32)),
        signature: String::new(),
        fields: Default::default(),
    }
}

async fn verifiable(listed: WalletCertificate) -> usize {
    let mut requested = RequestedCertificateSet::new();
    requested.add_certifier(key(43).public_key().to_hex());
    requested.add_type(to_base64(&[1; 32]), Vec::new());
    get_verifiable_certificates(
        &wallet(&key(41), Some(listed)),
        &requested,
        &key(44).public_key(),
        Some("test"),
    )
    .await
    .unwrap()
    .len()
}

#[tokio::test]
async fn a_wallet_certificate_key_in_a_lenient_form_is_not_forwarded_498() {
    let subject = key(42).public_key();
    let certifier = key(43).public_key();
    assert_eq!(
        verifiable(listed(&subject.to_hex(), &certifier.to_hex())).await,
        1
    );
    for (name, form) in lenient_forms(&subject) {
        assert_eq!(
            verifiable(listed(&form, &certifier.to_hex())).await,
            0,
            "{name}: a subject read leniently"
        );
    }
    for (name, form) in lenient_forms(&certifier) {
        assert_eq!(
            verifiable(listed(&subject.to_hex(), &form)).await,
            0,
            "{name}: a certifier read leniently"
        );
    }
}

// ---------------------------------------------------------------------------
// The Peer's own identity key, the wallet's answer (#498's second fold)
// ---------------------------------------------------------------------------

/// The reference refuses its wallet's identity key unless it is canonical
/// (`Peer.ts:1354-1355`, `assertAuthIdentityKey`, `AuthMessageValidation.ts:81-89`);
/// read leniently, a hybrid or odd-length answer became the canonical key.
#[tokio::test]
async fn a_wallet_identity_key_in_a_lenient_form_is_refused_by_the_peer_498() {
    let own = key(9);
    let peer = |identity: Option<String>| {
        let mut wallet = wallet(&own, None);
        wallet.identity = identity;
        Peer::new(PeerOptions {
            wallet,
            transport: bsv_rs::auth::transports::MockTransport::new(),
            certificates_to_request: None,
            session_manager: None,
            auto_persist_last_session: false,
            originator: None,
        })
    };
    let canonical = own.public_key();
    let answered = peer(Some(canonical.to_hex())).get_identity_key().await;
    assert_eq!(answered.unwrap(), canonical);
    for (name, form) in lenient_forms(&canonical) {
        let error = peer(Some(form)).get_identity_key().await.unwrap_err();
        assert!(strict_refusal(&error), "{name}: {error}");
    }
}
