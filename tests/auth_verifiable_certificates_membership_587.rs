//! #587: `get_verifiable_certificates` checks a listed certificate's certifier
//! and type against the requested set before proveCertificate and refuses the
//! whole call outside it, as the reference's `getVerifiableCertificates` does
//! (`ts-stack@edf6e03` `getVerifiableCertificates.ts:76-81`: the certifier's
//! text `includes()`-compared with the set's, which `assertAuthIdentityKey`
//! holds canonical, `AuthMessageValidation.ts:124`; a throw out of
//! `Promise.all`). Until #587 a valid lowercase certifier outside the set was
//! proved and forwarded, and an unrequested type proved with no fields.
//!
//! The verdicts and the reference's proveCertificate counts are recorded by
//! `tests/support/verifiable_certificates_membership_587.mjs`
//! (`tests/vectors/verifiable_certificates_membership_587.json`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg(feature = "auth")]

use async_trait::async_trait;
use bsv_rs::auth::types::RequestedCertificateSet;
use bsv_rs::auth::utils::get_verifiable_certificates;
use bsv_rs::primitives::PrivateKey;
use bsv_rs::wallet::*;
use bsv_rs::{Error, Result};
use std::sync::atomic::{AtomicUsize, Ordering};

/// A ProtoWallet that lists the given certificates and proves each with an
/// empty keyring, counting the proofs.
struct ListingWallet {
    inner: ProtoWallet,
    listed: Vec<WalletCertificate>,
    proofs: AtomicUsize,
}

macro_rules! listing_wallet {
    ($(($method:ident, $args:ty, $result:ty)),* $(,)?) => {
        #[async_trait]
        impl WalletInterface for ListingWallet {
            $(async fn $method(&self, args: $args, o: Option<&str>) -> Result<$result> {
                WalletInterface::$method(&self.inner, args, o).await
            })*

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
                self.proofs.fetch_add(1, Ordering::SeqCst);
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

listing_wallet! {
    (get_public_key, GetPublicKeyArgs, GetPublicKeyResult),
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

fn key(scalar: u8) -> PrivateKey {
    PrivateKey::from_bytes(&[scalar; 32]).unwrap()
}

fn recorded() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "vectors/verifiable_certificates_membership_587.json"
    ))
    .unwrap()
}

/// The recorded case `name`'s certificates, listed as the reference's were.
fn listed(case: &serde_json::Value) -> Vec<WalletCertificate> {
    let texts = |member: &str| -> Vec<String> {
        case[member]
            .as_array()
            .unwrap()
            .iter()
            .map(|text| text.as_str().unwrap().to_owned())
            .collect()
    };
    texts("certifiers")
        .into_iter()
        .zip(texts("types"))
        .map(|(certifier, certificate_type)| WalletCertificate {
            certificate_type,
            subject: key(42).public_key().to_hex(),
            serial_number: bsv_rs::primitives::to_base64(&[2; 32]),
            certifier,
            revocation_outpoint: format!("{}.0", "00".repeat(32)),
            signature: String::new(),
            fields: Default::default(),
        })
        .collect()
}

/// The recorded requested set: one certifier, one type of one field.
fn requested(recorded: &serde_json::Value) -> RequestedCertificateSet {
    let mut requested = RequestedCertificateSet::new();
    for certifier in recorded["requested"]["certifiers"].as_array().unwrap() {
        requested.add_certifier(certifier.as_str().unwrap().to_owned());
    }
    for (certificate_type, fields) in recorded["requested"]["types"].as_object().unwrap() {
        let fields = fields.as_array().unwrap().iter();
        let fields = fields.map(|field| field.as_str().unwrap().to_owned());
        requested.add_type(certificate_type.clone(), fields.collect());
    }
    requested
}

/// Each recorded case's verdict, in the reference's words, and its count of
/// proofs, but one: listed after a certificate outside the set, an in-set
/// certificate is proved by the reference (`Array.map` starts every callback
/// before `Promise.all` rejects) and not here (the loop stops at the refusal).
#[tokio::test]
async fn a_valid_certifier_outside_the_requested_set_refuses_the_call_587() {
    let recorded = recorded();
    assert_eq!(recorded["node"], "v22.18.0");
    let verifier = key(44).public_key();
    assert_eq!(recorded["verifier"], verifier.to_hex());
    let requested = requested(&recorded);
    let cases = recorded["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 6);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let wallet = ListingWallet {
            inner: ProtoWallet::new(Some(key(41))),
            listed: listed(case),
            proofs: AtomicUsize::new(0),
        };
        let verdict =
            get_verifiable_certificates(&wallet, &requested, &verifier, Some("test")).await;
        match (&case["verdict"]["ok"], verdict) {
            (serde_json::Value::Bool(true), Ok(certificates)) => {
                assert_eq!(case["verdict"]["count"], certificates.len(), "{name}");
            }
            (serde_json::Value::Bool(false), Err(Error::AuthError(message))) => {
                assert_eq!(case["verdict"]["message"], message, "{name}");
            }
            (_, other) => panic!("{name}: {other:?}"),
        }
        let proofs = wallet.proofs.load(Ordering::SeqCst);
        let expected = case["proveCalls"].as_u64().unwrap() as usize;
        if name == "outside_before_inside" {
            assert_eq!((expected, proofs), (1, 0), "{name}: the stated residue");
        } else {
            assert_eq!(proofs, expected, "{name}");
        }
    }
}

/// The issue's input alone: a valid, lowercase certifier outside the set
/// was proved and forwarded before #587.
#[tokio::test]
async fn a_lowercase_certifier_outside_the_set_is_not_proved_or_forwarded_587() {
    let recorded = recorded();
    let case = &recorded["cases"][1];
    assert_eq!(case["name"], "certifier_outside_set");
    let wallet = ListingWallet {
        inner: ProtoWallet::new(Some(key(41))),
        listed: listed(case),
        proofs: AtomicUsize::new(0),
    };
    let verifier = key(44).public_key();
    let verdict =
        get_verifiable_certificates(&wallet, &requested(&recorded), &verifier, Some("test")).await;
    assert_eq!(
        verdict.map(|certificates| certificates.len()),
        Err(Error::AuthError(
            "Wallet returned a certificate outside the requested certifier/type set".into()
        ))
    );
    assert_eq!(wallet.proofs.load(Ordering::SeqCst), 0);
}
