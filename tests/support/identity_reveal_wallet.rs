//! The counting wallet of the identity reveal's tests (#307, #310): a
//! ProtoWallet under a client that records each call, answers
//! proveCertificate with a keyring it is given and createAction with no
//! transaction, so nothing is broadcast; createAction's arguments and
//! originator kept (#315); every call's originator kept, and with a
//! signable transaction set createAction answers it and signAction's
//! arguments are kept, signAction answering no transaction (#318).
#![allow(dead_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use bsv_rs::primitives::PrivateKey;
use bsv_rs::wallet::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// A ProtoWallet that records each call by name; proveCertificate answers
/// a keyring of the names asked (or of `keyring` when set), createAction
/// no transaction; getPublicKey's and createSignature's arguments kept.
#[derive(Clone)]
pub struct Counting {
    inner: Arc<ProtoWallet>,
    calls: Arc<Mutex<Vec<&'static str>>>,
    originators: Arc<Mutex<Vec<String>>>,
    /// The signable transaction createAction answers (its atomic BEEF and
    /// reference), none by default (#318).
    pub signable: Option<SignableTransaction>,
    pub signed: Arc<Mutex<Option<SignActionArgs>>>,
    pub keyring: Option<HashMap<String, String>>,
    pub created: Arc<Mutex<Option<CreateActionArgs>>>,
    pub created_originator: Arc<Mutex<Option<String>>>,
    pub public_key_args: Arc<Mutex<Vec<GetPublicKeyArgs>>>,
    pub signature_args: Arc<Mutex<Vec<CreateSignatureArgs>>>,
}

impl Counting {
    /// The #307 wallet: the key of 32 bytes of 5.
    pub fn new() -> Self {
        Self::of_key(PrivateKey::from_bytes(&[5u8; 32]).unwrap())
    }

    /// A wallet of the scalar `n`, the reference's `new PrivateKey(n)`.
    pub fn of_scalar(n: u8) -> Self {
        let mut scalar = [0u8; 32];
        scalar[31] = n;
        Self::of_key(PrivateKey::from_bytes(&scalar).unwrap())
    }

    fn of_key(key: PrivateKey) -> Self {
        Self {
            inner: Arc::new(ProtoWallet::new(Some(key))),
            calls: Arc::default(),
            originators: Arc::default(),
            signable: None,
            signed: Arc::default(),
            keyring: None,
            created: Arc::default(),
            created_originator: Arc::default(),
            public_key_args: Arc::default(),
            signature_args: Arc::default(),
        }
    }

    pub fn calls(&self) -> Vec<&'static str> {
        self.calls.lock().unwrap().clone()
    }

    /// The originator each call received, in the order of `calls` (#318).
    pub fn originators(&self) -> Vec<String> {
        self.originators.lock().unwrap().clone()
    }

    fn note(&self, name: &'static str, originator: &str) {
        self.calls.lock().unwrap().push(name);
        self.originators
            .lock()
            .unwrap()
            .push(originator.to_string());
    }
}

// async_trait rewrites the impl it is applied to, so the macro writes the
// whole impl rather than methods inside one.
macro_rules! counting {
    ($(($method:ident, $args:ty, $result:ty)),* $(,)?) => {
        #[async_trait::async_trait]
        impl WalletInterface for Counting {
            $(async fn $method(&self, args: $args, o: &str) -> bsv_rs::Result<$result> {
                self.note(stringify!($method), o);
                WalletInterface::$method(&*self.inner, args, o).await
            })*

            async fn prove_certificate(
                &self,
                args: ProveCertificateArgs,
                o: &str,
            ) -> bsv_rs::Result<ProveCertificateResult> {
                self.note("prove_certificate", o);
                let asked = args.fields_to_reveal.iter().map(|f| (f.clone(), "AAAA".to_string()));
                Ok(ProveCertificateResult {
                    keyring_for_verifier: self.keyring.clone().unwrap_or_else(|| asked.collect()),
                    certificate: None,
                    verifier: None,
                })
            }
            async fn create_action(
                &self,
                args: CreateActionArgs,
                o: &str,
            ) -> bsv_rs::Result<CreateActionResult> {
                self.note("create_action", o);
                *self.created.lock().unwrap() = Some(args);
                *self.created_originator.lock().unwrap() = Some(o.to_string());
                Ok(CreateActionResult {
                    signable_transaction: self.signable.clone(),
                    ..Default::default()
                })
            }
            async fn sign_action(
                &self,
                args: SignActionArgs,
                o: &str,
            ) -> bsv_rs::Result<SignActionResult> {
                self.note("sign_action", o);
                *self.signed.lock().unwrap() = Some(args);
                Ok(SignActionResult {
                    txid: None,
                    tx: None,
                    send_with_results: None,
                })
            }
            async fn get_public_key(
                &self,
                args: GetPublicKeyArgs,
                o: &str,
            ) -> bsv_rs::Result<GetPublicKeyResult> {
                self.note("get_public_key", o);
                self.public_key_args.lock().unwrap().push(args.clone());
                WalletInterface::get_public_key(&*self.inner, args, o).await
            }
            async fn create_signature(
                &self,
                args: CreateSignatureArgs,
                o: &str,
            ) -> bsv_rs::Result<CreateSignatureResult> {
                self.note("create_signature", o);
                self.signature_args.lock().unwrap().push(args.clone());
                WalletInterface::create_signature(&*self.inner, args, o).await
            }
            async fn is_authenticated(&self, o: &str) -> bsv_rs::Result<AuthenticatedResult> {
                self.note("is_authenticated", o);
                WalletInterface::is_authenticated(&*self.inner, o).await
            }
            async fn wait_for_authentication(
                &self,
                o: &str,
            ) -> bsv_rs::Result<AuthenticatedResult> {
                self.note("wait_for_authentication", o);
                WalletInterface::wait_for_authentication(&*self.inner, o).await
            }
            async fn get_height(&self, o: &str) -> bsv_rs::Result<GetHeightResult> {
                self.note("get_height", o);
                WalletInterface::get_height(&*self.inner, o).await
            }
            async fn get_network(&self, o: &str) -> bsv_rs::Result<GetNetworkResult> {
                self.note("get_network", o);
                WalletInterface::get_network(&*self.inner, o).await
            }
            async fn get_version(&self, o: &str) -> bsv_rs::Result<GetVersionResult> {
                self.note("get_version", o);
                WalletInterface::get_version(&*self.inner, o).await
            }
        }
    };
}

counting! {
    (encrypt, EncryptArgs, EncryptResult),
    (decrypt, DecryptArgs, DecryptResult),
    (create_hmac, CreateHmacArgs, CreateHmacResult),
    (verify_hmac, VerifyHmacArgs, VerifyHmacResult),
    (verify_signature, VerifySignatureArgs, VerifySignatureResult),
    (reveal_counterparty_key_linkage, WalletRevealCounterpartyArgs, RevealCounterpartyKeyLinkageResult),
    (reveal_specific_key_linkage, WalletRevealSpecificArgs, RevealSpecificKeyLinkageResult),
    (abort_action, AbortActionArgs, AbortActionResult),
    (list_actions, ListActionsArgs, ListActionsResult),
    (internalize_action, InternalizeActionArgs, InternalizeActionResult),
    (list_outputs, ListOutputsArgs, ListOutputsResult),
    (relinquish_output, RelinquishOutputArgs, RelinquishOutputResult),
    (acquire_certificate, AcquireCertificateArgs, WalletCertificate),
    (list_certificates, ListCertificatesArgs, ListCertificatesResult),
    (relinquish_certificate, RelinquishCertificateArgs, RelinquishCertificateResult),
    (discover_by_identity_key, DiscoverByIdentityKeyArgs, DiscoverCertificatesResult),
    (discover_by_attributes, DiscoverByAttributesArgs, DiscoverCertificatesResult),
    (get_header_for_height, GetHeaderArgs, GetHeaderResult),
}
