//! The counting wallet of the identity reveal's tests (#307, #310): a
//! ProtoWallet under a client that records each call, answers
//! proveCertificate with a keyring it is given and createAction with no
//! transaction, so nothing is broadcast.
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
    pub keyring: Option<HashMap<String, String>>,
    pub created: Arc<Mutex<Option<CreateActionArgs>>>,
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
            keyring: None,
            created: Arc::default(),
            public_key_args: Arc::default(),
            signature_args: Arc::default(),
        }
    }

    pub fn calls(&self) -> Vec<&'static str> {
        self.calls.lock().unwrap().clone()
    }

    fn note(&self, name: &'static str) {
        self.calls.lock().unwrap().push(name);
    }
}

// async_trait rewrites the impl it is applied to, so the macro writes the
// whole impl rather than methods inside one.
macro_rules! counting {
    ($(($method:ident, $args:ty, $result:ty)),* $(,)?) => {
        #[async_trait::async_trait]
        impl WalletInterface for Counting {
            $(async fn $method(&self, args: $args, o: &str) -> bsv_rs::Result<$result> {
                self.note(stringify!($method));
                WalletInterface::$method(&*self.inner, args, o).await
            })*

            async fn prove_certificate(
                &self,
                args: ProveCertificateArgs,
                _o: &str,
            ) -> bsv_rs::Result<ProveCertificateResult> {
                self.note("prove_certificate");
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
                _o: &str,
            ) -> bsv_rs::Result<CreateActionResult> {
                self.note("create_action");
                *self.created.lock().unwrap() = Some(args);
                Ok(CreateActionResult::default())
            }
            async fn get_public_key(
                &self,
                args: GetPublicKeyArgs,
                o: &str,
            ) -> bsv_rs::Result<GetPublicKeyResult> {
                self.note("get_public_key");
                self.public_key_args.lock().unwrap().push(args.clone());
                WalletInterface::get_public_key(&*self.inner, args, o).await
            }
            async fn create_signature(
                &self,
                args: CreateSignatureArgs,
                o: &str,
            ) -> bsv_rs::Result<CreateSignatureResult> {
                self.note("create_signature");
                self.signature_args.lock().unwrap().push(args.clone());
                WalletInterface::create_signature(&*self.inner, args, o).await
            }
            async fn is_authenticated(&self, o: &str) -> bsv_rs::Result<AuthenticatedResult> {
                self.note("is_authenticated");
                WalletInterface::is_authenticated(&*self.inner, o).await
            }
            async fn wait_for_authentication(
                &self,
                o: &str,
            ) -> bsv_rs::Result<AuthenticatedResult> {
                self.note("wait_for_authentication");
                WalletInterface::wait_for_authentication(&*self.inner, o).await
            }
            async fn get_height(&self, o: &str) -> bsv_rs::Result<GetHeightResult> {
                self.note("get_height");
                WalletInterface::get_height(&*self.inner, o).await
            }
            async fn get_network(&self, o: &str) -> bsv_rs::Result<GetNetworkResult> {
                self.note("get_network");
                WalletInterface::get_network(&*self.inner, o).await
            }
            async fn get_version(&self, o: &str) -> bsv_rs::Result<GetVersionResult> {
                self.note("get_version");
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
    (sign_action, SignActionArgs, SignActionResult),
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
