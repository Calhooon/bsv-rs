//! A real ProtoWallet with explicit test-only verification behavior.
use async_trait::async_trait;
use bsv_rs::auth::MasterCertificate;
use bsv_rs::primitives::{PrivateKey, PublicKey};
use bsv_rs::wallet::*;
use bsv_rs::{Error, Result};

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::sync::Semaphore;

pub struct Gate {
    pub enabled: AtomicBool,
    pub entered: Semaphore,
    pub release: Semaphore,
}

impl Default for Gate {
    fn default() -> Self {
        Self {
            enabled: AtomicBool::new(false),
            entered: Semaphore::new(0),
            release: Semaphore::new(0),
        }
    }
}

pub struct TestWallet {
    pub inner: ProtoWallet,
    pub answering: bool,
    pub failure: Option<Error>,
    pub gate: Arc<Gate>,
    pub certificates: Vec<MasterCertificate>,
}

impl TestWallet {
    pub fn new(key: PrivateKey, answering: bool) -> Self {
        Self {
            inner: ProtoWallet::new(Some(key)),
            answering,
            failure: None,
            gate: Arc::default(),
            certificates: Vec::new(),
        }
    }
}

macro_rules! forward {
    ($(($method:ident, $args:ty, $result:ty)),* $(,)?) => {
        #[async_trait]
        impl WalletInterface for TestWallet {
            $(async fn $method(&self, args: $args, o: Option<&str>) -> Result<$result> {
                WalletInterface::$method(&self.inner, args, o).await
            })*

            async fn decrypt(&self, args: DecryptArgs, o: Option<&str>) -> Result<DecryptResult> {
                if self.gate.enabled.load(Ordering::SeqCst) {
                    self.gate.entered.add_permits(1);
                    self.gate.release.acquire().await.unwrap().forget();
                }
                WalletInterface::decrypt(&self.inner, args, o).await
            }
            async fn list_certificates(
                &self,
                args: ListCertificatesArgs,
                _: Option<&str>,
            ) -> Result<ListCertificatesResult> {
                let certificates: Vec<_> = self.certificates.iter().filter(|master| {
                    args.certifiers.contains(&master.certificate.certifier.to_hex())
                        && args.types.contains(&master.certificate.type_base64())
                }).map(|master| CertificateResult {
                    certificate: serde_json::from_value(
                        serde_json::to_value(&master.certificate).unwrap()
                    ).unwrap(),
                    keyring: None,
                    verifier: None,
                }).collect();
                Ok(ListCertificatesResult {
                    total_certificates: certificates.len() as u64,
                    certificates,
                })
            }
            async fn prove_certificate(
                &self,
                args: ProveCertificateArgs,
                o: Option<&str>,
            ) -> Result<ProveCertificateResult> {
                let master = self.certificates.iter().find(|master| {
                    master.certificate.serial_number_base64() == args.certificate.serial_number
                }).unwrap();
                let keyring = MasterCertificate::create_keyring_for_verifier(
                    &self.inner, &master.certificate.certifier,
                    &PublicKey::from_hex(&args.verifier)?, &master.certificate.fields,
                    &args.fields_to_reveal, &master.master_keyring,
                    &master.certificate.serial_number, None, None, o,
                ).await?;
                Ok(ProveCertificateResult {
                    keyring_for_verifier: keyring,
                    certificate: None,
                    verifier: Some(args.verifier),
                })
            }
            async fn verify_signature(
                &self,
                args: VerifySignatureArgs,
                o: Option<&str>,
            ) -> Result<VerifySignatureResult> {
                if let Some(error) = &self.failure {
                    return Err(error.clone());
                }
                match WalletInterface::verify_signature(&self.inner, args, o).await {
                    Err(_) if self.answering => Ok(VerifySignatureResult { valid: false }),
                    result => result,
                }
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

forward! {
    (get_public_key, GetPublicKeyArgs, GetPublicKeyResult),
    (encrypt, EncryptArgs, EncryptResult),

    (create_hmac, CreateHmacArgs, CreateHmacResult),
    (verify_hmac, VerifyHmacArgs, VerifyHmacResult),
    (create_signature, CreateSignatureArgs, CreateSignatureResult),
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
