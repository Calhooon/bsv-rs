//! Recording wallet used only by the #423 HTTP witnesses.

use bsv_rs::wallet::interface::{RevealCounterpartyKeyLinkageArgs, RevealSpecificKeyLinkageArgs};
use bsv_rs::wallet::*;
use bsv_rs::Result;
use serde_json::Value;
use std::sync::Arc;
use std::sync::Mutex;

pub struct TestWallet {
    inner: ProtoWallet,
    row: Value,
    pub actions: Arc<Mutex<Vec<Value>>>,
    pub payment_keys: Arc<Mutex<Vec<String>>>,
}
impl TestWallet {
    pub fn new(row: Value) -> Self {
        Self {
            inner: ProtoWallet::new(Some(super::key(41))),
            row,
            actions: Arc::default(),
            payment_keys: Arc::default(),
        }
    }
}

#[async_trait::async_trait]
impl WalletInterface for TestWallet {
    async fn get_public_key(
        &self,
        args: GetPublicKeyArgs,
        originator: Option<&str>,
    ) -> Result<GetPublicKeyResult> {
        if args
            .protocol_id
            .as_ref()
            .is_some_and(|p| p.protocol_name == "3241645161d8")
        {
            assert_eq!(
                args.protocol_id.as_ref().unwrap().security_level,
                SecurityLevel::Counterparty
            );
            assert_eq!(
                args.counterparty,
                Some(Counterparty::Other(super::key(42).public_key()))
            );
            self.payment_keys.lock().unwrap().push(args.key_id.unwrap());
            let call = self.row["public_key_calls"]
                .as_array()
                .unwrap()
                .iter()
                .find(|call| call["args"]["protocolID"][1] == "3241645161d8")
                .unwrap();
            return Ok(GetPublicKeyResult {
                public_key: call["result"]["publicKey"].as_str().unwrap().into(),
            });
        }
        WalletInterface::get_public_key(&self.inner, args, originator).await
    }
    async fn encrypt(&self, args: EncryptArgs, originator: Option<&str>) -> Result<EncryptResult> {
        WalletInterface::encrypt(&self.inner, args, originator).await
    }
    async fn decrypt(&self, args: DecryptArgs, originator: Option<&str>) -> Result<DecryptResult> {
        WalletInterface::decrypt(&self.inner, args, originator).await
    }
    async fn create_hmac(
        &self,
        args: CreateHmacArgs,
        originator: Option<&str>,
    ) -> Result<CreateHmacResult> {
        WalletInterface::create_hmac(&self.inner, args, originator).await
    }
    async fn verify_hmac(
        &self,
        args: VerifyHmacArgs,
        originator: Option<&str>,
    ) -> Result<VerifyHmacResult> {
        WalletInterface::verify_hmac(&self.inner, args, originator).await
    }
    async fn create_signature(
        &self,
        args: CreateSignatureArgs,
        originator: Option<&str>,
    ) -> Result<CreateSignatureResult> {
        WalletInterface::create_signature(&self.inner, args, originator).await
    }
    async fn verify_signature(
        &self,
        args: VerifySignatureArgs,
        originator: Option<&str>,
    ) -> Result<VerifySignatureResult> {
        WalletInterface::verify_signature(&self.inner, args, originator).await
    }
    async fn reveal_counterparty_key_linkage(
        &self,
        args: RevealCounterpartyKeyLinkageArgs,
        originator: Option<&str>,
    ) -> Result<RevealCounterpartyKeyLinkageResult> {
        WalletInterface::reveal_counterparty_key_linkage(&self.inner, args, originator).await
    }
    async fn reveal_specific_key_linkage(
        &self,
        args: RevealSpecificKeyLinkageArgs,
        originator: Option<&str>,
    ) -> Result<RevealSpecificKeyLinkageResult> {
        WalletInterface::reveal_specific_key_linkage(&self.inner, args, originator).await
    }
    async fn create_action(
        &self,
        args: CreateActionArgs,
        originator: Option<&str>,
    ) -> Result<CreateActionResult> {
        {
            let _ = originator;
            self.actions
                .lock()
                .unwrap()
                .push(serde_json::to_value(args).unwrap());
            Ok(CreateActionResult {
                tx: Some(vec![1, 2, 3]),
                ..Default::default()
            })
        }
    }
    async fn sign_action(
        &self,
        args: SignActionArgs,
        originator: Option<&str>,
    ) -> Result<SignActionResult> {
        WalletInterface::sign_action(&self.inner, args, originator).await
    }
    async fn abort_action(
        &self,
        args: AbortActionArgs,
        originator: Option<&str>,
    ) -> Result<AbortActionResult> {
        WalletInterface::abort_action(&self.inner, args, originator).await
    }
    async fn list_actions(
        &self,
        args: ListActionsArgs,
        originator: Option<&str>,
    ) -> Result<ListActionsResult> {
        WalletInterface::list_actions(&self.inner, args, originator).await
    }
    async fn internalize_action(
        &self,
        args: InternalizeActionArgs,
        originator: Option<&str>,
    ) -> Result<InternalizeActionResult> {
        WalletInterface::internalize_action(&self.inner, args, originator).await
    }
    async fn list_outputs(
        &self,
        args: ListOutputsArgs,
        originator: Option<&str>,
    ) -> Result<ListOutputsResult> {
        WalletInterface::list_outputs(&self.inner, args, originator).await
    }
    async fn relinquish_output(
        &self,
        args: RelinquishOutputArgs,
        originator: Option<&str>,
    ) -> Result<RelinquishOutputResult> {
        WalletInterface::relinquish_output(&self.inner, args, originator).await
    }
    async fn acquire_certificate(
        &self,
        args: AcquireCertificateArgs,
        originator: Option<&str>,
    ) -> Result<WalletCertificate> {
        WalletInterface::acquire_certificate(&self.inner, args, originator).await
    }
    async fn list_certificates(
        &self,
        args: ListCertificatesArgs,
        originator: Option<&str>,
    ) -> Result<ListCertificatesResult> {
        {
            let _ = (args, originator);
            Ok(ListCertificatesResult {
                total_certificates: 1,
                certificates: vec![
                    serde_json::from_value(self.row["held"]["certificate"].clone()).unwrap(),
                ],
            })
        }
    }
    async fn prove_certificate(
        &self,
        args: ProveCertificateArgs,
        originator: Option<&str>,
    ) -> Result<ProveCertificateResult> {
        {
            let _ = (args, originator);
            Ok(ProveCertificateResult {
                keyring_for_verifier: serde_json::from_value(self.row["held"]["keyring"].clone())
                    .unwrap(),
                certificate: None,
                verifier: None,
            })
        }
    }
    async fn relinquish_certificate(
        &self,
        args: RelinquishCertificateArgs,
        originator: Option<&str>,
    ) -> Result<RelinquishCertificateResult> {
        WalletInterface::relinquish_certificate(&self.inner, args, originator).await
    }
    async fn discover_by_identity_key(
        &self,
        args: DiscoverByIdentityKeyArgs,
        originator: Option<&str>,
    ) -> Result<DiscoverCertificatesResult> {
        WalletInterface::discover_by_identity_key(&self.inner, args, originator).await
    }
    async fn discover_by_attributes(
        &self,
        args: DiscoverByAttributesArgs,
        originator: Option<&str>,
    ) -> Result<DiscoverCertificatesResult> {
        WalletInterface::discover_by_attributes(&self.inner, args, originator).await
    }
    async fn is_authenticated(&self, originator: Option<&str>) -> Result<AuthenticatedResult> {
        WalletInterface::is_authenticated(&self.inner, originator).await
    }
    async fn wait_for_authentication(
        &self,
        originator: Option<&str>,
    ) -> Result<AuthenticatedResult> {
        WalletInterface::wait_for_authentication(&self.inner, originator).await
    }
    async fn get_height(&self, originator: Option<&str>) -> Result<GetHeightResult> {
        WalletInterface::get_height(&self.inner, originator).await
    }
    async fn get_header_for_height(
        &self,
        args: GetHeaderArgs,
        originator: Option<&str>,
    ) -> Result<GetHeaderResult> {
        WalletInterface::get_header_for_height(&self.inner, args, originator).await
    }
    async fn get_network(&self, originator: Option<&str>) -> Result<GetNetworkResult> {
        WalletInterface::get_network(&self.inner, originator).await
    }
    async fn get_version(&self, originator: Option<&str>) -> Result<GetVersionResult> {
        WalletInterface::get_version(&self.inner, originator).await
    }
}
