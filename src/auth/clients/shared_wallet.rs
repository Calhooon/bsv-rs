//! Private shared ownership adapter; callers need no Clone implementation.

use crate::wallet::interface::{RevealCounterpartyKeyLinkageArgs, RevealSpecificKeyLinkageArgs};
use crate::wallet::{
    AbortActionArgs, AbortActionResult, AcquireCertificateArgs, AuthenticatedResult,
    CreateActionArgs, CreateActionResult, CreateHmacArgs, CreateHmacResult, CreateSignatureArgs,
    CreateSignatureResult, DecryptArgs, DecryptResult, DiscoverByAttributesArgs,
    DiscoverByIdentityKeyArgs, DiscoverCertificatesResult, EncryptArgs, EncryptResult,
    GetHeaderArgs, GetHeaderResult, GetHeightResult, GetNetworkResult, GetPublicKeyArgs,
    GetPublicKeyResult, GetVersionResult, InternalizeActionArgs, InternalizeActionResult,
    ListActionsArgs, ListActionsResult, ListCertificatesArgs, ListCertificatesResult,
    ListOutputsArgs, ListOutputsResult, ProveCertificateArgs, ProveCertificateResult,
    RelinquishCertificateArgs, RelinquishCertificateResult, RelinquishOutputArgs,
    RelinquishOutputResult, RevealCounterpartyKeyLinkageResult, RevealSpecificKeyLinkageResult,
    SignActionArgs, SignActionResult, VerifyHmacArgs, VerifyHmacResult, VerifySignatureArgs,
    VerifySignatureResult, WalletCertificate, WalletInterface,
};
use crate::Result;
use std::sync::Arc;

pub(super) struct SharedWallet<W>(pub Arc<W>);

#[async_trait::async_trait]
impl<W: WalletInterface> WalletInterface for SharedWallet<W> {
    async fn get_public_key(
        &self,
        args: GetPublicKeyArgs,
        originator: Option<&str>,
    ) -> Result<GetPublicKeyResult> {
        self.0.get_public_key(args, originator).await
    }
    async fn encrypt(&self, args: EncryptArgs, originator: Option<&str>) -> Result<EncryptResult> {
        self.0.encrypt(args, originator).await
    }
    async fn decrypt(&self, args: DecryptArgs, originator: Option<&str>) -> Result<DecryptResult> {
        self.0.decrypt(args, originator).await
    }
    async fn create_hmac(
        &self,
        args: CreateHmacArgs,
        originator: Option<&str>,
    ) -> Result<CreateHmacResult> {
        self.0.create_hmac(args, originator).await
    }
    async fn verify_hmac(
        &self,
        args: VerifyHmacArgs,
        originator: Option<&str>,
    ) -> Result<VerifyHmacResult> {
        self.0.verify_hmac(args, originator).await
    }
    async fn create_signature(
        &self,
        args: CreateSignatureArgs,
        originator: Option<&str>,
    ) -> Result<CreateSignatureResult> {
        self.0.create_signature(args, originator).await
    }
    async fn verify_signature(
        &self,
        args: VerifySignatureArgs,
        originator: Option<&str>,
    ) -> Result<VerifySignatureResult> {
        self.0.verify_signature(args, originator).await
    }
    async fn reveal_counterparty_key_linkage(
        &self,
        args: RevealCounterpartyKeyLinkageArgs,
        originator: Option<&str>,
    ) -> Result<RevealCounterpartyKeyLinkageResult> {
        self.0
            .reveal_counterparty_key_linkage(args, originator)
            .await
    }
    async fn reveal_specific_key_linkage(
        &self,
        args: RevealSpecificKeyLinkageArgs,
        originator: Option<&str>,
    ) -> Result<RevealSpecificKeyLinkageResult> {
        self.0.reveal_specific_key_linkage(args, originator).await
    }
    async fn create_action(
        &self,
        args: CreateActionArgs,
        originator: Option<&str>,
    ) -> Result<CreateActionResult> {
        self.0.create_action(args, originator).await
    }
    async fn sign_action(
        &self,
        args: SignActionArgs,
        originator: Option<&str>,
    ) -> Result<SignActionResult> {
        self.0.sign_action(args, originator).await
    }
    async fn abort_action(
        &self,
        args: AbortActionArgs,
        originator: Option<&str>,
    ) -> Result<AbortActionResult> {
        self.0.abort_action(args, originator).await
    }
    async fn list_actions(
        &self,
        args: ListActionsArgs,
        originator: Option<&str>,
    ) -> Result<ListActionsResult> {
        self.0.list_actions(args, originator).await
    }
    async fn internalize_action(
        &self,
        args: InternalizeActionArgs,
        originator: Option<&str>,
    ) -> Result<InternalizeActionResult> {
        self.0.internalize_action(args, originator).await
    }
    async fn list_outputs(
        &self,
        args: ListOutputsArgs,
        originator: Option<&str>,
    ) -> Result<ListOutputsResult> {
        self.0.list_outputs(args, originator).await
    }
    async fn relinquish_output(
        &self,
        args: RelinquishOutputArgs,
        originator: Option<&str>,
    ) -> Result<RelinquishOutputResult> {
        self.0.relinquish_output(args, originator).await
    }
    async fn acquire_certificate(
        &self,
        args: AcquireCertificateArgs,
        originator: Option<&str>,
    ) -> Result<WalletCertificate> {
        self.0.acquire_certificate(args, originator).await
    }
    async fn list_certificates(
        &self,
        args: ListCertificatesArgs,
        originator: Option<&str>,
    ) -> Result<ListCertificatesResult> {
        self.0.list_certificates(args, originator).await
    }
    async fn prove_certificate(
        &self,
        args: ProveCertificateArgs,
        originator: Option<&str>,
    ) -> Result<ProveCertificateResult> {
        self.0.prove_certificate(args, originator).await
    }
    async fn relinquish_certificate(
        &self,
        args: RelinquishCertificateArgs,
        originator: Option<&str>,
    ) -> Result<RelinquishCertificateResult> {
        self.0.relinquish_certificate(args, originator).await
    }
    async fn discover_by_identity_key(
        &self,
        args: DiscoverByIdentityKeyArgs,
        originator: Option<&str>,
    ) -> Result<DiscoverCertificatesResult> {
        self.0.discover_by_identity_key(args, originator).await
    }
    async fn discover_by_attributes(
        &self,
        args: DiscoverByAttributesArgs,
        originator: Option<&str>,
    ) -> Result<DiscoverCertificatesResult> {
        self.0.discover_by_attributes(args, originator).await
    }
    async fn is_authenticated(&self, originator: Option<&str>) -> Result<AuthenticatedResult> {
        self.0.is_authenticated(originator).await
    }
    async fn wait_for_authentication(
        &self,
        originator: Option<&str>,
    ) -> Result<AuthenticatedResult> {
        self.0.wait_for_authentication(originator).await
    }
    async fn get_height(&self, originator: Option<&str>) -> Result<GetHeightResult> {
        self.0.get_height(originator).await
    }
    async fn get_header_for_height(
        &self,
        args: GetHeaderArgs,
        originator: Option<&str>,
    ) -> Result<GetHeaderResult> {
        self.0.get_header_for_height(args, originator).await
    }
    async fn get_network(&self, originator: Option<&str>) -> Result<GetNetworkResult> {
        self.0.get_network(originator).await
    }
    async fn get_version(&self, originator: Option<&str>) -> Result<GetVersionResult> {
        self.0.get_version(originator).await
    }
}
