//! `WalletInterface` for a client: the same dispatch and configured originator
//! as the inherent API. The trait's status records wrap the inherent values.

use super::*;
use crate::wallet::{AuthenticatedResult, GetHeightResult, GetNetworkResult, GetVersionResult};

// async_trait must see the whole impl; only the signatures are repeated here.
// Every operation uses the same forward! macro as the inherent methods.
macro_rules! impl_interface {
    ($($method:ident($args:ty) -> $result:ty;)*) => {
        #[async_trait::async_trait]
        impl WalletInterface for WalletClient {
            $(async fn $method(
                &self,
                args: $args,
                _originator: Option<&str>,
            ) -> Result<$result, Error> {
                forward!(self.$method(args))
            })*

            async fn is_authenticated(
                &self,
                _originator: Option<&str>,
            ) -> Result<AuthenticatedResult, Error> {
                Ok(AuthenticatedResult {
                    authenticated: forward!(self.is_authenticated())?,
                })
            }

            async fn get_height(&self, _originator: Option<&str>) -> Result<GetHeightResult, Error> {
                let height = u32::try_from(forward!(self.get_height())?)
                    .map_err(|_| Error::WalletError("wallet height exceeds u32".to_string()))?;
                Ok(GetHeightResult { height })
            }

            async fn get_network(&self, _originator: Option<&str>) -> Result<GetNetworkResult, Error> {
                Ok(GetNetworkResult {
                    network: forward!(self.get_network())?,
                })
            }

            async fn get_version(&self, _originator: Option<&str>) -> Result<GetVersionResult, Error> {
                Ok(GetVersionResult {
                    version: forward!(self.get_version())?,
                })
            }

            async fn get_header_for_height(
                &self,
                args: GetHeaderArgs,
                _originator: Option<&str>,
            ) -> Result<GetHeaderResult, Error> {
                forward!(self.get_header(args))
            }

            async fn wait_for_authentication(
                &self,
                _originator: Option<&str>,
            ) -> Result<AuthenticatedResult, Error> {
                Ok(AuthenticatedResult {
                    authenticated: forward!(self.wait_for_authentication())?,
                })
            }
        }
    };
}

impl_interface! {
    get_public_key(GetPublicKeyArgs) -> GetPublicKeyResult;
    encrypt(EncryptArgs) -> EncryptResult;
    decrypt(DecryptArgs) -> DecryptResult;
    create_hmac(CreateHmacArgs) -> CreateHmacResult;
    verify_hmac(VerifyHmacArgs) -> VerifyHmacResult;
    create_signature(CreateSignatureArgs) -> CreateSignatureResult;
    verify_signature(VerifySignatureArgs) -> VerifySignatureResult;
    reveal_counterparty_key_linkage(RevealCounterpartyKeyLinkageArgs) -> RevealCounterpartyKeyLinkageResult;
    reveal_specific_key_linkage(RevealSpecificKeyLinkageArgs) -> RevealSpecificKeyLinkageResult;
    create_action(CreateActionArgs) -> CreateActionResult;
    sign_action(SignActionArgs) -> SignActionResult;
    abort_action(AbortActionArgs) -> AbortActionResult;
    list_actions(ListActionsArgs) -> ListActionsResult;
    internalize_action(InternalizeActionArgs) -> InternalizeActionResult;
    list_outputs(ListOutputsArgs) -> ListOutputsResult;
    relinquish_output(RelinquishOutputArgs) -> RelinquishOutputResult;
    acquire_certificate(AcquireCertificateArgs) -> WalletCertificate;
    list_certificates(ListCertificatesArgs) -> ListCertificatesResult;
    prove_certificate(ProveCertificateArgs) -> ProveCertificateResult;
    relinquish_certificate(RelinquishCertificateArgs) -> RelinquishCertificateResult;
    discover_by_identity_key(DiscoverByIdentityKeyArgs) -> DiscoverCertificatesResult;
    discover_by_attributes(DiscoverByAttributesArgs) -> DiscoverCertificatesResult;
}
