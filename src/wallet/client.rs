//! Multi-substrate wallet client.
//!
//! This module provides the [`WalletClient`] which offers a unified interface
//! for communicating with wallets over various transport substrates.

#[cfg(feature = "http")]
use futures::lock::Mutex;
use std::sync::{Arc, OnceLock};

use super::client_instance::Instance;
use crate::wallet::interface::{
    RevealCounterpartyKeyLinkageArgs, RevealSpecificKeyLinkageArgs, WalletInterface,
};
use crate::wallet::types::{
    Network, RevealCounterpartyKeyLinkageResult, RevealSpecificKeyLinkageResult,
};
#[cfg(feature = "http")]
use crate::wallet::{substrates::HttpWalletWire, wire::WalletWireTransceiver};
use crate::wallet::{
    AbortActionArgs, AbortActionResult, AcquireCertificateArgs, CreateActionArgs,
    CreateActionResult, CreateHmacArgs, CreateHmacResult, CreateSignatureArgs,
    CreateSignatureResult, DecryptArgs, DecryptResult, DiscoverByAttributesArgs,
    DiscoverByIdentityKeyArgs, DiscoverCertificatesResult, EncryptArgs, EncryptResult,
    GetHeaderArgs, GetHeaderResult, GetPublicKeyArgs, GetPublicKeyResult, InternalizeActionArgs,
    InternalizeActionResult, ListActionsArgs, ListActionsResult, ListCertificatesArgs,
    ListCertificatesResult, ListOutputsArgs, ListOutputsResult, ProveCertificateArgs,
    ProveCertificateResult, RelinquishCertificateArgs, RelinquishCertificateResult,
    RelinquishOutputArgs, RelinquishOutputResult, SignActionArgs, SignActionResult, VerifyHmacArgs,
    VerifyHmacResult, VerifySignatureArgs, VerifySignatureResult, WalletCertificate,
};
use crate::Error;

/// Substrate types for WalletClient.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubstrateType {
    /// Auto-detect available substrate.
    ///
    /// Tries substrates in order:
    /// 1. Secure JSON API (https://localhost:2121)
    /// 2. JSON API (http://localhost:3321)
    /// 3. Wire protocol over HTTP (http://localhost:3301)
    ///
    /// Without `http`, no transport can be discovered; use `with_substrate`.
    Auto,

    /// HTTP JSON API (simpler, higher overhead).
    ///
    /// Default URL: http://localhost:3321
    #[cfg(feature = "http")]
    JsonApi,

    /// Wallet wire protocol over HTTP (efficient binary).
    ///
    /// Default URL: http://localhost:3301
    #[cfg(feature = "http")]
    Cicada,

    /// Secure local JSON API.
    ///
    /// URL: https://localhost:2121
    #[cfg(feature = "http")]
    SecureJsonApi,
}

/// Multi-substrate wallet client SDK.
///
/// WalletClient provides a unified interface for communicating with wallets
/// over various transport substrates. When set to [`SubstrateType::Auto`], it
/// will probe available substrates and use the first that responds.
///
/// # Substrate Selection
///
/// | Type | Protocol | Default Port | Use Case |
/// |------|----------|--------------|----------|
/// | `Auto` | Various | - | Production apps |
/// | `JsonApi` | JSON | 3321 | Debugging, simple integration |
/// | `Cicada` | Binary | 3301 | High performance |
/// | `SecureJsonApi` | JSON/TLS | 2121 | Secure local communication |
///
/// # Example
///
/// ```rust,ignore
/// use bsv_rs::wallet::{WalletClient, SubstrateType};
/// use bsv_rs::wallet::{GetPublicKeyArgs, Protocol, SecurityLevel};
///
/// // Create client with auto-detection
/// let client = WalletClient::new(SubstrateType::Auto, Some("myapp.example.com".into()));
///
/// // Get wallet version (triggers auto-detection)
/// let version = client.get_version().await?;
///
/// // Make wallet calls
/// let result = client.get_public_key(GetPublicKeyArgs {
///     identity_key: true,
///     protocol_id: None,
///     key_id: None,
///     counterparty: None,
///     for_self: None,
///     ..Default::default()
/// }).await?;
/// ```
///
/// A wallet the caller already holds (an in-process wallet, a substrate
/// built with its own URL or client) is handed over with
/// [`WalletClient::with_substrate`], the reference's `WalletInterface`
/// alternative of the constructor's `substrate` parameter (#335).
/// The core and its [`WalletInterface`] implementation need only `wallet`;
/// named HTTP substrates and discovery require `http` (#404). Trait calls
/// use this client's configured originator, just like inherent calls.
pub struct WalletClient {
    substrate_type: SubstrateType,
    originator: Option<String>,
    // The reference only reassigns its substrate during connection. Keep that
    // one-time resolution interior so wallet operations can all borrow &self.
    connected: OnceLock<ConnectedSubstrate>,
    #[cfg(feature = "http")]
    connecting: Mutex<()>,
}

/// Connected substrate variant.
enum ConnectedSubstrate {
    #[cfg(feature = "http")]
    JsonApi(http::JsonApi),
    #[cfg(feature = "http")]
    WireApi(WalletWireTransceiver<HttpWalletWire>),
    /// The instance handed to [`WalletClient::with_substrate`] (#335).
    Instance(Instance),
}

/// Forwards a call to the connected substrate with the client's originator:
/// the configured one, `None` when none is set (#329).
macro_rules! forward {
    ($client:ident.internalize_action($args:ident)) => {{
        crate::wallet::validation::validate_internalize_action_args(&$args)?;
        forward!(@call $client.internalize_action($args))
    }};
    ($client:ident.$method:ident($($args:ident)?)) => {
        forward!(@call $client.$method($($args)?))
    };
    (@call $client:ident.$method:ident($($args:ident)?)) => {{
        let originator = $client.effective_originator();
        let originator = originator.as_deref();
        match $client.connect().await? {
            #[cfg(feature = "http")]
            ConnectedSubstrate::JsonApi(s) => s.$method($($args,)? originator).await,
            #[cfg(feature = "http")]
            ConnectedSubstrate::WireApi(s) => s.$method($($args,)? originator).await,
            ConnectedSubstrate::Instance(s) => s.$method($($args,)? originator).await,
        }
    }};
}

#[cfg(feature = "http")]
mod http;
mod interface;

impl WalletClient {
    /// Creates a new wallet client.
    ///
    /// # Arguments
    ///
    /// * `substrate_type` - The type of substrate to use (`http` for named transports).
    ///   Without `http`, `Auto` reports no available substrate on a call;
    ///   use [`Self::with_substrate`] to supply an in-process wallet.
    /// * `originator` - Optional originator identifier for the client
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // Auto-detect substrate
    /// let client = WalletClient::new(SubstrateType::Auto, None);
    ///
    /// // Use specific substrate
    /// let client = WalletClient::new(SubstrateType::JsonApi, Some("myapp.com".into()));
    /// ```
    pub fn new(substrate_type: SubstrateType, originator: Option<String>) -> Self {
        Self {
            substrate_type,
            originator,
            connected: OnceLock::new(),
            #[cfg(feature = "http")]
            connecting: Mutex::new(()),
        }
    }

    /// Creates a client over a wallet the caller already holds: the
    /// reference's `new WalletClient(substrate: WalletInterface, originator)`
    /// (`ts-stack@edf6e03` `WalletClient.ts:83-107`), the instance kept as
    /// the substrate (#335).
    ///
    /// Nothing is probed: every call goes to `substrate` with the client's
    /// originator, the configured one or `None` (#329), exactly as it goes
    /// to a named substrate. The client reports [`SubstrateType::Auto`],
    /// the reference's default parameter, its substrate an instance.
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::sync::Arc;
    /// use bsv_rs::primitives::PrivateKey;
    /// use bsv_rs::wallet::{ProtoWallet, WalletClient};
    ///
    /// # async fn example() -> bsv_rs::Result<()> {
    /// let wallet = Arc::new(ProtoWallet::new(Some(PrivateKey::random())));
    /// let client = WalletClient::with_substrate(wallet, Some("myapp.com".into()));
    /// let version = client.get_version().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_substrate(substrate: Arc<dyn WalletInterface>, originator: Option<String>) -> Self {
        Self {
            substrate_type: SubstrateType::Auto,
            originator,
            connected: OnceLock::from(ConnectedSubstrate::Instance(Instance(substrate))),
            #[cfg(feature = "http")]
            connecting: Mutex::new(()),
        }
    }

    /// Returns the configured substrate type.
    pub fn substrate_type(&self) -> SubstrateType {
        self.substrate_type
    }

    /// Returns the configured originator.
    pub fn originator(&self) -> Option<&str> {
        self.originator.as_deref()
    }

    /// Returns the effective originator for requests: the configured one,
    /// `None` when none is set (#329).
    fn effective_originator(&self) -> Option<String> {
        self.originator.clone()
    }

    /// Ensures a substrate is connected, serializing discovery only.
    async fn connect(&self) -> Result<&ConnectedSubstrate, Error> {
        if let Some(connected) = self.connected.get() {
            return Ok(connected);
        }
        #[cfg(feature = "http")]
        {
            let _connecting = self.connecting.lock().await;
            if let Some(connected) = self.connected.get() {
                return Ok(connected);
            }
            let connected = http::connect(self.substrate_type, self.originator.clone()).await?;
            let _ = self.connected.set(connected);
            self.connected
                .get()
                .ok_or_else(|| Error::WalletError("no wallet substrate connected".to_string()))
        }
        #[cfg(not(feature = "http"))]
        Err(Error::WalletError(
            "no wallet available over any communication substrate".to_string(),
        ))
    }

    // =========================================================================
    // Wallet Interface Methods
    // =========================================================================

    /// Gets a public key from the wallet.
    pub async fn get_public_key(
        &self,
        args: GetPublicKeyArgs,
    ) -> Result<GetPublicKeyResult, Error> {
        forward!(self.get_public_key(args))
    }

    /// Encrypts data using the wallet's derived key.
    pub async fn encrypt(&self, args: EncryptArgs) -> Result<EncryptResult, Error> {
        forward!(self.encrypt(args))
    }

    /// Decrypts data using the wallet's derived key.
    pub async fn decrypt(&self, args: DecryptArgs) -> Result<DecryptResult, Error> {
        forward!(self.decrypt(args))
    }

    /// Creates an HMAC using the wallet's derived key.
    pub async fn create_hmac(&self, args: CreateHmacArgs) -> Result<CreateHmacResult, Error> {
        forward!(self.create_hmac(args))
    }

    /// Verifies an HMAC using the wallet's derived key.
    pub async fn verify_hmac(&self, args: VerifyHmacArgs) -> Result<VerifyHmacResult, Error> {
        forward!(self.verify_hmac(args))
    }

    /// Creates a signature using the wallet's derived key.
    pub async fn create_signature(
        &self,
        args: CreateSignatureArgs,
    ) -> Result<CreateSignatureResult, Error> {
        forward!(self.create_signature(args))
    }

    /// Verifies a signature using the wallet's derived key.
    pub async fn verify_signature(
        &self,
        args: VerifySignatureArgs,
    ) -> Result<VerifySignatureResult, Error> {
        forward!(self.verify_signature(args))
    }

    /// Checks if the wallet is authenticated.
    pub async fn is_authenticated(&self) -> Result<bool, Error> {
        forward!(self.is_authenticated())
    }

    /// Gets the current block height.
    pub async fn get_height(&self) -> Result<u64, Error> {
        forward!(self.get_height())
    }

    /// Gets the network the wallet is connected to.
    pub async fn get_network(&self) -> Result<Network, Error> {
        forward!(self.get_network())
    }

    /// Gets the wallet version.
    pub async fn get_version(&self) -> Result<String, Error> {
        forward!(self.get_version())
    }

    /// Reveals the key linkage with a counterparty to a verifier.
    pub async fn reveal_counterparty_key_linkage(
        &self,
        args: RevealCounterpartyKeyLinkageArgs,
    ) -> Result<RevealCounterpartyKeyLinkageResult, Error> {
        forward!(self.reveal_counterparty_key_linkage(args))
    }

    /// Reveals the linkage of one derived key to a verifier.
    pub async fn reveal_specific_key_linkage(
        &self,
        args: RevealSpecificKeyLinkageArgs,
    ) -> Result<RevealSpecificKeyLinkageResult, Error> {
        forward!(self.reveal_specific_key_linkage(args))
    }

    // =========================================================================
    // Action Methods
    // =========================================================================

    /// Creates a new transaction action.
    pub async fn create_action(&self, args: CreateActionArgs) -> Result<CreateActionResult, Error> {
        forward!(self.create_action(args))
    }

    /// Signs a previously created transaction.
    pub async fn sign_action(&self, args: SignActionArgs) -> Result<SignActionResult, Error> {
        forward!(self.sign_action(args))
    }

    /// Aborts an in-progress action.
    pub async fn abort_action(&self, args: AbortActionArgs) -> Result<AbortActionResult, Error> {
        forward!(self.abort_action(args))
    }

    /// Lists wallet actions (transactions).
    pub async fn list_actions(&self, args: ListActionsArgs) -> Result<ListActionsResult, Error> {
        forward!(self.list_actions(args))
    }

    /// Internalizes an external transaction.
    pub async fn internalize_action(
        &self,
        args: InternalizeActionArgs,
    ) -> Result<InternalizeActionResult, Error> {
        forward!(self.internalize_action(args))
    }

    // =========================================================================
    // Output Methods
    // =========================================================================

    /// Lists wallet outputs.
    pub async fn list_outputs(&self, args: ListOutputsArgs) -> Result<ListOutputsResult, Error> {
        forward!(self.list_outputs(args))
    }

    /// Relinquishes an output from a basket.
    pub async fn relinquish_output(
        &self,
        args: RelinquishOutputArgs,
    ) -> Result<RelinquishOutputResult, Error> {
        forward!(self.relinquish_output(args))
    }

    // =========================================================================
    // Certificate Methods
    // =========================================================================

    /// Acquires a certificate.
    pub async fn acquire_certificate(
        &self,
        args: AcquireCertificateArgs,
    ) -> Result<WalletCertificate, Error> {
        forward!(self.acquire_certificate(args))
    }

    /// Lists certificates.
    pub async fn list_certificates(
        &self,
        args: ListCertificatesArgs,
    ) -> Result<ListCertificatesResult, Error> {
        forward!(self.list_certificates(args))
    }

    /// Proves a certificate.
    pub async fn prove_certificate(
        &self,
        args: ProveCertificateArgs,
    ) -> Result<ProveCertificateResult, Error> {
        forward!(self.prove_certificate(args))
    }

    /// Relinquishes a certificate.
    pub async fn relinquish_certificate(
        &self,
        args: RelinquishCertificateArgs,
    ) -> Result<RelinquishCertificateResult, Error> {
        forward!(self.relinquish_certificate(args))
    }

    // =========================================================================
    // Discovery Methods
    // =========================================================================

    /// Discovers certificates by identity key.
    pub async fn discover_by_identity_key(
        &self,
        args: DiscoverByIdentityKeyArgs,
    ) -> Result<DiscoverCertificatesResult, Error> {
        forward!(self.discover_by_identity_key(args))
    }

    /// Discovers certificates by attributes.
    pub async fn discover_by_attributes(
        &self,
        args: DiscoverByAttributesArgs,
    ) -> Result<DiscoverCertificatesResult, Error> {
        forward!(self.discover_by_attributes(args))
    }

    // =========================================================================
    // Chain Methods
    // =========================================================================

    /// Gets a block header for a given height.
    pub async fn get_header(&self, args: GetHeaderArgs) -> Result<GetHeaderResult, Error> {
        forward!(self.get_header(args))
    }

    /// Waits for authentication.
    pub async fn wait_for_authentication(&self) -> Result<bool, Error> {
        forward!(self.wait_for_authentication())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_substrate_type() {
        let client = WalletClient::new(SubstrateType::Auto, None);
        assert_eq!(client.substrate_type(), SubstrateType::Auto);

        #[cfg(feature = "http")]
        {
            let client = WalletClient::new(SubstrateType::JsonApi, None);
            assert_eq!(client.substrate_type(), SubstrateType::JsonApi);
        }
    }

    #[test]
    fn test_originator() {
        let client = WalletClient::new(SubstrateType::Auto, Some("myapp.com".into()));
        assert_eq!(client.originator(), Some("myapp.com"));

        let client = WalletClient::new(SubstrateType::Auto, None);
        assert_eq!(client.originator(), None);
    }

    #[test]
    fn test_effective_originator() {
        let client = WalletClient::new(SubstrateType::Auto, Some("myapp.com".into()));
        assert_eq!(client.effective_originator().as_deref(), Some("myapp.com"));

        // None when none is set, never "" (#329)
        let client = WalletClient::new(SubstrateType::Auto, None);
        assert_eq!(client.effective_originator(), None);
    }
}
