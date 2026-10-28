//! Multi-substrate wallet client.
//!
//! This module provides the [`WalletClient`] which offers a unified interface
//! for communicating with wallets over various transport substrates.

#[cfg(feature = "http")]
use crate::wallet::substrates::{HttpWalletJson, HttpWalletWire, SECURE_JSON_URL};
#[cfg(feature = "http")]
use crate::wallet::wire::WalletWireTransceiver;
use std::sync::Arc;

use super::client_instance::Instance;
use crate::wallet::interface::{
    RevealCounterpartyKeyLinkageArgs, RevealSpecificKeyLinkageArgs, WalletInterface,
};
use crate::wallet::types::{
    Network, RevealCounterpartyKeyLinkageResult, RevealSpecificKeyLinkageResult,
};
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
    Auto,

    /// HTTP JSON API (simpler, higher overhead).
    ///
    /// Default URL: http://localhost:3321
    JsonApi,

    /// Wallet wire protocol over HTTP (efficient binary).
    ///
    /// Default URL: http://localhost:3301
    Cicada,

    /// Secure local JSON API.
    ///
    /// URL: https://localhost:2121
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
/// let mut client = WalletClient::new(SubstrateType::Auto, Some("myapp.example.com".into()));
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
pub struct WalletClient {
    substrate_type: SubstrateType,
    originator: Option<String>,
    #[cfg(feature = "http")]
    connected: Option<ConnectedSubstrate>,
}

/// Connected substrate variant.
#[cfg(feature = "http")]
enum ConnectedSubstrate {
    JsonApi(HttpWalletJson),
    WireApi(WalletWireTransceiver<HttpWalletWire>),
    /// The instance handed to [`WalletClient::with_substrate`] (#335).
    Instance(Instance),
}

/// Forwards a call to the connected substrate with the client's originator:
/// the configured one, `None` when none is set (#329).
macro_rules! forward {
    ($client:ident.$method:ident($($args:ident)?)) => {{
        let originator = $client.effective_originator();
        let originator = originator.as_deref();
        match $client.connect().await? {
            ConnectedSubstrate::JsonApi(s) => s.$method($($args,)? originator).await,
            ConnectedSubstrate::WireApi(s) => s.$method($($args,)? originator).await,
            ConnectedSubstrate::Instance(s) => s.$method($($args,)? originator).await,
        }
    }};
}

impl WalletClient {
    /// Creates a new wallet client.
    ///
    /// # Arguments
    ///
    /// * `substrate_type` - The type of substrate to use
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
            #[cfg(feature = "http")]
            connected: None,
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
    /// ```rust,ignore
    /// let wallet = Arc::new(ProtoWallet::new(Some(PrivateKey::random())));
    /// let mut client = WalletClient::with_substrate(wallet, Some("myapp.com".into()));
    /// let version = client.get_version().await?;
    /// ```
    pub fn with_substrate(substrate: Arc<dyn WalletInterface>, originator: Option<String>) -> Self {
        Self {
            substrate_type: SubstrateType::Auto,
            originator,
            connected: Some(ConnectedSubstrate::Instance(Instance(substrate))),
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

    /// Ensures a substrate is connected, auto-detecting if necessary.
    #[cfg(feature = "http")]
    async fn connect(&mut self) -> Result<&ConnectedSubstrate, Error> {
        // If already connected, return existing connection
        if let Some(ref connected) = self.connected {
            return Ok(connected);
        }

        // Connect based on substrate type
        match self.substrate_type {
            SubstrateType::Auto => {
                // Auto-detect: try substrates in order
                self.auto_detect().await?;
            }
            SubstrateType::JsonApi => {
                let client = HttpWalletJson::new(self.originator.clone(), None)?;
                self.connected = Some(ConnectedSubstrate::JsonApi(client));
            }
            SubstrateType::Cicada => {
                let wire = HttpWalletWire::new(self.originator.clone(), None)?;
                let transceiver = WalletWireTransceiver::new(wire);
                self.connected = Some(ConnectedSubstrate::WireApi(transceiver));
            }
            SubstrateType::SecureJsonApi => {
                let client = HttpWalletJson::new(
                    self.originator.clone(),
                    Some(SECURE_JSON_URL.to_string()),
                )?;
                self.connected = Some(ConnectedSubstrate::JsonApi(client));
            }
        }

        // set just above (or by auto_detect)
        self.connected
            .as_ref()
            .ok_or_else(|| Error::WalletError("no wallet substrate connected".to_string()))
    }

    /// Auto-detects available substrate by trying each in order.
    #[cfg(feature = "http")]
    async fn auto_detect(&mut self) -> Result<(), Error> {
        let originator = self.effective_originator();

        // Try secure JSON API first
        let secure_client =
            HttpWalletJson::new(self.originator.clone(), Some(SECURE_JSON_URL.to_string()))?;
        if let Ok(version) = secure_client.get_version(originator.as_deref()).await {
            if !version.is_empty() {
                self.connected = Some(ConnectedSubstrate::JsonApi(secure_client));
                return Ok(());
            }
        }

        // Try standard JSON API
        let json_client = HttpWalletJson::new(self.originator.clone(), None)?;
        if let Ok(version) = json_client.get_version(originator.as_deref()).await {
            if !version.is_empty() {
                self.connected = Some(ConnectedSubstrate::JsonApi(json_client));
                return Ok(());
            }
        }

        // Try wire protocol
        let wire = HttpWalletWire::new(self.originator.clone(), None)?;
        let wire_client = WalletWireTransceiver::new(wire);
        if let Ok(version) = wire_client.get_version(originator.as_deref()).await {
            if !version.is_empty() {
                self.connected = Some(ConnectedSubstrate::WireApi(wire_client));
                return Ok(());
            }
        }

        Err(Error::WalletError(
            "no wallet available over any communication substrate".to_string(),
        ))
    }

    // =========================================================================
    // Wallet Interface Methods
    // =========================================================================

    /// Gets a public key from the wallet.
    #[cfg(feature = "http")]
    pub async fn get_public_key(
        &mut self,
        args: GetPublicKeyArgs,
    ) -> Result<GetPublicKeyResult, Error> {
        forward!(self.get_public_key(args))
    }

    /// Encrypts data using the wallet's derived key.
    #[cfg(feature = "http")]
    pub async fn encrypt(&mut self, args: EncryptArgs) -> Result<EncryptResult, Error> {
        forward!(self.encrypt(args))
    }

    /// Decrypts data using the wallet's derived key.
    #[cfg(feature = "http")]
    pub async fn decrypt(&mut self, args: DecryptArgs) -> Result<DecryptResult, Error> {
        forward!(self.decrypt(args))
    }

    /// Creates an HMAC using the wallet's derived key.
    #[cfg(feature = "http")]
    pub async fn create_hmac(&mut self, args: CreateHmacArgs) -> Result<CreateHmacResult, Error> {
        forward!(self.create_hmac(args))
    }

    /// Verifies an HMAC using the wallet's derived key.
    #[cfg(feature = "http")]
    pub async fn verify_hmac(&mut self, args: VerifyHmacArgs) -> Result<VerifyHmacResult, Error> {
        forward!(self.verify_hmac(args))
    }

    /// Creates a signature using the wallet's derived key.
    #[cfg(feature = "http")]
    pub async fn create_signature(
        &mut self,
        args: CreateSignatureArgs,
    ) -> Result<CreateSignatureResult, Error> {
        forward!(self.create_signature(args))
    }

    /// Verifies a signature using the wallet's derived key.
    #[cfg(feature = "http")]
    pub async fn verify_signature(
        &mut self,
        args: VerifySignatureArgs,
    ) -> Result<VerifySignatureResult, Error> {
        forward!(self.verify_signature(args))
    }

    /// Checks if the wallet is authenticated.
    #[cfg(feature = "http")]
    pub async fn is_authenticated(&mut self) -> Result<bool, Error> {
        forward!(self.is_authenticated())
    }

    /// Gets the current block height.
    #[cfg(feature = "http")]
    pub async fn get_height(&mut self) -> Result<u64, Error> {
        forward!(self.get_height())
    }

    /// Gets the network the wallet is connected to.
    #[cfg(feature = "http")]
    pub async fn get_network(&mut self) -> Result<Network, Error> {
        forward!(self.get_network())
    }

    /// Gets the wallet version.
    #[cfg(feature = "http")]
    pub async fn get_version(&mut self) -> Result<String, Error> {
        forward!(self.get_version())
    }

    /// Reveals the key linkage with a counterparty to a verifier.
    ///
    /// The wire substrate refuses it: this crate's transceiver does not
    /// write the call.
    pub async fn reveal_counterparty_key_linkage(
        &mut self,
        args: RevealCounterpartyKeyLinkageArgs,
    ) -> Result<RevealCounterpartyKeyLinkageResult, Error> {
        let originator = self.effective_originator();
        let originator = originator.as_deref();
        match self.connect().await? {
            ConnectedSubstrate::JsonApi(s) => {
                s.reveal_counterparty_key_linkage(args, originator).await
            }
            ConnectedSubstrate::WireApi(_) => Err(wire_lacks("revealCounterpartyKeyLinkage")),
            ConnectedSubstrate::Instance(s) => {
                s.reveal_counterparty_key_linkage(args, originator).await
            }
        }
    }

    /// Reveals the linkage of one derived key to a verifier.
    ///
    /// The wire substrate refuses it: this crate's transceiver does not
    /// write the call.
    pub async fn reveal_specific_key_linkage(
        &mut self,
        args: RevealSpecificKeyLinkageArgs,
    ) -> Result<RevealSpecificKeyLinkageResult, Error> {
        let originator = self.effective_originator();
        let originator = originator.as_deref();
        match self.connect().await? {
            ConnectedSubstrate::JsonApi(s) => s.reveal_specific_key_linkage(args, originator).await,
            ConnectedSubstrate::WireApi(_) => Err(wire_lacks("revealSpecificKeyLinkage")),
            ConnectedSubstrate::Instance(s) => {
                s.reveal_specific_key_linkage(args, originator).await
            }
        }
    }

    // =========================================================================
    // Action Methods
    // =========================================================================

    /// Creates a new transaction action.
    #[cfg(feature = "http")]
    pub async fn create_action(
        &mut self,
        args: CreateActionArgs,
    ) -> Result<CreateActionResult, Error> {
        forward!(self.create_action(args))
    }

    /// Signs a previously created transaction.
    #[cfg(feature = "http")]
    pub async fn sign_action(&mut self, args: SignActionArgs) -> Result<SignActionResult, Error> {
        forward!(self.sign_action(args))
    }

    /// Aborts an in-progress action.
    #[cfg(feature = "http")]
    pub async fn abort_action(
        &mut self,
        args: AbortActionArgs,
    ) -> Result<AbortActionResult, Error> {
        forward!(self.abort_action(args))
    }

    /// Lists wallet actions (transactions).
    #[cfg(feature = "http")]
    pub async fn list_actions(
        &mut self,
        args: ListActionsArgs,
    ) -> Result<ListActionsResult, Error> {
        forward!(self.list_actions(args))
    }

    /// Internalizes an external transaction.
    #[cfg(feature = "http")]
    pub async fn internalize_action(
        &mut self,
        args: InternalizeActionArgs,
    ) -> Result<InternalizeActionResult, Error> {
        crate::wallet::validation::validate_internalize_action_args(&args)?;
        forward!(self.internalize_action(args))
    }

    // =========================================================================
    // Output Methods
    // =========================================================================

    /// Lists wallet outputs.
    #[cfg(feature = "http")]
    pub async fn list_outputs(
        &mut self,
        args: ListOutputsArgs,
    ) -> Result<ListOutputsResult, Error> {
        forward!(self.list_outputs(args))
    }

    /// Relinquishes an output from a basket.
    #[cfg(feature = "http")]
    pub async fn relinquish_output(
        &mut self,
        args: RelinquishOutputArgs,
    ) -> Result<RelinquishOutputResult, Error> {
        forward!(self.relinquish_output(args))
    }

    // =========================================================================
    // Certificate Methods
    // =========================================================================

    /// Acquires a certificate.
    #[cfg(feature = "http")]
    pub async fn acquire_certificate(
        &mut self,
        args: AcquireCertificateArgs,
    ) -> Result<WalletCertificate, Error> {
        forward!(self.acquire_certificate(args))
    }

    /// Lists certificates.
    #[cfg(feature = "http")]
    pub async fn list_certificates(
        &mut self,
        args: ListCertificatesArgs,
    ) -> Result<ListCertificatesResult, Error> {
        forward!(self.list_certificates(args))
    }

    /// Proves a certificate.
    #[cfg(feature = "http")]
    pub async fn prove_certificate(
        &mut self,
        args: ProveCertificateArgs,
    ) -> Result<ProveCertificateResult, Error> {
        forward!(self.prove_certificate(args))
    }

    /// Relinquishes a certificate.
    #[cfg(feature = "http")]
    pub async fn relinquish_certificate(
        &mut self,
        args: RelinquishCertificateArgs,
    ) -> Result<RelinquishCertificateResult, Error> {
        forward!(self.relinquish_certificate(args))
    }

    // =========================================================================
    // Discovery Methods
    // =========================================================================

    /// Discovers certificates by identity key.
    #[cfg(feature = "http")]
    pub async fn discover_by_identity_key(
        &mut self,
        args: DiscoverByIdentityKeyArgs,
    ) -> Result<DiscoverCertificatesResult, Error> {
        forward!(self.discover_by_identity_key(args))
    }

    /// Discovers certificates by attributes.
    #[cfg(feature = "http")]
    pub async fn discover_by_attributes(
        &mut self,
        args: DiscoverByAttributesArgs,
    ) -> Result<DiscoverCertificatesResult, Error> {
        forward!(self.discover_by_attributes(args))
    }

    // =========================================================================
    // Chain Methods
    // =========================================================================

    /// Gets a block header for a given height.
    #[cfg(feature = "http")]
    pub async fn get_header(&mut self, args: GetHeaderArgs) -> Result<GetHeaderResult, Error> {
        forward!(self.get_header(args))
    }

    /// Waits for authentication.
    #[cfg(feature = "http")]
    pub async fn wait_for_authentication(&mut self) -> Result<bool, Error> {
        forward!(self.wait_for_authentication())
    }
}

/// The refusal of a call the wire transceiver does not write.
#[cfg(feature = "http")]
fn wire_lacks(call: &str) -> Error {
    Error::WalletError(format!(
        "{call} is not available over the wallet wire substrate"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_substrate_type() {
        let client = WalletClient::new(SubstrateType::Auto, None);
        assert_eq!(client.substrate_type(), SubstrateType::Auto);

        let client = WalletClient::new(SubstrateType::JsonApi, None);
        assert_eq!(client.substrate_type(), SubstrateType::JsonApi);
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
