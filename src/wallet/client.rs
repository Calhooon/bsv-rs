//! Multi-substrate wallet client.
//!
//! This module provides the [`WalletClient`] which offers a unified interface
//! for communicating with wallets over various transport substrates.

#[cfg(feature = "http")]
use crate::wallet::substrates::{HttpWalletJson, HttpWalletWire, SECURE_JSON_URL};
#[cfg(feature = "http")]
use crate::wallet::wire::WalletWireTransceiver;

use crate::wallet::types::Network;
use crate::wallet::{
    CreateHmacArgs, CreateHmacResult, CreateSignatureArgs, CreateSignatureResult, DecryptArgs,
    DecryptResult, EncryptArgs, EncryptResult, GetPublicKeyArgs, GetPublicKeyResult,
    VerifyHmacArgs, VerifyHmacResult, VerifySignatureArgs, VerifySignatureResult,
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
/// use bsv_sdk::wallet::{WalletClient, SubstrateType};
/// use bsv_sdk::wallet::{GetPublicKeyArgs, Protocol, SecurityLevel};
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
/// }).await?;
/// ```
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

    /// Returns the configured substrate type.
    pub fn substrate_type(&self) -> SubstrateType {
        self.substrate_type
    }

    /// Returns the configured originator.
    pub fn originator(&self) -> Option<&str> {
        self.originator.as_deref()
    }

    /// Returns the effective originator for requests.
    fn effective_originator(&self) -> &str {
        self.originator.as_deref().unwrap_or("")
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
                let client = HttpWalletJson::new(self.originator.clone(), None);
                self.connected = Some(ConnectedSubstrate::JsonApi(client));
            }
            SubstrateType::Cicada => {
                let wire = HttpWalletWire::new(self.originator.clone(), None);
                let transceiver = WalletWireTransceiver::new(wire);
                self.connected = Some(ConnectedSubstrate::WireApi(transceiver));
            }
            SubstrateType::SecureJsonApi => {
                let client =
                    HttpWalletJson::new(self.originator.clone(), Some(SECURE_JSON_URL.to_string()));
                self.connected = Some(ConnectedSubstrate::JsonApi(client));
            }
        }

        // Safe to unwrap here because we just set it above (or auto_detect did)
        Ok(self.connected.as_ref().expect("connected was just set"))
    }

    /// Auto-detects available substrate by trying each in order.
    #[cfg(feature = "http")]
    async fn auto_detect(&mut self) -> Result<(), Error> {
        let originator = self.effective_originator().to_string();

        // Try secure JSON API first
        let secure_client =
            HttpWalletJson::new(Some(originator.clone()), Some(SECURE_JSON_URL.to_string()));
        if let Ok(version) = secure_client.get_version(&originator).await {
            if !version.is_empty() {
                self.connected = Some(ConnectedSubstrate::JsonApi(secure_client));
                return Ok(());
            }
        }

        // Try standard JSON API
        let json_client = HttpWalletJson::new(Some(originator.clone()), None);
        if let Ok(version) = json_client.get_version(&originator).await {
            if !version.is_empty() {
                self.connected = Some(ConnectedSubstrate::JsonApi(json_client));
                return Ok(());
            }
        }

        // Try wire protocol
        let wire = HttpWalletWire::new(Some(originator.clone()), None);
        let wire_client = WalletWireTransceiver::new(wire);
        if let Ok(version) = wire_client.get_version(&originator).await {
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
        let originator = self.effective_originator().to_string();
        let substrate = self.connect().await?;

        match substrate {
            ConnectedSubstrate::JsonApi(client) => client.get_public_key(args, &originator).await,
            ConnectedSubstrate::WireApi(client) => client.get_public_key(args, &originator).await,
        }
    }

    /// Encrypts data using the wallet's derived key.
    #[cfg(feature = "http")]
    pub async fn encrypt(&mut self, args: EncryptArgs) -> Result<EncryptResult, Error> {
        let originator = self.effective_originator().to_string();
        let substrate = self.connect().await?;

        match substrate {
            ConnectedSubstrate::JsonApi(client) => client.encrypt(args, &originator).await,
            ConnectedSubstrate::WireApi(client) => client.encrypt(args, &originator).await,
        }
    }

    /// Decrypts data using the wallet's derived key.
    #[cfg(feature = "http")]
    pub async fn decrypt(&mut self, args: DecryptArgs) -> Result<DecryptResult, Error> {
        let originator = self.effective_originator().to_string();
        let substrate = self.connect().await?;

        match substrate {
            ConnectedSubstrate::JsonApi(client) => client.decrypt(args, &originator).await,
            ConnectedSubstrate::WireApi(client) => client.decrypt(args, &originator).await,
        }
    }

    /// Creates an HMAC using the wallet's derived key.
    #[cfg(feature = "http")]
    pub async fn create_hmac(&mut self, args: CreateHmacArgs) -> Result<CreateHmacResult, Error> {
        let originator = self.effective_originator().to_string();
        let substrate = self.connect().await?;

        match substrate {
            ConnectedSubstrate::JsonApi(client) => client.create_hmac(args, &originator).await,
            ConnectedSubstrate::WireApi(client) => client.create_hmac(args, &originator).await,
        }
    }

    /// Verifies an HMAC using the wallet's derived key.
    #[cfg(feature = "http")]
    pub async fn verify_hmac(&mut self, args: VerifyHmacArgs) -> Result<VerifyHmacResult, Error> {
        let originator = self.effective_originator().to_string();
        let substrate = self.connect().await?;

        match substrate {
            ConnectedSubstrate::JsonApi(client) => client.verify_hmac(args, &originator).await,
            ConnectedSubstrate::WireApi(client) => client.verify_hmac(args, &originator).await,
        }
    }

    /// Creates a signature using the wallet's derived key.
    #[cfg(feature = "http")]
    pub async fn create_signature(
        &mut self,
        args: CreateSignatureArgs,
    ) -> Result<CreateSignatureResult, Error> {
        let originator = self.effective_originator().to_string();
        let substrate = self.connect().await?;

        match substrate {
            ConnectedSubstrate::JsonApi(client) => client.create_signature(args, &originator).await,
            ConnectedSubstrate::WireApi(client) => client.create_signature(args, &originator).await,
        }
    }

    /// Verifies a signature using the wallet's derived key.
    #[cfg(feature = "http")]
    pub async fn verify_signature(
        &mut self,
        args: VerifySignatureArgs,
    ) -> Result<VerifySignatureResult, Error> {
        let originator = self.effective_originator().to_string();
        let substrate = self.connect().await?;

        match substrate {
            ConnectedSubstrate::JsonApi(client) => client.verify_signature(args, &originator).await,
            ConnectedSubstrate::WireApi(client) => client.verify_signature(args, &originator).await,
        }
    }

    /// Checks if the wallet is authenticated.
    #[cfg(feature = "http")]
    pub async fn is_authenticated(&mut self) -> Result<bool, Error> {
        let originator = self.effective_originator().to_string();
        let substrate = self.connect().await?;

        match substrate {
            ConnectedSubstrate::JsonApi(client) => client.is_authenticated(&originator).await,
            ConnectedSubstrate::WireApi(client) => client.is_authenticated(&originator).await,
        }
    }

    /// Gets the current block height.
    #[cfg(feature = "http")]
    pub async fn get_height(&mut self) -> Result<u64, Error> {
        let originator = self.effective_originator().to_string();
        let substrate = self.connect().await?;

        match substrate {
            ConnectedSubstrate::JsonApi(client) => client.get_height(&originator).await,
            ConnectedSubstrate::WireApi(client) => client.get_height(&originator).await,
        }
    }

    /// Gets the network the wallet is connected to.
    #[cfg(feature = "http")]
    pub async fn get_network(&mut self) -> Result<Network, Error> {
        let originator = self.effective_originator().to_string();
        let substrate = self.connect().await?;

        match substrate {
            ConnectedSubstrate::JsonApi(client) => client.get_network(&originator).await,
            ConnectedSubstrate::WireApi(client) => client.get_network(&originator).await,
        }
    }

    /// Gets the wallet version.
    #[cfg(feature = "http")]
    pub async fn get_version(&mut self) -> Result<String, Error> {
        let originator = self.effective_originator().to_string();
        let substrate = self.connect().await?;

        match substrate {
            ConnectedSubstrate::JsonApi(client) => client.get_version(&originator).await,
            ConnectedSubstrate::WireApi(client) => client.get_version(&originator).await,
        }
    }
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
        assert_eq!(client.effective_originator(), "myapp.com");

        let client = WalletClient::new(SubstrateType::Auto, None);
        assert_eq!(client.effective_originator(), "");
    }
}
