//! WalletInterface trait definition.
//!
//! This module defines the `WalletInterface` trait which mirrors the TypeScript SDK's
//! Wallet interface. It provides a standard interface for all 28 wallet operations.
//!
//! # Architecture
//!
//! The trait enables different wallet implementations:
//! - `ProtoWallet`: Crypto-only operations (key derivation, signing, encryption)
//! - Future full wallet: UTXO management, transaction history, certificates, etc.
//!
//! The `WalletWireProcessor` is generic over `WalletInterface`, allowing it to work
//! with any compliant wallet implementation.

use crate::primitives::PublicKey;
use crate::wallet::types::{
    Counterparty, RevealCounterpartyKeyLinkageResult, RevealSpecificKeyLinkageResult,
};
use crate::wallet::{
    AbortActionArgs, AbortActionResult, AcquireCertificateArgs, AuthenticatedResult,
    CreateActionArgs, CreateActionResult, CreateHmacArgs, CreateHmacResult, CreateSignatureArgs,
    CreateSignatureResult, DecryptArgs, DecryptResult, DiscoverByAttributesArgs,
    DiscoverByIdentityKeyArgs, DiscoverCertificatesResult, EncryptArgs, EncryptResult,
    GetHeaderArgs, GetHeaderResult, GetHeightResult, GetNetworkResult, GetPublicKeyArgs,
    GetPublicKeyResult, GetVersionResult, InternalizeActionArgs, InternalizeActionResult,
    ListActionsArgs, ListActionsResult, ListCertificatesArgs, ListCertificatesResult,
    ListOutputsArgs, ListOutputsResult, Protocol, ProveCertificateArgs, ProveCertificateResult,
    RelinquishCertificateArgs, RelinquishCertificateResult, RelinquishOutputArgs,
    RelinquishOutputResult, SignActionArgs, SignActionResult, VerifyHmacArgs, VerifyHmacResult,
    VerifySignatureArgs, VerifySignatureResult, WalletCertificate,
};
use crate::Result;
use async_trait::async_trait;

/// Arguments for revealing counterparty key linkage via WalletInterface.
#[derive(Debug, Clone)]
pub struct RevealCounterpartyKeyLinkageArgs {
    /// The public key of the counterparty.
    pub counterparty: PublicKey,
    /// The public key of the verifier.
    pub verifier: PublicKey,
    /// Whether this is a privileged request.
    pub privileged: Option<bool>,
    /// Reason for privileged access.
    pub privileged_reason: Option<String>,
}

/// Arguments for revealing specific key linkage via WalletInterface.
#[derive(Debug, Clone)]
pub struct RevealSpecificKeyLinkageArgs {
    /// The counterparty involved in the linkage.
    pub counterparty: Counterparty,
    /// The public key of the verifier.
    pub verifier: PublicKey,
    /// The protocol ID for the linkage.
    pub protocol_id: Protocol,
    /// The key ID for the linkage.
    pub key_id: String,
    /// Whether this is a privileged request.
    pub privileged: Option<bool>,
    /// Reason for privileged access.
    pub privileged_reason: Option<String>,
}

/// The WalletInterface trait defines all 28 wallet operations.
///
/// This trait is designed to be API-compatible with the TypeScript SDK's `WalletInterface`.
/// Implementations can support all methods (full wallet) or a subset (crypto-only wallet).
///
/// # Method Categories
///
/// **Key Operations (8 methods):**
/// - `get_public_key`, `encrypt`, `decrypt`, `create_hmac`, `verify_hmac`
/// - `create_signature`, `verify_signature`
/// - `reveal_counterparty_key_linkage`, `reveal_specific_key_linkage`
///
/// **Action Operations (5 methods):**
/// - `create_action`, `sign_action`, `abort_action`, `list_actions`, `internalize_action`
///
/// **Output Operations (2 methods):**
/// - `list_outputs`, `relinquish_output`
///
/// **Certificate Operations (4 methods):**
/// - `acquire_certificate`, `list_certificates`, `prove_certificate`, `relinquish_certificate`
///
/// **Discovery Operations (2 methods):**
/// - `discover_by_identity_key`, `discover_by_attributes`
///
/// **Chain/Status Operations (5 methods):**
/// - `is_authenticated`, `wait_for_authentication`, `get_height`, `get_header_for_height`
/// - `get_network`, `get_version`
///
/// # Implementation Notes
///
/// Implementations that don't support certain operations should return
/// `Err(Error::WalletError("method not supported".to_string()))`.
#[async_trait]
pub trait WalletInterface: Send + Sync {
    // =========================================================================
    // Key Operations
    // =========================================================================

    /// Retrieves a derived or identity public key.
    async fn get_public_key(
        &self,
        args: GetPublicKeyArgs,
        originator: &str,
    ) -> Result<GetPublicKeyResult>;

    /// Encrypts plaintext data using derived keys.
    async fn encrypt(&self, args: EncryptArgs, originator: &str) -> Result<EncryptResult>;

    /// Decrypts ciphertext using derived keys.
    async fn decrypt(&self, args: DecryptArgs, originator: &str) -> Result<DecryptResult>;

    /// Creates an HMAC for the provided data.
    async fn create_hmac(&self, args: CreateHmacArgs, originator: &str)
        -> Result<CreateHmacResult>;

    /// Verifies an HMAC for the provided data.
    async fn verify_hmac(&self, args: VerifyHmacArgs, originator: &str)
        -> Result<VerifyHmacResult>;

    /// Creates a digital signature.
    async fn create_signature(
        &self,
        args: CreateSignatureArgs,
        originator: &str,
    ) -> Result<CreateSignatureResult>;

    /// Verifies a digital signature.
    async fn verify_signature(
        &self,
        args: VerifySignatureArgs,
        originator: &str,
    ) -> Result<VerifySignatureResult>;

    /// Reveals the key linkage between self and a counterparty to a verifier.
    async fn reveal_counterparty_key_linkage(
        &self,
        args: RevealCounterpartyKeyLinkageArgs,
        originator: &str,
    ) -> Result<RevealCounterpartyKeyLinkageResult>;

    /// Reveals a specific key linkage to a verifier.
    async fn reveal_specific_key_linkage(
        &self,
        args: RevealSpecificKeyLinkageArgs,
        originator: &str,
    ) -> Result<RevealSpecificKeyLinkageResult>;

    // =========================================================================
    // Action Operations
    // =========================================================================

    /// Creates a new Bitcoin transaction.
    async fn create_action(
        &self,
        args: CreateActionArgs,
        originator: &str,
    ) -> Result<CreateActionResult>;

    /// Signs a transaction previously created using `create_action`.
    async fn sign_action(&self, args: SignActionArgs, originator: &str)
        -> Result<SignActionResult>;

    /// Aborts a transaction that is in progress.
    async fn abort_action(
        &self,
        args: AbortActionArgs,
        originator: &str,
    ) -> Result<AbortActionResult>;

    /// Lists all transactions matching the specified labels.
    async fn list_actions(
        &self,
        args: ListActionsArgs,
        originator: &str,
    ) -> Result<ListActionsResult>;

    /// Submits a transaction to be internalized.
    async fn internalize_action(
        &self,
        args: InternalizeActionArgs,
        originator: &str,
    ) -> Result<InternalizeActionResult>;

    // =========================================================================
    // Output Operations
    // =========================================================================

    /// Lists spendable outputs in a basket.
    async fn list_outputs(
        &self,
        args: ListOutputsArgs,
        originator: &str,
    ) -> Result<ListOutputsResult>;

    /// Relinquishes an output from a basket.
    async fn relinquish_output(
        &self,
        args: RelinquishOutputArgs,
        originator: &str,
    ) -> Result<RelinquishOutputResult>;

    // =========================================================================
    // Certificate Operations
    // =========================================================================

    /// Acquires an identity certificate.
    async fn acquire_certificate(
        &self,
        args: AcquireCertificateArgs,
        originator: &str,
    ) -> Result<WalletCertificate>;

    /// Lists identity certificates.
    async fn list_certificates(
        &self,
        args: ListCertificatesArgs,
        originator: &str,
    ) -> Result<ListCertificatesResult>;

    /// Proves select fields of an identity certificate.
    async fn prove_certificate(
        &self,
        args: ProveCertificateArgs,
        originator: &str,
    ) -> Result<ProveCertificateResult>;

    /// Relinquishes an identity certificate.
    async fn relinquish_certificate(
        &self,
        args: RelinquishCertificateArgs,
        originator: &str,
    ) -> Result<RelinquishCertificateResult>;

    // =========================================================================
    // Discovery Operations
    // =========================================================================

    /// Discovers certificates by identity key.
    async fn discover_by_identity_key(
        &self,
        args: DiscoverByIdentityKeyArgs,
        originator: &str,
    ) -> Result<DiscoverCertificatesResult>;

    /// Discovers certificates by attributes.
    async fn discover_by_attributes(
        &self,
        args: DiscoverByAttributesArgs,
        originator: &str,
    ) -> Result<DiscoverCertificatesResult>;

    // =========================================================================
    // Chain/Status Operations
    // =========================================================================

    /// Checks if the user is authenticated.
    async fn is_authenticated(&self, originator: &str) -> Result<AuthenticatedResult>;

    /// Waits until the user is authenticated.
    async fn wait_for_authentication(&self, originator: &str) -> Result<AuthenticatedResult>;

    /// Gets the current blockchain height.
    async fn get_height(&self, originator: &str) -> Result<GetHeightResult>;

    /// Gets the block header at a specific height.
    async fn get_header_for_height(
        &self,
        args: GetHeaderArgs,
        originator: &str,
    ) -> Result<GetHeaderResult>;

    /// Gets the Bitcoin network (mainnet or testnet).
    async fn get_network(&self, originator: &str) -> Result<GetNetworkResult>;

    /// Gets the wallet version string.
    async fn get_version(&self, originator: &str) -> Result<GetVersionResult>;
}

/// Marker trait for wallets that support crypto-only operations.
///
/// Crypto-only wallets implement key derivation, signing, encryption, and HMAC
/// operations but do not support transaction creation, UTXO management, or
/// certificate storage.
pub trait CryptoWallet: WalletInterface {}

/// Marker trait for full wallet implementations.
///
/// Full wallets support all 28 WalletInterface methods including:
/// - UTXO storage and management
/// - Transaction history tracking
/// - Certificate storage
/// - Block header storage/fetching
pub trait FullWallet: WalletInterface {}
