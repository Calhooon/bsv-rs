//! Core wallet type definitions.
//!
//! This module provides the foundational types used throughout the wallet module,
//! including security levels, protocols, counterparty identifiers, transaction-related
//! types, and certificate structures. These types are designed to be API-compatible
//! with the TypeScript and Go BSV SDKs.
//!
//! # Type Categories
//!
//! - **Action Types**: CreateAction, SignAction, AbortAction, ListActions, InternalizeAction
//! - **Output Types**: ListOutputs, RelinquishOutput, WalletOutput
//! - **Certificate Types**: WalletCertificate, AcquireCertificate, ListCertificates, ProveCertificate
//! - **Discovery Types**: DiscoverByIdentityKey, DiscoverByAttributes
//! - **Auth/Chain Types**: Authentication, GetHeader, GetHeight, GetNetwork, GetVersion

use crate::primitives::PublicKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// =============================================================================
// Primitive Type Aliases
// =============================================================================

/// A transaction ID as a 32-byte array.
pub type TxId = [u8; 32];

/// A satoshi value (0 to 21 trillion).
/// Maximum: 21,000,000 BTC * 100,000,000 satoshis = 2.1 * 10^15 satoshis.
pub type SatoshiValue = u64;

/// Maximum satoshi value (total supply).
pub const MAX_SATOSHIS: u64 = 2_100_000_000_000_000;

// =============================================================================
// Network
// =============================================================================

/// The Bitcoin network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    /// Main network.
    #[default]
    Mainnet,
    /// Test network.
    Testnet,
}

impl Network {
    /// Returns the network as a string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Network::Mainnet => "mainnet",
            Network::Testnet => "testnet",
        }
    }
}

// =============================================================================
// Security Level
// =============================================================================

/// Security level for protocol operations.
///
/// Determines the level of user interaction required for key derivation:
/// - Level 0 (Silent): No user interaction required
/// - Level 1 (App): Requires user approval per application
/// - Level 2 (Counterparty): Requires user approval per counterparty per application
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[repr(u8)]
pub enum SecurityLevel {
    /// Level 0: Silently grants the request with no user interaction.
    #[default]
    #[serde(rename = "0")]
    Silent = 0,
    /// Level 1: Requires user approval for every application.
    #[serde(rename = "1")]
    App = 1,
    /// Level 2: Requires user approval per counterparty per application.
    #[serde(rename = "2")]
    Counterparty = 2,
}

impl SecurityLevel {
    /// Creates a security level from a u8 value.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(SecurityLevel::Silent),
            1 => Some(SecurityLevel::App),
            2 => Some(SecurityLevel::Counterparty),
            _ => None,
        }
    }

    /// Returns the security level as a u8.
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

impl From<SecurityLevel> for u8 {
    fn from(level: SecurityLevel) -> Self {
        level as u8
    }
}

impl TryFrom<u8> for SecurityLevel {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        SecurityLevel::from_u8(value).ok_or(())
    }
}

// =============================================================================
// Protocol
// =============================================================================

/// A wallet protocol identifier combining security level and protocol name.
///
/// The protocol name must be:
/// - 5 to 400 characters (or 430 for "specific linkage revelation" protocols)
/// - Lowercase letters, numbers, and single spaces only
/// - Cannot contain consecutive spaces
/// - Cannot end with " protocol"
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Protocol {
    /// The security level for this protocol.
    pub security_level: SecurityLevel,
    /// The protocol name (5-400 characters).
    pub protocol_name: String,
}

impl Protocol {
    /// Creates a new protocol.
    ///
    /// Note: This does not validate the protocol name. Use `validate()` for validation.
    pub fn new(security_level: SecurityLevel, protocol_name: impl Into<String>) -> Self {
        Self {
            security_level,
            protocol_name: protocol_name.into(),
        }
    }

    /// Creates a protocol from a tuple (security_level, protocol_name).
    /// This matches the TypeScript SDK's WalletProtocol type.
    pub fn from_tuple(tuple: (u8, &str)) -> Option<Self> {
        let security_level = SecurityLevel::from_u8(tuple.0)?;
        Some(Self {
            security_level,
            protocol_name: tuple.1.to_string(),
        })
    }

    /// Converts the protocol to a tuple representation.
    pub fn to_tuple(&self) -> (u8, &str) {
        (self.security_level.as_u8(), &self.protocol_name)
    }
}

// =============================================================================
// Counterparty
// =============================================================================

/// Identifies the counterparty for key derivation operations.
///
/// Can be:
/// - `Self_`: Derive keys for the wallet owner themselves
/// - `Anyone`: Derive keys that anyone can compute (publicly derivable)
/// - `Other(PublicKey)`: Derive keys for a specific counterparty identified by their public key
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Counterparty {
    /// Special: derive for self.
    Self_,
    /// Special: anyone can derive (publicly derivable keys).
    Anyone,
    /// Specific counterparty identified by their public key.
    Other(PublicKey),
}

impl Counterparty {
    /// Creates a counterparty from a public key hex string.
    pub fn from_hex(hex: &str) -> crate::Result<Self> {
        let pubkey = PublicKey::from_hex(hex)?;
        Ok(Counterparty::Other(pubkey))
    }

    /// Checks if this is the special "self" counterparty.
    pub fn is_self(&self) -> bool {
        matches!(self, Counterparty::Self_)
    }

    /// Checks if this is the special "anyone" counterparty.
    pub fn is_anyone(&self) -> bool {
        matches!(self, Counterparty::Anyone)
    }

    /// Returns the public key if this is a specific counterparty.
    pub fn public_key(&self) -> Option<&PublicKey> {
        match self {
            Counterparty::Other(pk) => Some(pk),
            _ => None,
        }
    }
}

// =============================================================================
// Outpoint
// =============================================================================

/// A transaction outpoint (txid + output index).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Outpoint {
    /// The transaction ID.
    pub txid: TxId,
    /// The output index within the transaction.
    pub vout: u32,
}

impl Outpoint {
    /// Creates a new outpoint.
    pub fn new(txid: TxId, vout: u32) -> Self {
        Self { txid, vout }
    }

    /// Parses an outpoint from the string format "txid.vout".
    pub fn from_string(s: &str) -> crate::Result<Self> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 2 {
            return Err(crate::Error::WalletError(format!(
                "Invalid outpoint format: expected 'txid.vout', got '{}'",
                s
            )));
        }

        let txid_hex = parts[0];
        if txid_hex.len() != 64 {
            return Err(crate::Error::WalletError(format!(
                "Invalid txid length: expected 64 hex chars, got {}",
                txid_hex.len()
            )));
        }

        let txid_bytes = crate::primitives::from_hex(txid_hex)?;
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&txid_bytes);

        let vout: u32 = parts[1]
            .parse()
            .map_err(|_| crate::Error::WalletError(format!("Invalid vout: '{}'", parts[1])))?;

        Ok(Self { txid, vout })
    }
}

impl std::fmt::Display for Outpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", crate::primitives::to_hex(&self.txid), self.vout)
    }
}

// =============================================================================
// Action Status
// =============================================================================

/// Status of a wallet action (transaction).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ActionStatus {
    /// Transaction has been completed and confirmed.
    Completed,
    /// Transaction is waiting to be processed.
    Unprocessed,
    /// Transaction is being sent to the network.
    Sending,
    /// Transaction is sent but not yet proven in a block.
    Unproven,
    /// Transaction requires signatures.
    Unsigned,
    /// Transaction was created with noSend option.
    #[serde(rename = "nosend")]
    NoSend,
    /// Transaction is non-final (has future locktime).
    #[serde(rename = "nonfinal")]
    NonFinal,
    /// Transaction failed.
    Failed,
}

impl ActionStatus {
    /// Returns the status as a string.
    pub fn as_str(&self) -> &'static str {
        match self {
            ActionStatus::Completed => "completed",
            ActionStatus::Unprocessed => "unprocessed",
            ActionStatus::Sending => "sending",
            ActionStatus::Unproven => "unproven",
            ActionStatus::Unsigned => "unsigned",
            ActionStatus::NoSend => "nosend",
            ActionStatus::NonFinal => "nonfinal",
            ActionStatus::Failed => "failed",
        }
    }
}

// =============================================================================
// Create Action Types
// =============================================================================

/// Input specification for creating a transaction action.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateActionInput {
    /// The outpoint being consumed.
    pub outpoint: Outpoint,
    /// A description of this input (5-50 characters).
    pub input_description: String,
    /// Optional unlocking script (hex encoded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unlocking_script: Option<Vec<u8>>,
    /// Optional length of the unlocking script (for deferred signing).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unlocking_script_length: Option<u32>,
    /// Optional sequence number for the input.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence_number: Option<u32>,
}

/// Output specification for creating a transaction action.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateActionOutput {
    /// The locking script (serialized).
    pub locking_script: Vec<u8>,
    /// The satoshi value.
    pub satoshis: SatoshiValue,
    /// A description of this output (5-50 characters).
    pub output_description: String,
    /// Optional basket name for UTXO tracking.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub basket: Option<String>,
    /// Optional custom instructions for the output.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_instructions: Option<String>,
    /// Optional tags for the output.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
}

/// Options for creating a transaction action.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateActionOptions {
    /// If true and all inputs have unlocking scripts, sign and process immediately.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sign_and_process: Option<bool>,
    /// If true, accept delayed broadcast.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accept_delayed_broadcast: Option<bool>,
    /// If "known", input transactions may omit validity proof data for known TXIDs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_self: Option<TrustSelf>,
    /// TXIDs that may be assumed valid.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub known_txids: Option<Vec<TxId>>,
    /// If true, only return TXID instead of full transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_txid_only: Option<bool>,
    /// If true, construct but don't send the transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_send: Option<bool>,
    /// Change outpoints from prior noSend actions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_send_change: Option<Vec<Outpoint>>,
    /// Batch send with these TXIDs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub send_with: Option<Vec<TxId>>,
    /// If false, don't randomize output order.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub randomize_outputs: Option<bool>,
}

/// Trust self option for BEEF validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustSelf {
    /// Trust known TXIDs.
    Known,
}

// =============================================================================
// Action Results
// =============================================================================

/// Status of a send-with result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SendWithResultStatus {
    /// Transaction is unproven.
    Unproven,
    /// Transaction is being sent.
    Sending,
    /// Transaction failed.
    Failed,
}

/// Result for a transaction sent with another action.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendWithResult {
    /// The transaction ID.
    pub txid: TxId,
    /// The status of the send operation.
    pub status: SendWithResultStatus,
}

/// Status of a review action result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ReviewActionResultStatus {
    /// Transaction was successful.
    Success,
    /// Transaction was a double spend.
    DoubleSpend,
    /// Service error occurred.
    ServiceError,
    /// Transaction was invalid.
    InvalidTx,
}

/// Result of reviewing an action.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReviewActionResult {
    /// The transaction ID.
    pub txid: TxId,
    /// The status of the review.
    pub status: ReviewActionResultStatus,
    /// Competing transaction IDs (for double spend).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub competing_txs: Option<Vec<TxId>>,
    /// Merged BEEF of competing transactions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub competing_beef: Option<Vec<u8>>,
}

/// A transaction that needs signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignableTransaction {
    /// The transaction in atomic BEEF format.
    pub tx: Vec<u8>,
    /// Reference for signing.
    pub reference: Vec<u8>,
}

/// Result of creating an action.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateActionResult {
    /// The transaction ID (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub txid: Option<TxId>,
    /// The transaction in atomic BEEF format (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx: Option<Vec<u8>>,
    /// Change outpoints for noSend transactions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_send_change: Option<Vec<Outpoint>>,
    /// Results of transactions sent with this action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub send_with_results: Option<Vec<SendWithResult>>,
    /// Transaction needing signatures (if sign_and_process is false).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signable_transaction: Option<SignableTransaction>,
}

// =============================================================================
// Certificate Types
// =============================================================================

/// Acquisition protocol for certificates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AcquisitionProtocol {
    /// Acquire directly.
    Direct,
    /// Acquire via issuance.
    Issuance,
}

/// A wallet certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Certificate {
    /// Certificate type (base64 encoded).
    pub certificate_type: String,
    /// Subject's public key (hex).
    pub subject: PublicKey,
    /// Serial number (base64 encoded).
    pub serial_number: String,
    /// Certifier's public key (hex).
    pub certifier: PublicKey,
    /// Revocation outpoint (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_outpoint: Option<Outpoint>,
    /// Certificate fields.
    pub fields: HashMap<String, String>,
    /// Signature (hex encoded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<Vec<u8>>,
}

/// Keyring revealer for certificates.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum KeyringRevealer {
    /// The certifier reveals the keyring.
    Certifier,
    /// A specific public key reveals the keyring.
    PublicKey(PublicKey),
}

// =============================================================================
// Wallet Action Types
// =============================================================================

/// A wallet action input.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletActionInput {
    /// The source outpoint.
    pub source_outpoint: Outpoint,
    /// The source satoshi value.
    pub source_satoshis: SatoshiValue,
    /// The source locking script (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_locking_script: Option<Vec<u8>>,
    /// The unlocking script (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unlocking_script: Option<Vec<u8>>,
    /// Description of this input.
    pub input_description: String,
    /// The sequence number.
    pub sequence_number: u32,
}

/// A wallet action output.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletActionOutput {
    /// The satoshi value.
    pub satoshis: SatoshiValue,
    /// The locking script (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locking_script: Option<Vec<u8>>,
    /// Whether this output is spendable by the wallet.
    pub spendable: bool,
    /// Custom instructions (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_instructions: Option<String>,
    /// Tags for the output.
    pub tags: Vec<String>,
    /// The output index.
    pub output_index: u32,
    /// Description of this output.
    pub output_description: String,
    /// The basket this output belongs to.
    pub basket: String,
}

/// A wallet action (transaction).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletAction {
    /// The transaction ID.
    pub txid: TxId,
    /// The total satoshi value.
    pub satoshis: SatoshiValue,
    /// The action status.
    pub status: ActionStatus,
    /// Whether this is an outgoing action.
    pub is_outgoing: bool,
    /// Description of this action.
    pub description: String,
    /// Labels for this action (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<Vec<String>>,
    /// Transaction version.
    pub version: u32,
    /// Transaction locktime.
    pub lock_time: u32,
    /// Inputs (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inputs: Option<Vec<WalletActionInput>>,
    /// Outputs (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outputs: Option<Vec<WalletActionOutput>>,
}

// =============================================================================
// Wallet Output Types
// =============================================================================

/// A spendable wallet output.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletOutput {
    /// The satoshi value.
    pub satoshis: SatoshiValue,
    /// The locking script (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locking_script: Option<Vec<u8>>,
    /// Whether this output is spendable.
    pub spendable: bool,
    /// Custom instructions (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_instructions: Option<String>,
    /// Tags (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    /// The outpoint.
    pub outpoint: Outpoint,
    /// Labels (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<Vec<String>>,
}

// =============================================================================
// Key Linkage Types
// =============================================================================

/// Result of revealing key linkage.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyLinkageResult {
    /// Encrypted linkage data.
    pub encrypted_linkage: Vec<u8>,
    /// Proof of encrypted linkage.
    pub encrypted_linkage_proof: Vec<u8>,
    /// The prover's public key.
    pub prover: PublicKey,
    /// The verifier's public key.
    pub verifier: PublicKey,
    /// The counterparty's public key.
    pub counterparty: PublicKey,
}

/// Result of revealing counterparty key linkage.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevealCounterpartyKeyLinkageResult {
    /// Base key linkage result.
    pub linkage: KeyLinkageResult,
    /// Time of revelation (ISO timestamp).
    pub revelation_time: String,
}

/// Result of revealing specific key linkage.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevealSpecificKeyLinkageResult {
    /// Base key linkage result.
    pub linkage: KeyLinkageResult,
    /// The protocol ID.
    pub protocol: Protocol,
    /// The key ID.
    pub key_id: String,
    /// The proof type.
    pub proof_type: u8,
}

// =============================================================================
// Query Mode
// =============================================================================

/// Query mode for filtering operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum QueryMode {
    /// Match any of the specified items.
    #[default]
    Any,
    /// Match all of the specified items.
    All,
}

impl QueryMode {
    /// Returns the query mode as a string.
    pub fn as_str(&self) -> &'static str {
        match self {
            QueryMode::Any => "any",
            QueryMode::All => "all",
        }
    }
}

impl std::str::FromStr for QueryMode {
    type Err = crate::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "any" => Ok(QueryMode::Any),
            "all" => Ok(QueryMode::All),
            _ => Err(crate::Error::WalletError(format!(
                "Invalid query mode: expected 'any' or 'all', got '{}'",
                s
            ))),
        }
    }
}

// =============================================================================
// Output Include Mode
// =============================================================================

/// Specifies what to include when listing outputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OutputInclude {
    /// Include locking scripts with each output.
    #[serde(rename = "locking scripts")]
    LockingScripts,
    /// Include entire transactions as aggregated BEEF.
    #[serde(rename = "entire transactions")]
    EntireTransactions,
}

impl OutputInclude {
    /// Returns the include mode as a string.
    pub fn as_str(&self) -> &'static str {
        match self {
            OutputInclude::LockingScripts => "locking scripts",
            OutputInclude::EntireTransactions => "entire transactions",
        }
    }
}

impl std::str::FromStr for OutputInclude {
    type Err = crate::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "locking scripts" => Ok(OutputInclude::LockingScripts),
            "entire transactions" => Ok(OutputInclude::EntireTransactions),
            _ => Err(crate::Error::WalletError(format!(
                "Invalid output include mode: expected 'locking scripts' or 'entire transactions', got '{}'",
                s
            ))),
        }
    }
}

// =============================================================================
// Create Action Args
// =============================================================================

/// Arguments for creating a new transaction action.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateActionArgs {
    /// A human-readable description of the action (5-50 characters).
    pub description: String,
    /// Optional BEEF data for input transactions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_beef: Option<Vec<u8>>,
    /// Optional array of inputs for the transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inputs: Option<Vec<CreateActionInput>>,
    /// Optional array of outputs for the transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outputs: Option<Vec<CreateActionOutput>>,
    /// Optional lock time for the transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lock_time: Option<u32>,
    /// Optional transaction version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<u32>,
    /// Optional labels for categorization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<Vec<String>>,
    /// Optional settings modifying transaction behavior.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<CreateActionOptions>,
}

// =============================================================================
// Sign Action Types
// =============================================================================

/// Unlocking script and sequence number for signing an input.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignActionSpend {
    /// The unlocking script for the input.
    pub unlocking_script: Vec<u8>,
    /// Optional sequence number for the input.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence_number: Option<u32>,
}

/// Options for signing a transaction.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignActionOptions {
    /// If true, accept delayed broadcast.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accept_delayed_broadcast: Option<bool>,
    /// If true, only return TXID instead of full transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_txid_only: Option<bool>,
    /// If true, construct but don't send the transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_send: Option<bool>,
    /// Batch send with these TXIDs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub send_with: Option<Vec<TxId>>,
}

/// Arguments for signing a previously created transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignActionArgs {
    /// Map of input indexes to their unlocking scripts.
    pub spends: HashMap<u32, SignActionSpend>,
    /// Reference number from createAction.
    pub reference: String,
    /// Optional settings for signing behavior.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<SignActionOptions>,
}

/// Result of signing a transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignActionResult {
    /// The transaction ID (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub txid: Option<TxId>,
    /// The transaction in atomic BEEF format (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx: Option<Vec<u8>>,
    /// Results of transactions sent with this action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub send_with_results: Option<Vec<SendWithResult>>,
}

// =============================================================================
// Abort Action Types
// =============================================================================

/// Arguments for aborting a transaction in progress.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AbortActionArgs {
    /// Reference number from createAction.
    pub reference: String,
}

/// Result of aborting a transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AbortActionResult {
    /// True if the action was successfully aborted.
    pub aborted: bool,
}

// =============================================================================
// List Actions Types
// =============================================================================

/// Arguments for listing wallet actions (transactions).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListActionsArgs {
    /// Labels to filter actions by.
    pub labels: Vec<String>,
    /// How to match labels (any/all).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label_query_mode: Option<QueryMode>,
    /// Whether to include labels in results.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_labels: Option<bool>,
    /// Whether to include input details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_inputs: Option<bool>,
    /// Whether to include input source locking scripts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_input_source_locking_scripts: Option<bool>,
    /// Whether to include input unlocking scripts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_input_unlocking_scripts: Option<bool>,
    /// Whether to include output details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_outputs: Option<bool>,
    /// Whether to include output locking scripts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_output_locking_scripts: Option<bool>,
    /// Maximum number of actions to return (default 10, max 10000).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// Number of actions to skip.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u32>,
    /// Whether to seek user permission if required.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seek_permission: Option<bool>,
}

/// Result of listing wallet actions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListActionsResult {
    /// Total number of matching actions.
    pub total_actions: u32,
    /// The matching actions.
    pub actions: Vec<WalletAction>,
}

// =============================================================================
// Internalize Action Types
// =============================================================================

/// Payment remittance information for wallet payments.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletPayment {
    /// Payment-level derivation prefix used by the sender.
    pub derivation_prefix: String,
    /// Output-level derivation suffix used by the sender.
    pub derivation_suffix: String,
    /// Public identity key of the sender.
    pub sender_identity_key: String,
}

/// Basket insertion remittance information.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BasketInsertion {
    /// Basket to place the output in.
    pub basket: String,
    /// Optional custom instructions for the output.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_instructions: Option<String>,
    /// Optional tags for the output.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
}

/// Output specification for internalization.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InternalizeOutput {
    /// Index of the output within the transaction.
    pub output_index: u32,
    /// Protocol type: "wallet payment" or "basket insertion".
    pub protocol: String,
    /// Remittance data for wallet payment protocol.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_remittance: Option<WalletPayment>,
    /// Remittance data for basket insertion protocol.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub insertion_remittance: Option<BasketInsertion>,
}

/// Arguments for internalizing a transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InternalizeActionArgs {
    /// Transaction in atomic BEEF format.
    pub tx: Vec<u8>,
    /// Metadata about outputs to internalize.
    pub outputs: Vec<InternalizeOutput>,
    /// Human-readable description of the transaction.
    pub description: String,
    /// Optional labels for the transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<Vec<String>>,
    /// Whether to seek user permission if required.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seek_permission: Option<bool>,
}

/// Result of internalizing a transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InternalizeActionResult {
    /// True if the transaction was accepted.
    pub accepted: bool,
}

// =============================================================================
// List Outputs Types
// =============================================================================

/// Arguments for listing wallet outputs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListOutputsArgs {
    /// Basket to list outputs from.
    pub basket: String,
    /// Optional tags to filter by.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    /// How to match tags (any/all).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag_query_mode: Option<QueryMode>,
    /// What to include in results.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include: Option<OutputInclude>,
    /// Whether to include custom instructions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_custom_instructions: Option<bool>,
    /// Whether to include tags.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_tags: Option<bool>,
    /// Whether to include labels.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_labels: Option<bool>,
    /// Maximum number of outputs to return (default 10, max 10000).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// Number of outputs to skip (negative for newest-first).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<i32>,
    /// Whether to seek user permission if required.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seek_permission: Option<bool>,
}

/// Result of listing wallet outputs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListOutputsResult {
    /// Total number of matching outputs.
    pub total_outputs: u32,
    /// Optional aggregated BEEF data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub beef: Option<Vec<u8>>,
    /// The matching outputs.
    pub outputs: Vec<WalletOutput>,
}

// =============================================================================
// Relinquish Output Types
// =============================================================================

/// Arguments for relinquishing an output from a basket.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelinquishOutputArgs {
    /// The basket containing the output.
    pub basket: String,
    /// The outpoint to relinquish.
    pub output: Outpoint,
}

/// Result of relinquishing an output.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelinquishOutputResult {
    /// True if the output was successfully relinquished.
    pub relinquished: bool,
}

// =============================================================================
// Wallet Certificate Types
// =============================================================================

/// A wallet certificate with all fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletCertificate {
    /// Certificate type (base64 encoded).
    pub certificate_type: String,
    /// Subject's public key (hex).
    pub subject: String,
    /// Serial number (base64 encoded).
    pub serial_number: String,
    /// Certifier's public key (hex).
    pub certifier: String,
    /// Revocation outpoint.
    pub revocation_outpoint: String,
    /// Signature (hex encoded).
    pub signature: String,
    /// Certificate fields.
    pub fields: HashMap<String, String>,
}

/// Arguments for acquiring a certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcquireCertificateArgs {
    /// Certificate type (base64 encoded).
    pub certificate_type: String,
    /// Certifier's public key (hex).
    pub certifier: String,
    /// Acquisition protocol ("direct" or "issuance").
    pub acquisition_protocol: AcquisitionProtocol,
    /// Certificate fields.
    pub fields: HashMap<String, String>,
    /// Serial number (required for direct acquisition).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial_number: Option<String>,
    /// Revocation outpoint (required for direct acquisition).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_outpoint: Option<String>,
    /// Signature (required for direct acquisition).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// Certifier URL (required for issuance acquisition).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certifier_url: Option<String>,
    /// Keyring revealer (required for direct acquisition).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keyring_revealer: Option<KeyringRevealer>,
    /// Keyring for subject (required for direct acquisition).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keyring_for_subject: Option<HashMap<String, String>>,
    /// Whether this is a privileged request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privileged: Option<bool>,
    /// Reason for privileged access.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privileged_reason: Option<String>,
}

/// Arguments for listing certificates.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListCertificatesArgs {
    /// Certifier public keys to filter by.
    pub certifiers: Vec<String>,
    /// Certificate types to filter by.
    pub types: Vec<String>,
    /// Maximum number of certificates to return.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// Number of certificates to skip.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u32>,
    /// Whether this is a privileged request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privileged: Option<bool>,
    /// Reason for privileged access.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privileged_reason: Option<String>,
}

/// Certificate with optional keyring (returned from listCertificates).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateResult {
    /// The certificate.
    pub certificate: WalletCertificate,
    /// Optional keyring for field decryption.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keyring: Option<HashMap<String, String>>,
    /// Optional verifier (for prove operations).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verifier: Option<String>,
}

/// Result of listing certificates.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListCertificatesResult {
    /// Total number of matching certificates.
    pub total_certificates: u32,
    /// The matching certificates.
    pub certificates: Vec<CertificateResult>,
}

/// Arguments for proving a certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProveCertificateArgs {
    /// The certificate to prove.
    pub certificate: WalletCertificate,
    /// Field names to reveal to the verifier.
    pub fields_to_reveal: Vec<String>,
    /// Verifier's public key (hex).
    pub verifier: String,
    /// Whether this is a privileged request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privileged: Option<bool>,
    /// Reason for privileged access.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privileged_reason: Option<String>,
}

/// Result of proving a certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProveCertificateResult {
    /// Keyring for the verifier to decrypt revealed fields.
    pub keyring_for_verifier: HashMap<String, String>,
    /// The certificate (if requested).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<WalletCertificate>,
    /// The verifier's public key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verifier: Option<String>,
}

/// Arguments for relinquishing a certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelinquishCertificateArgs {
    /// Certificate type (base64 encoded).
    pub certificate_type: String,
    /// Serial number (base64 encoded).
    pub serial_number: String,
    /// Certifier's public key (hex).
    pub certifier: String,
}

/// Result of relinquishing a certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelinquishCertificateResult {
    /// True if the certificate was successfully relinquished.
    pub relinquished: bool,
}

// =============================================================================
// Discovery Types
// =============================================================================

/// Information about a certificate certifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityCertifier {
    /// Name of the certifier.
    pub name: String,
    /// URL to the certifier's icon.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon_url: Option<String>,
    /// Description of the certifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Trust level (1-10).
    pub trust: u8,
}

/// An identity certificate with certifier information.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityCertificate {
    /// The base certificate.
    pub certificate: WalletCertificate,
    /// Information about the certifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certifier_info: Option<IdentityCertifier>,
    /// Publicly revealed keyring for field decryption.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publicly_revealed_keyring: Option<HashMap<String, String>>,
    /// Decrypted field values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decrypted_fields: Option<HashMap<String, String>>,
}

/// Arguments for discovering certificates by identity key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoverByIdentityKeyArgs {
    /// Identity key to search for.
    pub identity_key: String,
    /// Maximum number of certificates to return.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// Number of certificates to skip.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u32>,
    /// Whether to seek user permission if required.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seek_permission: Option<bool>,
}

/// Arguments for discovering certificates by attributes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoverByAttributesArgs {
    /// Attributes to search for.
    pub attributes: HashMap<String, String>,
    /// Maximum number of certificates to return.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// Number of certificates to skip.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u32>,
    /// Whether to seek user permission if required.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seek_permission: Option<bool>,
}

/// Result of discovering certificates.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoverCertificatesResult {
    /// Total number of matching certificates.
    pub total_certificates: u32,
    /// The matching certificates.
    pub certificates: Vec<IdentityCertificate>,
}

// =============================================================================
// Authentication Types
// =============================================================================

/// Result of checking authentication status.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatedResult {
    /// True if the user is authenticated.
    pub authenticated: bool,
}

// =============================================================================
// Chain/Header Types
// =============================================================================

/// Result of getting the current blockchain height.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetHeightResult {
    /// The current block height.
    pub height: u32,
}

/// Arguments for getting a block header.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetHeaderArgs {
    /// The block height.
    pub height: u32,
}

/// Result of getting a block header.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetHeaderResult {
    /// The 80-byte block header (hex encoded).
    pub header: String,
}

/// Result of getting the wallet network.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetNetworkResult {
    /// The network ("mainnet" or "testnet").
    pub network: Network,
}

/// Result of getting the wallet version.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetVersionResult {
    /// The wallet version string.
    pub version: String,
}

// =============================================================================
// Validation Helpers
// =============================================================================

/// Validates a satoshi value.
pub fn validate_satoshis(value: u64, name: &str) -> crate::Result<u64> {
    if value > MAX_SATOSHIS {
        return Err(crate::Error::WalletError(format!(
            "Invalid {}: {} exceeds maximum of {} satoshis",
            name, value, MAX_SATOSHIS
        )));
    }
    Ok(value)
}

/// Validates a description string (5-50 characters).
pub fn validate_description(desc: &str, name: &str) -> crate::Result<()> {
    if desc.len() < 5 {
        return Err(crate::Error::WalletError(format!(
            "Invalid {}: must be at least 5 characters, got {}",
            name,
            desc.len()
        )));
    }
    if desc.len() > 50 {
        return Err(crate::Error::WalletError(format!(
            "Invalid {}: must be at most 50 characters, got {}",
            name,
            desc.len()
        )));
    }
    Ok(())
}

/// Validates a key ID (1-800 characters).
pub fn validate_key_id(key_id: &str) -> crate::Result<()> {
    if key_id.is_empty() {
        return Err(crate::Error::ProtocolValidationError(
            "key ID must be at least 1 character".to_string(),
        ));
    }
    if key_id.len() > 800 {
        return Err(crate::Error::ProtocolValidationError(
            "key ID must be 800 characters or less".to_string(),
        ));
    }
    Ok(())
}

/// Validates a protocol name (5-400 characters, special handling for specific linkage revelation).
pub fn validate_protocol_name(name: &str) -> crate::Result<String> {
    let protocol_name = name.trim().to_lowercase();

    // Determine max length based on protocol type
    let max_len = if protocol_name.starts_with("specific linkage revelation ") {
        430
    } else {
        400
    };

    if protocol_name.len() > max_len {
        return Err(crate::Error::ProtocolValidationError(format!(
            "protocol name must be {} characters or less",
            max_len
        )));
    }
    if protocol_name.len() < 5 {
        return Err(crate::Error::ProtocolValidationError(
            "protocol name must be at least 5 characters".to_string(),
        ));
    }
    if protocol_name.contains("  ") {
        return Err(crate::Error::ProtocolValidationError(
            "protocol name cannot contain consecutive spaces".to_string(),
        ));
    }
    if !protocol_name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == ' ')
    {
        return Err(crate::Error::ProtocolValidationError(
            "protocol name can only contain lowercase letters, numbers, and spaces".to_string(),
        ));
    }
    if protocol_name.ends_with(" protocol") {
        return Err(crate::Error::ProtocolValidationError(
            "protocol name should not end with ' protocol'".to_string(),
        ));
    }

    Ok(protocol_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_level_conversion() {
        assert_eq!(SecurityLevel::from_u8(0), Some(SecurityLevel::Silent));
        assert_eq!(SecurityLevel::from_u8(1), Some(SecurityLevel::App));
        assert_eq!(SecurityLevel::from_u8(2), Some(SecurityLevel::Counterparty));
        assert_eq!(SecurityLevel::from_u8(3), None);

        assert_eq!(SecurityLevel::Silent.as_u8(), 0);
        assert_eq!(SecurityLevel::App.as_u8(), 1);
        assert_eq!(SecurityLevel::Counterparty.as_u8(), 2);
    }

    #[test]
    fn test_protocol_from_tuple() {
        let proto = Protocol::from_tuple((1, "test protocol name")).unwrap();
        assert_eq!(proto.security_level, SecurityLevel::App);
        assert_eq!(proto.protocol_name, "test protocol name");

        let tuple = proto.to_tuple();
        assert_eq!(tuple, (1, "test protocol name"));
    }

    #[test]
    fn test_outpoint_parsing() {
        let txid_hex = "0000000000000000000000000000000000000000000000000000000000000001";
        let outpoint_str = format!("{}.5", txid_hex);

        let outpoint = Outpoint::from_string(&outpoint_str).unwrap();
        assert_eq!(outpoint.vout, 5);
        assert_eq!(outpoint.txid[31], 1);

        assert_eq!(outpoint.to_string(), outpoint_str);
    }

    #[test]
    fn test_outpoint_invalid_format() {
        assert!(Outpoint::from_string("invalid").is_err());
        assert!(Outpoint::from_string("txid").is_err());
        assert!(Outpoint::from_string("abc.1").is_err()); // txid too short
    }

    #[test]
    fn test_validate_satoshis() {
        assert!(validate_satoshis(0, "test").is_ok());
        assert!(validate_satoshis(MAX_SATOSHIS, "test").is_ok());
        assert!(validate_satoshis(MAX_SATOSHIS + 1, "test").is_err());
    }

    #[test]
    fn test_validate_description() {
        assert!(validate_description("hello", "test").is_ok());
        assert!(validate_description("a".repeat(50).as_str(), "test").is_ok());
        assert!(validate_description("tiny", "test").is_err()); // Too short
        assert!(validate_description("a".repeat(51).as_str(), "test").is_err());
        // Too long
    }

    #[test]
    fn test_validate_key_id() {
        assert!(validate_key_id("a").is_ok());
        assert!(validate_key_id("a".repeat(800).as_str()).is_ok());
        assert!(validate_key_id("").is_err());
        assert!(validate_key_id("a".repeat(801).as_str()).is_err());
    }

    #[test]
    fn test_validate_protocol_name() {
        assert!(validate_protocol_name("hello").is_ok());
        assert!(validate_protocol_name("test protocol 123").is_ok());
        assert!(validate_protocol_name("TEST SYSTEM").is_ok()); // Gets lowercased

        assert!(validate_protocol_name("tiny").is_err()); // Too short
        assert!(validate_protocol_name("hello  world").is_err()); // Double space
        assert!(validate_protocol_name("hello-world").is_err()); // Invalid char
        assert!(validate_protocol_name("test protocol").is_err()); // Ends with " protocol"
    }

    #[test]
    fn test_counterparty_variants() {
        let cp_self = Counterparty::Self_;
        assert!(cp_self.is_self());
        assert!(!cp_self.is_anyone());
        assert!(cp_self.public_key().is_none());

        let cp_anyone = Counterparty::Anyone;
        assert!(!cp_anyone.is_self());
        assert!(cp_anyone.is_anyone());
        assert!(cp_anyone.public_key().is_none());
    }
}
