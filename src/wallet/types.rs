//! Core wallet type definitions.
//!
//! This module provides the foundational types used throughout the wallet module,
//! including security levels, protocols, counterparty identifiers, transaction-related
//! types, and certificate structures. These types are designed to be API-compatible
//! with the TypeScript and Go BSV SDKs.

use crate::primitives::PublicKey;
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum SecurityLevel {
    /// Level 0: Silently grants the request with no user interaction.
    #[default]
    Silent = 0,
    /// Level 1: Requires user approval for every application.
    App = 1,
    /// Level 2: Requires user approval per counterparty per application.
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
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
    NoSend,
    /// Transaction is non-final (has future locktime).
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
#[derive(Debug, Clone)]
pub struct CreateActionInput {
    /// The outpoint being consumed.
    pub outpoint: Outpoint,
    /// A description of this input (5-50 characters).
    pub input_description: String,
    /// Optional unlocking script (hex encoded).
    pub unlocking_script: Option<Vec<u8>>,
    /// Optional length of the unlocking script (for deferred signing).
    pub unlocking_script_length: Option<u32>,
    /// Optional sequence number for the input.
    pub sequence_number: Option<u32>,
}

/// Output specification for creating a transaction action.
#[derive(Debug, Clone)]
pub struct CreateActionOutput {
    /// The locking script (serialized).
    pub locking_script: Vec<u8>,
    /// The satoshi value.
    pub satoshis: SatoshiValue,
    /// A description of this output (5-50 characters).
    pub output_description: String,
    /// Optional basket name for UTXO tracking.
    pub basket: Option<String>,
    /// Optional custom instructions for the output.
    pub custom_instructions: Option<String>,
    /// Optional tags for the output.
    pub tags: Option<Vec<String>>,
}

/// Options for creating a transaction action.
#[derive(Debug, Clone, Default)]
pub struct CreateActionOptions {
    /// If true and all inputs have unlocking scripts, sign and process immediately.
    pub sign_and_process: Option<bool>,
    /// If true, accept delayed broadcast.
    pub accept_delayed_broadcast: Option<bool>,
    /// If "known", input transactions may omit validity proof data for known TXIDs.
    pub trust_self: Option<TrustSelf>,
    /// TXIDs that may be assumed valid.
    pub known_txids: Option<Vec<TxId>>,
    /// If true, only return TXID instead of full transaction.
    pub return_txid_only: Option<bool>,
    /// If true, construct but don't send the transaction.
    pub no_send: Option<bool>,
    /// Change outpoints from prior noSend actions.
    pub no_send_change: Option<Vec<Outpoint>>,
    /// Batch send with these TXIDs.
    pub send_with: Option<Vec<TxId>>,
    /// If false, don't randomize output order.
    pub randomize_outputs: Option<bool>,
}

/// Trust self option for BEEF validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustSelf {
    /// Trust known TXIDs.
    Known,
}

// =============================================================================
// Action Results
// =============================================================================

/// Status of a send-with result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendWithResultStatus {
    /// Transaction is unproven.
    Unproven,
    /// Transaction is being sent.
    Sending,
    /// Transaction failed.
    Failed,
}

/// Result for a transaction sent with another action.
#[derive(Debug, Clone)]
pub struct SendWithResult {
    /// The transaction ID.
    pub txid: TxId,
    /// The status of the send operation.
    pub status: SendWithResultStatus,
}

/// Status of a review action result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
#[derive(Debug, Clone)]
pub struct ReviewActionResult {
    /// The transaction ID.
    pub txid: TxId,
    /// The status of the review.
    pub status: ReviewActionResultStatus,
    /// Competing transaction IDs (for double spend).
    pub competing_txs: Option<Vec<TxId>>,
    /// Merged BEEF of competing transactions.
    pub competing_beef: Option<Vec<u8>>,
}

/// A transaction that needs signing.
#[derive(Debug, Clone)]
pub struct SignableTransaction {
    /// The transaction in atomic BEEF format.
    pub tx: Vec<u8>,
    /// Reference for signing.
    pub reference: Vec<u8>,
}

/// Result of creating an action.
#[derive(Debug, Clone)]
pub struct CreateActionResult {
    /// The transaction ID (if available).
    pub txid: Option<TxId>,
    /// The transaction in atomic BEEF format (if available).
    pub tx: Option<Vec<u8>>,
    /// Change outpoints for noSend transactions.
    pub no_send_change: Option<Vec<Outpoint>>,
    /// Results of transactions sent with this action.
    pub send_with_results: Option<Vec<SendWithResult>>,
    /// Transaction needing signatures (if sign_and_process is false).
    pub signable_transaction: Option<SignableTransaction>,
}

// =============================================================================
// Certificate Types
// =============================================================================

/// Acquisition protocol for certificates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcquisitionProtocol {
    /// Acquire directly.
    Direct,
    /// Acquire via issuance.
    Issuance,
}

/// A wallet certificate.
#[derive(Debug, Clone)]
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
    pub revocation_outpoint: Option<Outpoint>,
    /// Certificate fields.
    pub fields: HashMap<String, String>,
    /// Signature (hex encoded).
    pub signature: Option<Vec<u8>>,
}

/// Keyring revealer for certificates.
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
pub struct WalletActionInput {
    /// The source outpoint.
    pub source_outpoint: Outpoint,
    /// The source satoshi value.
    pub source_satoshis: SatoshiValue,
    /// The source locking script (optional).
    pub source_locking_script: Option<Vec<u8>>,
    /// The unlocking script (optional).
    pub unlocking_script: Option<Vec<u8>>,
    /// Description of this input.
    pub input_description: String,
    /// The sequence number.
    pub sequence_number: u32,
}

/// A wallet action output.
#[derive(Debug, Clone)]
pub struct WalletActionOutput {
    /// The satoshi value.
    pub satoshis: SatoshiValue,
    /// The locking script (optional).
    pub locking_script: Option<Vec<u8>>,
    /// Whether this output is spendable by the wallet.
    pub spendable: bool,
    /// Custom instructions (optional).
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
#[derive(Debug, Clone)]
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
    pub labels: Option<Vec<String>>,
    /// Transaction version.
    pub version: u32,
    /// Transaction locktime.
    pub lock_time: u32,
    /// Inputs (optional).
    pub inputs: Option<Vec<WalletActionInput>>,
    /// Outputs (optional).
    pub outputs: Option<Vec<WalletActionOutput>>,
}

// =============================================================================
// Wallet Output Types
// =============================================================================

/// A spendable wallet output.
#[derive(Debug, Clone)]
pub struct WalletOutput {
    /// The satoshi value.
    pub satoshis: SatoshiValue,
    /// The locking script (optional).
    pub locking_script: Option<Vec<u8>>,
    /// Whether this output is spendable.
    pub spendable: bool,
    /// Custom instructions (optional).
    pub custom_instructions: Option<String>,
    /// Tags (optional).
    pub tags: Option<Vec<String>>,
    /// The outpoint.
    pub outpoint: Outpoint,
    /// Labels (optional).
    pub labels: Option<Vec<String>>,
}

// =============================================================================
// Key Linkage Types
// =============================================================================

/// Result of revealing key linkage.
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
pub struct RevealCounterpartyKeyLinkageResult {
    /// Base key linkage result.
    pub linkage: KeyLinkageResult,
    /// Time of revelation (ISO timestamp).
    pub revelation_time: String,
}

/// Result of revealing specific key linkage.
#[derive(Debug, Clone)]
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
