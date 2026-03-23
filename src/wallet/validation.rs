//! Validation Helpers for Wallet Operations.
//!
//! This module provides comprehensive validation functions for wallet API inputs.
//! All validation functions follow a consistent pattern of returning
//! descriptive errors that include the parameter name and requirement.
//!
//! # Overview
//!
//! The validation functions ensure:
//! - Satoshi values are within valid bounds
//! - Strings meet length requirements (in bytes)
//! - Hex and Base64 strings are properly formatted
//! - Outpoints follow the "txid.vout" format
//! - Identifiers (baskets, labels, tags) are normalized
//!
//! # Example
//!
//! ```rust
//! use bsv_rs::wallet::validation::{validate_satoshis, validate_hex_string, validate_basket};
//!
//! // Validate satoshi amount
//! let sats = validate_satoshis(50000, "outputValue", Some(546)).unwrap();
//!
//! // Validate hex string
//! let hex = validate_hex_string("deadbeef", "txid", Some(8), Some(64)).unwrap();
//!
//! // Validate basket identifier
//! let basket = validate_basket("my-basket").unwrap();
//! ```

use crate::error::{Error, Result};
use crate::wallet::types::{Outpoint, Protocol, SecurityLevel, TxId, MAX_SATOSHIS};

// =============================================================================
// Basic Validation Functions
// =============================================================================

/// Validates a satoshi amount.
///
/// # Arguments
///
/// * `value` - The satoshi value to validate
/// * `name` - The parameter name for error messages
/// * `min` - Optional minimum value
///
/// # Returns
///
/// The validated value, or an error if invalid.
pub fn validate_satoshis(value: u64, name: &str, min: Option<u64>) -> Result<u64> {
    if value > MAX_SATOSHIS {
        return Err(Error::WalletError(format!(
            "Invalid {}: {} exceeds maximum of {} satoshis",
            name, value, MAX_SATOSHIS
        )));
    }
    if let Some(min_val) = min {
        if value < min_val {
            return Err(Error::WalletError(format!(
                "Invalid {}: must be at least {} satoshis",
                name, min_val
            )));
        }
    }
    Ok(value)
}

/// Validates an optional integer, returning a default if not provided.
///
/// # Arguments
///
/// * `value` - The optional value to validate
/// * `name` - The parameter name for error messages
/// * `default` - Default value if None
/// * `min` - Optional minimum value
/// * `max` - Optional maximum value
pub fn validate_integer(
    value: Option<i64>,
    name: &str,
    default: Option<i64>,
    min: Option<i64>,
    max: Option<i64>,
) -> Result<i64> {
    let value = match value {
        Some(v) => v,
        None => default.ok_or_else(|| {
            Error::WalletError(format!("Invalid {}: a valid integer is required", name))
        })?,
    };

    if let Some(min_val) = min {
        if value < min_val {
            return Err(Error::WalletError(format!(
                "Invalid {}: must be at least {}",
                name, min_val
            )));
        }
    }
    if let Some(max_val) = max {
        if value > max_val {
            return Err(Error::WalletError(format!(
                "Invalid {}: must be no more than {}",
                name, max_val
            )));
        }
    }
    Ok(value)
}

/// Validates an optional integer (u32 version).
pub fn validate_integer_u32(
    value: Option<u32>,
    name: &str,
    default: Option<u32>,
    min: Option<u32>,
    max: Option<u32>,
) -> Result<u32> {
    let value = match value {
        Some(v) => v,
        None => default.ok_or_else(|| {
            Error::WalletError(format!("Invalid {}: a valid integer is required", name))
        })?,
    };

    if let Some(min_val) = min {
        if value < min_val {
            return Err(Error::WalletError(format!(
                "Invalid {}: must be at least {}",
                name, min_val
            )));
        }
    }
    if let Some(max_val) = max {
        if value > max_val {
            return Err(Error::WalletError(format!(
                "Invalid {}: must be no more than {}",
                name, max_val
            )));
        }
    }
    Ok(value)
}

/// Validates a non-negative integer (zero allowed).
pub fn validate_positive_integer_or_zero(value: u64, _name: &str) -> Result<u64> {
    // u64 is always >= 0, so this is a no-op but matches the TS API
    Ok(value)
}

/// Validates a string length in bytes.
///
/// # Arguments
///
/// * `s` - The string to validate
/// * `name` - The parameter name for error messages
/// * `min` - Optional minimum byte length
/// * `max` - Optional maximum byte length
pub fn validate_string_length<'a>(
    s: &'a str,
    name: &str,
    min: Option<usize>,
    max: Option<usize>,
) -> Result<&'a str> {
    // Note: str.len() returns byte length in Rust, which matches the TS SDK behavior
    let bytes = s.len();
    if let Some(min_len) = min {
        if bytes < min_len {
            return Err(Error::WalletError(format!(
                "Invalid {}: must be at least {} bytes, got {}",
                name, min_len, bytes
            )));
        }
    }
    if let Some(max_len) = max {
        if bytes > max_len {
            return Err(Error::WalletError(format!(
                "Invalid {}: must be no more than {} bytes, got {}",
                name, max_len, bytes
            )));
        }
    }
    Ok(s)
}

/// Validates an optional string length.
pub fn validate_optional_string_length(
    s: Option<&str>,
    name: &str,
    min: Option<usize>,
    max: Option<usize>,
) -> Result<Option<String>> {
    match s {
        Some(s) => Ok(Some(validate_string_length(s, name, min, max)?.to_string())),
        None => Ok(None),
    }
}

// =============================================================================
// Hex and Base64 Validation
// =============================================================================

/// Validates a hex string.
///
/// Returns the normalized (trimmed, lowercase) hex string.
///
/// # Arguments
///
/// * `s` - The hex string to validate
/// * `name` - The parameter name for error messages
/// * `min_chars` - Optional minimum character length
/// * `max_chars` - Optional maximum character length
#[allow(unknown_lints, clippy::manual_is_multiple_of)]
pub fn validate_hex_string(
    s: &str,
    name: &str,
    min_chars: Option<usize>,
    max_chars: Option<usize>,
) -> Result<String> {
    let s = s.trim().to_lowercase();

    if s.len() % 2 != 0 {
        return Err(Error::WalletError(format!(
            "Invalid {}: hex string must have even length, got {}",
            name,
            s.len()
        )));
    }

    if !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::WalletError(format!(
            "Invalid {}: must be a valid hexadecimal string",
            name
        )));
    }

    if let Some(min_len) = min_chars {
        if s.len() < min_len {
            return Err(Error::WalletError(format!(
                "Invalid {}: must be at least {} characters, got {}",
                name,
                min_len,
                s.len()
            )));
        }
    }
    if let Some(max_len) = max_chars {
        if s.len() > max_len {
            return Err(Error::WalletError(format!(
                "Invalid {}: must be no more than {} characters, got {}",
                name,
                max_len,
                s.len()
            )));
        }
    }

    Ok(s)
}

/// Validates an optional hex string.
pub fn validate_optional_hex_string(
    s: Option<&str>,
    name: &str,
    min_chars: Option<usize>,
    max_chars: Option<usize>,
) -> Result<Option<String>> {
    match s {
        Some(s) => Ok(Some(validate_hex_string(s, name, min_chars, max_chars)?)),
        None => Ok(None),
    }
}

/// Checks if a string is a valid hex string.
#[allow(unknown_lints, clippy::manual_is_multiple_of)]
pub fn is_hex_string(s: &str) -> bool {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return false;
    }
    s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Validates a Base64 string.
///
/// # Arguments
///
/// * `s` - The Base64 string to validate
/// * `name` - The parameter name for error messages
/// * `min_decoded_bytes` - Optional minimum decoded byte length
/// * `max_decoded_bytes` - Optional maximum decoded byte length
pub fn validate_base64_string(
    s: &str,
    name: &str,
    min_decoded_bytes: Option<usize>,
    max_decoded_bytes: Option<usize>,
) -> Result<String> {
    let s = s.trim();

    if s.is_empty() {
        return Err(Error::WalletError(format!(
            "Invalid {}: must be a valid base64 string",
            name
        )));
    }

    // Validate base64 characters
    let mut padding_count = 0;
    for (i, c) in s.chars().enumerate() {
        match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '+' | '/' => continue,
            '=' => {
                if i < s.len() - 2 {
                    return Err(Error::WalletError(format!(
                        "Invalid {}: padding must be at the end",
                        name
                    )));
                }
                padding_count += 1;
            }
            _ => {
                return Err(Error::WalletError(format!(
                    "Invalid {}: must be a valid base64 string",
                    name
                )));
            }
        }
    }

    if padding_count > 2 {
        return Err(Error::WalletError(format!(
            "Invalid {}: too much padding",
            name
        )));
    }

    // Calculate decoded length
    let encoded_len = s.len() - padding_count;
    let decoded_bytes = (encoded_len * 3) / 4;

    if let Some(min_len) = min_decoded_bytes {
        if decoded_bytes < min_len {
            return Err(Error::WalletError(format!(
                "Invalid {}: decoded content must be at least {} bytes",
                name, min_len
            )));
        }
    }
    if let Some(max_len) = max_decoded_bytes {
        if decoded_bytes > max_len {
            return Err(Error::WalletError(format!(
                "Invalid {}: decoded content must be no more than {} bytes",
                name, max_len
            )));
        }
    }

    Ok(s.to_string())
}

/// Validates an optional Base64 string.
pub fn validate_optional_base64_string(
    s: Option<&str>,
    name: &str,
    min_decoded_bytes: Option<usize>,
    max_decoded_bytes: Option<usize>,
) -> Result<Option<String>> {
    match s {
        Some(s) => Ok(Some(validate_base64_string(
            s,
            name,
            min_decoded_bytes,
            max_decoded_bytes,
        )?)),
        None => Ok(None),
    }
}

// =============================================================================
// Outpoint Validation
// =============================================================================

/// Parses a wallet outpoint string "txid.vout" into an Outpoint.
///
/// # Arguments
///
/// * `outpoint` - The outpoint string in format "txid.vout"
///
/// # Returns
///
/// A parsed Outpoint struct.
pub fn parse_wallet_outpoint(outpoint: &str) -> Result<Outpoint> {
    let parts: Vec<&str> = outpoint.split('.').collect();
    if parts.len() != 2 {
        return Err(Error::WalletError(format!(
            "Invalid outpoint: expected format 'txid.vout', got '{}'",
            outpoint
        )));
    }

    let txid = validate_hex_string(parts[0], "outpoint txid", Some(64), Some(64))?;
    let vout: u32 = parts[1].parse().map_err(|_| {
        Error::WalletError(format!(
            "Invalid outpoint vout: '{}' is not a valid integer",
            parts[1]
        ))
    })?;

    let txid_bytes = crate::primitives::from_hex(&txid)
        .map_err(|_| Error::WalletError("Invalid txid hex".to_string()))?;

    let mut txid_array: TxId = [0u8; 32];
    txid_array.copy_from_slice(&txid_bytes);

    Ok(Outpoint::new(txid_array, vout))
}

/// Validates an outpoint string.
///
/// Returns the normalized outpoint string.
pub fn validate_outpoint_string(outpoint: &str, _name: &str) -> Result<String> {
    let parsed = parse_wallet_outpoint(outpoint)?;
    Ok(parsed.to_string())
}

/// Validates an optional outpoint string.
pub fn validate_optional_outpoint_string(
    outpoint: Option<&str>,
    name: &str,
) -> Result<Option<String>> {
    match outpoint {
        Some(o) => Ok(Some(validate_outpoint_string(o, name)?)),
        None => Ok(None),
    }
}

// =============================================================================
// Identifier Validation (Basket, Label, Tag)
// =============================================================================

/// Validates an identifier (trim, lowercase, byte length).
fn validate_identifier(
    s: &str,
    name: &str,
    min: Option<usize>,
    max: Option<usize>,
) -> Result<String> {
    let s = s.trim().to_lowercase();
    // Note: str.len() returns byte length in Rust
    let bytes = s.len();

    if let Some(min_len) = min {
        if bytes < min_len {
            return Err(Error::WalletError(format!(
                "Invalid {}: must be at least {} bytes",
                name, min_len
            )));
        }
    }
    if let Some(max_len) = max {
        if bytes > max_len {
            return Err(Error::WalletError(format!(
                "Invalid {}: must be no more than {} bytes",
                name, max_len
            )));
        }
    }

    Ok(s)
}

/// Validates a basket identifier (1-300 bytes, lowercase, trimmed).
pub fn validate_basket(s: &str) -> Result<String> {
    validate_identifier(s, "basket", Some(1), Some(300))
}

/// Validates an optional basket identifier.
pub fn validate_optional_basket(s: Option<&str>) -> Result<Option<String>> {
    match s {
        Some(s) => Ok(Some(validate_basket(s)?)),
        None => Ok(None),
    }
}

/// Validates a label identifier (1-300 bytes, lowercase, trimmed).
pub fn validate_label(s: &str) -> Result<String> {
    validate_identifier(s, "label", Some(1), Some(300))
}

/// Validates a tag identifier (1-300 bytes, lowercase, trimmed).
pub fn validate_tag(s: &str) -> Result<String> {
    validate_identifier(s, "tag", Some(1), Some(300))
}

/// Validates an originator string.
///
/// The originator must be 1-250 bytes total, with each dot-separated part
/// being 1-63 bytes.
pub fn validate_originator(s: Option<&str>) -> Result<Option<String>> {
    let s = match s {
        Some(s) => s,
        None => return Ok(None),
    };

    let s = s.trim().to_lowercase();
    validate_string_length(&s, "originator", Some(1), Some(250))?;

    for part in s.split('.') {
        validate_string_length(part, "originator part", Some(1), Some(63))?;
    }

    Ok(Some(s))
}

// =============================================================================
// Description Validation
// =============================================================================

/// Validates a description string (5-2000 bytes).
pub fn validate_description_5_2000(desc: &str, name: &str) -> Result<String> {
    validate_string_length(desc, name, Some(5), Some(2000))?;
    Ok(desc.to_string())
}

/// Validates a description string (5-50 bytes).
pub fn validate_description_5_50(desc: &str, name: &str) -> Result<String> {
    validate_string_length(desc, name, Some(5), Some(50))?;
    Ok(desc.to_string())
}

// =============================================================================
// Action Input/Output Validation
// =============================================================================

/// Validated create action input.
#[derive(Debug, Clone)]
pub struct ValidCreateActionInput {
    /// The outpoint being consumed.
    pub outpoint: Outpoint,
    /// Description of this input.
    pub input_description: String,
    /// Sequence number for the input.
    pub sequence_number: u32,
    /// Optional unlocking script (bytes).
    pub unlocking_script: Option<Vec<u8>>,
    /// Length of the unlocking script.
    pub unlocking_script_length: u32,
}

/// Validated create action output.
#[derive(Debug, Clone)]
pub struct ValidCreateActionOutput {
    /// The locking script (bytes).
    pub locking_script: Vec<u8>,
    /// The satoshi value.
    pub satoshis: u64,
    /// Description of this output.
    pub output_description: String,
    /// Optional basket name.
    pub basket: Option<String>,
    /// Optional custom instructions.
    pub custom_instructions: Option<String>,
    /// Tags for this output.
    pub tags: Vec<String>,
}

/// Validated create action options.
#[derive(Debug, Clone)]
pub struct ValidCreateActionOptions {
    /// Whether to sign and process immediately.
    pub sign_and_process: bool,
    /// Whether to accept delayed broadcast.
    pub accept_delayed_broadcast: bool,
    /// Known transaction IDs.
    pub known_txids: Vec<TxId>,
    /// Whether to return only the txid.
    pub return_txid_only: bool,
    /// Whether to skip sending the transaction.
    pub no_send: bool,
    /// Change outpoints from prior noSend actions.
    pub no_send_change: Vec<Outpoint>,
    /// TXIDs to send with this transaction.
    pub send_with: Vec<TxId>,
    /// Whether to randomize output order.
    pub randomize_outputs: bool,
}

impl Default for ValidCreateActionOptions {
    fn default() -> Self {
        Self {
            sign_and_process: true,
            accept_delayed_broadcast: true,
            known_txids: Vec::new(),
            return_txid_only: false,
            no_send: false,
            no_send_change: Vec::new(),
            send_with: Vec::new(),
            randomize_outputs: true,
        }
    }
}

/// Validated create action arguments.
#[derive(Debug, Clone)]
pub struct ValidCreateActionArgs {
    /// Description of this action.
    pub description: String,
    /// Optional input BEEF data.
    pub input_beef: Option<Vec<u8>>,
    /// Validated inputs.
    pub inputs: Vec<ValidCreateActionInput>,
    /// Validated outputs.
    pub outputs: Vec<ValidCreateActionOutput>,
    /// Transaction lock time.
    pub lock_time: u32,
    /// Transaction version.
    pub version: u32,
    /// Labels for this action.
    pub labels: Vec<String>,
    /// Validated options.
    pub options: ValidCreateActionOptions,
    /// True if this is a sendWith batch.
    pub is_send_with: bool,
    /// True if delayed broadcast is accepted.
    pub is_delayed: bool,
    /// True if noSend is enabled.
    pub is_no_send: bool,
    /// True if there is a new transaction.
    pub is_new_tx: bool,
    /// True if this is a remix change request.
    pub is_remix_change: bool,
    /// True if signing is required.
    pub is_sign_action: bool,
}

/// Raw create action input for validation.
#[derive(Debug, Clone)]
pub struct CreateActionInputRaw {
    /// The outpoint string "txid.vout".
    pub outpoint: String,
    /// Description of this input.
    pub input_description: String,
    /// Optional unlocking script (hex).
    pub unlocking_script: Option<String>,
    /// Optional unlocking script length.
    pub unlocking_script_length: Option<u32>,
    /// Optional sequence number.
    pub sequence_number: Option<u32>,
}

/// Raw create action output for validation.
#[derive(Debug, Clone)]
pub struct CreateActionOutputRaw {
    /// The locking script (hex).
    pub locking_script: String,
    /// The satoshi value.
    pub satoshis: u64,
    /// Description of this output.
    pub output_description: String,
    /// Optional basket name.
    pub basket: Option<String>,
    /// Optional custom instructions.
    pub custom_instructions: Option<String>,
    /// Tags for this output.
    pub tags: Vec<String>,
}

/// Raw create action options for validation.
#[derive(Debug, Clone, Default)]
pub struct CreateActionOptionsRaw {
    /// Whether to sign and process immediately.
    pub sign_and_process: Option<bool>,
    /// Whether to accept delayed broadcast.
    pub accept_delayed_broadcast: Option<bool>,
    /// Known transaction IDs (hex).
    pub known_txids: Vec<String>,
    /// Whether to return only the txid.
    pub return_txid_only: Option<bool>,
    /// Whether to skip sending the transaction.
    pub no_send: Option<bool>,
    /// Change outpoints from prior noSend actions.
    pub no_send_change: Vec<String>,
    /// TXIDs to send with this transaction (hex).
    pub send_with: Vec<String>,
    /// Whether to randomize output order.
    pub randomize_outputs: Option<bool>,
}

/// Raw create action arguments for validation.
#[derive(Debug, Clone)]
pub struct CreateActionArgsRaw {
    /// Description of this action.
    pub description: String,
    /// Optional input BEEF data.
    pub input_beef: Option<Vec<u8>>,
    /// Raw inputs.
    pub inputs: Vec<CreateActionInputRaw>,
    /// Raw outputs.
    pub outputs: Vec<CreateActionOutputRaw>,
    /// Optional lock time.
    pub lock_time: Option<u32>,
    /// Optional version.
    pub version: Option<u32>,
    /// Labels for this action.
    pub labels: Vec<String>,
    /// Raw options.
    pub options: Option<CreateActionOptionsRaw>,
}

/// Validates a create action input.
pub fn validate_create_action_input(
    input: &CreateActionInputRaw,
) -> Result<ValidCreateActionInput> {
    if input.unlocking_script.is_none() && input.unlocking_script_length.is_none() {
        return Err(Error::WalletError(
            "unlockingScript or unlockingScriptLength must be provided".to_string(),
        ));
    }

    let unlocking_script = input
        .unlocking_script
        .as_ref()
        .map(|s| validate_hex_string(s, "unlockingScript", None, None))
        .transpose()?
        .map(|s| crate::primitives::from_hex(&s).unwrap());

    let unlocking_script_length = input
        .unlocking_script_length
        .or_else(|| unlocking_script.as_ref().map(|s| s.len() as u32))
        .unwrap_or(0);

    if let Some(ref script) = unlocking_script {
        if unlocking_script_length != script.len() as u32 {
            return Err(Error::WalletError(
                "unlockingScriptLength must match unlockingScript length if both provided"
                    .to_string(),
            ));
        }
    }

    Ok(ValidCreateActionInput {
        outpoint: parse_wallet_outpoint(&input.outpoint)?,
        input_description: validate_description_5_2000(
            &input.input_description,
            "inputDescription",
        )?,
        sequence_number: input.sequence_number.unwrap_or(0xffffffff),
        unlocking_script,
        unlocking_script_length,
    })
}

/// Validates a create action output.
pub fn validate_create_action_output(
    output: &CreateActionOutputRaw,
) -> Result<ValidCreateActionOutput> {
    let locking_script = validate_hex_string(&output.locking_script, "lockingScript", None, None)?;
    let locking_script_bytes = crate::primitives::from_hex(&locking_script)
        .map_err(|_| Error::WalletError("Invalid lockingScript hex".to_string()))?;

    Ok(ValidCreateActionOutput {
        locking_script: locking_script_bytes,
        satoshis: validate_satoshis(output.satoshis, "satoshis", None)?,
        output_description: validate_description_5_2000(
            &output.output_description,
            "outputDescription",
        )?,
        basket: validate_optional_basket(output.basket.as_deref())?,
        custom_instructions: output.custom_instructions.clone(),
        tags: output
            .tags
            .iter()
            .map(|t| validate_tag(t))
            .collect::<Result<_>>()?,
    })
}

/// Validates create action options.
pub fn validate_create_action_options(
    options: Option<&CreateActionOptionsRaw>,
) -> Result<ValidCreateActionOptions> {
    let options = match options {
        Some(o) => o,
        None => return Ok(ValidCreateActionOptions::default()),
    };

    Ok(ValidCreateActionOptions {
        sign_and_process: options.sign_and_process.unwrap_or(true),
        accept_delayed_broadcast: options.accept_delayed_broadcast.unwrap_or(true),
        known_txids: options
            .known_txids
            .iter()
            .map(|t| {
                let hex = validate_hex_string(t, "knownTxid", Some(64), Some(64))?;
                let bytes = crate::primitives::from_hex(&hex)
                    .map_err(|_| Error::WalletError("Invalid knownTxid hex".to_string()))?;
                let mut arr: TxId = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Ok(arr)
            })
            .collect::<Result<_>>()?,
        return_txid_only: options.return_txid_only.unwrap_or(false),
        no_send: options.no_send.unwrap_or(false),
        no_send_change: options
            .no_send_change
            .iter()
            .map(|o| parse_wallet_outpoint(o))
            .collect::<Result<_>>()?,
        send_with: options
            .send_with
            .iter()
            .map(|t| {
                let hex = validate_hex_string(t, "sendWith", Some(64), Some(64))?;
                let bytes = crate::primitives::from_hex(&hex)
                    .map_err(|_| Error::WalletError("Invalid sendWith hex".to_string()))?;
                let mut arr: TxId = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Ok(arr)
            })
            .collect::<Result<_>>()?,
        randomize_outputs: options.randomize_outputs.unwrap_or(true),
    })
}

/// Validates create action arguments.
pub fn validate_create_action_args(args: &CreateActionArgsRaw) -> Result<ValidCreateActionArgs> {
    let description = validate_description_5_2000(&args.description, "description")?;

    let inputs: Vec<ValidCreateActionInput> = args
        .inputs
        .iter()
        .map(validate_create_action_input)
        .collect::<Result<_>>()?;

    let outputs: Vec<ValidCreateActionOutput> = args
        .outputs
        .iter()
        .map(validate_create_action_output)
        .collect::<Result<_>>()?;

    let labels: Vec<String> = args
        .labels
        .iter()
        .map(|l| validate_label(l))
        .collect::<Result<_>>()?;

    let options = validate_create_action_options(args.options.as_ref())?;

    let is_send_with = !options.send_with.is_empty();
    let is_remix_change = !is_send_with && inputs.is_empty() && outputs.is_empty();
    let is_new_tx = is_remix_change || !inputs.is_empty() || !outputs.is_empty();
    let is_sign_action = is_new_tx
        && (!options.sign_and_process || inputs.iter().any(|i| i.unlocking_script.is_none()));

    Ok(ValidCreateActionArgs {
        description,
        input_beef: args.input_beef.clone(),
        inputs,
        outputs,
        lock_time: args.lock_time.unwrap_or(0),
        version: args.version.unwrap_or(1),
        labels,
        options,
        is_send_with,
        is_delayed: true,
        is_no_send: false,
        is_new_tx,
        is_remix_change,
        is_sign_action,
    })
}

// =============================================================================
// Sign Action Validation
// =============================================================================

/// Raw sign action spend for validation.
#[derive(Debug, Clone)]
pub struct SignActionSpendRaw {
    /// The unlocking script (hex).
    pub unlocking_script: String,
    /// Optional sequence number.
    pub sequence_number: Option<u32>,
}

/// Validated sign action spend.
#[derive(Debug, Clone)]
pub struct ValidSignActionSpend {
    /// The unlocking script (bytes).
    pub unlocking_script: Vec<u8>,
    /// The sequence number.
    pub sequence_number: u32,
}

/// Validates a sign action spend.
pub fn validate_sign_action_spend(spend: &SignActionSpendRaw) -> Result<ValidSignActionSpend> {
    let hex = validate_hex_string(&spend.unlocking_script, "unlockingScript", None, None)?;
    let bytes = crate::primitives::from_hex(&hex)
        .map_err(|_| Error::WalletError("Invalid unlockingScript hex".to_string()))?;

    Ok(ValidSignActionSpend {
        unlocking_script: bytes,
        sequence_number: spend.sequence_number.unwrap_or(0xffffffff),
    })
}

// =============================================================================
// List Actions/Outputs Validation
// =============================================================================

/// Query mode for tag or label queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryMode {
    /// Match any of the specified items.
    Any,
    /// Match all of the specified items.
    All,
}

/// Validates a query mode string.
pub fn validate_query_mode(mode: Option<&str>, name: &str) -> Result<QueryMode> {
    match mode {
        None | Some("any") => Ok(QueryMode::Any),
        Some("all") => Ok(QueryMode::All),
        Some(other) => Err(Error::WalletError(format!(
            "Invalid {}: must be 'any' or 'all', got '{}'",
            name, other
        ))),
    }
}

/// Validated list outputs arguments.
#[derive(Debug, Clone)]
pub struct ValidListOutputsArgs {
    /// The basket to list outputs from.
    pub basket: String,
    /// Tags to filter by.
    pub tags: Vec<String>,
    /// Tag query mode (any/all).
    pub tag_query_mode: QueryMode,
    /// Whether to include locking scripts.
    pub include_locking_scripts: bool,
    /// Whether to include full transactions.
    pub include_transactions: bool,
    /// Whether to include custom instructions.
    pub include_custom_instructions: bool,
    /// Whether to include tags.
    pub include_tags: bool,
    /// Whether to include labels.
    pub include_labels: bool,
    /// Maximum results to return.
    pub limit: u32,
    /// Offset for pagination.
    pub offset: i32,
    /// Whether to seek permission.
    pub seek_permission: bool,
    /// Known transaction IDs.
    pub known_txids: Vec<String>,
}

/// Validated list actions arguments.
#[derive(Debug, Clone)]
pub struct ValidListActionsArgs {
    /// Labels to filter by.
    pub labels: Vec<String>,
    /// Label query mode (any/all).
    pub label_query_mode: QueryMode,
    /// Whether to include labels.
    pub include_labels: bool,
    /// Whether to include inputs.
    pub include_inputs: bool,
    /// Whether to include input source locking scripts.
    pub include_input_source_locking_scripts: bool,
    /// Whether to include input unlocking scripts.
    pub include_input_unlocking_scripts: bool,
    /// Whether to include outputs.
    pub include_outputs: bool,
    /// Whether to include output locking scripts.
    pub include_output_locking_scripts: bool,
    /// Maximum results to return.
    pub limit: u32,
    /// Offset for pagination.
    pub offset: u32,
    /// Whether to seek permission.
    pub seek_permission: bool,
}

// =============================================================================
// Certificate Validation
// =============================================================================

/// Validates certificate field names (1-50 bytes each).
pub fn validate_certificate_fields(
    fields: &std::collections::HashMap<String, String>,
) -> Result<std::collections::HashMap<String, String>> {
    let mut result = std::collections::HashMap::new();
    for (field_name, value) in fields {
        validate_string_length(field_name, "field name", Some(1), Some(50))?;
        result.insert(field_name.clone(), value.clone());
    }
    Ok(result)
}

/// Validates a keyring revealer (either "certifier" or a public key hex).
pub fn validate_keyring_revealer(kr: &str, name: &str) -> Result<String> {
    if kr == "certifier" {
        return Ok(kr.to_string());
    }
    validate_hex_string(kr, name, Some(66), Some(66))
}

// =============================================================================
// Protocol Validation
// =============================================================================

/// Validates and creates a Protocol from a tuple (security_level, protocol_name).
pub fn validate_protocol_tuple(tuple: (u8, &str)) -> Result<Protocol> {
    let security_level = SecurityLevel::from_u8(tuple.0).ok_or_else(|| {
        Error::WalletError(format!(
            "Invalid security level: {} (must be 0, 1, or 2)",
            tuple.0
        ))
    })?;

    // Validate protocol name
    let protocol_name = crate::wallet::types::validate_protocol_name(tuple.1)?;

    Ok(Protocol::new(security_level, protocol_name))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_satoshis() {
        assert!(validate_satoshis(0, "test", None).is_ok());
        assert!(validate_satoshis(MAX_SATOSHIS, "test", None).is_ok());
        assert!(validate_satoshis(MAX_SATOSHIS + 1, "test", None).is_err());
        assert!(validate_satoshis(100, "test", Some(50)).is_ok());
        assert!(validate_satoshis(100, "test", Some(200)).is_err());
    }

    #[test]
    fn test_validate_integer() {
        assert_eq!(
            validate_integer(Some(5), "test", None, None, None).unwrap(),
            5
        );
        assert_eq!(
            validate_integer(None, "test", Some(10), None, None).unwrap(),
            10
        );
        assert!(validate_integer(None, "test", None, None, None).is_err());
        assert!(validate_integer(Some(5), "test", None, Some(10), None).is_err());
        assert!(validate_integer(Some(15), "test", None, None, Some(10)).is_err());
    }

    #[test]
    fn test_validate_string_length() {
        assert!(validate_string_length("hello", "test", None, None).is_ok());
        assert!(validate_string_length("hi", "test", Some(5), None).is_err());
        assert!(validate_string_length("hello world", "test", None, Some(5)).is_err());
    }

    #[test]
    fn test_validate_hex_string() {
        assert!(validate_hex_string("deadbeef", "test", None, None).is_ok());
        assert!(validate_hex_string("DEADBEEF", "test", None, None).is_ok()); // Case insensitive
        assert!(validate_hex_string("  deadbeef  ", "test", None, None).is_ok()); // Trimmed
        assert!(validate_hex_string("deadbee", "test", None, None).is_err()); // Odd length
        assert!(validate_hex_string("ghijkl", "test", None, None).is_err()); // Invalid chars
        assert!(validate_hex_string("dead", "test", Some(8), None).is_err()); // Too short
        assert!(validate_hex_string("deadbeef", "test", None, Some(4)).is_err());
        // Too long
    }

    #[test]
    fn test_validate_base64_string() {
        assert!(validate_base64_string("SGVsbG8=", "test", None, None).is_ok());
        assert!(validate_base64_string("SGVsbG8", "test", None, None).is_ok()); // No padding
        assert!(validate_base64_string("", "test", None, None).is_err()); // Empty
        assert!(validate_base64_string("SGVsb@8=", "test", None, None).is_err());
        // Invalid char
    }

    #[test]
    fn test_parse_wallet_outpoint() {
        let txid = "0000000000000000000000000000000000000000000000000000000000000001";
        let outpoint_str = format!("{}.5", txid);

        let outpoint = parse_wallet_outpoint(&outpoint_str).unwrap();
        assert_eq!(outpoint.vout, 5);
        assert_eq!(outpoint.txid[31], 1);
    }

    #[test]
    fn test_parse_wallet_outpoint_invalid() {
        assert!(parse_wallet_outpoint("invalid").is_err());
        assert!(parse_wallet_outpoint("abc.1").is_err()); // txid too short
        assert!(parse_wallet_outpoint("00000000000000000000000000000000.abc").is_err());
        // vout not int
    }

    #[test]
    fn test_validate_basket() {
        assert!(validate_basket("my-basket").is_ok());
        assert!(validate_basket("  MY_BASKET  ").is_ok()); // Trimmed and lowercased
        assert!(validate_basket("").is_err()); // Empty
        assert!(validate_basket(&"a".repeat(301)).is_err()); // Too long
    }

    #[test]
    fn test_validate_label() {
        assert!(validate_label("my-label").is_ok());
        assert!(validate_label("").is_err());
    }

    #[test]
    fn test_validate_tag() {
        assert!(validate_tag("my-tag").is_ok());
        assert!(validate_tag("").is_err());
    }

    #[test]
    fn test_validate_originator() {
        assert!(validate_originator(None).unwrap().is_none());
        assert!(validate_originator(Some("example.com")).is_ok());
        assert!(validate_originator(Some("sub.example.com")).is_ok());
        assert!(validate_originator(Some("")).is_err()); // Empty
        assert!(validate_originator(Some(&"a".repeat(251))).is_err()); // Too long
    }

    #[test]
    fn test_validate_query_mode() {
        assert_eq!(validate_query_mode(None, "test").unwrap(), QueryMode::Any);
        assert_eq!(
            validate_query_mode(Some("any"), "test").unwrap(),
            QueryMode::Any
        );
        assert_eq!(
            validate_query_mode(Some("all"), "test").unwrap(),
            QueryMode::All
        );
        assert!(validate_query_mode(Some("invalid"), "test").is_err());
    }

    #[test]
    fn test_validate_protocol_tuple() {
        let proto = validate_protocol_tuple((1, "test application")).unwrap();
        assert_eq!(proto.security_level, SecurityLevel::App);
        assert_eq!(proto.protocol_name, "test application");

        // Invalid security level
        assert!(validate_protocol_tuple((5, "test")).is_err());

        // Invalid protocol name (too short)
        assert!(validate_protocol_tuple((1, "abc")).is_err());
    }

    #[test]
    fn test_is_hex_string() {
        assert!(is_hex_string("deadbeef"));
        assert!(is_hex_string("DEADBEEF"));
        assert!(!is_hex_string("deadbee")); // Odd length
        assert!(!is_hex_string("ghijkl")); // Invalid chars
    }
}
