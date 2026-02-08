//! Wire protocol encoding utilities.
//!
//! This module provides [`WireReader`] and [`WireWriter`] types that extend the
//! primitives Reader/Writer with signed varint support and convenience methods
//! for the WalletWire protocol.

use crate::primitives::encoding::{Reader, Writer};
use crate::primitives::{from_hex, to_hex, PublicKey};
use crate::wallet::types::{
    ActionStatus, BasketInsertion, Counterparty, IdentityCertificate, IdentityCertifier,
    InternalizeOutput, Outpoint, OutputInclude, Protocol, QueryMode, SecurityLevel, SendWithResult,
    SendWithResultStatus, SignActionSpend, WalletAction, WalletActionInput, WalletActionOutput,
    WalletCertificate, WalletOutput, WalletPayment,
};
use crate::Error;
use std::collections::HashMap;

/// Wire protocol reader with signed varint support.
///
/// Wraps the primitives [`Reader`] and adds methods for reading signed varints
/// and other wire protocol types.
pub struct WireReader<'a> {
    inner: Reader<'a>,
}

impl<'a> WireReader<'a> {
    /// Creates a new wire reader over the given bytes.
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            inner: Reader::new(data),
        }
    }

    /// Returns the number of bytes remaining.
    pub fn remaining(&self) -> usize {
        self.inner.remaining()
    }

    /// Returns true if no bytes remain.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Returns the current position.
    pub fn position(&self) -> usize {
        self.inner.position()
    }

    // =========================================================================
    // Basic types (delegated to inner reader)
    // =========================================================================

    /// Reads an unsigned byte.
    pub fn read_u8(&mut self) -> Result<u8, Error> {
        self.inner.read_u8()
    }

    /// Reads a signed byte.
    pub fn read_i8(&mut self) -> Result<i8, Error> {
        self.inner.read_i8()
    }

    /// Reads a 16-bit unsigned integer in little-endian.
    pub fn read_u16_le(&mut self) -> Result<u16, Error> {
        self.inner.read_u16_le()
    }

    /// Reads a 32-bit unsigned integer in little-endian.
    pub fn read_u32_le(&mut self) -> Result<u32, Error> {
        self.inner.read_u32_le()
    }

    /// Reads a 64-bit unsigned integer in little-endian.
    pub fn read_u64_le(&mut self) -> Result<u64, Error> {
        self.inner.read_u64_le()
    }

    /// Reads a fixed number of bytes.
    pub fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], Error> {
        self.inner.read_bytes(len)
    }

    /// Reads all remaining bytes.
    pub fn read_remaining(&mut self) -> &'a [u8] {
        self.inner.read_remaining()
    }

    /// Reads an unsigned varint.
    pub fn read_var_int(&mut self) -> Result<u64, Error> {
        self.inner.read_var_int()
    }

    // =========================================================================
    // Signed varint (for optional values)
    // =========================================================================

    /// Reads a signed varint.
    ///
    /// The WalletWire protocol uses signed varints to encode optional values,
    /// where -1 indicates null/undefined.
    ///
    /// The encoding uses ZigZag encoding to efficiently store negative numbers:
    /// - Non-negative n is encoded as 2n
    /// - Negative n is encoded as 2|n| - 1
    pub fn read_signed_var_int(&mut self) -> Result<i64, Error> {
        let unsigned = self.inner.read_var_int()?;
        // ZigZag decode: (n >> 1) ^ -(n & 1)
        let signed = ((unsigned >> 1) as i64) ^ (-((unsigned & 1) as i64));
        Ok(signed)
    }

    /// Reads an optional value encoded as a signed varint.
    ///
    /// Returns `None` if the value is negative (representing null/undefined).
    pub fn read_optional_var_int(&mut self) -> Result<Option<u64>, Error> {
        let signed = self.read_signed_var_int()?;
        if signed < 0 {
            Ok(None)
        } else {
            Ok(Some(signed as u64))
        }
    }

    // =========================================================================
    // Wire protocol types
    // =========================================================================

    /// Reads a length-prefixed string.
    pub fn read_string(&mut self) -> Result<String, Error> {
        let len = self.read_var_int()? as usize;
        let bytes = self.read_bytes(len)?;
        String::from_utf8(bytes.to_vec())
            .map_err(|e| Error::WalletError(format!("invalid UTF-8: {}", e)))
    }

    /// Reads an optional string (length -1 = null).
    pub fn read_optional_string(&mut self) -> Result<Option<String>, Error> {
        let len = self.read_signed_var_int()?;
        if len < 0 {
            Ok(None)
        } else {
            let bytes = self.read_bytes(len as usize)?;
            let s = String::from_utf8(bytes.to_vec())
                .map_err(|e| Error::WalletError(format!("invalid UTF-8: {}", e)))?;
            Ok(Some(s))
        }
    }

    /// Reads an optional byte array (length -1 = null).
    pub fn read_optional_bytes(&mut self) -> Result<Option<Vec<u8>>, Error> {
        let len = self.read_signed_var_int()?;
        if len < 0 {
            Ok(None)
        } else {
            let bytes = self.read_bytes(len as usize)?;
            Ok(Some(bytes.to_vec()))
        }
    }

    /// Reads a string array (count -1 = null/empty).
    pub fn read_string_array(&mut self) -> Result<Vec<String>, Error> {
        let count = self.read_signed_var_int()?;
        if count < 0 {
            return Ok(Vec::new());
        }

        let mut strings = Vec::with_capacity(count as usize);
        for _ in 0..count {
            strings.push(self.read_string()?);
        }
        Ok(strings)
    }

    /// Reads an optional boolean (i8: -1 = undefined, 0 = false, 1 = true).
    pub fn read_optional_bool(&mut self) -> Result<Option<bool>, Error> {
        let flag = self.read_i8()?;
        match flag {
            -1 => Ok(None),
            0 => Ok(Some(false)),
            1 => Ok(Some(true)),
            _ => Err(Error::WalletError(format!(
                "invalid boolean flag: expected -1, 0, or 1, got {}",
                flag
            ))),
        }
    }

    /// Reads an outpoint (32-byte txid + varint index).
    pub fn read_outpoint(&mut self) -> Result<Outpoint, Error> {
        let txid_bytes = self.read_bytes(32)?;
        let mut txid = [0u8; 32];
        txid.copy_from_slice(txid_bytes);
        let vout = self.read_var_int()? as u32;
        Ok(Outpoint::new(txid, vout))
    }

    /// Reads an outpoint as a string (txid.vout format).
    pub fn read_outpoint_string(&mut self) -> Result<String, Error> {
        let outpoint = self.read_outpoint()?;
        Ok(outpoint.to_string())
    }

    /// Reads a counterparty.
    ///
    /// Encoding:
    /// - 0 = undefined
    /// - 11 = "self"
    /// - 12 = "anyone"
    /// - otherwise: first byte + 32 more = 33-byte compressed public key
    pub fn read_counterparty(&mut self) -> Result<Option<Counterparty>, Error> {
        let flag = self.read_u8()?;
        match flag {
            0 => Ok(None),
            11 => Ok(Some(Counterparty::Self_)),
            12 => Ok(Some(Counterparty::Anyone)),
            _ => {
                // First byte is part of the 33-byte public key
                let remaining = self.read_bytes(32)?;
                let mut pubkey_bytes = vec![flag];
                pubkey_bytes.extend_from_slice(remaining);
                let pubkey = PublicKey::from_bytes(&pubkey_bytes)?;
                Ok(Some(Counterparty::Other(pubkey)))
            }
        }
    }

    /// Reads a protocol ID (security level + protocol name).
    pub fn read_protocol_id(&mut self) -> Result<Protocol, Error> {
        let level = self.read_u8()?;
        let security_level = SecurityLevel::from_u8(level)
            .ok_or_else(|| Error::WalletError(format!("invalid security level: {}", level)))?;
        let protocol_name = self.read_string()?;
        Ok(Protocol::new(security_level, protocol_name))
    }

    /// Reads an optional protocol ID.
    ///
    /// Returns None if the security level is 255 (sentinel for undefined).
    pub fn read_optional_protocol_id(&mut self) -> Result<Option<Protocol>, Error> {
        let level = self.read_u8()?;
        if level == 255 {
            // Read and discard the empty protocol name
            let _ = self.read_string()?;
            return Ok(None);
        }
        let security_level = SecurityLevel::from_u8(level)
            .ok_or_else(|| Error::WalletError(format!("invalid security level: {}", level)))?;
        let protocol_name = self.read_string()?;
        Ok(Some(Protocol::new(security_level, protocol_name)))
    }

    /// Reads an action status code.
    pub fn read_action_status(&mut self) -> Result<Option<ActionStatus>, Error> {
        let code = self.read_i8()?;
        let status = match code {
            1 => Some(ActionStatus::Completed),
            2 => Some(ActionStatus::Unprocessed),
            3 => Some(ActionStatus::Sending),
            4 => Some(ActionStatus::Unproven),
            5 => Some(ActionStatus::Unsigned),
            6 => Some(ActionStatus::NoSend),
            7 => Some(ActionStatus::NonFinal),
            8 => Some(ActionStatus::Failed),
            -1 => None,
            _ => {
                return Err(Error::WalletError(format!(
                    "invalid action status code: {}",
                    code
                )))
            }
        };
        Ok(status)
    }

    /// Reads a 32-byte txid as hex string.
    pub fn read_txid_hex(&mut self) -> Result<String, Error> {
        let bytes = self.read_bytes(32)?;
        Ok(to_hex(bytes))
    }

    /// Reads a 33-byte compressed public key as hex string.
    pub fn read_pubkey_hex(&mut self) -> Result<String, Error> {
        let bytes = self.read_bytes(33)?;
        Ok(to_hex(bytes))
    }

    // =========================================================================
    // New type encoding methods
    // =========================================================================

    /// Reads a query mode (0 = any, 1 = all).
    pub fn read_query_mode(&mut self) -> Result<QueryMode, Error> {
        let val = self.read_u8()?;
        match val {
            0 => Ok(QueryMode::Any),
            1 => Ok(QueryMode::All),
            _ => Err(Error::WalletError(format!(
                "invalid query mode: expected 0 (any) or 1 (all), got {}",
                val
            ))),
        }
    }

    /// Reads an optional query mode.
    pub fn read_optional_query_mode(&mut self) -> Result<Option<QueryMode>, Error> {
        let val = self.read_i8()?;
        match val {
            -1 => Ok(None),
            0 => Ok(Some(QueryMode::Any)),
            1 => Ok(Some(QueryMode::All)),
            _ => Err(Error::WalletError(format!(
                "invalid query mode: expected -1, 0, or 1, got {}",
                val
            ))),
        }
    }

    /// Reads an output include mode.
    pub fn read_output_include(&mut self) -> Result<OutputInclude, Error> {
        let val = self.read_u8()?;
        match val {
            0 => Ok(OutputInclude::LockingScripts),
            1 => Ok(OutputInclude::EntireTransactions),
            _ => Err(Error::WalletError(format!(
                "invalid output include mode: expected 0 or 1, got {}",
                val
            ))),
        }
    }

    /// Reads an optional output include mode.
    pub fn read_optional_output_include(&mut self) -> Result<Option<OutputInclude>, Error> {
        let val = self.read_i8()?;
        match val {
            -1 => Ok(None),
            0 => Ok(Some(OutputInclude::LockingScripts)),
            1 => Ok(Some(OutputInclude::EntireTransactions)),
            _ => Err(Error::WalletError(format!(
                "invalid output include mode: expected -1, 0, or 1, got {}",
                val
            ))),
        }
    }

    /// Reads a string to string map.
    pub fn read_string_map(&mut self) -> Result<HashMap<String, String>, Error> {
        let count = self.read_signed_var_int()?;
        if count < 0 {
            return Ok(HashMap::new());
        }

        let mut map = HashMap::with_capacity(count as usize);
        for _ in 0..count {
            let key = self.read_string()?;
            let value = self.read_string()?;
            map.insert(key, value);
        }
        Ok(map)
    }

    /// Reads an optional string map.
    pub fn read_optional_string_map(&mut self) -> Result<Option<HashMap<String, String>>, Error> {
        let count = self.read_signed_var_int()?;
        if count < 0 {
            return Ok(None);
        }

        let mut map = HashMap::with_capacity(count as usize);
        for _ in 0..count {
            let key = self.read_string()?;
            let value = self.read_string()?;
            map.insert(key, value);
        }
        Ok(Some(map))
    }

    /// Reads a SendWithResultStatus.
    pub fn read_send_with_result_status(&mut self) -> Result<SendWithResultStatus, Error> {
        let val = self.read_u8()?;
        match val {
            0 => Ok(SendWithResultStatus::Unproven),
            1 => Ok(SendWithResultStatus::Sending),
            2 => Ok(SendWithResultStatus::Failed),
            _ => Err(Error::WalletError(format!(
                "invalid send with result status: {}",
                val
            ))),
        }
    }

    /// Reads a SendWithResult.
    pub fn read_send_with_result(&mut self) -> Result<SendWithResult, Error> {
        let txid_bytes = self.read_bytes(32)?;
        let mut txid = [0u8; 32];
        txid.copy_from_slice(txid_bytes);
        let status = self.read_send_with_result_status()?;
        Ok(SendWithResult { txid, status })
    }

    /// Reads an array of SendWithResults.
    pub fn read_send_with_result_array(&mut self) -> Result<Option<Vec<SendWithResult>>, Error> {
        let count = self.read_signed_var_int()?;
        if count < 0 {
            return Ok(None);
        }

        let mut results = Vec::with_capacity(count as usize);
        for _ in 0..count {
            results.push(self.read_send_with_result()?);
        }
        Ok(Some(results))
    }

    /// Reads a SignActionSpend.
    pub fn read_sign_action_spend(&mut self) -> Result<SignActionSpend, Error> {
        let unlocking_script_len = self.read_var_int()? as usize;
        let unlocking_script = self.read_bytes(unlocking_script_len)?.to_vec();
        let sequence_number = self.read_optional_var_int()?.map(|v| v as u32);
        Ok(SignActionSpend {
            unlocking_script,
            sequence_number,
        })
    }

    /// Reads a map of u32 to SignActionSpend.
    pub fn read_sign_action_spends(&mut self) -> Result<HashMap<u32, SignActionSpend>, Error> {
        let count = self.read_signed_var_int()?;
        if count < 0 {
            return Ok(HashMap::new());
        }

        let mut spends = HashMap::with_capacity(count as usize);
        for _ in 0..count {
            let index = self.read_var_int()? as u32;
            let spend = self.read_sign_action_spend()?;
            spends.insert(index, spend);
        }
        Ok(spends)
    }

    /// Reads a WalletCertificate.
    pub fn read_wallet_certificate(&mut self) -> Result<WalletCertificate, Error> {
        let certificate_type = self.read_string()?;
        let subject = self.read_pubkey_hex()?; // 33-byte compressed pubkey as hex
        let serial_number = self.read_string()?;
        let certifier = self.read_pubkey_hex()?; // 33-byte compressed pubkey as hex
        let revocation_outpoint = self.read_outpoint_string()?;
        let signature_len = self.read_var_int()? as usize;
        let signature = to_hex(self.read_bytes(signature_len)?);
        let fields = self.read_string_map()?;

        Ok(WalletCertificate {
            certificate_type,
            subject,
            serial_number,
            certifier,
            revocation_outpoint,
            signature,
            fields,
        })
    }

    /// Reads an optional WalletCertificate.
    pub fn read_optional_wallet_certificate(&mut self) -> Result<Option<WalletCertificate>, Error> {
        let flag = self.read_i8()?;
        if flag < 0 {
            return Ok(None);
        }
        // Re-read as we consumed the flag
        self.read_wallet_certificate().map(Some)
    }

    /// Reads an IdentityCertifier.
    pub fn read_identity_certifier(&mut self) -> Result<IdentityCertifier, Error> {
        let name = self.read_string()?;
        let icon_url = self.read_optional_string()?;
        let description = self.read_optional_string()?;
        let trust = self.read_u8()?;

        Ok(IdentityCertifier {
            name,
            icon_url,
            description,
            trust,
        })
    }

    /// Reads an optional IdentityCertifier.
    pub fn read_optional_identity_certifier(&mut self) -> Result<Option<IdentityCertifier>, Error> {
        let flag = self.read_i8()?;
        if flag < 0 {
            return Ok(None);
        }
        let name = self.read_string()?;
        let icon_url = self.read_optional_string()?;
        let description = self.read_optional_string()?;
        let trust = self.read_u8()?;

        Ok(Some(IdentityCertifier {
            name,
            icon_url,
            description,
            trust,
        }))
    }

    /// Reads an IdentityCertificate.
    pub fn read_identity_certificate(&mut self) -> Result<IdentityCertificate, Error> {
        let certificate = self.read_wallet_certificate()?;
        let certifier_info = self.read_optional_identity_certifier()?;
        let publicly_revealed_keyring = self.read_optional_string_map()?;
        let decrypted_fields = self.read_optional_string_map()?;

        Ok(IdentityCertificate {
            certificate,
            certifier_info,
            publicly_revealed_keyring,
            decrypted_fields,
        })
    }

    /// Reads a WalletPayment.
    pub fn read_wallet_payment(&mut self) -> Result<WalletPayment, Error> {
        let derivation_prefix = self.read_string()?;
        let derivation_suffix = self.read_string()?;
        let sender_identity_key = self.read_string()?;

        Ok(WalletPayment {
            derivation_prefix,
            derivation_suffix,
            sender_identity_key,
        })
    }

    /// Reads an optional WalletPayment.
    pub fn read_optional_wallet_payment(&mut self) -> Result<Option<WalletPayment>, Error> {
        let flag = self.read_i8()?;
        if flag < 0 {
            return Ok(None);
        }
        self.read_wallet_payment().map(Some)
    }

    /// Reads a BasketInsertion.
    pub fn read_basket_insertion(&mut self) -> Result<BasketInsertion, Error> {
        let basket = self.read_string()?;
        let custom_instructions = self.read_optional_string()?;
        let tags = {
            let arr = self.read_string_array()?;
            if arr.is_empty() {
                None
            } else {
                Some(arr)
            }
        };

        Ok(BasketInsertion {
            basket,
            custom_instructions,
            tags,
        })
    }

    /// Reads an optional BasketInsertion.
    pub fn read_optional_basket_insertion(&mut self) -> Result<Option<BasketInsertion>, Error> {
        let flag = self.read_i8()?;
        if flag < 0 {
            return Ok(None);
        }
        self.read_basket_insertion().map(Some)
    }

    /// Reads an InternalizeOutput.
    pub fn read_internalize_output(&mut self) -> Result<InternalizeOutput, Error> {
        let output_index = self.read_var_int()? as u32;
        let protocol = self.read_string()?;
        let payment_remittance = self.read_optional_wallet_payment()?;
        let insertion_remittance = self.read_optional_basket_insertion()?;

        Ok(InternalizeOutput {
            output_index,
            protocol,
            payment_remittance,
            insertion_remittance,
        })
    }

    /// Reads a WalletActionInput.
    pub fn read_wallet_action_input(&mut self) -> Result<WalletActionInput, Error> {
        let source_outpoint = self.read_outpoint()?;
        let source_satoshis = self.read_var_int()?;
        let source_locking_script = self.read_optional_bytes()?;
        let unlocking_script = self.read_optional_bytes()?;
        let input_description = self.read_string()?;
        let sequence_number = self.read_u32_le()?;

        Ok(WalletActionInput {
            source_outpoint,
            source_satoshis,
            source_locking_script,
            unlocking_script,
            input_description,
            sequence_number,
        })
    }

    /// Reads a WalletActionOutput.
    pub fn read_wallet_action_output(&mut self) -> Result<WalletActionOutput, Error> {
        let satoshis = self.read_var_int()?;
        let locking_script = self.read_optional_bytes()?;
        let spendable = self.read_optional_bool()?.unwrap_or(false);
        let custom_instructions = self.read_optional_string()?;
        let tags = self.read_string_array()?;
        let output_index = self.read_var_int()? as u32;
        let output_description = self.read_string()?;
        let basket = self.read_string()?;

        Ok(WalletActionOutput {
            satoshis,
            locking_script,
            spendable,
            custom_instructions,
            tags,
            output_index,
            output_description,
            basket,
        })
    }

    /// Reads a WalletAction.
    pub fn read_wallet_action(&mut self) -> Result<WalletAction, Error> {
        let txid_bytes = self.read_bytes(32)?;
        let mut txid = [0u8; 32];
        txid.copy_from_slice(txid_bytes);
        // satoshis can be negative for outgoing transactions
        let satoshis = self.read_signed_var_int()?;
        let status = self
            .read_action_status()?
            .unwrap_or(ActionStatus::Unprocessed);
        let is_outgoing = self.read_optional_bool()?.unwrap_or(false);
        let description = self.read_string()?;
        let labels = {
            let arr = self.read_string_array()?;
            if arr.is_empty() {
                None
            } else {
                Some(arr)
            }
        };
        let version = self.read_u32_le()?;
        let lock_time = self.read_u32_le()?;

        // Read optional inputs array
        let inputs_count = self.read_signed_var_int()?;
        let inputs = if inputs_count < 0 {
            None
        } else {
            let mut inputs = Vec::with_capacity(inputs_count as usize);
            for _ in 0..inputs_count {
                inputs.push(self.read_wallet_action_input()?);
            }
            Some(inputs)
        };

        // Read optional outputs array
        let outputs_count = self.read_signed_var_int()?;
        let outputs = if outputs_count < 0 {
            None
        } else {
            let mut outputs = Vec::with_capacity(outputs_count as usize);
            for _ in 0..outputs_count {
                outputs.push(self.read_wallet_action_output()?);
            }
            Some(outputs)
        };

        Ok(WalletAction {
            txid,
            satoshis,
            status,
            is_outgoing,
            description,
            labels,
            version,
            lock_time,
            inputs,
            outputs,
        })
    }

    /// Reads a WalletOutput.
    pub fn read_wallet_output(&mut self) -> Result<WalletOutput, Error> {
        let satoshis = self.read_var_int()?;
        let locking_script = self.read_optional_bytes()?;
        let spendable = self.read_optional_bool()?.unwrap_or(false);
        let custom_instructions = self.read_optional_string()?;
        let tags = {
            let arr = self.read_string_array()?;
            if arr.is_empty() {
                None
            } else {
                Some(arr)
            }
        };
        let outpoint = self.read_outpoint()?;
        let labels = {
            let arr = self.read_string_array()?;
            if arr.is_empty() {
                None
            } else {
                Some(arr)
            }
        };

        Ok(WalletOutput {
            satoshis,
            locking_script,
            spendable,
            custom_instructions,
            tags,
            outpoint,
            labels,
        })
    }
}

/// Wire protocol writer with signed varint support.
///
/// Wraps the primitives [`Writer`] and adds methods for writing signed varints
/// and other wire protocol types.
pub struct WireWriter {
    inner: Writer,
}

impl WireWriter {
    /// Creates a new wire writer.
    pub fn new() -> Self {
        Self {
            inner: Writer::new(),
        }
    }

    /// Creates a new wire writer with pre-allocated capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: Writer::with_capacity(capacity),
        }
    }

    /// Returns the current length of written data.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true if no data has been written.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Returns a reference to the written bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.inner.as_bytes()
    }

    /// Consumes the writer and returns the written bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.inner.into_bytes()
    }

    // =========================================================================
    // Basic types (delegated to inner writer)
    // =========================================================================

    /// Writes an unsigned byte.
    pub fn write_u8(&mut self, val: u8) -> &mut Self {
        self.inner.write_u8(val);
        self
    }

    /// Writes a signed byte.
    pub fn write_i8(&mut self, val: i8) -> &mut Self {
        self.inner.write_i8(val);
        self
    }

    /// Writes a 16-bit unsigned integer in little-endian.
    pub fn write_u16_le(&mut self, val: u16) -> &mut Self {
        self.inner.write_u16_le(val);
        self
    }

    /// Writes a 32-bit unsigned integer in little-endian.
    pub fn write_u32_le(&mut self, val: u32) -> &mut Self {
        self.inner.write_u32_le(val);
        self
    }

    /// Writes a 64-bit unsigned integer in little-endian.
    pub fn write_u64_le(&mut self, val: u64) -> &mut Self {
        self.inner.write_u64_le(val);
        self
    }

    /// Writes raw bytes.
    pub fn write_bytes(&mut self, data: &[u8]) -> &mut Self {
        self.inner.write_bytes(data);
        self
    }

    /// Writes an unsigned varint.
    pub fn write_var_int(&mut self, val: u64) -> &mut Self {
        self.inner.write_var_int(val);
        self
    }

    // =========================================================================
    // Signed varint (for optional values)
    // =========================================================================

    /// Writes a signed varint using ZigZag encoding.
    ///
    /// ZigZag encoding maps signed integers to unsigned integers:
    /// - Non-negative n is encoded as 2n
    /// - Negative n is encoded as 2|n| - 1
    pub fn write_signed_var_int(&mut self, val: i64) -> &mut Self {
        // ZigZag encode: (n << 1) ^ (n >> 63)
        let unsigned = ((val << 1) ^ (val >> 63)) as u64;
        self.write_var_int(unsigned)
    }

    /// Writes an optional value as a signed varint.
    ///
    /// `None` is encoded as -1.
    pub fn write_optional_var_int(&mut self, val: Option<u64>) -> &mut Self {
        match val {
            Some(v) => self.write_signed_var_int(v as i64),
            None => self.write_signed_var_int(-1),
        }
    }

    // =========================================================================
    // Wire protocol types
    // =========================================================================

    /// Writes a length-prefixed string.
    pub fn write_string(&mut self, s: &str) -> &mut Self {
        let bytes = s.as_bytes();
        self.write_var_int(bytes.len() as u64);
        self.write_bytes(bytes)
    }

    /// Writes an optional string (length -1 = null).
    pub fn write_optional_string(&mut self, s: Option<&str>) -> &mut Self {
        match s {
            Some(s) => {
                let bytes = s.as_bytes();
                self.write_signed_var_int(bytes.len() as i64);
                self.write_bytes(bytes)
            }
            None => self.write_signed_var_int(-1),
        }
    }

    /// Writes optional bytes (length -1 = null).
    pub fn write_optional_bytes(&mut self, data: Option<&[u8]>) -> &mut Self {
        match data {
            Some(data) => {
                self.write_signed_var_int(data.len() as i64);
                self.write_bytes(data)
            }
            None => self.write_signed_var_int(-1),
        }
    }

    /// Writes a string array.
    pub fn write_string_array(&mut self, strings: &[String]) -> &mut Self {
        self.write_signed_var_int(strings.len() as i64);
        for s in strings {
            self.write_string(s);
        }
        self
    }

    /// Writes an optional string array (None becomes count -1).
    pub fn write_optional_string_array(&mut self, strings: Option<&[String]>) -> &mut Self {
        match strings {
            Some(strings) => self.write_string_array(strings),
            None => self.write_signed_var_int(-1),
        }
    }

    /// Writes an optional boolean (i8: -1 = undefined, 0 = false, 1 = true).
    pub fn write_optional_bool(&mut self, val: Option<bool>) -> &mut Self {
        let flag = match val {
            None => -1,
            Some(false) => 0,
            Some(true) => 1,
        };
        self.write_i8(flag)
    }

    /// Writes an outpoint (32-byte txid + varint index).
    pub fn write_outpoint(&mut self, outpoint: &Outpoint) -> &mut Self {
        self.write_bytes(&outpoint.txid);
        self.write_var_int(outpoint.vout as u64)
    }

    /// Writes an outpoint from a string (txid.vout format).
    pub fn write_outpoint_string(&mut self, outpoint: &str) -> Result<&mut Self, Error> {
        let parsed = Outpoint::from_string(outpoint)?;
        Ok(self.write_outpoint(&parsed))
    }

    /// Writes a counterparty.
    ///
    /// Encoding:
    /// - None = 0
    /// - Self_ = 11
    /// - Anyone = 12
    /// - Other(pubkey) = 33-byte compressed public key
    pub fn write_counterparty(&mut self, counterparty: Option<&Counterparty>) -> &mut Self {
        match counterparty {
            None => self.write_u8(0),
            Some(Counterparty::Self_) => self.write_u8(11),
            Some(Counterparty::Anyone) => self.write_u8(12),
            Some(Counterparty::Other(pubkey)) => self.write_bytes(&pubkey.to_compressed()),
        }
    }

    /// Writes a protocol ID (security level + protocol name).
    pub fn write_protocol_id(&mut self, protocol: &Protocol) -> &mut Self {
        self.write_u8(protocol.security_level.as_u8());
        self.write_string(&protocol.protocol_name)
    }

    /// Writes an optional protocol ID.
    ///
    /// If None, writes a security level of 255 to indicate undefined.
    pub fn write_optional_protocol_id(&mut self, protocol: Option<&Protocol>) -> &mut Self {
        match protocol {
            Some(p) => self.write_protocol_id(p),
            None => {
                self.write_u8(255); // Sentinel for undefined
                self.write_string("")
            }
        }
    }

    /// Writes an action status code.
    pub fn write_action_status(&mut self, status: Option<ActionStatus>) -> &mut Self {
        let code = match status {
            Some(ActionStatus::Completed) => 1,
            Some(ActionStatus::Unprocessed) => 2,
            Some(ActionStatus::Sending) => 3,
            Some(ActionStatus::Unproven) => 4,
            Some(ActionStatus::Unsigned) => 5,
            Some(ActionStatus::NoSend) => 6,
            Some(ActionStatus::NonFinal) => 7,
            Some(ActionStatus::Failed) => 8,
            None => -1,
        };
        self.write_i8(code)
    }

    /// Writes a 32-byte txid from hex string.
    pub fn write_txid_hex(&mut self, txid: &str) -> Result<&mut Self, Error> {
        let bytes = from_hex(txid)?;
        if bytes.len() != 32 {
            return Err(Error::WalletError(format!(
                "invalid txid length: expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        Ok(self.write_bytes(&bytes))
    }

    // =========================================================================
    // New type encoding methods
    // =========================================================================

    /// Writes a query mode (0 = any, 1 = all).
    pub fn write_query_mode(&mut self, mode: QueryMode) -> &mut Self {
        let val = match mode {
            QueryMode::Any => 0,
            QueryMode::All => 1,
        };
        self.write_u8(val)
    }

    /// Writes an optional query mode (-1 = None).
    pub fn write_optional_query_mode(&mut self, mode: Option<QueryMode>) -> &mut Self {
        match mode {
            None => self.write_i8(-1),
            Some(QueryMode::Any) => self.write_i8(0),
            Some(QueryMode::All) => self.write_i8(1),
        }
    }

    /// Writes an output include mode.
    pub fn write_output_include(&mut self, mode: OutputInclude) -> &mut Self {
        let val = match mode {
            OutputInclude::LockingScripts => 0,
            OutputInclude::EntireTransactions => 1,
        };
        self.write_u8(val)
    }

    /// Writes an optional output include mode.
    pub fn write_optional_output_include(&mut self, mode: Option<OutputInclude>) -> &mut Self {
        match mode {
            None => self.write_i8(-1),
            Some(OutputInclude::LockingScripts) => self.write_i8(0),
            Some(OutputInclude::EntireTransactions) => self.write_i8(1),
        }
    }

    /// Writes a string to string map.
    pub fn write_string_map(&mut self, map: &HashMap<String, String>) -> &mut Self {
        self.write_signed_var_int(map.len() as i64);
        for (key, value) in map {
            self.write_string(key);
            self.write_string(value);
        }
        self
    }

    /// Writes an optional string map.
    pub fn write_optional_string_map(
        &mut self,
        map: Option<&HashMap<String, String>>,
    ) -> &mut Self {
        match map {
            None => self.write_signed_var_int(-1),
            Some(map) => self.write_string_map(map),
        }
    }

    /// Writes a SendWithResultStatus.
    pub fn write_send_with_result_status(&mut self, status: SendWithResultStatus) -> &mut Self {
        let val = match status {
            SendWithResultStatus::Unproven => 0,
            SendWithResultStatus::Sending => 1,
            SendWithResultStatus::Failed => 2,
        };
        self.write_u8(val)
    }

    /// Writes a SendWithResult.
    pub fn write_send_with_result(&mut self, result: &SendWithResult) -> &mut Self {
        self.write_bytes(&result.txid);
        self.write_send_with_result_status(result.status)
    }

    /// Writes an optional array of SendWithResults.
    pub fn write_send_with_result_array(
        &mut self,
        results: Option<&[SendWithResult]>,
    ) -> &mut Self {
        match results {
            None => self.write_signed_var_int(-1),
            Some(results) => {
                self.write_signed_var_int(results.len() as i64);
                for r in results {
                    self.write_send_with_result(r);
                }
                self
            }
        }
    }

    /// Writes a SignActionSpend.
    pub fn write_sign_action_spend(&mut self, spend: &SignActionSpend) -> &mut Self {
        self.write_var_int(spend.unlocking_script.len() as u64);
        self.write_bytes(&spend.unlocking_script);
        self.write_optional_var_int(spend.sequence_number.map(|v| v as u64))
    }

    /// Writes a map of u32 to SignActionSpend.
    pub fn write_sign_action_spends(
        &mut self,
        spends: &HashMap<u32, SignActionSpend>,
    ) -> &mut Self {
        self.write_signed_var_int(spends.len() as i64);
        for (index, spend) in spends {
            self.write_var_int(*index as u64);
            self.write_sign_action_spend(spend);
        }
        self
    }

    /// Writes a WalletCertificate.
    pub fn write_wallet_certificate(
        &mut self,
        cert: &WalletCertificate,
    ) -> Result<&mut Self, Error> {
        self.write_string(&cert.certificate_type);
        // Write subject as 33-byte pubkey (from hex)
        let subject_bytes = from_hex(&cert.subject)?;
        self.write_bytes(&subject_bytes);
        self.write_string(&cert.serial_number);
        // Write certifier as 33-byte pubkey (from hex)
        let certifier_bytes = from_hex(&cert.certifier)?;
        self.write_bytes(&certifier_bytes);
        // Write revocation outpoint
        self.write_outpoint_string(&cert.revocation_outpoint)?;
        // Write signature
        let sig_bytes = from_hex(&cert.signature)?;
        self.write_var_int(sig_bytes.len() as u64);
        self.write_bytes(&sig_bytes);
        // Write fields
        self.write_string_map(&cert.fields);
        Ok(self)
    }

    /// Writes an optional WalletCertificate.
    pub fn write_optional_wallet_certificate(
        &mut self,
        cert: Option<&WalletCertificate>,
    ) -> Result<&mut Self, Error> {
        match cert {
            None => {
                self.write_i8(-1);
                Ok(self)
            }
            Some(cert) => {
                self.write_i8(1);
                self.write_wallet_certificate(cert)
            }
        }
    }

    /// Writes an IdentityCertifier.
    pub fn write_identity_certifier(&mut self, certifier: &IdentityCertifier) -> &mut Self {
        self.write_string(&certifier.name);
        self.write_optional_string(certifier.icon_url.as_deref());
        self.write_optional_string(certifier.description.as_deref());
        self.write_u8(certifier.trust)
    }

    /// Writes an optional IdentityCertifier.
    pub fn write_optional_identity_certifier(
        &mut self,
        certifier: Option<&IdentityCertifier>,
    ) -> &mut Self {
        match certifier {
            None => self.write_i8(-1),
            Some(c) => {
                self.write_i8(1);
                self.write_identity_certifier(c)
            }
        }
    }

    /// Writes an IdentityCertificate.
    pub fn write_identity_certificate(
        &mut self,
        cert: &IdentityCertificate,
    ) -> Result<&mut Self, Error> {
        self.write_wallet_certificate(&cert.certificate)?;
        self.write_optional_identity_certifier(cert.certifier_info.as_ref());
        self.write_optional_string_map(cert.publicly_revealed_keyring.as_ref());
        self.write_optional_string_map(cert.decrypted_fields.as_ref());
        Ok(self)
    }

    /// Writes a WalletPayment.
    pub fn write_wallet_payment(&mut self, payment: &WalletPayment) -> &mut Self {
        self.write_string(&payment.derivation_prefix);
        self.write_string(&payment.derivation_suffix);
        self.write_string(&payment.sender_identity_key)
    }

    /// Writes an optional WalletPayment.
    pub fn write_optional_wallet_payment(&mut self, payment: Option<&WalletPayment>) -> &mut Self {
        match payment {
            None => self.write_i8(-1),
            Some(p) => {
                self.write_i8(1);
                self.write_wallet_payment(p)
            }
        }
    }

    /// Writes a BasketInsertion.
    pub fn write_basket_insertion(&mut self, insertion: &BasketInsertion) -> &mut Self {
        self.write_string(&insertion.basket);
        self.write_optional_string(insertion.custom_instructions.as_deref());
        let tags = insertion.tags.as_deref().unwrap_or(&[]);
        self.write_string_array(tags)
    }

    /// Writes an optional BasketInsertion.
    pub fn write_optional_basket_insertion(
        &mut self,
        insertion: Option<&BasketInsertion>,
    ) -> &mut Self {
        match insertion {
            None => self.write_i8(-1),
            Some(i) => {
                self.write_i8(1);
                self.write_basket_insertion(i)
            }
        }
    }

    /// Writes an InternalizeOutput.
    pub fn write_internalize_output(&mut self, output: &InternalizeOutput) -> &mut Self {
        self.write_var_int(output.output_index as u64);
        self.write_string(&output.protocol);
        self.write_optional_wallet_payment(output.payment_remittance.as_ref());
        self.write_optional_basket_insertion(output.insertion_remittance.as_ref())
    }

    /// Writes a WalletActionInput.
    pub fn write_wallet_action_input(&mut self, input: &WalletActionInput) -> &mut Self {
        self.write_outpoint(&input.source_outpoint);
        self.write_var_int(input.source_satoshis);
        self.write_optional_bytes(input.source_locking_script.as_deref());
        self.write_optional_bytes(input.unlocking_script.as_deref());
        self.write_string(&input.input_description);
        self.write_u32_le(input.sequence_number)
    }

    /// Writes a WalletActionOutput.
    pub fn write_wallet_action_output(&mut self, output: &WalletActionOutput) -> &mut Self {
        self.write_var_int(output.satoshis);
        self.write_optional_bytes(output.locking_script.as_deref());
        self.write_optional_bool(Some(output.spendable));
        self.write_optional_string(output.custom_instructions.as_deref());
        self.write_string_array(&output.tags);
        self.write_var_int(output.output_index as u64);
        self.write_string(&output.output_description);
        self.write_string(&output.basket)
    }

    /// Writes a WalletAction.
    pub fn write_wallet_action(&mut self, action: &WalletAction) -> &mut Self {
        self.write_bytes(&action.txid);
        // satoshis can be negative for outgoing transactions
        self.write_signed_var_int(action.satoshis);
        self.write_action_status(Some(action.status));
        self.write_optional_bool(Some(action.is_outgoing));
        self.write_string(&action.description);
        let labels = action.labels.as_deref().unwrap_or(&[]);
        self.write_string_array(labels);
        self.write_u32_le(action.version);
        self.write_u32_le(action.lock_time);

        // Write optional inputs array
        match &action.inputs {
            None => {
                self.write_signed_var_int(-1);
            }
            Some(inputs) => {
                self.write_signed_var_int(inputs.len() as i64);
                for input in inputs {
                    self.write_wallet_action_input(input);
                }
            }
        }

        // Write optional outputs array
        match &action.outputs {
            None => {
                self.write_signed_var_int(-1);
            }
            Some(outputs) => {
                self.write_signed_var_int(outputs.len() as i64);
                for output in outputs {
                    self.write_wallet_action_output(output);
                }
            }
        }

        self
    }

    /// Writes a WalletOutput.
    pub fn write_wallet_output(&mut self, output: &WalletOutput) -> &mut Self {
        self.write_var_int(output.satoshis);
        self.write_optional_bytes(output.locking_script.as_deref());
        self.write_optional_bool(Some(output.spendable));
        self.write_optional_string(output.custom_instructions.as_deref());
        let tags = output.tags.as_deref().unwrap_or(&[]);
        self.write_string_array(tags);
        self.write_outpoint(&output.outpoint);
        let labels = output.labels.as_deref().unwrap_or(&[]);
        self.write_string_array(labels)
    }
}

impl Default for WireWriter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::PrivateKey;

    #[test]
    fn test_signed_var_int_roundtrip() {
        let test_values: &[i64] = &[
            0,
            1,
            -1,
            127,
            -127,
            128,
            -128,
            255,
            -255,
            1000,
            -1000,
            i64::MAX,
            i64::MIN,
        ];

        for &val in test_values {
            let mut writer = WireWriter::new();
            writer.write_signed_var_int(val);

            let mut reader = WireReader::new(writer.as_bytes());
            let read_val = reader.read_signed_var_int().unwrap();

            assert_eq!(read_val, val, "roundtrip failed for {}", val);
        }
    }

    #[test]
    fn test_optional_var_int() {
        // Test Some value
        let mut writer = WireWriter::new();
        writer.write_optional_var_int(Some(42));

        let mut reader = WireReader::new(writer.as_bytes());
        assert_eq!(reader.read_optional_var_int().unwrap(), Some(42));

        // Test None
        let mut writer = WireWriter::new();
        writer.write_optional_var_int(None);

        let mut reader = WireReader::new(writer.as_bytes());
        assert_eq!(reader.read_optional_var_int().unwrap(), None);
    }

    #[test]
    fn test_string_roundtrip() {
        let mut writer = WireWriter::new();
        writer.write_string("Hello, BSV!");

        let mut reader = WireReader::new(writer.as_bytes());
        assert_eq!(reader.read_string().unwrap(), "Hello, BSV!");
    }

    #[test]
    fn test_optional_string() {
        // Test Some
        let mut writer = WireWriter::new();
        writer.write_optional_string(Some("test"));

        let mut reader = WireReader::new(writer.as_bytes());
        assert_eq!(
            reader.read_optional_string().unwrap(),
            Some("test".to_string())
        );

        // Test None
        let mut writer = WireWriter::new();
        writer.write_optional_string(None);

        let mut reader = WireReader::new(writer.as_bytes());
        assert_eq!(reader.read_optional_string().unwrap(), None);
    }

    #[test]
    fn test_optional_bool() {
        for val in [None, Some(false), Some(true)] {
            let mut writer = WireWriter::new();
            writer.write_optional_bool(val);

            let mut reader = WireReader::new(writer.as_bytes());
            assert_eq!(reader.read_optional_bool().unwrap(), val);
        }
    }

    #[test]
    fn test_outpoint_roundtrip() {
        let txid = [0xab; 32];
        let outpoint = Outpoint::new(txid, 42);

        let mut writer = WireWriter::new();
        writer.write_outpoint(&outpoint);

        let mut reader = WireReader::new(writer.as_bytes());
        let read_outpoint = reader.read_outpoint().unwrap();

        assert_eq!(read_outpoint.txid, outpoint.txid);
        assert_eq!(read_outpoint.vout, outpoint.vout);
    }

    #[test]
    fn test_counterparty_roundtrip() {
        let private_key = PrivateKey::random();
        let public_key = private_key.public_key();

        let test_cases: Vec<Option<Counterparty>> = vec![
            None,
            Some(Counterparty::Self_),
            Some(Counterparty::Anyone),
            Some(Counterparty::Other(public_key)),
        ];

        for cp in test_cases {
            let mut writer = WireWriter::new();
            writer.write_counterparty(cp.as_ref());

            let mut reader = WireReader::new(writer.as_bytes());
            let read_cp = reader.read_counterparty().unwrap();

            match (&cp, &read_cp) {
                (None, None) => {}
                (Some(Counterparty::Self_), Some(Counterparty::Self_)) => {}
                (Some(Counterparty::Anyone), Some(Counterparty::Anyone)) => {}
                (Some(Counterparty::Other(a)), Some(Counterparty::Other(b))) => {
                    assert_eq!(a.to_compressed(), b.to_compressed());
                }
                _ => panic!("counterparty mismatch: {:?} vs {:?}", cp, read_cp),
            }
        }
    }

    #[test]
    fn test_protocol_id_roundtrip() {
        let protocol = Protocol::new(SecurityLevel::App, "test protocol");

        let mut writer = WireWriter::new();
        writer.write_protocol_id(&protocol);

        let mut reader = WireReader::new(writer.as_bytes());
        let read_protocol = reader.read_protocol_id().unwrap();

        assert_eq!(read_protocol.security_level, protocol.security_level);
        assert_eq!(read_protocol.protocol_name, protocol.protocol_name);
    }

    #[test]
    fn test_action_status_roundtrip() {
        let statuses = [
            None,
            Some(ActionStatus::Completed),
            Some(ActionStatus::Unprocessed),
            Some(ActionStatus::Sending),
            Some(ActionStatus::Unproven),
            Some(ActionStatus::Unsigned),
            Some(ActionStatus::NoSend),
            Some(ActionStatus::NonFinal),
            Some(ActionStatus::Failed),
        ];

        for status in statuses {
            let mut writer = WireWriter::new();
            writer.write_action_status(status);

            let mut reader = WireReader::new(writer.as_bytes());
            assert_eq!(reader.read_action_status().unwrap(), status);
        }
    }

    #[test]
    fn test_string_array_roundtrip() {
        let strings = vec!["foo".to_string(), "bar".to_string(), "baz".to_string()];

        let mut writer = WireWriter::new();
        writer.write_string_array(&strings);

        let mut reader = WireReader::new(writer.as_bytes());
        assert_eq!(reader.read_string_array().unwrap(), strings);
    }

    // =========================================================================
    // Wire Protocol Complex Type Roundtrip Tests
    // =========================================================================

    #[test]
    fn test_optional_bytes_roundtrip() {
        // Some bytes
        let mut writer = WireWriter::new();
        writer.write_optional_bytes(Some(&[1, 2, 3, 4, 5]));
        let mut reader = WireReader::new(writer.as_bytes());
        assert_eq!(
            reader.read_optional_bytes().unwrap(),
            Some(vec![1, 2, 3, 4, 5])
        );

        // None
        let mut writer = WireWriter::new();
        writer.write_optional_bytes(None);
        let mut reader = WireReader::new(writer.as_bytes());
        assert_eq!(reader.read_optional_bytes().unwrap(), None);

        // Empty bytes
        let mut writer = WireWriter::new();
        writer.write_optional_bytes(Some(&[]));
        let mut reader = WireReader::new(writer.as_bytes());
        assert_eq!(reader.read_optional_bytes().unwrap(), Some(vec![]));
    }

    #[test]
    fn test_optional_string_array_roundtrip() {
        // Some array
        let strings = vec!["alpha".to_string(), "beta".to_string()];
        let mut writer = WireWriter::new();
        writer.write_optional_string_array(Some(&strings));
        let mut reader = WireReader::new(writer.as_bytes());
        assert_eq!(reader.read_string_array().unwrap(), strings);

        // None
        let mut writer = WireWriter::new();
        writer.write_optional_string_array(None);
        let mut reader = WireReader::new(writer.as_bytes());
        assert_eq!(reader.read_string_array().unwrap(), Vec::<String>::new());
    }

    #[test]
    fn test_optional_protocol_id_roundtrip() {
        // Some protocol
        let protocol = Protocol::new(SecurityLevel::Counterparty, "linkage protocol");
        let mut writer = WireWriter::new();
        writer.write_optional_protocol_id(Some(&protocol));
        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_optional_protocol_id().unwrap();
        assert!(read.is_some());
        let read = read.unwrap();
        assert_eq!(read.security_level, SecurityLevel::Counterparty);
        assert_eq!(read.protocol_name, "linkage protocol");

        // None
        let mut writer = WireWriter::new();
        writer.write_optional_protocol_id(None);
        let mut reader = WireReader::new(writer.as_bytes());
        assert_eq!(reader.read_optional_protocol_id().unwrap(), None);
    }

    #[test]
    fn test_query_mode_roundtrip() {
        for mode in [QueryMode::Any, QueryMode::All] {
            let mut writer = WireWriter::new();
            writer.write_query_mode(mode);
            let mut reader = WireReader::new(writer.as_bytes());
            assert_eq!(reader.read_query_mode().unwrap(), mode);
        }
    }

    #[test]
    fn test_optional_query_mode_roundtrip() {
        for mode in [None, Some(QueryMode::Any), Some(QueryMode::All)] {
            let mut writer = WireWriter::new();
            writer.write_optional_query_mode(mode);
            let mut reader = WireReader::new(writer.as_bytes());
            assert_eq!(reader.read_optional_query_mode().unwrap(), mode);
        }
    }

    #[test]
    fn test_output_include_roundtrip() {
        for mode in [
            OutputInclude::LockingScripts,
            OutputInclude::EntireTransactions,
        ] {
            let mut writer = WireWriter::new();
            writer.write_output_include(mode);
            let mut reader = WireReader::new(writer.as_bytes());
            assert_eq!(reader.read_output_include().unwrap(), mode);
        }
    }

    #[test]
    fn test_optional_output_include_roundtrip() {
        for mode in [
            None,
            Some(OutputInclude::LockingScripts),
            Some(OutputInclude::EntireTransactions),
        ] {
            let mut writer = WireWriter::new();
            writer.write_optional_output_include(mode);
            let mut reader = WireReader::new(writer.as_bytes());
            assert_eq!(reader.read_optional_output_include().unwrap(), mode);
        }
    }

    #[test]
    fn test_string_map_roundtrip() {
        let mut map = HashMap::new();
        map.insert("key1".to_string(), "value1".to_string());
        map.insert("key2".to_string(), "value2".to_string());
        map.insert("key3".to_string(), "value3".to_string());

        let mut writer = WireWriter::new();
        writer.write_string_map(&map);
        let mut reader = WireReader::new(writer.as_bytes());
        assert_eq!(reader.read_string_map().unwrap(), map);

        // Empty map
        let empty_map = HashMap::new();
        let mut writer = WireWriter::new();
        writer.write_string_map(&empty_map);
        let mut reader = WireReader::new(writer.as_bytes());
        assert_eq!(reader.read_string_map().unwrap(), empty_map);
    }

    #[test]
    fn test_optional_string_map_roundtrip() {
        // Some map
        let mut map = HashMap::new();
        map.insert("a".to_string(), "b".to_string());

        let mut writer = WireWriter::new();
        writer.write_optional_string_map(Some(&map));
        let mut reader = WireReader::new(writer.as_bytes());
        assert_eq!(reader.read_optional_string_map().unwrap(), Some(map));

        // None
        let mut writer = WireWriter::new();
        writer.write_optional_string_map(None);
        let mut reader = WireReader::new(writer.as_bytes());
        assert_eq!(reader.read_optional_string_map().unwrap(), None);
    }

    #[test]
    fn test_send_with_result_status_roundtrip() {
        for status in [
            SendWithResultStatus::Unproven,
            SendWithResultStatus::Sending,
            SendWithResultStatus::Failed,
        ] {
            let mut writer = WireWriter::new();
            writer.write_send_with_result_status(status);
            let mut reader = WireReader::new(writer.as_bytes());
            assert_eq!(reader.read_send_with_result_status().unwrap(), status);
        }
    }

    #[test]
    fn test_send_with_result_roundtrip() {
        let result = SendWithResult {
            txid: [0xaa; 32],
            status: SendWithResultStatus::Sending,
        };

        let mut writer = WireWriter::new();
        writer.write_send_with_result(&result);
        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_send_with_result().unwrap();

        assert_eq!(read.txid, result.txid);
        assert_eq!(read.status, result.status);
    }

    #[test]
    fn test_send_with_result_array_roundtrip() {
        // Some array
        let results = vec![
            SendWithResult {
                txid: [0x11; 32],
                status: SendWithResultStatus::Unproven,
            },
            SendWithResult {
                txid: [0x22; 32],
                status: SendWithResultStatus::Failed,
            },
        ];

        let mut writer = WireWriter::new();
        writer.write_send_with_result_array(Some(&results));
        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_send_with_result_array().unwrap().unwrap();
        assert_eq!(read.len(), 2);
        assert_eq!(read[0].txid, results[0].txid);
        assert_eq!(read[0].status, results[0].status);
        assert_eq!(read[1].txid, results[1].txid);
        assert_eq!(read[1].status, results[1].status);

        // None
        let mut writer = WireWriter::new();
        writer.write_send_with_result_array(None);
        let mut reader = WireReader::new(writer.as_bytes());
        assert!(reader.read_send_with_result_array().unwrap().is_none());

        // Empty array
        let mut writer = WireWriter::new();
        writer.write_send_with_result_array(Some(&[]));
        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_send_with_result_array().unwrap().unwrap();
        assert!(read.is_empty());
    }

    #[test]
    fn test_sign_action_spend_roundtrip() {
        // With sequence number
        let spend = SignActionSpend {
            unlocking_script: vec![0x48, 0x30, 0x45, 0x02, 0x21],
            sequence_number: Some(0xfffffffe),
        };

        let mut writer = WireWriter::new();
        writer.write_sign_action_spend(&spend);
        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_sign_action_spend().unwrap();
        assert_eq!(read.unlocking_script, spend.unlocking_script);
        assert_eq!(read.sequence_number, spend.sequence_number);

        // Without sequence number
        let spend_no_seq = SignActionSpend {
            unlocking_script: vec![0x00],
            sequence_number: None,
        };

        let mut writer = WireWriter::new();
        writer.write_sign_action_spend(&spend_no_seq);
        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_sign_action_spend().unwrap();
        assert_eq!(read.unlocking_script, spend_no_seq.unlocking_script);
        assert_eq!(read.sequence_number, None);
    }

    #[test]
    fn test_sign_action_spends_map_roundtrip() {
        let mut spends = HashMap::new();
        spends.insert(
            0,
            SignActionSpend {
                unlocking_script: vec![0x01, 0x02, 0x03],
                sequence_number: Some(0xffffffff),
            },
        );
        spends.insert(
            3,
            SignActionSpend {
                unlocking_script: vec![0xaa, 0xbb],
                sequence_number: None,
            },
        );

        let mut writer = WireWriter::new();
        writer.write_sign_action_spends(&spends);
        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_sign_action_spends().unwrap();
        assert_eq!(read.len(), spends.len());
        for (key, val) in &spends {
            let read_val = read.get(key).unwrap();
            assert_eq!(read_val.unlocking_script, val.unlocking_script);
            assert_eq!(read_val.sequence_number, val.sequence_number);
        }

        // Empty map
        let empty: HashMap<u32, SignActionSpend> = HashMap::new();
        let mut writer = WireWriter::new();
        writer.write_sign_action_spends(&empty);
        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_sign_action_spends().unwrap();
        assert!(read.is_empty());
    }

    fn make_test_certificate() -> WalletCertificate {
        // Use valid 33-byte hex strings (compressed pubkey format)
        let pubkey = PrivateKey::random().public_key();
        let certifier = PrivateKey::random().public_key();
        let mut fields = HashMap::new();
        fields.insert("name".to_string(), "encrypted_value_1".to_string());
        fields.insert("email".to_string(), "encrypted_value_2".to_string());

        WalletCertificate {
            certificate_type: "z8nzALhCLnLbi4p6iCDW4oiFd6jd".to_string(),
            subject: pubkey.to_hex(),
            serial_number: "cert-serial-12345".to_string(),
            certifier: certifier.to_hex(),
            revocation_outpoint: format!("{}.0", crate::primitives::to_hex(&[0xcc; 32])),
            signature: crate::primitives::to_hex(&[0xdd; 72]),
            fields,
        }
    }

    #[test]
    fn test_wallet_certificate_roundtrip() {
        let cert = make_test_certificate();

        let mut writer = WireWriter::new();
        writer.write_wallet_certificate(&cert).unwrap();
        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_wallet_certificate().unwrap();

        assert_eq!(read.certificate_type, cert.certificate_type);
        assert_eq!(read.serial_number, cert.serial_number);
        assert_eq!(read.revocation_outpoint, cert.revocation_outpoint);
        assert_eq!(read.signature, cert.signature);
        assert_eq!(read.fields, cert.fields);
    }

    #[test]
    fn test_optional_wallet_certificate_roundtrip() {
        // Some certificate
        let cert = make_test_certificate();
        let mut writer = WireWriter::new();
        writer
            .write_optional_wallet_certificate(Some(&cert))
            .unwrap();
        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_optional_wallet_certificate().unwrap();
        assert!(read.is_some());
        let read = read.unwrap();
        assert_eq!(read.certificate_type, cert.certificate_type);

        // None
        let mut writer = WireWriter::new();
        writer.write_optional_wallet_certificate(None).unwrap();
        let mut reader = WireReader::new(writer.as_bytes());
        assert!(reader.read_optional_wallet_certificate().unwrap().is_none());
    }

    #[test]
    fn test_identity_certifier_roundtrip() {
        // Full certifier
        let certifier = IdentityCertifier {
            name: "Test CA".to_string(),
            icon_url: Some("https://example.com/icon.png".to_string()),
            description: Some("A test certificate authority".to_string()),
            trust: 3,
        };

        let mut writer = WireWriter::new();
        writer.write_identity_certifier(&certifier);
        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_identity_certifier().unwrap();
        assert_eq!(read.name, certifier.name);
        assert_eq!(read.icon_url, certifier.icon_url);
        assert_eq!(read.description, certifier.description);
        assert_eq!(read.trust, certifier.trust);

        // Minimal certifier (no optional fields)
        let minimal = IdentityCertifier {
            name: "Minimal CA".to_string(),
            icon_url: None,
            description: None,
            trust: 1,
        };

        let mut writer = WireWriter::new();
        writer.write_identity_certifier(&minimal);
        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_identity_certifier().unwrap();
        assert_eq!(read.name, minimal.name);
        assert_eq!(read.icon_url, None);
        assert_eq!(read.description, None);
        assert_eq!(read.trust, minimal.trust);
    }

    #[test]
    fn test_optional_identity_certifier_roundtrip() {
        // Some
        let certifier = IdentityCertifier {
            name: "Some CA".to_string(),
            icon_url: None,
            description: None,
            trust: 5,
        };
        let mut writer = WireWriter::new();
        writer.write_optional_identity_certifier(Some(&certifier));
        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_optional_identity_certifier().unwrap().unwrap();
        assert_eq!(read.name, certifier.name);
        assert_eq!(read.trust, certifier.trust);

        // None
        let mut writer = WireWriter::new();
        writer.write_optional_identity_certifier(None);
        let mut reader = WireReader::new(writer.as_bytes());
        assert!(reader.read_optional_identity_certifier().unwrap().is_none());
    }

    #[test]
    fn test_identity_certificate_roundtrip() {
        let mut keyring = HashMap::new();
        keyring.insert("name".to_string(), "revealed_key_1".to_string());

        let mut decrypted = HashMap::new();
        decrypted.insert("name".to_string(), "John Doe".to_string());
        decrypted.insert("email".to_string(), "john@example.com".to_string());

        let cert = IdentityCertificate {
            certificate: make_test_certificate(),
            certifier_info: Some(IdentityCertifier {
                name: "Trusted CA".to_string(),
                icon_url: Some("https://ca.example.com/icon.png".to_string()),
                description: None,
                trust: 4,
            }),
            publicly_revealed_keyring: Some(keyring),
            decrypted_fields: Some(decrypted),
        };

        let mut writer = WireWriter::new();
        writer.write_identity_certificate(&cert).unwrap();
        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_identity_certificate().unwrap();

        assert_eq!(
            read.certificate.certificate_type,
            cert.certificate.certificate_type
        );
        assert!(read.certifier_info.is_some());
        assert_eq!(read.certifier_info.unwrap().name, "Trusted CA");
        assert_eq!(
            read.publicly_revealed_keyring,
            cert.publicly_revealed_keyring
        );
        assert_eq!(read.decrypted_fields, cert.decrypted_fields);

        // Minimal: no optional fields
        let minimal_cert = IdentityCertificate {
            certificate: make_test_certificate(),
            certifier_info: None,
            publicly_revealed_keyring: None,
            decrypted_fields: None,
        };

        let mut writer = WireWriter::new();
        writer.write_identity_certificate(&minimal_cert).unwrap();
        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_identity_certificate().unwrap();
        assert!(read.certifier_info.is_none());
        assert_eq!(read.publicly_revealed_keyring, None);
        assert_eq!(read.decrypted_fields, None);
    }

    #[test]
    fn test_wallet_payment_roundtrip() {
        let payment = WalletPayment {
            derivation_prefix: "prefix_abc123".to_string(),
            derivation_suffix: "suffix_xyz789".to_string(),
            sender_identity_key: PrivateKey::random().public_key().to_hex(),
        };

        let mut writer = WireWriter::new();
        writer.write_wallet_payment(&payment);
        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_wallet_payment().unwrap();
        assert_eq!(read.derivation_prefix, payment.derivation_prefix);
        assert_eq!(read.derivation_suffix, payment.derivation_suffix);
        assert_eq!(read.sender_identity_key, payment.sender_identity_key);
    }

    #[test]
    fn test_optional_wallet_payment_roundtrip() {
        // Some
        let payment = WalletPayment {
            derivation_prefix: "pfx".to_string(),
            derivation_suffix: "sfx".to_string(),
            sender_identity_key: "deadbeef".to_string(),
        };
        let mut writer = WireWriter::new();
        writer.write_optional_wallet_payment(Some(&payment));
        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_optional_wallet_payment().unwrap().unwrap();
        assert_eq!(read.derivation_prefix, payment.derivation_prefix);

        // None
        let mut writer = WireWriter::new();
        writer.write_optional_wallet_payment(None);
        let mut reader = WireReader::new(writer.as_bytes());
        assert!(reader.read_optional_wallet_payment().unwrap().is_none());
    }

    #[test]
    fn test_basket_insertion_roundtrip() {
        // Full basket insertion
        let insertion = BasketInsertion {
            basket: "my-basket".to_string(),
            custom_instructions: Some("special instructions".to_string()),
            tags: Some(vec!["tag1".to_string(), "tag2".to_string()]),
        };

        let mut writer = WireWriter::new();
        writer.write_basket_insertion(&insertion);
        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_basket_insertion().unwrap();
        assert_eq!(read.basket, insertion.basket);
        assert_eq!(read.custom_instructions, insertion.custom_instructions);
        assert_eq!(read.tags, insertion.tags);

        // Minimal basket insertion
        let minimal = BasketInsertion {
            basket: "simple".to_string(),
            custom_instructions: None,
            tags: None,
        };

        let mut writer = WireWriter::new();
        writer.write_basket_insertion(&minimal);
        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_basket_insertion().unwrap();
        assert_eq!(read.basket, minimal.basket);
        assert_eq!(read.custom_instructions, None);
        assert_eq!(read.tags, None);
    }

    #[test]
    fn test_optional_basket_insertion_roundtrip() {
        let insertion = BasketInsertion {
            basket: "test-basket".to_string(),
            custom_instructions: None,
            tags: None,
        };

        // Some
        let mut writer = WireWriter::new();
        writer.write_optional_basket_insertion(Some(&insertion));
        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_optional_basket_insertion().unwrap().unwrap();
        assert_eq!(read.basket, "test-basket");

        // None
        let mut writer = WireWriter::new();
        writer.write_optional_basket_insertion(None);
        let mut reader = WireReader::new(writer.as_bytes());
        assert!(reader.read_optional_basket_insertion().unwrap().is_none());
    }

    #[test]
    fn test_internalize_output_roundtrip() {
        // With payment
        let output = InternalizeOutput {
            output_index: 0,
            protocol: "wallet payment".to_string(),
            payment_remittance: Some(WalletPayment {
                derivation_prefix: "prefix".to_string(),
                derivation_suffix: "suffix".to_string(),
                sender_identity_key: "sender_key_hex".to_string(),
            }),
            insertion_remittance: None,
        };

        let mut writer = WireWriter::new();
        writer.write_internalize_output(&output);
        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_internalize_output().unwrap();
        assert_eq!(read.output_index, 0);
        assert_eq!(read.protocol, "wallet payment");
        assert!(read.payment_remittance.is_some());
        assert!(read.insertion_remittance.is_none());

        // With basket insertion
        let output2 = InternalizeOutput {
            output_index: 5,
            protocol: "basket insertion".to_string(),
            payment_remittance: None,
            insertion_remittance: Some(BasketInsertion {
                basket: "tokens".to_string(),
                custom_instructions: Some("mint".to_string()),
                tags: Some(vec!["nft".to_string()]),
            }),
        };

        let mut writer = WireWriter::new();
        writer.write_internalize_output(&output2);
        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_internalize_output().unwrap();
        assert_eq!(read.output_index, 5);
        assert!(read.payment_remittance.is_none());
        assert!(read.insertion_remittance.is_some());
        assert_eq!(read.insertion_remittance.unwrap().basket, "tokens");
    }

    #[test]
    fn test_wallet_action_input_roundtrip() {
        // Full input
        let input = WalletActionInput {
            source_outpoint: Outpoint::new([0xab; 32], 0),
            source_satoshis: 50_000,
            source_locking_script: Some(vec![0x76, 0xa9, 0x14]),
            unlocking_script: Some(vec![0x48, 0x30, 0x45]),
            input_description: "spending utxo".to_string(),
            sequence_number: 0xfffffffe,
        };

        let mut writer = WireWriter::new();
        writer.write_wallet_action_input(&input);
        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_wallet_action_input().unwrap();
        assert_eq!(read.source_outpoint.txid, input.source_outpoint.txid);
        assert_eq!(read.source_outpoint.vout, input.source_outpoint.vout);
        assert_eq!(read.source_satoshis, input.source_satoshis);
        assert_eq!(read.source_locking_script, input.source_locking_script);
        assert_eq!(read.unlocking_script, input.unlocking_script);
        assert_eq!(read.input_description, input.input_description);
        assert_eq!(read.sequence_number, input.sequence_number);

        // Minimal input (no optional scripts)
        let minimal = WalletActionInput {
            source_outpoint: Outpoint::new([0x00; 32], 42),
            source_satoshis: 0,
            source_locking_script: None,
            unlocking_script: None,
            input_description: "".to_string(),
            sequence_number: 0xffffffff,
        };

        let mut writer = WireWriter::new();
        writer.write_wallet_action_input(&minimal);
        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_wallet_action_input().unwrap();
        assert_eq!(read.source_locking_script, None);
        assert_eq!(read.unlocking_script, None);
        assert_eq!(read.source_satoshis, 0);
    }

    #[test]
    fn test_wallet_action_output_roundtrip() {
        // Full output
        let output = WalletActionOutput {
            satoshis: 100_000,
            locking_script: Some(vec![0x76, 0xa9, 0x14, 0x00, 0x88, 0xac]),
            spendable: true,
            custom_instructions: Some("custom data here".to_string()),
            tags: vec!["payment".to_string(), "invoice".to_string()],
            output_index: 0,
            output_description: "payment to recipient".to_string(),
            basket: "payments".to_string(),
        };

        let mut writer = WireWriter::new();
        writer.write_wallet_action_output(&output);
        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_wallet_action_output().unwrap();
        assert_eq!(read.satoshis, output.satoshis);
        assert_eq!(read.locking_script, output.locking_script);
        assert_eq!(read.spendable, output.spendable);
        assert_eq!(read.custom_instructions, output.custom_instructions);
        assert_eq!(read.tags, output.tags);
        assert_eq!(read.output_index, output.output_index);
        assert_eq!(read.output_description, output.output_description);
        assert_eq!(read.basket, output.basket);

        // Minimal output
        let minimal = WalletActionOutput {
            satoshis: 0,
            locking_script: None,
            spendable: false,
            custom_instructions: None,
            tags: vec![],
            output_index: 1,
            output_description: "".to_string(),
            basket: "".to_string(),
        };

        let mut writer = WireWriter::new();
        writer.write_wallet_action_output(&minimal);
        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_wallet_action_output().unwrap();
        assert_eq!(read.satoshis, 0);
        assert_eq!(read.locking_script, None);
        assert!(!read.spendable);
        assert_eq!(read.custom_instructions, None);
        assert!(read.tags.is_empty());
    }

    #[test]
    fn test_wallet_action_roundtrip() {
        // Full action with inputs and outputs
        let action = WalletAction {
            txid: [0xab; 32],
            satoshis: 50_000,
            status: ActionStatus::Completed,
            is_outgoing: true,
            description: "sent payment".to_string(),
            labels: Some(vec!["outgoing".to_string(), "payment".to_string()]),
            version: 1,
            lock_time: 0,
            inputs: Some(vec![WalletActionInput {
                source_outpoint: Outpoint::new([0xcc; 32], 0),
                source_satoshis: 100_000,
                source_locking_script: Some(vec![0x76, 0xa9]),
                unlocking_script: Some(vec![0x48, 0x30]),
                input_description: "funding utxo".to_string(),
                sequence_number: 0xffffffff,
            }]),
            outputs: Some(vec![WalletActionOutput {
                satoshis: 50_000,
                locking_script: Some(vec![0x76, 0xa9, 0x14]),
                spendable: false,
                custom_instructions: None,
                tags: vec!["payment".to_string()],
                output_index: 0,
                output_description: "recipient output".to_string(),
                basket: "".to_string(),
            }]),
        };

        let mut writer = WireWriter::new();
        writer.write_wallet_action(&action);
        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_wallet_action().unwrap();
        assert_eq!(read.txid, action.txid);
        assert_eq!(read.satoshis, action.satoshis);
        assert_eq!(read.status, action.status);
        assert_eq!(read.is_outgoing, action.is_outgoing);
        assert_eq!(read.description, action.description);
        assert_eq!(read.labels, action.labels);
        assert_eq!(read.version, action.version);
        assert_eq!(read.lock_time, action.lock_time);
        assert!(read.inputs.is_some());
        assert_eq!(read.inputs.as_ref().unwrap().len(), 1);
        assert!(read.outputs.is_some());
        assert_eq!(read.outputs.as_ref().unwrap().len(), 1);

        // Negative satoshis (outgoing tx)
        let outgoing = WalletAction {
            txid: [0x11; 32],
            satoshis: -25_000,
            status: ActionStatus::Sending,
            is_outgoing: true,
            description: "outgoing".to_string(),
            labels: None,
            version: 1,
            lock_time: 500_000,
            inputs: None,
            outputs: None,
        };

        let mut writer = WireWriter::new();
        writer.write_wallet_action(&outgoing);
        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_wallet_action().unwrap();
        assert_eq!(read.satoshis, -25_000);
        assert_eq!(read.status, ActionStatus::Sending);
        assert!(read.inputs.is_none());
        assert!(read.outputs.is_none());
        assert_eq!(read.labels, None);
    }

    #[test]
    fn test_wallet_output_roundtrip() {
        // Full output
        let output = WalletOutput {
            satoshis: 75_000,
            locking_script: Some(vec![0x76, 0xa9, 0x14, 0x00, 0x88, 0xac]),
            spendable: true,
            custom_instructions: Some("custom".to_string()),
            tags: Some(vec!["utxo".to_string()]),
            outpoint: Outpoint::new([0xdd; 32], 1),
            labels: Some(vec!["label1".to_string(), "label2".to_string()]),
        };

        let mut writer = WireWriter::new();
        writer.write_wallet_output(&output);
        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_wallet_output().unwrap();
        assert_eq!(read.satoshis, output.satoshis);
        assert_eq!(read.locking_script, output.locking_script);
        assert_eq!(read.spendable, output.spendable);
        assert_eq!(read.custom_instructions, output.custom_instructions);
        assert_eq!(read.tags, output.tags);
        assert_eq!(read.outpoint.txid, output.outpoint.txid);
        assert_eq!(read.outpoint.vout, output.outpoint.vout);
        assert_eq!(read.labels, output.labels);

        // Minimal output
        let minimal = WalletOutput {
            satoshis: 546,
            locking_script: None,
            spendable: false,
            custom_instructions: None,
            tags: None,
            outpoint: Outpoint::new([0x00; 32], 0),
            labels: None,
        };

        let mut writer = WireWriter::new();
        writer.write_wallet_output(&minimal);
        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_wallet_output().unwrap();
        assert_eq!(read.satoshis, 546);
        assert_eq!(read.locking_script, None);
        assert!(!read.spendable);
        assert_eq!(read.custom_instructions, None);
        assert_eq!(read.tags, None);
        assert_eq!(read.labels, None);
    }

    #[test]
    fn test_txid_hex_roundtrip() {
        let txid = crate::primitives::to_hex(&[0xab; 32]);
        let mut writer = WireWriter::new();
        writer.write_txid_hex(&txid).unwrap();
        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_txid_hex().unwrap();
        assert_eq!(read, txid);
    }

    #[test]
    fn test_outpoint_string_roundtrip() {
        let outpoint_str = format!("{}.42", crate::primitives::to_hex(&[0xee; 32]));
        let mut writer = WireWriter::new();
        writer.write_outpoint_string(&outpoint_str).unwrap();
        let mut reader = WireReader::new(writer.as_bytes());
        let read = reader.read_outpoint_string().unwrap();
        assert_eq!(read, outpoint_str);
    }

    #[test]
    fn test_multiple_types_sequential() {
        // Write multiple different types into a single buffer, then read them all back
        let mut writer = WireWriter::new();

        writer.write_u8(42);
        writer.write_signed_var_int(-100);
        writer.write_string("hello");
        writer.write_optional_string(None);
        writer.write_optional_bool(Some(true));
        writer.write_outpoint(&Outpoint::new([0xff; 32], 7));
        writer.write_counterparty(Some(&Counterparty::Self_));
        writer.write_protocol_id(&Protocol::new(SecurityLevel::App, "test protocol"));
        writer.write_action_status(Some(ActionStatus::Completed));
        writer.write_query_mode(QueryMode::All);
        writer.write_output_include(OutputInclude::EntireTransactions);

        let mut reader = WireReader::new(writer.as_bytes());

        assert_eq!(reader.read_u8().unwrap(), 42);
        assert_eq!(reader.read_signed_var_int().unwrap(), -100);
        assert_eq!(reader.read_string().unwrap(), "hello");
        assert_eq!(reader.read_optional_string().unwrap(), None);
        assert_eq!(reader.read_optional_bool().unwrap(), Some(true));
        let op = reader.read_outpoint().unwrap();
        assert_eq!(op.txid, [0xff; 32]);
        assert_eq!(op.vout, 7);
        assert_eq!(
            reader.read_counterparty().unwrap(),
            Some(Counterparty::Self_)
        );
        let proto = reader.read_protocol_id().unwrap();
        assert_eq!(proto.security_level, SecurityLevel::App);
        assert_eq!(proto.protocol_name, "test protocol");
        assert_eq!(
            reader.read_action_status().unwrap(),
            Some(ActionStatus::Completed)
        );
        assert_eq!(reader.read_query_mode().unwrap(), QueryMode::All);
        assert_eq!(
            reader.read_output_include().unwrap(),
            OutputInclude::EntireTransactions
        );

        assert!(reader.is_empty());
    }

    #[test]
    fn test_empty_collections() {
        // Empty string
        let mut writer = WireWriter::new();
        writer.write_string("");
        let mut reader = WireReader::new(writer.as_bytes());
        assert_eq!(reader.read_string().unwrap(), "");

        // Empty string array
        let mut writer = WireWriter::new();
        writer.write_string_array(&[]);
        let mut reader = WireReader::new(writer.as_bytes());
        let arr = reader.read_string_array().unwrap();
        assert!(arr.is_empty());

        // Empty string map
        let empty_map: HashMap<String, String> = HashMap::new();
        let mut writer = WireWriter::new();
        writer.write_string_map(&empty_map);
        let mut reader = WireReader::new(writer.as_bytes());
        assert_eq!(reader.read_string_map().unwrap(), empty_map);
    }

    #[test]
    fn test_unicode_strings_roundtrip() {
        let unicode_strings = ["日本語テスト", "Ü̈ñîcödé", "🚀💰🔐", "mixed ASCII and 中文"];

        for s in unicode_strings {
            let mut writer = WireWriter::new();
            writer.write_string(s);
            let mut reader = WireReader::new(writer.as_bytes());
            assert_eq!(reader.read_string().unwrap(), s);
        }
    }

    #[test]
    fn test_large_data_roundtrip() {
        // Large string (1000 chars)
        let large_string: String = "x".repeat(1000);
        let mut writer = WireWriter::new();
        writer.write_string(&large_string);
        let mut reader = WireReader::new(writer.as_bytes());
        assert_eq!(reader.read_string().unwrap(), large_string);

        // Large byte array
        let large_bytes: Vec<u8> = (0..=255).cycle().take(4096).collect();
        let mut writer = WireWriter::new();
        writer.write_optional_bytes(Some(&large_bytes));
        let mut reader = WireReader::new(writer.as_bytes());
        assert_eq!(reader.read_optional_bytes().unwrap().unwrap(), large_bytes);
    }

    #[test]
    fn test_protocol_id_all_security_levels() {
        for level in [
            SecurityLevel::Silent,
            SecurityLevel::App,
            SecurityLevel::Counterparty,
        ] {
            let protocol = Protocol::new(level, "test protocol for level");
            let mut writer = WireWriter::new();
            writer.write_protocol_id(&protocol);
            let mut reader = WireReader::new(writer.as_bytes());
            let read = reader.read_protocol_id().unwrap();
            assert_eq!(read.security_level, level);
            assert_eq!(read.protocol_name, "test protocol for level");
        }
    }

    #[test]
    fn test_wallet_action_all_statuses() {
        let statuses = [
            ActionStatus::Completed,
            ActionStatus::Unprocessed,
            ActionStatus::Sending,
            ActionStatus::Unproven,
            ActionStatus::Unsigned,
            ActionStatus::NoSend,
            ActionStatus::NonFinal,
            ActionStatus::Failed,
        ];

        for status in statuses {
            let action = WalletAction {
                txid: [0x00; 32],
                satoshis: 0,
                status,
                is_outgoing: false,
                description: "test".to_string(),
                labels: None,
                version: 1,
                lock_time: 0,
                inputs: None,
                outputs: None,
            };

            let mut writer = WireWriter::new();
            writer.write_wallet_action(&action);
            let mut reader = WireReader::new(writer.as_bytes());
            let read = reader.read_wallet_action().unwrap();
            assert_eq!(read.status, status);
        }
    }
}
