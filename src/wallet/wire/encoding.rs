//! Wire protocol encoding utilities.
//!
//! This module provides [`WireReader`] and [`WireWriter`] types that extend the
//! primitives Reader/Writer with signed varint support and convenience methods
//! for the WalletWire protocol.

use crate::primitives::encoding::{Reader, Writer};
use crate::primitives::{bounded_capacity, from_base64, from_hex, to_base64, to_hex, PublicKey};
use crate::wallet::types::{
    ActionStatus, BasketInsertion, Counterparty, IdentityCertificate, IdentityCertifier,
    InternalizeOutput, Outpoint, OutputInclude, Protocol, QueryMode, SecurityLevel, SendWithResult,
    SendWithResultStatus, SignActionSpend, WalletAction, WalletActionInput, WalletActionOutput,
    WalletCertificate, WalletOutput, WalletPayment,
};
use crate::Error;
use indexmap::IndexMap;
use std::collections::HashMap;

#[path = "reader.rs"]
mod reader;

/// Sentinel value for nil/absent optional values in the Go-compatible wire format.
/// Go uses `VarInt(math.MaxUint64)` (9 bytes: `FF FF FF FF FF FF FF FF FF`) as a nil sentinel.
const NIL_SENTINEL: u64 = u64::MAX;

/// Wire protocol reader with signed varint support.
///
/// Wraps the primitives [`Reader`] and adds methods for reading signed varints
/// and other wire protocol types. Short reads return [`Error::WalletError`]
/// with `ReaderUint8Array read exceeds available data`, the reference's words.
pub struct WireReader<'a> {
    inner: Reader<'a>,
}

impl<'a> WireReader<'a> {
    // =========================================================================
    // Signed varint (for optional values)
    // =========================================================================

    /// Reads a signed varint: nine `0xFF` (`u64::MAX`) is `-1`, BRC-100's
    /// absent value, any other the plain varint (TS `readVarIntNum`, Go
    /// `ReadOptionalUint32`; #149). Refused above `i64::MAX`.
    pub fn read_signed_var_int(&mut self) -> Result<i64, Error> {
        match self.read_var_int()? {
            u64::MAX => Ok(-1),
            value => i64::try_from(value).map_err(|_| {
                Error::WalletError(format!(
                    "invalid signed varint: expected at most {} or -1, got {}",
                    i64::MAX,
                    value
                ))
            }),
        }
    }

    /// Reads an optional varint: `None` for nine `0xFF` (`-1`), else the value.
    pub fn read_optional_var_int(&mut self) -> Result<Option<u64>, Error> {
        let value = self.read_var_int()?;
        Ok((value != u64::MAX).then_some(value))
    }

    // =========================================================================
    // Wire protocol types
    // =========================================================================

    /// Reads an unsigned strict varint byte length ([`Self::wire_length`]).
    pub(crate) fn read_length(&mut self) -> Result<usize, Error> {
        let length = self.read_var_int()?;
        self.wire_length(length)
    }

    /// Reads a length-prefixed string.
    pub fn read_string(&mut self) -> Result<String, Error> {
        let len = self.read_length()?;
        let bytes = self.read_bytes(len)?;
        String::from_utf8(bytes.to_vec())
            .map_err(|e| Error::WalletError(format!("invalid UTF-8: {}", e)))
    }

    /// Reads an optional string (Go-compatible: VarInt(MaxUint64) = null).
    pub fn read_optional_string(&mut self) -> Result<Option<String>, Error> {
        let len = self.read_var_int()?;
        if len == NIL_SENTINEL {
            Ok(None)
        } else {
            let bytes = self.read_bytes(self.wire_length(len)?)?;
            let s = String::from_utf8(bytes.to_vec())
                .map_err(|e| Error::WalletError(format!("invalid UTF-8: {}", e)))?;
            Ok(Some(s))
        }
    }

    /// Reads an optional byte array (Go-compatible: VarInt(MaxUint64) = null).
    pub fn read_optional_bytes(&mut self) -> Result<Option<Vec<u8>>, Error> {
        let len = self.read_var_int()?;
        if len == NIL_SENTINEL {
            Ok(None)
        } else {
            let bytes = self.read_bytes(self.wire_length(len)?)?;
            Ok(Some(bytes.to_vec()))
        }
    }

    /// Reads a string array: optional count, then plain length-prefixed entries.
    pub fn read_string_array(&mut self) -> Result<Vec<String>, Error> {
        let count = self.read_optional_count()?;
        if count == NIL_SENTINEL {
            return Ok(Vec::new());
        }

        let mut strings = Vec::with_capacity(bounded_capacity(count as usize, self.remaining(), 1));
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
        let vout = self.read_var_int_u32("outpoint index")?;
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
                // `#decodeCounterparty`'s `Point.fromDER` (`WalletWireProcessor.ts:2459-2460`):
                // a 33-byte key whose tag is not `02`/`03` (a `05` among them) is
                // its `Unknown point format` (`Point.ts:303-325`; #550)
                if !matches!(flag, 2 | 3) {
                    return Err(Error::WalletError("Unknown point format".into()));
                }
                let pubkey = PublicKey::from_bytes(&pubkey_bytes)?;
                Ok(Some(Counterparty::Other(pubkey)))
            }
        }
    }

    /// Reads a protocol ID (security level + protocol name).
    pub fn read_protocol_id(&mut self) -> Result<Protocol, Error> {
        let level = self.read_u8()?;
        let security_level = SecurityLevel::from_u8(level).ok_or_else(|| {
            Error::WalletError(format!(
                "Invalid security level: expected 0, 1, or 2, received {level}"
            ))
        })?;
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
        let security_level = SecurityLevel::from_u8(level).ok_or_else(|| {
            Error::WalletError(format!(
                "Invalid security level: expected 0, 1, or 2, received {level}"
            ))
        })?;
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

    /// Reads a string to string map (Go-compatible: VarInt(MaxUint64) = empty).
    pub fn read_string_map(&mut self) -> Result<IndexMap<String, String>, Error> {
        let count = self.read_optional_count()?;
        if count == NIL_SENTINEL {
            return Ok(IndexMap::new());
        }

        let mut map =
            IndexMap::with_capacity(bounded_capacity(count as usize, self.remaining(), 2));
        for _ in 0..count {
            let key = self.read_string()?;
            let value = self.read_string()?;
            map.insert(key, value);
        }
        Ok(map)
    }

    /// Reads an optional string map.
    pub fn read_optional_string_map(&mut self) -> Result<Option<IndexMap<String, String>>, Error> {
        let count = self.read_optional_count()?;
        if count == NIL_SENTINEL {
            return Ok(None);
        }

        let mut map =
            IndexMap::with_capacity(bounded_capacity(count as usize, self.remaining(), 2));
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
        let count = self.read_response_count("sendWithResults", 1001, 33)?;
        if count == NIL_SENTINEL {
            return Ok(None);
        }

        let mut results = Vec::with_capacity(bounded_capacity(count as usize, self.remaining(), 1));
        for _ in 0..count {
            results.push(self.read_send_with_result()?);
        }
        Ok(Some(results))
    }

    /// Reads a SignActionSpend.
    pub fn read_sign_action_spend(&mut self) -> Result<SignActionSpend, Error> {
        let unlocking_script_len = self.read_length()?;
        let unlocking_script = self.read_bytes(unlocking_script_len)?.to_vec();
        let sequence_number = self.read_optional_var_int_u32("signAction spend sequenceNumber")?;
        Ok(SignActionSpend {
            unlocking_script,
            sequence_number,
        })
    }

    /// Reads a map of u32 to SignActionSpend.
    pub fn read_sign_action_spends(&mut self) -> Result<HashMap<u32, SignActionSpend>, Error> {
        let count = self.read_request_count("signAction spends")?;
        let mut spends =
            HashMap::with_capacity(bounded_capacity(count as usize, self.remaining(), 1));
        for _ in 0..count {
            let index = self.read_var_int_u32("sign action spend input index")?;
            let spend = self.read_sign_action_spend()?;
            spends.insert(index, spend);
        }
        Ok(spends)
    }

    /// Reads a WalletCertificate as `Certificate.fromBinary` reads it
    /// (`ts-stack@edf6e03` `Certificate.ts:329-408`; bsv-rs#183): type(32),
    /// serial(32), subject and certifier (33-byte compressed points), the
    /// outpoint, the fields (a strict count, bounded, unique 1-50 byte names),
    /// then the bytes remaining as a DER signature, kept as `toDER` writes it.
    pub fn read_wallet_certificate(&mut self) -> Result<WalletCertificate, Error> {
        super::result_validation::certificate_size(self.remaining())?;
        let certificate_type = to_base64(self.read_bytes(32)?);
        let serial_number = to_base64(self.read_bytes(32)?);
        let subject = self.read_compressed_key("certificate subject")?;
        let certifier = self.read_compressed_key("certificate certifier")?;
        let revocation_outpoint = self.read_outpoint_string()?;
        let fields = self.read_certificate_fields()?;
        let signature = self.read_certificate_signature()?;

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

    /// Reads an IdentityCertifier as a discovery entry carries it
    /// (`WalletWireTransceiver.ts:1704-1710` at `ts-stack@edf6e03`; go-sdk@2ca481c
    /// `wallet/serializer/identity_certificate.go:63-66`): name, iconUrl and
    /// description as plain varint-length strings, trust a byte. An empty
    /// iconUrl or description is `""`, as the transceiver reads it; a
    /// trust outside 1 to 10 is refused in the reference's words,
    /// `#requireInteger(readUInt8(), 'discovery trust', 1, 10)` (`:1710`,
    /// `:2018-2025`; bsv-rs#247), where go-sdk reads any byte (`:66`). The
    /// transceiver's discovery reader reads its certifier info here.
    pub fn read_identity_certifier(&mut self) -> Result<IdentityCertifier, Error> {
        Ok(IdentityCertifier {
            name: self.read_string()?,
            icon_url: self.read_string()?,
            description: self.read_string()?,
            trust: super::require_discovery_trust(self.read_u8()?)?,
        })
    }

    /// Reads a discovery entry's certifier info: no present flag, the reference
    /// having no absent case (the members are required, bsv-rs#105). Go's zero
    /// value, which go-sdk writes for an absent certifier info (empty strings,
    /// trust 0), is refused at its trust as the transceiver refuses it
    /// (bsv-rs#247).
    pub fn read_optional_identity_certifier(&mut self) -> Result<Option<IdentityCertifier>, Error> {
        self.read_identity_certifier().map(Some)
    }

    /// Reads an IdentityCertificate as `write_identity_certificate` writes it and
    /// the reference reads one discovery entry (`WalletWireTransceiver.ts:1702-1745`
    /// at `ts-stack@edf6e03`; go-sdk@2ca481c `identity_certificate.go:51-100`):
    /// the certificate behind a varint length, the certifier info, the public
    /// keyring as varint-length keys and raw-byte values (base64 in the struct),
    /// the decrypted fields as string pairs. Every member is present, as the
    /// reference's entry has it (an empty map empty, #105); a repeated key in
    /// either map is refused in the transceiver's words
    /// (`#setUniqueWireRecordEntry`, `:1992-2002`; bsv-rs#192). The maps are
    /// the transceiver's own reading (`read_discovery_maps`, bsv-rs#236): a
    /// strict count, at most 100,000 and no more than the bytes left
    /// (`:1711-1716`, `:1955-1969`), each key 1 to 50 bytes and not an unsafe
    /// name (`#readRecordKey`, `:1979-1990`), refused in its words.
    pub fn read_identity_certificate(&mut self) -> Result<IdentityCertificate, Error> {
        let cert_len = self.read_length()?;
        let certificate = WireReader::new(self.read_bytes(cert_len)?).read_wallet_certificate()?;
        let certifier_info = self.read_identity_certifier()?;
        let (publicly_revealed_keyring, decrypted_fields) = self.read_discovery_maps()?;

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
            let arr = self.read_insertion_tags()?;
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
        let output_index = self.read_var_int_u32("internalize output index")?;
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

    /// Reads a WalletActionInput (Go-compatible format).
    pub fn read_wallet_action_input(&mut self) -> Result<WalletActionInput, Error> {
        let source_outpoint = self.read_outpoint()?;
        let source_satoshis = self.read_satoshis("listActions input sourceSatoshis")?;
        let source_locking_script = self.read_optional_bytes()?;
        let unlocking_script = self.read_optional_bytes()?;
        let input_description = self.read_string()?;
        // Go uses VarInt for sequence_number (not u32_le)
        let sequence_number = self.read_var_int_u32("listActions input sequenceNumber")?;

        Ok(WalletActionInput {
            source_outpoint,
            source_satoshis,
            source_locking_script,
            unlocking_script,
            input_description,
            sequence_number,
        })
    }

    /// Reads a WalletActionOutput (Go-compatible field order).
    ///
    /// Go order: OutputIndex → Satoshis → LockingScript → Spendable
    ///          → OutputDescription → Basket → Tags → CustomInstructions
    pub fn read_wallet_action_output(&mut self) -> Result<WalletActionOutput, Error> {
        let output_index = self.read_var_int_u32("listActions output outputIndex")?;
        let satoshis = self.read_satoshis("listActions output satoshis")?;
        let locking_script = self.read_optional_bytes()?;
        let spendable = self.read_optional_bool()?.unwrap_or(false);
        let output_description = self.read_string()?;
        let basket = self.read_optional_string()?.unwrap_or_default();
        let tags = self.read_response_strings("listActions output tags")?;
        let custom_instructions = self.read_optional_string()?;

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

    /// Reads a WalletAction (Go-compatible format).
    ///
    /// Go format: txid(32 reversed) → satoshis(varint) → status(u8) → isOutgoing(optional bool)
    ///           → description(string) → labels(string slice) → version(varint) → lockTime(varint)
    ///           → inputs(varint count or MaxUint64) → outputs(varint count or MaxUint64)
    pub fn read_wallet_action(&mut self) -> Result<WalletAction, Error> {
        let txid_bytes = self.read_bytes(32)?;
        let mut txid = [0u8; 32];
        txid.copy_from_slice(txid_bytes);
        // The reference's signed net amount in its bound (bsv-rs#236)
        let satoshis = self.read_action_satoshis()?;
        let status = self
            .read_action_status()?
            .unwrap_or(ActionStatus::Unprocessed);
        let is_outgoing = self.read_optional_bool()?.unwrap_or(false);
        let description = self.read_string()?;
        let labels = {
            let arr = self.read_response_strings("listActions labels")?;
            if arr.is_empty() {
                None
            } else {
                Some(arr)
            }
        };
        // Go uses VarInt for version/lockTime (not u32_le)
        let version = self.read_var_int_u32("listActions version")?;
        let lock_time = self.read_var_int_u32("listActions lockTime")?;

        // Read optional inputs array (Go uses VarInt(MaxUint64) for nil)
        let inputs_count = self.read_response_count("listActions inputs", 100_000, 1)?;
        let inputs = if inputs_count == NIL_SENTINEL {
            None
        } else {
            let mut inputs =
                Vec::with_capacity(bounded_capacity(inputs_count as usize, self.remaining(), 1));
            for _ in 0..inputs_count {
                inputs.push(self.read_wallet_action_input()?);
            }
            Some(inputs)
        };

        // Read optional outputs array (Go uses VarInt(MaxUint64) for nil)
        let outputs_count = self.read_response_count("listActions outputs", 100_000, 1)?;
        let outputs = if outputs_count == NIL_SENTINEL {
            None
        } else {
            let mut outputs = Vec::with_capacity(bounded_capacity(
                outputs_count as usize,
                self.remaining(),
                1,
            ));
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

    /// Reads a WalletOutput (Go-compatible field order).
    ///
    /// Go order: Outpoint → Satoshis → LockingScript → CustomInstructions → Tags → Labels
    /// Note: Go WalletOutput does NOT have a `spendable` field. Defaults to true.
    pub fn read_wallet_output(&mut self) -> Result<WalletOutput, Error> {
        let outpoint = self.read_outpoint()?;
        let satoshis = self.read_satoshis("listOutputs satoshis")?;
        let locking_script = self.read_optional_bytes()?;
        let custom_instructions = self.read_optional_string()?;
        let tags = {
            let arr = self.read_response_strings("listOutputs tags")?;
            if arr.is_empty() {
                None
            } else {
                Some(arr)
            }
        };
        let labels = {
            let arr = self.read_response_strings("listOutputs labels")?;
            if arr.is_empty() {
                None
            } else {
                Some(arr)
            }
        };

        Ok(WalletOutput {
            satoshis,
            locking_script,
            spendable: true, // Go defaults to true; field not on wire
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

    /// Writes a signed varint: a non-negative value as the plain varint, `-1`
    /// (absent) as nine `0xFF`, as TS `writeVarIntNum` and Go
    /// `WriteNegativeOne` do (#149). Any other negative is refused, the
    /// field named: no reader of the wire keeps it.
    pub fn write_signed_var_int(&mut self, field: &str, val: i64) -> Result<&mut Self, Error> {
        if val < -1 {
            return Err(Error::WalletError(format!(
                "invalid {}: expected at least -1, got {}",
                field, val
            )));
        }
        Ok(self.write_var_int(u64::try_from(val).unwrap_or(u64::MAX)))
    }

    /// Writes an optional varint: `None` as nine `0xFF` (`-1`), `Some(v)` as
    /// the plain varint (`Some(u64::MAX)` is the same bytes as `None`).
    pub fn write_optional_var_int(&mut self, val: Option<u64>) -> &mut Self {
        self.write_var_int(val.unwrap_or(u64::MAX))
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

    /// Writes an optional string (Go-compatible: VarInt(MaxUint64) = null).
    ///
    /// Go uses `WriteOptionalString`: empty string → NegativeOne, non-empty → VarInt(len) + bytes.
    pub fn write_optional_string(&mut self, s: Option<&str>) -> &mut Self {
        match s {
            Some(s) if !s.is_empty() => {
                let bytes = s.as_bytes();
                self.write_var_int(bytes.len() as u64);
                self.write_bytes(bytes)
            }
            _ => self.write_var_int(NIL_SENTINEL),
        }
    }

    /// Writes optional bytes (Go-compatible: VarInt(MaxUint64) = null).
    pub fn write_optional_bytes(&mut self, data: Option<&[u8]>) -> &mut Self {
        match data {
            Some(data) if !data.is_empty() => {
                self.write_var_int(data.len() as u64);
                self.write_bytes(data)
            }
            _ => self.write_var_int(NIL_SENTINEL),
        }
    }

    /// Writes a string array: count, then plain length-prefixed entries.
    pub fn write_string_array(&mut self, strings: &[String]) -> &mut Self {
        self.write_var_int(strings.len() as u64);
        for s in strings {
            self.write_string(s);
        }
        self
    }

    /// Writes an optional string array (None becomes VarInt(MaxUint64)).
    pub fn write_optional_string_array(&mut self, strings: Option<&[String]>) -> &mut Self {
        match strings {
            Some(strings) => self.write_string_array(strings),
            None => self.write_var_int(NIL_SENTINEL),
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

    /// Writes a string to string map in its order, the reference's `Object.entries`
    /// (`WalletWireTransceiver.ts:1389`, `:1583`; #385; go-sdk sorts), VarInt count.
    pub fn write_string_map(&mut self, map: &IndexMap<String, String>) -> &mut Self {
        self.write_var_int(map.len() as u64);
        for (key, value) in map {
            self.write_string(key);
            self.write_string(value);
        }
        self
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

    /// Writes an optional array of SendWithResults (Go-compatible: VarInt(MaxUint64) for None).
    pub fn write_send_with_result_array(
        &mut self,
        results: Option<&[SendWithResult]>,
    ) -> &mut Self {
        match results {
            None => self.write_var_int(NIL_SENTINEL),
            Some(results) => {
                self.write_var_int(results.len() as u64);
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

    /// Writes a map of u32 to SignActionSpend (Go-compatible: VarInt count).
    pub fn write_sign_action_spends(
        &mut self,
        spends: &HashMap<u32, SignActionSpend>,
    ) -> &mut Self {
        self.write_var_int(spends.len() as u64);
        for (index, spend) in spends {
            self.write_var_int(*index as u64);
            self.write_sign_action_spend(spend);
        }
        self
    }

    /// Writes a WalletCertificate as `Certificate.toBinary` writes it
    /// (`ts-stack@edf6e03` `Certificate.ts:229-321`; go-sdk@2ca481c
    /// `wallet/serializer/certificate.go:27-66`): type(32), serial(32),
    /// subject(33), certifier(33), the outpoint, the fields (in the signed
    /// order, `localeCompare`'s, `:282`; bsv-rs#246), then the signature's
    /// bytes with no length prefix. What the reference's writer
    /// refuses is refused before a byte is written, in the readers' words
    /// (bsv-rs#189): a subject or certifier that is not a compressed point
    /// (`:241-253`), a field name outside 1 to 50 bytes or unsafe (`:289`), a
    /// signature that is not DER (`:300-312`); the DER it accepts is written as
    /// given (`:311`). Since bsv-rs#246 the reference's three bounds too: more
    /// than 100,000 fields (`:57-58`), a value over 1 MiB (`:76-79`), a frame
    /// over 16 MiB (`:315-319`).
    pub fn write_wallet_certificate(
        &mut self,
        cert: &WalletCertificate,
    ) -> Result<&mut Self, Error> {
        let bytes = certificate_bytes(cert)?;
        Ok(self.write_bytes(&bytes))
    }

    /// Writes an optional WalletCertificate: no present flag for one the
    /// certificate writer refuses.
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
                let bytes = certificate_bytes(cert)?;
                self.write_i8(1);
                Ok(self.write_bytes(&bytes))
            }
        }
    }

    /// Writes an IdentityCertificate as one discovery entry
    /// (`WalletWireProcessor.ts:2478-2558` at `ts-stack@edf6e03`; go-sdk@2ca481c
    /// `wallet/serializer/identity_certificate.go:12-49`): the certificate behind
    /// a varint length, certifierInfo's name, iconUrl and description as plain
    /// strings and trust a byte, the public keyring's values as raw bytes, the
    /// decrypted fields as strings. Every member is required by the type (#105).
    pub fn write_identity_certificate(
        &mut self,
        cert: &IdentityCertificate,
    ) -> Result<&mut Self, Error> {
        // The reference's reader refuses a trust outside 1 to 10 (bsv-rs#183):
        // no frame is written that it refuses.
        let info = &cert.certifier_info;
        super::require_discovery_trust(info.trust)?;
        let mut cert_writer = WireWriter::new();
        cert_writer.write_wallet_certificate(&cert.certificate)?;
        let cert_bytes = cert_writer.into_bytes();
        self.write_var_int(cert_bytes.len() as u64);
        self.write_bytes(&cert_bytes);

        self.write_string(&info.name);
        self.write_string(&info.icon_url);
        self.write_string(&info.description);
        self.write_u8(info.trust);

        // In its order, the reference's `#recordEntries` (`WalletWireProcessor.ts:2523`, #385)
        let keyring = &cert.publicly_revealed_keyring;
        self.write_var_int(keyring.len() as u64);
        for (key, value) in keyring {
            let value = from_base64(value)
                .map_err(|e| Error::WalletError(format!("invalid keyring value base64: {}", e)))?;
            self.write_string(key);
            self.write_var_int(value.len() as u64);
            self.write_bytes(&value);
        }
        self.write_string_map(&cert.decrypted_fields);
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

    /// Writes a WalletActionInput (Go-compatible: VarInt for sequence_number).
    pub fn write_wallet_action_input(&mut self, input: &WalletActionInput) -> &mut Self {
        self.write_outpoint(&input.source_outpoint);
        self.write_var_int(input.source_satoshis);
        self.write_optional_bytes(input.source_locking_script.as_deref());
        self.write_optional_bytes(input.unlocking_script.as_deref());
        self.write_string(&input.input_description);
        // Go uses VarInt for sequence_number (not u32_le)
        self.write_var_int(input.sequence_number as u64)
    }

    /// Writes a WalletActionOutput (Go-compatible field order).
    ///
    /// Go order: OutputIndex → Satoshis → LockingScript → Spendable
    ///          → OutputDescription → Basket → Tags → CustomInstructions
    pub fn write_wallet_action_output(&mut self, output: &WalletActionOutput) -> &mut Self {
        self.write_var_int(output.output_index as u64);
        self.write_var_int(output.satoshis);
        self.write_optional_bytes(output.locking_script.as_deref());
        self.write_optional_bool(Some(output.spendable));
        self.write_string(&output.output_description);
        self.write_string(&output.basket);
        self.write_string_array(&output.tags);
        self.write_optional_string(output.custom_instructions.as_deref())
    }

    /// Writes a WalletAction (Go-compatible format).
    ///
    /// Go format: txid(32) → satoshis(varint) → status(u8) → isOutgoing(optional bool)
    ///           → description(string) → labels(string slice) → version(varint) → lockTime(varint)
    ///           → inputs(varint count or MaxUint64) → outputs(varint count or MaxUint64)
    pub fn write_wallet_action(&mut self, action: &WalletAction) -> &mut Self {
        self.write_bytes(&action.txid);
        // Go uses unsigned VarInt for satoshis
        self.write_var_int(action.satoshis as u64);
        self.write_action_status(Some(action.status));
        self.write_optional_bool(Some(action.is_outgoing));
        self.write_string(&action.description);
        let labels = action.labels.as_deref().unwrap_or(&[]);
        self.write_string_array(labels);
        // Go uses VarInt for version/lockTime (not u32_le)
        self.write_var_int(action.version as u64);
        self.write_var_int(action.lock_time as u64);

        // Write optional inputs array (Go uses VarInt(MaxUint64) for nil)
        match &action.inputs {
            None => {
                self.write_var_int(NIL_SENTINEL);
            }
            Some(inputs) => {
                self.write_var_int(inputs.len() as u64);
                for input in inputs {
                    self.write_wallet_action_input(input);
                }
            }
        }

        // Write optional outputs array (Go uses VarInt(MaxUint64) for nil)
        match &action.outputs {
            None => {
                self.write_var_int(NIL_SENTINEL);
            }
            Some(outputs) => {
                self.write_var_int(outputs.len() as u64);
                for output in outputs {
                    self.write_wallet_action_output(output);
                }
            }
        }

        self
    }

    /// Writes a WalletOutput (Go-compatible field order).
    ///
    /// Go order: Outpoint → Satoshis → LockingScript → CustomInstructions → Tags → Labels
    /// Note: Go WalletOutput does NOT write a `spendable` field.
    pub fn write_wallet_output(&mut self, output: &WalletOutput) -> &mut Self {
        self.write_outpoint(&output.outpoint);
        self.write_var_int(output.satoshis);
        self.write_optional_bytes(output.locking_script.as_deref());
        self.write_optional_string(output.custom_instructions.as_deref());
        let tags = output.tags.as_deref().unwrap_or(&[]);
        self.write_string_array(tags);
        let labels = output.labels.as_deref().unwrap_or(&[]);
        self.write_string_array(labels)
    }
}

impl Default for WireWriter {
    fn default() -> Self {
        Self::new()
    }
}

/// The certificate's bytes, every part checked before the frame is built, so
/// a refusal leaves the caller's writer as it was.
fn certificate_bytes(cert: &WalletCertificate) -> Result<Vec<u8>, Error> {
    let mut w = WireWriter::new();

    // Type and serial: each decoded from base64, 32 raw bytes
    w.write_bytes(&decoded_32_bytes(
        &cert.certificate_type,
        "certificate_type",
    )?);
    w.write_bytes(&decoded_32_bytes(&cert.serial_number, "serial_number")?);

    // Subject and certifier: 33-byte compressed points from hex
    for (hex, what) in [
        (&cert.subject, "certificate subject"),
        (&cert.certifier, "certificate certifier"),
    ] {
        let key = from_hex(hex).map_err(|_| {
            Error::WalletError(format!(
                "Invalid {what}: expected a compressed secp256k1 public key"
            ))
        })?;
        super::require_compressed_key(&key, what)?;
        w.write_bytes(&key);
    }

    // Revocation outpoint
    w.write_outpoint_string(&cert.revocation_outpoint)?;

    // Fields, checked and in the order the signature is made over,
    // `localeCompare`'s (`Certificate.ts:282`), not the bytes: a byte-ordered
    // frame of a certificate signed here does not verify over the bytes
    // received (#246)
    let names = checked_field_names(&cert.fields)?;
    w.write_var_int(names.len() as u64);
    for name in names {
        w.write_string(name);
        w.write_string(&cert.fields[name]);
    }

    // Signature: raw bytes, no length prefix (the bytes remaining)
    let sig_bytes = from_hex(&cert.signature)?;
    if !sig_bytes.is_empty() {
        super::certificate_signature_der(&sig_bytes)?;
    }
    w.write_bytes(&sig_bytes);

    // The frame: at most 16 MiB (`Certificate.ts:315-319`), in the
    // reference writer's words (the reader's are `snapshotCertificateBinary`'s)
    if w.as_bytes().len() > super::MAX_CERTIFICATE_BINARY_BYTES {
        return Err(super::refused(super::certificate_binary_written_refusal()));
    }

    Ok(w.into_bytes())
}

/// A certificate type or serial number: base64 text decoding to 32 bytes,
/// refused in the words the writer always used.
fn decoded_32_bytes(text: &str, what: &str) -> Result<Vec<u8>, Error> {
    let bytes = from_base64(text)
        .map_err(|e| Error::WalletError(format!("invalid {what} base64: {}", e)))?;
    if bytes.len() != 32 {
        return Err(Error::WalletError(format!(
            "{what} must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

/// The field names in the signed order, every bound checked first in the map's
/// order, as `snapshotCertificateFields` walks `Reflect.ownKeys` before `toBinary`
/// sorts (`Certificate.ts:56-83`, `:281-282`): at most 100,000 fields, each name
/// 1 to 50 bytes and safe, each value at most 1 MiB, in the readers' words (#246, #385).
fn checked_field_names(fields: &IndexMap<String, String>) -> Result<Vec<&str>, Error> {
    if fields.len() > super::MAX_CERTIFICATE_FIELDS {
        return Err(super::refused(format!(
            "Certificate field count exceeds the maximum of {}",
            super::MAX_CERTIFICATE_FIELDS
        )));
    }
    for (name, value) in fields {
        super::require_certificate_field_name_length(name.len())?;
        super::require_safe_certificate_field_name(name)?;
        if value.len() > super::MAX_CERTIFICATE_FIELD_VALUE_BYTES {
            return Err(super::refused(super::certificate_field_value_refusal(name)));
        }
    }
    let mut names: Vec<&str> = fields.keys().map(String::as_str).collect();
    crate::wallet::collation::sort_field_names(&mut names);
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::PrivateKey;

    #[test]
    fn test_signed_var_int_roundtrip() {
        for val in [0, 1, -1, 127, 128, 252, 253, 1000, i64::MAX] {
            let mut writer = WireWriter::new();
            writer.write_signed_var_int("v", val).unwrap();
            let mut reader = WireReader::new(writer.as_bytes());
            assert_eq!(reader.read_signed_var_int().unwrap(), val);
        }
        for val in [-2, i64::MIN] {
            assert!(WireWriter::new().write_signed_var_int("v", val).is_err());
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

    #[test]
    fn string_array_with_an_empty_entry_roundtrips() {
        let strings = vec![String::new(), "a".to_string()];
        let mut writer = WireWriter::new();
        writer.write_string_array(&strings);

        let mut reader = WireReader::new(writer.as_bytes());
        assert_eq!(reader.read_string_array(), Ok(strings));
        assert!(reader.is_empty());
        assert_eq!(writer.as_bytes(), b"\x02\x00\x01a");
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

        // Empty bytes - Go treats empty same as nil (both write NIL_SENTINEL)
        let mut writer = WireWriter::new();
        writer.write_optional_bytes(Some(&[]));
        let mut reader = WireReader::new(writer.as_bytes());
        assert_eq!(reader.read_optional_bytes().unwrap(), None);
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
        let mut map = IndexMap::new();
        map.insert("key1".to_string(), "value1".to_string());
        map.insert("key2".to_string(), "value2".to_string());
        map.insert("key3".to_string(), "value3".to_string());

        let mut writer = WireWriter::new();
        writer.write_string_map(&map);
        let mut reader = WireReader::new(writer.as_bytes());
        assert_eq!(reader.read_string_map().unwrap(), map);

        // Empty map
        let empty_map = IndexMap::new();
        let mut writer = WireWriter::new();
        writer.write_string_map(&empty_map);
        let mut reader = WireReader::new(writer.as_bytes());
        assert_eq!(reader.read_string_map().unwrap(), empty_map);
    }

    #[test]
    fn test_optional_string_map_roundtrip() {
        // Some map: a count and its pairs
        let mut map = IndexMap::new();
        map.insert("a".to_string(), "b".to_string());

        let mut writer = WireWriter::new();
        writer.write_string_map(&map);
        let mut reader = WireReader::new(writer.as_bytes());
        assert_eq!(reader.read_optional_string_map().unwrap(), Some(map));

        // None: the NIL sentinel
        let mut writer = WireWriter::new();
        writer.write_var_int(NIL_SENTINEL);
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
        let mut fields = IndexMap::new();
        fields.insert("name".to_string(), "encrypted_value_1".to_string());
        fields.insert("email".to_string(), "encrypted_value_2".to_string());

        // Type and serial must be valid base64-encoded 32-byte values (Go format)
        let type_bytes = [0xaa; 32];
        let serial_bytes = [0xbb; 32];

        WalletCertificate {
            certificate_type: crate::primitives::to_base64(&type_bytes),
            subject: pubkey.to_hex(),
            serial_number: crate::primitives::to_base64(&serial_bytes),
            certifier: certifier.to_hex(),
            revocation_outpoint: format!("{}.0", crate::primitives::to_hex(&[0xcc; 32])),
            signature: "3006020101020101".to_string(),
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

        // Minimal output (spendable not on wire, defaults to true on read)
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
        // Go wire format has no spendable field; defaults to true on read
        assert!(read.spendable);
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
        writer.write_signed_var_int("v", 100).unwrap();
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
        assert_eq!(reader.read_signed_var_int().unwrap(), 100);
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
        let empty_map: IndexMap<String, String> = IndexMap::new();
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
