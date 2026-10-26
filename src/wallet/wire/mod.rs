//! WalletWire binary protocol for efficient wallet communication.
//!
//! This module implements the WalletWire protocol, which provides efficient binary
//! serialization for wallet operations. The protocol is designed to be binary-compatible
//! with the TypeScript and Go BSV SDK implementations.
//!
//! # Architecture
//!
//! The protocol uses a client-server model:
//!
//! - **[`WalletWireTransceiver`]** (client): Serializes method calls into binary messages
//!   and deserializes responses. Implements the wallet interface trait.
//!
//! - **[`WalletWire`]** (transport): Abstract trait for binary message transmission.
//!   Can be implemented over HTTP, WebSocket, IPC, etc.
//!
//! - **[`WalletWireProcessor`]** (server): Deserializes incoming messages and dispatches
//!   to the appropriate wallet method. Returns serialized responses.
//!
//! # Wire Format
//!
//! ## Request Frame
//!
//! ```text
//! ┌─────────┬──────────────┬────────────┬────────────────┐
//! │ Call    │ Originator   │ Originator │ Serialized     │
//! │ Code    │ Length       │ String     │ Parameters     │
//! │ (1 byte)│ (1 byte)     │ (N bytes)  │ (variable)     │
//! └─────────┴──────────────┴────────────┴────────────────┘
//! ```
//!
//! ## Response Frame
//!
//! ```text
//! ┌─────────┬────────────────────────────────────────────┐
//! │ Error   │ Result Data (if success) or Error Message  │
//! │ (1 byte)│ (variable length)                          │
//! └─────────┴────────────────────────────────────────────┘
//! ```
//!
//! # Serialization Rules
//!
//! | Type | Encoding |
//! |------|----------|
//! | Strings | VarInt length + UTF-8 bytes |
//! | Optional values | -1 (signed VarInt) for null/undefined |
//! | Booleans | Int8 (1 = true, 0 = false, -1 = undefined) |
//! | Binary data | VarInt length + raw bytes |
//! | Outpoints | 32-byte TXID + VarInt index |
//! | Public keys | 33 bytes (compressed) |
//! | Counterparty | 0 = undefined, 11 = 'self', 12 = 'anyone', else 33-byte pubkey |
//!
//! # Example
//!
//! ```rust,ignore
//! use bsv_rs::wallet::wire::{WalletWire, WalletWireTransceiver};
//!
//! // Implement transport
//! struct HttpWire { /* ... */ }
//!
//! impl WalletWire for HttpWire {
//!     async fn transmit_to_wallet(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
//!         // Send message over HTTP and return response
//!     }
//! }
//!
//! // Create transceiver
//! let wire = HttpWire::new("https://wallet.example.com");
//! let wallet = WalletWireTransceiver::new(wire);
//!
//! // Use wallet methods
//! let result = wallet.get_public_key(args, "originator").await?;
//! ```

mod calls;
mod encoding;
mod processor;
mod requests;
mod results;
mod transceiver;
mod validation;

pub use calls::WalletCall;
pub use encoding::{WireReader, WireWriter};
pub use processor::WalletWireProcessor;
pub use transceiver::WalletWireTransceiver;

use crate::primitives::PublicKey;
use crate::wallet::types::{Counterparty, Protocol};
use crate::Error;
use std::collections::HashMap;

// The u32 field readers live here, not in encoding.rs: that file is held at
// its recorded line limit by the ratchet (docs/RATCHETS.md).
impl WireReader<'_> {
    /// Reads an unsigned varint carrying a `u32` field: an output or input
    /// index, a sequence number, a version, a lock time, a height, a total.
    ///
    /// Each is a `u32` by the transaction format or by BRC-100's
    /// `PositiveIntegerOrZero` (at most `2^32 - 1`), so a value above
    /// `u32::MAX` is refused with the field named, never truncated.
    pub(crate) fn read_var_int_u32(&mut self, field: &str) -> Result<u32, Error> {
        let value = self.read_var_int()?;
        var_int_u32(field, value)
    }

    /// Reads an optional signed varint (`-1` for absent) carrying a `u32`
    /// field, refused above `u32::MAX` as [`Self::read_var_int_u32`] is.
    pub(crate) fn read_optional_var_int_u32(&mut self, field: &str) -> Result<Option<u32>, Error> {
        self.read_optional_var_int()?
            .map(|value| var_int_u32(field, value))
            .transpose()
    }
}

fn var_int_u32(field: &str, value: u64) -> Result<u32, Error> {
    u32::try_from(value).map_err(|_| {
        Error::WalletError(format!(
            "invalid {}: expected at most {}, got {}",
            field,
            u32::MAX,
            value
        ))
    })
}

// The reference's readers of a certificate and its records (bsv-rs#183):
// `Certificate.fromBinary` (`ts-stack@edf6e03` `Certificate.ts:329-408`) and
// the transceiver's record readers (`WalletWireTransceiver.ts:1955-2008`),
// each refusal in the reference's words.

/// `Certificate.ts:25-28`, `WalletWireTransceiver.ts:67`.
const MAX_CERTIFICATE_BINARY_BYTES: usize = 16 * 1024 * 1024;
const MAX_CERTIFICATE_FIELDS: usize = 100_000;
const MAX_CERTIFICATE_FIELD_VALUE_BYTES: usize = 1024 * 1024;
const MAX_CERTIFICATE_SIGNATURE_BYTES: usize = 72;
const MAX_WIRE_RESPONSE_COLLECTION_ITEMS: usize = 100_000;
/// `Number.MAX_SAFE_INTEGER`, the strict varint reader's bound.
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// A wire record: a key to its value.
type Record = HashMap<String, String>;

fn refused(words: impl Into<String>) -> Error {
    Error::WalletError(words.into())
}

impl WireReader<'_> {
    /// `readVarIntNumStrict(false)` (`readVarIntNumStrict.ts`): a canonical
    /// varint, refused past `2^53 - 1` (nine 0xFF included: no NIL sentinel).
    pub(crate) fn read_var_int_num_strict(&mut self) -> Result<usize, Error> {
        let value = self.read_var_int()?;
        if value > MAX_SAFE_INTEGER {
            return Err(refused(
                "number too large to retain precision - use readVarIntBn",
            ));
        }
        usize::try_from(value).map_err(|_| refused("Wallet Wire count exceeds the platform"))
    }

    /// `readVarIntNumStrict(false)` as a byte length: the strict bound, then
    /// the bytes remaining before it is narrowed (`wire_length`, bsv-rs#192).
    fn read_strict_length(&mut self) -> Result<usize, Error> {
        let value = self.read_var_int()?;
        if value > MAX_SAFE_INTEGER {
            return Err(refused(
                "number too large to retain precision - use readVarIntBn",
            ));
        }
        self.wire_length(value)
    }

    /// A count, then `#requireResponseCollectionLength` (`:1955-1969`) with a
    /// byte per item.
    pub(crate) fn read_collection_count(&mut self, name: &str) -> Result<usize, Error> {
        let count = self.read_var_int_num_strict()?;
        if count > MAX_WIRE_RESPONSE_COLLECTION_ITEMS {
            return Err(refused(format!(
                "Wallet Wire {name} exceeds the maximum collection size of {MAX_WIRE_RESPONSE_COLLECTION_ITEMS}"
            )));
        }
        if count > self.remaining() {
            return Err(refused(format!(
                "Wallet Wire {name} count exceeds the remaining response data"
            )));
        }
        Ok(count)
    }

    /// `#readBooleanFlag` (`:1971-1977`).
    pub(crate) fn read_boolean_flag(&mut self, name: &str) -> Result<bool, Error> {
        match self.read_i8()? {
            0 => Ok(false),
            1 => Ok(true),
            flag => Err(refused(format!(
                "Invalid {name} flag: expected 0 or 1, received {flag}"
            ))),
        }
    }

    /// 33 bytes that decompress to a point, as hex (`assertCompressedPublicKey`,
    /// `Certificate.ts:135-142`; `#readCompressedPublicKey`, `:2004-2008`).
    pub(crate) fn read_compressed_key(&mut self, what: &str) -> Result<String, Error> {
        let bytes = self.read_bytes(33)?;
        if !matches!(bytes[0], 0x02 | 0x03) || PublicKey::from_bytes(bytes).is_err() {
            return Err(refused(format!(
                "Invalid {what}: expected a compressed secp256k1 public key"
            )));
        }
        Ok(crate::primitives::to_hex(bytes))
    }

    /// A counted record, the one reading of the transceiver's records and
    /// `read_identity_certificate`'s maps (bsv-rs#236): the count
    /// (`read_collection_count`), then its entries (`read_wire_record`).
    pub(crate) fn read_counted_wire_record(
        &mut self,
        name: &str,
        value: impl FnMut(&mut Self) -> Result<String, Error>,
    ) -> Result<HashMap<String, String>, Error> {
        let count = self.read_collection_count(name)?;
        self.read_wire_record(name, count, value)
    }

    /// A discovery entry's two maps (`WalletWireTransceiver.ts:1711-1752`), read
    /// by the transceiver's discovery reader and `read_identity_certificate`
    /// alike (bsv-rs#236): the public keyring's values raw bytes as base64, the
    /// decrypted fields' values UTF-8; an empty map `None`.
    pub(crate) fn read_discovery_maps(
        &mut self,
    ) -> Result<(Option<Record>, Option<Record>), Error> {
        let keyring =
            self.read_counted_wire_record("discovery public keyring", Self::read_base64_value)?;
        let fields =
            self.read_counted_wire_record("discovery decrypted fields", Self::read_utf8_value)?;
        Ok((
            Some(keyring).filter(|m| !m.is_empty()),
            Some(fields).filter(|m| !m.is_empty()),
        ))
    }

    /// A record of `count` entries (`#readRecordKey`, `:1979-1990`;
    /// `#setUniqueWireRecordEntry`, `:1992-2002`), each value read by `value`.
    fn read_wire_record(
        &mut self,
        name: &str,
        count: usize,
        mut value: impl FnMut(&mut Self) -> Result<String, Error>,
    ) -> Result<HashMap<String, String>, Error> {
        let mut record = HashMap::with_capacity(count);
        for _ in 0..count {
            let length = self.read_var_int_num_strict()?;
            if !(1..=50).contains(&length) {
                return Err(refused(format!(
                    "Invalid {name} key length: expected 1\u{2013}50 bytes, received {length}"
                )));
            }
            let key = utf8(self.read_bytes(length)?)?;
            if is_unsafe_record_key(&key) {
                return Err(refused(format!("Unsafe {name} key: {key}")));
            }
            let entry = value(self)?;
            set_unique_record_entry(&mut record, name, key, entry)?;
        }
        Ok(record)
    }

    /// A varint-length value as UTF-8 (`toUTF8Strict`).
    pub(crate) fn read_utf8_value(&mut self) -> Result<String, Error> {
        let length = self.read_strict_length()?;
        utf8(self.read_bytes(length)?)
    }

    /// A varint-length value as the base64 of its bytes.
    pub(crate) fn read_base64_value(&mut self) -> Result<String, Error> {
        let length = self.read_strict_length()?;
        Ok(crate::primitives::to_base64(self.read_bytes(length)?))
    }

    /// The certificate's fields (`Certificate.ts:356-387`).
    pub(crate) fn read_certificate_fields(&mut self) -> Result<HashMap<String, String>, Error> {
        if self.remaining() > MAX_CERTIFICATE_BINARY_BYTES {
            return Err(refused(format!(
                "Certificate binary must be a byte array of at most {MAX_CERTIFICATE_BINARY_BYTES} bytes"
            )));
        }
        let count = self.read_var_int_num_strict()?;
        if count > MAX_CERTIFICATE_FIELDS {
            return Err(refused(format!(
                "Certificate field count exceeds the maximum of {MAX_CERTIFICATE_FIELDS}"
            )));
        }
        if count > self.remaining() / 3 {
            return Err(refused(
                "Certificate field count exceeds the available data",
            ));
        }
        let mut fields = HashMap::with_capacity(count);
        for _ in 0..count {
            let length = self.read_var_int_num_strict()?;
            if !(1..=50).contains(&length) {
                return Err(refused(format!(
                    "Invalid certificate field name length: received {length}"
                )));
            }
            let name = utf8(self.read_bytes(length)?)?;
            if is_unsafe_record_key(&name) {
                return Err(refused(format!("Unsafe certificate field name: {name}")));
            }
            if fields.contains_key(&name) {
                return Err(refused(format!("Duplicate certificate field name: {name}")));
            }
            let length = self.read_var_int_num_strict()?;
            if length > MAX_CERTIFICATE_FIELD_VALUE_BYTES {
                return Err(refused(format!(
                    "Certificate field {name} exceeds the maximum of {MAX_CERTIFICATE_FIELD_VALUE_BYTES} bytes"
                )));
            }
            let value = utf8(self.read_bytes(length)?)?;
            fields.insert(name, value);
        }
        Ok(fields)
    }

    /// The bytes remaining as the certificate's signature (`Certificate.ts:390-397`):
    /// at most 72, parsed by `Signature.fromDER` and kept as `toDER` writes it.
    pub(crate) fn read_certificate_signature(&mut self) -> Result<String, Error> {
        let bytes = self.read_remaining();
        if bytes.is_empty() {
            return Ok(String::new());
        }
        if bytes.len() > MAX_CERTIFICATE_SIGNATURE_BYTES {
            return Err(refused("Certificate signature exceeds the DER size limit"));
        }
        reference_der(bytes).map(|der| crate::primitives::to_hex(&der))
    }
}

/// `#setUniqueWireRecordEntry` (`:1992-2002`): a repeated key refused, never
/// kept over the earlier one.
fn set_unique_record_entry(
    record: &mut HashMap<String, String>,
    name: &str,
    key: String,
    value: String,
) -> Result<(), Error> {
    if record.contains_key(&key) {
        return Err(refused(format!("Duplicate {name} key: {key}")));
    }
    record.insert(key, value);
    Ok(())
}

/// `isUnsafeRecordKey` (`SafeRecord.ts`).
fn is_unsafe_record_key(key: &str) -> bool {
    matches!(key, "__proto__" | "constructor" | "prototype")
}

fn utf8(bytes: &[u8]) -> Result<String, Error> {
    String::from_utf8(bytes.to_vec()).map_err(|e| refused(format!("invalid UTF-8: {e}")))
}

/// `Signature.fromDER` (`Signature.ts:44-97`) then `toDER` (`:201-250`): the
/// reference's checks, in its order and words, and its re-encoding (an
/// integer minimal, a zero byte before a high bit).
fn reference_der(der: &[u8]) -> Result<Vec<u8>, Error> {
    let invalid = || refused("Signature DER invalid");
    // `getLength`: a short-form length; a missing byte fails the next check.
    let length = |at: usize| match der.get(at) {
        Some(b) if b & 0x80 == 0 => Ok(*b as usize),
        Some(_) => Err(refused("Invalid DER entity length")),
        None => Err(invalid()),
    };
    if der.first() != Some(&0x30) {
        return Err(refused("Signature DER must start with 0x30"));
    }
    if length(1)? + 2 != der.len() || der.get(2) != Some(&0x02) {
        return Err(invalid());
    }
    let r_end = 4 + length(3)?;
    if der.get(r_end) != Some(&0x02) {
        return Err(invalid());
    }
    let s_len = length(r_end + 1)?;
    if der.len() != r_end + 2 + s_len {
        return Err(refused("Invalid R-length in signature DER"));
    }
    // `toDER` (`Signature.ts:225-239`): R is written through `toArray`, which
    // gives a zero one byte `00`; S's leading zeros are dropped by a trailing
    // `while` loop that leaves a zero S empty, `02 00`.
    let integer = |bytes: &[u8], which: &str, zero_is_empty: bool| -> Result<Vec<u8>, Error> {
        if bytes.first() == Some(&0) && bytes.get(1).map_or(0, |b| b & 0x80) == 0 {
            return Err(refused(format!("Invalid {which}-value in signature DER")));
        }
        let start = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
        let mut minimal = bytes[start..].to_vec();
        if minimal.is_empty() && zero_is_empty {
            return Ok(minimal);
        }
        if minimal.first().is_none_or(|b| b & 0x80 != 0) {
            minimal.insert(0, 0);
        }
        Ok(minimal)
    };
    let r = integer(&der[4..r_end], "R", false)?;
    let s = integer(&der[r_end + 2..], "S", true)?;
    let mut out = vec![0x30, (4 + r.len() + s.len()) as u8, 0x02, r.len() as u8];
    out.extend_from_slice(&r);
    out.extend_from_slice(&[0x02, s.len() as u8]);
    out.extend_from_slice(&s);
    Ok(out)
}

/// `#requireResponseLength` (`WalletWireTransceiver.ts:2027-2031`).
pub(crate) fn require_response_length(
    result: &[u8],
    length: usize,
    call: &str,
) -> Result<(), Error> {
    if result.len() != length {
        return Err(refused(format!(
            "Wallet Wire {call} response has an invalid length"
        )));
    }
    Ok(())
}

/// `#requirePageCapacity` (`WalletWireTransceiver.ts:1948-1953`), called
/// before each listCertificates or discovery entry is read (`:1509`,
/// `:1700`): `returned` entries already read may not reach the requested
/// limit, 10 when none was requested (bsv-rs#190).
pub(crate) fn require_page_capacity(
    returned: usize,
    requested_limit: Option<u32>,
    call: &str,
) -> Result<(), Error> {
    let maximum = requested_limit.unwrap_or(10);
    if returned >= maximum as usize {
        return Err(refused(format!(
            "Wallet Wire {call} response exceeds the requested page limit of {maximum}"
        )));
    }
    Ok(())
}

/// `#assertPageCount` (`WalletWireTransceiver.ts:1940-1946`), after the page
/// is read (`:1550`, `:1759`): no more entries than the declared total, the
/// total of every page (bsv-rs#190).
pub(crate) fn assert_page_count(returned: usize, total: u32, call: &str) -> Result<(), Error> {
    if returned > total as usize {
        return Err(refused(format!(
            "Wallet Wire {call} response returned {returned} records but declared a total of {total}"
        )));
    }
    Ok(())
}

/// The processor's getHeaderForHeight result: the wallet's header as its 80
/// bytes, another length refused as `validateWalletResult` refuses it
/// (`WalletResultValidation.ts:2296-2297`, `hex(result.header, call, 'header', 80)`).
pub(crate) fn header_result(header: &str) -> Result<Vec<u8>, Error> {
    let bytes = crate::primitives::from_hex(header)?;
    if bytes.len() != 80 {
        return Err(refused(
            "Invalid getHeaderForHeight result header: expected 80 hexadecimal bytes",
        ));
    }
    Ok(bytes)
}

/// `#requireInteger(value, 'discovery trust', 1, 10)` (`WalletWireTransceiver.ts:1710`,
/// `:2018-2025`), the reader's check and the writer's.
pub(crate) fn require_discovery_trust(trust: u8) -> Result<u8, Error> {
    if !(1..=10).contains(&trust) {
        return Err(refused(format!(
            "Invalid discovery trust: expected an integer from 1 to 10, received {trust}"
        )));
    }
    Ok(trust)
}

/// The signature calls' data or hash (bsv-rs#199): the data-type flag `1`
/// then the data behind its varint length, or `2` then the 32 bytes of the
/// hash (`WalletWireTransceiver.ts:1082-1090` createSignature, `:1137-1144`
/// verifySignature; BRC-100 `wallet/0100.md:2191-2193`, `:2217-2219` at
/// `5119a9b`). Exactly one of the two is given, as `validateWalletArgs`
/// refuses otherwise before the reference writes (`validationHelpers.ts:1777-1787`).
pub(crate) fn write_data_or_hash(
    writer: &mut WireWriter,
    hash_field: &str,
    data: Option<&[u8]>,
    hash: Option<&[u8; 32]>,
) -> Result<(), Error> {
    match (data, hash) {
        (Some(data), None) => {
            writer.write_u8(1);
            writer.write_var_int(data.len() as u64);
            writer.write_bytes(data);
        }
        (None, Some(hash)) => {
            writer.write_u8(2);
            writer.write_bytes(hash);
        }
        _ => {
            return Err(refused(format!(
                "The data, {hash_field} parameter must be exactly one value"
            )))
        }
    }
    Ok(())
}

/// The privileged flag and reason (`#encodePrivilegedParams`,
/// `WalletWireTransceiver.ts:1448-1462` at `ts-stack@edf6e03`): the flag an
/// `i8` (-1 absent), the reason's length an `i8` (-1 absent) and its UTF-8
/// bytes; a reason past 127 bytes, which the frame cannot carry, is refused
/// before a byte is written (#193).
pub(crate) fn write_privileged_params(
    writer: &mut WireWriter,
    privileged: Option<bool>,
    reason: Option<&str>,
) -> Result<(), Error> {
    writer.write_optional_bool(privileged);
    match reason.map(str::as_bytes) {
        None => {
            writer.write_i8(-1);
        }
        Some(bytes) => {
            let length = i8::try_from(bytes.len()).map_err(|_| {
                refused(format!(
                    "Invalid privilegedReason length: expected 0 to 127 bytes, got {}",
                    bytes.len()
                ))
            })?;
            writer.write_i8(length);
            writer.write_bytes(bytes);
        }
    }
    Ok(())
}

/// The key-related parameters (`#encodeKeyRelatedParams`,
/// `WalletWireTransceiver.ts:1351-1376`): the protocol, the key ID, the
/// counterparty, then the privileged flag and reason (#193).
pub(crate) fn write_key_related_params(
    writer: &mut WireWriter,
    protocol: &Protocol,
    key_id: &str,
    counterparty: Option<&Counterparty>,
    privileged: Option<bool>,
    reason: Option<&str>,
) -> Result<(), Error> {
    writer.write_protocol_id(protocol);
    writer.write_string(key_id);
    writer.write_counterparty(counterparty);
    write_privileged_params(writer, privileged, reason)
}

/// Transport abstraction for wallet wire protocol.
///
/// Implementations of this trait handle the actual transmission of binary
/// messages to and from the wallet. This could be HTTP, WebSocket, IPC,
/// or any other transport mechanism.
///
/// # Example
///
/// ```rust,ignore
/// use bsv_rs::wallet::wire::WalletWire;
///
/// struct WebSocketWire {
///     url: String,
/// }
///
/// #[async_trait::async_trait]
/// impl WalletWire for WebSocketWire {
///     async fn transmit_to_wallet(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
///         // Send over WebSocket and receive response
///     }
/// }
/// ```
#[async_trait::async_trait]
pub trait WalletWire: Send + Sync {
    /// Transmits a binary message to the wallet and receives a response.
    ///
    /// # Arguments
    ///
    /// * `message` - The binary message to send
    ///
    /// # Returns
    ///
    /// The binary response from the wallet
    async fn transmit_to_wallet(&self, message: &[u8]) -> Result<Vec<u8>, Error>;
}

/// Counterparty wire encoding constants.
pub mod counterparty_codes {
    /// Counterparty is undefined/null.
    pub const UNDEFINED: u8 = 0;
    /// Counterparty is "self".
    pub const SELF: u8 = 11;
    /// Counterparty is "anyone".
    pub const ANYONE: u8 = 12;
}

/// Action status wire encoding.
pub mod status_codes {
    /// Status code for "completed".
    pub const COMPLETED: i8 = 1;
    /// Status code for "unprocessed".
    pub const UNPROCESSED: i8 = 2;
    /// Status code for "sending".
    pub const SENDING: i8 = 3;
    /// Status code for "unproven".
    pub const UNPROVEN: i8 = 4;
    /// Status code for "unsigned".
    pub const UNSIGNED: i8 = 5;
    /// Status code for "nosend".
    pub const NOSEND: i8 = 6;
    /// Status code for "nonfinal".
    pub const NONFINAL: i8 = 7;
    /// Status code for "failed".
    pub const FAILED: i8 = 8;
    /// Status code for unknown/undefined.
    pub const UNKNOWN: i8 = -1;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counterparty_codes() {
        assert_eq!(counterparty_codes::UNDEFINED, 0);
        assert_eq!(counterparty_codes::SELF, 11);
        assert_eq!(counterparty_codes::ANYONE, 12);
    }

    #[test]
    fn test_status_codes() {
        assert_eq!(status_codes::COMPLETED, 1);
        assert_eq!(status_codes::FAILED, 8);
        assert_eq!(status_codes::UNKNOWN, -1);
    }
}
