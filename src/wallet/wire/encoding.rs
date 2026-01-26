//! Wire protocol encoding utilities.
//!
//! This module provides [`WireReader`] and [`WireWriter`] types that extend the
//! primitives Reader/Writer with signed varint support and convenience methods
//! for the WalletWire protocol.

use crate::primitives::encoding::{Reader, Writer};
use crate::primitives::{from_hex, to_hex, PublicKey};
use crate::wallet::types::{ActionStatus, Counterparty, Outpoint, Protocol, SecurityLevel};
use crate::Error;

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
}
