//! Encoding utilities for hex, base58, base64, and UTF-8.
//!
//! This module provides functions for encoding and decoding data in various formats
//! commonly used in Bitcoin and blockchain applications.
//!
//! # Examples
//!
//! ## Hex encoding
//!
//! ```rust
//! use bsv_rs::primitives::encoding::{to_hex, from_hex};
//!
//! let bytes = vec![0xde, 0xad, 0xbe, 0xef];
//! let hex_str = to_hex(&bytes);
//! assert_eq!(hex_str, "deadbeef");
//!
//! let decoded = from_hex("DEADBEEF").unwrap();
//! assert_eq!(decoded, bytes);
//! ```
//!
//! ## Base58 encoding
//!
//! ```rust
//! use bsv_rs::primitives::encoding::{to_base58, from_base58};
//!
//! // Leading zeros become '1' characters
//! let bytes = vec![0x00, 0x00, 0x00];
//! let encoded = to_base58(&bytes);
//! assert_eq!(encoded, "111");
//!
//! let decoded = from_base58("111").unwrap();
//! assert_eq!(decoded, bytes);
//! ```
//!
//! ## Reader and Writer
//!
//! ```rust
//! use bsv_rs::primitives::encoding::{Reader, Writer};
//!
//! // Writing binary data
//! let mut writer = Writer::new();
//! writer.write_u8(0x01);
//! writer.write_u32_le(0x12345678);
//! writer.write_var_int(1000);
//! writer.write_var_bytes(b"hello");
//!
//! let data = writer.into_bytes();
//!
//! // Reading it back
//! let mut reader = Reader::new(&data);
//! assert_eq!(reader.read_u8().unwrap(), 0x01);
//! assert_eq!(reader.read_u32_le().unwrap(), 0x12345678);
//! assert_eq!(reader.read_var_int().unwrap(), 1000);
//! assert_eq!(reader.read_var_bytes().unwrap(), b"hello");
//! assert!(reader.is_empty());
//! ```

use crate::error::{Error, Result};
use crate::primitives::hash::sha256d;

// ============================================================================
// Hex Encoding
// ============================================================================

/// Converts a byte slice to a lowercase hexadecimal string.
///
/// # Arguments
///
/// * `data` - The bytes to encode
///
/// # Returns
///
/// A lowercase hexadecimal string representation
///
/// # Example
///
/// ```rust
/// use bsv_rs::primitives::encoding::to_hex;
///
/// assert_eq!(to_hex(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
/// assert_eq!(to_hex(&[0x00, 0x01, 0x02]), "000102");
/// ```
pub fn to_hex(data: &[u8]) -> String {
    hex::encode(data)
}

/// Decodes a hexadecimal string to bytes.
///
/// The input is case-insensitive and must have an even number of characters.
///
/// # Arguments
///
/// * `s` - The hexadecimal string to decode
///
/// # Returns
///
/// The decoded bytes, or an error if the string is invalid
///
/// # Example
///
/// ```rust
/// use bsv_rs::primitives::encoding::from_hex;
///
/// assert_eq!(from_hex("deadbeef").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
/// assert_eq!(from_hex("DEADBEEF").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
/// assert!(from_hex("invalid").is_err());
/// assert!(from_hex("deadbee").is_err()); // Odd length
/// ```
pub fn from_hex(s: &str) -> Result<Vec<u8>> {
    hex::decode(s).map_err(|e| Error::InvalidHex(e.to_string()))
}

// ============================================================================
// Base58 Encoding (Bitcoin alphabet)
// ============================================================================

/// The Bitcoin Base58 alphabet.
/// Excludes 0, O, I, and l to avoid ambiguity.
pub const BASE58_ALPHABET: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Converts a byte slice to a Base58 string using the Bitcoin alphabet.
///
/// Leading zero bytes are encoded as '1' characters.
///
/// # Arguments
///
/// * `data` - The bytes to encode
///
/// # Returns
///
/// A Base58 encoded string
///
/// # Example
///
/// ```rust
/// use bsv_rs::primitives::encoding::to_base58;
///
/// // Leading zeros become '1' characters
/// assert_eq!(to_base58(&[0x00]), "1");
/// assert_eq!(to_base58(&[0x00, 0x00, 0x00]), "111");
///
/// // Regular encoding
/// let bytes = hex::decode("0123456789ABCDEF").unwrap();
/// assert_eq!(to_base58(&bytes), "C3CPq7c8PY");
/// ```
pub fn to_base58(data: &[u8]) -> String {
    bs58::encode(data)
        .with_alphabet(bs58::Alphabet::BITCOIN)
        .into_string()
}

/// Decodes a Base58 string to bytes using the Bitcoin alphabet.
///
/// Leading '1' characters are decoded as zero bytes.
///
/// # Arguments
///
/// * `s` - The Base58 string to decode
///
/// # Returns
///
/// The decoded bytes, or an error if the string contains invalid characters
///
/// # Example
///
/// ```rust
/// use bsv_rs::primitives::encoding::from_base58;
///
/// assert_eq!(from_base58("111").unwrap(), vec![0x00, 0x00, 0x00]);
/// assert!(from_base58("0OIl").is_err()); // Invalid characters
/// ```
pub fn from_base58(s: &str) -> Result<Vec<u8>> {
    if s.is_empty() {
        return Err(Error::InvalidBase58("empty string".to_string()));
    }
    bs58::decode(s)
        .with_alphabet(bs58::Alphabet::BITCOIN)
        .into_vec()
        .map_err(|e| Error::InvalidBase58(e.to_string()))
}

// ============================================================================
// Base58Check Encoding (with version byte and checksum)
// ============================================================================

/// Encodes data with a version prefix using Base58Check encoding.
///
/// Base58Check = Base58(version || payload || checksum)
/// where checksum = first 4 bytes of SHA256(SHA256(version || payload))
///
/// This is used for Bitcoin addresses and WIF private keys.
///
/// # Arguments
///
/// * `payload` - The data to encode
/// * `version` - The version byte(s) to prepend
///
/// # Returns
///
/// A Base58Check encoded string
///
/// # Example
///
/// ```rust
/// use bsv_rs::primitives::encoding::{to_base58_check, from_base58_check};
///
/// // Bitcoin mainnet address (version 0x00)
/// let pubkey_hash = hex::decode("f5f2d624cfb5c3f66d06123d0829d1c9cebf770e").unwrap();
/// let address = to_base58_check(&pubkey_hash, &[0x00]);
/// assert_eq!(address, "1PRTTaJesdNovgne6Ehcdu1fpEdX7913CK");
///
/// // WIF private key (version 0x80)
/// let private_key = hex::decode("1E99423A4ED27608A15A2616A2B0E9E52CED330AC530EDCC32C8FFC6A526AEDD").unwrap();
/// let wif = to_base58_check(&private_key, &[0x80]);
/// assert_eq!(wif, "5J3mBbAH58CpQ3Y5RNJpUKPE62SQ5tfcvU2JpbnkeyhfsYB1Jcn");
/// ```
pub fn to_base58_check(payload: &[u8], version: &[u8]) -> String {
    // Build version || payload
    let mut data = Vec::with_capacity(version.len() + payload.len() + 4);
    data.extend_from_slice(version);
    data.extend_from_slice(payload);

    // Compute checksum = first 4 bytes of SHA256(SHA256(version || payload))
    let checksum = sha256d(&data);
    data.extend_from_slice(&checksum[..4]);

    to_base58(&data)
}

/// Decodes a Base58Check encoded string.
///
/// Validates the checksum and returns the version bytes and payload separately.
///
/// # Arguments
///
/// * `s` - The Base58Check encoded string
///
/// # Returns
///
/// A tuple of (version, payload), or an error if the checksum is invalid
///
/// # Example
///
/// ```rust
/// use bsv_rs::primitives::encoding::from_base58_check;
///
/// // Decode a Bitcoin address
/// let (version, pubkey_hash) = from_base58_check("1PRTTaJesdNovgne6Ehcdu1fpEdX7913CK").unwrap();
/// assert_eq!(version, vec![0x00]);
/// assert_eq!(pubkey_hash.len(), 20);
///
/// // Decode a WIF private key
/// let (version, payload) = from_base58_check("5J3mBbAH58CpQ3Y5RNJpUKPE62SQ5tfcvU2JpbnkeyhfsYB1Jcn").unwrap();
/// assert_eq!(version, vec![0x80]);
/// assert_eq!(payload.len(), 32);
/// ```
pub fn from_base58_check(s: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    from_base58_check_with_prefix_length(s, 1)
}

/// Decodes a Base58Check encoded string with a custom prefix length.
///
/// # Arguments
///
/// * `s` - The Base58Check encoded string
/// * `prefix_length` - The length of the version prefix in bytes
///
/// # Returns
///
/// A tuple of (version, payload), or an error if the checksum is invalid
pub fn from_base58_check_with_prefix_length(
    s: &str,
    prefix_length: usize,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let bytes = from_base58(s)?;

    // Need at least prefix + 4 bytes checksum
    if bytes.len() < prefix_length + 4 {
        return Err(Error::InvalidBase58(
            "data too short for Base58Check".to_string(),
        ));
    }

    let version = bytes[..prefix_length].to_vec();
    let payload = bytes[prefix_length..bytes.len() - 4].to_vec();
    let checksum = &bytes[bytes.len() - 4..];

    // Verify checksum
    let mut data = Vec::with_capacity(version.len() + payload.len());
    data.extend_from_slice(&version);
    data.extend_from_slice(&payload);
    let expected_checksum = sha256d(&data);

    if checksum != &expected_checksum[..4] {
        return Err(Error::InvalidChecksum);
    }

    Ok((version, payload))
}

// ============================================================================
// Base64 Encoding
// ============================================================================

/// Encodes bytes to a Base64 string.
///
/// # Arguments
///
/// * `data` - The bytes to encode
///
/// # Returns
///
/// A Base64 encoded string with standard padding
///
/// # Example
///
/// ```rust
/// use bsv_rs::primitives::encoding::to_base64;
///
/// assert_eq!(to_base64(b"Hello"), "SGVsbG8=");
/// assert_eq!(to_base64(b"f"), "Zg==");
/// assert_eq!(to_base64(b"fo"), "Zm8=");
/// assert_eq!(to_base64(b"foo"), "Zm9v");
/// ```
pub fn to_base64(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Decodes a Base64 string to bytes.
///
/// Supports both standard and URL-safe Base64 (+ vs - and / vs _).
/// Whitespace is stripped before decoding.
///
/// # Arguments
///
/// * `s` - The Base64 string to decode
///
/// # Returns
///
/// The decoded bytes, or an error if the string is invalid
///
/// # Example
///
/// ```rust
/// use bsv_rs::primitives::encoding::from_base64;
///
/// assert_eq!(from_base64("SGVsbG8=").unwrap(), b"Hello");
/// assert_eq!(from_base64("Zg==").unwrap(), b"f");
/// assert_eq!(from_base64("Zm8=").unwrap(), b"fo");
/// assert_eq!(from_base64("Zm9v").unwrap(), b"foo");
///
/// // URL-safe variant
/// assert_eq!(from_base64("_w==").unwrap(), vec![255]);
/// ```
pub fn from_base64(s: &str) -> Result<Vec<u8>> {
    use base64::engine::general_purpose;
    use base64::Engine;

    // Strip whitespace and convert URL-safe characters
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            _ => c,
        })
        .collect();

    // Use STANDARD_NO_PAD for decoding to handle both padded and unpadded input
    // First try STANDARD (with padding), then try STANDARD_NO_PAD
    general_purpose::STANDARD
        .decode(&cleaned)
        .or_else(|_| general_purpose::STANDARD_NO_PAD.decode(&cleaned))
        .map_err(|e| Error::InvalidBase64(e.to_string()))
}

// ============================================================================
// UTF-8 Encoding
// ============================================================================

/// Converts a string to its UTF-8 byte representation.
///
/// This is mostly for API consistency with the TypeScript SDK.
///
/// # Arguments
///
/// * `s` - The string to convert
///
/// # Returns
///
/// The UTF-8 encoded bytes
///
/// # Example
///
/// ```rust
/// use bsv_rs::primitives::encoding::to_utf8_bytes;
///
/// assert_eq!(to_utf8_bytes("Hello"), vec![72, 101, 108, 108, 111]);
/// assert_eq!(to_utf8_bytes("€"), vec![0xE2, 0x82, 0xAC]); // 3-byte UTF-8
/// assert_eq!(to_utf8_bytes("😃"), vec![0xF0, 0x9F, 0x98, 0x83]); // 4-byte UTF-8
/// ```
pub fn to_utf8_bytes(s: &str) -> Vec<u8> {
    s.as_bytes().to_vec()
}

/// Converts UTF-8 bytes to a string.
///
/// # Arguments
///
/// * `data` - The UTF-8 encoded bytes
///
/// # Returns
///
/// The decoded string, or an error if the bytes are not valid UTF-8
///
/// # Example
///
/// ```rust
/// use bsv_rs::primitives::encoding::from_utf8_bytes;
///
/// assert_eq!(from_utf8_bytes(&[72, 101, 108, 108, 111]).unwrap(), "Hello");
/// assert!(from_utf8_bytes(&[0xFF, 0xFE]).is_err()); // Invalid UTF-8
/// ```
pub fn from_utf8_bytes(data: &[u8]) -> Result<String> {
    String::from_utf8(data.to_vec()).map_err(|e| Error::InvalidUtf8(e.to_string()))
}

// ============================================================================
// Binary Reader
// ============================================================================

/// A binary reader for parsing Bitcoin data structures.
///
/// `Reader` provides methods for reading integers in little-endian format
/// and Bitcoin-specific variable-length integers (varints).
///
/// # Example
///
/// ```rust
/// use bsv_rs::primitives::encoding::Reader;
///
/// let data = vec![0x01, 0x02, 0x00, 0x03, 0x00, 0x00, 0x00];
/// let mut reader = Reader::new(&data);
///
/// assert_eq!(reader.read_u8().unwrap(), 0x01);
/// assert_eq!(reader.read_u16_le().unwrap(), 0x0002);
/// assert_eq!(reader.read_u32_le().unwrap(), 0x00000003);
/// assert!(reader.is_empty());
/// ```
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Creates a new reader over the given byte slice.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to read from
    ///
    /// # Returns
    ///
    /// A new reader positioned at the beginning
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    /// Returns the number of bytes remaining to be read.
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    /// Returns true if there are no more bytes to read.
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Returns the current read position.
    pub fn position(&self) -> usize {
        self.pos
    }

    // ------------------------------------------------------------------------
    // Unsigned integers (little-endian)
    // ------------------------------------------------------------------------

    /// Reads a single unsigned byte.
    pub fn read_u8(&mut self) -> Result<u8> {
        self.ensure_remaining(1)?;
        let val = self.data[self.pos];
        self.pos += 1;
        Ok(val)
    }

    /// Reads a 16-bit unsigned integer in little-endian format.
    pub fn read_u16_le(&mut self) -> Result<u16> {
        self.ensure_remaining(2)?;
        let bytes = [self.data[self.pos], self.data[self.pos + 1]];
        self.pos += 2;
        Ok(u16::from_le_bytes(bytes))
    }

    /// Reads a 32-bit unsigned integer in little-endian format.
    pub fn read_u32_le(&mut self) -> Result<u32> {
        self.ensure_remaining(4)?;
        let bytes = [
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ];
        self.pos += 4;
        Ok(u32::from_le_bytes(bytes))
    }

    /// Reads a 64-bit unsigned integer in little-endian format.
    pub fn read_u64_le(&mut self) -> Result<u64> {
        self.ensure_remaining(8)?;
        let bytes = [
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
            self.data[self.pos + 4],
            self.data[self.pos + 5],
            self.data[self.pos + 6],
            self.data[self.pos + 7],
        ];
        self.pos += 8;
        Ok(u64::from_le_bytes(bytes))
    }

    // ------------------------------------------------------------------------
    // Signed integers (little-endian)
    // ------------------------------------------------------------------------

    /// Reads a single signed byte.
    pub fn read_i8(&mut self) -> Result<i8> {
        self.ensure_remaining(1)?;
        let val = self.data[self.pos] as i8;
        self.pos += 1;
        Ok(val)
    }

    /// Reads a 16-bit signed integer in little-endian format.
    pub fn read_i16_le(&mut self) -> Result<i16> {
        self.ensure_remaining(2)?;
        let bytes = [self.data[self.pos], self.data[self.pos + 1]];
        self.pos += 2;
        Ok(i16::from_le_bytes(bytes))
    }

    /// Reads a 32-bit signed integer in little-endian format.
    pub fn read_i32_le(&mut self) -> Result<i32> {
        self.ensure_remaining(4)?;
        let bytes = [
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ];
        self.pos += 4;
        Ok(i32::from_le_bytes(bytes))
    }

    /// Reads a 64-bit signed integer in little-endian format.
    pub fn read_i64_le(&mut self) -> Result<i64> {
        self.ensure_remaining(8)?;
        let bytes = [
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
            self.data[self.pos + 4],
            self.data[self.pos + 5],
            self.data[self.pos + 6],
            self.data[self.pos + 7],
        ];
        self.pos += 8;
        Ok(i64::from_le_bytes(bytes))
    }

    // ------------------------------------------------------------------------
    // Bitcoin-specific
    // ------------------------------------------------------------------------

    /// Reads a Bitcoin variable-length integer.
    ///
    /// Bitcoin varints are encoded as follows:
    /// - `0x00-0xFC`: 1 byte, value as-is
    /// - `0xFD`: 3 bytes total, `0xFD` prefix + 2 bytes little-endian uint16
    /// - `0xFE`: 5 bytes total, `0xFE` prefix + 4 bytes little-endian uint32
    /// - `0xFF`: 9 bytes total, `0xFF` prefix + 8 bytes little-endian uint64
    ///
    /// # Returns
    ///
    /// The decoded value as a u64
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_rs::primitives::encoding::Reader;
    ///
    /// // Single byte: 0xFC (252)
    /// let mut reader = Reader::new(&[0xFC]);
    /// assert_eq!(reader.read_var_int().unwrap(), 0xFC);
    ///
    /// // 3-byte: 0xFD 0xFD 0x00 (253)
    /// let mut reader = Reader::new(&[0xFD, 0xFD, 0x00]);
    /// assert_eq!(reader.read_var_int().unwrap(), 0xFD);
    /// ```
    pub fn read_var_int(&mut self) -> Result<u64> {
        let first = self.read_u8()?;
        match first {
            0x00..=0xFC => Ok(first as u64),
            0xFD => Ok(self.read_u16_le()? as u64),
            0xFE => Ok(self.read_u32_le()? as u64),
            0xFF => self.read_u64_le(),
        }
    }

    /// Reads a Bitcoin varint as a usize, for use as a length.
    ///
    /// This is a convenience method that converts the u64 result to usize.
    /// It will return an error if the value exceeds usize::MAX on 32-bit platforms.
    pub fn read_var_int_num(&mut self) -> Result<usize> {
        let val = self.read_var_int()?;
        usize::try_from(val)
            .map_err(|_| Error::CryptoError(format!("varint value {} exceeds maximum usize", val)))
    }

    // ------------------------------------------------------------------------
    // Byte sequences
    // ------------------------------------------------------------------------

    /// Reads a fixed number of bytes.
    ///
    /// # Arguments
    ///
    /// * `len` - The number of bytes to read
    ///
    /// # Returns
    ///
    /// A slice of the requested bytes
    pub fn read_bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        self.ensure_remaining(len)?;
        let bytes = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(bytes)
    }

    /// Reads a variable-length byte sequence (varint length prefix followed by bytes).
    ///
    /// This is commonly used in Bitcoin for scripts and other length-prefixed data.
    ///
    /// # Returns
    ///
    /// A slice of the bytes
    pub fn read_var_bytes(&mut self) -> Result<&'a [u8]> {
        let len = self.read_var_int_num()?;
        self.read_bytes(len)
    }

    /// Reads all remaining bytes.
    ///
    /// # Returns
    ///
    /// A slice containing all bytes from the current position to the end
    pub fn read_remaining(&mut self) -> &'a [u8] {
        let bytes = &self.data[self.pos..];
        self.pos = self.data.len();
        bytes
    }

    // ------------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------------

    fn ensure_remaining(&self, needed: usize) -> Result<()> {
        if self.remaining() < needed {
            Err(Error::ReaderUnderflow {
                needed,
                available: self.remaining(),
            })
        } else {
            Ok(())
        }
    }
}

// ============================================================================
// Binary Writer
// ============================================================================

/// A binary writer for serializing Bitcoin data structures.
///
/// `Writer` provides methods for writing integers in little-endian format
/// and Bitcoin-specific variable-length integers (varints).
///
/// # Example
///
/// ```rust
/// use bsv_rs::primitives::encoding::Writer;
///
/// let mut writer = Writer::new();
/// writer.write_u8(0x01);
/// writer.write_u16_le(0x0002);
/// writer.write_u32_le(0x00000003);
///
/// let data = writer.into_bytes();
/// assert_eq!(data, vec![0x01, 0x02, 0x00, 0x03, 0x00, 0x00, 0x00]);
/// ```
#[derive(Debug, Clone, Default)]
pub struct Writer {
    data: Vec<u8>,
}

impl Writer {
    /// Creates a new empty writer.
    pub fn new() -> Self {
        Writer { data: Vec::new() }
    }

    /// Creates a new writer with pre-allocated capacity.
    ///
    /// # Arguments
    ///
    /// * `capacity` - The number of bytes to pre-allocate
    pub fn with_capacity(capacity: usize) -> Self {
        Writer {
            data: Vec::with_capacity(capacity),
        }
    }

    /// Returns the current length of the written data.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns true if no data has been written.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Returns a reference to the written bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Consumes the writer and returns the written bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }

    // ------------------------------------------------------------------------
    // Unsigned integers (little-endian)
    // ------------------------------------------------------------------------

    /// Writes a single unsigned byte.
    pub fn write_u8(&mut self, val: u8) -> &mut Self {
        self.data.push(val);
        self
    }

    /// Writes a 16-bit unsigned integer in little-endian format.
    pub fn write_u16_le(&mut self, val: u16) -> &mut Self {
        self.data.extend_from_slice(&val.to_le_bytes());
        self
    }

    /// Writes a 32-bit unsigned integer in little-endian format.
    pub fn write_u32_le(&mut self, val: u32) -> &mut Self {
        self.data.extend_from_slice(&val.to_le_bytes());
        self
    }

    /// Writes a 64-bit unsigned integer in little-endian format.
    pub fn write_u64_le(&mut self, val: u64) -> &mut Self {
        self.data.extend_from_slice(&val.to_le_bytes());
        self
    }

    // ------------------------------------------------------------------------
    // Signed integers (little-endian)
    // ------------------------------------------------------------------------

    /// Writes a single signed byte.
    pub fn write_i8(&mut self, val: i8) -> &mut Self {
        self.data.push(val as u8);
        self
    }

    /// Writes a 16-bit signed integer in little-endian format.
    pub fn write_i16_le(&mut self, val: i16) -> &mut Self {
        self.data.extend_from_slice(&val.to_le_bytes());
        self
    }

    /// Writes a 32-bit signed integer in little-endian format.
    pub fn write_i32_le(&mut self, val: i32) -> &mut Self {
        self.data.extend_from_slice(&val.to_le_bytes());
        self
    }

    /// Writes a 64-bit signed integer in little-endian format.
    pub fn write_i64_le(&mut self, val: i64) -> &mut Self {
        self.data.extend_from_slice(&val.to_le_bytes());
        self
    }

    // ------------------------------------------------------------------------
    // Bitcoin-specific
    // ------------------------------------------------------------------------

    /// Writes a Bitcoin variable-length integer.
    ///
    /// Bitcoin varints are encoded as follows:
    /// - `0x00-0xFC`: 1 byte, value as-is
    /// - `0xFD-0xFFFF`: 3 bytes, `0xFD` prefix + 2 bytes little-endian uint16
    /// - `0x10000-0xFFFFFFFF`: 5 bytes, `0xFE` prefix + 4 bytes little-endian uint32
    /// - `0x100000000-0xFFFFFFFFFFFFFFFF`: 9 bytes, `0xFF` prefix + 8 bytes little-endian uint64
    ///
    /// # Arguments
    ///
    /// * `val` - The value to encode
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_rs::primitives::encoding::Writer;
    ///
    /// let mut w = Writer::new();
    /// w.write_var_int(252); // 0xFC - single byte
    /// assert_eq!(w.len(), 1);
    ///
    /// let mut w = Writer::new();
    /// w.write_var_int(253); // 0xFD - needs 3-byte encoding
    /// assert_eq!(w.len(), 3);
    ///
    /// let mut w = Writer::new();
    /// w.write_var_int(0x10000); // needs 5-byte encoding
    /// assert_eq!(w.len(), 5);
    ///
    /// let mut w = Writer::new();
    /// w.write_var_int(0x100000000); // needs 9-byte encoding
    /// assert_eq!(w.len(), 9);
    /// ```
    pub fn write_var_int(&mut self, val: u64) -> &mut Self {
        if val < 0xFD {
            self.data.push(val as u8);
        } else if val <= 0xFFFF {
            self.data.push(0xFD);
            self.data.extend_from_slice(&(val as u16).to_le_bytes());
        } else if val <= 0xFFFFFFFF {
            self.data.push(0xFE);
            self.data.extend_from_slice(&(val as u32).to_le_bytes());
        } else {
            self.data.push(0xFF);
            self.data.extend_from_slice(&val.to_le_bytes());
        }
        self
    }

    // ------------------------------------------------------------------------
    // Byte sequences
    // ------------------------------------------------------------------------

    /// Writes raw bytes.
    ///
    /// # Arguments
    ///
    /// * `data` - The bytes to write
    pub fn write_bytes(&mut self, data: &[u8]) -> &mut Self {
        self.data.extend_from_slice(data);
        self
    }

    /// Writes a variable-length byte sequence (varint length prefix followed by bytes).
    ///
    /// This is commonly used in Bitcoin for scripts and other length-prefixed data.
    ///
    /// # Arguments
    ///
    /// * `data` - The bytes to write
    pub fn write_var_bytes(&mut self, data: &[u8]) -> &mut Self {
        self.write_var_int(data.len() as u64);
        self.data.extend_from_slice(data);
        self
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------------
    // Hex encoding tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_to_hex_basic() {
        assert_eq!(to_hex(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert_eq!(to_hex(&[0x00, 0x01, 0x02, 0x03]), "00010203");
        assert_eq!(to_hex(&[]), "");
    }

    #[test]
    fn test_from_hex_basic() {
        assert_eq!(from_hex("deadbeef").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(from_hex("00010203").unwrap(), vec![0x00, 0x01, 0x02, 0x03]);
        assert_eq!(from_hex("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn test_from_hex_case_insensitive() {
        assert_eq!(from_hex("DEADBEEF").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(from_hex("DeAdBeEf").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_from_hex_invalid() {
        assert!(from_hex("invalid").is_err());
        assert!(from_hex("deadbee").is_err()); // Odd length
        assert!(from_hex("gg").is_err()); // Invalid characters
    }

    // ------------------------------------------------------------------------
    // Base58 encoding tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_to_base58_leading_zeros() {
        assert_eq!(to_base58(&[0x00]), "1");
        assert_eq!(to_base58(&[0x00, 0x00, 0x00]), "111");
    }

    #[test]
    fn test_to_base58_known_values() {
        // From Go SDK tests
        let bytes = from_hex("0123456789ABCDEF").unwrap();
        assert_eq!(to_base58(&bytes), "C3CPq7c8PY");

        let bytes = from_hex("000000287FB4CD").unwrap();
        assert_eq!(to_base58(&bytes), "111233QC4");

        // Empty
        assert_eq!(to_base58(&[]), "");

        // All zeros
        assert_eq!(to_base58(&[0, 0, 0, 0]), "1111");

        // Large number
        assert_eq!(to_base58(&[255, 255, 255, 255]), "7YXq9G");
    }

    #[test]
    fn test_from_base58_leading_ones() {
        assert_eq!(from_base58("1").unwrap(), vec![0x00]);
        assert_eq!(from_base58("111").unwrap(), vec![0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_from_base58_known_values() {
        assert_eq!(
            to_hex(&from_base58("C3CPq7c8PY").unwrap()),
            "0123456789abcdef"
        );
        assert_eq!(to_hex(&from_base58("111233QC4").unwrap()), "000000287fb4cd");
    }

    #[test]
    fn test_from_base58_invalid() {
        // Invalid characters (0, O, I, l are not in Base58 alphabet)
        assert!(from_base58("0").is_err());
        assert!(from_base58("O").is_err());
        assert!(from_base58("I").is_err());
        assert!(from_base58("l").is_err());
        assert!(from_base58("").is_err()); // Empty string
    }

    #[test]
    fn test_base58_roundtrip() {
        let original =
            from_hex("02c0ded2bc1f1305fb0faac5e6c03ee3a1924234985427b6167ca569d13df435cfeb05f9d2")
                .unwrap();
        let encoded = to_base58(&original);
        assert_eq!(
            encoded,
            "6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV"
        );
        let decoded = from_base58(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_from_base58_with_leading_ones() {
        let decoded = from_base58("111z").unwrap();
        assert_eq!(to_hex(&decoded), "00000039");
    }

    // ------------------------------------------------------------------------
    // Base58Check tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_base58check_address() {
        // Known Bitcoin address
        let pubkey_hash = from_hex("f5f2d624cfb5c3f66d06123d0829d1c9cebf770e").unwrap();
        let encoded = to_base58_check(&pubkey_hash, &[0x00]);
        assert_eq!(encoded, "1PRTTaJesdNovgne6Ehcdu1fpEdX7913CK");

        let (version, payload) = from_base58_check(&encoded).unwrap();
        assert_eq!(version, vec![0x00]);
        assert_eq!(payload, pubkey_hash);
    }

    #[test]
    fn test_base58check_wif() {
        // Known WIF private key
        let private_key =
            from_hex("1E99423A4ED27608A15A2616A2B0E9E52CED330AC530EDCC32C8FFC6A526AEDD").unwrap();
        let encoded = to_base58_check(&private_key, &[0x80]);
        assert_eq!(
            encoded,
            "5J3mBbAH58CpQ3Y5RNJpUKPE62SQ5tfcvU2JpbnkeyhfsYB1Jcn"
        );

        let (version, payload) = from_base58_check(&encoded).unwrap();
        assert_eq!(version, vec![0x80]);
        assert_eq!(payload, private_key);
    }

    #[test]
    fn test_base58check_wif_compressed() {
        // WIF with compression flag (33 bytes: 32 + 0x01)
        let private_key_compressed =
            from_hex("1E99423A4ED27608A15A2616A2B0E9E52CED330AC530EDCC32C8FFC6A526AEDD01").unwrap();
        let encoded = to_base58_check(&private_key_compressed, &[0x80]);
        assert_eq!(
            encoded,
            "KxFC1jmwwCoACiCAWZ3eXa96mBM6tb3TYzGmf6YwgdGWZgawvrtJ"
        );

        let (version, payload) = from_base58_check(&encoded).unwrap();
        assert_eq!(version, vec![0x80]);
        assert_eq!(payload, private_key_compressed);
    }

    #[test]
    fn test_base58check_invalid_checksum() {
        // Tamper with a valid address
        let _valid = "1PRTTaJesdNovgne6Ehcdu1fpEdX7913CK";
        // Change last character
        let invalid = "1PRTTaJesdNovgne6Ehcdu1fpEdX7913CL";
        let result = from_base58_check(invalid);
        assert!(result.is_err());
    }

    #[test]
    fn test_base58check_multiple_addresses() {
        // Test from TypeScript SDK
        let data = from_hex("27b5891b01da2db74cde1689a97a2acbe23d5fb1").unwrap();
        let encoded = to_base58_check(&data, &[0x00]);
        assert_eq!(encoded, "14cxpo3MBCYYWCgF74SWTdcmxipnGUsPw3");
    }

    // ------------------------------------------------------------------------
    // Base64 tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_to_base64_basic() {
        assert_eq!(to_base64(b"f"), "Zg==");
        assert_eq!(to_base64(b"fo"), "Zm8=");
        assert_eq!(to_base64(b"foo"), "Zm9v");
        assert_eq!(to_base64(b"Hello"), "SGVsbG8=");
    }

    #[test]
    fn test_from_base64_basic() {
        assert_eq!(from_base64("Zg==").unwrap(), b"f");
        assert_eq!(from_base64("Zm8=").unwrap(), b"fo");
        assert_eq!(from_base64("Zm9v").unwrap(), b"foo");
        assert_eq!(from_base64("SGVsbG8=").unwrap(), b"Hello");
    }

    #[test]
    fn test_from_base64_no_padding() {
        // Base64 without padding should still work with the standard engine
        assert_eq!(from_base64("SGVsbG8").unwrap(), b"Hello");
        assert_eq!(from_base64("QQ").unwrap(), b"A");
        assert_eq!(from_base64("Zm8").unwrap(), b"fo");
    }

    #[test]
    fn test_from_base64_url_safe() {
        // URL-safe characters should be converted
        assert_eq!(from_base64("_w==").unwrap(), vec![255]);
    }

    #[test]
    fn test_from_base64_whitespace() {
        // Whitespace should be ignored
        assert_eq!(from_base64("S G V s b G 8 =\n").unwrap(), b"Hello");
    }

    #[test]
    fn test_from_base64_invalid() {
        assert!(from_base64("A?==").is_err());
    }

    // ------------------------------------------------------------------------
    // UTF-8 tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_to_utf8_bytes_basic() {
        assert_eq!(to_utf8_bytes("Hello"), vec![72, 101, 108, 108, 111]);
        assert_eq!(to_utf8_bytes("€"), vec![0xE2, 0x82, 0xAC]);
        assert_eq!(to_utf8_bytes("😃"), vec![0xF0, 0x9F, 0x98, 0x83]);
    }

    #[test]
    fn test_from_utf8_bytes_basic() {
        assert_eq!(from_utf8_bytes(&[72, 101, 108, 108, 111]).unwrap(), "Hello");
        assert_eq!(from_utf8_bytes(&[0xE2, 0x82, 0xAC]).unwrap(), "€");
    }

    #[test]
    fn test_from_utf8_bytes_invalid() {
        assert!(from_utf8_bytes(&[0xFF, 0xFE]).is_err());
    }

    // ------------------------------------------------------------------------
    // Reader tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_reader_basic() {
        let data = vec![0x01, 0x02, 0x03, 0x04];
        let mut reader = Reader::new(&data);

        assert_eq!(reader.position(), 0);
        assert_eq!(reader.remaining(), 4);
        assert!(!reader.is_empty());

        assert_eq!(reader.read_u8().unwrap(), 0x01);
        assert_eq!(reader.position(), 1);
        assert_eq!(reader.remaining(), 3);
    }

    #[test]
    fn test_reader_u16_le() {
        let data = vec![0x01, 0x02];
        let mut reader = Reader::new(&data);
        assert_eq!(reader.read_u16_le().unwrap(), 0x0201);
    }

    #[test]
    fn test_reader_u32_le() {
        let data = vec![0x01, 0x02, 0x03, 0x04];
        let mut reader = Reader::new(&data);
        assert_eq!(reader.read_u32_le().unwrap(), 0x04030201);
    }

    #[test]
    fn test_reader_u64_le() {
        let data = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let mut reader = Reader::new(&data);
        assert_eq!(reader.read_u64_le().unwrap(), 0x0807060504030201);
    }

    #[test]
    fn test_reader_signed_integers() {
        // i8: -1
        let data = vec![0xFF];
        let mut reader = Reader::new(&data);
        assert_eq!(reader.read_i8().unwrap(), -1);

        // i16: -1
        let data = vec![0xFF, 0xFF];
        let mut reader = Reader::new(&data);
        assert_eq!(reader.read_i16_le().unwrap(), -1);

        // i32: -1
        let data = vec![0xFF, 0xFF, 0xFF, 0xFF];
        let mut reader = Reader::new(&data);
        assert_eq!(reader.read_i32_le().unwrap(), -1);

        // i64: -1
        let data = vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let mut reader = Reader::new(&data);
        assert_eq!(reader.read_i64_le().unwrap(), -1);
    }

    #[test]
    fn test_reader_underflow() {
        let data = vec![0x01, 0x02];
        let mut reader = Reader::new(&data);
        assert!(reader.read_u32_le().is_err());
    }

    #[test]
    fn test_reader_read_bytes() {
        let data = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let mut reader = Reader::new(&data);

        assert_eq!(reader.read_bytes(3).unwrap(), &[0x01, 0x02, 0x03]);
        assert_eq!(reader.read_bytes(2).unwrap(), &[0x04, 0x05]);
        assert!(reader.is_empty());
    }

    #[test]
    fn test_reader_read_remaining() {
        let data = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let mut reader = Reader::new(&data);

        reader.read_u8().unwrap();
        reader.read_u8().unwrap();

        let remaining = reader.read_remaining();
        assert_eq!(remaining, &[0x03, 0x04, 0x05]);
        assert!(reader.is_empty());
    }

    #[test]
    fn test_reader_varint_single_byte() {
        // Values 0x00-0xFC are encoded as single byte
        let data = vec![0x00];
        let mut reader = Reader::new(&data);
        assert_eq!(reader.read_var_int().unwrap(), 0);

        let data = vec![0xFC];
        let mut reader = Reader::new(&data);
        assert_eq!(reader.read_var_int().unwrap(), 0xFC);
    }

    #[test]
    fn test_reader_varint_three_bytes() {
        // Values 0xFD-0xFFFF use 0xFD prefix + 2 bytes
        let data = vec![0xFD, 0xFD, 0x00];
        let mut reader = Reader::new(&data);
        assert_eq!(reader.read_var_int().unwrap(), 0xFD);

        let data = vec![0xFD, 0xFF, 0xFF];
        let mut reader = Reader::new(&data);
        assert_eq!(reader.read_var_int().unwrap(), 0xFFFF);
    }

    #[test]
    fn test_reader_varint_five_bytes() {
        // Values 0x10000-0xFFFFFFFF use 0xFE prefix + 4 bytes
        let data = vec![0xFE, 0x00, 0x00, 0x01, 0x00];
        let mut reader = Reader::new(&data);
        assert_eq!(reader.read_var_int().unwrap(), 0x10000);

        let data = vec![0xFE, 0xFF, 0xFF, 0xFF, 0xFF];
        let mut reader = Reader::new(&data);
        assert_eq!(reader.read_var_int().unwrap(), 0xFFFFFFFF);
    }

    #[test]
    fn test_reader_varint_nine_bytes() {
        // Values > 0xFFFFFFFF use 0xFF prefix + 8 bytes
        let data = vec![0xFF, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
        let mut reader = Reader::new(&data);
        assert_eq!(reader.read_var_int().unwrap(), 0x100000000);

        let data = vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let mut reader = Reader::new(&data);
        assert_eq!(reader.read_var_int().unwrap(), u64::MAX);
    }

    #[test]
    fn test_reader_varint_incomplete() {
        // Incomplete 3-byte varint
        let data = vec![0xFD, 0x01];
        let mut reader = Reader::new(&data);
        assert!(reader.read_var_int().is_err());
    }

    #[test]
    fn test_reader_var_bytes() {
        let data = vec![0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f]; // length 5 + "hello"
        let mut reader = Reader::new(&data);
        assert_eq!(reader.read_var_bytes().unwrap(), b"hello");
        assert!(reader.is_empty());
    }

    // ------------------------------------------------------------------------
    // Writer tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_writer_basic() {
        let mut writer = Writer::new();
        assert!(writer.is_empty());
        assert_eq!(writer.len(), 0);

        writer.write_u8(0x01);
        assert!(!writer.is_empty());
        assert_eq!(writer.len(), 1);
        assert_eq!(writer.as_bytes(), &[0x01]);
    }

    #[test]
    fn test_writer_u16_le() {
        let mut writer = Writer::new();
        writer.write_u16_le(0x0201);
        assert_eq!(writer.into_bytes(), vec![0x01, 0x02]);
    }

    #[test]
    fn test_writer_u32_le() {
        let mut writer = Writer::new();
        writer.write_u32_le(0x04030201);
        assert_eq!(writer.into_bytes(), vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_writer_u64_le() {
        let mut writer = Writer::new();
        writer.write_u64_le(0x0807060504030201);
        assert_eq!(
            writer.into_bytes(),
            vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
    }

    #[test]
    fn test_writer_signed_integers() {
        let mut writer = Writer::new();
        writer.write_i8(-1);
        assert_eq!(writer.as_bytes(), &[0xFF]);

        let mut writer = Writer::new();
        writer.write_i16_le(-1);
        assert_eq!(writer.as_bytes(), &[0xFF, 0xFF]);

        let mut writer = Writer::new();
        writer.write_i32_le(-1);
        assert_eq!(writer.as_bytes(), &[0xFF, 0xFF, 0xFF, 0xFF]);

        let mut writer = Writer::new();
        writer.write_i64_le(-1);
        assert_eq!(
            writer.as_bytes(),
            &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        );
    }

    #[test]
    fn test_writer_varint_single_byte() {
        // Values 0-252 (0xFC) are encoded as single byte
        let mut writer = Writer::new();
        writer.write_var_int(0);
        assert_eq!(writer.len(), 1);
        assert_eq!(writer.as_bytes(), &[0x00]);

        let mut writer = Writer::new();
        writer.write_var_int(0xFC);
        assert_eq!(writer.len(), 1);
        assert_eq!(writer.as_bytes(), &[0xFC]);
    }

    #[test]
    fn test_writer_varint_three_bytes() {
        // Values 253-65535 use 0xFD prefix + 2 bytes
        let mut writer = Writer::new();
        writer.write_var_int(0xFD);
        assert_eq!(writer.len(), 3);
        assert_eq!(writer.as_bytes(), &[0xFD, 0xFD, 0x00]);

        let mut writer = Writer::new();
        writer.write_var_int(0xFFFF);
        assert_eq!(writer.len(), 3);
        assert_eq!(writer.as_bytes(), &[0xFD, 0xFF, 0xFF]);
    }

    #[test]
    fn test_writer_varint_five_bytes() {
        // Values 0x10000-0xFFFFFFFF use 0xFE prefix + 4 bytes
        let mut writer = Writer::new();
        writer.write_var_int(0x10000);
        assert_eq!(writer.len(), 5);
        assert_eq!(writer.as_bytes(), &[0xFE, 0x00, 0x00, 0x01, 0x00]);

        let mut writer = Writer::new();
        writer.write_var_int(0xFFFFFFFF);
        assert_eq!(writer.len(), 5);
        assert_eq!(writer.as_bytes(), &[0xFE, 0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_writer_varint_nine_bytes() {
        // Values > 0xFFFFFFFF use 0xFF prefix + 8 bytes
        let mut writer = Writer::new();
        writer.write_var_int(0x100000000);
        assert_eq!(writer.len(), 9);
        assert_eq!(
            writer.as_bytes(),
            &[0xFF, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]
        );

        let mut writer = Writer::new();
        writer.write_var_int(u64::MAX);
        assert_eq!(writer.len(), 9);
        assert_eq!(
            writer.as_bytes(),
            &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        );
    }

    #[test]
    fn test_writer_var_bytes() {
        let mut writer = Writer::new();
        writer.write_var_bytes(b"hello");
        assert_eq!(
            writer.into_bytes(),
            vec![0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f]
        );
    }

    #[test]
    fn test_writer_write_bytes() {
        let mut writer = Writer::new();
        writer.write_bytes(&[0x01, 0x02, 0x03]);
        assert_eq!(writer.into_bytes(), vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_writer_chaining() {
        let mut writer = Writer::new();
        writer
            .write_u8(0x01)
            .write_u16_le(0x0302)
            .write_u32_le(0x07060504);
        assert_eq!(
            writer.into_bytes(),
            vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]
        );
    }

    // ------------------------------------------------------------------------
    // Reader/Writer round-trip tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_reader_writer_roundtrip() {
        let mut writer = Writer::new();
        writer.write_u8(0x01);
        writer.write_u32_le(0x12345678);
        writer.write_var_int(0xFFFFF);
        writer.write_var_bytes(b"hello");

        let data = writer.into_bytes();
        let mut reader = Reader::new(&data);

        assert_eq!(reader.read_u8().unwrap(), 0x01);
        assert_eq!(reader.read_u32_le().unwrap(), 0x12345678);
        assert_eq!(reader.read_var_int().unwrap(), 0xFFFFF);
        assert_eq!(reader.read_var_bytes().unwrap(), b"hello");
        assert!(reader.is_empty());
    }

    #[test]
    fn test_varint_roundtrip() {
        fn assert_varint_roundtrip(val: u64) {
            let mut writer = Writer::new();
            writer.write_var_int(val);
            let mut reader = Reader::new(writer.as_bytes());
            assert_eq!(reader.read_var_int().unwrap(), val);
        }

        // Single byte (0x00-0xFC)
        assert_varint_roundtrip(0);
        assert_varint_roundtrip(0xFC);

        // 3-byte form (0xFD prefix)
        assert_varint_roundtrip(0xFD);
        assert_varint_roundtrip(0xFFFF);

        // 5-byte form (0xFE prefix)
        assert_varint_roundtrip(0x10000);
        assert_varint_roundtrip(0xFFFFFFFF);

        // 9-byte form (0xFF prefix)
        assert_varint_roundtrip(0x100000000);
        assert_varint_roundtrip(u64::MAX);
    }

    #[test]
    fn test_varint_encoding_size() {
        // Verify correct encoding sizes
        let mut w = Writer::new();
        w.write_var_int(0xFC);
        assert_eq!(w.len(), 1);

        let mut w = Writer::new();
        w.write_var_int(0xFD);
        assert_eq!(w.len(), 3);

        let mut w = Writer::new();
        w.write_var_int(0x10000);
        assert_eq!(w.len(), 5);

        let mut w = Writer::new();
        w.write_var_int(0x100000000);
        assert_eq!(w.len(), 9);
    }

    // ------------------------------------------------------------------------
    // TypeScript compatibility tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_ts_hex_conversion() {
        // From utils.test.ts
        assert_eq!(from_hex("1234").unwrap(), vec![0x12, 0x34]);
        assert_eq!(to_hex(&[0, 1, 2, 3]), "00010203");
    }

    #[test]
    fn test_ts_base58_conversion() {
        // From utils.test.ts
        let actual = from_base58("6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV").unwrap();
        assert_eq!(
            to_hex(&actual),
            "02c0ded2bc1f1305fb0faac5e6c03ee3a1924234985427b6167ca569d13df435cfeb05f9d2"
        );

        let actual = from_base58("111z").unwrap();
        assert_eq!(to_hex(&actual), "00000039");

        let actual = to_base58(
            &from_hex("02c0ded2bc1f1305fb0faac5e6c03ee3a1924234985427b6167ca569d13df435cfeb05f9d2")
                .unwrap(),
        );
        assert_eq!(actual, "6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV");

        assert_eq!(to_base58(&[0, 0, 0, 4]), "1115");
    }

    #[test]
    fn test_ts_base58check() {
        // From utils.test.ts - base58check encoding and decoding
        let data = from_hex("f5f2d624cfb5c3f66d06123d0829d1c9cebf770e").unwrap();
        let encoded = to_base58_check(&data, &[0]);
        assert_eq!(encoded, "1PRTTaJesdNovgne6Ehcdu1fpEdX7913CK");

        let (version, decoded) = from_base58_check(&encoded).unwrap();
        assert_eq!(version, vec![0]);
        assert_eq!(decoded, data);

        // Custom prefix test
        let data =
            from_hex("1E99423A4ED27608A15A2616A2B0E9E52CED330AC530EDCC32C8FFC6A526AEDD").unwrap();
        let encoded = to_base58_check(&data, &[0x80]);
        assert_eq!(
            encoded,
            "5J3mBbAH58CpQ3Y5RNJpUKPE62SQ5tfcvU2JpbnkeyhfsYB1Jcn"
        );
    }

    #[test]
    fn test_ts_base64() {
        // From utils.test.ts - base64 decoding
        assert_eq!(from_base64("Zg==").unwrap(), vec![102]);
        assert_eq!(from_base64("Zm8=").unwrap(), vec![102, 111]);
        assert_eq!(from_base64("Zm9v").unwrap(), vec![102, 111, 111]);
        assert_eq!(
            from_base64("SGVsbG8=").unwrap(),
            vec![72, 101, 108, 108, 111]
        );
    }

    #[test]
    fn test_ts_utf8() {
        // From utils.test.ts
        assert_eq!(to_utf8_bytes("1234"), vec![49, 50, 51, 52]);

        // Unicode: U+1234 in UTF-8 is [0xE1, 0x88, 0xB4]
        assert_eq!(to_utf8_bytes("\u{1234}"), vec![0xE1, 0x88, 0xB4]);

        // Mixed
        assert_eq!(
            to_utf8_bytes("\u{1234}234"),
            vec![0xE1, 0x88, 0xB4, 50, 51, 52]
        );
    }

    #[test]
    fn test_ts_reader() {
        // From Reader.test.ts
        let buf = vec![0];
        let mut reader = Reader::new(&buf);
        assert_eq!(reader.read_u8().unwrap(), 0);

        // ReadUInt16LE
        let buf = vec![1, 0];
        let mut reader = Reader::new(&buf);
        assert_eq!(reader.read_u16_le().unwrap(), 1);

        // ReadUInt32LE
        let buf = vec![1, 0, 0, 0];
        let mut reader = Reader::new(&buf);
        assert_eq!(reader.read_u32_le().unwrap(), 1);

        // ReadInt8 negative
        let buf = vec![0xFF];
        let mut reader = Reader::new(&buf);
        assert_eq!(reader.read_i8().unwrap(), -1);

        // ReadInt32LE negative
        let buf = vec![0xFF, 0xFF, 0xFF, 0xFF];
        let mut reader = Reader::new(&buf);
        assert_eq!(reader.read_i32_le().unwrap(), -1);
    }

    #[test]
    fn test_ts_writer() {
        // From Writer.test.ts
        let mut writer = Writer::new();
        writer.write_u8(1);
        assert_eq!(to_hex(writer.as_bytes()), "01");

        let mut writer = Writer::new();
        writer.write_i8(-1);
        assert_eq!(to_hex(writer.as_bytes()), "ff");

        let mut writer = Writer::new();
        writer.write_u16_le(1);
        assert_eq!(to_hex(writer.as_bytes()), "0100");

        let mut writer = Writer::new();
        writer.write_i16_le(-1);
        assert_eq!(to_hex(writer.as_bytes()), "ffff");

        let mut writer = Writer::new();
        writer.write_u32_le(1);
        assert_eq!(to_hex(writer.as_bytes()), "01000000");

        let mut writer = Writer::new();
        writer.write_i32_le(-1);
        assert_eq!(to_hex(writer.as_bytes()), "ffffffff");

        let mut writer = Writer::new();
        writer.write_u64_le(1);
        assert_eq!(to_hex(writer.as_bytes()), "0100000000000000");
    }

    #[test]
    fn test_ts_varint_writer() {
        // From Writer.test.ts
        let mut writer = Writer::new();
        writer.write_var_int(1);
        assert_eq!(writer.len(), 1);

        let mut writer = Writer::new();
        writer.write_var_int(1000);
        assert_eq!(writer.len(), 3);

        let mut writer = Writer::new();
        writer.write_var_int(2u64.pow(17));
        assert_eq!(writer.len(), 5);

        let mut writer = Writer::new();
        writer.write_var_int(2u64.pow(33));
        assert_eq!(writer.len(), 9);
    }

    #[test]
    fn test_ts_varint_reader() {
        // From Reader.test.ts
        let buf = vec![50];
        let mut reader = Reader::new(&buf);
        assert_eq!(reader.read_var_int().unwrap(), 50);

        let buf = vec![253, 253, 0];
        let mut reader = Reader::new(&buf);
        assert_eq!(reader.read_var_int().unwrap(), 253);

        let mut buf = vec![254, 0, 0, 0, 0];
        buf[1..5].copy_from_slice(&50000u32.to_le_bytes());
        let mut reader = Reader::new(&buf);
        assert_eq!(reader.read_var_int().unwrap(), 50000);
    }
}
