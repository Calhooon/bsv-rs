//! The wire's basic reads share ReaderUint8Array's short-read words (#458).
//! `ts-stack@edf6e03` `ReaderUint8Array.ts:38-46` checks every fixed-width
//! read, byte slice and CompactSize read, not only the header's originator.

use super::{Reader, WireReader};
use crate::Error;

fn underflow() -> Error {
    Error::WalletError("ReaderUint8Array read exceeds available data".into())
}

fn reference_error(error: Error) -> Error {
    match error {
        Error::ReaderUnderflow { .. } => underflow(),
        other => other,
    }
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

    /// Reads an unsigned byte.
    pub fn read_u8(&mut self) -> Result<u8, Error> {
        self.inner.read_u8().map_err(reference_error)
    }

    /// Reads a signed byte.
    pub fn read_i8(&mut self) -> Result<i8, Error> {
        self.inner.read_i8().map_err(reference_error)
    }

    /// Reads a 16-bit unsigned integer in little-endian.
    pub fn read_u16_le(&mut self) -> Result<u16, Error> {
        self.inner.read_u16_le().map_err(reference_error)
    }

    /// Reads a 32-bit unsigned integer in little-endian.
    pub fn read_u32_le(&mut self) -> Result<u32, Error> {
        self.inner.read_u32_le().map_err(reference_error)
    }

    /// Reads a 64-bit unsigned integer in little-endian.
    pub fn read_u64_le(&mut self) -> Result<u64, Error> {
        self.inner.read_u64_le().map_err(reference_error)
    }

    /// Reads a fixed number of bytes.
    pub fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], Error> {
        self.inner.read_bytes(len).map_err(reference_error)
    }

    /// Reads all remaining bytes.
    pub fn read_remaining(&mut self) -> &'a [u8] {
        self.inner.read_remaining()
    }

    /// Reads an unsigned varint.
    pub fn read_var_int(&mut self) -> Result<u64, Error> {
        self.inner.read_var_int().map_err(reference_error)
    }

    /// The reference's number precision check, before any length or count use.
    pub(crate) fn wire_number(value: u64) -> Result<u64, Error> {
        if value > super::super::MAX_SAFE_INTEGER {
            Err(Error::WalletError(
                "number too large to retain precision - use readVarIntBn".into(),
            ))
        } else {
            Ok(value)
        }
    }

    /// An unsigned `readVarIntNumStrict(false)` without platform narrowing.
    pub(crate) fn read_var_int_num_strict_u64(&mut self) -> Result<u64, Error> {
        Self::wire_number(self.read_var_int()?)
    }

    /// A collection length with the reference's signed -1 absence sentinel.
    pub(crate) fn read_optional_count(&mut self) -> Result<u64, Error> {
        let value = self.read_var_int()?;
        if value == u64::MAX {
            Ok(value)
        } else {
            Self::wire_number(value)
        }
    }

    /// Checks number precision, then the remaining bytes before narrowing.
    /// A safe length past `usize::MAX` on wasm32 uses the reader's refusal
    /// (#192); a length past `2^53 - 1` uses the precision refusal (#458).
    pub(crate) fn wire_length(&self, length: u64) -> Result<usize, Error> {
        Self::wire_number(length)?;
        match usize::try_from(length) {
            Ok(needed) if needed <= self.remaining() => Ok(needed),
            _ => Err(underflow()),
        }
    }
}
