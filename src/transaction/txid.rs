//! A transaction id as a value (#845).
//!
//! [`Txid`] holds the 32 bytes of a transaction id in wire order: the order
//! of [`Transaction::hash`](super::Transaction::hash) and of an outpoint in a
//! serialized transaction. Text becomes a `Txid` only through
//! [`Txid::from_hex`] (and `FromStr`), which takes exactly 64 hex digits, so
//! a text that names no transaction id cannot be held where one is written:
//! until #845 an input's `source_txid` was a `String` nothing checked, and
//! the serializer wrote one it could not read as 32 zero bytes.
//!
//! The byte doors name their order and there is no `From<[u8; 32]>`: a
//! display-order array handed to a wire-order door type-checks and names
//! another transaction.

use std::fmt;
use std::str::FromStr;

use crate::{Error, Result};

/// The refusal of a text that is not 64 hex digits, the reference's words
/// under `label` (`requireTXID`, `ts-stack@edf6e03` `Transaction.ts:95-100`).
fn not_a_txid(label: &str) -> Error {
    Error::TransactionError(format!(
        "{label} must be a 32-byte hexadecimal transaction ID."
    ))
}

/// A transaction id: 32 bytes, held in wire order.
///
/// # Example
///
/// ```
/// use bsv_rs::transaction::Txid;
///
/// let text = "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16";
/// let txid = Txid::from_hex(text).unwrap();
/// assert_eq!(txid.to_string(), text);
/// // The display text is the wire bytes reversed.
/// assert_eq!(txid.as_wire_bytes()[0], 0x16);
/// assert_eq!(txid.to_display_bytes()[0], 0xf4);
/// // Upper case names the same id; anything but 64 hex digits is refused.
/// assert_eq!(text.to_uppercase().parse::<Txid>().unwrap(), txid);
/// assert!(Txid::from_hex("abcd").is_err());
/// assert!(Txid::from_hex("").is_err());
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Txid([u8; 32]);

impl Txid {
    /// Reads a transaction id from its display text: exactly 64 hex digits,
    /// either case, nothing trimmed.
    ///
    /// # Errors
    ///
    /// `Error::TransactionError("txid must be a 32-byte hexadecimal
    /// transaction ID.")` for any other text; the text is not echoed.
    pub fn from_hex(text: &str) -> Result<Self> {
        Self::named(text, "txid")
    }

    /// [`Txid::from_hex`], the refusal naming `label` (the reference's
    /// `requireTXID(value, label)`).
    pub(crate) fn named(text: &str, label: &str) -> Result<Self> {
        let digits = text.as_bytes();
        if digits.len() != 64 {
            return Err(not_a_txid(label));
        }
        let mut wire = [0u8; 32];
        let mut digits = digits.iter().copied().map(nibble);
        // Display order is the wire order reversed.
        for byte in wire.iter_mut().rev() {
            let (Some(Some(high)), Some(Some(low))) = (digits.next(), digits.next()) else {
                return Err(not_a_txid(label));
            };
            *byte = (high << 4) | low;
        }
        Ok(Self(wire))
    }

    /// The id whose wire-order bytes are `bytes` (a transaction's
    /// [`hash`](super::Transaction::hash), an outpoint as serialized).
    pub const fn from_wire_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The bytes in wire order.
    pub const fn as_wire_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The id whose display-order bytes are `bytes` (the decoded hex text).
    pub fn from_display_bytes(mut bytes: [u8; 32]) -> Self {
        bytes.reverse();
        Self(bytes)
    }

    /// The bytes in display order (the hex text, decoded).
    pub fn to_display_bytes(&self) -> [u8; 32] {
        let mut bytes = self.0;
        bytes.reverse();
        bytes
    }

    /// Whether every byte is zero: the txid of a coinbase input's outpoint.
    pub fn is_null(&self) -> bool {
        self.0 == [0u8; 32]
    }
}

/// One hex digit's value, either case.
fn nibble(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}

/// The display text: 64 lower-case hex digits.
impl fmt::Display for Txid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0.iter().rev() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Txid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Txid({self})")
    }
}

impl FromStr for Txid {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self> {
        Self::from_hex(text)
    }
}

/// A `Txid` against its display text, either case: `txid == "f418.."`.
impl PartialEq<str> for Txid {
    fn eq(&self, text: &str) -> bool {
        Self::from_hex(text).is_ok_and(|other| other == *self)
    }
}

impl PartialEq<&str> for Txid {
    fn eq(&self, text: &&str) -> bool {
        *self == **text
    }
}

impl PartialEq<String> for Txid {
    fn eq(&self, text: &String) -> bool {
        *self == **text
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEXT: &str = "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16";

    #[test]
    fn a_txid_reads_exactly_64_hex_digits_of_either_case_845() {
        let txid = Txid::from_hex(TEXT).unwrap();
        assert_eq!(txid.to_string(), TEXT);
        assert_eq!(Txid::from_hex(&TEXT.to_uppercase()).unwrap(), txid);
        assert_eq!(format!("{txid:?}"), format!("Txid({TEXT})"));
        for bad in [
            String::new(),
            "abcd".to_string(),
            "zz".to_string(),
            "a".repeat(63),
            "a".repeat(65),
            "aa".repeat(33),
            "zz".repeat(32),
            format!(" {}a ", "aa".repeat(31)),
            format!("0x{}", "aa".repeat(31)),
            format!("+{}", "a".repeat(63)),
            // 64 bytes, not 64 digits: a two-byte character among them.
            format!("é{}", "a".repeat(62)),
        ] {
            assert_eq!(
                Txid::from_hex(&bad),
                Err(Error::TransactionError(
                    "txid must be a 32-byte hexadecimal transaction ID.".to_string()
                )),
                "{bad:?}"
            );
            assert!(bad.parse::<Txid>().is_err());
            assert!(txid != bad);
        }
    }

    #[test]
    fn the_byte_doors_name_their_order_845() {
        let txid = Txid::from_hex(TEXT).unwrap();
        let display: [u8; 32] = hex::decode(TEXT).unwrap().try_into().unwrap();
        let mut wire = display;
        wire.reverse();
        assert_eq!(txid.as_wire_bytes(), &wire);
        assert_eq!(txid.to_display_bytes(), display);
        assert_eq!(Txid::from_wire_bytes(wire), txid);
        assert_eq!(Txid::from_display_bytes(display), txid);
        assert_ne!(Txid::from_wire_bytes(display), txid);
        assert!(!txid.is_null());
        assert!(Txid::from_wire_bytes([0; 32]).is_null());
        assert!(txid == TEXT && txid == *TEXT && txid == TEXT.to_uppercase());
    }
}
