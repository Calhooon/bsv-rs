//! The key strings `PublicKey::from_hex` reads: the reference's (#498).
//!
//! `PublicKey.fromString` at `ts-stack@edf6e03` (`PublicKey.ts:49-51`) is
//! `Point.fromString` (`Point.ts:345-348`): the text decoded as hex with an
//! odd-length string padded by a leading `0` (`utils.ts:127-128`, the rule of
//! `hex.ts:27-29`), then `Point.fromDER` (`Point.ts:303-325`): a hybrid key
//! (`06`/`07` + x + y) accepted when the prefix's low bit is the low bit of y's
//! last byte as written, an x of a compressed key reduced modulo p by
//! `Point.fromX` (`Point.ts:365-384`), and the coordinates of an uncompressed or
//! hybrid key judged modulo p by `Point.validate` (`Point.ts:495-510`). The point
//! held is the reduced one, so `to_hex` writes the strict form back.
//!
//! The keeper's word (2026-10-30 05:1xZ, #498): accept as the reference does,
//! the question upstream; strictness returns on the upstream's answer, and the
//! strict reading is `PublicKey::from_bytes` of the decoded bytes.

use super::PublicKey;
use crate::error::{Error, Result};
use crate::primitives::encoding::from_hex;
use crate::primitives::BigNumber;

/// Decodes `text` as the reference's `toArray(text, 'hex')` does: an
/// odd-length string read with a leading `0`, a refused character named at its
/// place in `text`. The PushDrop sites decode a wallet's key text with it
/// (#545).
pub(crate) fn reference_hex(text: &str) -> Result<Vec<u8>> {
    if text.len().is_multiple_of(2) {
        return from_hex(text);
    }
    hex::decode(format!("0{text}")).map_err(|error| {
        Error::InvalidHex(match error {
            hex::FromHexError::InvalidHexCharacter { c, index } => {
                hex::FromHexError::InvalidHexCharacter {
                    c,
                    index: index - 1,
                }
                .to_string()
            }
            other => other.to_string(),
        })
    })
}

/// A 32-byte big-endian coordinate reduced modulo the field prime.
fn reduced(coordinate: &[u8]) -> Vec<u8> {
    BigNumber::from_bytes_be(coordinate)
        .modulo(&BigNumber::secp256k1_prime())
        .to_bytes_be(32)
}

/// Reads key bytes as `Point.fromDER` does; a refusal keeps the strict
/// parser's words and error class (`Error::InvalidPublicKey`).
pub(crate) fn from_reference_der(bytes: &[u8]) -> Result<PublicKey> {
    let mut strict = Vec::with_capacity(bytes.len());
    match (bytes.len(), bytes.first().copied(), bytes.last().copied()) {
        (65, Some(prefix @ (4 | 6 | 7)), Some(last)) => {
            if prefix != 4 && (prefix & 1) != (last & 1) {
                return PublicKey::from_bytes(bytes);
            }
            strict.push(4);
            strict.extend(reduced(&bytes[1..33]));
            strict.extend(reduced(&bytes[33..65]));
        }
        (33, Some(prefix @ (2 | 3)), _) => {
            strict.push(prefix);
            strict.extend(reduced(&bytes[1..33]));
        }
        _ => {
            // Every other shape is the reference's `Unknown point format`; the
            // strict parser refuses it too (the compact `05` since #550), in
            // k256's words where it does.
            return PublicKey::from_bytes(bytes).and(Err(Error::InvalidPublicKey(
                "Invalid public key encoding: unknown point format".to_string(),
            )));
        }
    }
    PublicKey::from_bytes(&strict)
}

/// `PublicKey::from_hex`: the reference's `PublicKey.fromString`.
pub(super) fn from_reference_hex(text: &str) -> Result<PublicKey> {
    from_reference_der(&reference_hex(text)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GX: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    #[test]
    fn an_odd_length_refusal_names_the_character_at_its_place_498() {
        assert_eq!(
            reference_hex("not-hex").unwrap_err(),
            Error::InvalidHex("Invalid character 'n' at position 0".into())
        );
        assert_eq!(
            reference_hex(&format!("2{}g", &GX[..63])).unwrap_err(),
            Error::InvalidHex("Invalid character 'g' at position 64".into())
        );
        assert_eq!(reference_hex("abc").unwrap(), vec![0x0a, 0xbc]);
    }

    #[test]
    fn a_shape_the_reference_does_not_read_is_refused_whatever_k256_reads_498() {
        for bytes in [
            vec![],
            vec![0],
            vec![2],
            from_hex(&format!("05{GX}")).unwrap(),
        ] {
            assert!(matches!(
                from_reference_der(&bytes),
                Err(Error::InvalidPublicKey(_))
            ));
        }
    }
}
