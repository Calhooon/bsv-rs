//! The record checks the reference's discovery runs on a revelation token
//! before it authenticates it (#553): the toolbox's `decodeIdentityOutput`
//! (`ts-stack@edf6e03`
//! `wallet-toolbox/src/utility/identityUtils.ts:497-522`), which the SDK's
//! `IdentityClient` reaches through its wallet's `discoverByIdentityKey` and
//! `discoverByAttributes` (`IdentityClient.ts:559-655`; the toolbox's
//! `Wallet.ts:904-1010`, `parseResults`, `identityUtils.ts:671-707`): two
//! fields, the certificate 1 to 256 KiB, the signature 8 to 80 bytes, then
//! `certificateRecord` (`:87-132`): the text read as `toUTF8Strict` reads it
//! (a leading byte-order mark dropped, `TextDecoder`'s default), a JSON
//! object of the eight members and no other, `fields` and `keyring` objects
//! of 1 to 100 names each, every keyring name a field's, every keyring value
//! a string of at most 2048 UTF-16 units. A record that fails is skipped, as
//! every failure in `decodeIdentityOutput` is (`:555-557`), and so is one
//! whose members do not read as a certificate (`:540-550`, `verify` false).
//! That `verify` is `Certificate.toBinary` under a catch (`ts-stack@edf6e03`
//! `packages/sdk/src/auth/certificates/Certificate.ts:425-440`), so its text
//! rules are the record's too: `type` and `serialNumber` canonical base64 of
//! 32 bytes (`:233-238`, `WalletByteEncoding.ts:39-64`), the revocation
//! outpoint a string of a 64-hex txid and an optional plain decimal index
//! (`:257-270`), every field value a string (`:281`, `:63-72`).

use super::super::token_maps::{self, TokenMaps};
use crate::auth::certificates::revocation_outpoint_from_str;
use crate::primitives::{from_hex, PublicKey};
use crate::wallet::types::Outpoint;
use serde_json::{Map, Value};

#[path = "client_record_lenient.rs"]
mod lenient;

/// `MAX_IDENTITY_CERTIFICATE_BYTES` (`identityUtils.ts:23`).
const MAX_CERTIFICATE_BYTES: usize = 256 * 1024;
/// `MAX_IDENTITY_FIELDS` (`identityUtils.ts:24`).
const MAX_FIELDS: usize = 100;
/// The keyring value's bound in UTF-16 units (`identityUtils.ts:127`).
const MAX_KEYRING_VALUE_UNITS: usize = 2048;
/// The members `certificateRecord` allows and requires (`:90-99`).
const MEMBERS: [&str; 8] = [
    "type",
    "serialNumber",
    "subject",
    "certifier",
    "revocationOutpoint",
    "fields",
    "keyring",
    "signature",
];

/// A revelation token's certificate, its members read.
pub(in crate::identity) struct Record {
    pub(in crate::identity) cert_type: [u8; 32],
    pub(in crate::identity) serial_number: [u8; 32],
    pub(in crate::identity) subject: PublicKey,
    pub(in crate::identity) certifier: PublicKey,
    pub(in crate::identity) revocation_outpoint: Option<Outpoint>,
    pub(in crate::identity) signature: Option<Vec<u8>>,
    pub(in crate::identity) maps: TokenMaps,
}

/// The token's certificate when its fields pass the reference's bounds and
/// its first field the reference's record checks; `None` skips the token.
pub(in crate::identity) fn read(fields: &[Vec<u8>]) -> Option<Record> {
    let [certificate, signature] = fields else {
        return None;
    };
    if !(1..=MAX_CERTIFICATE_BYTES).contains(&certificate.len())
        || !(8..=80).contains(&signature.len())
    {
        return None;
    }
    let bytes = certificate
        .strip_prefix(&[0xef, 0xbb, 0xbf])
        .unwrap_or(certificate);
    let text = std::str::from_utf8(bytes).ok()?;
    let (object, maps) = match serde_json::from_str::<Value>(text) {
        Ok(Value::Object(object)) => (object, token_maps::read(text)),
        Ok(_) => return None,
        // A lone surrogate escape `JSON.parse` keeps and a `String` cannot (#566)
        Err(_) => lenient::read(text)?,
    };
    if !is_certificate_record(&object) {
        return None;
    }
    members(&object, maps)
}

/// `certificateRecord`'s member set, cardinality and keyring checks.
fn is_certificate_record(object: &Map<String, Value>) -> bool {
    if object.len() != MEMBERS.len() || !MEMBERS.iter().all(|m| object.contains_key(*m)) {
        return false;
    }
    let (Some(Value::Object(fields)), Some(Value::Object(keyring))) =
        (object.get("fields"), object.get("keyring"))
    else {
        return false;
    };
    let cardinality = 1..=MAX_FIELDS;
    // Every field value a string, as `snapshotCertificateFields` asks
    // (`Certificate.ts:63-72`), where the maps' reader drops one that is not
    fields.values().all(Value::is_string)
        && cardinality.contains(&fields.len())
        && cardinality.contains(&keyring.len())
        && keyring.iter().all(|(name, value)| {
            fields.contains_key(name)
                && value
                    .as_str()
                    .is_some_and(|key| key.encode_utf16().count() <= MAX_KEYRING_VALUE_UNITS)
        })
}

/// The members a certificate is built from; one that does not read as the
/// reference's `Certificate` would have it skips the token.
fn members(object: &Map<String, Value>, maps: TokenMaps) -> Option<Record> {
    let text = |name: &str| object.get(name).and_then(Value::as_str);
    let id = |name: &str| canonical_id(text(name)?);
    Some(Record {
        cert_type: id("type")?,
        serial_number: id("serialNumber")?,
        // Strictly, as Certificate.verify's toBinary refuses a lenient form (#498)
        subject: PublicKey::from_strict_hex(text("subject")?).ok()?,
        certifier: PublicKey::from_strict_hex(text("certifier")?).ok()?,
        revocation_outpoint: Some(outpoint(text("revocationOutpoint")?)?),
        // Hex, as the reference's WalletCertificate carries it; one that is
        // not fails the verification after (`IdentityClient.ts:823-825`)
        signature: text("signature").and_then(|s| from_hex(s).ok()),
        maps,
    })
}

/// `assertCanonicalBase64Length` (`Certificate.ts:30-43`): padded, no
/// whitespace, no URL alphabet, the unused bits zero, 32 bytes.
fn canonical_id(text: &str) -> Option<[u8; 32]> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    let bytes = STANDARD.decode(text).ok()?;
    (STANDARD.encode(&bytes) == text).then_some(())?;
    bytes.try_into().ok()
}

/// The revocation outpoint as `toBinary` reads it (`Certificate.ts:257-270`):
/// at most one dot, a txid of 64 hex characters, the index `0` or a decimal
/// without a sign or a leading zero, at most `0xffffffff`, absent read as 0.
fn outpoint(text: &str) -> Option<Outpoint> {
    let mut parts = text.split('.');
    let txid = parts.next()?;
    let index = parts.next().unwrap_or("0");
    let plain = index == "0"
        || (index.starts_with(|c: char| ('1'..='9').contains(&c))
            && index.bytes().all(|b| b.is_ascii_digit()));
    if parts.next().is_some()
        || txid.len() != 64
        || !txid.bytes().all(|b| b.is_ascii_hexdigit())
        || !plain
    {
        return None;
    }
    let index: u32 = index.parse().ok()?;
    revocation_outpoint_from_str(&format!("{txid}.{index}")).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_outpoint_reads_as_certificate_to_binary_reads_it_553() {
        let txid = "ab".repeat(32);
        for (index, vout) in [("", Some(0)), (".0", Some(0)), (".7", Some(7))] {
            let read = outpoint(&format!("{txid}{index}")).map(|o| o.vout);
            assert_eq!(read, vout, "{index:?}");
        }
        assert_eq!(
            outpoint(&format!("{txid}.4294967295")).map(|o| o.vout),
            Some(u32::MAX)
        );
        for index in [
            ".00",
            ".+0",
            ".-0",
            ". 1",
            ".",
            ".1.2",
            ".4294967296",
            ".1e3",
        ] {
            assert!(outpoint(&format!("{txid}{index}")).is_none(), "{index:?}");
        }
        for text in [
            "",
            "ab",
            &"ab".repeat(33),
            &format!("{}.0", "zz".repeat(32)),
        ] {
            assert!(outpoint(text).is_none(), "{text:?}");
        }
    }

    #[test]
    fn a_certificate_id_is_canonical_base64_of_32_bytes_553() {
        let padded = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
        assert_eq!(canonical_id(padded), Some([1; 32]));
        let unpadded = padded.trim_end_matches('=');
        let spaced = format!("{} {}", &padded[..4], &padded[4..]);
        // The unused bits set: `E=` ends 0b0100, `F=` 0b0101
        let trailing_bits = padded.replace("E=", "F=");
        let url = "_".repeat(43) + "=";
        let short = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB";
        for text in [unpadded, &spaced, &trailing_bits, &url, short, ""] {
            assert_eq!(canonical_id(text), None, "{text:?}");
        }
    }
}
