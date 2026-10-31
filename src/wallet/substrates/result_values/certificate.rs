//! `validateCertificate` (`WalletResultValidation.ts:1477-1537`). This is
//! structural validation, not verification of the certificate's signature.

use super::{invalid, member, record, Object, Result};
use crate::primitives::PublicKey;
use crate::wallet::{validation::crypto::is_canonical_der_signature, WalletCertificate};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::value::RawValue;

const MAX_CERTIFICATE_BYTES: usize = 16 * 1024 * 1024;

pub(super) fn validate(raw: Option<&RawValue>, call: &str, field: &str) -> Result<()> {
    // record() is outside the reference's catch: null is "an object".
    let values = record(raw, call, field)?;
    if read(&values).is_some_and(|certificate| canonical(&certificate)) {
        Ok(())
    } else {
        Err(invalid(
            call,
            field,
            "a canonical signed wallet certificate",
        ))
    }
}

/// Read the last occurrence of each field as `JSON.parse` does. A direct
/// struct deserializer rejects duplicate fields before #365's fallback.
fn read(values: &Object<'_>) -> Option<WalletCertificate> {
    fn field<T: serde::de::DeserializeOwned>(values: &Object<'_>, name: &str) -> Option<T> {
        serde_json::from_str(member(values, name)?.get()).ok()
    }
    Some(WalletCertificate {
        certificate_type: field(values, "type")?,
        subject: field(values, "subject")?,
        serial_number: field(values, "serialNumber")?,
        certifier: field(values, "certifier")?,
        revocation_outpoint: field(values, "revocationOutpoint")?,
        signature: field(values, "signature")?,
        fields: field(values, "fields")?,
    })
}

fn canonical(certificate: &WalletCertificate) -> bool {
    let fixed = [&certificate.certificate_type, &certificate.serial_number];
    if !fixed.iter().all(|value| base64_32(value)) {
        return false;
    }
    if ![&certificate.subject, &certificate.certifier]
        .iter()
        // isValidCompressedPublicKey refuses an x at or above p
        // (Secp256k1Validation.ts:15-22): the strict reader, not from_hex's (#498).
        .all(|key| {
            key.len() == 66
                && hex::decode(key).is_ok_and(|bytes| PublicKey::from_bytes(&bytes).is_ok())
        })
    {
        return false;
    }
    let Some(index) = revocation_index(&certificate.revocation_outpoint)
        .and_then(|index| usize::try_from(index).ok())
    else {
        return false;
    };
    let Ok(signature) = hex::decode(&certificate.signature) else {
        return false;
    };
    if !is_canonical_der_signature(&signature) {
        return false;
    }
    let mut length = 32 * 3 + 33 * 2 + compact_size(index);
    length += compact_size(certificate.fields.len()) + signature.len();
    for (name, value) in &certificate.fields {
        if !(1..=50).contains(&name.len()) {
            return false;
        }
        length = length.saturating_add(compact_size(name.len()) + name.len());
        length = length.saturating_add(compact_size(value.len()) + value.len());
    }
    length <= MAX_CERTIFICATE_BYTES
}

fn base64_32(value: &str) -> bool {
    STANDARD
        .decode(value)
        .is_ok_and(|bytes| bytes.len() == 32 && STANDARD.encode(bytes) == value)
}

fn revocation_index(value: &str) -> Option<u32> {
    let mut parts = value.split('.');
    let txid = parts.next()?;
    if txid.len() != 64 || !txid.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let index = parts.next().unwrap_or("0");
    if parts.next().is_some() || (index.len() > 1 && index.starts_with('0')) {
        return None;
    }
    if index.is_empty() || !index.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    index.parse().ok()
}

fn compact_size(value: usize) -> usize {
    match value {
        0..=252 => 1,
        253..=65535 => 3,
        65536..=0xffff_ffff => 5,
        _ => 9,
    }
}
