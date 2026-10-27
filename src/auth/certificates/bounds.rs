//! The reference's certificate bounds and its decrypt error wrappers, each
//! in its words (`ts-stack@edf6e03` `Certificate.ts`, `MasterCertificate.ts`,
//! `VerifiableCertificate.ts`; bsv-rs#275, bsv-rs#297).
//!
//! go-sdk@2ca481c carries none of these bounds (`auth/certificates/*.go`
//! checks no field count, keyring entry size or plaintext size) and wraps a
//! decrypt failure in its own words (`ErrFieldDecryption`, `master.go:22`).

use crate::wallet::wire::{
    certificate_binary_read_refusal, certificate_binary_written_refusal,
    certificate_field_value_refusal, reference_der, CERTIFICATE_SIGNATURE_DER_LIMIT_REFUSAL,
    MAX_CERTIFICATE_BINARY_BYTES, MAX_CERTIFICATE_FIELDS, MAX_CERTIFICATE_FIELD_VALUE_BYTES,
    MAX_CERTIFICATE_SIGNATURE_BYTES,
};
use crate::{Error, Result};
use std::collections::HashMap;

/// A master certificate's fields, its keyring's entries and the fields to
/// reveal: at most 100 (`MasterCertificate.ts:18`); a verifier's keyring
/// likewise (`VerifiableCertificate.ts:17`).
pub(crate) const MAX_RECORD_ENTRIES: usize = 100;
/// A keyring entry's ciphertext (`MasterCertificate.ts:19`,
/// `VerifiableCertificate.ts:18`).
pub(crate) const MAX_KEYRING_VALUE_BYTES: usize = 2048;
/// A field's plaintext (`MasterCertificate.ts:21`, `VerifiableCertificate.ts:20`).
pub(crate) const MAX_DECRYPTED_FIELD_BYTES: usize = 64 * 1024;

/// `MasterCertificate.decryptField`'s wrapper (`MasterCertificate.ts:621-623`).
pub(crate) const MASTER_FIELD_DECRYPT_FAILED: &str = "Failed to decrypt certificate field!";
/// `MasterCertificate.decryptFields`'s wrapper (`MasterCertificate.ts:559-561`).
pub(crate) const MASTER_FIELDS_DECRYPT_FAILED: &str =
    "Failed to decrypt all master certificate fields.";

/// A certificate refusal in the reference's words.
pub(crate) fn refused(words: impl Into<String>) -> Error {
    Error::CertificateValidationError(words.into())
}

/// The words a wrapper quotes: a certificate refusal's own text; the
/// cipher's two refusals in the reference's (`SymmetricKey.ts:205`, a
/// ciphertext shorter than its IV and tag, the only length this path's
/// `decrypt`s refuse; `:217`, `:232`, the tag not matching); else the error
/// as this crate prints it (a plaintext that is not UTF-8 is refused in the
/// platform's words on both sides, Node's `TextDecoder` there).
fn message(error: &Error) -> String {
    match error {
        Error::CertificateValidationError(words) => words.clone(),
        Error::InvalidDataLength { .. } => "Ciphertext too short".to_string(),
        Error::DecryptionFailed => "Decryption failed!".to_string(),
        other => other.to_string(),
    }
}

/// `VerifiableCertificate.decryptFields`'s wrapper, the failure's words
/// quoted (`VerifiableCertificate.ts:214-217`).
pub(crate) fn verifiable_decrypt_failed(error: &Error) -> Error {
    refused(format!(
        "Failed to decrypt selectively revealed certificate fields using keyring: {}",
        message(error)
    ))
}

/// `canonicalBase64` (`MasterCertificate.ts:63-74`,
/// `VerifiableCertificate.ts:41-52`): canonical base64 (padded, no
/// whitespace, no URL alphabet, the unused bits zero,
/// `WalletByteEncoding.ts:39-64`) of 1 to `maximum` bytes, or refused.
pub(crate) fn canonical_base64(value: &str, what: &str, maximum: usize) -> Result<Vec<u8>> {
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|_| refused(format!("{what} must use canonical base64 encoding")))?;
    if decoded.is_empty() || decoded.len() > maximum {
        return Err(refused(format!(
            "{what} is empty, oversized, or non-canonical"
        )));
    }
    Ok(decoded)
}

/// A keyring entry's ciphertext, canonical base64 of 1 to 2048 bytes;
/// `what` is the keyring's name in the reference's words (`Master
/// certificate keyring field`, `Certificate keyring field`).
pub(crate) fn keyring_ciphertext(what: &str, field_name: &str, value: &str) -> Result<Vec<u8>> {
    canonical_base64(
        value,
        &format!("{what} {field_name}"),
        MAX_KEYRING_VALUE_BYTES,
    )
}

/// `denseBytes` with a maximum (`MasterCertificate.ts:81-101`): 1 to
/// `maximum` bytes, or refused.
pub(crate) fn dense_bytes(bytes: Vec<u8>, what: &str, maximum: usize) -> Result<Vec<u8>> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(refused(format!(
            "{what} must be a non-empty byte array of at most {maximum} bytes"
        )));
    }
    Ok(bytes)
}

/// `isUnsafeRecordKey` (`SafeRecord.ts`).
fn is_unsafe_record_key(key: &str) -> bool {
    matches!(key, "__proto__" | "constructor" | "prototype")
}

/// A name of 1 to 50 bytes that is no unsafe record key.
pub(crate) fn is_safe_field_name(name: &str) -> bool {
    (1..=50).contains(&name.len()) && !is_unsafe_record_key(name)
}

/// The master certificate's `assertCertificateFieldName`
/// (`MasterCertificate.ts:23-29`).
pub(crate) fn require_master_field_name(name: &str) -> Result<()> {
    if !is_safe_field_name(name) {
        return Err(refused(
            "Certificate field name must be a safe UTF-8 string of 1–50 bytes",
        ));
    }
    Ok(())
}

/// A record's names in byte order: the reference walks its own key order,
/// this crate's map has none, so a refusal among several names is the
/// first in byte order.
fn sorted_names(record: &HashMap<String, String>) -> Vec<&str> {
    let mut names: Vec<&str> = record.keys().map(String::as_str).collect();
    names.sort_unstable();
    names
}

/// `snapshotStringRecord` (`MasterCertificate.ts:31-61`): at most 100
/// entries, each name safe and 1 to 50 bytes.
pub(crate) fn snapshot_record(record: &HashMap<String, String>, what: &str) -> Result<()> {
    if record.len() > MAX_RECORD_ENTRIES {
        return Err(refused(format!(
            "{what} cannot contain more than {MAX_RECORD_ENTRIES} entries"
        )));
    }
    sorted_names(record)
        .into_iter()
        .try_for_each(require_master_field_name)
}

/// `snapshotFieldsToReveal` (`MasterCertificate.ts:125-146`): at most 100
/// names, each safe and 1 to 50 bytes, none twice.
pub(crate) fn snapshot_fields_to_reveal(fields_to_reveal: &[String]) -> Result<()> {
    if fields_to_reveal.len() > MAX_RECORD_ENTRIES {
        return Err(refused(format!(
            "fieldsToReveal must be an array of at most {MAX_RECORD_ENTRIES} strings"
        )));
    }
    let mut seen = std::collections::HashSet::new();
    for name in fields_to_reveal {
        require_master_field_name(name)?;
        if !seen.insert(name.as_str()) {
            return Err(refused(format!(
                "fieldsToReveal contains duplicate field: {name}"
            )));
        }
    }
    Ok(())
}

/// `createKeyringForVerifier`'s checks ahead of the first decrypt
/// (`MasterCertificate.ts:348-365`): the fields to reveal, both records
/// snapshotted, every field's text canonical base64 of 1 byte to 1 MiB
/// (bsv-rs#275) and every keyring entry's of 1 to 2048 bytes, revealed or not.
pub(crate) fn require_keyring_for_verifier_inputs(
    fields: &HashMap<String, String>,
    fields_to_reveal: &[String],
    master_keyring: &HashMap<String, String>,
) -> Result<()> {
    snapshot_fields_to_reveal(fields_to_reveal)?;
    snapshot_record(fields, "Certificate fields")?;
    snapshot_record(master_keyring, "Master certificate keyring")?;
    for name in sorted_names(fields) {
        field_ciphertext(name, &fields[name])?;
    }
    for name in sorted_names(master_keyring) {
        keyring_ciphertext(
            "Master certificate keyring field",
            name,
            &master_keyring[name],
        )?;
    }
    Ok(())
}

/// A field to reveal, present and not empty (`MasterCertificate.ts:371-380`).
pub(crate) fn field_to_reveal<'a>(
    fields: &'a HashMap<String, String>,
    field_name: &str,
) -> Result<&'a String> {
    fields
        .get(field_name)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            refused(format!(
                "Fields to reveal must be a subset of the certificate fields. Missing the \"{field_name}\" field."
            ))
        })
}

/// The `MasterCertificate` constructor's checks (`MasterCertificate.ts:195-233`):
/// both records snapshotted, every field with a non-empty keyring entry, its
/// text canonical base64 of 1 byte to 1 MiB and the entry's of 1 to 2048
/// bytes, then every keyring entry so.
pub(crate) fn require_master_certificate(
    fields: &HashMap<String, String>,
    master_keyring: &HashMap<String, String>,
) -> Result<()> {
    snapshot_record(fields, "Certificate fields")?;
    snapshot_record(master_keyring, "Master certificate keyring")?;
    for name in sorted_names(fields) {
        let entry = master_keyring
            .get(name)
            .filter(|entry| !entry.is_empty())
            .ok_or_else(|| {
                refused(format!(
                    "Master keyring must contain a value for every field. Missing or empty key for field: \"{name}\"."
                ))
            })?;
        field_ciphertext(name, &fields[name])?;
        keyring_ciphertext("Master certificate keyring field", name, entry)?;
    }
    for name in sorted_names(master_keyring) {
        keyring_ciphertext(
            "Master certificate keyring field",
            name,
            &master_keyring[name],
        )?;
    }
    Ok(())
}

/// A field value's ciphertext: the value held is the ciphertext's base64
/// text (BRC-52 `0052.md:97`), decoded here, at decrypt time, and nowhere
/// earlier (#261), as the reference's `canonicalBase64` decodes it (called
/// at `MasterCertificate.ts:215-219`, `:352-356`, `:534-538`, `:587-591`;
/// `VerifiableCertificate.ts:187-191`): 1 byte to 1 MiB (bsv-rs#275).
pub(crate) fn field_ciphertext(field_name: &str, field_value: &str) -> Result<Vec<u8>> {
    canonical_base64(
        field_value,
        &format!("Certificate field {field_name}"),
        MAX_CERTIFICATE_FIELD_VALUE_BYTES,
    )
}

/// `Certificate.toBinary`'s field checks (`Certificate.ts:281-297`, the
/// snapshot `:44-84`): at most 100,000 fields, then each name 1 to 50 bytes
/// and safe (`assertCertificateFieldName`, `:117-126`) and its value at most
/// 1 MiB, before anything is written; the names returned in the signed order.
pub(crate) fn checked_field_names(fields: &HashMap<String, String>) -> Result<Vec<&str>> {
    if fields.len() > MAX_CERTIFICATE_FIELDS {
        return Err(refused(format!(
            "Certificate field count exceeds the maximum of {MAX_CERTIFICATE_FIELDS}"
        )));
    }
    let mut names: Vec<&str> = fields.keys().map(String::as_str).collect();
    crate::wallet::collation::sort_field_names(&mut names);
    for &name in &names {
        if !(1..=50).contains(&name.len()) {
            return Err(refused(format!(
                "Invalid certificate field name length: expected 1–50 bytes, received {}",
                name.len()
            )));
        }
        require_safe_field_name(name)?;
        if fields[name].len() > MAX_CERTIFICATE_FIELD_VALUE_BYTES {
            return Err(refused(certificate_field_value_refusal(name)));
        }
    }
    Ok(names)
}

/// `Certificate.fromBinary`'s field count (`Certificate.ts:357-363`): at most
/// 100,000, and no more than a third of the bytes remaining after it.
pub(crate) fn require_field_count(count: usize, remaining: usize) -> Result<()> {
    if count > MAX_CERTIFICATE_FIELDS {
        return Err(refused(format!(
            "Certificate field count exceeds the maximum of {MAX_CERTIFICATE_FIELDS}"
        )));
    }
    if count > remaining / 3 {
        return Err(refused(
            "Certificate field count exceeds the available data",
        ));
    }
    Ok(())
}

/// `Certificate.fromBinary`'s declared name length, 1 to 50, before the
/// name is read (`Certificate.ts:367-370`).
pub(crate) fn require_field_name_length(length: usize) -> Result<()> {
    if !(1..=50).contains(&length) {
        return Err(refused(format!(
            "Invalid certificate field name length: received {length}"
        )));
    }
    Ok(())
}

/// `assertCertificateFieldName`'s safety (`Certificate.ts:124-126`).
pub(crate) fn require_safe_field_name(name: &str) -> Result<()> {
    if is_unsafe_record_key(name) {
        return Err(refused(format!("Unsafe certificate field name: {name}")));
    }
    Ok(())
}

/// `Certificate.toBinary`'s frame, its length taken once it is written
/// (`Certificate.ts:315-319`): at most 16 MiB (bsv-rs#301).
pub(crate) fn require_written_frame(length: usize) -> Result<()> {
    if length > MAX_CERTIFICATE_BINARY_BYTES {
        return Err(refused(certificate_binary_written_refusal()));
    }
    Ok(())
}

/// `Certificate.fromBinary`'s frame, before a byte is read
/// (`snapshotCertificateBinary`, `Certificate.ts:87-91`): at most 16 MiB
/// (bsv-rs#301).
pub(crate) fn require_read_frame(length: usize) -> Result<()> {
    if length > MAX_CERTIFICATE_BINARY_BYTES {
        return Err(refused(certificate_binary_read_refusal()));
    }
    Ok(())
}

/// `Certificate.toBinary`'s signature, at most 72 bytes, checked as the
/// reference checks its hex, at most 144 characters, before it is written
/// (`Certificate.ts:300-307`; bsv-rs#301).
pub(crate) fn require_written_signature(signature: &[u8]) -> Result<()> {
    if signature.len() > MAX_CERTIFICATE_SIGNATURE_BYTES {
        return Err(refused("Invalid certificate signature encoding"));
    }
    Ok(())
}

/// `Signature.fromDER` then `toDER` on a certificate's signature, the
/// wire's reading (`wallet::wire::reference_der`, one function) in this
/// type's class: `toBinary` parses it and writes the bytes given
/// (`Certificate.ts:309-311`), `fromBinary` keeps the re-encoding
/// (`:395-397`), `verify` verifies what it parses (`:432-435`; bsv-rs#305).
pub(crate) fn der_signature(signature: &[u8]) -> Result<Vec<u8>> {
    reference_der(signature).map_err(refused)
}

/// `Certificate.fromBinary`'s signature, the bytes after the fields, at
/// most 72 before they are read (`Certificate.ts:390-394`; bsv-rs#301).
pub(crate) fn require_read_signature(remaining: usize) -> Result<()> {
    if remaining > MAX_CERTIFICATE_SIGNATURE_BYTES {
        return Err(refused(CERTIFICATE_SIGNATURE_DER_LIMIT_REFUSAL));
    }
    Ok(())
}
