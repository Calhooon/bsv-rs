//! The checks [`IdentityClient::publicly_reveal_attributes`] makes around its
//! wallet calls, the reference's in its order and words (`ts-stack@edf6e03`
//! `packages/sdk/src/identity/IdentityClient.ts:420-499`; #307): the
//! certificate's fields and the names to reveal, then the master
//! certificate's signature, all before the wallet is asked for anything;
//! after `proveCertificate`, the keyring's names against the names asked.
//!
//! [`IdentityClient::publicly_reveal_attributes`]: super::IdentityClient::publicly_reveal_attributes

use crate::auth::certificates::Certificate;
use crate::wallet::WalletCertificate;
use crate::{Error, Result};
use std::collections::{HashMap, HashSet};

/// The most names one reveal may ask for (`IdentityClient.ts:431-433`).
const MAX_FIELDS_TO_REVEAL: usize = 100;

/// The most UTF-8 bytes in a name to reveal (`IdentityClient.ts:439`,
/// `identityString` at `:89-102`).
const MAX_FIELD_NAME_BYTES: usize = 50;

fn refused(words: impl Into<String>) -> Error {
    Error::IdentityError(words.into())
}

/// The reference's `isUnsafeRecordKey` (`primitives/SafeRecord.ts`).
fn is_unsafe_record_key(key: &str) -> bool {
    matches!(key, "__proto__" | "constructor" | "prototype")
}

/// The reference's `hasUnsafeDisplayControl` (`IdentityClient.ts:70-87`);
/// every range is in the BMP, so a `char` reads as its UTF-16 unit does.
fn has_unsafe_display_control(value: &str) -> bool {
    value.chars().any(|c| {
        let code = c as u32;
        code < 9
            || (code > 10 && code < 13)
            || (code > 13 && code < 32)
            || code == 127
            || (0x200b..=0x200f).contains(&code)
            || (0x202a..=0x202e).contains(&code)
            || (0x2066..=0x2069).contains(&code)
            || code == 0xfeff
    })
}

/// Everything the reference refuses before `proveCertificate`
/// (`IdentityClient.ts:420-467`): the certificate's field names
/// (`identityRecord`, `:45-65`), its fields present, the names to reveal
/// (one to 100, each 1 to 50 bytes, no unsafe record key or display
/// control, no repeat, each a field of the certificate), then the master
/// certificate's signature, its failure in the reference's one sentence
/// whatever failed under it (`:451-467`).
pub(super) fn check_master_certificate(
    certificate: &WalletCertificate,
    fields_to_reveal: &[String],
) -> Result<()> {
    if certificate.fields.keys().any(|k| is_unsafe_record_key(k)) {
        return Err(refused(
            "Invalid display identity: certificate.fields contains an unsafe field",
        ));
    }
    if certificate.fields.is_empty() {
        return Err(refused(
            "Public reveal failed: Certificate has no fields to reveal!",
        ));
    }
    if fields_to_reveal.is_empty() {
        return Err(refused(
            "Public reveal failed: You must reveal at least one field!",
        ));
    }
    if fields_to_reveal.len() > MAX_FIELDS_TO_REVEAL {
        return Err(refused(
            "Public reveal failed: You may reveal at most 100 fields!",
        ));
    }
    let mut requested = HashSet::new();
    for (index, name) in fields_to_reveal.iter().enumerate() {
        if name.len() > MAX_FIELD_NAME_BYTES || has_unsafe_display_control(name) {
            return Err(refused(format!(
                "Invalid display identity: fieldsToReveal[{index}] is oversized or contains unsafe controls"
            )));
        }
        if name.is_empty() || is_unsafe_record_key(name) {
            return Err(refused(
                "Public reveal failed: invalid certificate field name!",
            ));
        }
        if !requested.insert(name.as_str()) {
            return Err(refused(
                "Public reveal failed: duplicate certificate field name!",
            ));
        }
        if !certificate.fields.contains_key(name) {
            return Err(refused(
                "Public reveal failed: requested field is not present in the certificate!",
            ));
        }
    }
    if !master_signature_verifies(certificate) {
        return Err(refused(
            "Public reveal failed: Certificate verification failed!",
        ));
    }
    Ok(())
}

/// The reference builds a `Certificate` of the wallet certificate's members
/// and asks `verify` (`IdentityClient.ts:451-467`); here the certificate is
/// read from the same members' JSON, a member it cannot hold a `false`.
fn master_signature_verifies(certificate: &WalletCertificate) -> bool {
    serde_json::to_value(certificate)
        .and_then(serde_json::from_value::<Certificate>)
        .is_ok_and(|master| matches!(master.verify(), Ok(true)))
}

/// The wallet's keyring names exactly the names asked
/// (`IdentityClient.ts:487-491`); the reference's base64 bound on each
/// value (`:492-499`) is not followed (the changelog's #307 note).
pub(super) fn check_keyring_fields(
    keyring: &HashMap<String, String>,
    fields_to_reveal: &[String],
) -> Result<()> {
    let requested: HashSet<&str> = fields_to_reveal.iter().map(String::as_str).collect();
    if keyring.len() != requested.len() || keyring.keys().any(|k| !requested.contains(k.as_str())) {
        return Err(refused(
            "Public reveal failed: wallet returned a keyring for unrequested fields!",
        ));
    }
    Ok(())
}
