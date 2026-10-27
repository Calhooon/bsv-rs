//! The checks [`IdentityClient::publicly_reveal_attributes`] makes around its
//! wallet calls, the reference's in its order and words (`ts-stack@edf6e03`
//! `packages/sdk/src/identity/IdentityClient.ts:420-499`; #307): the
//! certificate's fields and the names to reveal, then the master
//! certificate's signature, all before the wallet is asked for anything;
//! after `proveCertificate`, the keyring's names against the names asked
//! and each value's base64 form and size, the trimmed values published;
//! then the identity token, the PushDrop the subject signs (`:501-509`, #310).
//!
//! [`IdentityClient::publicly_reveal_attributes`]: super::IdentityClient::publicly_reveal_attributes

use crate::auth::certificates::Certificate;
use crate::error::WalletRefusalClass;
use crate::primitives::PublicKey;
use crate::script::templates::PushDrop;
use crate::script::LockingScript;
use crate::wallet::{
    Counterparty, CreateSignatureArgs, GetPublicKeyArgs, Protocol, WalletCertificate,
    WalletInterface,
};
use crate::{Error, Result};
use serde::{Serialize, Serializer};
use std::collections::{BTreeMap, HashMap, HashSet};

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

/// The wallet's keyring after `proveCertificate` (`IdentityClient.ts:478-499`):
/// a name `__proto__`, `constructor` or `prototype` refused first, as
/// `identityRecord` refuses it (`:480-483`, `:45-65`), whether or not the
/// count matches; then any other name than those asked, or one missing
/// (`:484-491`); then each value through [`keyring_value`] (`:492-499`).
/// The answer is the keyring with each value trimmed, the one the PushDrop
/// carries, in the order of the names asked. The reference judges and
/// publishes the values in the wallet's key order; the crate's keyring is a
/// map, so they are judged and published in the order of the names asked,
/// the reference's own wallet's order (`MasterCertificate.ts:348`, `:370`).
pub(super) fn check_keyring(
    keyring: &HashMap<String, String>,
    fields_to_reveal: &[String],
) -> Result<Vec<(String, String)>> {
    if keyring.keys().any(|k| is_unsafe_record_key(k)) {
        return Err(refused(
            "Invalid display identity: proof result keyringForVerifier contains an unsafe field",
        ));
    }
    let requested: HashSet<&str> = fields_to_reveal.iter().map(String::as_str).collect();
    if keyring.len() != requested.len() || keyring.keys().any(|k| !requested.contains(k.as_str())) {
        return Err(refused(
            "Public reveal failed: wallet returned a keyring for unrequested fields!",
        ));
    }
    fields_to_reveal
        .iter()
        .filter_map(|name| keyring.get_key_value(name))
        .map(|(name, value)| Ok((name.clone(), keyring_value(value, name)?)))
        .collect()
}

/// The most bytes a keyring value may decode to (`IdentityClient.ts:497`).
const MAX_KEYRING_VALUE_BYTES: usize = 2048;

/// The reference's `validateBase64String(value, 'keyringForVerifier.<name>',
/// 1, 2048)` (`validationHelpers.ts:488-498`, its helpers at `:439-476`):
/// the value trimmed as JavaScript's `trim` trims, then base64 by its
/// shape (letters, digits, `+`, `/`, at most two `=` at the end, a length
/// the padding allows) and 1 to 2048 bytes by `floor(3 * unpadded / 4)`,
/// nothing decoded. A refusal is `WERR_INVALID_PARAMETER` (code 6,
/// `WERR_INVALID_PARAMETER.ts`): `The keyringForVerifier.<name> parameter
/// must be valid base64 string`, `.. at least 1 bytes`, `.. no more than
/// 2048 bytes`. The answer is the trimmed text.
fn keyring_value(value: &str, name: &str) -> Result<String> {
    base64_parameter(
        value,
        &format!("keyringForVerifier.{name}"),
        1,
        MAX_KEYRING_VALUE_BYTES,
    )
}

/// `validateBase64String(value, parameter, min, max)`
/// (`validationHelpers.ts:439-498`): the value trimmed, base64 by its shape,
/// `min` to `max` bytes by `floor(3 * unpadded / 4)`; a refusal
/// `WERR_INVALID_PARAMETER` in its words. The revocation's serial number
/// too, 32 bytes exactly (`IdentityClient.ts:712-717`, #327).
pub(super) fn base64_parameter(
    value: &str,
    parameter: &str,
    min: usize,
    max: usize,
) -> Result<String> {
    let invalid = |must_be: &str| Error::WalletRefusal {
        class: WalletRefusalClass::InvalidParameter,
        message: format!("The {parameter} parameter must be {must_be}"),
    };
    let value = value.trim_matches(is_js_whitespace);
    let not_base64 = || invalid("valid base64 string");
    if value.is_empty() {
        return Err(not_base64());
    }
    let length = value.len();
    let mut padding = 0;
    for (index, byte) in value.bytes().enumerate() {
        if byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/' {
            continue;
        }
        if byte != b'=' || index + 2 < length {
            return Err(not_base64());
        }
        padding += 1;
    }
    let remainder = length % 4;
    if padding > 2
        || (padding > 0 && remainder != 0)
        || (remainder != 0 && remainder != 4 - padding)
    {
        return Err(not_base64());
    }
    let bytes = (length - padding) * 3 / 4;
    if bytes < min {
        return Err(invalid(&format!("at least {min} bytes")));
    }
    if bytes > max {
        return Err(invalid(&format!("no more than {max} bytes")));
    }
    Ok(value.to_string())
}

/// What JavaScript's `String.prototype.trim` removes: `WhiteSpace` and
/// `LineTerminator` (ECMA-262), Unicode's `White_Space` with U+FEFF and
/// without U+0085, which Rust's `char::is_whitespace` has the other way.
fn is_js_whitespace(c: char) -> bool {
    c == '\u{feff}' || (c.is_whitespace() && c != '\u{85}')
}

/// The certificate JSON the identity token carries, the reference's
/// `JSON.stringify({ ...certificate, keyring })` (`IdentityClient.ts:502`):
/// the wallet certificate's members in `WalletCertificate`'s order
/// (`Wallet.interfaces.ts:851`), then the keyring in the order of the names
/// asked. The fields are written by name, since the crate's map keeps no
/// order of the wallet's.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Published<'a> {
    #[serde(rename = "type")]
    certificate_type: &'a str,
    subject: &'a str,
    serial_number: &'a str,
    certifier: &'a str,
    revocation_outpoint: &'a str,
    signature: &'a str,
    fields: BTreeMap<&'a str, &'a str>,
    keyring: InOrder<'a>,
}

/// A keyring written in the order it is held.
struct InOrder<'a>(&'a [(String, String)]);

impl Serialize for InOrder<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.collect_map(self.0.iter().map(|(name, value)| (name, value)))
    }
}

/// The identity token, as the reference's `PushDrop.lock(fields, protocolID,
/// keyID, 'anyone', true, true)` builds it (`IdentityClient.ts:501-509`,
/// `PushDrop.ts:146-202`): the key `getPublicKey` answers for the client's
/// protocol and key ID, counterparty `anyone`, `forSelf: true`; the
/// certificate JSON and `createSignature`'s signature over it (the same
/// protocol, key ID and counterparty) pushed and dropped. The overlay's
/// identity reader asks this shape and that the key and signature be the
/// subject's under `[1, 'identity']` key `1` (`identityTokenValidation.ts:92-136`).
pub(super) async fn identity_token<W: WalletInterface + ?Sized>(
    wallet: &W,
    originator: &str,
    (level, name): (u8, &str),
    key_id: &str,
    certificate: &WalletCertificate,
    keyring: &[(String, String)],
) -> Result<LockingScript> {
    let published = Published {
        certificate_type: &certificate.certificate_type,
        subject: &certificate.subject,
        serial_number: &certificate.serial_number,
        certifier: &certificate.certifier,
        revocation_outpoint: &certificate.revocation_outpoint,
        signature: &certificate.signature,
        fields: certificate
            .fields
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect(),
        keyring: InOrder(keyring),
    };
    let json = serde_json::to_vec(&published)
        .map_err(|e| refused(format!("Failed to serialize certificate: {e}")))?;
    let protocol = Protocol::from_tuple((level, name))
        .ok_or_else(|| refused(format!("Invalid protocol ID: ({level}, {name})")))?;
    let key = wallet
        .get_public_key(
            GetPublicKeyArgs {
                protocol_id: Some(protocol.clone()),
                key_id: Some(key_id.to_string()),
                counterparty: Some(Counterparty::Anyone),
                for_self: Some(true),
                ..Default::default()
            },
            originator,
        )
        .await?;
    let signature = wallet
        .create_signature(
            CreateSignatureArgs {
                data: Some(json.clone()),
                protocol_id: protocol,
                key_id: key_id.to_string(),
                counterparty: Some(Counterparty::Anyone),
                ..Default::default()
            },
            originator,
        )
        .await?
        .signature;
    let key = PublicKey::from_hex(&key.public_key)?;
    Ok(PushDrop::new(key, vec![json, signature]).lock())
}
