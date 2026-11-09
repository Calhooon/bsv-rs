//! The reference overlay's question bounds, refused before the network (#756):
//! `IdentityClient::query`'s question checked in the order and words of
//! `ts-stack@edf6e03` `packages/overlays/topics/src/identity/IdentityLookupService.ts:83-123`
//! (the words in `packages/overlays/topics/src/shared/queryValidation.ts`:
//! `:9` the prefix, `:58`, `:72`, `:126`, `:174-178`, `:188`, `:247-256`),
//! where the overlay refuses the whole question and the resolver read its
//! refusal as an empty answer and charged the host. Hardening, not parity:
//! the reference's SDK client sends the question as built
//! (`IdentityClient.ts:614`, `:736`).

use crate::identity::types::IdentityQuery;
use crate::primitives::PublicKey;
use crate::{Error, Result};

/// The names `requireMongoFieldName` refuses beside `.`, `$` and NUL
/// (`queryValidation.ts:6`).
const UNSAFE_NAMES: [&str; 3] = ["__proto__", "constructor", "prototype"];

fn invalid(message: &str) -> Error {
    Error::IdentityError(format!("Invalid lookup query: {message}"))
}

/// The overlay's checks of the question `query` sends, in its order: `limit`
/// 1 to 100, `offset` 0 to 100000, `identityKey`, a set certifier as
/// `certifiers[0]` (the default SocialCert key, sent when none is set, passes),
/// a set type as `certificateTypes[0]` (1 to 44 bytes, then base64 of 32
/// bytes as `validateBase64String` reads it), then `attributes` (1 to 32
/// fields; per entry the name, then the value, the entries in the order
/// `Object.entries` walks the sent text: array-index names ahead, ascending,
/// then the rest as inserted). The earliest refusal is the
/// overlay's whole message, as `Error::IdentityError`.
pub(super) fn check(query: &IdentityQuery) -> Result<()> {
    if query.limit.is_some_and(|limit| !(1..=100).contains(&limit)) {
        return Err(invalid("limit must be an integer from 1 to 100"));
    }
    if query.offset.is_some_and(|offset| offset > 100_000) {
        return Err(invalid("offset must be an integer from 0 to 100000"));
    }
    if let Some(key) = query.identity_key.as_deref() {
        if !(1..=66).contains(&key.len()) {
            return Err(invalid("identityKey must contain 1-66 UTF-8 bytes"));
        }
        public_key(key, "identityKey")?;
    }
    if let Some(certifier) = query.certifier.as_deref() {
        bounded_item(certifier, 66, "certifiers[0]")?;
        public_key(certifier, "certifiers[0]")?;
    }
    // `IdentityLookupService.ts:97-100`: `readStringArray`'s 44-byte item
    // bound, then `requireBase64_32` (`queryValidation.ts:183-190`), whose
    // `validateBase64String` (`validationHelpers.ts:488-498`) is
    // `reveal::base64_parameter`; any refusal of it the overlay's one sentence.
    if let Some(cert_type) = query.certificate_type.as_deref() {
        bounded_item(cert_type, 44, "certificateTypes[0]")?;
        if super::reveal::base64_parameter(cert_type, "certificateTypes[0]", 32, 32).is_err() {
            return Err(invalid(
                "certificateTypes[0] must be a 32-byte base64 value",
            ));
        }
    }
    let Some(attributes) = query.attributes.as_ref() else {
        return Ok(());
    };
    if !(1..=32).contains(&attributes.len()) {
        return Err(invalid("attributes must contain 1-32 fields"));
    }
    // `Object.entries` of the attributes `query` sends in insertion order
    // (`IdentityLookupService.ts:113-125`): array-index names ahead (#751's fold)
    for (name, value) in super::client_attributes::js_order(attributes) {
        if !(1..=50).contains(&name.len())
            || name.contains(['.', '$', '\0'])
            || UNSAFE_NAMES.contains(&name)
        {
            return Err(invalid(
                "attribute names must be safe MongoDB field segments of at most 50 UTF-8 bytes",
            ));
        }
        if value.len() > 500 {
            return Err(invalid(
                "attribute values must be strings of at most 500 UTF-8 bytes",
            ));
        }
    }
    Ok(())
}

/// `readStringArray`'s item bound (`queryValidation.ts:124-127`).
fn bounded_item(value: &str, max_bytes: usize, field: &str) -> Result<()> {
    if (1..=max_bytes).contains(&value.len()) {
        return Ok(());
    }
    Err(invalid(&format!(
        "{field} must be a non-empty bounded string"
    )))
}

/// `requirePublicKey` (`queryValidation.ts:172-180`): `02` or `03` and 64 hex
/// digits of either case, then the point as `PublicKey.fromString` reads it
/// (`PublicKey::from_hex`, the reference's reading since #498: an x at or
/// above p reduced, an x of no point refused).
fn public_key(value: &str, field: &str) -> Result<()> {
    let shaped = value.len() == 66
        && (value.starts_with("02") || value.starts_with("03"))
        && value.bytes().all(|byte| byte.is_ascii_hexdigit());
    if !shaped {
        return Err(invalid(&format!("{field} must be a compressed public key")));
    }
    if PublicKey::from_hex(value).is_err() {
        return Err(invalid(&format!(
            "{field} must be a valid compressed public key"
        )));
    }
    Ok(())
}
