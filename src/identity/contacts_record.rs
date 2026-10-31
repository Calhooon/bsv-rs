//! The contact record the reference's token carries (#544): `validateContact`
//! (`ts-stack@edf6e03` `ContactsManager.ts:171-198`), the seven display
//! fields (`:35-43`) with the reference's spellings plus an optional
//! `metadata` object, every other member refused, in the reference's words.
//! This crate's `Contact` maps onto it: `notes` and `tags` travel in
//! `metadata` (the reference's place for them, `saveContact`'s
//! `metadata` "ex. notes, aliases", `:519-526`); `added_at` stays out of the
//! token, held beside it in the manager's cache; the three badge fields
//! are `Contact`'s own, written and read as held (#552).

use super::Contact;
use crate::identity::reveal::is_js_whitespace;
use crate::primitives::PublicKey;
use crate::{Error, Result};
use serde_json::{Map, Value};

/// `MAX_CONTACT_PLAINTEXT_BYTES` and `MAX_CONTACT_CIPHERTEXT_BYTES`
/// (`ContactsManager.ts:32-33`).
pub(super) const MAX_PLAINTEXT: usize = 64 * 1024;
pub(super) const MAX_CIPHERTEXT: usize = MAX_PLAINTEXT + 1024;

/// `DISPLAY_FIELDS` (`ContactsManager.ts:35-43`), in the reference's order.
const DISPLAY_FIELDS: [&str; 7] = [
    "name",
    "avatarURL",
    "abbreviatedKey",
    "identityKey",
    "badgeIconURL",
    "badgeLabel",
    "badgeClickURL",
];

fn invalid(words: impl Into<String>) -> Error {
    Error::IdentityError(words.into())
}

/// `isUnsafeRecordKey` (`SafeRecord.ts`).
fn unsafe_key(key: &str) -> bool {
    matches!(key, "__proto__" | "constructor" | "prototype")
}

/// `containsDisallowedControl` (`ContactsManager.ts:58-66`): C0 controls but
/// tab, LF and CR, and DEL.
fn disallowed_control(value: &str) -> bool {
    value
        .chars()
        .any(|c| matches!(c as u32, 0..=8 | 11 | 12 | 14..=31 | 127))
}

/// `boundedString` (`ContactsManager.ts:69-81`).
fn bounded<'a>(value: &'a Value, field: &str, max: usize, allow_empty: bool) -> Result<&'a str> {
    let text = value
        .as_str()
        .ok_or_else(|| invalid(format!("Invalid contact: {field} must be a string")))?;
    if (!allow_empty && text.is_empty()) || text.len() > max || disallowed_control(text) {
        return Err(invalid(format!(
            "Invalid contact: {field} is empty, oversized, or contains control characters"
        )));
    }
    Ok(text)
}

/// `validateIdentityKey` (`ContactsManager.ts:83-94`).
pub(super) fn identity_key(value: &Value) -> Result<String> {
    let key = bounded(value, "identityKey", 66, false)?;
    let words = "Invalid contact: identityKey must be a canonical compressed public key";
    let shaped = key.len() == 66
        && (key.starts_with("02") || key.starts_with("03"))
        && key
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !shaped || !PublicKey::from_hex(key).is_ok_and(|k| k.to_hex() == key) {
        return Err(invalid(words));
    }
    Ok(key.to_string())
}

/// `safeResource` (`ContactsManager.ts:96-102`).
fn safe_resource(value: &Value, field: &str) -> Result<String> {
    let resource = bounded(value, field, 2048, true)?;
    let scheme = resource.trim_matches(is_js_whitespace).to_ascii_lowercase();
    if ["javascript:", "data:", "vbscript:", "file:", "blob:"]
        .iter()
        .any(|unsafe_scheme| scheme.starts_with(unsafe_scheme))
    {
        return Err(invalid(format!(
            "Invalid contact: {field} uses an unsafe URL scheme"
        )));
    }
    Ok(resource.to_string())
}

/// `safeNavigation` (`ContactsManager.ts:104-127`): the URL as WHATWG
/// serialises it.
fn safe_navigation(value: &Value) -> Result<String> {
    let navigation = bounded(value, "badgeClickURL", 2048, true)?;
    if navigation.is_empty() {
        return Ok(String::new());
    }
    let parsed = url::Url::parse(navigation)
        .map_err(|_| invalid("Invalid contact: badgeClickURL must be an absolute HTTPS URL"))?;
    let local_http = parsed.scheme() == "http"
        && matches!(
            parsed.host_str(),
            Some("localhost" | "127.0.0.1" | "::1" | "[::1]")
        );
    if (parsed.scheme() != "https" && !local_http)
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(invalid(
            "Invalid contact: badgeClickURL must be a credential-free HTTPS URL",
        ));
    }
    Ok(parsed.to_string())
}

/// `sanitizeJsonValue` (`ContactsManager.ts:129-159`).
fn sanitize(value: &Value, depth: usize, nodes: &mut usize) -> Result<()> {
    *nodes += 1;
    if depth > 10 || *nodes > 2000 {
        return Err(invalid(
            "Invalid contact metadata: structure is too complex",
        ));
    }
    match value {
        Value::Array(items) if items.len() > 1000 => {
            Err(invalid("Invalid contact metadata: arrays are too large"))
        }
        Value::Array(items) => items
            .iter()
            .try_for_each(|item| sanitize(item, depth + 1, nodes)),
        Value::Object(members) if members.len() > 200 => Err(invalid(
            "Invalid contact metadata: objects have too many fields",
        )),
        Value::Object(members) => members.iter().try_for_each(|(key, member)| {
            if unsafe_key(key) || key.len() > 200 {
                return Err(invalid(
                    "Invalid contact metadata: unsafe or oversized field name",
                ));
            }
            sanitize(member, depth + 1, nodes)
        }),
        _ => Ok(()),
    }
}

/// `sanitizeMetadata` (`ContactsManager.ts:161-169`).
fn metadata(value: &Value) -> Result<Map<String, Value>> {
    let Value::Object(members) = value else {
        return Err(invalid("Invalid contact metadata: an object is required"));
    };
    sanitize(value, 0, &mut 0)?;
    if value.to_string().len() > MAX_PLAINTEXT / 2 {
        return Err(invalid(
            "Invalid contact metadata: encoded value is too large",
        ));
    }
    Ok(members.clone())
}

/// The record `validateContact` returns, its members in the reference's
/// order, as `JSON.stringify` writes it.
#[derive(serde::Serialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(super) struct ContactRecord {
    pub name: String,
    #[serde(rename = "avatarURL")]
    pub avatar_url: String,
    pub abbreviated_key: String,
    pub identity_key: String,
    #[serde(rename = "badgeIconURL")]
    pub badge_icon_url: String,
    pub badge_label: String,
    #[serde(rename = "badgeClickURL")]
    pub badge_click_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Map<String, Value>>,
}

/// `validateContact` (`ContactsManager.ts:171-198`) on a parsed record: an
/// object of the display fields and an optional `metadata`, judged member
/// by member in the reference's order and words.
pub(super) fn validate(value: &Value) -> Result<ContactRecord> {
    let Value::Object(members) = value else {
        return Err(invalid("Invalid contact: an object is required"));
    };
    if let Some(key) = members.keys().find(|key| {
        (!DISPLAY_FIELDS.contains(&key.as_str()) && *key != "metadata") || unsafe_key(key)
    }) {
        return Err(invalid(format!("Invalid contact: unexpected field {key}")));
    }
    if let Some(field) = DISPLAY_FIELDS.iter().find(|f| !members.contains_key(**f)) {
        return Err(invalid(format!(
            "Invalid contact: {field} must be an own data property"
        )));
    }
    Ok(ContactRecord {
        name: bounded(&members["name"], "name", 500, false)?.into(),
        avatar_url: safe_resource(&members["avatarURL"], "avatarURL")?,
        abbreviated_key: bounded(&members["abbreviatedKey"], "abbreviatedKey", 256, true)?.into(),
        identity_key: identity_key(&members["identityKey"])?,
        badge_icon_url: safe_resource(&members["badgeIconURL"], "badgeIconURL")?,
        badge_label: bounded(&members["badgeLabel"], "badgeLabel", 1000, true)?.into(),
        badge_click_url: safe_navigation(&members["badgeClickURL"])?,
        metadata: members.get("metadata").map(metadata).transpose()?,
    })
}

/// The record this crate writes for `contact`, validated as the reference's
/// `saveContact` validates it before any wallet call (`:527-528`).
pub(super) fn record_of(contact: &Contact) -> Result<ContactRecord> {
    let mut meta = match &contact.metadata {
        None => None,
        Some(Value::Object(members)) => Some(members.clone()),
        Some(_) => return Err(invalid("Invalid contact metadata: an object is required")),
    };
    if let Some(notes) = &contact.notes {
        meta.get_or_insert_with(Map::new)
            .insert("notes".into(), Value::String(notes.clone()));
    }
    if !contact.tags.is_empty() {
        meta.get_or_insert_with(Map::new)
            .insert("tags".into(), contact.tags.clone().into());
    }
    let display = contact.to_displayable_identity();
    let mut record = serde_json::json!({
        "name": contact.name,
        "avatarURL": contact.avatar_url.clone().unwrap_or_default(),
        "abbreviatedKey": display.abbreviated_key,
        "identityKey": contact.identity_key,
        "badgeIconURL": contact.badge_icon_url,
        "badgeLabel": contact.badge_label,
        "badgeClickURL": contact.badge_click_url,
    });
    if let Some(meta) = meta {
        record["metadata"] = Value::Object(meta);
    }
    validate(&record)
}

/// The `Contact` a validated record reads as: `notes` and `tags` taken back
/// out of `metadata`, `added_at` the caller's.
pub(super) fn contact_of(record: ContactRecord, added_at: u64) -> Contact {
    let mut meta = record.metadata.unwrap_or_default();
    let notes = match meta.remove("notes") {
        Some(Value::String(notes)) => Some(notes),
        Some(other) => {
            meta.insert("notes".into(), other);
            None
        }
        None => None,
    };
    let tags = match meta.remove("tags") {
        Some(Value::Array(items)) if items.iter().all(Value::is_string) => items
            .into_iter()
            .filter_map(|item| item.as_str().map(str::to_string))
            .collect(),
        Some(other) => {
            meta.insert("tags".into(), other);
            Vec::new()
        }
        None => Vec::new(),
    };
    let mut contact = Contact::new(record.name, record.identity_key)
        .with_added_at(added_at)
        .with_tags(tags)
        .with_badge_icon_url(record.badge_icon_url)
        .with_badge_label(record.badge_label)
        .with_badge_click_url(record.badge_click_url);
    contact.avatar_url = (!record.avatar_url.is_empty()).then_some(record.avatar_url);
    contact.notes = notes;
    contact.metadata = (!meta.is_empty()).then_some(Value::Object(meta));
    contact
}

/// `#parseContactPlaintext` (`ContactsManager.ts:468-472`): 1 to 64 KiB,
/// strict UTF-8 (one leading BOM dropped, as `TextDecoder` drops it), JSON,
/// then the record.
pub(super) fn parse_plaintext(plaintext: &[u8]) -> Result<ContactRecord> {
    if plaintext.is_empty() || plaintext.len() > MAX_PLAINTEXT {
        return Err(invalid(format!(
            "contact plaintext must contain 1-{MAX_PLAINTEXT} bytes"
        )));
    }
    let text = std::str::from_utf8(plaintext)
        .map_err(|_| invalid("The encoded data was not valid for encoding utf-8"))?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let value: Value = serde_json::from_str(text).map_err(|e| invalid(e.to_string()))?;
    validate(&value)
}

/// `#readKeyID` (`ContactsManager.ts:414-429`): the custom instructions a
/// JSON object of exactly `keyID`, base64 of 32 bytes.
pub(super) fn read_key_id(instructions: Option<&str>) -> Result<String> {
    let words = || invalid("Invalid contact custom instructions");
    let text = instructions.filter(|t| t.len() <= 256).ok_or_else(words)?;
    let parsed: Value = serde_json::from_str(text).map_err(|e| invalid(e.to_string()))?;
    let Value::Object(members) = parsed else {
        return Err(words());
    };
    if members.len() != 1 {
        return Err(words());
    }
    let key_id = members
        .get("keyID")
        .ok_or_else(words)?
        .as_str()
        .ok_or_else(|| invalid("Invalid contact keyID"))?;
    crate::identity::reveal::base64_parameter(key_id, "contact keyID", 32, 32)
}
