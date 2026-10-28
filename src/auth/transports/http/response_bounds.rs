//! Header bounds and mappings from SimplifiedFetchTransport.ts:234-356 (#416).

use reqwest::header::HeaderMap;

use super::headers;
use crate::{Error, Result};

/// Fetch joins repeated header values and exposes each wire byte as Latin-1.
/// Encode that text as UTF-8 when measuring it or writing the signed payload.
pub(super) fn value(map: &HeaderMap, name: &str) -> Option<String> {
    if !map.contains_key(name) {
        return None;
    }
    Some(
        map.get_all(name)
            .iter()
            .map(|value| {
                value
                    .as_bytes()
                    .trim_ascii()
                    .iter()
                    .map(|byte| char::from(*byte))
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join(", "),
    )
}

pub(super) fn malformed(url: &str, header: &str, marker: &str, cause: &str) -> Error {
    Error::AuthError(format!(
        "Failed to parse {header} returned by {url}: {marker}. {cause}"
    ))
}

pub(super) fn signature(url: &str, map: &HeaderMap) -> Result<Vec<u8>> {
    let text = value(map, headers::SIGNATURE).unwrap_or_default();
    let invalid = || {
        malformed(
            url,
            headers::SIGNATURE,
            "[invalid]",
            "signature must be bounded even-length hexadecimal",
        )
    };
    if text.is_empty()
        || text.len() > 2048
        || !text.len().is_multiple_of(2)
        || !text.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(invalid());
    }
    hex::decode(text).map_err(|_| invalid())
}

pub(super) fn request_id(map: &HeaderMap) -> Result<Option<Vec<u8>>> {
    let Some(text) = value(map, headers::REQUEST_ID) else {
        return Ok(None);
    };
    if !base64_shape(&text) {
        return Err(Error::AuthError(
            "Authenticated response request ID must be canonical base64".into(),
        ));
    }
    let invalid = || {
        Error::AuthError("Authenticated response request ID must encode exactly 32 bytes".into())
    };
    // A canonical encoding of 32 bytes is 44 characters. Avoid allocating
    // an arbitrarily long decoded value merely to reject its byte count.
    if text.len() != 44 {
        return Err(invalid());
    }
    let bytes = crate::primitives::from_base64(&text).map_err(|_| invalid())?;
    if bytes.len() != 32 || crate::primitives::to_base64(&bytes) != text {
        return Err(invalid());
    }
    Ok(Some(bytes))
}

/// The reference's regex checks framing; padding bits are checked separately
/// by decode/re-encode and use the second (32-byte) diagnostic.
fn base64_shape(text: &str) -> bool {
    let (body, suffix) = if let Some(body) = text.strip_suffix("==") {
        (body, 2)
    } else if let Some(body) = text.strip_suffix('=') {
        (body, 1)
    } else {
        (text, 0)
    };
    text.len().is_multiple_of(4)
        && body.len() % 4 == (4 - suffix) % 4
        && body
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/')
}

pub(super) fn signed_headers(map: &HeaderMap) -> Result<Vec<(String, String)>> {
    let mut names: Vec<_> = map
        .keys()
        .map(|name| name.as_str())
        .filter(|name| {
            (name.starts_with("x-bsv-") || *name == "authorization")
                && !name.starts_with("x-bsv-auth")
        })
        .collect();
    // Headers.forEach walks byte-sorted names before the reference sorts the
    // signed subset by localeCompare. Preserve its first-refusal order too.
    names.sort_unstable();
    let mut total = 0;
    for (index, name) in names.iter().enumerate() {
        let text = value(map, name).unwrap_or_default();
        if name.is_empty() || name.len() > 1024 || text.len() > 32 * 1024 {
            return Err(Error::AuthError(
                "Authenticated response contains an oversized signed header".into(),
            ));
        }
        total += name.len() + text.len();
        if index >= 512 || total > 256 * 1024 {
            return Err(Error::AuthError(
                "Authenticated response signed headers exceed their limit".into(),
            ));
        }
    }
    // Header names are ASCII; the existing reference collation covers them.
    crate::wallet::collation::sort_field_names(&mut names);
    Ok(names
        .into_iter()
        .map(|name| (name.to_owned(), value(map, name).unwrap_or_default()))
        .collect())
}
