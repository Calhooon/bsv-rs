//! The general answer's authentication, judged before it becomes a message
//! (bsv-rs#354).
//!
//! The reference refuses a general answer that lacks any of
//! `x-bsv-auth-version`, `x-bsv-auth-identity-key` and `x-bsv-auth-signature`
//! (`#validateResponseAuthentication`, `ts-stack@edf6e03`
//! `packages/sdk/src/auth/transports/SimplifiedFetchTransport.ts:220-232`,
//! called at `:365` after the body is read and before the message is built)
//! in `#createUnauthenticatedResponseError`'s words (`:464-494`), with its body
//! preview (`#getBodyPreview`, `#isTextualContent`, `#formatBinaryPreview`,
//! `:512-579`). Through 0.9.0-beta.1 this crate read such an answer as a
//! message whose sender was the client's own identity key. The named host
//! answered, so the refusal is [`Error::AuthError`], never a
//! [`crate::TransportFault`].

use reqwest::header::{HeaderMap, CONTENT_TYPE};
use reqwest::StatusCode;

use super::headers;
use crate::{Error, Result};

/// The headers the reference requires, in its order (`:221-225`).
const REQUIRED: [&str; 3] = [headers::VERSION, headers::IDENTITY_KEY, headers::SIGNATURE];
/// The body bytes the preview reads (`:517`).
const PREVIEW_BYTES: usize = 1024;
/// The preview's length in UTF-16 code units before it is cut (`:533`).
const PREVIEW_UNITS: usize = 512;
/// The content types the reference reads as text (`:549-558`), and a
/// `charset=` of any type (`:559`).
const TEXTUAL: [&str; 9] = [
    "application/json",
    "application/problem+json",
    "application/xml",
    "application/xhtml+xml",
    "application/javascript",
    "application/ecmascript",
    "application/x-www-form-urlencoded",
    "text/",
    "charset=",
];

/// Refuses a general answer missing a required header, in the reference's
/// words: `Received HTTP <status> <reason> from <url> without valid BSV
/// authentication (missing headers: <names>)`, then ` - body preview: <text>`
/// when the body is not empty.
pub(super) fn refuse_unauthenticated(
    url: &str,
    status: StatusCode,
    response_headers: &HeaderMap,
    body: &[u8],
) -> Result<()> {
    let missing: Vec<&str> = REQUIRED
        .into_iter()
        .filter(|name| absent(response_headers, name))
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    // The reason phrase is the status code's canonical one: reqwest does not
    // keep the phrase on the wire, which fetch's `statusText` reports.
    let status_description = match status.canonical_reason() {
        Some(reason) => format!("{} {}", status.as_u16(), reason),
        None => status.as_u16().to_string(),
    };
    let mut text = format!(
        "Received HTTP {} from {} without valid BSV authentication (missing headers: {})",
        status_description,
        url,
        missing.join(", ")
    );
    if let Some(preview) = body_preview(body, &header_text(response_headers, CONTENT_TYPE)) {
        text.push_str(" - body preview: ");
        text.push_str(&preview);
    }
    Err(Error::AuthError(text))
}

/// `Headers.get` joins repeated values with `", "`, so a header is absent when
/// it is not sent or is sent once with nothing but JavaScript white space
/// (`value.trim().length === 0`, `:227`; a header value is Latin-1 there).
fn absent(response_headers: &HeaderMap, name: &str) -> bool {
    let mut values = response_headers.get_all(name).iter();
    match (values.next(), values.next()) {
        (None, _) => true,
        (Some(value), None) => value
            .as_bytes()
            .iter()
            .all(|b| matches!(b, 0x09..=0x0d | 0x20 | 0xa0)),
        (Some(_), Some(_)) => false,
    }
}

/// A header's values as `Headers.get` joins them.
fn header_text(response_headers: &HeaderMap, name: reqwest::header::HeaderName) -> String {
    response_headers
        .get_all(name)
        .iter()
        .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
        .collect::<Vec<_>>()
        .join(", ")
}

/// `#getBodyPreview` (`:512-540`): the first 1,024 bytes as text or as hex,
/// cut at 512 UTF-16 code units.
fn body_preview(body: &[u8], content_type: &str) -> Option<String> {
    if body.is_empty() {
        return None;
    }
    let truncated = body.len() > PREVIEW_BYTES;
    let slice = body.get(..PREVIEW_BYTES).unwrap_or(body);
    let mut preview = if is_textual(content_type, slice) {
        // `toUTF8` is a non-fatal `TextDecoder`: a leading BOM dropped, each
        // ill-formed subsequence one U+FFFD, as `from_utf8_lossy` reads it.
        let text = slice.strip_prefix(b"\xef\xbb\xbf").unwrap_or(slice);
        String::from_utf8_lossy(text).into_owned()
    } else {
        let hex = crate::primitives::to_hex(slice);
        format!("0x{}{}", hex, if truncated { "\u{2026}" } else { "" })
    };
    if preview.encode_utf16().count() > PREVIEW_UNITS {
        preview = utf16_prefix(&preview, PREVIEW_UNITS);
        preview.push('\u{2026}');
    }
    if truncated {
        preview.push_str(" (truncated)");
    }
    Some(preview)
}

/// `#isTextualContent` (`:542-574`): a textual content type or a `charset=`,
/// else more than 80 percent printable ASCII, tab, line feed or return.
fn is_textual(content_type: &str, sample: &[u8]) -> bool {
    if sample.is_empty() {
        return false;
    }
    let lowered = content_type.to_lowercase();
    if TEXTUAL.iter().any(|token| lowered.contains(token)) {
        return true;
    }
    let printable = sample
        .iter()
        .filter(|b| matches!(b, 9 | 10 | 13 | 32..=126))
        .count();
    // printable / len > 0.8, in integers
    printable * 5 > sample.len() * 4
}

/// `String.prototype.slice(0, units)`: a pair the cut splits leaves its high
/// surrogate alone, which UTF-8 writes as U+FFFD (`TextEncoder`'s reading).
fn utf16_prefix(text: &str, units: usize) -> String {
    let mut out = String::new();
    let mut taken = 0;
    for c in text.chars() {
        let width = c.len_utf16();
        if taken + width > units {
            if taken < units {
                out.push('\u{fffd}');
            }
            break;
        }
        out.push(c);
        taken += width;
    }
    out
}
