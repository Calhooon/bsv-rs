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
//! message whose sender was the client's own identity key.
//!
//! The class is #87's: an unsigned 429, 502, 503 or 504 is not the named
//! host's word but a gateway's or a limiter's, a
//! [`crate::TransportFault`] by `status_fault` (a 429 or a 503 with
//! `Retry-After` rate limited with its wait, the rest may have been
//! received), the refusal's words its detail; every other status is the
//! named host's answer, [`Error::AuthError`].

use reqwest::header::{HeaderMap, CONTENT_TYPE};
use reqwest::{Response, StatusCode};

use super::headers;
use crate::primitives::PublicKey;
use crate::transaction::broadcasters::transport_fault as fault;
use crate::{Error, Result};

/// The headers the reference requires, in its order (`:221-225`).
const REQUIRED: [&str; 3] = [headers::VERSION, headers::IDENTITY_KEY, headers::SIGNATURE];
/// The body bytes the preview reads (`:517`).
const PREVIEW_BYTES: usize = 1024;
/// The preview's length in UTF-16 code units before it is cut (`:533`).
const PREVIEW_UNITS: usize = 512;
/// The content types the reference reads as text (`:549-558`).
const TEXTUAL: [&str; 8] = [
    "application/json",
    "application/problem+json",
    "application/xml",
    "application/xhtml+xml",
    "application/javascript",
    "application/ecmascript",
    "application/x-www-form-urlencoded",
    "text/",
];

/// The answer's status, the status line's own reason phrase when it is not
/// the canonical one (hyper keeps that one alone, as `ext::ReasonPhrase` in
/// the answer's extensions), and its headers.
pub(super) fn head(response: &Response) -> (StatusCode, Option<Vec<u8>>, HeaderMap) {
    let reason = response
        .extensions()
        .get::<hyper::ext::ReasonPhrase>()
        .map(|reason| reason.as_bytes().to_vec());
    (response.status(), reason, response.headers().clone())
}

/// Refuses a general answer missing a required header, in the reference's
/// words: `Received HTTP <status> <reason> from <url> without valid BSV
/// authentication (missing headers: <names>)`, then ` - body preview: <text>`
/// when the body is not empty; a transport fault when the status is one.
pub(super) fn refuse_unauthenticated(
    url: &str,
    status: StatusCode,
    reason: Option<&[u8]>,
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
    Err(refusal(
        url,
        status,
        reason,
        response_headers,
        body,
        &missing,
    ))
}

/// Shared with a non-success handshake, whose missing-header list is empty.
pub(super) fn refusal(
    url: &str,
    status: StatusCode,
    reason: Option<&[u8]>,
    response_headers: &HeaderMap,
    body: &[u8],
    missing: &[&str],
) -> Error {
    let header_message = if missing.is_empty() {
        "response lacked required BSV auth headers".into()
    } else {
        format!("missing headers: {}", missing.join(", "))
    };
    let mut text = format!(
        "Received HTTP {} from {} without valid BSV authentication ({})",
        status_description(status, reason),
        url,
        header_message
    );
    if let Some(preview) = body_preview(body, &header_text(response_headers, CONTENT_TYPE)) {
        text.push_str(" - body preview: ");
        text.push_str(&preview);
    }
    let class = fault::status_fault(status, response_headers);
    fault::fault_or(class, Some(status), text, Error::AuthError)
}

/// The answer's sender: the identity key it carries, which
/// `refuse_unauthenticated` has required (#354), read strictly as the
/// reference's `assertAuthIdentityKey` reads it
/// (`AuthMessageValidation.ts:344`, `:81-89`; #498).
pub(super) fn sender(response_headers: &HeaderMap) -> Result<PublicKey> {
    PublicKey::from_strict_hex(
        response_headers
            .get(headers::IDENTITY_KEY)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default(),
    )
}

/// `statusText.trim()` after the status, or the status alone when nothing is
/// left (`:470-472`). fetch's `statusText` is the wire's phrase; hyper keeps
/// no canonical phrase, so its absence is the canonical one, or none for a
/// status without one. A phrase with a byte above `0x7e` hyper's parser
/// reads as empty (httparse's `parse_reason`), where fetch reads it as UTF-8
/// (an ill-formed byte one U+FFFD, recorded under Node v22.18.0): the status
/// alone here (the parity note).
fn status_description(status: StatusCode, reason: Option<&[u8]>) -> String {
    let text = match reason {
        Some(bytes) => String::from_utf8_lossy(bytes).into_owned(),
        None => status.canonical_reason().unwrap_or_default().to_owned(),
    };
    let trimmed = text.trim_matches(is_js_whitespace);
    if trimmed.is_empty() {
        status.as_u16().to_string()
    } else {
        format!("{} {}", status.as_u16(), trimmed)
    }
}

/// What JavaScript's `String.prototype.trim` removes: `WhiteSpace` and
/// `LineTerminator` (ECMA-262), Unicode's `White_Space` with U+FEFF and
/// without U+0085, which Rust's `char::is_whitespace` has the other way.
fn is_js_whitespace(c: char) -> bool {
    c == '\u{feff}' || (c.is_whitespace() && c != '\u{85}')
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
    if TEXTUAL.iter().any(|token| lowered.contains(token)) || lowered.contains("charset=") {
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
