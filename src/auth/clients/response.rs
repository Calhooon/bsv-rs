//! Bounded response decoding, in AuthFetch.ts:428-495,1246-1300's words.

use crate::{Error, Result};
use indexmap::IndexMap;

pub(super) const OVERHEAD: usize = 512 * 1024;
pub(super) const MAX_SAFE_INTEGER: u64 = (1_u64 << 53) - 1;

/// An owned, buffered equivalent of the reference's Fetch `Response`.
/// Headers use lowercase names; the body can be read repeatedly as bytes.
/// No browser stream, status text, response URL or redirect metadata is implied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    /// HTTP status code.
    pub status: u16,
    /// Response headers in Fetch's sorted name order, with case-insensitive
    /// access through [`Self::header`].
    pub headers: IndexMap<String, String>,
    /// Complete response body.
    pub body: Vec<u8>,
}

impl Response {
    /// Returns a header without requiring the caller to lowercase its name.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }

    /// Whether the HTTP status is in the successful 200–299 range.
    #[must_use]
    pub const fn ok(&self) -> bool {
        self.status >= 200 && self.status < 300
    }

    /// Decodes an already authenticated general-message payload.
    ///
    /// Authentication remains the Peer's responsibility. A different 32-byte
    /// request ID returns `Ok(None)` before parsing the remainder, just as line
    /// 439 does; the waiting fetch continues until its matching reply/deadline.
    ///
    /// # Errors
    /// Refuses invalid limits, truncated/noncanonical frames, invalid status or
    /// headers, oversized bodies and trailing bytes in the reference's words.
    pub fn from_authenticated_payload(
        payload: &[u8],
        request_id: &[u8; 32],
        sender: &str,
        max_body_bytes: usize,
    ) -> Result<Option<Self>> {
        if !matches_request(payload, request_id, max_body_bytes)? {
            return Ok(None);
        }
        let mut reader = ResponseReader {
            bytes: payload,
            position: 32,
        };
        let status = reader.varint("status code", false)?;
        if !(200..=599).contains(&status) {
            return Err(words(
                "Authenticated response contains an invalid HTTP status code.",
            ));
        }
        let headers = read_headers(&mut reader, sender)?;
        let body = reader.body(max_body_bytes)?;
        if reader.position != payload.len() {
            return Err(words("Authenticated response contains trailing bytes."));
        }
        // Fetch's Response constructor refuses a body for these statuses.
        if !body.is_empty() && matches!(status, 204 | 205 | 304) {
            return Err(words(&format!(
                "Response constructor: Invalid response status code {status}"
            )));
        }
        Ok(Some(Self {
            status: u16::try_from(status).map_err(|_| {
                words("Authenticated response contains an invalid HTTP status code.")
            })?,
            headers,
            body,
        }))
    }
}

fn read_headers(reader: &mut ResponseReader<'_>, sender: &str) -> Result<IndexMap<String, String>> {
    let count = reader.bounded(512, 0, "response header count")?;
    let mut headers = IndexMap::new();
    let mut total = 0;
    for _ in 0..count {
        let key_length = reader.bounded(1024, 1, "response header name length")?;
        let key = text(reader.read(key_length, "response header name")?)?;
        let value_length = reader.bounded(32 * 1024, 0, "response header value length")?;
        let value = text(reader.read(value_length, "response header value")?)?;
        total += key_length + value_length;
        if total > 256 * 1024 {
            return Err(words(
                "Authenticated response headers exceed the configured limit.",
            ));
        }
        byte_string(&key)?;
        byte_string(&value)?;
        if key.is_empty()
            || !key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
        {
            return Err(words(&format!(
                "Headers.set: \"{key}\" is an invalid header name."
            )));
        }
        let value = value.trim_matches([' ', '\t', '\r', '\n']);
        if value.contains(['\0', '\r', '\n']) {
            return Err(words(&format!(
                "Headers.set: \"{value}\" is an invalid header value."
            )));
        }
        headers.insert(key.to_ascii_lowercase(), value.to_owned());
    }
    headers.insert("x-bsv-auth-identity-key".into(), sender.into());
    headers.sort_keys();
    Ok(headers)
}

pub(super) fn matches_request(payload: &[u8], request_id: &[u8; 32], limit: usize) -> Result<bool> {
    validate_limit(limit)?;
    if payload.len() > limit.saturating_add(OVERHEAD) {
        return Err(words(
            "Authenticated response frame exceeds the configured limit.",
        ));
    }
    let id = payload
        .get(..32)
        .ok_or_else(|| words("Authenticated response truncated while reading response nonce."))?;
    Ok(id == request_id)
}

fn byte_string(value: &str) -> Result<()> {
    let mut index = 0;
    for character in value.chars() {
        if u32::from(character) > 255 {
            return Err(words(&format!("Cannot convert argument to a ByteString because the character at index {index} has a value of {} which is greater than 255.", u32::from(character))));
        }
        index += character.len_utf16();
    }
    Ok(())
}

fn text(bytes: &[u8]) -> Result<String> {
    // TextDecoder's default strips a leading UTF-8 BOM.
    let bytes = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);
    String::from_utf8(bytes.to_vec())
        .map_err(|_| words("The encoded data was not valid for encoding utf-8"))
}

pub(super) fn validate_limit(bytes: usize) -> Result<()> {
    if bytes == 0 || bytes as u64 > MAX_SAFE_INTEGER {
        return Err(words("maxResponseBytes must be a positive safe integer"));
    }
    Ok(())
}

pub(super) fn words(text: &str) -> Error {
    Error::AuthError(text.into())
}

struct ResponseReader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> ResponseReader<'a> {
    fn body(&mut self, maximum: usize) -> Result<Vec<u8>> {
        let maximum = i64::try_from(maximum)
            .map_err(|_| words("maxResponseBytes must be a positive safe integer"))?;
        let length = self.varint("response body length", true)?;
        if length < -1 || length > maximum {
            return Err(words(
                "Authenticated response body exceeds the configured limit.",
            ));
        }
        if length <= 0 {
            return Ok(Vec::new());
        }
        let length = usize::try_from(length)
            .map_err(|_| words("Authenticated response body exceeds the configured limit."))?;
        Ok(self.read(length, "response body")?.to_vec())
    }

    fn read(&mut self, count: usize, field: &str) -> Result<&'a [u8]> {
        let end = self.position.saturating_add(count);
        let slice = self.bytes.get(self.position..end).ok_or_else(|| {
            words(&format!(
                "Authenticated response truncated while reading {field}."
            ))
        })?;
        self.position = end;
        Ok(slice)
    }

    fn varint(&mut self, field: &str, signed: bool) -> Result<i64> {
        let first = self.read(1, field)?[0];
        let size = match first {
            0xfd => 2,
            0xfe => 4,
            0xff => 8,
            _ => 0,
        };
        let mut bytes = [0; 8];
        bytes[..size].copy_from_slice(self.read(size, field)?);
        let value = if size == 0 {
            u64::from(first)
        } else {
            u64::from_le_bytes(bytes)
        };
        if matches!(size, 2) && value < 0xfd
            || size == 4 && value <= 0xffff
            || size == 8 && value <= 0xffff_ffff
        {
            return Err(words("non-canonical varInt"));
        }
        if signed && value == u64::MAX {
            return Ok(-1);
        }
        if value > MAX_SAFE_INTEGER {
            return Err(words(
                "number too large to retain precision - use readVarIntBn",
            ));
        }
        i64::try_from(value)
            .map_err(|_| words("number too large to retain precision - use readVarIntBn"))
    }

    fn bounded(&mut self, max: usize, min: usize, field: &str) -> Result<usize> {
        let value = usize::try_from(self.varint(field, false)?).map_err(|_| {
            words(&format!(
                "Authenticated response contains an invalid {field}."
            ))
        })?;
        if value < min || value > max {
            return Err(words(&format!(
                "Authenticated response contains an invalid {field}."
            )));
        }
        Ok(value)
    }
}
