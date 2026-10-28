//! Buffered-response limits from SimplifiedFetchTransport.ts at edf6e03.

use super::SimplifiedFetchTransport;
use crate::transaction::broadcasters::transport_fault as fault;
use crate::{Error, Result};

#[cfg(test)]
#[path = "body_tests.rs"]
mod tests;

pub(super) struct ResponseLimits {
    pub(super) application: usize,
    pub(super) handshake: usize,
}

impl Default for ResponseLimits {
    fn default() -> Self {
        Self {
            application: 16 * 1024 * 1024,
            handshake: 1024 * 1024,
        }
    }
}

impl SimplifiedFetchTransport {
    /// Sets the maximum buffered application-response body size in bytes.
    ///
    /// The default is 16 MiB, matching the reference's `maxResponseBytes`.
    /// The limit includes error responses and applies with a supplied client.
    /// Zero and values above JavaScript's maximum safe integer are refused.
    pub fn with_max_response_bytes(mut self, bytes: usize) -> Result<Self> {
        positive_limit(bytes, "maxResponseBytes")?;
        self.limits.application = bytes;
        Ok(self)
    }

    /// Sets the maximum buffered `/.well-known/auth` response size in bytes.
    ///
    /// The default is 1 MiB, matching `maxHandshakeResponseBytes` in the
    /// reference. The limit is checked before JSON or HTTP-status handling.
    /// Zero and values above JavaScript's maximum safe integer are refused.
    pub fn with_max_handshake_response_bytes(mut self, bytes: usize) -> Result<Self> {
        positive_limit(bytes, "maxHandshakeResponseBytes")?;
        self.limits.handshake = bytes;
        Ok(self)
    }
}

fn positive_limit(bytes: usize, name: &str) -> Result<()> {
    if bytes == 0 || bytes as u64 > 9_007_199_254_740_991 {
        return Err(Error::AuthError(format!(
            "{name} must be a positive safe integer"
        )));
    }
    Ok(())
}

/// Check the declared length first, then each chunk before extending the
/// buffer. Dropping the response on refusal stops consuming its stream.
pub(super) async fn read(
    url: &str,
    mut response: reqwest::Response,
    maximum: usize,
    read_error: &str,
) -> Result<Vec<u8>> {
    if let Some(length) = response.headers().get(reqwest::header::CONTENT_LENGTH) {
        let text = length.as_bytes();
        if text.is_empty() || !text.iter().all(u8::is_ascii_digit) {
            return Err(Error::AuthError(format!(
                "Invalid Content-Length returned by {url}"
            )));
        }
        let declared = length
            .to_str()
            .ok()
            .and_then(|text| text.parse::<u64>().ok());
        if declared.is_none_or(|size| size > maximum as u64 || size > 9_007_199_254_740_991) {
            return Err(oversized(url, maximum));
        }
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| fault::auth_error(&error, read_error))?
    {
        if chunk.len() > maximum.saturating_sub(body.len()) {
            return Err(oversized(url, maximum));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn oversized(url: &str, maximum: usize) -> Error {
    Error::AuthError(format!(
        "Authenticated response from {url} exceeds {maximum} bytes"
    ))
}
