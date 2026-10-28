//! The handshake and malformed certificate-header words (#410).

use reqwest::header::HeaderMap;

use super::{
    body, client, headers, json_syntax, response_bounds, unauthenticated, SimplifiedFetchTransport,
};
use crate::auth::{AuthMessage, RequestedCertificateSet};
use crate::transaction::broadcasters::transport_fault as fault;
use crate::{Error, Result};

impl SimplifiedFetchTransport {
    pub(super) async fn send_auth_message(&self, message: &AuthMessage) -> Result<()> {
        let url = self.auth_url();
        let response = self
            .client
            .post(&url)
            .json(message)
            .send()
            .await
            .map_err(|e| fault::auth_error(&e, "HTTP request failed"))?;
        client::refuse_redirect(&url, &response)?;
        let (status, reason, response_headers) = unauthenticated::head(&response);
        let body = body::read(
            &url,
            response,
            self.limits.handshake,
            "Failed to read auth response",
        )
        .await?;
        if !status.is_success() {
            // The reference supplies no missing-header list here, even when
            // some or all authentication headers are present (:143-151).
            return Err(unauthenticated::refusal(
                &url,
                status,
                reason.as_deref(),
                &response_headers,
                &body,
                &[],
            ));
        }
        // The reference's TextDecoder replaces invalid UTF-8 and drops a BOM.
        let text = String::from_utf8_lossy(body.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&body));
        let message = serde_json::from_str(&text).map_err(|error| {
            Error::AuthError(json_syntax::diagnostic(&text).unwrap_or_else(|| {
                format!("Failed to parse auth response: {error} - body: {text}")
            }))
        })?;
        self.invoke_callback(message).await
    }
}

/// The header is parsed on every general reply, whatever its message type,
/// as in #parseRequestedCertificates (:234-258), never silently discarded.
pub(super) fn requested_certificates(
    url: &str,
    response_headers: &HeaderMap,
) -> Result<Option<RequestedCertificateSet>> {
    let Some(value) = response_bounds::value(response_headers, headers::REQUESTED_CERTIFICATES)
    else {
        return Ok(None);
    };
    if value.len() > 256 * 1024 {
        return Err(response_bounds::malformed(
            url,
            headers::REQUESTED_CERTIFICATES,
            "[oversized]",
            "header exceeds its byte limit",
        ));
    }
    serde_json::from_str(&value).map(Some).map_err(|error| {
        let cause = json_syntax::diagnostic(&value).unwrap_or_else(|| error.to_string());
        Error::AuthError(format!(
            "Failed to parse {} returned by {url}: {value}. {cause}",
            headers::REQUESTED_CERTIFICATES,
        ))
    })
}
