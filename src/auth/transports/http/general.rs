//! General-message HTTP exchange, with the reference's response bounds (#416).

use reqwest::header::HeaderMap;

use super::{body, client, handshake, headers, response_bounds, unauthenticated, write_varint};
use super::{HttpRequest, SimplifiedFetchTransport};
use crate::auth::{AuthMessage, MessageType};
use crate::transaction::broadcasters::transport_fault as fault;
use crate::{Error, Result};

impl SimplifiedFetchTransport {
    pub(super) async fn send_general_message(&self, message: &AuthMessage) -> Result<()> {
        let payload = message
            .payload
            .as_ref()
            .ok_or_else(|| Error::AuthError("General message must have payload".into()))?;
        let request = HttpRequest::from_payload(payload)?;
        let url = format!("{}{}", self.base_url, request.url_postfix());
        let response = self
            .general_request(message, &request, &url)
            .send()
            .await
            .map_err(|error| fault::auth_error(&error, "HTTP request failed"))?;
        client::refuse_redirect(&url, &response)?;
        let (status, reason, response_headers) = unauthenticated::head(&response);
        let bytes = body::read(
            &url,
            response,
            self.limits.application,
            "Failed to read response",
        )
        .await?;
        unauthenticated::refuse_unauthenticated(
            &url,
            status,
            reason.as_deref(),
            &response_headers,
            &bytes,
        )?;
        self.invoke_callback(response_message(
            &url,
            status.as_u16(),
            &response_headers,
            &bytes,
        )?)
        .await
    }

    fn general_request(
        &self,
        message: &AuthMessage,
        request: &HttpRequest,
        url: &str,
    ) -> reqwest::RequestBuilder {
        let normalized = request.method.to_uppercase();
        let method_text = match normalized.as_str() {
            "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD" => &normalized,
            _ => &request.method,
        };
        let method =
            reqwest::Method::from_bytes(method_text.as_bytes()).unwrap_or(reqwest::Method::GET);
        let mut builder = self
            .client
            .request(method, url)
            .header(headers::VERSION, &message.version)
            .header(headers::IDENTITY_KEY, message.identity_key.to_hex())
            .header(
                headers::REQUEST_ID,
                crate::primitives::to_base64(&request.request_id),
            );
        if let Some(nonce) = &message.nonce {
            builder = builder.header(headers::NONCE, nonce);
        }
        if let Some(nonce) = &message.your_nonce {
            builder = builder.header(headers::YOUR_NONCE, nonce);
        }
        if let Some(signature) = &message.signature {
            builder = builder.header(headers::SIGNATURE, crate::primitives::to_hex(signature));
        }
        for (key, value) in &request.headers {
            let lower = key.to_lowercase();
            if (lower.starts_with("x-bsv-") || lower == "authorization" || lower == "content-type")
                && !lower.starts_with("x-bsv-auth")
            {
                builder = builder.header(key.as_str(), value.as_str());
            }
        }
        if !request.body.is_empty() {
            builder = builder.body(request.body.clone());
        }
        builder
    }
}

fn response_message(url: &str, status: u16, map: &HeaderMap, body: &[u8]) -> Result<AuthMessage> {
    // Match #createGeneralResponseMessage's order: signature, certificate
    // header, then request ID and signed headers while writing the payload.
    let signature = response_bounds::signature(url, map)?;
    let message_type = if response_bounds::value(map, headers::MESSAGE_TYPE).as_deref()
        == Some("certificateRequest")
    {
        MessageType::CertificateRequest
    } else {
        MessageType::General
    };
    let mut message = AuthMessage::new(message_type, unauthenticated::sender(map)?);
    message.signature = Some(signature);
    message.requested_certificates = handshake::requested_certificates(url, map)?;
    message.payload = Some(response_payload(status, map, body)?);
    message.nonce = response_bounds::value(map, headers::NONCE);
    message.your_nonce = response_bounds::value(map, headers::YOUR_NONCE);
    Ok(message)
}

fn response_payload(status: u16, map: &HeaderMap, body: &[u8]) -> Result<Vec<u8>> {
    let mut payload = response_bounds::request_id(map)?.unwrap_or_default();
    payload.extend(write_varint(i64::from(status)));
    let included = response_bounds::signed_headers(map)?;
    payload.extend(write_varint(included.len() as i64));
    for (key, value) in included {
        payload.extend(write_varint(key.len() as i64));
        payload.extend_from_slice(key.as_bytes());
        payload.extend(write_varint(value.len() as i64));
        payload.extend_from_slice(value.as_bytes());
    }
    payload.extend(write_varint(if body.is_empty() {
        -1
    } else {
        body.len() as i64
    }));
    payload.extend_from_slice(body);
    Ok(payload)
}
