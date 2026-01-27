//! HTTP transport for auth messages (SimplifiedFetchTransport).
//!
//! This module provides HTTP-based transport for authentication messages,
//! implementing BRC-104 headers for authenticated HTTP communication.
//!
//! ## BRC-104 Protocol
//!
//! - Handshake messages (InitialRequest, InitialResponse, CertificateRequest, CertificateResponse)
//!   are sent as JSON POST to `/.well-known/auth`
//! - General messages deserialize the payload into HTTP request components (method, URL, headers, body),
//!   add auth headers, and make actual HTTP requests
//!
//! ## Payload Format for General Messages
//!
//! Request payload: `[request_id: 32][method: varint+str][url: varint+str][headers: varint+pairs][body: varint+bytes]`
//! Response payload: `[request_id: 32][status: varint][headers: varint+pairs][body: varint+bytes]`

use crate::auth::types::AuthMessage;

#[cfg(feature = "http")]
use crate::auth::types::MessageType;
use crate::{Error, Result};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Transport trait for sending/receiving auth messages.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Sends an authentication message.
    async fn send(&self, message: &AuthMessage) -> Result<()>;

    /// Registers a callback for incoming messages.
    ///
    /// The callback is invoked asynchronously when a message is received.
    fn set_callback(&self, callback: Box<TransportCallback>);

    /// Clears the registered callback.
    fn clear_callback(&self);
}

/// Type alias for transport callback function.
pub type TransportCallback = dyn Fn(AuthMessage) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>>
    + Send
    + Sync;

/// BRC-104 HTTP header names for authenticated requests.
pub mod headers {
    /// Auth protocol version.
    pub const VERSION: &str = "x-bsv-auth-version";
    /// Sender's identity public key (hex).
    pub const IDENTITY_KEY: &str = "x-bsv-auth-identity-key";
    /// Sender's nonce (base64).
    pub const NONCE: &str = "x-bsv-auth-nonce";
    /// Recipient's nonce from previous message (base64).
    pub const YOUR_NONCE: &str = "x-bsv-auth-your-nonce";
    /// Message signature (base64 or hex).
    pub const SIGNATURE: &str = "x-bsv-auth-signature";
    /// Message type.
    pub const MESSAGE_TYPE: &str = "x-bsv-auth-message-type";
    /// Request ID for correlating requests/responses (base64).
    pub const REQUEST_ID: &str = "x-bsv-auth-request-id";
    /// Requested certificates specification (JSON).
    pub const REQUESTED_CERTIFICATES: &str = "x-bsv-auth-requested-certificates";
}

/// Deserialized HTTP request from General message payload.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    /// Request ID (32 bytes, for correlation).
    pub request_id: [u8; 32],
    /// HTTP method (GET, POST, PUT, DELETE, etc.).
    pub method: String,
    /// URL path/postfix (e.g., "/api/users").
    pub url_postfix: String,
    /// HTTP headers (key-value pairs).
    pub headers: Vec<(String, String)>,
    /// Request body.
    pub body: Vec<u8>,
}

impl HttpRequest {
    /// Deserializes an HTTP request from payload bytes.
    ///
    /// Format: `[request_id: 32][method: varint+str][url: varint+str][headers: varint+pairs][body: varint+bytes]`
    pub fn from_payload(payload: &[u8]) -> Result<Self> {
        let mut cursor = 0;

        // Read request ID (32 bytes)
        if payload.len() < 32 {
            return Err(Error::AuthError("Payload too short for request ID".into()));
        }
        let mut request_id = [0u8; 32];
        request_id.copy_from_slice(&payload[..32]);
        cursor += 32;

        // Read method (varint length + string)
        let (method_len, bytes_read) = read_varint(&payload[cursor..])?;
        cursor += bytes_read;
        let method = if method_len > 0 {
            if cursor + method_len > payload.len() {
                return Err(Error::AuthError("Payload too short for method".into()));
            }
            let s = String::from_utf8(payload[cursor..cursor + method_len].to_vec())
                .map_err(|e| Error::AuthError(format!("Invalid method UTF-8: {}", e)))?;
            cursor += method_len;
            s
        } else {
            "GET".to_string()
        };

        // Read URL postfix (varint length + string)
        let (url_len, bytes_read) = read_varint(&payload[cursor..])?;
        cursor += bytes_read;
        let url_postfix = if url_len > 0 {
            if cursor + url_len > payload.len() {
                return Err(Error::AuthError("Payload too short for URL".into()));
            }
            let s = String::from_utf8(payload[cursor..cursor + url_len].to_vec())
                .map_err(|e| Error::AuthError(format!("Invalid URL UTF-8: {}", e)))?;
            cursor += url_len;
            s
        } else {
            String::new()
        };

        // Read headers (varint count, then pairs of varint+string)
        let (header_count, bytes_read) = read_varint(&payload[cursor..])?;
        cursor += bytes_read;
        let mut headers = Vec::with_capacity(header_count);
        for _ in 0..header_count {
            // Read key
            let (key_len, bytes_read) = read_varint(&payload[cursor..])?;
            cursor += bytes_read;
            if cursor + key_len > payload.len() {
                return Err(Error::AuthError("Payload too short for header key".into()));
            }
            let key = String::from_utf8(payload[cursor..cursor + key_len].to_vec())
                .map_err(|e| Error::AuthError(format!("Invalid header key UTF-8: {}", e)))?;
            cursor += key_len;

            // Read value
            let (val_len, bytes_read) = read_varint(&payload[cursor..])?;
            cursor += bytes_read;
            if cursor + val_len > payload.len() {
                return Err(Error::AuthError("Payload too short for header value".into()));
            }
            let value = String::from_utf8(payload[cursor..cursor + val_len].to_vec())
                .map_err(|e| Error::AuthError(format!("Invalid header value UTF-8: {}", e)))?;
            cursor += val_len;

            headers.push((key, value));
        }

        // Read body (varint length + bytes)
        let (body_len, bytes_read) = read_varint(&payload[cursor..])?;
        cursor += bytes_read;
        let body = if body_len > 0 {
            if cursor + body_len > payload.len() {
                return Err(Error::AuthError("Payload too short for body".into()));
            }
            payload[cursor..cursor + body_len].to_vec()
        } else {
            Vec::new()
        };

        Ok(Self {
            request_id,
            method,
            url_postfix,
            headers,
            body,
        })
    }

    /// Serializes this HTTP request into payload bytes.
    pub fn to_payload(&self) -> Vec<u8> {
        let mut payload = Vec::new();

        // Write request ID (32 bytes)
        payload.extend_from_slice(&self.request_id);

        // Write method (varint length + string)
        let method_bytes = self.method.as_bytes();
        payload.extend(write_varint(method_bytes.len()));
        payload.extend_from_slice(method_bytes);

        // Write URL postfix (varint length + string)
        let url_bytes = self.url_postfix.as_bytes();
        payload.extend(write_varint(url_bytes.len()));
        payload.extend_from_slice(url_bytes);

        // Write headers (varint count, then pairs)
        payload.extend(write_varint(self.headers.len()));
        for (key, value) in &self.headers {
            let key_bytes = key.as_bytes();
            payload.extend(write_varint(key_bytes.len()));
            payload.extend_from_slice(key_bytes);
            let val_bytes = value.as_bytes();
            payload.extend(write_varint(val_bytes.len()));
            payload.extend_from_slice(val_bytes);
        }

        // Write body (varint length + bytes)
        payload.extend(write_varint(self.body.len()));
        payload.extend_from_slice(&self.body);

        payload
    }
}

/// HTTP response to be serialized as General message payload.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// Request ID (32 bytes, from response header).
    pub request_id: [u8; 32],
    /// HTTP status code.
    pub status: u16,
    /// HTTP headers (only x-bsv-* and authorization, excluding x-bsv-auth-*).
    pub headers: Vec<(String, String)>,
    /// Response body.
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// Serializes this HTTP response into payload bytes.
    ///
    /// Format: `[request_id: 32][status: varint][headers: varint+pairs][body: varint+bytes]`
    pub fn to_payload(&self) -> Vec<u8> {
        let mut payload = Vec::new();

        // Write request ID (32 bytes)
        payload.extend_from_slice(&self.request_id);

        // Write status (varint)
        payload.extend(write_varint(self.status as usize));

        // Write headers (varint count, then pairs)
        payload.extend(write_varint(self.headers.len()));
        for (key, value) in &self.headers {
            let key_bytes = key.as_bytes();
            payload.extend(write_varint(key_bytes.len()));
            payload.extend_from_slice(key_bytes);
            let val_bytes = value.as_bytes();
            payload.extend(write_varint(val_bytes.len()));
            payload.extend_from_slice(val_bytes);
        }

        // Write body (varint length + bytes)
        payload.extend(write_varint(self.body.len()));
        payload.extend_from_slice(&self.body);

        payload
    }

    /// Deserializes an HTTP response from payload bytes.
    pub fn from_payload(payload: &[u8]) -> Result<Self> {
        let mut cursor = 0;

        // Read request ID (32 bytes)
        if payload.len() < 32 {
            return Err(Error::AuthError(
                "Response payload too short for request ID".into(),
            ));
        }
        let mut request_id = [0u8; 32];
        request_id.copy_from_slice(&payload[..32]);
        cursor += 32;

        // Read status (varint)
        let (status, bytes_read) = read_varint(&payload[cursor..])?;
        cursor += bytes_read;
        let status = status as u16;

        // Read headers (varint count, then pairs)
        let (header_count, bytes_read) = read_varint(&payload[cursor..])?;
        cursor += bytes_read;
        let mut headers = Vec::with_capacity(header_count);
        for _ in 0..header_count {
            let (key_len, bytes_read) = read_varint(&payload[cursor..])?;
            cursor += bytes_read;
            if cursor + key_len > payload.len() {
                return Err(Error::AuthError(
                    "Response payload too short for header key".into(),
                ));
            }
            let key = String::from_utf8(payload[cursor..cursor + key_len].to_vec())
                .map_err(|e| Error::AuthError(format!("Invalid header key UTF-8: {}", e)))?;
            cursor += key_len;

            let (val_len, bytes_read) = read_varint(&payload[cursor..])?;
            cursor += bytes_read;
            if cursor + val_len > payload.len() {
                return Err(Error::AuthError(
                    "Response payload too short for header value".into(),
                ));
            }
            let value = String::from_utf8(payload[cursor..cursor + val_len].to_vec())
                .map_err(|e| Error::AuthError(format!("Invalid header value UTF-8: {}", e)))?;
            cursor += val_len;

            headers.push((key, value));
        }

        // Read body (varint length + bytes)
        let (body_len, bytes_read) = read_varint(&payload[cursor..])?;
        cursor += bytes_read;
        let body = if body_len > 0 && cursor + body_len <= payload.len() {
            payload[cursor..cursor + body_len].to_vec()
        } else {
            Vec::new()
        };

        Ok(Self {
            request_id,
            status,
            headers,
            body,
        })
    }
}

/// Reads a varint from the given bytes, returning (value, bytes_consumed).
fn read_varint(bytes: &[u8]) -> Result<(usize, usize)> {
    if bytes.is_empty() {
        return Err(Error::AuthError("Empty varint".into()));
    }

    let mut value: usize = 0;
    let mut shift = 0;
    let mut consumed = 0;

    for &byte in bytes {
        consumed += 1;
        value |= ((byte & 0x7F) as usize) << shift;
        if byte & 0x80 == 0 {
            return Ok((value, consumed));
        }
        shift += 7;
        if shift >= 64 {
            return Err(Error::AuthError("Varint too large".into()));
        }
    }

    Err(Error::AuthError("Incomplete varint".into()))
}

/// Writes a value as a varint.
fn write_varint(mut value: usize) -> Vec<u8> {
    let mut result = Vec::new();
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        result.push(byte);
        if value == 0 {
            break;
        }
    }
    result
}

/// HTTP-based transport for authentication.
///
/// Sends auth messages to `.well-known/auth` endpoint for handshake,
/// and general messages as HTTP requests with auth headers.
pub struct SimplifiedFetchTransport {
    /// Base URL of the remote server.
    base_url: String,
    /// HTTP client (only available with `http` feature).
    #[cfg(feature = "http")]
    client: reqwest::Client,
    /// Callback for incoming messages.
    callback: Arc<RwLock<Option<Box<TransportCallback>>>>,
}

impl std::fmt::Debug for SimplifiedFetchTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SimplifiedFetchTransport")
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl SimplifiedFetchTransport {
    /// Creates a new HTTP transport.
    ///
    /// # Arguments
    /// * `base_url` - Base URL of the remote server (e.g., `https://example.com`)
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            #[cfg(feature = "http")]
            client: reqwest::Client::new(),
            callback: Arc::new(RwLock::new(None)),
        }
    }

    /// Returns the base URL.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Returns the auth endpoint URL.
    #[cfg_attr(not(feature = "http"), allow(dead_code))]
    fn auth_url(&self) -> String {
        format!("{}/.well-known/auth", self.base_url)
    }

    /// Converts an AuthMessage to HTTP headers for general messages.
    pub fn message_to_headers(&self, message: &AuthMessage) -> Vec<(String, String)> {
        let mut headers = Vec::new();

        headers.push((headers::VERSION.to_string(), message.version.clone()));
        headers.push((
            headers::IDENTITY_KEY.to_string(),
            message.identity_key.to_hex(),
        ));
        headers.push((
            headers::MESSAGE_TYPE.to_string(),
            message.message_type.as_str().to_string(),
        ));

        if let Some(ref nonce) = message.nonce {
            headers.push((headers::NONCE.to_string(), nonce.clone()));
        }

        if let Some(ref your_nonce) = message.your_nonce {
            headers.push((headers::YOUR_NONCE.to_string(), your_nonce.clone()));
        }

        if let Some(ref sig) = message.signature {
            headers.push((
                headers::SIGNATURE.to_string(),
                crate::primitives::to_base64(sig),
            ));
        }

        if let Some(ref req_certs) = message.requested_certificates {
            if let Ok(json) = serde_json::to_string(req_certs) {
                headers.push((headers::REQUESTED_CERTIFICATES.to_string(), json));
            }
        }

        headers
    }

    /// Parses HTTP headers into AuthMessage fields.
    pub fn headers_to_message_fields(
        &self,
        header_map: &[(String, String)],
    ) -> Result<(Option<String>, Option<String>, Option<Vec<u8>>)> {
        #![allow(clippy::type_complexity)]
        let mut nonce = None;
        let mut your_nonce = None;
        let mut signature = None;

        for (key, value) in header_map {
            match key.to_lowercase().as_str() {
                k if k == headers::NONCE.to_lowercase() => {
                    nonce = Some(value.clone());
                }
                k if k == headers::YOUR_NONCE.to_lowercase() => {
                    your_nonce = Some(value.clone());
                }
                k if k == headers::SIGNATURE.to_lowercase() => {
                    signature = Some(crate::primitives::from_base64(value)?);
                }
                _ => {}
            }
        }

        Ok((nonce, your_nonce, signature))
    }

    /// Invokes the callback with a message.
    #[cfg_attr(not(feature = "http"), allow(dead_code))]
    async fn invoke_callback(&self, message: AuthMessage) -> Result<()> {
        let callback = self.callback.read().await;
        if let Some(ref cb) = *callback {
            cb(message).await?;
        }
        Ok(())
    }
}

#[async_trait]
impl Transport for SimplifiedFetchTransport {
    async fn send(&self, message: &AuthMessage) -> Result<()> {
        #[cfg(not(feature = "http"))]
        {
            let _ = message;
            return Err(Error::AuthError(
                "HTTP transport requires the 'http' feature".into(),
            ));
        }

        #[cfg(feature = "http")]
        {
            match message.message_type {
                MessageType::InitialRequest
                | MessageType::InitialResponse
                | MessageType::CertificateRequest
                | MessageType::CertificateResponse => {
                    // Send as JSON POST to .well-known/auth
                    let response = self
                        .client
                        .post(self.auth_url())
                        .json(message)
                        .send()
                        .await
                        .map_err(|e| Error::AuthError(format!("HTTP request failed: {}", e)))?;

                    if !response.status().is_success() {
                        let status = response.status();
                        let body = response.text().await.unwrap_or_default();
                        return Err(Error::AuthError(format!(
                            "Auth endpoint returned {}: {}",
                            status, body
                        )));
                    }

                    // Parse response as AuthMessage
                    let response_message: AuthMessage = response.json().await.map_err(|e| {
                        Error::AuthError(format!("Failed to parse auth response: {}", e))
                    })?;

                    // Invoke callback with response
                    self.invoke_callback(response_message).await?;
                }
                MessageType::General => {
                    // BRC-104: For General messages, deserialize payload as HTTP request,
                    // add auth headers, and make actual HTTP request

                    let payload = message.payload.as_ref().ok_or_else(|| {
                        Error::AuthError("General message must have payload".into())
                    })?;

                    // Parse the HTTP request from payload
                    let http_request = HttpRequest::from_payload(payload)?;

                    // Build URL
                    let url = format!("{}{}", self.base_url, http_request.url_postfix);

                    // Build request with auth headers
                    let mut request_builder = match http_request.method.to_uppercase().as_str() {
                        "GET" => self.client.get(&url),
                        "POST" => self.client.post(&url),
                        "PUT" => self.client.put(&url),
                        "DELETE" => self.client.delete(&url),
                        "PATCH" => self.client.patch(&url),
                        "HEAD" => self.client.head(&url),
                        _ => self.client.request(
                            reqwest::Method::from_bytes(http_request.method.as_bytes())
                                .unwrap_or(reqwest::Method::GET),
                            &url,
                        ),
                    };

                    // Add auth headers
                    request_builder = request_builder
                        .header(headers::VERSION, &message.version)
                        .header(headers::IDENTITY_KEY, message.identity_key.to_hex());

                    if let Some(ref nonce) = message.nonce {
                        request_builder = request_builder.header(headers::NONCE, nonce);
                    }

                    if let Some(ref your_nonce) = message.your_nonce {
                        request_builder = request_builder.header(headers::YOUR_NONCE, your_nonce);
                    }

                    if let Some(ref sig) = message.signature {
                        request_builder =
                            request_builder.header(headers::SIGNATURE, crate::primitives::to_hex(sig));
                    }

                    // Add request ID header
                    request_builder = request_builder.header(
                        headers::REQUEST_ID,
                        crate::primitives::to_base64(&http_request.request_id),
                    );

                    // Add original headers from payload (x-bsv-*, authorization, content-type)
                    for (key, value) in &http_request.headers {
                        let lower_key = key.to_lowercase();
                        if lower_key.starts_with("x-bsv-")
                            || lower_key == "authorization"
                            || lower_key == "content-type"
                        {
                            // Skip x-bsv-auth-* headers (we add our own)
                            if !lower_key.starts_with("x-bsv-auth") {
                                request_builder = request_builder.header(key.as_str(), value.as_str());
                            }
                        }
                    }

                    // Add body if present
                    if !http_request.body.is_empty() {
                        request_builder = request_builder.body(http_request.body.clone());
                    }

                    // Send request
                    let response = request_builder
                        .send()
                        .await
                        .map_err(|e| Error::AuthError(format!("HTTP request failed: {}", e)))?;

                    // Extract response headers and body
                    let response_status = response.status().as_u16();
                    let response_headers = response.headers().clone();
                    let response_body = response
                        .bytes()
                        .await
                        .map_err(|e| Error::AuthError(format!("Failed to read response: {}", e)))?
                        .to_vec();

                    // Check for required auth headers
                    let required_headers = [headers::VERSION, headers::IDENTITY_KEY, headers::SIGNATURE];
                    for header_name in &required_headers {
                        if response_headers.get(*header_name).is_none() {
                            return Err(Error::AuthError(format!(
                                "Response missing required auth header: {}",
                                header_name
                            )));
                        }
                    }

                    // Extract request ID from response
                    let response_request_id: [u8; 32] = if let Some(rid) = response_headers.get(headers::REQUEST_ID) {
                        let rid_str = rid.to_str().unwrap_or_default();
                        crate::primitives::from_base64(rid_str)?
                            .try_into()
                            .map_err(|_| Error::AuthError("Invalid request ID length".into()))?
                    } else {
                        http_request.request_id // Use original if not provided
                    };

                    // Extract non-auth headers (x-bsv-* except x-bsv-auth-*, authorization)
                    let mut included_headers: Vec<(String, String)> = Vec::new();
                    for (key, value) in response_headers.iter() {
                        let key_str = key.as_str().to_lowercase();
                        if (key_str.starts_with("x-bsv-") || key_str == "authorization")
                            && !key_str.starts_with("x-bsv-auth")
                        {
                            if let Ok(v) = value.to_str() {
                                included_headers.push((key_str, v.to_string()));
                            }
                        }
                    }
                    // Sort headers for consistent ordering
                    included_headers.sort_by(|a, b| a.0.cmp(&b.0));

                    // Build response payload
                    let http_response = HttpResponse {
                        request_id: response_request_id,
                        status: response_status,
                        headers: included_headers,
                        body: response_body,
                    };

                    // Build response AuthMessage
                    let resp_identity_key = response_headers
                        .get(headers::IDENTITY_KEY)
                        .and_then(|v| v.to_str().ok())
                        .ok_or_else(|| Error::AuthError("Missing identity key header".into()))?;

                    let response_identity = crate::primitives::PublicKey::from_hex(resp_identity_key)?;

                    let mut response_message =
                        AuthMessage::new(MessageType::General, response_identity);
                    response_message.payload = Some(http_response.to_payload());

                    // Extract nonces from response headers
                    if let Some(nonce) = response_headers.get(headers::NONCE) {
                        response_message.nonce = nonce.to_str().ok().map(String::from);
                    }
                    if let Some(your_nonce) = response_headers.get(headers::YOUR_NONCE) {
                        response_message.your_nonce = your_nonce.to_str().ok().map(String::from);
                    }

                    // Extract signature
                    if let Some(sig) = response_headers.get(headers::SIGNATURE) {
                        let sig_str = sig.to_str().unwrap_or_default();
                        // Try hex first, then base64
                        response_message.signature = crate::primitives::from_hex(sig_str)
                            .or_else(|_| crate::primitives::from_base64(sig_str))
                            .ok();
                    }

                    // Check for certificate request in response
                    if let Some(msg_type) = response_headers.get(headers::MESSAGE_TYPE) {
                        if msg_type.to_str().ok() == Some("certificateRequest") {
                            // Handle certificate request in response
                            if let Some(req_certs) = response_headers.get(headers::REQUESTED_CERTIFICATES)
                            {
                                if let Ok(requested) =
                                    serde_json::from_str(req_certs.to_str().unwrap_or("{}"))
                                {
                                    response_message.requested_certificates = Some(requested);
                                }
                            }
                        }
                    }

                    // Invoke callback with response
                    self.invoke_callback(response_message).await?;
                }
            }

            Ok(())
        }
    }

    fn set_callback(&self, callback: Box<TransportCallback>) {
        // We need to spawn a task to set the callback since we can't
        // make this method async
        let callback_store = self.callback.clone();
        tokio::spawn(async move {
            let mut cb = callback_store.write().await;
            *cb = Some(callback);
        });
    }

    fn clear_callback(&self) {
        let callback_store = self.callback.clone();
        tokio::spawn(async move {
            let mut cb = callback_store.write().await;
            *cb = None;
        });
    }
}

/// A mock transport for testing.
#[derive(Default)]
pub struct MockTransport {
    /// Messages that have been sent.
    sent_messages: Arc<RwLock<Vec<AuthMessage>>>,
    /// Messages to return in response.
    response_queue: Arc<RwLock<Vec<AuthMessage>>>,
    /// Callback for incoming messages.
    callback: Arc<RwLock<Option<Box<TransportCallback>>>>,
}

impl std::fmt::Debug for MockTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockTransport")
            .field("sent_messages", &"<messages>")
            .field("response_queue", &"<queue>")
            .field("callback", &"<callback>")
            .finish()
    }
}

impl MockTransport {
    /// Creates a new mock transport.
    pub fn new() -> Self {
        Self::default()
    }

    /// Queues a response message.
    pub async fn queue_response(&self, message: AuthMessage) {
        let mut queue = self.response_queue.write().await;
        queue.push(message);
    }

    /// Gets all sent messages.
    pub async fn get_sent_messages(&self) -> Vec<AuthMessage> {
        let sent = self.sent_messages.read().await;
        sent.clone()
    }

    /// Clears sent messages.
    pub async fn clear_sent(&self) {
        let mut sent = self.sent_messages.write().await;
        sent.clear();
    }

    /// Simulates receiving a message from the remote peer.
    pub async fn receive_message(&self, message: AuthMessage) -> Result<()> {
        let callback = self.callback.read().await;
        if let Some(ref cb) = *callback {
            cb(message).await?;
        }
        Ok(())
    }
}

#[async_trait]
impl Transport for MockTransport {
    async fn send(&self, message: &AuthMessage) -> Result<()> {
        // Store sent message
        {
            let mut sent = self.sent_messages.write().await;
            sent.push(message.clone());
        }

        // If there's a queued response, invoke callback
        let response = {
            let mut queue = self.response_queue.write().await;
            if !queue.is_empty() {
                Some(queue.remove(0))
            } else {
                None
            }
        };

        if let Some(resp) = response {
            let callback = self.callback.read().await;
            if let Some(ref cb) = *callback {
                cb(resp).await?;
            }
        }

        Ok(())
    }

    fn set_callback(&self, callback: Box<TransportCallback>) {
        let callback_store = self.callback.clone();
        tokio::spawn(async move {
            let mut cb = callback_store.write().await;
            *cb = Some(callback);
        });
    }

    fn clear_callback(&self) {
        let callback_store = self.callback.clone();
        tokio::spawn(async move {
            let mut cb = callback_store.write().await;
            *cb = None;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::types::MessageType;

    #[test]
    fn test_simplified_fetch_transport_new() {
        let transport = SimplifiedFetchTransport::new("https://example.com/");
        assert_eq!(transport.base_url(), "https://example.com");
        assert_eq!(transport.auth_url(), "https://example.com/.well-known/auth");
    }

    #[test]
    fn test_simplified_fetch_transport_trailing_slash() {
        let transport = SimplifiedFetchTransport::new("https://example.com///");
        assert_eq!(transport.base_url(), "https://example.com");
    }

    #[tokio::test]
    async fn test_mock_transport_send_and_receive() {
        let transport = MockTransport::new();

        // Set callback
        let received = Arc::new(RwLock::new(Vec::new()));
        let received_clone = received.clone();
        transport.set_callback(Box::new(move |msg| {
            let received = received_clone.clone();
            Box::pin(async move {
                let mut r = received.write().await;
                r.push(msg);
                Ok(())
            })
        }));

        // Wait for callback to be set
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        // Queue a response
        let response = AuthMessage::new(
            MessageType::InitialResponse,
            crate::primitives::PrivateKey::random().public_key(),
        );
        transport.queue_response(response.clone()).await;

        // Send a message
        let request = AuthMessage::new(
            MessageType::InitialRequest,
            crate::primitives::PrivateKey::random().public_key(),
        );
        transport.send(&request).await.unwrap();

        // Check sent messages
        let sent = transport.get_sent_messages().await;
        assert_eq!(sent.len(), 1);

        // Wait for callback to be invoked
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        // Check received messages
        let recv = received.read().await;
        assert_eq!(recv.len(), 1);
    }

    // =================
    // BRC-104 Varint tests
    // =================

    #[test]
    fn test_varint_roundtrip() {
        let test_values: Vec<usize> = vec![0, 1, 127, 128, 255, 256, 16383, 16384, 65535, 1000000];

        for value in test_values {
            let encoded = write_varint(value);
            let (decoded, _bytes_read) = read_varint(&encoded).unwrap();
            assert_eq!(decoded, value, "Varint roundtrip failed for {}", value);
        }
    }

    #[test]
    fn test_varint_encoding_sizes() {
        // 0-127: 1 byte
        assert_eq!(write_varint(0).len(), 1);
        assert_eq!(write_varint(127).len(), 1);

        // 128-16383: 2 bytes
        assert_eq!(write_varint(128).len(), 2);
        assert_eq!(write_varint(16383).len(), 2);

        // 16384-2097151: 3 bytes
        assert_eq!(write_varint(16384).len(), 3);
        assert_eq!(write_varint(2097151).len(), 3);
    }

    #[test]
    fn test_varint_empty_error() {
        let result = read_varint(&[]);
        assert!(result.is_err());
    }

    // =================
    // HttpRequest tests
    // =================

    #[test]
    fn test_http_request_roundtrip() {
        let request = HttpRequest {
            request_id: [42u8; 32],
            method: "POST".to_string(),
            url_postfix: "/api/v1/users".to_string(),
            headers: vec![
                ("content-type".to_string(), "application/json".to_string()),
                ("x-bsv-custom".to_string(), "value".to_string()),
            ],
            body: b"hello world".to_vec(),
        };

        let payload = request.to_payload();
        let decoded = HttpRequest::from_payload(&payload).unwrap();

        assert_eq!(decoded.request_id, request.request_id);
        assert_eq!(decoded.method, request.method);
        assert_eq!(decoded.url_postfix, request.url_postfix);
        assert_eq!(decoded.headers, request.headers);
        assert_eq!(decoded.body, request.body);
    }

    #[test]
    fn test_http_request_get_default() {
        // Empty method should default to GET
        let mut payload = vec![0u8; 32]; // request_id
        payload.extend(write_varint(0)); // empty method
        payload.extend(write_varint(0)); // empty url
        payload.extend(write_varint(0)); // no headers
        payload.extend(write_varint(0)); // no body

        let request = HttpRequest::from_payload(&payload).unwrap();
        assert_eq!(request.method, "GET");
    }

    #[test]
    fn test_http_request_with_large_body() {
        let request = HttpRequest {
            request_id: [1u8; 32],
            method: "PUT".to_string(),
            url_postfix: "/data".to_string(),
            headers: vec![],
            body: vec![0xAB; 10000], // 10KB body
        };

        let payload = request.to_payload();
        let decoded = HttpRequest::from_payload(&payload).unwrap();

        assert_eq!(decoded.body.len(), 10000);
        assert_eq!(decoded.body[0], 0xAB);
    }

    #[test]
    fn test_http_request_payload_too_short() {
        let payload = vec![0u8; 10]; // Too short for request_id
        let result = HttpRequest::from_payload(&payload);
        assert!(result.is_err());
    }

    // =================
    // HttpResponse tests
    // =================

    #[test]
    fn test_http_response_roundtrip() {
        let response = HttpResponse {
            request_id: [99u8; 32],
            status: 200,
            headers: vec![
                ("content-type".to_string(), "text/plain".to_string()),
                ("x-bsv-data".to_string(), "abc".to_string()),
            ],
            body: b"OK".to_vec(),
        };

        let payload = response.to_payload();
        let decoded = HttpResponse::from_payload(&payload).unwrap();

        assert_eq!(decoded.request_id, response.request_id);
        assert_eq!(decoded.status, response.status);
        assert_eq!(decoded.headers, response.headers);
        assert_eq!(decoded.body, response.body);
    }

    #[test]
    fn test_http_response_status_codes() {
        for status in [200, 201, 400, 401, 403, 404, 500, 503] {
            let response = HttpResponse {
                request_id: [0u8; 32],
                status,
                headers: vec![],
                body: vec![],
            };

            let payload = response.to_payload();
            let decoded = HttpResponse::from_payload(&payload).unwrap();
            assert_eq!(decoded.status, status);
        }
    }

    #[test]
    fn test_http_response_empty_body() {
        let response = HttpResponse {
            request_id: [0u8; 32],
            status: 204, // No Content
            headers: vec![],
            body: vec![],
        };

        let payload = response.to_payload();
        let decoded = HttpResponse::from_payload(&payload).unwrap();
        assert!(decoded.body.is_empty());
    }

    // =================
    // message_to_headers tests
    // =================

    #[test]
    fn test_message_to_headers() {
        let transport = SimplifiedFetchTransport::new("https://example.com");
        let key = crate::primitives::PrivateKey::random().public_key();
        let mut msg = AuthMessage::new(MessageType::General, key.clone());
        msg.nonce = Some("test-nonce".to_string());
        msg.your_nonce = Some("peer-nonce".to_string());
        msg.signature = Some(vec![0x30, 0x44]); // Fake DER signature

        let headers = transport.message_to_headers(&msg);

        // Check headers exist
        let headers_map: std::collections::HashMap<_, _> = headers.into_iter().collect();
        assert_eq!(headers_map.get(headers::VERSION), Some(&"0.1".to_string()));
        assert_eq!(
            headers_map.get(headers::IDENTITY_KEY),
            Some(&key.to_hex())
        );
        assert_eq!(headers_map.get(headers::NONCE), Some(&"test-nonce".to_string()));
        assert_eq!(
            headers_map.get(headers::YOUR_NONCE),
            Some(&"peer-nonce".to_string())
        );
        assert!(headers_map.get(headers::SIGNATURE).is_some());
    }

    #[test]
    fn test_headers_to_message_fields() {
        let transport = SimplifiedFetchTransport::new("https://example.com");
        let headers = vec![
            (headers::NONCE.to_string(), "test-nonce".to_string()),
            (headers::YOUR_NONCE.to_string(), "peer-nonce".to_string()),
            (
                headers::SIGNATURE.to_string(),
                crate::primitives::to_base64(&[0x30, 0x44]),
            ),
        ];

        let (nonce, your_nonce, signature) = transport.headers_to_message_fields(&headers).unwrap();

        assert_eq!(nonce, Some("test-nonce".to_string()));
        assert_eq!(your_nonce, Some("peer-nonce".to_string()));
        assert_eq!(signature, Some(vec![0x30, 0x44]));
    }
}
