//! HTTP transport for auth messages (SimplifiedFetchTransport).
//!
//! This module provides HTTP-based transport for authentication messages,
//! implementing BRC-104 headers for authenticated HTTP communication.

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
    /// Message signature (base64).
    pub const SIGNATURE: &str = "x-bsv-auth-signature";
    /// Message type.
    pub const MESSAGE_TYPE: &str = "x-bsv-auth-message-type";
    /// Request ID for correlating requests/responses.
    pub const REQUEST_ID: &str = "x-bsv-auth-request-id";
    /// Requested certificates specification (JSON).
    pub const REQUESTED_CERTIFICATES: &str = "x-bsv-auth-requested-certificates";
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
    /// * `base_url` - Base URL of the remote server (e.g., "https://example.com")
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
    #[allow(dead_code)]
    fn message_to_headers(&self, message: &AuthMessage) -> Vec<(String, String)> {
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
    #[allow(dead_code)]
    fn headers_to_message_fields(
        &self,
        header_map: &[(String, String)],
    ) -> Result<(Option<String>, Option<String>, Option<Vec<u8>>)> {
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
                        .post(&self.auth_url())
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
                    // For general messages, we need to:
                    // 1. Deserialize payload as HTTP request
                    // 2. Add auth headers
                    // 3. Send request
                    // 4. Reconstruct AuthMessage from response

                    // For simplicity in this implementation, we send general messages
                    // as JSON to the auth endpoint as well
                    let response = self
                        .client
                        .post(&self.auth_url())
                        .json(message)
                        .send()
                        .await
                        .map_err(|e| Error::AuthError(format!("HTTP request failed: {}", e)))?;

                    if !response.status().is_success() {
                        let status = response.status();
                        let body = response.text().await.unwrap_or_default();
                        return Err(Error::AuthError(format!(
                            "Server returned {}: {}",
                            status, body
                        )));
                    }

                    // Parse response as AuthMessage
                    let response_message: AuthMessage = response.json().await.map_err(|e| {
                        Error::AuthError(format!("Failed to parse response: {}", e))
                    })?;

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
}
