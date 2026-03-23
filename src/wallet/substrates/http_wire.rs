//! HTTP transport for the WalletWire binary protocol.
//!
//! This module provides an HTTP-based implementation of the [`WalletWire`] trait,
//! enabling wallet communication over HTTP using the efficient binary wire protocol.

use crate::wallet::wire::{WalletCall, WalletWire};
use crate::Error;
use reqwest::Client;

/// HTTP transport for the WalletWire binary protocol.
///
/// `HttpWalletWire` implements the [`WalletWire`] trait by sending binary
/// messages over HTTP POST requests. It extracts the call name from the
/// message to construct the appropriate endpoint URL.
///
/// # Wire Message Format
///
/// The incoming binary message has the format:
/// ```text
/// [call_code: 1 byte][originator_len: 1 byte][originator: N bytes][payload: ...]
/// ```
///
/// # HTTP Request
///
/// - Method: POST
/// - URL: `{base_url}/{call_name}` (e.g., `http://localhost:3301/getPublicKey`)
/// - Content-Type: `application/octet-stream`
/// - Headers: `Origin` header set from originator if present
/// - Body: The raw payload bytes
///
/// # Example
///
/// ```rust,ignore
/// use bsv_rs::wallet::substrates::HttpWalletWire;
/// use bsv_rs::wallet::wire::WalletWireTransceiver;
///
/// // Create wire transport
/// let wire = HttpWalletWire::new(
///     Some("myapp.example.com".into()),
///     None, // Uses default http://localhost:3301
/// );
///
/// // Wrap with transceiver for high-level wallet operations
/// let wallet = WalletWireTransceiver::new(wire);
///
/// // Make wallet calls
/// let version = wallet.get_version("myapp.example.com").await?;
/// ```
pub struct HttpWalletWire {
    client: Client,
    base_url: String,
    originator: Option<String>,
}

impl HttpWalletWire {
    /// Creates a new HTTP wallet wire transport.
    ///
    /// # Arguments
    ///
    /// * `originator` - Optional originator identifier for the client
    /// * `base_url` - Optional base URL; defaults to `http://localhost:3301`
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // With defaults
    /// let wire = HttpWalletWire::new(None, None);
    ///
    /// // With custom originator and URL
    /// let wire = HttpWalletWire::new(
    ///     Some("myapp.example.com".into()),
    ///     Some("https://wallet.example.com:3301".into()),
    /// );
    /// ```
    pub fn new(originator: Option<String>, base_url: Option<String>) -> Self {
        Self {
            client: Client::new(),
            base_url: base_url.unwrap_or_else(|| super::DEFAULT_WIRE_URL.to_string()),
            originator,
        }
    }

    /// Creates a new HTTP wallet wire transport with a custom HTTP client.
    ///
    /// This allows configuration of timeouts, TLS settings, proxies, etc.
    pub fn with_client(
        client: Client,
        originator: Option<String>,
        base_url: Option<String>,
    ) -> Self {
        Self {
            client,
            base_url: base_url.unwrap_or_else(|| super::DEFAULT_WIRE_URL.to_string()),
            originator,
        }
    }

    /// Returns the base URL.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Returns the originator.
    pub fn originator(&self) -> Option<&str> {
        self.originator.as_deref()
    }
}

#[async_trait::async_trait]
impl WalletWire for HttpWalletWire {
    async fn transmit_to_wallet(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        // Parse the message header to extract call code and originator
        if message.is_empty() {
            return Err(Error::WalletError("empty message".to_string()));
        }

        // First byte is the call code
        let call_code = message[0];
        let call = WalletCall::try_from(call_code)?;
        let call_name = call.method_name();

        // Second byte is originator length
        if message.len() < 2 {
            return Err(Error::WalletError(
                "message too short for originator length".to_string(),
            ));
        }
        let originator_len = message[1] as usize;

        // Extract originator string
        if message.len() < 2 + originator_len {
            return Err(Error::WalletError(
                "message too short for originator".to_string(),
            ));
        }
        let originator = if originator_len > 0 {
            String::from_utf8(message[2..2 + originator_len].to_vec())
                .map_err(|_| Error::WalletError("invalid originator UTF-8".to_string()))?
        } else {
            String::new()
        };

        // Remaining bytes are the payload
        let payload = &message[2 + originator_len..];

        // Build URL
        let url = format!("{}/{}", self.base_url, call_name);

        // Build request
        let mut request = self
            .client
            .post(&url)
            .header("Content-Type", "application/octet-stream")
            .body(payload.to_vec());

        // Set Origin header from originator (or fallback to configured originator)
        let origin = if !originator.is_empty() {
            Some(to_origin_header(&originator))
        } else {
            self.originator.as_ref().map(|o| to_origin_header(o))
        };

        if let Some(origin) = origin {
            request = request.header("Origin", origin);
        }

        // Send request
        let response = request
            .send()
            .await
            .map_err(|e| Error::WalletError(format!("HTTP request failed: {}", e)))?;

        // Check status
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(Error::WalletError(format!(
                "HTTP {} for {}: {}",
                status, call_name, body
            )));
        }

        // Return response bytes
        let bytes = response
            .bytes()
            .await
            .map_err(|e| Error::WalletError(format!("failed to read response body: {}", e)))?;

        Ok(bytes.to_vec())
    }
}

/// Converts an originator domain to an origin header value.
fn to_origin_header(originator: &str) -> String {
    // If it already looks like a URL, use it as-is
    if originator.starts_with("http://") || originator.starts_with("https://") {
        originator.to_string()
    } else {
        // Convert domain to http:// origin
        format!("http://{}", originator)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_origin_header() {
        assert_eq!(to_origin_header("example.com"), "http://example.com");
        assert_eq!(to_origin_header("http://example.com"), "http://example.com");
        assert_eq!(
            to_origin_header("https://example.com"),
            "https://example.com"
        );
    }

    #[test]
    fn test_default_url() {
        let wire = HttpWalletWire::new(None, None);
        assert_eq!(wire.base_url(), "http://localhost:3301");
    }

    #[test]
    fn test_custom_url() {
        let wire = HttpWalletWire::new(None, Some("https://wallet.example.com".into()));
        assert_eq!(wire.base_url(), "https://wallet.example.com");
    }

    #[test]
    fn test_originator() {
        let wire = HttpWalletWire::new(Some("myapp.example.com".into()), None);
        assert_eq!(wire.originator(), Some("myapp.example.com"));

        let wire = HttpWalletWire::new(None, None);
        assert_eq!(wire.originator(), None);
    }
}
