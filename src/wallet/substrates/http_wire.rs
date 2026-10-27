//! HTTP transport for the WalletWire binary protocol.
//!
//! This module provides an HTTP-based implementation of the [`WalletWire`] trait,
//! enabling wallet communication over HTTP using the efficient binary wire protocol.

use crate::transaction::broadcasters::transport_fault as fault;
use crate::wallet::validation::validate_originator;
use crate::wallet::wire::{WalletCall, WalletWire};
use crate::{Error, TransportFault};
use reqwest::{Client, StatusCode};

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
/// - Headers: `Origin`, the frame's originator as `validate_originator`
///   normalized it, raw (no origin form), empty when the frame has none
/// - Body: The raw payload bytes
///
/// # The originator (#323)
///
/// The reference's rule (`ts-stack@edf6e03` `HTTPWalletWire.ts:17-20`,
/// `:50-66`): the constructor validates the originator and normalizes the
/// base URL (an exact origin, cleartext only to a loopback host); a frame's
/// originator is validated, and when one is configured the frame's must
/// equal it, else the frame is refused unsent. The client `new` builds
/// follows no redirect (`redirect: 'error'`); a client given to
/// `with_client` is used as given.
///
/// # Example
///
/// ```rust,ignore
/// use bsv_rs::wallet::substrates::HttpWalletWire;
/// use bsv_rs::wallet::wire::WalletWireTransceiver;
///
/// let wire = HttpWalletWire::new(Some("myapp.example.com".into()), None)?;
/// let wallet = WalletWireTransceiver::new(wire);
/// let version = wallet.get_version("myapp.example.com").await?;
/// ```
pub struct HttpWalletWire {
    client: Client,
    base_url: String,
    originator: Option<String>,
}

/// The reference's `MAX_WALLET_WIRE_FRAME_BYTES` (`WalletWire.ts:9`).
const MAX_WALLET_WIRE_FRAME_BYTES: usize = 256 * 1024 * 1024;

impl HttpWalletWire {
    /// Creates a wire to the wallet at `base_url` (default
    /// `http://localhost:3301`) on a client that follows no redirect.
    ///
    /// # Errors
    ///
    /// The originator and the base URL refused as the type's doc says.
    pub fn new(originator: Option<String>, base_url: Option<String>) -> Result<Self, Error> {
        Self::with_client(super::origin::default_client()?, originator, base_url)
    }

    /// Creates a wire on `client`, used as given (its redirect policy too).
    ///
    /// # Errors
    ///
    /// As [`HttpWalletWire::new`].
    pub fn with_client(
        client: Client,
        originator: Option<String>,
        base_url: Option<String>,
    ) -> Result<Self, Error> {
        let originator = validate_originator(originator.as_deref())?;
        let base_url = base_url.as_deref().unwrap_or(super::DEFAULT_WIRE_URL);
        Ok(Self {
            client,
            base_url: super::origin::normalize_wallet_http_base_url(base_url)?,
            originator,
        })
    }

    /// Returns the base URL, the origin the constructor normalized.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Returns the originator, as `validate_originator` normalized it.
    pub fn originator(&self) -> Option<&str> {
        self.originator.as_deref()
    }

    /// The frame's originator, validated, and refused when it is not the
    /// configured one (`HTTPWalletWire.ts:43-56`).
    fn frame_originator(&self, bytes: &[u8]) -> Result<Option<String>, Error> {
        let originator = match bytes {
            [] => None,
            bytes => {
                let text = std::str::from_utf8(bytes)
                    .map_err(|_| Error::WalletError("invalid originator UTF-8".to_string()))?;
                validate_originator(Some(text))?
            }
        };
        if self.originator.is_some() && originator != self.originator {
            return Err(Error::WalletError(
                "Wallet Wire frame originator does not match the configured originator".to_string(),
            ));
        }
        Ok(originator)
    }
}

#[async_trait::async_trait]
impl WalletWire for HttpWalletWire {
    async fn transmit_to_wallet(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        // Parse the message header to extract call code and originator
        if message.is_empty() {
            return Err(Error::WalletError("empty message".to_string()));
        }
        if message.len() > MAX_WALLET_WIRE_FRAME_BYTES {
            return Err(Error::WalletError(
                "HTTPWalletWire request exceeds the maximum permitted size".to_string(),
            ));
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

        if originator_len > 250 {
            return Err(Error::WalletError(format!(
                "Invalid originator length: expected at most 250 bytes, received {originator_len}"
            )));
        }
        if message.len() < 2 + originator_len {
            return Err(Error::WalletError(
                "message too short for originator".to_string(),
            ));
        }
        let originator = self.frame_originator(&message[2..2 + originator_len])?;

        // Remaining bytes are the payload
        let payload = &message[2 + originator_len..];

        // Build URL
        let url = format!("{}/{}", self.base_url, call_name);

        // The frame's originator raw, empty when it has none
        let request = self
            .client
            .post(&url)
            .header("Content-Type", "application/octet-stream")
            .header("Origin", originator.unwrap_or_default())
            .body(payload.to_vec());

        // Send request
        let response = request
            .send()
            .await
            .map_err(|e| fault::wallet_error(&e, format!("HTTP request failed: {}", e)))?;

        if response.status().is_redirection() {
            return Err(super::origin::redirect_refused(
                response.status(),
                call_name,
            ));
        }
        // Check status: the wire has no busy word, so a fault is the
        // status's, read before the body
        if !response.status().is_success() {
            let code = response.status();
            let fault = fault::status_fault(code, response.headers());
            let body = response.text().await.unwrap_or_default();
            let detail = format!("HTTP {} for {}: {}", code, call_name, body);
            let status = Some(code.as_u16());
            return Err(match (fault, code) {
                (
                    Some(fault @ TransportFault::RateLimited { .. }),
                    StatusCode::TOO_MANY_REQUESTS,
                ) => Error::TransportFault {
                    fault,
                    status,
                    detail,
                },
                (Some(_), _) => Error::WalletTransport { status, detail },
                (None, _) => Error::WalletError(detail),
            });
        }

        // Return response bytes
        let bytes = response
            .bytes()
            .await
            .map_err(|e| fault::wallet_error(&e, format!("failed to read response body: {}", e)))?;

        Ok(bytes.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_url() {
        let wire = HttpWalletWire::new(None, None).unwrap();
        assert_eq!(wire.base_url(), "http://localhost:3301");
    }

    #[test]
    fn test_custom_url() {
        let wire = HttpWalletWire::new(None, Some("https://wallet.example.com".into())).unwrap();
        assert_eq!(wire.base_url(), "https://wallet.example.com");
    }

    #[test]
    fn test_originator() {
        let wire = HttpWalletWire::new(Some("myapp.example.com".into()), None).unwrap();
        assert_eq!(wire.originator(), Some("myapp.example.com"));

        let wire = HttpWalletWire::new(None, None).unwrap();
        assert_eq!(wire.originator(), None);
    }
}
