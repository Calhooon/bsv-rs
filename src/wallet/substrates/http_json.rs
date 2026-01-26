//! HTTP transport using JSON payloads.
//!
//! This module provides an HTTP-based wallet substrate that communicates
//! using JSON-encoded payloads instead of the binary wire protocol.

use crate::wallet::types::{Counterparty, Network, Protocol};
use crate::wallet::{
    CreateHmacArgs, CreateHmacResult, CreateSignatureArgs, CreateSignatureResult, DecryptArgs,
    DecryptResult, EncryptArgs, EncryptResult, GetPublicKeyArgs, GetPublicKeyResult,
    VerifyHmacArgs, VerifyHmacResult, VerifySignatureArgs, VerifySignatureResult,
};
use crate::Error;
use reqwest::Client;
use serde::{Deserialize, Serialize};

/// HTTP substrate using JSON payloads.
///
/// `HttpWalletJson` provides a simpler, more debuggable alternative to the
/// binary wire protocol. Each wallet method is called via HTTP POST with
/// JSON request/response bodies.
///
/// # Endpoints
///
/// Each wallet method maps to a URL path:
/// - `getPublicKey` -> `POST /getPublicKey`
/// - `encrypt` -> `POST /encrypt`
/// - `decrypt` -> `POST /decrypt`
/// - etc.
///
/// # Example
///
/// ```rust,ignore
/// use bsv_sdk::wallet::substrates::HttpWalletJson;
/// use bsv_sdk::wallet::{GetPublicKeyArgs, Protocol, SecurityLevel};
///
/// let client = HttpWalletJson::new(
///     Some("myapp.example.com".into()),
///     None, // Uses default http://localhost:3321
/// );
///
/// let result = client.get_public_key(
///     GetPublicKeyArgs {
///         identity_key: true,
///         protocol_id: None,
///         key_id: None,
///         counterparty: None,
///         for_self: None,
///     },
///     "myapp.example.com",
/// ).await?;
/// ```
pub struct HttpWalletJson {
    client: Client,
    base_url: String,
    originator: Option<String>,
}

impl HttpWalletJson {
    /// Creates a new HTTP JSON wallet client.
    ///
    /// # Arguments
    ///
    /// * `originator` - Optional originator identifier for the client
    /// * `base_url` - Optional base URL; defaults to `http://localhost:3321`
    pub fn new(originator: Option<String>, base_url: Option<String>) -> Self {
        Self {
            client: Client::new(),
            base_url: base_url.unwrap_or_else(|| super::DEFAULT_JSON_URL.to_string()),
            originator,
        }
    }

    /// Creates a new HTTP JSON wallet client with a custom HTTP client.
    pub fn with_client(
        client: Client,
        originator: Option<String>,
        base_url: Option<String>,
    ) -> Self {
        Self {
            client,
            base_url: base_url.unwrap_or_else(|| super::DEFAULT_JSON_URL.to_string()),
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

    /// Makes a JSON API request to the wallet.
    async fn request<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        args: &T,
        originator: &str,
    ) -> Result<R, Error> {
        let url = format!("{}/{}", self.base_url, method);

        // Build request with originator header
        let origin = if !originator.is_empty() {
            to_origin_header(originator)
        } else if let Some(ref orig) = self.originator {
            to_origin_header(orig)
        } else {
            String::new()
        };

        let mut request = self.client.post(&url).json(args);

        if !origin.is_empty() {
            request = request.header("Originator", &origin);
        }

        // Send request
        let response = request
            .send()
            .await
            .map_err(|e| Error::WalletError(format!("HTTP request failed: {}", e)))?;

        // Check for error status
        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();

            // Try to parse error response
            if let Ok(error_response) = serde_json::from_str::<JsonErrorResponse>(&text) {
                return Err(wallet_error_from_code(
                    error_response.code,
                    &error_response.description,
                ));
            }

            return Err(Error::WalletError(format!(
                "HTTP {} for {}: {}",
                status, method, text
            )));
        }

        // Parse response
        response
            .json::<R>()
            .await
            .map_err(|e| Error::WalletError(format!("failed to parse JSON response: {}", e)))
    }

    // =========================================================================
    // Wallet Interface Methods
    // =========================================================================

    /// Gets a public key from the wallet.
    pub async fn get_public_key(
        &self,
        args: GetPublicKeyArgs,
        originator: &str,
    ) -> Result<GetPublicKeyResult, Error> {
        let request = JsonGetPublicKeyRequest {
            identity_key: args.identity_key,
            protocol_id: args.protocol_id.as_ref().map(protocol_to_json),
            key_id: args.key_id,
            counterparty: args.counterparty.as_ref().map(counterparty_to_string),
            for_self: args.for_self,
        };

        let response: JsonGetPublicKeyResponse =
            self.request("getPublicKey", &request, originator).await?;

        Ok(GetPublicKeyResult {
            public_key: response.public_key,
        })
    }

    /// Encrypts data using the wallet's derived key.
    pub async fn encrypt(
        &self,
        args: EncryptArgs,
        originator: &str,
    ) -> Result<EncryptResult, Error> {
        let request = JsonEncryptRequest {
            protocol_id: protocol_to_json(&args.protocol_id),
            key_id: args.key_id,
            counterparty: args.counterparty.as_ref().map(counterparty_to_string),
            plaintext: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &args.plaintext,
            ),
        };

        let response: JsonEncryptResponse = self.request("encrypt", &request, originator).await?;

        let ciphertext = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &response.ciphertext,
        )
        .map_err(|e| Error::WalletError(format!("invalid base64 ciphertext: {}", e)))?;

        Ok(EncryptResult { ciphertext })
    }

    /// Decrypts data using the wallet's derived key.
    pub async fn decrypt(
        &self,
        args: DecryptArgs,
        originator: &str,
    ) -> Result<DecryptResult, Error> {
        let request = JsonDecryptRequest {
            protocol_id: protocol_to_json(&args.protocol_id),
            key_id: args.key_id,
            counterparty: args.counterparty.as_ref().map(counterparty_to_string),
            ciphertext: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &args.ciphertext,
            ),
        };

        let response: JsonDecryptResponse = self.request("decrypt", &request, originator).await?;

        let plaintext = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &response.plaintext,
        )
        .map_err(|e| Error::WalletError(format!("invalid base64 plaintext: {}", e)))?;

        Ok(DecryptResult { plaintext })
    }

    /// Creates an HMAC using the wallet's derived key.
    pub async fn create_hmac(
        &self,
        args: CreateHmacArgs,
        originator: &str,
    ) -> Result<CreateHmacResult, Error> {
        let request = JsonCreateHmacRequest {
            protocol_id: protocol_to_json(&args.protocol_id),
            key_id: args.key_id,
            counterparty: args.counterparty.as_ref().map(counterparty_to_string),
            data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &args.data),
        };

        let response: JsonCreateHmacResponse =
            self.request("createHmac", &request, originator).await?;

        let hmac_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &response.hmac)
                .map_err(|e| Error::WalletError(format!("invalid base64 hmac: {}", e)))?;

        if hmac_bytes.len() != 32 {
            return Err(Error::WalletError(format!(
                "invalid HMAC length: expected 32, got {}",
                hmac_bytes.len()
            )));
        }

        let mut hmac = [0u8; 32];
        hmac.copy_from_slice(&hmac_bytes);

        Ok(CreateHmacResult { hmac })
    }

    /// Verifies an HMAC using the wallet's derived key.
    pub async fn verify_hmac(
        &self,
        args: VerifyHmacArgs,
        originator: &str,
    ) -> Result<VerifyHmacResult, Error> {
        let request = JsonVerifyHmacRequest {
            protocol_id: protocol_to_json(&args.protocol_id),
            key_id: args.key_id,
            counterparty: args.counterparty.as_ref().map(counterparty_to_string),
            data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &args.data),
            hmac: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, args.hmac),
        };

        let response: JsonVerifyHmacResponse =
            self.request("verifyHmac", &request, originator).await?;

        Ok(VerifyHmacResult {
            valid: response.valid,
        })
    }

    /// Creates a signature using the wallet's derived key.
    pub async fn create_signature(
        &self,
        args: CreateSignatureArgs,
        originator: &str,
    ) -> Result<CreateSignatureResult, Error> {
        let request = JsonCreateSignatureRequest {
            protocol_id: protocol_to_json(&args.protocol_id),
            key_id: args.key_id,
            counterparty: args.counterparty.as_ref().map(counterparty_to_string),
            data: args
                .data
                .map(|d| base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &d)),
            hash_to_directly_sign: args
                .hash_to_directly_sign
                .map(|h| crate::primitives::to_hex(&h)),
        };

        let response: JsonCreateSignatureResponse = self
            .request("createSignature", &request, originator)
            .await?;

        let signature = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &response.signature,
        )
        .map_err(|e| Error::WalletError(format!("invalid base64 signature: {}", e)))?;

        Ok(CreateSignatureResult { signature })
    }

    /// Verifies a signature using the wallet's derived key.
    pub async fn verify_signature(
        &self,
        args: VerifySignatureArgs,
        originator: &str,
    ) -> Result<VerifySignatureResult, Error> {
        let request = JsonVerifySignatureRequest {
            protocol_id: protocol_to_json(&args.protocol_id),
            key_id: args.key_id,
            counterparty: args.counterparty.as_ref().map(counterparty_to_string),
            for_self: args.for_self,
            data: args
                .data
                .map(|d| base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &d)),
            hash_to_directly_verify: args
                .hash_to_directly_verify
                .map(|h| crate::primitives::to_hex(&h)),
            signature: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &args.signature,
            ),
        };

        let response: JsonVerifySignatureResponse = self
            .request("verifySignature", &request, originator)
            .await?;

        Ok(VerifySignatureResult {
            valid: response.valid,
        })
    }

    /// Checks if the wallet is authenticated.
    pub async fn is_authenticated(&self, originator: &str) -> Result<bool, Error> {
        #[derive(Serialize)]
        struct EmptyRequest {}

        #[derive(Deserialize)]
        struct AuthResponse {
            authenticated: bool,
        }

        let response: AuthResponse = self
            .request("isAuthenticated", &EmptyRequest {}, originator)
            .await?;

        Ok(response.authenticated)
    }

    /// Gets the current block height.
    pub async fn get_height(&self, originator: &str) -> Result<u64, Error> {
        #[derive(Serialize)]
        struct EmptyRequest {}

        #[derive(Deserialize)]
        struct HeightResponse {
            height: u64,
        }

        let response: HeightResponse = self
            .request("getHeight", &EmptyRequest {}, originator)
            .await?;

        Ok(response.height)
    }

    /// Gets the network the wallet is connected to.
    pub async fn get_network(&self, originator: &str) -> Result<Network, Error> {
        #[derive(Serialize)]
        struct EmptyRequest {}

        #[derive(Deserialize)]
        struct NetworkResponse {
            network: String,
        }

        let response: NetworkResponse = self
            .request("getNetwork", &EmptyRequest {}, originator)
            .await?;

        match response.network.as_str() {
            "mainnet" => Ok(Network::Mainnet),
            "testnet" => Ok(Network::Testnet),
            _ => Err(Error::WalletError(format!(
                "unknown network: {}",
                response.network
            ))),
        }
    }

    /// Gets the wallet version.
    pub async fn get_version(&self, originator: &str) -> Result<String, Error> {
        #[derive(Serialize)]
        struct EmptyRequest {}

        #[derive(Deserialize)]
        struct VersionResponse {
            version: String,
        }

        let response: VersionResponse = self
            .request("getVersion", &EmptyRequest {}, originator)
            .await?;

        Ok(response.version)
    }
}

// =============================================================================
// JSON Request/Response Types
// =============================================================================

#[derive(Deserialize)]
struct JsonErrorResponse {
    code: u8,
    description: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonGetPublicKeyRequest {
    identity_key: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol_id: Option<(u8, String)>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    counterparty: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    for_self: Option<bool>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsonGetPublicKeyResponse {
    public_key: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonEncryptRequest {
    protocol_id: (u8, String),
    key_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    counterparty: Option<String>,
    plaintext: String, // base64
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsonEncryptResponse {
    ciphertext: String, // base64
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonDecryptRequest {
    protocol_id: (u8, String),
    key_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    counterparty: Option<String>,
    ciphertext: String, // base64
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsonDecryptResponse {
    plaintext: String, // base64
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonCreateHmacRequest {
    protocol_id: (u8, String),
    key_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    counterparty: Option<String>,
    data: String, // base64
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsonCreateHmacResponse {
    hmac: String, // base64
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonVerifyHmacRequest {
    protocol_id: (u8, String),
    key_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    counterparty: Option<String>,
    data: String, // base64
    hmac: String, // base64
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsonVerifyHmacResponse {
    valid: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonCreateSignatureRequest {
    protocol_id: (u8, String),
    key_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    counterparty: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<String>, // base64
    #[serde(skip_serializing_if = "Option::is_none")]
    hash_to_directly_sign: Option<String>, // hex
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsonCreateSignatureResponse {
    signature: String, // base64
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonVerifySignatureRequest {
    protocol_id: (u8, String),
    key_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    counterparty: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    for_self: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<String>, // base64
    #[serde(skip_serializing_if = "Option::is_none")]
    hash_to_directly_verify: Option<String>, // hex
    signature: String, // base64
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsonVerifySignatureResponse {
    valid: bool,
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Converts an originator domain to an origin header value.
fn to_origin_header(originator: &str) -> String {
    if originator.starts_with("http://") || originator.starts_with("https://") {
        originator.to_string()
    } else {
        format!("http://{}", originator)
    }
}

/// Converts a Protocol to JSON tuple format.
fn protocol_to_json(protocol: &Protocol) -> (u8, String) {
    (
        protocol.security_level.as_u8(),
        protocol.protocol_name.clone(),
    )
}

/// Converts a Counterparty to string format for JSON.
fn counterparty_to_string(counterparty: &Counterparty) -> String {
    match counterparty {
        Counterparty::Self_ => "self".to_string(),
        Counterparty::Anyone => "anyone".to_string(),
        Counterparty::Other(pubkey) => crate::primitives::to_hex(&pubkey.to_compressed()),
    }
}

/// Creates a wallet error from an error code.
fn wallet_error_from_code(code: u8, description: &str) -> Error {
    Error::WalletError(format!("wallet error (code {}): {}", code, description))
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
    fn test_protocol_to_json() {
        use crate::wallet::SecurityLevel;

        let protocol = Protocol::new(SecurityLevel::App, "my test protocol");
        let json = protocol_to_json(&protocol);
        assert_eq!(json, (1, "my test protocol".to_string()));
    }

    #[test]
    fn test_counterparty_to_string() {
        assert_eq!(counterparty_to_string(&Counterparty::Self_), "self");
        assert_eq!(counterparty_to_string(&Counterparty::Anyone), "anyone");
    }

    #[test]
    fn test_default_url() {
        let client = HttpWalletJson::new(None, None);
        assert_eq!(client.base_url(), "http://localhost:3321");
    }

    #[test]
    fn test_custom_url() {
        let client = HttpWalletJson::new(None, Some("https://wallet.example.com".into()));
        assert_eq!(client.base_url(), "https://wallet.example.com");
    }
}
