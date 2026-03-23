//! HTTP transport using JSON payloads.
//!
//! This module provides an HTTP-based wallet substrate that communicates
//! using JSON-encoded payloads instead of the binary wire protocol.

use crate::wallet::interface::{RevealCounterpartyKeyLinkageArgs, RevealSpecificKeyLinkageArgs};
use crate::wallet::types::{
    Counterparty, Network, Protocol, RevealCounterpartyKeyLinkageResult,
    RevealSpecificKeyLinkageResult,
};
use crate::wallet::{
    AbortActionArgs, AbortActionResult, AcquireCertificateArgs, AuthenticatedResult,
    CreateActionArgs, CreateActionResult, CreateHmacArgs, CreateHmacResult, CreateSignatureArgs,
    CreateSignatureResult, DecryptArgs, DecryptResult, DiscoverByAttributesArgs,
    DiscoverByIdentityKeyArgs, DiscoverCertificatesResult, EncryptArgs, EncryptResult,
    GetHeaderArgs, GetHeaderResult, GetHeightResult, GetNetworkResult, GetPublicKeyArgs,
    GetPublicKeyResult, GetVersionResult, InternalizeActionArgs, InternalizeActionResult,
    ListActionsArgs, ListActionsResult, ListCertificatesArgs, ListCertificatesResult,
    ListOutputsArgs, ListOutputsResult, ProveCertificateArgs, ProveCertificateResult,
    RelinquishCertificateArgs, RelinquishCertificateResult, RelinquishOutputArgs,
    RelinquishOutputResult, SignActionArgs, SignActionResult, VerifyHmacArgs, VerifyHmacResult,
    VerifySignatureArgs, VerifySignatureResult, WalletCertificate, WalletInterface,
};

use crate::Error;
use async_trait::async_trait;
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
/// use bsv_rs::wallet::substrates::HttpWalletJson;
/// use bsv_rs::wallet::{GetPublicKeyArgs, Protocol, SecurityLevel};
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
#[derive(Clone)]
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
            plaintext: args.plaintext,
        };

        let response: JsonEncryptResponse = self.request("encrypt", &request, originator).await?;

        Ok(EncryptResult {
            ciphertext: response.ciphertext,
        })
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
            ciphertext: args.ciphertext,
        };

        let response: JsonDecryptResponse = self.request("decrypt", &request, originator).await?;

        Ok(DecryptResult {
            plaintext: response.plaintext,
        })
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
            data: args.data,
        };

        let response: JsonCreateHmacResponse =
            self.request("createHmac", &request, originator).await?;

        if response.hmac.len() != 32 {
            return Err(Error::WalletError(format!(
                "invalid HMAC length: expected 32, got {}",
                response.hmac.len()
            )));
        }

        let mut hmac = [0u8; 32];
        hmac.copy_from_slice(&response.hmac);

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
            data: args.data,
            hmac: args.hmac.to_vec(),
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
            data: args.data,
            hash_to_directly_sign: args
                .hash_to_directly_sign
                .map(|h| crate::primitives::to_hex(&h)),
        };

        let response: JsonCreateSignatureResponse = self
            .request("createSignature", &request, originator)
            .await?;

        Ok(CreateSignatureResult {
            signature: response.signature,
        })
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
            data: args.data,
            hash_to_directly_verify: args
                .hash_to_directly_verify
                .map(|h| crate::primitives::to_hex(&h)),
            signature: args.signature,
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

    // =========================================================================
    // Action Methods
    // =========================================================================

    /// Creates a new transaction action.
    pub async fn create_action(
        &self,
        args: CreateActionArgs,
        originator: &str,
    ) -> Result<CreateActionResult, Error> {
        self.request("createAction", &args, originator).await
    }

    /// Signs a previously created action.
    pub async fn sign_action(
        &self,
        args: SignActionArgs,
        originator: &str,
    ) -> Result<SignActionResult, Error> {
        self.request("signAction", &args, originator).await
    }

    /// Aborts an in-progress action.
    pub async fn abort_action(
        &self,
        args: AbortActionArgs,
        originator: &str,
    ) -> Result<AbortActionResult, Error> {
        self.request("abortAction", &args, originator).await
    }

    /// Lists wallet actions (transactions).
    pub async fn list_actions(
        &self,
        args: ListActionsArgs,
        originator: &str,
    ) -> Result<ListActionsResult, Error> {
        self.request("listActions", &args, originator).await
    }

    /// Internalizes an external transaction.
    pub async fn internalize_action(
        &self,
        args: InternalizeActionArgs,
        originator: &str,
    ) -> Result<InternalizeActionResult, Error> {
        self.request("internalizeAction", &args, originator).await
    }

    // =========================================================================
    // Output Methods
    // =========================================================================

    /// Lists wallet outputs.
    pub async fn list_outputs(
        &self,
        args: ListOutputsArgs,
        originator: &str,
    ) -> Result<ListOutputsResult, Error> {
        self.request("listOutputs", &args, originator).await
    }

    /// Relinquishes an output from a basket.
    pub async fn relinquish_output(
        &self,
        args: RelinquishOutputArgs,
        originator: &str,
    ) -> Result<RelinquishOutputResult, Error> {
        self.request("relinquishOutput", &args, originator).await
    }

    // =========================================================================
    // Certificate Methods
    // =========================================================================

    /// Acquires a certificate.
    pub async fn acquire_certificate(
        &self,
        args: AcquireCertificateArgs,
        originator: &str,
    ) -> Result<WalletCertificate, Error> {
        self.request("acquireCertificate", &args, originator).await
    }

    /// Lists certificates.
    pub async fn list_certificates(
        &self,
        args: ListCertificatesArgs,
        originator: &str,
    ) -> Result<ListCertificatesResult, Error> {
        self.request("listCertificates", &args, originator).await
    }

    /// Proves a certificate.
    pub async fn prove_certificate(
        &self,
        args: ProveCertificateArgs,
        originator: &str,
    ) -> Result<ProveCertificateResult, Error> {
        self.request("proveCertificate", &args, originator).await
    }

    /// Relinquishes a certificate.
    pub async fn relinquish_certificate(
        &self,
        args: RelinquishCertificateArgs,
        originator: &str,
    ) -> Result<RelinquishCertificateResult, Error> {
        self.request("relinquishCertificate", &args, originator)
            .await
    }

    // =========================================================================
    // Discovery Methods
    // =========================================================================

    /// Discovers certificates by identity key.
    pub async fn discover_by_identity_key(
        &self,
        args: DiscoverByIdentityKeyArgs,
        originator: &str,
    ) -> Result<DiscoverCertificatesResult, Error> {
        self.request("discoverByIdentityKey", &args, originator)
            .await
    }

    /// Discovers certificates by attributes.
    pub async fn discover_by_attributes(
        &self,
        args: DiscoverByAttributesArgs,
        originator: &str,
    ) -> Result<DiscoverCertificatesResult, Error> {
        self.request("discoverByAttributes", &args, originator)
            .await
    }

    // =========================================================================
    // Chain Methods
    // =========================================================================

    /// Gets a block header for a given height.
    pub async fn get_header(
        &self,
        args: GetHeaderArgs,
        originator: &str,
    ) -> Result<GetHeaderResult, Error> {
        self.request("getHeaderForHeight", &args, originator).await
    }

    /// Waits for authentication.
    pub async fn wait_for_authentication(&self, originator: &str) -> Result<bool, Error> {
        #[derive(Serialize)]
        struct EmptyRequest {}

        #[derive(Deserialize)]
        struct AuthResponse {
            authenticated: bool,
        }

        let response: AuthResponse = self
            .request("waitForAuthentication", &EmptyRequest {}, originator)
            .await?;

        Ok(response.authenticated)
    }

    // =========================================================================
    // Key Linkage Methods
    // =========================================================================

    /// Reveals counterparty key linkage.
    pub async fn reveal_counterparty_key_linkage(
        &self,
        args: RevealCounterpartyKeyLinkageArgs,
        originator: &str,
    ) -> Result<RevealCounterpartyKeyLinkageResult, Error> {
        let request = JsonRevealCounterpartyRequest {
            counterparty: crate::primitives::to_hex(&args.counterparty.to_compressed()),
            verifier: crate::primitives::to_hex(&args.verifier.to_compressed()),
            privileged: args.privileged,
            privileged_reason: args.privileged_reason,
        };

        self.request("revealCounterpartyKeyLinkage", &request, originator)
            .await
    }

    /// Reveals specific key linkage.
    pub async fn reveal_specific_key_linkage(
        &self,
        args: RevealSpecificKeyLinkageArgs,
        originator: &str,
    ) -> Result<RevealSpecificKeyLinkageResult, Error> {
        let request = JsonRevealSpecificRequest {
            counterparty: counterparty_to_string(&args.counterparty),
            verifier: crate::primitives::to_hex(&args.verifier.to_compressed()),
            protocol_id: protocol_to_json(&args.protocol_id),
            key_id: args.key_id,
            privileged: args.privileged,
            privileged_reason: args.privileged_reason,
        };

        self.request("revealSpecificKeyLinkage", &request, originator)
            .await
    }
}

// =============================================================================
// WalletInterface Implementation
// =============================================================================

#[async_trait]
impl WalletInterface for HttpWalletJson {
    async fn get_public_key(
        &self,
        args: GetPublicKeyArgs,
        originator: &str,
    ) -> crate::Result<GetPublicKeyResult> {
        self.get_public_key(args, originator).await
    }

    async fn encrypt(&self, args: EncryptArgs, originator: &str) -> crate::Result<EncryptResult> {
        self.encrypt(args, originator).await
    }

    async fn decrypt(&self, args: DecryptArgs, originator: &str) -> crate::Result<DecryptResult> {
        self.decrypt(args, originator).await
    }

    async fn create_hmac(
        &self,
        args: CreateHmacArgs,
        originator: &str,
    ) -> crate::Result<CreateHmacResult> {
        self.create_hmac(args, originator).await
    }

    async fn verify_hmac(
        &self,
        args: VerifyHmacArgs,
        originator: &str,
    ) -> crate::Result<VerifyHmacResult> {
        self.verify_hmac(args, originator).await
    }

    async fn create_signature(
        &self,
        args: CreateSignatureArgs,
        originator: &str,
    ) -> crate::Result<CreateSignatureResult> {
        self.create_signature(args, originator).await
    }

    async fn verify_signature(
        &self,
        args: VerifySignatureArgs,
        originator: &str,
    ) -> crate::Result<VerifySignatureResult> {
        self.verify_signature(args, originator).await
    }

    async fn reveal_counterparty_key_linkage(
        &self,
        args: RevealCounterpartyKeyLinkageArgs,
        originator: &str,
    ) -> crate::Result<RevealCounterpartyKeyLinkageResult> {
        self.reveal_counterparty_key_linkage(args, originator).await
    }

    async fn reveal_specific_key_linkage(
        &self,
        args: RevealSpecificKeyLinkageArgs,
        originator: &str,
    ) -> crate::Result<RevealSpecificKeyLinkageResult> {
        self.reveal_specific_key_linkage(args, originator).await
    }

    async fn create_action(
        &self,
        args: CreateActionArgs,
        originator: &str,
    ) -> crate::Result<CreateActionResult> {
        self.create_action(args, originator).await
    }

    async fn sign_action(
        &self,
        args: SignActionArgs,
        originator: &str,
    ) -> crate::Result<SignActionResult> {
        self.sign_action(args, originator).await
    }

    async fn abort_action(
        &self,
        args: AbortActionArgs,
        originator: &str,
    ) -> crate::Result<AbortActionResult> {
        self.abort_action(args, originator).await
    }

    async fn list_actions(
        &self,
        args: ListActionsArgs,
        originator: &str,
    ) -> crate::Result<ListActionsResult> {
        self.list_actions(args, originator).await
    }

    async fn internalize_action(
        &self,
        args: InternalizeActionArgs,
        originator: &str,
    ) -> crate::Result<InternalizeActionResult> {
        self.internalize_action(args, originator).await
    }

    async fn list_outputs(
        &self,
        args: ListOutputsArgs,
        originator: &str,
    ) -> crate::Result<ListOutputsResult> {
        self.list_outputs(args, originator).await
    }

    async fn relinquish_output(
        &self,
        args: RelinquishOutputArgs,
        originator: &str,
    ) -> crate::Result<RelinquishOutputResult> {
        self.relinquish_output(args, originator).await
    }

    async fn acquire_certificate(
        &self,
        args: AcquireCertificateArgs,
        originator: &str,
    ) -> crate::Result<WalletCertificate> {
        self.acquire_certificate(args, originator).await
    }

    async fn list_certificates(
        &self,
        args: ListCertificatesArgs,
        originator: &str,
    ) -> crate::Result<ListCertificatesResult> {
        self.list_certificates(args, originator).await
    }

    async fn prove_certificate(
        &self,
        args: ProveCertificateArgs,
        originator: &str,
    ) -> crate::Result<ProveCertificateResult> {
        self.prove_certificate(args, originator).await
    }

    async fn relinquish_certificate(
        &self,
        args: RelinquishCertificateArgs,
        originator: &str,
    ) -> crate::Result<RelinquishCertificateResult> {
        self.relinquish_certificate(args, originator).await
    }

    async fn discover_by_identity_key(
        &self,
        args: DiscoverByIdentityKeyArgs,
        originator: &str,
    ) -> crate::Result<DiscoverCertificatesResult> {
        self.discover_by_identity_key(args, originator).await
    }

    async fn discover_by_attributes(
        &self,
        args: DiscoverByAttributesArgs,
        originator: &str,
    ) -> crate::Result<DiscoverCertificatesResult> {
        self.discover_by_attributes(args, originator).await
    }

    async fn is_authenticated(&self, originator: &str) -> crate::Result<AuthenticatedResult> {
        Ok(AuthenticatedResult {
            authenticated: self.is_authenticated(originator).await?,
        })
    }

    async fn wait_for_authentication(
        &self,
        originator: &str,
    ) -> crate::Result<AuthenticatedResult> {
        Ok(AuthenticatedResult {
            authenticated: self.wait_for_authentication(originator).await?,
        })
    }

    async fn get_height(&self, originator: &str) -> crate::Result<GetHeightResult> {
        Ok(GetHeightResult {
            height: self.get_height(originator).await? as u32,
        })
    }

    async fn get_header_for_height(
        &self,
        args: GetHeaderArgs,
        originator: &str,
    ) -> crate::Result<GetHeaderResult> {
        self.get_header(args, originator).await
    }

    async fn get_network(&self, originator: &str) -> crate::Result<GetNetworkResult> {
        Ok(GetNetworkResult {
            network: self.get_network(originator).await?,
        })
    }

    async fn get_version(&self, originator: &str) -> crate::Result<GetVersionResult> {
        Ok(GetVersionResult {
            version: self.get_version(originator).await?,
        })
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
    plaintext: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsonEncryptResponse {
    ciphertext: Vec<u8>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonDecryptRequest {
    protocol_id: (u8, String),
    key_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    counterparty: Option<String>,
    ciphertext: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsonDecryptResponse {
    plaintext: Vec<u8>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonCreateHmacRequest {
    protocol_id: (u8, String),
    key_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    counterparty: Option<String>,
    data: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsonCreateHmacResponse {
    hmac: Vec<u8>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonVerifyHmacRequest {
    protocol_id: (u8, String),
    key_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    counterparty: Option<String>,
    data: Vec<u8>,
    hmac: Vec<u8>,
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
    data: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hash_to_directly_sign: Option<String>, // hex
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsonCreateSignatureResponse {
    signature: Vec<u8>,
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
    data: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hash_to_directly_verify: Option<String>, // hex
    signature: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsonVerifySignatureResponse {
    valid: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonRevealCounterpartyRequest {
    counterparty: String, // hex pubkey
    verifier: String,     // hex pubkey
    #[serde(skip_serializing_if = "Option::is_none")]
    privileged: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    privileged_reason: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonRevealSpecificRequest {
    counterparty: String,      // "self", "anyone", or hex pubkey
    verifier: String,          // hex pubkey
    protocol_id: (u8, String), // (security_level, protocol_name)
    key_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    privileged: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    privileged_reason: Option<String>,
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
