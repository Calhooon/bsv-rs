//! HTTP transport using JSON payloads.
//!
//! This module provides an HTTP-based wallet substrate that communicates
//! using JSON-encoded payloads instead of the binary wire protocol.

use crate::wallet::interface::{RevealCounterpartyKeyLinkageArgs, RevealSpecificKeyLinkageArgs};
use crate::wallet::types::{
    Counterparty, Network, Protocol, RevealCounterpartyKeyLinkageResult,
    RevealSpecificKeyLinkageResult,
};
use crate::wallet::validation::validate_originator;
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

use crate::transaction::broadcasters::transport_fault::{self as fault, delta_seconds_ms};
use crate::{Error, TransportFault, WalletRefusalClass};
use async_trait::async_trait;
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};

mod key_requests;
mod review_actions;
use key_requests::{
    key_params, permission, JsonCreateHmacRequest, JsonCreateHmacResponse,
    JsonCreateSignatureRequest, JsonCreateSignatureResponse, JsonDecryptRequest,
    JsonDecryptResponse, JsonEncryptRequest, JsonEncryptResponse, JsonGetPublicKeyRequest,
    JsonGetPublicKeyResponse, JsonKeyParams, JsonPermission, JsonRevealCounterpartyRequest,
    JsonRevealSpecificRequest, JsonVerifyHmacRequest, JsonVerifyHmacResponse,
    JsonVerifySignatureRequest, JsonVerifySignatureResponse,
};
use review_actions::ReviewRequest;

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
/// # The originator (#323)
///
/// The reference's rule (`ts-stack@edf6e03` `HTTPWalletJSON.ts:280-314`): the
/// constructor's originator, validated there (`validate_originator`: a
/// hostname, its port dropped), is the one sent, as both `Origin` and
/// `Originator` in the origin form (`http://example.com`); a method's
/// `originator` argument is not sent. A call with none configured is refused
/// before a request is made, in the reference's words. The reference skips
/// the rule in a browser, whose `fetch` sets `Origin` itself; this crate has
/// no browser target (`http` is native-only, `build.rs`), so it is
/// unconditional. The base URL is an exact origin, cleartext only to a
/// loopback host; a body over 256 MiB is refused unsent; the client `new`
/// builds follows no redirect (`redirect: 'error'`), a client given to
/// `with_client` is used as given.
///
/// # Example
///
/// ```rust,ignore
/// use bsv_rs::wallet::substrates::HttpWalletJson;
/// use bsv_rs::wallet::GetPublicKeyArgs;
///
/// let client = HttpWalletJson::new(Some("myapp.example.com".into()), None)?;
/// let result = client
///     .get_public_key(GetPublicKeyArgs { identity_key: true, ..Default::default() }, "")
///     .await?;
/// ```
#[derive(Clone)]
pub struct HttpWalletJson {
    client: Client,
    base_url: String,
    originator: Option<String>,
}

/// The reference's `MAX_WALLET_JSON_REQUEST_BYTES` (`HTTPWalletJSON.ts:60`).
const MAX_WALLET_JSON_REQUEST_BYTES: usize = 256 * 1024 * 1024;

impl HttpWalletJson {
    /// Creates a client of the wallet at `base_url` (default
    /// `http://localhost:3321`) on a client that follows no redirect.
    ///
    /// # Errors
    ///
    /// The base URL and the originator refused as the type's doc says.
    pub fn new(originator: Option<String>, base_url: Option<String>) -> Result<Self, Error> {
        Self::with_client(super::origin::default_client()?, originator, base_url)
    }

    /// Creates a client on `client`, used as given (its redirect policy too).
    ///
    /// # Errors
    ///
    /// As [`HttpWalletJson::new`].
    pub fn with_client(
        client: Client,
        originator: Option<String>,
        base_url: Option<String>,
    ) -> Result<Self, Error> {
        let base_url = base_url.as_deref().unwrap_or(super::DEFAULT_JSON_URL);
        Ok(Self {
            client,
            base_url: super::origin::normalize_wallet_http_base_url(base_url)?,
            originator: validate_originator(originator.as_deref())?,
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

    /// Makes a JSON API request to the wallet; the call's originator is not
    /// sent, the constructor's is (`HTTPWalletJSON.ts:296-314`).
    async fn request<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        args: &T,
        originator: Option<&str>,
    ) -> Result<R, Error> {
        self.request_bound(method, args, originator, None).await
    }

    /// [`request`](Self::request), a code-5 body with its results read
    /// against `review`, the createAction or signAction asked (#339).
    async fn request_bound<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        args: &T,
        _originator: Option<&str>,
        review: Option<&ReviewRequest>,
    ) -> Result<R, Error> {
        let Some(originator) = self.originator.as_deref() else {
            return Err(Error::WalletError(ORIGINATOR_REQUIRED.to_string()));
        };
        let origin = super::origin::to_origin_header(originator)?;
        let body = serde_json::to_vec(args)
            .map_err(|e| Error::WalletError(format!("failed to serialize request: {e}")))?;
        if body.len() > MAX_WALLET_JSON_REQUEST_BYTES {
            return Err(Error::WalletError(REQUEST_TOO_LARGE.to_string()));
        }
        let request = (self.client.post(format!("{}/{}", self.base_url, method)))
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .header("Origin", &origin)
            .header("Originator", &origin)
            .body(body);

        // Send request
        let response = request
            .send()
            .await
            .map_err(|e| request_error(e, "HTTP request failed"))?;

        if response.status().is_redirection() {
            return Err(super::origin::redirect_refused(response.status(), method));
        }
        if !response.status().is_success() {
            let status = response.status();
            let transport = fault::status_fault(status, response.headers());
            let retry_after = fault::retry_after(response.headers()).map(str::to_owned);
            let text = response.text().await.unwrap_or_default();

            // The body's busy word, at any status, is the wallet's promise
            // that it took no action; the status alone promises nothing
            if let Some(busy) = wallet_busy_from_response(&text, retry_after.as_deref()) {
                return Err(busy);
            }
            // A 400's code-5 body with its results is the reference's
            // WERR_REVIEW_ACTIONS, every member read as it reads them (#339)
            if let Ok(body) = serde_json::from_str::<serde_json::Value>(&text) {
                if review_actions::is_review_body(status.as_u16(), &body) {
                    return Err(review_actions::read(&body, method, review));
                }
            }
            let detail = format!("HTTP {} for {}: {}", status, method, text);

            // A 429, whatever the body, is a rate limit with its wait
            if let (
                Some(fault @ TransportFault::RateLimited { .. }),
                StatusCode::TOO_MANY_REQUESTS,
            ) = (transport, status)
            {
                let status = Some(status.as_u16());
                return Err(Error::TransportFault {
                    fault,
                    status,
                    detail,
                });
            }

            // The wallet's error body: its class by name or code (#137), else
            // a numeric code with its description
            if let Some(error) = wallet_error_from_body(&text) {
                return Err(error);
            }

            // A gateway status without the wallet's word is the edge's
            // answer: the way failed, and nothing is promised
            if transport.is_some() {
                return Err(Error::WalletTransport {
                    status: Some(status.as_u16()),
                    detail,
                });
            }

            return Err(Error::WalletError(detail));
        }

        // Parse response
        response
            .json::<R>()
            .await
            .map_err(|e| request_error(e, "failed to parse JSON response"))
    }

    // =========================================================================
    // Wallet Interface Methods
    // =========================================================================

    /// Gets a public key from the wallet.
    pub async fn get_public_key(
        &self,
        args: GetPublicKeyArgs,
        originator: Option<&str>,
    ) -> Result<GetPublicKeyResult, Error> {
        let request = JsonGetPublicKeyRequest {
            identity_key: args.identity_key,
            protocol_id: args.protocol_id.as_ref().map(protocol_to_json),
            key_id: args.key_id,
            counterparty: args.counterparty.as_ref().map(counterparty_to_string),
            for_self: args.for_self,
            permission: permission!(args),
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
        originator: Option<&str>,
    ) -> Result<EncryptResult, Error> {
        let request = JsonEncryptRequest {
            key: key_params!(args),
            plaintext: args.plaintext,
            permission: permission!(args),
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
        originator: Option<&str>,
    ) -> Result<DecryptResult, Error> {
        let request = JsonDecryptRequest {
            key: key_params!(args),
            ciphertext: args.ciphertext,
            permission: permission!(args),
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
        originator: Option<&str>,
    ) -> Result<CreateHmacResult, Error> {
        let request = JsonCreateHmacRequest {
            key: key_params!(args),
            data: args.data,
            permission: permission!(args),
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
        originator: Option<&str>,
    ) -> Result<VerifyHmacResult, Error> {
        let request = JsonVerifyHmacRequest {
            key: key_params!(args),
            data: args.data,
            hmac: args.hmac.to_vec(),
            permission: permission!(args),
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
        originator: Option<&str>,
    ) -> Result<CreateSignatureResult, Error> {
        let request = JsonCreateSignatureRequest {
            key: key_params!(args),
            data: args.data,
            hash_to_directly_sign: args.hash_to_directly_sign.map(|h| h.to_vec()),
            permission: permission!(args),
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
        originator: Option<&str>,
    ) -> Result<VerifySignatureResult, Error> {
        let request = JsonVerifySignatureRequest {
            key: key_params!(args),
            for_self: args.for_self,
            data: args.data,
            hash_to_directly_verify: args.hash_to_directly_verify.map(|h| h.to_vec()),
            signature: args.signature,
            permission: permission!(args),
        };

        let response: JsonVerifySignatureResponse = self
            .request("verifySignature", &request, originator)
            .await?;

        Ok(VerifySignatureResult {
            valid: response.valid,
        })
    }

    /// Checks if the wallet is authenticated.
    pub async fn is_authenticated(&self, originator: Option<&str>) -> Result<bool, Error> {
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
    pub async fn get_height(&self, originator: Option<&str>) -> Result<u64, Error> {
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
    pub async fn get_network(&self, originator: Option<&str>) -> Result<Network, Error> {
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
    pub async fn get_version(&self, originator: Option<&str>) -> Result<String, Error> {
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
        originator: Option<&str>,
    ) -> Result<CreateActionResult, Error> {
        let review = ReviewRequest::create_action(&args);
        (self.request_bound("createAction", &args, originator, Some(&review))).await
    }

    /// Signs a previously created action.
    pub async fn sign_action(
        &self,
        args: SignActionArgs,
        originator: Option<&str>,
    ) -> Result<SignActionResult, Error> {
        let review = ReviewRequest::sign_action(&args);
        (self.request_bound("signAction", &args, originator, Some(&review))).await
    }

    /// Aborts an in-progress action.
    pub async fn abort_action(
        &self,
        args: AbortActionArgs,
        originator: Option<&str>,
    ) -> Result<AbortActionResult, Error> {
        self.request("abortAction", &args, originator).await
    }

    /// Lists wallet actions (transactions).
    pub async fn list_actions(
        &self,
        args: ListActionsArgs,
        originator: Option<&str>,
    ) -> Result<ListActionsResult, Error> {
        self.request("listActions", &args, originator).await
    }

    /// Internalizes an external transaction.
    pub async fn internalize_action(
        &self,
        args: InternalizeActionArgs,
        originator: Option<&str>,
    ) -> Result<InternalizeActionResult, Error> {
        crate::wallet::validation::validate_internalize_action_args(&args)?;
        self.request("internalizeAction", &args, originator).await
    }

    // =========================================================================
    // Output Methods
    // =========================================================================

    /// Lists wallet outputs.
    pub async fn list_outputs(
        &self,
        args: ListOutputsArgs,
        originator: Option<&str>,
    ) -> Result<ListOutputsResult, Error> {
        self.request("listOutputs", &args, originator).await
    }

    /// Relinquishes an output from a basket.
    pub async fn relinquish_output(
        &self,
        args: RelinquishOutputArgs,
        originator: Option<&str>,
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
        originator: Option<&str>,
    ) -> Result<WalletCertificate, Error> {
        self.request("acquireCertificate", &args, originator).await
    }

    /// Lists certificates.
    pub async fn list_certificates(
        &self,
        args: ListCertificatesArgs,
        originator: Option<&str>,
    ) -> Result<ListCertificatesResult, Error> {
        self.request("listCertificates", &args, originator).await
    }

    /// Proves a certificate.
    pub async fn prove_certificate(
        &self,
        args: ProveCertificateArgs,
        originator: Option<&str>,
    ) -> Result<ProveCertificateResult, Error> {
        self.request("proveCertificate", &args, originator).await
    }

    /// Relinquishes a certificate.
    pub async fn relinquish_certificate(
        &self,
        args: RelinquishCertificateArgs,
        originator: Option<&str>,
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
        originator: Option<&str>,
    ) -> Result<DiscoverCertificatesResult, Error> {
        self.request("discoverByIdentityKey", &args, originator)
            .await
    }

    /// Discovers certificates by attributes.
    pub async fn discover_by_attributes(
        &self,
        args: DiscoverByAttributesArgs,
        originator: Option<&str>,
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
        originator: Option<&str>,
    ) -> Result<GetHeaderResult, Error> {
        self.request("getHeaderForHeight", &args, originator).await
    }

    /// Waits for authentication.
    pub async fn wait_for_authentication(&self, originator: Option<&str>) -> Result<bool, Error> {
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
        originator: Option<&str>,
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
        originator: Option<&str>,
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
        originator: Option<&str>,
    ) -> crate::Result<GetPublicKeyResult> {
        self.get_public_key(args, originator).await
    }

    async fn encrypt(
        &self,
        args: EncryptArgs,
        originator: Option<&str>,
    ) -> crate::Result<EncryptResult> {
        self.encrypt(args, originator).await
    }

    async fn decrypt(
        &self,
        args: DecryptArgs,
        originator: Option<&str>,
    ) -> crate::Result<DecryptResult> {
        self.decrypt(args, originator).await
    }

    async fn create_hmac(
        &self,
        args: CreateHmacArgs,
        originator: Option<&str>,
    ) -> crate::Result<CreateHmacResult> {
        self.create_hmac(args, originator).await
    }

    async fn verify_hmac(
        &self,
        args: VerifyHmacArgs,
        originator: Option<&str>,
    ) -> crate::Result<VerifyHmacResult> {
        self.verify_hmac(args, originator).await
    }

    async fn create_signature(
        &self,
        args: CreateSignatureArgs,
        originator: Option<&str>,
    ) -> crate::Result<CreateSignatureResult> {
        self.create_signature(args, originator).await
    }

    async fn verify_signature(
        &self,
        args: VerifySignatureArgs,
        originator: Option<&str>,
    ) -> crate::Result<VerifySignatureResult> {
        self.verify_signature(args, originator).await
    }

    async fn reveal_counterparty_key_linkage(
        &self,
        args: RevealCounterpartyKeyLinkageArgs,
        originator: Option<&str>,
    ) -> crate::Result<RevealCounterpartyKeyLinkageResult> {
        self.reveal_counterparty_key_linkage(args, originator).await
    }

    async fn reveal_specific_key_linkage(
        &self,
        args: RevealSpecificKeyLinkageArgs,
        originator: Option<&str>,
    ) -> crate::Result<RevealSpecificKeyLinkageResult> {
        self.reveal_specific_key_linkage(args, originator).await
    }

    async fn create_action(
        &self,
        args: CreateActionArgs,
        originator: Option<&str>,
    ) -> crate::Result<CreateActionResult> {
        self.create_action(args, originator).await
    }

    async fn sign_action(
        &self,
        args: SignActionArgs,
        originator: Option<&str>,
    ) -> crate::Result<SignActionResult> {
        self.sign_action(args, originator).await
    }

    async fn abort_action(
        &self,
        args: AbortActionArgs,
        originator: Option<&str>,
    ) -> crate::Result<AbortActionResult> {
        self.abort_action(args, originator).await
    }

    async fn list_actions(
        &self,
        args: ListActionsArgs,
        originator: Option<&str>,
    ) -> crate::Result<ListActionsResult> {
        self.list_actions(args, originator).await
    }

    async fn internalize_action(
        &self,
        args: InternalizeActionArgs,
        originator: Option<&str>,
    ) -> crate::Result<InternalizeActionResult> {
        self.internalize_action(args, originator).await
    }

    async fn list_outputs(
        &self,
        args: ListOutputsArgs,
        originator: Option<&str>,
    ) -> crate::Result<ListOutputsResult> {
        self.list_outputs(args, originator).await
    }

    async fn relinquish_output(
        &self,
        args: RelinquishOutputArgs,
        originator: Option<&str>,
    ) -> crate::Result<RelinquishOutputResult> {
        self.relinquish_output(args, originator).await
    }

    async fn acquire_certificate(
        &self,
        args: AcquireCertificateArgs,
        originator: Option<&str>,
    ) -> crate::Result<WalletCertificate> {
        self.acquire_certificate(args, originator).await
    }

    async fn list_certificates(
        &self,
        args: ListCertificatesArgs,
        originator: Option<&str>,
    ) -> crate::Result<ListCertificatesResult> {
        self.list_certificates(args, originator).await
    }

    async fn prove_certificate(
        &self,
        args: ProveCertificateArgs,
        originator: Option<&str>,
    ) -> crate::Result<ProveCertificateResult> {
        self.prove_certificate(args, originator).await
    }

    async fn relinquish_certificate(
        &self,
        args: RelinquishCertificateArgs,
        originator: Option<&str>,
    ) -> crate::Result<RelinquishCertificateResult> {
        self.relinquish_certificate(args, originator).await
    }

    async fn discover_by_identity_key(
        &self,
        args: DiscoverByIdentityKeyArgs,
        originator: Option<&str>,
    ) -> crate::Result<DiscoverCertificatesResult> {
        self.discover_by_identity_key(args, originator).await
    }

    async fn discover_by_attributes(
        &self,
        args: DiscoverByAttributesArgs,
        originator: Option<&str>,
    ) -> crate::Result<DiscoverCertificatesResult> {
        self.discover_by_attributes(args, originator).await
    }

    async fn is_authenticated(
        &self,
        originator: Option<&str>,
    ) -> crate::Result<AuthenticatedResult> {
        Ok(AuthenticatedResult {
            authenticated: self.is_authenticated(originator).await?,
        })
    }

    async fn wait_for_authentication(
        &self,
        originator: Option<&str>,
    ) -> crate::Result<AuthenticatedResult> {
        Ok(AuthenticatedResult {
            authenticated: self.wait_for_authentication(originator).await?,
        })
    }

    async fn get_height(&self, originator: Option<&str>) -> crate::Result<GetHeightResult> {
        Ok(GetHeightResult {
            height: self.get_height(originator).await? as u32,
        })
    }

    async fn get_header_for_height(
        &self,
        args: GetHeaderArgs,
        originator: Option<&str>,
    ) -> crate::Result<GetHeaderResult> {
        self.get_header(args, originator).await
    }

    async fn get_network(&self, originator: Option<&str>) -> crate::Result<GetNetworkResult> {
        Ok(GetNetworkResult {
            network: self.get_network(originator).await?,
        })
    }

    async fn get_version(&self, originator: Option<&str>) -> crate::Result<GetVersionResult> {
        Ok(GetVersionResult {
            version: self.get_version(originator).await?,
        })
    }
}

// =============================================================================
// JSON Request/Response Types
// =============================================================================

/// A wallet's error body, every field optional: the reference's envelope
/// (`isError`, `name`, `message`, a numeric `code` for 5 to 8:
/// `ts-stack@edf6e03` `packages/sdk/src/wallet/WalletError.ts:29-67`, the
/// toolbox's `toJson`, `packages/wallet/wallet-toolbox/src/sdk/WalletError.ts:143-151`
/// and `WERR_errors.ts:110,136,225,278`), the toolbox's status form (`code`
/// the `WERR_*` name, `description`; `asStatus`, `WalletError.ts:126-132`
/// there), and this substrate's older form (a numeric `code`, `description`).
#[derive(Deserialize)]
struct JsonErrorBody {
    #[serde(default)]
    code: Option<serde_json::Value>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    description: Option<String>,
}

/// The body codes that answer busy: bsv-wallet-cli's `STORE_BUSY` (a
/// contended store), and the TS wallet toolbox edge's capacity answer
/// `ERR_SERVER_BUSY` (ts-stack@edf6e03
/// `packages/wallet/wallet-toolbox/src/storage/remoting/edgePolicy.ts:668-672`,
/// a 503 with `Retry-After: 1`).
const BUSY_CODES: [&str; 2] = ["STORE_BUSY", "ERR_SERVER_BUSY"];

/// A busy answer's body: a string `code`, and the detail as `message`
/// (bsv-wallet-cli) or `description` (the TS toolbox).
#[derive(Deserialize)]
struct JsonBusyResponse {
    code: String,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    description: Option<String>,
}

// =============================================================================
// Helper Functions
// =============================================================================

/// The reference's words for a call with no originator configured.
const ORIGINATOR_REQUIRED: &str = "HTTPWalletJSON: originator is required when using the HTTP \
    substrate in Node.js. Pass an originator (e.g. \"example.com\") to the constructor.";

/// The reference's words for a body over the bound.
const REQUEST_TOO_LARGE: &str = "HTTPWalletJSON request exceeds the maximum permitted size";

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

/// Creates the error for a failed send or body read: a transport fault of
/// the one classifier (a connection error, a timeout, a body cut: a decode
/// error whose source is not `serde_json`'s) is
/// [`Error::WalletTransport`] with no status; a request that could not be
/// built, a redirect refused and a success body that is not the expected
/// JSON stay [`Error::WalletError`].
fn request_error(e: reqwest::Error, context: &str) -> Error {
    fault::wallet_error(&e, format!("{}: {}", context, e))
}

/// Creates a wallet error from an error code.
fn wallet_error_from_code(code: u8, description: &str) -> Error {
    Error::WalletError(format!("wallet error (code {}): {}", code, description))
}

/// Creates the error a wallet's error body names (#137): an
/// [`Error::WalletRefusal`] when its `name`, else its `code` (a
/// `WalletRefusalClass` name, or an SDK code 2 to 8), names a class, the
/// words its `message`, else its `description`, else the name; a numeric
/// `code` naming no class with a `description` the coded wallet error, as
/// before; any other body `None`. The name decides before the number, so
/// the toolbox's `WERR_INVALID_MERKLE_ROOT` with its JSON code 8 is that
/// class and a bare 8 the SDK's `abortRefused`.
fn wallet_error_from_body(body: &str) -> Option<Error> {
    let body = serde_json::from_str::<JsonErrorBody>(body).ok()?;
    let code_name = body.code.as_ref().and_then(serde_json::Value::as_str);
    let code_number = body
        .code
        .as_ref()
        .and_then(serde_json::Value::as_u64)
        .and_then(|code| u8::try_from(code).ok());
    let class = body
        .name
        .as_deref()
        .and_then(WalletRefusalClass::from_name)
        .or_else(|| code_number.and_then(WalletRefusalClass::from_code))
        .or_else(|| code_name.and_then(WalletRefusalClass::from_name));
    let Some(class) = class else {
        return Some(wallet_error_from_code(
            code_number?,
            body.description.as_deref()?,
        ));
    };
    let message = body
        .message
        .filter(|m| !m.is_empty())
        .or(body.description.filter(|d| !d.is_empty()))
        .unwrap_or_else(|| class.name().to_string());
    Some(Error::WalletRefusal { class, message })
}

/// Creates [`Error::WalletBusy`] from an error answer whose body's `code` is
/// one of [`BUSY_CODES`], at any status; any other body is `None`. The detail
/// is the body's `message`, else its `description`, else the code.
fn wallet_busy_from_response(body: &str, retry_after: Option<&str>) -> Option<Error> {
    let busy = serde_json::from_str::<JsonBusyResponse>(body).ok()?;
    if !BUSY_CODES.contains(&busy.code.as_str()) {
        return None;
    }
    let detail = busy
        .message
        .filter(|m| !m.is_empty())
        .or(busy.description.filter(|d| !d.is_empty()))
        .unwrap_or(busy.code);
    Some(Error::WalletBusy {
        detail,
        retry_after_ms: retry_after.and_then(parse_retry_after_ms),
    })
}

/// Reads a `Retry-After` value as milliseconds when it is delta-seconds
/// (RFC 9110 section 10.2.3: `1*DIGIT`); an HTTP-date, or anything else,
/// reads as `None` (0.8.2's busy wait; a 429's wait reads a date too).
fn parse_retry_after_ms(value: &str) -> Option<u64> {
    delta_seconds_ms(value)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let client = HttpWalletJson::new(None, None).unwrap();
        assert_eq!(client.base_url(), "http://localhost:3321");
    }

    #[test]
    fn retry_after_delta_seconds_reads_as_milliseconds() {
        assert_eq!(parse_retry_after_ms("2"), Some(2000));
        assert_eq!(parse_retry_after_ms(" 0 "), Some(0));
        assert_eq!(parse_retry_after_ms("99999999999999999999"), Some(u64::MAX));
    }

    #[test]
    fn retry_after_http_date_or_junk_reads_as_none() {
        assert_eq!(parse_retry_after_ms("Wed, 21 Oct 2026 07:28:00 GMT"), None);
        assert_eq!(parse_retry_after_ms(""), None);
        assert_eq!(parse_retry_after_ms("-1"), None);
        assert_eq!(parse_retry_after_ms("1.5"), None);
    }

    #[test]
    fn a_busy_code_without_message_or_description_is_its_own_detail() {
        assert_eq!(
            wallet_busy_from_response(r#"{"code":"STORE_BUSY"}"#, None),
            Some(Error::WalletBusy {
                detail: "STORE_BUSY".into(),
                retry_after_ms: None,
            })
        );
        assert_eq!(
            wallet_busy_from_response(r#"{"code":"STORE_BUSY","message":""}"#, Some("3")),
            Some(Error::WalletBusy {
                detail: "STORE_BUSY".into(),
                retry_after_ms: Some(3000),
            })
        );
    }

    #[test]
    fn a_body_without_a_busy_code_is_not_busy() {
        assert_eq!(wallet_busy_from_response("store contended", None), None);
        assert_eq!(wallet_busy_from_response("", Some("1")), None);
        assert_eq!(
            wallet_busy_from_response(r#"{"message":"busy"}"#, None),
            None
        );
        assert_eq!(
            wallet_busy_from_response(r#"{"code":1,"description":"writer held"}"#, None),
            None
        );
        assert_eq!(
            wallet_busy_from_response(r#"{"code":"INSUFFICIENT_FUNDS","message":"x"}"#, None),
            None
        );
    }

    #[test]
    fn test_custom_url() {
        let client = HttpWalletJson::new(None, Some("https://wallet.example.com".into())).unwrap();
        assert_eq!(client.base_url(), "https://wallet.example.com");
    }
}
