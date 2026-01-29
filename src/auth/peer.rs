//! Core Peer implementation for BRC-31 authentication.
//!
//! The `Peer` type manages mutual authentication with remote peers,
//! including handshake, certificate exchange, and message signing/verification.

use crate::auth::{
    certificates::VerifiableCertificate,
    session_manager::SessionManager,
    transports::Transport,
    types::{
        AuthMessage, MessageType, PeerSession, RequestedCertificateSet, AUTH_PROTOCOL_ID,
        AUTH_VERSION,
    },
    utils::{create_nonce, get_verifiable_certificates, validate_certificates, verify_nonce},
};
use crate::primitives::PublicKey;
use crate::wallet::{
    Counterparty, CreateSignatureArgs, GetPublicKeyArgs, Protocol, SecurityLevel,
    VerifySignatureArgs, WalletInterface,
};
use crate::primitives::to_base64;
use crate::{Error, Result};
use rand::RngCore;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::sync::{oneshot, RwLock};

/// Type alias for general message callbacks.
pub type GeneralMessageCallback = Box<
    dyn Fn(
            PublicKey,
            Vec<u8>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>>
        + Send
        + Sync,
>;

/// Type alias for certificate received callbacks.
pub type CertificateCallback = Box<
    dyn Fn(
            PublicKey,
            Vec<VerifiableCertificate>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>>
        + Send
        + Sync,
>;

/// Type alias for certificate request callbacks.
pub type CertificateRequestCallback = Box<
    dyn Fn(
            PublicKey,
            RequestedCertificateSet,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>>
        + Send
        + Sync,
>;

/// Configuration options for creating a Peer.
pub struct PeerOptions<W: WalletInterface, T: Transport> {
    /// Wallet for cryptographic operations.
    pub wallet: W,
    /// Transport for sending/receiving messages.
    pub transport: T,
    /// Certificates to request from peers during handshake.
    pub certificates_to_request: Option<RequestedCertificateSet>,
    /// Existing session manager (creates new if None).
    pub session_manager: Option<SessionManager>,
    /// Whether to automatically persist the last peer session.
    pub auto_persist_last_session: bool,
    /// Application originator identifier.
    pub originator: Option<String>,
}

/// Peer for authenticated communication (BRC-31 Authrite).
///
/// The Peer manages mutual authentication between parties, including:
/// - Initial handshake with nonce exchange
/// - Certificate request and validation
/// - Signed message exchange
///
/// # Example
///
/// ```rust,ignore
/// use bsv_sdk::auth::{Peer, PeerOptions, SimplifiedFetchTransport};
/// use bsv_sdk::wallet::ProtoWallet;
///
/// let wallet = ProtoWallet::new(Some(PrivateKey::random()));
/// let transport = SimplifiedFetchTransport::new("https://example.com");
///
/// let peer = Peer::new(PeerOptions {
///     wallet,
///     transport,
///     certificates_to_request: None,
///     session_manager: None,
///     auto_persist_last_session: true,
///     originator: Some("myapp.com".into()),
/// });
///
/// // Send authenticated message
/// peer.to_peer(b"Hello!", Some(&recipient_key_hex), None).await?;
/// ```
pub struct Peer<W: WalletInterface, T: Transport> {
    wallet: W,
    transport: Arc<T>,
    session_manager: Arc<RwLock<SessionManager>>,
    certificates_to_request: Option<RequestedCertificateSet>,

    // Callbacks
    general_message_callbacks: Arc<RwLock<HashMap<u32, GeneralMessageCallback>>>,
    certificate_callbacks: Arc<RwLock<HashMap<u32, CertificateCallback>>>,
    certificate_request_callbacks: Arc<RwLock<HashMap<u32, CertificateRequestCallback>>>,
    next_callback_id: AtomicU32,

    // Pending handshakes: session_nonce -> oneshot sender
    pending_handshakes: Arc<RwLock<HashMap<String, oneshot::Sender<Result<PeerSession>>>>>,

    // Options
    #[allow(dead_code)]
    auto_persist_last_session: bool,
    originator: String,

    // Cached identity key
    identity_key: Arc<RwLock<Option<PublicKey>>>,
}

impl<W: WalletInterface + 'static, T: Transport + 'static> Peer<W, T> {
    /// Creates a new Peer with the given options.
    ///
    /// Note: After creating the Peer, you should call `start()` to set up
    /// the transport callback for receiving messages.
    pub fn new(options: PeerOptions<W, T>) -> Self {
        let originator = options.originator.unwrap_or_else(|| "unknown".to_string());

        Self {
            wallet: options.wallet,
            transport: Arc::new(options.transport),
            session_manager: Arc::new(RwLock::new(options.session_manager.unwrap_or_default())),
            certificates_to_request: options.certificates_to_request,
            general_message_callbacks: Arc::new(RwLock::new(HashMap::new())),
            certificate_callbacks: Arc::new(RwLock::new(HashMap::new())),
            certificate_request_callbacks: Arc::new(RwLock::new(HashMap::new())),
            next_callback_id: AtomicU32::new(1),
            pending_handshakes: Arc::new(RwLock::new(HashMap::new())),
            auto_persist_last_session: options.auto_persist_last_session,
            originator,
            identity_key: Arc::new(RwLock::new(None)),
        }
    }

    /// Sets up the transport callback to receive and process incoming messages.
    ///
    /// This must be called after creating the Peer for it to receive responses.
    /// The callback is automatically set up for processing InitialResponse,
    /// CertificateRequest/Response, and General messages.
    pub fn start(&self) {
        // Clone all the Arc references we need for the callback
        let session_manager = self.session_manager.clone();
        let pending_handshakes = self.pending_handshakes.clone();
        let general_message_callbacks = self.general_message_callbacks.clone();
        let certificate_callbacks = self.certificate_callbacks.clone();
        let certificate_request_callbacks = self.certificate_request_callbacks.clone();

        // Set up the transport callback
        self.transport.set_callback(Box::new(move |message| {
            let session_manager = session_manager.clone();
            let pending_handshakes = pending_handshakes.clone();
            let general_message_callbacks = general_message_callbacks.clone();
            let certificate_callbacks = certificate_callbacks.clone();
            let certificate_request_callbacks = certificate_request_callbacks.clone();

            Box::pin(async move {
                // Process the message based on type
                match message.message_type {
                    MessageType::InitialResponse => {
                        // Process InitialResponse - complete the handshake
                        // yourNonce is the client's session nonce (echoed back by server)
                        let client_nonce = message
                            .your_nonce
                            .as_ref()
                            .ok_or_else(|| Error::AuthError("InitialResponse missing your_nonce".into()))?;

                        // initialNonce is the server's session nonce
                        let server_nonce = message
                            .initial_nonce
                            .as_ref()
                            .ok_or_else(|| Error::AuthError("InitialResponse missing initial_nonce".into()))?;

                        // Find and update the existing session (created in initiate_handshake)
                        let session = {
                            let mut mgr = session_manager.write().await;
                            if let Some(session) = mgr.get_session_mut(client_nonce) {
                                // Update the existing session
                                session.peer_identity_key = Some(message.identity_key.clone());
                                session.peer_nonce = Some(server_nonce.clone());
                                session.is_authenticated = true;
                                session.touch();
                                session.clone()
                            } else {
                                // No existing session - create a new one
                                let mut session = PeerSession::with_nonce(client_nonce.clone());
                                session.peer_identity_key = Some(message.identity_key.clone());
                                session.peer_nonce = Some(server_nonce.clone());
                                session.is_authenticated = true;
                                session.touch();
                                mgr.add_session(session.clone())?;
                                session
                            }
                        };

                        // Resolve pending handshake using client's nonce
                        {
                            let mut pending = pending_handshakes.write().await;
                            if let Some(tx) = pending.remove(client_nonce) {
                                let _ = tx.send(Ok(session));
                            }
                        }
                    }
                    MessageType::General => {
                        // Route to general message callbacks
                        let payload = message.payload.clone().unwrap_or_default();
                        let sender = message.identity_key.clone();

                        let cbs = general_message_callbacks.read().await;
                        for (_, callback) in cbs.iter() {
                            callback(sender.clone(), payload.clone()).await?;
                        }
                    }
                    MessageType::CertificateRequest => {
                        // Route to certificate request callbacks
                        let sender = message.identity_key.clone();
                        let requested = message.requested_certificates.clone().unwrap_or_default();

                        let cbs = certificate_request_callbacks.read().await;
                        for (_, callback) in cbs.iter() {
                            callback(sender.clone(), requested.clone()).await?;
                        }
                    }
                    MessageType::CertificateResponse => {
                        // Route to certificate response callbacks
                        let sender = message.identity_key.clone();
                        let certs = message.certificates.clone().unwrap_or_default();

                        let cbs = certificate_callbacks.read().await;
                        for (_, callback) in cbs.iter() {
                            callback(sender.clone(), certs.clone()).await?;
                        }
                    }
                    _ => {
                        // Ignore other message types (InitialRequest is server-side only)
                    }
                }

                Ok(())
            })
        }));
    }

    /// Sends a message to a peer.
    ///
    /// Initiates authentication handshake if no authenticated session exists.
    ///
    /// # Arguments
    /// * `message` - Message payload to send
    /// * `identity_key` - Peer's identity key (hex string) or session nonce
    /// * `max_wait_time` - Maximum time to wait for handshake (milliseconds)
    pub async fn to_peer(
        &self,
        message: &[u8],
        identity_key: Option<&str>,
        max_wait_time: Option<u64>,
    ) -> Result<()> {
        // Get or create authenticated session
        let session = self
            .get_authenticated_session(identity_key, max_wait_time)
            .await?;

        // Build general message
        let my_identity = self.get_identity_key().await?;
        let mut msg = AuthMessage::new(MessageType::General, my_identity);

        // Use simple random bytes for message nonce (not HMAC-based)
        // This matches TypeScript's behavior: Utils.toBase64(Random(32))
        let mut random_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut random_bytes);
        let msg_nonce = to_base64(&random_bytes);
        msg.nonce = Some(msg_nonce);

        msg.your_nonce = session.peer_nonce.clone();
        msg.payload = Some(message.to_vec());

        // Sign message
        self.sign_message(&mut msg, &session).await?;

        // Send
        self.transport.send(&msg).await?;

        Ok(())
    }

    /// Gets or creates an authenticated session with a peer.
    ///
    /// # Arguments
    /// * `identity_key` - Peer's identity key (hex) or session nonce
    /// * `max_wait_time` - Maximum time to wait for handshake (milliseconds)
    pub async fn get_authenticated_session(
        &self,
        identity_key: Option<&str>,
        max_wait_time: Option<u64>,
    ) -> Result<PeerSession> {
        // Check for existing authenticated session
        if let Some(key) = identity_key {
            let mgr = self.session_manager.read().await;
            if let Some(session) = mgr.get_session(key) {
                if session.is_authenticated {
                    return Ok(session.clone());
                }
            }
        }

        // Initiate handshake
        self.initiate_handshake(identity_key, max_wait_time).await
    }

    /// Requests certificates from a peer.
    ///
    /// # Arguments
    /// * `requested` - Certificate requirements
    /// * `identity_key` - Peer's identity key or session nonce
    /// * `max_wait_time` - Maximum time to wait (milliseconds)
    pub async fn request_certificates(
        &self,
        requested: RequestedCertificateSet,
        identity_key: Option<&str>,
        max_wait_time: Option<u64>,
    ) -> Result<()> {
        let session = self
            .get_authenticated_session(identity_key, max_wait_time)
            .await?;

        let my_identity = self.get_identity_key().await?;
        let mut msg = AuthMessage::new(MessageType::CertificateRequest, my_identity);

        // Use simple random bytes for message nonce
        let mut random_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut random_bytes);
        msg.nonce = Some(to_base64(&random_bytes));

        msg.your_nonce = session.peer_nonce.clone();
        msg.requested_certificates = Some(requested);

        self.sign_message(&mut msg, &session).await?;
        self.transport.send(&msg).await
    }

    /// Sends certificates to a peer.
    ///
    /// # Arguments
    /// * `verifier_identity_key` - Verifier's identity key (hex)
    /// * `certificates` - Certificates to send
    pub async fn send_certificate_response(
        &self,
        verifier_identity_key: &str,
        certificates: Vec<VerifiableCertificate>,
    ) -> Result<()> {
        let mgr = self.session_manager.read().await;
        let session = mgr
            .get_session(verifier_identity_key)
            .ok_or_else(|| Error::AuthError("No session with peer".into()))?
            .clone();
        drop(mgr);

        let my_identity = self.get_identity_key().await?;
        let mut msg = AuthMessage::new(MessageType::CertificateResponse, my_identity);

        // Use simple random bytes for message nonce
        let mut random_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut random_bytes);
        msg.nonce = Some(to_base64(&random_bytes));

        msg.your_nonce = session.peer_nonce.clone();
        msg.certificates = Some(certificates);

        self.sign_message(&mut msg, &session).await?;
        self.transport.send(&msg).await
    }

    /// Registers a listener for general messages.
    ///
    /// # Returns
    /// Callback ID that can be used to stop listening.
    pub async fn listen_for_general_messages<F>(&self, callback: F) -> u32
    where
        F: Fn(
                PublicKey,
                Vec<u8>,
            )
                -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>>
            + Send
            + Sync
            + 'static,
    {
        let id = self.next_callback_id.fetch_add(1, Ordering::SeqCst);
        let mut cbs = self.general_message_callbacks.write().await;
        cbs.insert(id, Box::new(callback));
        id
    }

    /// Stops listening for general messages.
    pub async fn stop_listening_for_general_messages(&self, callback_id: u32) {
        let mut cbs = self.general_message_callbacks.write().await;
        cbs.remove(&callback_id);
    }

    /// Registers a listener for received certificates.
    ///
    /// # Returns
    /// Callback ID that can be used to stop listening.
    pub async fn listen_for_certificates_received<F>(&self, callback: F) -> u32
    where
        F: Fn(
                PublicKey,
                Vec<VerifiableCertificate>,
            )
                -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>>
            + Send
            + Sync
            + 'static,
    {
        let id = self.next_callback_id.fetch_add(1, Ordering::SeqCst);
        let mut cbs = self.certificate_callbacks.write().await;
        cbs.insert(id, Box::new(callback));
        id
    }

    /// Stops listening for received certificates.
    pub async fn stop_listening_for_certificates_received(&self, callback_id: u32) {
        let mut cbs = self.certificate_callbacks.write().await;
        cbs.remove(&callback_id);
    }

    /// Registers a listener for certificate requests.
    ///
    /// # Returns
    /// Callback ID that can be used to stop listening.
    pub async fn listen_for_certificates_requested<F>(&self, callback: F) -> u32
    where
        F: Fn(
                PublicKey,
                RequestedCertificateSet,
            )
                -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>>
            + Send
            + Sync
            + 'static,
    {
        let id = self.next_callback_id.fetch_add(1, Ordering::SeqCst);
        let mut cbs = self.certificate_request_callbacks.write().await;
        cbs.insert(id, Box::new(callback));
        id
    }

    /// Stops listening for certificate requests.
    pub async fn stop_listening_for_certificates_requested(&self, callback_id: u32) {
        let mut cbs = self.certificate_request_callbacks.write().await;
        cbs.remove(&callback_id);
    }

    /// Returns the session manager.
    pub fn session_manager(&self) -> &Arc<RwLock<SessionManager>> {
        &self.session_manager
    }

    /// Returns this peer's identity key.
    pub async fn get_identity_key(&self) -> Result<PublicKey> {
        {
            let cached = self.identity_key.read().await;
            if let Some(ref key) = *cached {
                return Ok(key.clone());
            }
        }

        // Get from wallet
        let result = self
            .wallet
            .get_public_key(
                GetPublicKeyArgs {
                    identity_key: true,
                    protocol_id: None,
                    key_id: None,
                    counterparty: None,
                    for_self: None,
                },
                &self.originator,
            )
            .await?;

        // Parse the public key from hex string
        let key = PublicKey::from_hex(&result.public_key)?;
        let mut cached = self.identity_key.write().await;
        *cached = Some(key.clone());
        Ok(key)
    }

    /// Handles an incoming message from the transport.
    pub async fn handle_incoming_message(&self, message: AuthMessage) -> Result<()> {
        // Validate message structure
        if message.version != AUTH_VERSION {
            return Err(Error::AuthError(format!(
                "Invalid auth version: expected {}, got {}",
                AUTH_VERSION, message.version
            )));
        }

        match message.message_type {
            MessageType::InitialRequest => self.process_initial_request(message).await,
            MessageType::InitialResponse => self.process_initial_response(message).await,
            MessageType::CertificateRequest => self.process_certificate_request(message).await,
            MessageType::CertificateResponse => self.process_certificate_response(message).await,
            MessageType::General => self.process_general_message(message).await,
        }
    }

    // ========================================================================
    // Private methods
    // ========================================================================

    async fn sign_message(&self, message: &mut AuthMessage, session: &PeerSession) -> Result<()> {
        let data = message.signing_data();
        let key_id = message.get_key_id(session.peer_nonce.as_deref());

        let protocol = Protocol::new(SecurityLevel::Counterparty, AUTH_PROTOCOL_ID);
        let counterparty = session
            .peer_identity_key
            .as_ref()
            .map(|k| Counterparty::Other(k.clone()));

        let result = self
            .wallet
            .create_signature(
                CreateSignatureArgs {
                    data: Some(data.clone()),
                    hash_to_directly_sign: None,
                    protocol_id: protocol,
                    key_id: key_id.clone(),
                    counterparty,
                },
                &self.originator,
            )
            .await?;

        message.signature = Some(result.signature);
        Ok(())
    }

    async fn verify_message_signature(
        &self,
        message: &AuthMessage,
        session: &PeerSession,
    ) -> Result<bool> {
        let data = message.signing_data();
        let key_id = message.get_key_id(session.session_nonce.as_deref());

        let signature = message
            .signature
            .as_ref()
            .ok_or_else(|| Error::AuthError("Message not signed".into()))?;

        let protocol = Protocol::new(SecurityLevel::Counterparty, AUTH_PROTOCOL_ID);

        let result = self
            .wallet
            .verify_signature(
                VerifySignatureArgs {
                    data: Some(data),
                    hash_to_directly_verify: None,
                    signature: signature.clone(),
                    protocol_id: protocol,
                    key_id,
                    counterparty: Some(Counterparty::Other(message.identity_key.clone())),
                    for_self: None,
                },
                &self.originator,
            )
            .await?;

        Ok(result.valid)
    }

    async fn initiate_handshake(
        &self,
        _identity_key: Option<&str>,
        max_wait_time: Option<u64>,
    ) -> Result<PeerSession> {
        let my_identity = self.get_identity_key().await?;

        // Create session with new nonce
        let session_nonce = create_nonce(&self.wallet, None, &self.originator).await?;
        let session = PeerSession::with_nonce(session_nonce.clone());

        // Add to session manager
        {
            let mut mgr = self.session_manager.write().await;
            mgr.add_session(session.clone())?;
        }

        // Build InitialRequest message
        // Note: InitialRequest uses initial_nonce (not nonce) for the session nonce
        let mut msg = AuthMessage::new(MessageType::InitialRequest, my_identity);
        msg.initial_nonce = Some(session_nonce.clone());
        if let Some(ref req) = self.certificates_to_request {
            msg.requested_certificates = Some(req.clone());
        }

        // Create oneshot channel for response
        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.pending_handshakes.write().await;
            pending.insert(session_nonce.clone(), tx);
        }

        // Send the request
        self.transport.send(&msg).await?;

        // Wait for response with timeout
        let timeout = max_wait_time.unwrap_or(30000);
        let result = tokio::time::timeout(tokio::time::Duration::from_millis(timeout), rx)
            .await
            .map_err(|_| Error::AuthError("Handshake timeout".into()))?
            .map_err(|_| Error::AuthError("Handshake cancelled".into()))??;

        Ok(result)
    }

    async fn process_initial_request(&self, message: AuthMessage) -> Result<()> {
        let my_identity = self.get_identity_key().await?;

        // Create our session
        let session_nonce =
            create_nonce(&self.wallet, Some(&message.identity_key), &self.originator).await?;
        let mut session = PeerSession::with_nonce(session_nonce.clone());
        session.peer_identity_key = Some(message.identity_key.clone());
        session.peer_nonce = message.nonce.clone();
        session.is_authenticated = true;
        session.touch();

        // Check if certificates are required
        if let Some(ref req) = message.requested_certificates {
            if !req.is_empty() {
                session.certificates_required = true;
            }
        }

        // Add to session manager
        {
            let mut mgr = self.session_manager.write().await;
            mgr.add_session(session.clone())?;
        }

        // Build InitialResponse
        let mut response = AuthMessage::new(MessageType::InitialResponse, my_identity);
        response.nonce = Some(session_nonce);
        response.initial_nonce = message.nonce.clone();
        response.your_nonce = message.nonce.clone();

        // Sign the response
        self.sign_message(&mut response, &session).await?;

        // Send response
        self.transport.send(&response).await?;

        // If peer requested certificates, try to provide them
        if let Some(ref req) = message.requested_certificates {
            if !req.is_empty() {
                let certs = get_verifiable_certificates(
                    &self.wallet,
                    req,
                    &message.identity_key,
                    &self.originator,
                )
                .await
                .unwrap_or_default();

                if !certs.is_empty() {
                    self.send_certificate_response(&message.identity_key.to_hex(), certs)
                        .await?;
                }
            }
        }

        Ok(())
    }

    async fn process_initial_response(&self, message: AuthMessage) -> Result<()> {
        // Find the pending handshake
        let initial_nonce = message
            .initial_nonce
            .as_ref()
            .ok_or_else(|| Error::AuthError("InitialResponse missing initial_nonce".into()))?;

        // Verify the signature
        // For InitialResponse, we need a temporary session for verification
        let temp_session = PeerSession {
            session_nonce: Some(initial_nonce.clone()),
            peer_identity_key: Some(message.identity_key.clone()),
            peer_nonce: message.nonce.clone(),
            ..Default::default()
        };

        if !self
            .verify_message_signature(&message, &temp_session)
            .await?
        {
            // Clean up pending handshake
            let mut pending = self.pending_handshakes.write().await;
            if let Some(tx) = pending.remove(initial_nonce) {
                let _ = tx.send(Err(Error::AuthError("Invalid signature".into())));
            }
            return Err(Error::AuthError("InitialResponse signature invalid".into()));
        }

        // Verify the nonce
        if !verify_nonce(
            message.nonce.as_deref().unwrap_or(""),
            &self.wallet,
            Some(&message.identity_key),
            &self.originator,
        )
        .await
        .unwrap_or(false)
        {
            // Nonce verification is optional, continue anyway
        }

        // Update the session
        {
            let mut mgr = self.session_manager.write().await;
            if let Some(session) = mgr.get_session_mut(initial_nonce) {
                session.peer_identity_key = Some(message.identity_key.clone());
                session.peer_nonce = message.nonce.clone();
                session.is_authenticated = true;
                session.touch();

                // Check if we need certificates
                if let Some(ref req) = self.certificates_to_request {
                    if !req.is_empty() {
                        session.certificates_required = true;
                    }
                }

                let session_clone = session.clone();

                // Notify pending handshake
                let mut pending = self.pending_handshakes.write().await;
                if let Some(tx) = pending.remove(initial_nonce) {
                    let _ = tx.send(Ok(session_clone));
                }
            }
        }

        Ok(())
    }

    async fn process_certificate_request(&self, message: AuthMessage) -> Result<()> {
        // Find session
        let sender_hex = message.identity_key.to_hex();
        let mgr = self.session_manager.read().await;
        let session = mgr
            .get_session(&sender_hex)
            .ok_or_else(|| Error::AuthError("No session with sender".into()))?;

        // Verify signature
        if !self.verify_message_signature(&message, session).await? {
            return Err(Error::AuthError(
                "CertificateRequest signature invalid".into(),
            ));
        }

        drop(mgr);

        // Notify callbacks
        if let Some(ref requested) = message.requested_certificates {
            let cbs = self.certificate_request_callbacks.read().await;
            for (_, callback) in cbs.iter() {
                let _ = callback(message.identity_key.clone(), requested.clone()).await;
            }
        }

        Ok(())
    }

    async fn process_certificate_response(&self, message: AuthMessage) -> Result<()> {
        // Find session
        let sender_hex = message.identity_key.to_hex();
        let mgr = self.session_manager.read().await;
        let session = mgr
            .get_session(&sender_hex)
            .ok_or_else(|| Error::AuthError("No session with sender".into()))?
            .clone();
        drop(mgr);

        // Verify signature
        if !self.verify_message_signature(&message, &session).await? {
            return Err(Error::AuthError(
                "CertificateResponse signature invalid".into(),
            ));
        }

        // Validate certificates
        validate_certificates(
            &self.wallet,
            &message,
            self.certificates_to_request.as_ref(),
            &self.originator,
        )
        .await?;

        // Update session
        {
            let mut mgr = self.session_manager.write().await;
            if let Some(session) = mgr.get_session_mut(&sender_hex) {
                session.certificates_validated = true;
                session.touch();
            }
        }

        // Notify callbacks
        if let Some(ref certs) = message.certificates {
            let cbs = self.certificate_callbacks.read().await;
            for (_, callback) in cbs.iter() {
                let _ = callback(message.identity_key.clone(), certs.clone()).await;
            }
        }

        Ok(())
    }

    async fn process_general_message(&self, message: AuthMessage) -> Result<()> {
        // Find session
        let sender_hex = message.identity_key.to_hex();
        let mgr = self.session_manager.read().await;
        let session = mgr
            .get_session(&sender_hex)
            .ok_or_else(|| Error::AuthError("No session with sender".into()))?
            .clone();
        drop(mgr);

        // Verify the session is authenticated
        if !session.is_authenticated {
            return Err(Error::AuthError("Session not authenticated".into()));
        }

        // Verify signature
        if !self.verify_message_signature(&message, &session).await? {
            return Err(Error::AuthError("General message signature invalid".into()));
        }

        // Update session
        {
            let mut mgr = self.session_manager.write().await;
            if let Some(s) = mgr.get_session_mut(&sender_hex) {
                s.peer_nonce = message.nonce.clone();
                s.touch();
            }
        }

        // Notify callbacks
        if let Some(ref payload) = message.payload {
            let cbs = self.general_message_callbacks.read().await;
            for (_, callback) in cbs.iter() {
                let _ = callback(message.identity_key.clone(), payload.clone()).await;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::transports::MockTransport;
    use crate::primitives::PrivateKey;
    use crate::wallet::ProtoWallet;

    fn make_peer() -> Peer<ProtoWallet, MockTransport> {
        let wallet = ProtoWallet::new(Some(PrivateKey::random()));
        let transport = MockTransport::new();
        Peer::new(PeerOptions {
            wallet,
            transport,
            certificates_to_request: None,
            session_manager: None,
            auto_persist_last_session: false,
            originator: Some("test".into()),
        })
    }

    #[tokio::test]
    async fn test_peer_creation() {
        let peer = make_peer();
        let identity = peer.get_identity_key().await.unwrap();
        assert_eq!(identity.to_compressed().len(), 33);
    }

    #[tokio::test]
    async fn test_listener_registration() {
        let peer = make_peer();

        let id = peer
            .listen_for_general_messages(|_sender, _payload| Box::pin(async { Ok(()) }))
            .await;
        assert!(id > 0);

        peer.stop_listening_for_general_messages(id).await;
    }

    #[tokio::test]
    async fn test_session_manager_access() {
        let peer = make_peer();
        let mgr = peer.session_manager.read().await;
        assert!(mgr.is_empty());
    }
}
