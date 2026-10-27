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
    utils::{
        assert_requested_certificate_set, check_received_requested_certificates, create_nonce,
        get_verifiable_certificates, validate_certificates, verify_nonce,
    },
};
use crate::primitives::to_base64;
use crate::primitives::PublicKey;
use crate::wallet::{
    Counterparty, CreateSignatureArgs, GetPublicKeyArgs, Protocol, SecurityLevel,
    VerifySignatureArgs, WalletInterface,
};
use crate::{Error, Result};
use rand::RngCore;
use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{oneshot, RwLock};

/// Wait for `future` to complete, or time out after `timeout_ms` milliseconds.
///
/// On native targets this delegates to `tokio::time::timeout`, which requires
/// a Tokio runtime with the `time` driver enabled. On `wasm32-unknown-unknown`
/// (with the `wasm` feature enabled) it instead races the future against a
/// `futures_timer::Delay`, which has no runtime dependency and therefore works
/// inside Cloudflare Workers, browser `wasm-bindgen-futures` executors, and
/// other JS-async-style environments that do not provide a Tokio time driver.
///
/// A timeout is reported as `Error::AuthError("Handshake timeout".into())` so
/// the existing call-site error semantics are preserved.
#[cfg(not(all(target_arch = "wasm32", feature = "wasm")))]
async fn wait_with_timeout<F>(future: F, timeout_ms: u64) -> Result<F::Output>
where
    F: Future,
{
    tokio::time::timeout(Duration::from_millis(timeout_ms), future)
        .await
        .map_err(|_| Error::AuthError("Handshake timeout".into()))
}

#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
async fn wait_with_timeout<F>(future: F, timeout_ms: u64) -> Result<F::Output>
where
    F: Future,
{
    use futures::future::{select, Either};
    use futures::pin_mut;

    let delay = futures_timer::Delay::new(Duration::from_millis(timeout_ms));
    pin_mut!(future);
    pin_mut!(delay);
    match select(future, delay).await {
        Either::Left((output, _)) => Ok(output),
        Either::Right(((), _)) => Err(Error::AuthError("Handshake timeout".into())),
    }
}

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
/// use bsv_rs::auth::{Peer, PeerOptions, SimplifiedFetchTransport};
/// use bsv_rs::wallet::ProtoWallet;
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
    wallet: Arc<W>,
    transport: Arc<T>,
    session_manager: Arc<RwLock<SessionManager>>,
    certificates_to_request: Option<RequestedCertificateSet>,

    // Callbacks
    general_message_callbacks: Arc<RwLock<HashMap<u32, GeneralMessageCallback>>>,
    certificate_callbacks: Arc<RwLock<HashMap<u32, CertificateCallback>>>,
    certificate_request_callbacks: Arc<RwLock<HashMap<u32, CertificateRequestCallback>>>,
    next_callback_id: Arc<AtomicU32>,

    // Pending handshakes: session_nonce -> oneshot sender
    pending_handshakes: Arc<RwLock<HashMap<String, oneshot::Sender<Result<PeerSession>>>>>,

    // Options
    #[allow(dead_code)]
    auto_persist_last_session: bool,
    originator: Option<String>,

    // Cached identity key
    identity_key: Arc<RwLock<Option<PublicKey>>>,
}

impl<W: WalletInterface + 'static, T: Transport + 'static> Peer<W, T> {
    /// Creates a new Peer with the given options.
    ///
    /// Note: After creating the Peer, you should call `start()` to set up
    /// the transport callback for receiving messages.
    pub fn new(options: PeerOptions<W, T>) -> Self {
        Self {
            wallet: Arc::new(options.wallet),
            transport: Arc::new(options.transport),
            session_manager: Arc::new(RwLock::new(options.session_manager.unwrap_or_default())),
            certificates_to_request: options.certificates_to_request,
            general_message_callbacks: Arc::new(RwLock::new(HashMap::new())),
            certificate_callbacks: Arc::new(RwLock::new(HashMap::new())),
            certificate_request_callbacks: Arc::new(RwLock::new(HashMap::new())),
            next_callback_id: Arc::new(AtomicU32::new(1)),
            pending_handshakes: Arc::new(RwLock::new(HashMap::new())),
            auto_persist_last_session: options.auto_persist_last_session,
            originator: options.originator,
            identity_key: Arc::new(RwLock::new(None)),
        }
    }

    /// Sets up the transport callback: every incoming message goes through
    /// [`handle_incoming_message`](Self::handle_incoming_message), the one
    /// verifying path of both roles, as the reference's `Peer` has one
    /// (`Peer.ts:766-794`). A client's initial response and general messages
    /// are verified as a server's are (#353): the nonce it echoes, its session,
    /// the pinned identity and the signature; an initial request is answered.
    pub fn start(&self) {
        let peer = Arc::new(self.share());
        self.transport.set_callback(Box::new(move |message| {
            let peer = Arc::clone(&peer);
            Box::pin(async move { peer.handle_incoming_message(message).await })
        }));
    }

    /// The same as [`start`](Self::start), kept for the callers that hold the
    /// Peer in an `Arc` (until 0.9 `start` did not verify; #353).
    pub fn start_server(self: &Arc<Self>) {
        self.start();
    }

    /// A Peer over the same wallet, transport, sessions, callbacks and pending
    /// handshakes, for the transport callback to own.
    fn share(&self) -> Self {
        Self {
            wallet: Arc::clone(&self.wallet),
            transport: Arc::clone(&self.transport),
            session_manager: Arc::clone(&self.session_manager),
            certificates_to_request: self.certificates_to_request.clone(),
            general_message_callbacks: Arc::clone(&self.general_message_callbacks),
            certificate_callbacks: Arc::clone(&self.certificate_callbacks),
            certificate_request_callbacks: Arc::clone(&self.certificate_request_callbacks),
            next_callback_id: Arc::clone(&self.next_callback_id),
            pending_handshakes: Arc::clone(&self.pending_handshakes),
            auto_persist_last_session: self.auto_persist_last_session,
            originator: self.originator.clone(),
            identity_key: Arc::clone(&self.identity_key),
        }
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
        assert_requested_certificate_set(&requested)?; // before a session or a signature (#294)
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
        msg.set_requested_certificates(requested);

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
        msg.set_certificates(certificates);

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
                    ..Default::default()
                },
                self.originator.as_deref(),
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
        check_received_requested_certificates(&message)?; // before any handler (#294)

        match message.message_type {
            MessageType::InitialRequest => {
                self.check_own_policy()?; // before the response is signed (#294)
                self.process_initial_request(message).await
            }
            MessageType::InitialResponse => self.process_initial_response(message).await,
            MessageType::CertificateRequest => self.process_certificate_request(message).await,
            MessageType::CertificateResponse => self.process_certificate_response(message).await,
            MessageType::General => self.process_general_message(message).await,
        }
    }

    // ========================================================================
    // Private methods
    // ========================================================================

    /// This peer's own policy, refused where the reference snapshots it
    /// (`Peer.ts:332`, `:630`, `:811`; its construction-time refusal, `:158`,
    /// made here since `new` cannot fail; #294)
    fn check_own_policy(&self) -> Result<()> {
        self.certificates_to_request
            .as_ref()
            .map_or(Ok(()), assert_requested_certificate_set)
    }

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
                    protocol_id: protocol,
                    key_id: key_id.clone(),
                    counterparty,
                    ..Default::default()
                },
                self.originator.as_deref(),
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
                    ..Default::default()
                },
                self.originator.as_deref(),
            )
            .await?;

        Ok(result.valid)
    }

    async fn initiate_handshake(
        &self,
        identity_key: Option<&str>,
        max_wait_time: Option<u64>,
    ) -> Result<PeerSession> {
        self.check_own_policy()?; // before a nonce or a message (#294)

        // The responder pinned to the identity asked for (`Peer.ts:637`), its
        // initial response refused if another answers (`:903-908`; #353)
        let pinned = identity_key.map(PublicKey::from_hex).transpose()?;
        let my_identity = self.get_identity_key().await?;

        // Create session with new nonce
        let session_nonce = create_nonce(&*self.wallet, None, self.originator.as_deref()).await?;
        let mut session = PeerSession::with_nonce(session_nonce.clone());
        session.peer_identity_key = pinned;

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
            msg.set_requested_certificates(req.clone());
        }

        // Create oneshot channel for response
        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.pending_handshakes.write().await;
            pending.insert(session_nonce.clone(), tx);
        }

        // Send the request and wait for the response; a failed handshake's
        // session removed, as the reference does (`Peer.ts:658-664`)
        let timeout = max_wait_time.unwrap_or(30000);
        let result = match self.transport.send(&msg).await {
            Ok(()) => wait_with_timeout(rx, timeout)
                .await
                .and_then(|r| r.map_err(|_| Error::AuthError("Handshake cancelled".into())))
                .and_then(|r| r),
            Err(e) => Err(e),
        };
        if result.is_err() {
            self.pending_handshakes.write().await.remove(&session_nonce);
            self.session_manager.write().await.remove_session(&session);
        }
        result
    }

    async fn process_initial_request(&self, message: AuthMessage) -> Result<()> {
        let my_identity = self.get_identity_key().await?;

        // Create our session nonce (counterparty=None=Self, matching Go/TS)
        let session_nonce = create_nonce(&*self.wallet, None, self.originator.as_deref()).await?;
        let mut session = PeerSession::with_nonce(session_nonce.clone());
        session.peer_identity_key = Some(message.identity_key.clone());
        session.peer_nonce = message.initial_nonce.clone();
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

        // Build InitialResponse (matching Go/TS field mapping)
        // initial_nonce = responder's session nonce (matches Go: InitialNonce = session.SessionNonce)
        // nonce = responder's session nonce (same value, matches Go: Nonce = ourNonce)
        // your_nonce = initiator's nonce echoed back (for session lookup by initiator)
        let mut response = AuthMessage::new(MessageType::InitialResponse, my_identity);
        response.nonce = Some(session_nonce.clone());
        response.initial_nonce = Some(session_nonce);
        response.your_nonce = message.initial_nonce.clone();

        // Sign the response
        self.sign_message(&mut response, &session).await?;

        // Send response
        self.transport.send(&response).await?;

        // If peer requested certificates, try to provide them
        if let Some(ref req) = message.requested_certificates {
            if !req.is_empty() {
                let certs = get_verifiable_certificates(
                    &*self.wallet,
                    req,
                    &message.identity_key,
                    self.originator.as_deref(),
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
        // The pending handshake is the one named by yourNonce (our nonce
        // echoed back); a refusal is delivered to it, not left to time out.
        let our_nonce = message.your_nonce.clone().unwrap_or_default();
        let result = self
            .process_initial_response_inner(&message, &our_nonce)
            .await;

        if let Err(ref e) = result {
            let mut pending = self.pending_handshakes.write().await;
            if let Some(tx) = pending.remove(&our_nonce) {
                let _ = tx.send(Err(e.clone()));
            }
        }

        result
    }

    /// The reference's `authenticateInitialResponse` (`Peer.ts:886-930`), its
    /// checks in its order and words: yourNonce is ours, its session exists,
    /// the responder is the pinned peer, the signature verifies, the
    /// responder's nonce is present (#353).
    async fn process_initial_response_inner(
        &self,
        message: &AuthMessage,
        our_nonce: &str,
    ) -> Result<()> {
        let sender = message.identity_key.to_hex();
        if !self.verify_own_nonce(our_nonce).await {
            return Err(Error::AuthError(format!(
                "Initial response nonce verification failed from peer: {sender}"
            )));
        }

        let session = self
            .session_manager
            .read()
            .await
            .get_session(our_nonce)
            .cloned();
        let session = session.ok_or_else(|| {
            Error::AuthError(format!("Peer session not found for peer: {sender}"))
        })?;
        if session
            .peer_identity_key
            .as_ref()
            .is_some_and(|pinned| *pinned != message.identity_key)
        {
            return Err(Error::AuthError(
                "initialResponse identity does not match the requested peer identity.".into(),
            ));
        }

        if !self.verify_message_signature(message, &session).await? {
            return Err(Error::AuthError(format!(
                "Unable to verify initial response signature for peer: {sender}"
            )));
        }
        let peer_nonce = message
            .initial_nonce
            .clone()
            .filter(|nonce| !nonce.is_empty())
            .ok_or_else(|| {
                Error::AuthError("Initial response message nonce is required.".into())
            })?;

        // Update the session and its secondary index (identity key mapping).
        let mut updated = session;
        updated.peer_identity_key = Some(message.identity_key.clone());
        updated.peer_nonce = Some(peer_nonce);
        updated.is_authenticated = true;
        updated.touch();
        if let Some(ref req) = self.certificates_to_request {
            if !req.is_empty() {
                updated.certificates_required = true;
            }
        }
        self.session_manager
            .write()
            .await
            .update_session(updated.clone());

        // Notify pending handshake
        let mut pending = self.pending_handshakes.write().await;
        if let Some(tx) = pending.remove(our_nonce) {
            let _ = tx.send(Ok(updated));
        }

        Ok(())
    }

    /// Whether `nonce` is one this peer's wallet made (counterparty self), as
    /// the reference's `verifyNonce` reads it: a malformed nonce is `false`.
    async fn verify_own_nonce(&self, nonce: &str) -> bool {
        verify_nonce(nonce, &*self.wallet, None, self.originator.as_deref())
            .await
            .unwrap_or(false)
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
            for callback in cbs.values() {
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
            &*self.wallet,
            &message,
            self.certificates_to_request.as_ref(),
            self.originator.as_deref(),
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
            for callback in cbs.values() {
                let _ = callback(message.identity_key.clone(), certs.clone()).await;
            }
        }

        Ok(())
    }

    /// The reference's `processGeneralMessage` (`Peer.ts:1270-1314`), its
    /// checks in its order and words: yourNonce is ours, its session exists
    /// and is the sender's, the signature verifies, the message's nonce and
    /// the session's are present (#353).
    async fn process_general_message(&self, message: AuthMessage) -> Result<()> {
        let sender = message.identity_key.to_hex();
        let your_nonce = message.your_nonce.as_deref().unwrap_or_default();
        if !self.verify_own_nonce(your_nonce).await {
            return Err(Error::AuthError(format!(
                "Unable to verify nonce for general message from: {sender}"
            )));
        }

        let session = self
            .session_manager
            .read()
            .await
            .get_session(your_nonce)
            .cloned();
        let session = session.ok_or_else(|| {
            Error::AuthError(format!("Session not found for nonce: {your_nonce}"))
        })?;
        match session.peer_identity_key {
            None => {
                return Err(Error::AuthError(
                    "Peer identity is not established for general message.".into(),
                ))
            }
            Some(ref verified) if *verified != message.identity_key => {
                return Err(Error::AuthError(
                    "general identity does not match the authenticated session.".into(),
                ))
            }
            Some(_) => {}
        }

        if !self.verify_message_signature(&message, &session).await? {
            return Err(Error::AuthError(format!(
                "Invalid signature in generalMessage from {sender}"
            )));
        }
        if message.nonce.as_deref().is_none_or(str::is_empty) {
            return Err(Error::AuthError(
                "General message nonce is required.".into(),
            ));
        }
        let session_nonce = session.session_nonce.clone().ok_or_else(|| {
            Error::AuthError("Session nonce is required for general messages".into())
        })?;

        // The session marked authenticated (`Peer.ts:1315`); its peer nonce is
        // the one its initial message named, not this message's
        if let Some(s) = self
            .session_manager
            .write()
            .await
            .get_session_mut(&session_nonce)
        {
            s.is_authenticated = true;
            s.touch();
        }

        // Notify callbacks, a listener's error the message's (`Peer.ts:1329-1331`)
        let payload = message.payload.unwrap_or_default();
        let cbs = self.general_message_callbacks.read().await;
        for callback in cbs.values() {
            callback(message.identity_key.clone(), payload.clone()).await?;
        }

        Ok(())
    }
}

#[cfg(test)]
#[path = "peer_tests.rs"]
mod tests;
