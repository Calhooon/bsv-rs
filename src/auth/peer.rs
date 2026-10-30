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
        assert_requested_certificate_set, check_received_message,
        check_received_requested_certificates, create_nonce, get_verifiable_certificates,
        verify_nonce, MAX_CERTIFICATES,
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
use std::sync::{Arc, Weak};
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
pub(crate) async fn wait_with_timeout<F>(future: F, timeout_ms: u64) -> Result<F::Output>
where
    F: Future,
{
    tokio::time::timeout(Duration::from_millis(timeout_ms), future)
        .await
        .map_err(|_| Error::AuthError("Handshake timeout".into()))
}

#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
pub(crate) async fn wait_with_timeout<F>(future: F, timeout_ms: u64) -> Result<F::Output>
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

/// A Peer's hold on its transport: strong for the Peer, weak for the Peer the
/// transport's callback owns, so the callback keeps neither the transport nor
/// the Peer's state alive after the Peer is dropped, as the reference's `Peer`
/// holds no reference to itself (#353).
enum TransportHold<T> {
    Owned(Arc<T>),
    Callback(Weak<T>),
}

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
    transport: TransportHold<T>,
    session_manager: Arc<RwLock<SessionManager>>,
    certificates_to_request: Option<RequestedCertificateSet>,

    // Callbacks
    general_message_callbacks: Arc<RwLock<HashMap<u32, GeneralMessageCallback>>>,
    certificate_callbacks: Arc<RwLock<HashMap<u32, CertificateCallback>>>,
    certificate_request_callbacks: Arc<RwLock<HashMap<u32, CertificateRequestCallback>>>,
    next_callback_id: Arc<AtomicU32>,

    // Pending handshakes: session_nonce -> oneshot sender
    pending_handshakes: Arc<RwLock<HashMap<String, oneshot::Sender<Result<PeerSession>>>>>,
    pending_certificate_validation:
        Arc<RwLock<HashMap<String, Arc<certificate_wait::PendingValidation>>>>,

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
            transport: TransportHold::Owned(Arc::new(options.transport)),
            session_manager: Arc::new(RwLock::new(options.session_manager.unwrap_or_default())),
            certificates_to_request: options.certificates_to_request,
            general_message_callbacks: Arc::new(RwLock::new(HashMap::new())),
            certificate_callbacks: Arc::new(RwLock::new(HashMap::new())),
            certificate_request_callbacks: Arc::new(RwLock::new(HashMap::new())),
            next_callback_id: Arc::new(AtomicU32::new(1)),
            pending_handshakes: Arc::new(RwLock::new(HashMap::new())),
            pending_certificate_validation: Arc::new(RwLock::new(HashMap::new())),
            auto_persist_last_session: options.auto_persist_last_session,
            originator: options.originator,
            identity_key: Arc::new(RwLock::new(None)),
        }
    }

    /// Shares the client-wide manager across per-origin peers.
    pub(crate) fn share_session_manager(&mut self, manager: Arc<RwLock<SessionManager>>) {
        self.session_manager = manager;
    }

    /// Sets up the transport callback: every incoming message goes through
    /// [`handle_incoming_message`](Self::handle_incoming_message), the one
    /// verifying path of both roles, as the reference's `Peer` has one
    /// (`Peer.ts:766-794`). A client's initial response and general messages
    /// are verified as a server's are (#353): the nonce it echoes, its session,
    /// the pinned identity and the signature; an initial request is answered.
    pub fn start(&self) {
        let Ok(transport) = self.transport() else {
            return;
        };
        let peer = Arc::new(self.share());
        transport.set_callback(Box::new(move |message| {
            let peer = Arc::clone(&peer);
            Box::pin(async move { peer.handle_incoming_message(message).await })
        }));
    }

    /// The same as [`start`](Self::start), kept for the callers that hold the
    /// Peer in an `Arc` (until 0.9 `start` did not verify; #353).
    pub fn start_server(self: &Arc<Self>) {
        self.start();
    }

    /// A Peer over the same wallet, sessions, callbacks and pending handshakes,
    /// for the transport callback to own; the transport held weakly, so no
    /// cycle runs through the callback (a dropped Peer is freed).
    fn share(&self) -> Self {
        let transport = match &self.transport {
            TransportHold::Owned(transport) => Arc::downgrade(transport),
            TransportHold::Callback(transport) => Weak::clone(transport),
        };
        Self {
            wallet: Arc::clone(&self.wallet),
            transport: TransportHold::Callback(transport),
            session_manager: Arc::clone(&self.session_manager),
            certificates_to_request: self.certificates_to_request.clone(),
            general_message_callbacks: Arc::clone(&self.general_message_callbacks),
            certificate_callbacks: Arc::clone(&self.certificate_callbacks),
            certificate_request_callbacks: Arc::clone(&self.certificate_request_callbacks),
            next_callback_id: Arc::clone(&self.next_callback_id),
            pending_handshakes: Arc::clone(&self.pending_handshakes),
            pending_certificate_validation: Arc::clone(&self.pending_certificate_validation),
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
        self.transport()?.send(&msg).await?;

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
        msg.initial_nonce = session.session_nonce.clone();
        msg.set_requested_certificates(requested);

        self.sign_message(&mut msg, &session).await?;
        self.transport()?.send(&msg).await
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
        if certificates.len() > MAX_CERTIFICATES {
            return Err(Error::AuthError(
                "certificates must be an array of at most 100 entries".into(),
            ));
        }
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
        msg.initial_nonce = session.session_nonce.clone();
        msg.set_certificates(certificates);

        self.sign_message(&mut msg, &session).await?;
        self.transport()?.send(&msg).await
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
        check_received_message(&message)?; // the certificate bound and all nonces (#445)

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

    /// The transport, while the Peer that owns it lives.
    fn transport(&self) -> Result<Arc<T>> {
        match &self.transport {
            TransportHold::Owned(transport) => Ok(Arc::clone(transport)),
            TransportHold::Callback(transport) => transport
                .upgrade()
                .ok_or_else(|| Error::AuthError("Peer has been dropped".into())),
        }
    }

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
        let transport = self.transport()?;

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
        let result = match transport.send(&msg).await {
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
}

#[cfg(test)]
#[path = "peer_tests.rs"]
mod tests;

#[path = "peer_incoming.rs"]
mod incoming;

#[path = "peer_certificate_wait.rs"]
mod certificate_wait;

#[path = "peer_initial.rs"]
mod initial;

#[path = "peer_certificates.rs"]
mod certificates_received;
