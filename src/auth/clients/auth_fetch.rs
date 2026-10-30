//! The reference's `AuthFetch` client (`ts-stack@edf6e03`, AuthFetch.ts).
//!
//! BRC-104 supplies the transport framing; request correlation, certificate
//! queues, fallback validation and BRC-105 payment retries belong to this client.
//! The owned [`Response`] is the native equivalent of Fetch's buffered response.

pub use super::response::Response;
use super::{
    payment::PaymentContext, retry::RetryBudget, shared_wallet::SharedWallet, state::PeerState,
};
use crate::auth::{
    Peer, RequestedCertificateSet, SessionManager, SimplifiedFetchTransport, Transport,
};
use crate::wallet::WalletInterface;
use crate::{Error, Result};
use indexmap::IndexMap;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::{oneshot, Mutex as AsyncMutex, RwLock};

type TransportFactory<T> = dyn Fn(&str, usize) -> Result<T> + Send + Sync;

/// Options for one authenticated HTTP request.
#[derive(Clone, Debug, Default)]
pub struct AuthFetchOptions {
    /// Method as supplied; defaults to `GET` (its case is signed unchanged).
    pub method: Option<String>,
    /// Insertion-ordered headers; only content-type, authorization and x-bsv-*.
    pub headers: IndexMap<String, String>,
    /// Body bytes. `None` applies the reference's method/content-type default;
    /// `Some(vec![])` corresponds to an empty typed array, not a JS empty string.
    pub body: Option<Vec<u8>>,
    /// Remaining fetch attempts; decremented on entry, refused at zero.
    pub retry_counter: Option<u32>,
    /// Maximum paid attempts; zero/absent selects the reference default of three.
    pub payment_retry_attempts: Option<u32>,
    /// Caller labels appended after the automatic `brc105 <hex> <hex>` label.
    pub labels: Vec<String>,
}

/// An authenticated client sharing a wallet and session manager across origins.
///
/// `new` uses [`SimplifiedFetchTransport`] (`http` enables network I/O).
/// [`Self::with_transport_factory`] also supports an embedder's transport on wasm,
/// without starting a runtime, thread, server or background task.
pub struct AuthFetch<W: WalletInterface, T: Transport = SimplifiedFetchTransport> {
    pub(super) wallet: Arc<W>,
    pub(super) requested_certificates: Option<RequestedCertificateSet>,
    pub(super) session_manager: Arc<RwLock<SessionManager>>,
    pub(super) peers: AsyncMutex<HashMap<String, Arc<PeerState<W, T>>>>,
    pub(super) transport: Box<TransportFactory<T>>,
    pub(super) received: Arc<Mutex<VecDeque<crate::auth::VerifiableCertificate>>>,
    pending: AtomicUsize,
    pub(super) originator: Option<String>,
    pub(super) response_timeout_ms: u64,
    pub(super) max_response_bytes: usize,
    #[cfg(feature = "http")]
    pub(super) http_client: crate::auth::transports::NativeFetchClient,
}

impl<W: WalletInterface + 'static> AuthFetch<W> {
    /// Creates a client with optional handshake certificate policy and sessions.
    pub fn new(
        wallet: W,
        requested_certificates: Option<RequestedCertificateSet>,
        session_manager: Option<SessionManager>,
    ) -> Self {
        Self::with_response_transport_factory(
            wallet,
            requested_certificates,
            session_manager,
            |origin, _limit| {
                let transport = SimplifiedFetchTransport::new(origin);
                #[cfg(feature = "http")]
                let transport = transport.with_max_response_bytes(_limit)?;
                Ok(transport)
            },
        )
    }

    /// Uses the caller's HTTP client for transport and unauthenticated fallback.
    /// The caller owns its redirect policy, as with the transport's `with_client`.
    #[cfg(feature = "http")]
    pub fn with_client(
        wallet: W,
        requested_certificates: Option<RequestedCertificateSet>,
        session_manager: Option<SessionManager>,
        client: crate::auth::transports::NativeFetchClient,
    ) -> Self {
        let transport_client = client.clone();
        let mut fetch = Self::with_response_transport_factory(
            wallet,
            requested_certificates,
            session_manager,
            move |origin, limit| {
                SimplifiedFetchTransport::with_client(origin, transport_client.clone())
                    .with_max_response_bytes(limit)
            },
        );
        fetch.http_client = client;
        fetch
    }
}

impl<W: WalletInterface + 'static, T: Transport + 'static> AuthFetch<W, T> {
    /// Supplies a transport per URL origin. The factory must not start a worker;
    /// its send future delivers responses to the callback installed by `Peer`.
    pub fn with_transport_factory(
        wallet: W,
        requested_certificates: Option<RequestedCertificateSet>,
        session_manager: Option<SessionManager>,
        transport: impl Fn(&str) -> T + Send + Sync + 'static,
    ) -> Self {
        Self::with_response_transport_factory(
            wallet,
            requested_certificates,
            session_manager,
            move |origin, _| Ok(transport(origin)),
        )
    }

    fn with_response_transport_factory(
        wallet: W,
        requested_certificates: Option<RequestedCertificateSet>,
        session_manager: Option<SessionManager>,
        transport: impl Fn(&str, usize) -> Result<T> + Send + Sync + 'static,
    ) -> Self {
        Self {
            wallet: Arc::new(wallet),
            requested_certificates,
            session_manager: Arc::new(RwLock::new(session_manager.unwrap_or_default())),
            peers: AsyncMutex::new(HashMap::new()),
            transport: Box::new(transport),
            received: Arc::new(Mutex::new(VecDeque::new())),
            pending: AtomicUsize::new(0),
            originator: None,
            response_timeout_ms: 30_000,
            max_response_bytes: 16 * 1024 * 1024,
            #[cfg(feature = "http")]
            http_client: crate::auth::transports::fetch_client::default_client(),
        }
    }

    /// Sets the optional wallet originator before using the client.
    #[must_use]
    pub fn with_originator(mut self, originator: Option<String>) -> Self {
        self.originator = originator;
        self
    }

    /// Configures the response deadline in milliseconds (default 30,000).
    #[must_use]
    pub fn with_response_timeout_ms(mut self, milliseconds: u64) -> Self {
        self.response_timeout_ms = milliseconds;
        self
    }

    /// Configures the response body limit (default 16 MiB) for parsing, native
    /// HTTP transport and fallback, and the corresponding Peer payload bound.
    /// A custom factory owns its transport's I/O limits. Existing peers are reset.
    ///
    /// # Errors
    /// Refuses zero or a limit above JavaScript's maximum safe integer.
    pub fn with_max_response_bytes(mut self, bytes: usize) -> Result<Self> {
        super::response::validate_limit(bytes)?;
        self.max_response_bytes = bytes;
        self.peers.get_mut().clear();
        Ok(self)
    }

    /// Mutually authenticates, sends a request, and handles bounded payment retries.
    ///
    /// # Errors
    /// Propagates authentication, transport, body, wallet and payment refusals;
    /// also refuses exhausted retries or a response deadline.
    pub async fn fetch(&self, url: &str, options: AuthFetchOptions) -> Result<Response> {
        let retry = RetryBudget::new(options.retry_counter);
        self.fetch_inner(url, options, None, retry).await
    }

    pub(super) async fn fetch_inner(
        &self,
        url: &str,
        options: AuthFetchOptions,
        payment: Option<PaymentContext>,
        retry: RetryBudget,
    ) -> Result<Response> {
        retry.enter()?;
        let parsed = url::Url::parse(url).map_err(|_| Error::AuthError("Invalid URL".into()))?;
        let origin = parsed.origin().ascii_serialization();
        let state = self.get_peer(&origin).await?;
        let response = if *state.mutual.read().await == Some(false) {
            self.fallback(url, &options, &state).await?
        } else {
            let payload = super::request::serialize(&parsed, &options)?;
            match self.authenticated(&state, &payload).await {
                Ok(response) => response,
                Err(error) => {
                    if Self::stale(&error, &state).await {
                        self.peers.lock().await.remove(&origin);
                        retry.initialize();
                        return Box::pin(self.fetch_inner(url, options, payment, retry)).await;
                    }
                    if error
                        .to_string()
                        .contains("HTTP server failed to authenticate")
                    {
                        self.fallback(url, &options, &state).await?
                    } else {
                        return Err(error);
                    }
                }
            }
        };
        if response.status == 402 {
            self.pay_and_retry(url, options, response, payment, retry)
                .await
        } else {
            Ok(response)
        }
    }

    async fn stale(error: &Error, state: &PeerState<W, T>) -> bool {
        let text = error.to_string();
        text.contains("Session not found for nonce")
            || (text.contains("without valid BSV authentication")
                && state.identity.read().await.is_some()
                && text.contains("HTTP 401 "))
    }

    async fn authenticated(
        &self,
        state: &Arc<PeerState<W, T>>,
        payload: &[u8],
    ) -> Result<Response> {
        super::transport::validate_payload(payload.len(), self.max_response_bytes)?;
        let previous = self.pending.fetch_add(1, Ordering::AcqRel);
        let _pending = Pending(&self.pending);
        if previous >= 1000 {
            return Err(Error::AuthError(
                "Authentication request capacity exceeded.".into(),
            ));
        }
        let request_id: [u8; 32] = payload[..32]
            .try_into()
            .map_err(|_| Error::AuthError("Invalid request ID".into()))?;
        let (send, receive) = oneshot::channel();
        let listener = self.listen_for_response(state, request_id, send).await;
        let work = async {
            state.wait_for_certificates().await?;
            let identity = state.identity.read().await.clone();
            state
                .peer
                .to_peer(payload, identity.as_deref(), None)
                .await?;
            receive.await.map_err(|_| {
                Error::AuthError("Timed out waiting for authenticated response.".into())
            })?
        };
        let result = crate::auth::peer::wait_with_timeout(work, self.response_timeout_ms)
            .await
            .map_err(|_| Error::AuthError("Timed out waiting for authenticated response.".into()));
        state
            .peer
            .stop_listening_for_general_messages(listener)
            .await;
        result?
    }
    async fn listen_for_response(
        &self,
        state: &Arc<PeerState<W, T>>,
        request_id: [u8; 32],
        send: oneshot::Sender<Result<Response>>,
    ) -> u32 {
        let send = Arc::new(Mutex::new(Some(send)));
        let weak = Arc::downgrade(state);
        let limit = self.max_response_bytes;
        state
            .peer
            .listen_for_general_messages(move |sender, payload| {
                let weak = weak.clone();
                let send = Arc::clone(&send);
                Box::pin(async move {
                    // The reference commits the identity on an in-bounds ID
                    // match, before parsing the status, headers or body.
                    if matches!(
                        super::response::matches_request(&payload, &request_id, limit),
                        Ok(true)
                    ) {
                        if let Some(state) = weak.upgrade() {
                            *state.identity.write().await = Some(sender.to_hex());
                            *state.mutual.write().await = Some(true);
                        }
                    }
                    let parsed = Response::from_authenticated_payload(
                        &payload,
                        &request_id,
                        &sender.to_hex(),
                        limit,
                    );
                    if matches!(parsed, Ok(None)) {
                        return Ok(());
                    }
                    if let Some(send) = send
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .take()
                    {
                        let result = parsed.and_then(|value| {
                            value.ok_or_else(|| Error::AuthError("Invalid request ID".into()))
                        });
                        let _ = send.send(result);
                    }
                    Ok(())
                })
            })
            .await
    }
}

struct Pending<'a>(&'a AtomicUsize);
impl Drop for Pending<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

pub(super) type ClientPeer<W, T> = Peer<SharedWallet<W>, super::transport::FetchTransport<T>>;
