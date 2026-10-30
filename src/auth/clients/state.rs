//! Per-origin peer, certificate queue and received-certificate buffer.

use super::auth_fetch::{AuthFetch, ClientPeer};
use super::response::words;
use super::shared_wallet::SharedWallet;
use crate::auth::{
    utils::get_verifiable_certificates, Peer, PeerOptions, RequestedCertificateSet, Transport,
    VerifiableCertificate,
};
use crate::wallet::WalletInterface;
use crate::Result;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use tokio::sync::{oneshot, RwLock};

pub(super) struct PeerState<W: WalletInterface, T: Transport> {
    pub peer: Arc<ClientPeer<W, T>>,
    pub identity: RwLock<Option<String>>,
    pub mutual: RwLock<Option<bool>>,
    pending_certificates: AtomicUsize,
}

pub(super) async fn wait(milliseconds: u64) {
    let _ = crate::auth::peer::wait_with_timeout(std::future::pending::<()>(), milliseconds).await;
}

impl<W: WalletInterface + 'static, T: Transport + 'static> PeerState<W, T> {
    pub async fn wait_for_certificates(&self) -> Result<()> {
        let start = crate::util::time::current_time_ms();
        while self.pending_certificates.load(Ordering::Acquire) > 0 {
            if crate::util::time::current_time_ms().saturating_sub(start) > 30_000 {
                return Err(words("Timeout waiting for certificate request to complete"));
            }
            wait(100).await;
        }
        Ok(())
    }
}

impl<W: WalletInterface + 'static, T: Transport + 'static> AuthFetch<W, T> {
    pub(super) async fn get_peer(&self, origin: &str) -> Result<Arc<PeerState<W, T>>> {
        let mut peers = self.peers.lock().await;
        if let Some(peer) = peers.get(origin) {
            return Ok(Arc::clone(peer));
        }
        let mut peer = Peer::new(PeerOptions {
            wallet: SharedWallet(Arc::clone(&self.wallet)),
            transport: super::transport::FetchTransport::new(
                (self.transport)(origin, self.max_response_bytes)?,
                self.max_response_bytes,
            ),
            certificates_to_request: self.requested_certificates.clone(),
            session_manager: None,
            auto_persist_last_session: false,
            originator: self.originator.clone(),
        });
        peer.share_session_manager(Arc::clone(&self.session_manager));
        let state = Arc::new(PeerState {
            peer: Arc::new(peer),
            identity: RwLock::new(None),
            mutual: RwLock::new(None),
            pending_certificates: AtomicUsize::new(0),
        });
        self.listen_for_certificates(&state).await;
        state.peer.start();
        peers.insert(origin.into(), Arc::clone(&state));
        Ok(state)
    }

    async fn listen_for_certificates(&self, state: &Arc<PeerState<W, T>>) {
        self.retain_certificates_from(state).await;
        let weak = Arc::downgrade(state);
        let wallet = Arc::clone(&self.wallet);
        let originator = self.originator.clone();
        state
            .peer
            .listen_for_certificates_requested(move |verifier, requested| {
                let state = weak.upgrade();
                let wallet = Arc::clone(&wallet);
                let originator = originator.clone();
                if let Some(state) = &state {
                    state.pending_certificates.fetch_add(1, Ordering::AcqRel);
                }
                Box::pin(async move {
                    let Some(state) = state else {
                        return Ok(());
                    };
                    let _pending = CertificatePending(&state.pending_certificates);
                    let result = async {
                        let certificates = get_verifiable_certificates(
                            wallet.as_ref(),
                            &requested,
                            &verifier,
                            originator.as_deref(),
                        )
                        .await?;
                        if !certificates.is_empty() {
                            state
                                .peer
                                .send_certificate_response(&verifier.to_hex(), certificates)
                                .await?;
                        }
                        Ok(())
                    }
                    .await;
                    // The reference's finally block delays removal even when the wallet refuses.
                    wait(500).await;
                    result
                })
            })
            .await;
    }

    async fn retain_certificates_from(&self, state: &Arc<PeerState<W, T>>) {
        let received = Arc::clone(&self.received);
        state
            .peer
            .listen_for_certificates_received(move |_, certificates| {
                let received = Arc::clone(&received);
                Box::pin(async move {
                    if certificates.len() > 100 {
                        return Err(words("Certificate response exceeds the per-message limit"));
                    }
                    let mut received = received
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    received.extend(certificates);
                    while received.len() > 1000 {
                        received.pop_front();
                    }
                    Ok(())
                })
            })
            .await;
    }

    /// Requests certificates and returns the first validated response. The same
    /// certificates remain available through [`Self::consume_received_certificates`].
    ///
    /// # Errors
    /// Propagates peer or certificate refusals and the 30-second deadline.
    pub async fn send_certificate_request(
        &self,
        base_url: &str,
        certificates_to_request: RequestedCertificateSet,
    ) -> Result<Vec<VerifiableCertificate>> {
        let url = url::Url::parse(base_url).map_err(|_| words("Invalid URL"))?;
        let origin = url.origin().ascii_serialization();
        let state = self.get_peer(&origin).await?;
        let (send, receive) = oneshot::channel();
        let send = Mutex::new(Some(send));
        let listener = state
            .peer
            .listen_for_certificates_received(move |_, certificates| {
                if let Some(send) = send
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take()
                {
                    let _ = send.send(certificates);
                }
                Box::pin(async { Ok(()) })
            })
            .await;
        let work = async {
            let identity = state.identity.read().await.clone();
            state
                .peer
                .request_certificates(certificates_to_request, identity.as_deref(), None)
                .await?;
            receive
                .await
                .map_err(|_| words("Certificate response listener closed"))
        };
        let result = crate::auth::peer::wait_with_timeout(work, 30_000).await;
        state
            .peer
            .stop_listening_for_certificates_received(listener)
            .await;
        result.map_err(|_| words(&format!("sendCertificateRequest timed out after 30000ms waiting for certificate response from {origin}")))?
    }

    /// Returns all retained certificates, clearing the buffer (most recent 1,000).
    pub fn consume_received_certificates(&self) -> Vec<VerifiableCertificate> {
        self.received
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .drain(..)
            .collect()
    }
}

struct CertificatePending<'a>(&'a AtomicUsize);
impl Drop for CertificatePending<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}
