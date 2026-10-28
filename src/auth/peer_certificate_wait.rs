//! One certificate-authorization wait and deadline per session (Peer.ts:286-329).

use super::{wait_with_timeout, Error, Peer, PublicKey, Result, Transport, WalletInterface};
use crate::auth::types::current_time_ms;
use std::sync::Arc;
use tokio::sync::watch;

pub(super) struct PendingValidation {
    result: watch::Sender<Option<Result<()>>>,
    started: u64,
}

impl<W: WalletInterface + 'static, T: Transport + 'static> Peer<W, T> {
    pub(super) async fn wait_for_certificate_validation(&self, nonce: &str) -> Result<()> {
        // Lock in session -> wait-map order, also used by the response: validation
        // cannot finish between the readiness check and registering this wait.
        let manager = self.session_manager.read().await;
        let session = manager
            .get_session(nonce)
            .ok_or_else(|| Error::AuthError(format!("Session not found for nonce: {nonce}")))?;
        if !session.certificates_required || session.certificates_validated {
            return Ok(());
        }
        let identity = session
            .peer_identity_key
            .as_ref()
            .map_or_else(|| "unknown".to_owned(), PublicKey::to_hex);
        let pending = self
            .pending_certificate_validation
            .write()
            .await
            .entry(nonce.to_owned())
            .or_insert_with(|| {
                Arc::new(PendingValidation {
                    result: watch::channel(None).0,
                    started: current_time_ms(),
                })
            })
            .clone();
        drop(manager);
        let mut receiver = pending.result.subscribe();
        let remaining = 30_000u64.saturating_sub(current_time_ms().saturating_sub(pending.started));
        let outcome = wait_with_timeout(
            async {
                loop {
                    if let Some(result) = receiver.borrow().clone() {
                        return result;
                    }
                    if receiver.changed().await.is_err() {
                        return Err(Error::AuthError("Certificate validation cancelled".into()));
                    }
                }
            },
            remaining,
        )
        .await
        .unwrap_or_else(|_| {
            Err(Error::AuthError(format!(
                "Timeout waiting for certificate validation from peer {identity}"
            )))
        });
        let mut waits = self.pending_certificate_validation.write().await;
        if waits
            .get(nonce)
            .is_some_and(|entry| Arc::ptr_eq(entry, &pending))
        {
            pending.result.send_replace(Some(outcome.clone()));
            waits.remove(nonce);
        }
        outcome
    }

    pub(super) async fn resolve_certificate_validation(&self, nonce: &str) {
        if let Some(pending) = self
            .pending_certificate_validation
            .write()
            .await
            .remove(nonce)
        {
            pending.result.send_replace(Some(Ok(())));
        }
    }
}
