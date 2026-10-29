//! Initial certificate exchange, in the order of Peer.ts:800-1035 (edf6e03).

use super::{
    create_nonce, get_verifiable_certificates, AuthMessage, Counterparty, CreateSignatureArgs,
    Error, MessageType, Peer, PeerSession, Protocol, Result, SecurityLevel, Transport,
    VerifiableCertificate, WalletInterface, AUTH_PROTOCOL_ID,
};

impl<W: WalletInterface + 'static, T: Transport + 'static> Peer<W, T> {
    pub(super) async fn process_initial_request(&self, message: AuthMessage) -> Result<()> {
        let initial_nonce = message
            .initial_nonce
            .as_deref()
            .filter(|n| !n.is_empty())
            .ok_or_else(|| {
                Error::AuthError("Missing required fields in initialRequest message.".into())
            })?;
        if !self
            .session_manager
            .write()
            .await
            .claim_initial_request_nonce(&message.identity_key.to_hex(), initial_nonce)?
        {
            return Err(Error::AuthError("Replayed initialRequest nonce.".into()));
        }
        let session_nonce = create_nonce(&*self.wallet, None, self.originator.as_deref()).await?;
        let mut session = PeerSession::with_nonce(session_nonce.clone());
        session.peer_identity_key = Some(message.identity_key.clone());
        session.peer_nonce = message.initial_nonce.clone();
        session.is_authenticated = true;
        self.set_certificate_requirement(&mut session);
        session.touch();
        self.session_manager
            .write()
            .await
            .add_session(session.clone())?;

        let response = self.create_initial_response(&message, &session).await?;
        self.transport()?.send(&response).await
    }

    /// Select proofs, sign the nonces, then obtain our identity and build the response.
    /// The fields and wallet call order are Peer.ts:830-874.
    async fn create_initial_response(
        &self,
        message: &AuthMessage,
        session: &PeerSession,
    ) -> Result<AuthMessage> {
        let certificates = self.initial_response_certificates(message).await?;
        let their_nonce = message.initial_nonce.as_deref().unwrap_or_default();
        let our_nonce = session.session_nonce.as_deref().unwrap_or_default();
        // Both canonical: theirs refused at intake otherwise (#445), ours created here.
        let data = [their_nonce, our_nonce]
            .into_iter()
            .map(crate::primitives::from_base64)
            .collect::<Result<Vec<_>>>()?
            .concat();
        let signed = self
            .wallet
            .create_signature(
                CreateSignatureArgs {
                    data: Some(data),
                    protocol_id: Protocol::new(SecurityLevel::Counterparty, AUTH_PROTOCOL_ID),
                    key_id: format!("{their_nonce} {our_nonce}"),
                    counterparty: Some(Counterparty::Other(message.identity_key.clone())),
                    ..Default::default()
                },
                self.originator.as_deref(),
            )
            .await?;
        let mut response =
            AuthMessage::new(MessageType::InitialResponse, self.get_identity_key().await?);
        response.initial_nonce.clone_from(&session.session_nonce);
        response.your_nonce.clone_from(&message.initial_nonce);
        if let Some(certificates) = certificates {
            response.set_certificates(certificates);
        }
        response
            .set_requested_certificates(self.certificates_to_request.clone().unwrap_or_default());
        response.signature = Some(signed.signature);
        Ok(response)
    }

    /// A request listener owns selection; otherwise query and prove before responding.
    /// Peer.ts:832-851,1000-1021. Wallet and observer errors retain their words.
    async fn initial_response_certificates(
        &self,
        message: &AuthMessage,
    ) -> Result<Option<Vec<VerifiableCertificate>>> {
        let Some(requested) = message
            .requested_certificates
            .as_ref()
            .filter(|r| !r.certifiers.is_empty())
        else {
            return Ok(None);
        };
        let callbacks = self.certificate_request_callbacks.read().await;
        if !callbacks.is_empty() {
            for callback in callbacks.values() {
                callback(message.identity_key.clone(), requested.clone()).await?;
            }
            return Ok(None);
        }
        drop(callbacks);
        get_verifiable_certificates(
            &*self.wallet,
            requested,
            &message.identity_key,
            self.originator.as_deref(),
        )
        .await
        .map(Some)
    }

    pub(super) fn set_certificate_requirement(&self, session: &mut PeerSession) {
        session.certificates_required = self
            .certificates_to_request
            .as_ref()
            .is_some_and(|req| !req.certifiers.is_empty());
        session.certificates_validated = !session.certificates_required;
    }

    /// Authenticate, validate, release handshake waiters, then answer (Peer.ts:1029-1035).
    pub(super) async fn process_initial_response(&self, message: AuthMessage) -> Result<()> {
        let our_nonce = message.your_nonce.clone().unwrap_or_default();
        let result = async {
            let mut session = self
                .authenticate_initial_response(&message, &our_nonce)
                .await?;
            self.validate_initial_response_certificates(&message, &mut session)
                .await?;
            Ok(session)
        }
        .await;
        if let Some(tx) = self.pending_handshakes.write().await.remove(&our_nonce) {
            let _ = tx.send(result.clone());
        }
        result?;
        if let Some(certificates) = self
            .initial_response_certificates(&message)
            .await?
            .filter(|certificates| !certificates.is_empty())
        {
            self.send_certificate_response(&message.identity_key.to_hex(), certificates)
                .await?;
        }
        Ok(())
    }

    /// Only nonempty certificates under our own policy authorize this exact session.
    /// Commit readiness and release validation waiters before observers (Peer.ts:957-990).
    async fn validate_initial_response_certificates(
        &self,
        message: &AuthMessage,
        session: &mut PeerSession,
    ) -> Result<()> {
        let Some(certificates) = message
            .certificates
            .as_ref()
            .filter(|certificates| session.certificates_required && !certificates.is_empty())
        else {
            return Ok(());
        };
        let policy = self.certificates_to_request.clone().unwrap_or_default();
        self.validate_received_certificates(message, Some(&policy))
            .await?;
        let nonce = session
            .session_nonce
            .as_deref()
            .unwrap_or_default()
            .to_owned();
        let mut manager = self.session_manager.write().await;
        let current = manager
            .get_session_mut(&nonce)
            .ok_or_else(|| Error::AuthError(format!("Session not found for nonce: {nonce}")))?;
        current.certificates_validated = true;
        current.touch();
        *session = current.clone();
        self.resolve_certificate_validation(&nonce).await;
        drop(manager);
        let callbacks = self.certificate_callbacks.read().await;
        for callback in callbacks.values() {
            callback(message.identity_key.clone(), certificates.clone()).await?;
        }
        Ok(())
    }
}
