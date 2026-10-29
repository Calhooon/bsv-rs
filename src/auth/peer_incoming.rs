//! Incoming Peer messages: nonce claims, certificate authorization and callbacks.

use super::{
    validate_certificates, verify_nonce, AuthMessage, Error, MessageType, Peer, PeerSession,
    Result, Transport, WalletInterface,
};

impl<W: WalletInterface + 'static, T: Transport + 'static> Peer<W, T> {
    /// Authenticate, then claim initialNonce before changing the session (Peer.ts:886-956).
    pub(super) async fn authenticate_initial_response(
        &self,
        message: &AuthMessage,
        our_nonce: &str,
    ) -> Result<PeerSession> {
        let sender = message.identity_key.to_hex();
        if !self.verify_own_nonce(our_nonce).await {
            return Err(Error::AuthError(format!(
                "Initial response nonce verification failed from peer: {sender}"
            )));
        }
        let mut session = self
            .session_manager
            .read()
            .await
            .get_session(our_nonce)
            .cloned()
            .ok_or_else(|| {
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
            .as_deref()
            .filter(|n| !n.is_empty())
            .ok_or_else(|| {
                Error::AuthError("Initial response message nonce is required.".into())
            })?;
        self.claim_message_nonce(our_nonce, peer_nonce, MessageType::InitialResponse)
            .await?;
        session.peer_identity_key = Some(message.identity_key.clone());
        session.peer_nonce = Some(peer_nonce.to_owned());
        session.is_authenticated = true;
        self.set_certificate_requirement(&mut session);
        session.touch();
        self.session_manager
            .write()
            .await
            .update_session(session.clone());
        Ok(session)
    }

    pub(super) async fn verify_own_nonce(&self, nonce: &str) -> bool {
        verify_nonce(nonce, &*self.wallet, None, self.originator.as_deref())
            .await
            .unwrap_or(false)
    }

    async fn claim_message_nonce(
        &self,
        session: &str,
        nonce: &str,
        kind: MessageType,
    ) -> Result<()> {
        if !self
            .session_manager
            .write()
            .await
            .claim_message_nonce(session, nonce)?
        {
            return Err(Error::AuthError(format!("Replayed {kind} message nonce.")));
        }
        Ok(())
    }

    /// Nonce, exact session, identity, signature, message nonce, claim, authentication.
    /// The order and words are Peer.ts:1044-1090,1177-1225,1270-1315.
    async fn authenticate_message(&self, message: &AuthMessage) -> Result<PeerSession> {
        let sender = message.identity_key.to_hex();
        let kind = message.message_type;
        let context = match kind {
            MessageType::CertificateRequest => "certificate request message",
            MessageType::CertificateResponse => "certificate response",
            _ => "general message",
        };
        let your_nonce = message.your_nonce.as_deref().unwrap_or_default();
        if !self.verify_own_nonce(your_nonce).await {
            return Err(Error::AuthError(format!(
                "Unable to verify nonce for {context} from: {sender}"
            )));
        }
        let session = self
            .session_manager
            .read()
            .await
            .get_session(your_nonce)
            .cloned()
            .ok_or_else(|| {
                Error::AuthError(format!("Session not found for nonce: {your_nonce}"))
            })?;
        Self::require_matching_identity(&session, message)?;
        self.require_message_signature(message, &session).await?;
        let nonce = message
            .nonce
            .as_deref()
            .filter(|n| !n.is_empty())
            .ok_or_else(|| {
                let label = match kind {
                    MessageType::CertificateRequest => "Certificate request",
                    MessageType::CertificateResponse => "Certificate response",
                    _ => "General",
                };
                Error::AuthError(format!("{label} message nonce is required."))
            })?;
        let session_nonce = session.session_nonce.as_deref().ok_or_else(|| {
            Error::AuthError("Session nonce is required for general messages".into())
        })?;
        self.claim_message_nonce(session_nonce, nonce, kind).await?;
        if let Some(current) = self
            .session_manager
            .write()
            .await
            .get_session_mut(session_nonce)
        {
            current.is_authenticated = true;
            current.touch();
        }
        Ok(session)
    }

    async fn require_message_signature(
        &self,
        message: &AuthMessage,
        session: &PeerSession,
    ) -> Result<()> {
        if self.verify_message_signature(message, session).await? {
            return Ok(());
        }
        let sender = message.identity_key.to_hex();
        let words = match message.message_type {
            MessageType::CertificateRequest => {
                format!("Invalid signature in certificate request message from {sender}")
            }
            MessageType::CertificateResponse => {
                format!("Unable to verify certificate response signature for peer: {sender}")
            }
            _ => format!("Invalid signature in generalMessage from {sender}"),
        };
        Err(Error::AuthError(words))
    }

    fn require_matching_identity(session: &PeerSession, message: &AuthMessage) -> Result<()> {
        let kind = message.message_type;
        match &session.peer_identity_key {
            None => Err(Error::AuthError(format!(
                "Peer identity is not established for {kind} message."
            ))),
            Some(key) if *key != message.identity_key => Err(Error::AuthError(format!(
                "{kind} identity does not match the authenticated session."
            ))),
            Some(_) => Ok(()),
        }
    }

    pub(super) async fn process_certificate_request(&self, message: AuthMessage) -> Result<()> {
        self.authenticate_message(&message).await?;
        if let Some(requested) = message
            .requested_certificates
            .as_ref()
            .filter(|r| !r.certifiers.is_empty())
        {
            let cbs = self.certificate_request_callbacks.read().await;
            for callback in cbs.values() {
                callback(message.identity_key.clone(), requested.clone()).await?;
            }
        }
        Ok(())
    }

    pub(super) async fn process_certificate_response(&self, message: AuthMessage) -> Result<()> {
        let session = self.authenticate_message(&message).await?;
        if let Some(certs) = message.certificates.as_ref().filter(|c| !c.is_empty()) {
            validate_certificates(
                &*self.wallet,
                &message,
                self.certificates_to_request.as_ref(),
                self.originator.as_deref(),
            )
            .await?;
            let nonce = session.session_nonce.as_deref().unwrap_or_default();
            let mut manager = self.session_manager.write().await;
            if let Some(current) = manager.get_session_mut(nonce) {
                current.certificates_validated = true;
                current.touch();
                self.resolve_certificate_validation(nonce).await;
            }
            drop(manager);
            let cbs = self.certificate_callbacks.read().await;
            for callback in cbs.values() {
                callback(message.identity_key.clone(), certs.clone()).await?;
            }
        } else {
            let cbs = self.certificate_callbacks.read().await;
            for callback in cbs.values() {
                callback(message.identity_key.clone(), Vec::new()).await?;
            }
        }
        Ok(())
    }

    pub(super) async fn process_general_message(&self, message: AuthMessage) -> Result<()> {
        let session = self.authenticate_message(&message).await?;
        self.wait_for_certificate_validation(session.session_nonce.as_deref().unwrap_or_default())
            .await?;
        let payload = message.payload.unwrap_or_default();
        let cbs = self.general_message_callbacks.read().await;
        for callback in cbs.values() {
            callback(message.identity_key.clone(), payload.clone()).await?;
        }
        Ok(())
    }
}
