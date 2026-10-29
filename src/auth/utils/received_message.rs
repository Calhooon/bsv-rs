//! The rest of the reference's message intake that this crate applies
//! before any handler (#445): `assertValidAuthMessageShape`'s certificate
//! bound and every required nonce's text and length (`ts-stack@edf6e03`
//! `packages/sdk/src/auth/AuthMessageValidation.ts:330-404`, called through
//! `snapshotAuthMessage` at `Peer.ts:767`).

use super::requested_set::assert_canonical_base64;
use crate::auth::types::{AuthMessage, MessageType};
use crate::{Error, Result};

/// Certificates per message, the reference's `MAX_CERTIFICATES`
/// (`AuthMessageValidation.ts:11`, `validateCertificates.ts:9`).
pub(crate) const MAX_CERTIFICATES: usize = 100;

/// Refuses a received message carrying more than 100 certificates
/// (`AuthMessageValidation.ts:348-352`), then missing, noncanonical or
/// wrong-length nonces (`:355-389`), in the reference's order and words.
/// Session nonces must encode 48 bytes; later message nonces 32 bytes.
/// This deliberately closes the Peer's legacy 32-byte session-nonce
/// acceptance window introduced in 0.3.6.
pub(crate) fn check_received_message(message: &AuthMessage) -> Result<()> {
    if message
        .certificates
        .as_ref()
        .is_some_and(|certificates| certificates.len() > MAX_CERTIFICATES)
    {
        return Err(Error::AuthError(
            "Authentication certificates exceed their limit.".into(),
        ));
    }
    let nonces: &[(&Option<String>, &str, usize)] = match message.message_type {
        MessageType::InitialRequest => {
            &[(&message.initial_nonce, "initialRequest.initialNonce", 48)]
        }
        MessageType::InitialResponse => &[
            (&message.initial_nonce, "initialResponse.initialNonce", 48),
            (&message.your_nonce, "initialResponse.yourNonce", 48),
        ],
        MessageType::CertificateRequest => &[
            (&message.nonce, "certificateRequest.nonce", 32),
            (
                &message.initial_nonce,
                "certificateRequest.initialNonce",
                48,
            ),
            (&message.your_nonce, "certificateRequest.yourNonce", 48),
        ],
        MessageType::CertificateResponse => &[
            (&message.nonce, "certificateResponse.nonce", 32),
            (
                &message.initial_nonce,
                "certificateResponse.initialNonce",
                48,
            ),
            (&message.your_nonce, "certificateResponse.yourNonce", 48),
        ],
        MessageType::General => &[
            (&message.nonce, "general.nonce", 32),
            (&message.your_nonce, "general.yourNonce", 48),
        ],
    };
    for (nonce, name, bytes) in nonces {
        let nonce = nonce
            .as_deref()
            .ok_or_else(|| Error::AuthError(format!("{name} must be canonical base64.")))?;
        assert_canonical_base64(nonce, name, *bytes)?;
    }
    if message.message_type == MessageType::CertificateRequest
        && message.requested_certificates.is_none()
    {
        return Err(Error::AuthError(
            "requestedCertificates must be an object.".into(),
        ));
    }
    Ok(())
}
