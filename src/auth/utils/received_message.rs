//! The rest of the reference's message intake that this crate applies
//! before any handler (#445): `assertValidAuthMessageShape`'s certificate
//! bound and the handshake nonces' text (`ts-stack@edf6e03`
//! `packages/sdk/src/auth/AuthMessageValidation.ts:330-404`, called through
//! `snapshotAuthMessage` at `Peer.ts:767`).

use super::requested_set::canonical_base64;
use crate::auth::types::{AuthMessage, MessageType};
use crate::{Error, Result};

/// Certificates per message, the reference's `MAX_CERTIFICATES`
/// (`AuthMessageValidation.ts:11`, `validateCertificates.ts:9`).
pub(crate) const MAX_CERTIFICATES: usize = 100;

/// Refuses a received message carrying more than 100 certificates
/// (`AuthMessageValidation.ts:348-352`), then a handshake nonce that is not
/// canonical base64 (`:355-361`), in the reference's words, before any
/// handler: so neither certificate path verifies a certificate of such a
/// message, and no handshake signs or verifies over a nonce the reference
/// cannot decode.
///
/// Two of the intake's rules are not applied, stated in the #445 entry: a
/// nonce's length (`must encode exactly 48 bytes`; the 32-byte legacy nonce
/// is still accepted, 0.3.6) and the nonces of the other three types.
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
    let nonces: &[(&Option<String>, &str)] = match message.message_type {
        MessageType::InitialRequest => &[(&message.initial_nonce, "initialRequest.initialNonce")],
        MessageType::InitialResponse => &[
            (&message.initial_nonce, "initialResponse.initialNonce"),
            (&message.your_nonce, "initialResponse.yourNonce"),
        ],
        _ => &[],
    };
    for (nonce, name) in nonces {
        if let Some(nonce) = nonce {
            canonical_base64(nonce, name)?;
        }
    }
    Ok(())
}
