//! One validator for both certificate paths, the reference's
//! `validateCertificates` (`ts-stack@edf6e03`
//! `packages/sdk/src/auth/utils/validateCertificates.ts:64-137`), which
//! `Peer.ts:970` (an initial response) and `:1242` (a certificate response)
//! both call (#445).

use super::{
    AuthMessage, Error, Peer, RequestedCertificateSet, Result, Transport, VerifiableCertificate,
    WalletInterface, MAX_CERTIFICATES,
};
use crate::auth::utils::certificate_continuation;
use futures::{stream::FuturesUnordered, TryStreamExt};

impl<W: WalletInterface + 'static, T: Transport + 'static> Peer<W, T> {
    /// The message's certificates, at most 100, judged concurrently, each in order:
    /// subject, signature, then under a policy its certifier, type, decryption
    /// and disclosed fields (`validateCertificates.ts:73-134`).
    pub(super) async fn validate_received_certificates(
        &self,
        message: &AuthMessage,
        policy: Option<&RequestedCertificateSet>,
    ) -> Result<()> {
        let certificates = match message.certificates.as_deref() {
            Some(certificates) if !certificates.is_empty() => certificates,
            _ => {
                return Err(Error::AuthError(
                    "No certificates were provided in the AuthMessage.".into(),
                ))
            }
        };
        if certificates.len() > MAX_CERTIFICATES {
            return Err(Error::AuthError(format!(
                "AuthMessage cannot contain more than {MAX_CERTIFICATES} certificates."
            )));
        }
        certificates
            .iter()
            .map(|certificate| self.validate_received_certificate(certificate, message, policy))
            .collect::<FuturesUnordered<_>>()
            .try_collect::<Vec<_>>()
            .await
            .map(|_| ())
    }

    async fn validate_received_certificate(
        &self,
        certificate: &VerifiableCertificate,
        message: &AuthMessage,
        policy: Option<&RequestedCertificateSet>,
    ) -> Result<()> {
        let cert = &certificate.certificate;
        if cert.subject != message.identity_key {
            return Err(Error::AuthError(format!(
                "The subject of one of your certificates (\"{}\") is not the same as the request sender (\"{}\").",
                cert.subject.to_hex(), message.identity_key.to_hex()
            )));
        }
        let serial = cert.serial_number_base64();
        let verified = certificate.verify();
        // JS verify() computes synchronously but returns a Promise. Its
        // mandatory await lets every subject check run before this result.
        certificate_continuation().await;
        if !verified? {
            return Err(Error::AuthError(format!(
                "The signature for the certificate with serial number {serial} is invalid!"
            )));
        }
        let requested = policy
            .map(|policy| requested_fields(certificate, policy, &serial))
            .transpose()?;
        let disclosed = certificate
            .clone()
            .decrypt_fields(&*self.wallet, None, None, self.originator.as_deref())
            .await;
        // Even a synchronous decryptFields rejection resumes after the
        // other certificates' signature and policy checks (Promise.all).
        certificate_continuation().await;
        let disclosed = disclosed?;
        if requested.is_some_and(|requested| {
            disclosed.is_empty() || disclosed.keys().any(|field| !requested.contains(field))
        }) {
            return Err(Error::AuthError(format!(
                "Certificate {serial} did not reveal a non-empty requested field set"
            )));
        }
        Ok(())
    }
}

/// The certifier, then the type (`validateCertificates.ts:108-123`).
fn requested_fields<'a>(
    certificate: &VerifiableCertificate,
    policy: &'a RequestedCertificateSet,
    serial: &str,
) -> Result<&'a Vec<String>> {
    let certifier = certificate.certificate.certifier.to_hex();
    if !policy.certifiers.contains(&certifier) {
        return Err(Error::AuthError(format!(
            "Certificate with serial number {serial} has an unrequested certifier: {certifier}"
        )));
    }
    let cert_type = certificate.certificate.type_base64();
    policy.types.get(&cert_type).ok_or_else(|| {
        Error::AuthError(format!(
            "Certificate with type {cert_type} was not requested"
        ))
    })
}

/// A certificate response must match the policy before it is validated
/// (`Peer.ts:1229-1241`, `#matchesCertificatePolicy` at `:359-389`): every
/// certificate's certifier and type requested, its keyring a nonempty set of
/// requested fields. The reference also matches a pending dynamic request;
/// this crate keeps none, so only the handshake policy is matched.
pub(super) fn require_requested_certificates(
    certificates: &[VerifiableCertificate],
    policy: &RequestedCertificateSet,
) -> Result<()> {
    let matches = certificates.iter().all(|certificate| {
        let cert = &certificate.certificate;
        let Some(fields) = policy.types.get(&cert.type_base64()) else {
            return false;
        };
        policy.certifiers.contains(&cert.certifier.to_hex())
            && !certificate.keyring.is_empty()
            && certificate.keyring.len() <= fields.len()
            && certificate
                .keyring
                .keys()
                .all(|field| fields.contains(field))
    });
    if matches {
        return Ok(());
    }
    Err(Error::AuthError(
        "Certificates do not match a locally requested set for this session.".into(),
    ))
}
