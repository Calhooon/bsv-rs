//! `get_verifiable_certificates`, the reference's `getVerifiableCertificates`
//! (`ts-stack@edf6e03` `packages/sdk/src/auth/utils/getVerifiableCertificates.ts:46-108`).

use crate::auth::certificates::{Certificate, VerifiableCertificate};
use crate::auth::types::RequestedCertificateSet;
use crate::primitives::PublicKey;
use crate::wallet::{
    validate_result_public_key as result_key, ListCertificatesArgs, ProveCertificateArgs,
    WalletCertificate, WalletInterface,
};
use crate::{Error, Result};

/// The reference's refusal of a listed certificate whose certifier or type is
/// outside the requested set (`getVerifiableCertificates.ts:76-81`).
pub(crate) const OUTSIDE_REQUESTED_SET: &str =
    "Wallet returned a certificate outside the requested certifier/type set";

/// Retrieves verifiable certificates matching a request.
///
/// Queries the wallet for certificates matching the requested certifiers
/// and types, then creates verifiable certificates with keyrings for
/// the specified verifier.
///
/// # Arguments
/// * `wallet` - Wallet to query for certificates
/// * `requested` - Certificate requirements
/// * `verifier_identity_key` - Verifier's public key (for keyring creation)
/// * `originator` - Application originator
///
/// # Errors
/// The wallet's errors, and `Error::AuthError` in the reference's words when
/// the wallet lists a certificate whose certifier text is none of the
/// requested set's or whose type the set does not request
/// (`getVerifiableCertificates.ts:76-81`, before proveCertificate; #587).
pub async fn get_verifiable_certificates<W: WalletInterface>(
    wallet: &W,
    requested: &RequestedCertificateSet,
    verifier_identity_key: &PublicKey,
    originator: Option<&str>,
) -> Result<Vec<VerifiableCertificate>> {
    let args = ListCertificatesArgs {
        certifiers: requested.certifiers.clone(),
        types: requested.types.keys().cloned().collect(),
        limit: None,
        offset: None,
        privileged: None,
        privileged_reason: None,
    };
    let list_result = wallet.list_certificates(args, originator).await?;

    let mut verifiable_certs = Vec::new();
    for (index, cert_result) in list_result.certificates.into_iter().enumerate() {
        let certificate = cert_result.certificate;
        // Subject: the result validator's `publicKey` (WalletResultValidation.ts:1489-1493,928-933), before proveCertificate as the reference's client judges it (#582)
        let field = format!("certificates[{index}].subject");
        let subject = result_key(&certificate.subject, "listCertificates", &field);
        let Ok(subject) = subject else { continue };
        // Certifier and type: the requested set's texts, before proveCertificate, the whole call refused (getVerifiableCertificates.ts:76-81; #587)
        let in_set = requested.certifiers.contains(&certificate.certifier);
        let Some(fields_to_reveal) = requested.types.get(&certificate.certificate_type) else {
            return Err(Error::AuthError(OUTSIDE_REQUESTED_SET.into()));
        };
        if !in_set {
            return Err(Error::AuthError(OUTSIDE_REQUESTED_SET.into()));
        }
        // The set's certifiers canonical (AuthMessageValidation.ts:124); a caller's non-canonical set skips here where the reference proves it (#582, a stated residue)
        let certifier = super::assert_auth_identity_key(&certificate.certifier);
        let Ok(certifier) = certifier else { continue };

        let prove_args = ProveCertificateArgs {
            certificate: certificate.clone(),
            fields_to_reveal: fields_to_reveal.clone(),
            verifier: verifier_identity_key.to_hex(),
            privileged: None,
            privileged_reason: None,
        };
        let prove_result = wallet.prove_certificate(prove_args, originator).await?;

        let Some(base_cert) = base_certificate(&certificate, subject, certifier)? else {
            continue; // Skip malformed certificates
        };
        // The keyring held as its base64 text, decoded only where the
        // verifier's wallet decrypts (#268), as the reference holds the
        // wallet's `keyringForVerifier` strings (`ts-stack@edf6e03`
        // `getVerifiableCertificates.ts:92-104`); an entry that did not
        // decode was dropped here before.
        let verifiable = VerifiableCertificate::new(base_cert, prove_result.keyring_for_verifier);
        verifiable_certs.push(verifiable);
    }

    Ok(verifiable_certs)
}

/// The wallet's certificate as a `Certificate`, `None` when its type or
/// serial number is not 32 bytes.
fn base_certificate(
    certificate: &WalletCertificate,
    subject: PublicKey,
    certifier: PublicKey,
) -> Result<Option<Certificate>> {
    let cert_type = crate::primitives::from_base64(&certificate.certificate_type)?;
    let serial_number = crate::primitives::from_base64(&certificate.serial_number)?;
    let (Ok(type_arr), Ok(serial_arr)) = (
        <[u8; 32]>::try_from(cert_type.as_slice()),
        <[u8; 32]>::try_from(serial_number.as_slice()),
    ) else {
        return Ok(None);
    };

    // Parse revocation outpoint
    let revocation_outpoint = if certificate.revocation_outpoint.is_empty() {
        None
    } else {
        crate::auth::certificates::revocation_outpoint_from_str(&certificate.revocation_outpoint)
            .ok()
    };

    // Parse signature
    let signature = if certificate.signature.is_empty() {
        None
    } else {
        crate::primitives::from_hex(&certificate.signature).ok()
    };

    Ok(Some(
        Certificate::new(type_arr, serial_arr, subject, certifier)
            .with_revocation_outpoint(revocation_outpoint)
            // Each value is its base64 text, never decoded: BRC-52 signs
            // that text (`0052.md:97`; #261).
            .with_fields(certificate.fields.clone())
            .with_signature(signature),
    ))
}
