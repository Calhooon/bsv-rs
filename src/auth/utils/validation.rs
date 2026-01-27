//! Certificate validation utilities.
//!
//! This module provides utilities for validating certificates in
//! authentication messages.

use crate::auth::certificates::VerifiableCertificate;
use crate::auth::types::{AuthMessage, RequestedCertificateSet};
use crate::primitives::PublicKey;
use crate::wallet::WalletInterface;
use crate::{Error, Result};

/// Validates certificates in an authentication message.
///
/// Performs the following checks for each certificate:
/// 1. Certificate subject matches message sender
/// 2. Certificate signature is valid
/// 3. Certifiers are in the trusted set (if specified)
/// 4. Certificate types match requested types (if specified)
/// 5. Attempts to decrypt fields with verifier's wallet
///
/// # Arguments
/// * `verifier_wallet` - Wallet for field decryption
/// * `message` - The authentication message containing certificates
/// * `certificates_requested` - Optional certificate requirements
/// * `originator` - Application originator
///
/// # Errors
/// Returns an error if any certificate fails validation.
pub async fn validate_certificates<W: WalletInterface>(
    verifier_wallet: &W,
    message: &AuthMessage,
    certificates_requested: Option<&RequestedCertificateSet>,
    originator: &str,
) -> Result<()> {
    let certs = match &message.certificates {
        Some(c) if !c.is_empty() => c,
        _ => {
            // If certificates were requested but none provided
            if let Some(req) = certificates_requested {
                if !req.is_empty() {
                    return Err(Error::AuthError(
                        "Required certificates not provided".into(),
                    ));
                }
            }
            return Ok(());
        }
    };

    let sender_key = &message.identity_key;

    for cert in certs {
        validate_certificate(
            verifier_wallet,
            cert,
            sender_key,
            certificates_requested,
            originator,
        )
        .await?;
    }

    Ok(())
}

/// Validates a single certificate.
///
/// # Arguments
/// * `verifier_wallet` - Wallet for field decryption
/// * `cert` - The certificate to validate
/// * `sender_key` - Expected subject public key
/// * `certificates_requested` - Optional certificate requirements
/// * `originator` - Application originator
pub async fn validate_certificate<W: WalletInterface>(
    verifier_wallet: &W,
    cert: &VerifiableCertificate,
    sender_key: &PublicKey,
    certificates_requested: Option<&RequestedCertificateSet>,
    originator: &str,
) -> Result<()> {
    // 1. Verify subject matches sender
    if &cert.certificate.subject != sender_key {
        return Err(Error::AuthError(
            "Certificate subject does not match message sender".into(),
        ));
    }

    // 2. Verify certificate signature
    if !cert.verify()? {
        return Err(Error::AuthError("Certificate signature invalid".into()));
    }

    // 3. If we have requirements, check them
    if let Some(req) = certificates_requested {
        // Check certifier is trusted
        let certifier_hex = cert.certificate.certifier.to_hex();
        if !req.certifiers.is_empty() && !req.certifiers.contains(&certifier_hex) {
            return Err(Error::AuthError(format!(
                "Certificate from untrusted certifier: {}",
                certifier_hex
            )));
        }

        // Check type matches
        let type_b64 = cert.certificate.type_base64();
        if !req.types.is_empty() && !req.types.contains_key(&type_b64) {
            return Err(Error::AuthError(format!(
                "Certificate type not in requested set: {}",
                type_b64
            )));
        }

        // 4. Try to decrypt required fields if keyring available
        if let Some(required_fields) = req.types.get(&type_b64) {
            if !required_fields.is_empty() && cert.has_keyring() {
                // Verify all required fields have keys in keyring
                for field_name in required_fields {
                    if !cert.keyring.contains_key(field_name) {
                        return Err(Error::AuthError(format!(
                            "Required field '{}' not revealed in certificate",
                            field_name
                        )));
                    }
                }

                // Attempt to decrypt fields to verify keyring is valid
                let mut cert_clone = cert.clone();
                cert_clone
                    .decrypt_fields(verifier_wallet, &cert.certificate.subject, originator)
                    .await?;
            }
        }
    }

    Ok(())
}

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
pub async fn get_verifiable_certificates<W: WalletInterface>(
    wallet: &W,
    requested: &RequestedCertificateSet,
    verifier_identity_key: &PublicKey,
    originator: &str,
) -> Result<Vec<VerifiableCertificate>> {
    use crate::wallet::{ListCertificatesArgs, ProveCertificateArgs};

    // Build certifiers list for query
    let certifiers: Vec<String> = requested.certifiers.clone();

    // Build types list for query
    let types: Vec<String> = requested.types.keys().cloned().collect();

    // Query wallet for matching certificates
    let list_result = wallet
        .list_certificates(
            ListCertificatesArgs {
                certifiers,
                types,
                limit: None,
                offset: None,
                privileged: None,
                privileged_reason: None,
            },
            originator,
        )
        .await?;

    let mut verifiable_certs = Vec::new();

    for cert_result in list_result.certificates {
        // Get fields to reveal for this certificate type
        let fields_to_reveal = requested
            .types
            .get(&cert_result.certificate.certificate_type)
            .cloned()
            .unwrap_or_default();

        // Create verifiable certificate with keyring
        let prove_result = wallet
            .prove_certificate(
                ProveCertificateArgs {
                    certificate: cert_result.certificate.clone(),
                    fields_to_reveal,
                    verifier: verifier_identity_key.to_hex(),
                    privileged: None,
                    privileged_reason: None,
                },
                originator,
            )
            .await?;

        // Convert to VerifiableCertificate
        let cert_type = crate::primitives::from_base64(&cert_result.certificate.certificate_type)?;
        let serial_number = crate::primitives::from_base64(&cert_result.certificate.serial_number)?;

        if cert_type.len() != 32 || serial_number.len() != 32 {
            continue; // Skip malformed certificates
        }

        let mut type_arr = [0u8; 32];
        let mut serial_arr = [0u8; 32];
        type_arr.copy_from_slice(&cert_type);
        serial_arr.copy_from_slice(&serial_number);

        // Parse subject and certifier from hex strings
        let subject = match PublicKey::from_hex(&cert_result.certificate.subject) {
            Ok(pk) => pk,
            Err(_) => continue, // Skip if invalid
        };
        let certifier = match PublicKey::from_hex(&cert_result.certificate.certifier) {
            Ok(pk) => pk,
            Err(_) => continue, // Skip if invalid
        };

        // Parse revocation outpoint
        let revocation_outpoint = if cert_result.certificate.revocation_outpoint.is_empty() {
            None
        } else {
            crate::wallet::types::Outpoint::from_string(
                &cert_result.certificate.revocation_outpoint,
            )
            .ok()
        };

        // Parse signature
        let signature = if cert_result.certificate.signature.is_empty() {
            None
        } else {
            crate::primitives::from_hex(&cert_result.certificate.signature).ok()
        };

        let base_cert = crate::auth::certificates::Certificate {
            cert_type: type_arr,
            serial_number: serial_arr,
            subject,
            certifier,
            revocation_outpoint,
            fields: cert_result
                .certificate
                .fields
                .iter()
                .filter_map(|(k, v)| {
                    crate::primitives::from_base64(v)
                        .ok()
                        .map(|decoded| (k.clone(), decoded))
                })
                .collect(),
            signature,
        };

        // Convert keyring
        let keyring: std::collections::HashMap<String, Vec<u8>> = prove_result
            .keyring_for_verifier
            .iter()
            .filter_map(|(k, v)| {
                crate::primitives::from_base64(v)
                    .ok()
                    .map(|decoded| (k.clone(), decoded))
            })
            .collect();

        let verifiable = VerifiableCertificate::new(base_cert, keyring);
        verifiable_certs.push(verifiable);
    }

    Ok(verifiable_certs)
}

/// Checks if certificates match the requested requirements.
///
/// Does not perform cryptographic verification, just checks types
/// and certifiers against requirements.
pub fn certificates_match_request(
    certs: &[VerifiableCertificate],
    requested: &RequestedCertificateSet,
) -> bool {
    if requested.is_empty() {
        return true;
    }

    // Check each requested type is satisfied
    for (type_id, required_fields) in &requested.types {
        let matching_cert = certs.iter().find(|c| {
            let cert_type_b64 = c.certificate.type_base64();
            cert_type_b64 == *type_id
        });

        let Some(cert) = matching_cert else {
            return false;
        };

        // Check certifier is trusted
        if !requested.certifiers.is_empty() {
            let certifier_hex = cert.certificate.certifier.to_hex();
            if !requested.certifiers.contains(&certifier_hex) {
                return false;
            }
        }

        // Check required fields are in keyring
        for field in required_fields {
            if !cert.keyring.contains_key(field) {
                return false;
            }
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::certificates::Certificate;
    use crate::primitives::PrivateKey;
    use std::collections::HashMap;

    fn make_test_cert(certifier_key: &PrivateKey, subject: &PublicKey) -> VerifiableCertificate {
        let mut cert = Certificate::new(
            [1u8; 32],
            [2u8; 32],
            subject.clone(),
            certifier_key.public_key(),
        );
        cert.sign(certifier_key).unwrap();
        VerifiableCertificate::from_certificate(cert)
    }

    #[test]
    fn test_certificates_match_empty_request() {
        let certifier = PrivateKey::random();
        let subject = PrivateKey::random().public_key();

        let cert = make_test_cert(&certifier, &subject);
        let requested = RequestedCertificateSet::new();

        assert!(certificates_match_request(&[cert], &requested));
    }

    #[test]
    fn test_certificates_match_certifier() {
        let certifier = PrivateKey::random();
        let subject = PrivateKey::random().public_key();

        let cert = make_test_cert(&certifier, &subject);

        let mut requested = RequestedCertificateSet::new();
        requested.add_certifier(certifier.public_key().to_hex());
        requested.add_type(cert.certificate.type_base64(), vec![]);

        assert!(certificates_match_request(&[cert], &requested));
    }

    #[test]
    fn test_certificates_dont_match_wrong_certifier() {
        let certifier = PrivateKey::random();
        let other_certifier = PrivateKey::random();
        let subject = PrivateKey::random().public_key();

        let cert = make_test_cert(&certifier, &subject);

        let mut requested = RequestedCertificateSet::new();
        requested.add_certifier(other_certifier.public_key().to_hex());
        requested.add_type(cert.certificate.type_base64(), vec![]);

        assert!(!certificates_match_request(&[cert], &requested));
    }

    #[test]
    fn test_certificates_dont_match_missing_fields() {
        let certifier = PrivateKey::random();
        let subject = PrivateKey::random().public_key();

        let cert = make_test_cert(&certifier, &subject);

        let mut requested = RequestedCertificateSet::new();
        requested.add_type(
            cert.certificate.type_base64(),
            vec!["name".to_string(), "email".to_string()],
        );

        // Certificate has no keyring entries for required fields
        assert!(!certificates_match_request(&[cert], &requested));
    }

    #[test]
    fn test_certificates_match_with_keyring() {
        let certifier = PrivateKey::random();
        let subject = PrivateKey::random().public_key();

        let mut cert_inner = Certificate::new(
            [1u8; 32],
            [2u8; 32],
            subject.clone(),
            certifier.public_key(),
        );
        cert_inner.sign(&certifier).unwrap();

        let mut keyring = HashMap::new();
        keyring.insert("name".to_string(), vec![1, 2, 3]);
        keyring.insert("email".to_string(), vec![4, 5, 6]);

        let cert = VerifiableCertificate::new(cert_inner, keyring);

        let mut requested = RequestedCertificateSet::new();
        requested.add_type(
            cert.certificate.type_base64(),
            vec!["name".to_string(), "email".to_string()],
        );

        assert!(certificates_match_request(&[cert], &requested));
    }
}
