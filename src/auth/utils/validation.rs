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

/// Validates the encoding of a certificate's fields.
///
/// This function checks that a certificate's structural encoding is well-formed:
///
/// - Certificate type is exactly 32 bytes
/// - Serial number is exactly 32 bytes
/// - Subject and certifier are valid compressed public keys
/// - All field names are non-empty and at most 50 bytes (UTF-8)
/// - If a signature is present, it is a valid DER encoding
///
/// This is analogous to the TypeScript SDK's certificate field validation
/// in `validationHelpers.ts`.
///
/// # Arguments
///
/// * `cert` - The certificate to validate
///
/// # Returns
///
/// `Ok(())` if the certificate encoding is valid, or an error describing
/// the first validation failure found.
///
/// # Example
///
/// ```rust,ignore
/// use bsv_sdk::auth::utils::validate_certificate_encoding;
/// use bsv_sdk::auth::Certificate;
///
/// let cert = Certificate::new(
///     [1u8; 32], [2u8; 32],
///     subject_pubkey, certifier_pubkey,
/// );
/// validate_certificate_encoding(&cert)?;
/// ```
pub fn validate_certificate_encoding(cert: &crate::auth::certificates::Certificate) -> Result<()> {
    // cert_type is always [u8; 32], so it's always valid by construction.
    // serial_number is always [u8; 32], so it's always valid by construction.

    // Validate subject is a valid public key by checking it round-trips.
    let subject_bytes = cert.subject.to_compressed();
    if subject_bytes.len() != 33 {
        return Err(Error::CertificateValidationError(
            "Subject public key must be 33 bytes compressed".into(),
        ));
    }
    PublicKey::from_bytes(&subject_bytes).map_err(|_| {
        Error::CertificateValidationError("Subject is not a valid public key".into())
    })?;

    // Validate certifier is a valid public key.
    let certifier_bytes = cert.certifier.to_compressed();
    if certifier_bytes.len() != 33 {
        return Err(Error::CertificateValidationError(
            "Certifier public key must be 33 bytes compressed".into(),
        ));
    }
    PublicKey::from_bytes(&certifier_bytes).map_err(|_| {
        Error::CertificateValidationError("Certifier is not a valid public key".into())
    })?;

    // Validate field names: non-empty, max 50 bytes UTF-8.
    for field_name in cert.fields.keys() {
        if field_name.is_empty() {
            return Err(Error::CertificateValidationError(
                "Field name cannot be empty".into(),
            ));
        }
        if field_name.len() > 50 {
            return Err(Error::CertificateValidationError(format!(
                "Field name '{}' exceeds 50 bytes",
                field_name
            )));
        }
    }

    // Validate signature DER encoding if present.
    if let Some(ref sig_bytes) = cert.signature {
        if sig_bytes.is_empty() {
            return Err(Error::CertificateValidationError(
                "Signature present but empty".into(),
            ));
        }
        crate::primitives::ec::Signature::from_der(sig_bytes).map_err(|_| {
            Error::CertificateValidationError("Signature is not valid DER encoding".into())
        })?;
    }

    // Validate revocation outpoint if present.
    if let Some(ref outpoint) = cert.revocation_outpoint {
        // Outpoint txid should be 32 bytes (always is by type) and vout should be reasonable
        if outpoint.txid == [0u8; 32] && outpoint.vout == 0 {
            return Err(Error::CertificateValidationError(
                "Revocation outpoint is the null sentinel (all-zero txid, vout 0)".into(),
            ));
        }
    }

    Ok(())
}

/// Validates that a [`RequestedCertificateSet`] is well-formed.
///
/// This function checks the structural validity of a certificate request:
///
/// - All certifier entries are valid hex-encoded compressed public keys (66 hex chars)
/// - All type IDs are valid base64 strings that decode to exactly 32 bytes
/// - All field names within each type are non-empty and at most 50 bytes (UTF-8)
/// - The set is not empty (at least one type must be specified)
///
/// This is analogous to the TypeScript SDK's validation of certificate-related
/// arguments in `validationHelpers.ts`.
///
/// # Arguments
///
/// * `requested` - The certificate request set to validate
///
/// # Returns
///
/// `Ok(())` if the request set is valid, or an error describing the first
/// validation failure found.
///
/// # Example
///
/// ```rust,ignore
/// use bsv_sdk::auth::{RequestedCertificateSet, utils::validate_requested_certificate_set};
///
/// let mut req = RequestedCertificateSet::new();
/// req.add_certifier("02abc...".to_string());
/// req.add_type("base64_type_id".to_string(), vec!["name".into(), "email".into()]);
///
/// validate_requested_certificate_set(&req)?;
/// ```
pub fn validate_requested_certificate_set(requested: &RequestedCertificateSet) -> Result<()> {
    // Must have at least one type specified to be useful.
    if requested.types.is_empty() {
        return Err(Error::CertificateValidationError(
            "Requested certificate set must specify at least one type".into(),
        ));
    }

    // Validate certifier hex strings.
    for (i, certifier_hex) in requested.certifiers.iter().enumerate() {
        let trimmed = certifier_hex.trim();
        if trimmed.is_empty() {
            return Err(Error::CertificateValidationError(format!(
                "Certifier at index {} is empty",
                i
            )));
        }

        // Should be valid hex, 66 chars (33 bytes compressed pubkey).
        if trimmed.len() != 66 {
            return Err(Error::CertificateValidationError(format!(
                "Certifier '{}' is not a 33-byte compressed public key (expected 66 hex chars, got {})",
                trimmed,
                trimmed.len()
            )));
        }

        // Try to parse as a public key.
        let bytes = crate::primitives::from_hex(trimmed).map_err(|_| {
            Error::CertificateValidationError(format!("Certifier '{}' is not valid hex", trimmed))
        })?;

        PublicKey::from_bytes(&bytes).map_err(|_| {
            Error::CertificateValidationError(format!(
                "Certifier '{}' is not a valid public key",
                trimmed
            ))
        })?;
    }

    // Validate type IDs and field names.
    for (type_id, fields) in &requested.types {
        let trimmed = type_id.trim();
        if trimmed.is_empty() {
            return Err(Error::CertificateValidationError(
                "Certificate type ID cannot be empty".into(),
            ));
        }

        // Type ID should be valid base64 decoding to 32 bytes.
        let decoded = crate::primitives::from_base64(trimmed).map_err(|_| {
            Error::CertificateValidationError(format!(
                "Certificate type '{}' is not valid base64",
                trimmed
            ))
        })?;

        if decoded.len() != 32 {
            return Err(Error::CertificateValidationError(format!(
                "Certificate type '{}' decodes to {} bytes, expected 32",
                trimmed,
                decoded.len()
            )));
        }

        // Validate field names.
        for field_name in fields {
            if field_name.is_empty() {
                return Err(Error::CertificateValidationError(format!(
                    "Field name in type '{}' cannot be empty",
                    trimmed
                )));
            }
            if field_name.len() > 50 {
                return Err(Error::CertificateValidationError(format!(
                    "Field name '{}' in type '{}' exceeds 50 bytes",
                    field_name, trimmed
                )));
            }
        }
    }

    Ok(())
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

    // =======================================
    // Tests for validate_certificate_encoding
    // =======================================

    #[test]
    fn test_validate_certificate_encoding_valid() {
        let certifier = PrivateKey::random();
        let subject = PrivateKey::random().public_key();

        let mut cert = Certificate::new([1u8; 32], [2u8; 32], subject, certifier.public_key());
        cert.set_field("name", b"encrypted_value".to_vec());
        cert.sign(&certifier).unwrap();

        validate_certificate_encoding(&cert).unwrap();
    }

    #[test]
    fn test_validate_certificate_encoding_no_signature() {
        let certifier = PrivateKey::random();
        let subject = PrivateKey::random().public_key();

        let cert = Certificate::new([1u8; 32], [2u8; 32], subject, certifier.public_key());

        // No signature is valid (unsigned certificate)
        validate_certificate_encoding(&cert).unwrap();
    }

    #[test]
    fn test_validate_certificate_encoding_empty_field_name() {
        let certifier = PrivateKey::random();
        let subject = PrivateKey::random().public_key();

        let mut cert = Certificate::new([1u8; 32], [2u8; 32], subject, certifier.public_key());
        cert.fields.insert("".to_string(), vec![1, 2, 3]);

        let result = validate_certificate_encoding(&cert);
        assert!(matches!(result, Err(Error::CertificateValidationError(_))));
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Field name cannot be empty"));
    }

    #[test]
    fn test_validate_certificate_encoding_long_field_name() {
        let certifier = PrivateKey::random();
        let subject = PrivateKey::random().public_key();

        let mut cert = Certificate::new([1u8; 32], [2u8; 32], subject, certifier.public_key());
        let long_name = "a".repeat(51);
        cert.fields.insert(long_name, vec![1, 2, 3]);

        let result = validate_certificate_encoding(&cert);
        assert!(matches!(result, Err(Error::CertificateValidationError(_))));
        assert!(result.unwrap_err().to_string().contains("exceeds 50 bytes"));
    }

    #[test]
    fn test_validate_certificate_encoding_invalid_der_signature() {
        let certifier = PrivateKey::random();
        let subject = PrivateKey::random().public_key();

        let mut cert = Certificate::new([1u8; 32], [2u8; 32], subject, certifier.public_key());
        cert.signature = Some(vec![0xFF, 0xFF, 0xFF]); // Invalid DER

        let result = validate_certificate_encoding(&cert);
        assert!(matches!(result, Err(Error::CertificateValidationError(_))));
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("not valid DER encoding"));
    }

    #[test]
    fn test_validate_certificate_encoding_empty_signature() {
        let certifier = PrivateKey::random();
        let subject = PrivateKey::random().public_key();

        let mut cert = Certificate::new([1u8; 32], [2u8; 32], subject, certifier.public_key());
        cert.signature = Some(vec![]); // Empty signature bytes

        let result = validate_certificate_encoding(&cert);
        assert!(matches!(result, Err(Error::CertificateValidationError(_))));
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Signature present but empty"));
    }

    #[test]
    fn test_validate_certificate_encoding_with_revocation() {
        let certifier = PrivateKey::random();
        let subject = PrivateKey::random().public_key();

        let mut cert = Certificate::new([1u8; 32], [2u8; 32], subject, certifier.public_key());
        cert.revocation_outpoint = Some(crate::wallet::types::Outpoint::new([3u8; 32], 5));
        cert.sign(&certifier).unwrap();

        validate_certificate_encoding(&cert).unwrap();
    }

    #[test]
    fn test_validate_certificate_encoding_null_revocation_outpoint() {
        let certifier = PrivateKey::random();
        let subject = PrivateKey::random().public_key();

        let mut cert = Certificate::new([1u8; 32], [2u8; 32], subject, certifier.public_key());
        // Set the null sentinel outpoint explicitly
        cert.revocation_outpoint = Some(crate::wallet::types::Outpoint::new([0u8; 32], 0));

        let result = validate_certificate_encoding(&cert);
        assert!(matches!(result, Err(Error::CertificateValidationError(_))));
        assert!(result.unwrap_err().to_string().contains("null sentinel"));
    }

    #[test]
    fn test_validate_certificate_encoding_50_byte_field_name() {
        let certifier = PrivateKey::random();
        let subject = PrivateKey::random().public_key();

        let mut cert = Certificate::new([1u8; 32], [2u8; 32], subject, certifier.public_key());
        let exactly_50 = "a".repeat(50);
        cert.fields.insert(exactly_50, vec![1, 2, 3]);

        // Exactly 50 bytes should be valid
        validate_certificate_encoding(&cert).unwrap();
    }

    #[test]
    fn test_validate_certificate_encoding_multiple_fields() {
        let certifier = PrivateKey::random();
        let subject = PrivateKey::random().public_key();

        let mut cert = Certificate::new([1u8; 32], [2u8; 32], subject, certifier.public_key());
        cert.set_field("name", b"alice".to_vec());
        cert.set_field("email", b"alice@example.com".to_vec());
        cert.set_field("phone", b"+1234567890".to_vec());
        cert.sign(&certifier).unwrap();

        validate_certificate_encoding(&cert).unwrap();
    }

    // =======================================
    // Tests for validate_requested_certificate_set
    // =======================================

    #[test]
    fn test_validate_requested_certificate_set_valid() {
        let certifier = PrivateKey::random();
        let type_bytes = [1u8; 32];
        let type_b64 = crate::primitives::to_base64(&type_bytes);

        let mut req = RequestedCertificateSet::new();
        req.add_certifier(certifier.public_key().to_hex());
        req.add_type(type_b64, vec!["name".to_string(), "email".to_string()]);

        validate_requested_certificate_set(&req).unwrap();
    }

    #[test]
    fn test_validate_requested_certificate_set_empty_types() {
        let certifier = PrivateKey::random();

        let mut req = RequestedCertificateSet::new();
        req.add_certifier(certifier.public_key().to_hex());
        // No types specified

        let result = validate_requested_certificate_set(&req);
        assert!(matches!(result, Err(Error::CertificateValidationError(_))));
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("at least one type"));
    }

    #[test]
    fn test_validate_requested_certificate_set_invalid_certifier_hex() {
        let type_bytes = [1u8; 32];
        let type_b64 = crate::primitives::to_base64(&type_bytes);

        let mut req = RequestedCertificateSet::new();
        req.add_certifier("not_valid_hex");
        req.add_type(type_b64, vec!["name".to_string()]);

        let result = validate_requested_certificate_set(&req);
        assert!(matches!(result, Err(Error::CertificateValidationError(_))));
    }

    #[test]
    fn test_validate_requested_certificate_set_wrong_length_certifier() {
        let type_bytes = [1u8; 32];
        let type_b64 = crate::primitives::to_base64(&type_bytes);

        let mut req = RequestedCertificateSet::new();
        req.add_certifier("02abcdef"); // Too short (8 chars, need 66)
        req.add_type(type_b64, vec!["name".to_string()]);

        let result = validate_requested_certificate_set(&req);
        assert!(matches!(result, Err(Error::CertificateValidationError(_))));
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("33-byte compressed public key"));
    }

    #[test]
    fn test_validate_requested_certificate_set_empty_certifier() {
        let type_bytes = [1u8; 32];
        let type_b64 = crate::primitives::to_base64(&type_bytes);

        let mut req = RequestedCertificateSet::new();
        req.add_certifier("");
        req.add_type(type_b64, vec!["name".to_string()]);

        let result = validate_requested_certificate_set(&req);
        assert!(matches!(result, Err(Error::CertificateValidationError(_))));
        assert!(result.unwrap_err().to_string().contains("empty"));
    }

    #[test]
    fn test_validate_requested_certificate_set_invalid_type_base64() {
        let certifier = PrivateKey::random();

        let mut req = RequestedCertificateSet::new();
        req.add_certifier(certifier.public_key().to_hex());
        req.add_type("not valid base64!!!".to_string(), vec!["name".to_string()]);

        let result = validate_requested_certificate_set(&req);
        assert!(matches!(result, Err(Error::CertificateValidationError(_))));
        assert!(result.unwrap_err().to_string().contains("not valid base64"));
    }

    #[test]
    fn test_validate_requested_certificate_set_wrong_length_type() {
        let certifier = PrivateKey::random();
        // Valid base64, but decodes to 16 bytes instead of 32
        let short_type = crate::primitives::to_base64(&[1u8; 16]);

        let mut req = RequestedCertificateSet::new();
        req.add_certifier(certifier.public_key().to_hex());
        req.add_type(short_type, vec!["name".to_string()]);

        let result = validate_requested_certificate_set(&req);
        assert!(matches!(result, Err(Error::CertificateValidationError(_))));
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("decodes to 16 bytes, expected 32"));
    }

    #[test]
    fn test_validate_requested_certificate_set_empty_field_name() {
        let certifier = PrivateKey::random();
        let type_b64 = crate::primitives::to_base64(&[1u8; 32]);

        let mut req = RequestedCertificateSet::new();
        req.add_certifier(certifier.public_key().to_hex());
        req.add_type(type_b64, vec!["".to_string()]);

        let result = validate_requested_certificate_set(&req);
        assert!(matches!(result, Err(Error::CertificateValidationError(_))));
        assert!(result.unwrap_err().to_string().contains("cannot be empty"));
    }

    #[test]
    fn test_validate_requested_certificate_set_long_field_name() {
        let certifier = PrivateKey::random();
        let type_b64 = crate::primitives::to_base64(&[1u8; 32]);

        let mut req = RequestedCertificateSet::new();
        req.add_certifier(certifier.public_key().to_hex());
        req.add_type(type_b64, vec!["a".repeat(51)]);

        let result = validate_requested_certificate_set(&req);
        assert!(matches!(result, Err(Error::CertificateValidationError(_))));
        assert!(result.unwrap_err().to_string().contains("exceeds 50 bytes"));
    }

    #[test]
    fn test_validate_requested_certificate_set_empty_type_id() {
        let certifier = PrivateKey::random();

        let mut req = RequestedCertificateSet::new();
        req.add_certifier(certifier.public_key().to_hex());
        req.add_type("".to_string(), vec!["name".to_string()]);

        let result = validate_requested_certificate_set(&req);
        assert!(matches!(result, Err(Error::CertificateValidationError(_))));
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("type ID cannot be empty"));
    }

    #[test]
    fn test_validate_requested_certificate_set_no_certifiers_valid() {
        // A set with types but no certifiers is valid (any certifier accepted)
        let type_b64 = crate::primitives::to_base64(&[1u8; 32]);

        let mut req = RequestedCertificateSet::new();
        req.add_type(type_b64, vec!["name".to_string()]);

        validate_requested_certificate_set(&req).unwrap();
    }

    #[test]
    fn test_validate_requested_certificate_set_no_fields_valid() {
        // A type with no fields required is valid (just checking type exists)
        let certifier = PrivateKey::random();
        let type_b64 = crate::primitives::to_base64(&[1u8; 32]);

        let mut req = RequestedCertificateSet::new();
        req.add_certifier(certifier.public_key().to_hex());
        req.add_type(type_b64, vec![]);

        validate_requested_certificate_set(&req).unwrap();
    }

    #[test]
    fn test_validate_requested_certificate_set_multiple_types() {
        let certifier = PrivateKey::random();
        let type_b64_1 = crate::primitives::to_base64(&[1u8; 32]);
        let type_b64_2 = crate::primitives::to_base64(&[2u8; 32]);

        let mut req = RequestedCertificateSet::new();
        req.add_certifier(certifier.public_key().to_hex());
        req.add_type(type_b64_1, vec!["name".to_string()]);
        req.add_type(type_b64_2, vec!["email".to_string(), "phone".to_string()]);

        validate_requested_certificate_set(&req).unwrap();
    }
}
