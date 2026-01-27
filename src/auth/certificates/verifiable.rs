//! VerifiableCertificate with verifier-specific keyring.
//!
//! A verifiable certificate includes a keyring that allows a specific
//! verifier to decrypt selected fields.

use super::{Certificate, CERTIFICATE_FIELD_ENCRYPTION_PROTOCOL};
use crate::primitives::PublicKey;
use crate::wallet::{Counterparty, DecryptArgs, Protocol, SecurityLevel, WalletInterface};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Certificate with verifier-specific keyring for field decryption.
///
/// The keyring contains encryption keys specific to this verifier,
/// allowing decryption of only the fields that were revealed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiableCertificate {
    /// Base certificate.
    #[serde(flatten)]
    pub certificate: Certificate,

    /// Keyring for this verifier: field_name -> encrypted_key.
    /// Only fields in the keyring can be decrypted.
    #[serde(default)]
    pub keyring: HashMap<String, Vec<u8>>,

    /// Cached decrypted field values.
    #[serde(skip)]
    decrypted_fields: Option<HashMap<String, String>>,
}

impl VerifiableCertificate {
    /// Creates a verifiable certificate from a base certificate and keyring.
    pub fn new(certificate: Certificate, keyring: HashMap<String, Vec<u8>>) -> Self {
        Self {
            certificate,
            keyring,
            decrypted_fields: None,
        }
    }

    /// Creates from certificate with empty keyring.
    pub fn from_certificate(certificate: Certificate) -> Self {
        Self {
            certificate,
            keyring: HashMap::new(),
            decrypted_fields: None,
        }
    }

    /// Returns true if the keyring has keys for any fields.
    pub fn has_keyring(&self) -> bool {
        !self.keyring.is_empty()
    }

    /// Returns the list of field names that can be decrypted.
    pub fn revealable_fields(&self) -> Vec<&String> {
        self.keyring.keys().collect()
    }

    /// Decrypts a single field using the verifier keyring.
    ///
    /// # Arguments
    /// * `verifier_wallet` - Verifier's wallet for decryption
    /// * `subject` - Subject's public key (the counterparty)
    /// * `field_name` - Name of the field to decrypt
    /// * `originator` - Application originator
    pub async fn decrypt_field<W: WalletInterface>(
        &self,
        verifier_wallet: &W,
        subject: &PublicKey,
        field_name: &str,
        originator: &str,
    ) -> Result<String> {
        // Get the encrypted value from the keyring
        let encrypted_key = self.keyring.get(field_name).ok_or_else(|| {
            Error::AuthError(format!(
                "Field '{}' not in keyring (not revealed for this verifier)",
                field_name
            ))
        })?;

        let protocol = Protocol::new(SecurityLevel::Counterparty, CERTIFICATE_FIELD_ENCRYPTION_PROTOCOL);
        let key_id = Certificate::get_field_encryption_key_id_verifiable(
            field_name,
            &self.certificate.serial_number,
        );

        let decrypted = verifier_wallet
            .decrypt(
                DecryptArgs {
                    ciphertext: encrypted_key.clone(),
                    protocol_id: protocol,
                    key_id,
                    counterparty: Some(Counterparty::Other(subject.clone())),
                },
                originator,
            )
            .await?;

        String::from_utf8(decrypted.plaintext).map_err(|e| Error::InvalidUtf8(e.to_string()))
    }

    /// Decrypts all fields that have keys in the keyring.
    ///
    /// Results are cached for subsequent calls.
    pub async fn decrypt_fields<W: WalletInterface>(
        &mut self,
        verifier_wallet: &W,
        subject: &PublicKey,
        originator: &str,
    ) -> Result<HashMap<String, String>> {
        // Return cached result if available
        if let Some(ref cached) = self.decrypted_fields {
            return Ok(cached.clone());
        }

        let mut decrypted = HashMap::new();

        for field_name in self.keyring.keys() {
            let value = self
                .decrypt_field(verifier_wallet, subject, field_name, originator)
                .await?;
            decrypted.insert(field_name.clone(), value);
        }

        // Cache the result
        self.decrypted_fields = Some(decrypted.clone());

        Ok(decrypted)
    }

    /// Returns cached decrypted fields if available.
    pub fn get_decrypted_fields(&self) -> Option<&HashMap<String, String>> {
        self.decrypted_fields.as_ref()
    }

    /// Clears the cached decrypted fields.
    pub fn clear_decrypted_cache(&mut self) {
        self.decrypted_fields = None;
    }

    /// Verifies the underlying certificate signature.
    pub fn verify(&self) -> Result<bool> {
        self.certificate.verify()
    }

    /// Returns the subject's public key.
    pub fn subject(&self) -> &PublicKey {
        &self.certificate.subject
    }

    /// Returns the certifier's public key.
    pub fn certifier(&self) -> &PublicKey {
        &self.certificate.certifier
    }

    /// Returns the certificate type.
    pub fn cert_type(&self) -> &[u8; 32] {
        &self.certificate.cert_type
    }

    /// Returns the serial number.
    pub fn serial_number(&self) -> &[u8; 32] {
        &self.certificate.serial_number
    }

    /// Converts to a JSON-serializable format with base64-encoded values.
    pub fn to_json_value(&self) -> serde_json::Value {
        serde_json::json!({
            "type": self.certificate.type_base64(),
            "serialNumber": self.certificate.serial_number_base64(),
            "subject": self.certificate.subject.to_hex(),
            "certifier": self.certificate.certifier.to_hex(),
            "revocationOutpoint": self.certificate.revocation_outpoint.as_ref().map(|o| o.to_string()),
            "fields": self.certificate.fields.iter()
                .map(|(k, v)| (k.clone(), crate::primitives::to_base64(v)))
                .collect::<HashMap<String, String>>(),
            "signature": self.certificate.signature.as_ref().map(|s| crate::primitives::to_base64(s)),
            "keyring": self.keyring.iter()
                .map(|(k, v)| (k.clone(), crate::primitives::to_base64(v)))
                .collect::<HashMap<String, String>>(),
        })
    }
}

impl std::ops::Deref for VerifiableCertificate {
    type Target = Certificate;

    fn deref(&self) -> &Self::Target {
        &self.certificate
    }
}

impl From<Certificate> for VerifiableCertificate {
    fn from(certificate: Certificate) -> Self {
        Self::from_certificate(certificate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::PrivateKey;

    #[test]
    fn test_verifiable_certificate_creation() {
        let certifier = PrivateKey::random();
        let subject = PrivateKey::random().public_key();

        let mut cert = Certificate::new([1u8; 32], [2u8; 32], subject.clone(), certifier.public_key());
        cert.sign(&certifier).unwrap();

        let mut keyring = HashMap::new();
        keyring.insert("name".to_string(), vec![1, 2, 3]);

        let verifiable = VerifiableCertificate::new(cert, keyring);

        assert!(verifiable.verify().unwrap());
        assert!(verifiable.has_keyring());
        assert_eq!(verifiable.revealable_fields().len(), 1);
    }

    #[test]
    fn test_from_certificate() {
        let certifier = PrivateKey::random();
        let subject = PrivateKey::random().public_key();

        let mut cert = Certificate::new([1u8; 32], [2u8; 32], subject, certifier.public_key());
        cert.sign(&certifier).unwrap();

        let verifiable = VerifiableCertificate::from_certificate(cert);

        assert!(verifiable.verify().unwrap());
        assert!(!verifiable.has_keyring());
    }

    #[test]
    fn test_deref_to_certificate() {
        let certifier = PrivateKey::random();
        let subject = PrivateKey::random().public_key();

        let mut cert = Certificate::new([1u8; 32], [2u8; 32], subject.clone(), certifier.public_key());
        cert.sign(&certifier).unwrap();

        let verifiable = VerifiableCertificate::from_certificate(cert);

        // Should be able to access Certificate fields via Deref
        assert_eq!(verifiable.subject, subject);
        assert_eq!(verifiable.cert_type, [1u8; 32]);
    }

    #[test]
    fn test_json_serialization() {
        let certifier = PrivateKey::random();
        let subject = PrivateKey::random().public_key();

        let mut cert = Certificate::new([1u8; 32], [2u8; 32], subject, certifier.public_key());
        cert.fields.insert("email".to_string(), vec![4, 5, 6]);
        cert.sign(&certifier).unwrap();

        let mut keyring = HashMap::new();
        keyring.insert("email".to_string(), vec![7, 8, 9]);

        let verifiable = VerifiableCertificate::new(cert, keyring);
        let json = verifiable.to_json_value();

        assert!(json.get("type").is_some());
        assert!(json.get("serialNumber").is_some());
        assert!(json.get("keyring").is_some());
    }
}
