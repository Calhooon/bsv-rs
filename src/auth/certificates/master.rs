//! MasterCertificate with field encryption and keyring management.
//!
//! The master certificate contains the encryption keys for all fields,
//! allowing the subject to create keyrings for specific verifiers.

use super::{Certificate, CERTIFICATE_FIELD_ENCRYPTION_PROTOCOL};
use crate::primitives::PublicKey;
use crate::wallet::{
    Counterparty, DecryptArgs, EncryptArgs, Protocol, SecurityLevel, WalletInterface,
};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Certificate with master keyring for field encryption.
///
/// The master keyring contains the encryption keys for all fields,
/// allowing the subject to create keyrings for specific verifiers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MasterCertificate {
    /// Base certificate.
    #[serde(flatten)]
    pub certificate: Certificate,

    /// Master keyring: field_name -> encrypted_master_key.
    /// The master key is encrypted from certifier to subject.
    #[serde(default)]
    pub master_keyring: HashMap<String, Vec<u8>>,
}

impl MasterCertificate {
    /// Creates a new master certificate from a base certificate and keyring.
    pub fn new(certificate: Certificate, master_keyring: HashMap<String, Vec<u8>>) -> Self {
        Self {
            certificate,
            master_keyring,
        }
    }

    /// Creates encrypted certificate fields and master keyring.
    ///
    /// # Arguments
    /// * `creator_wallet` - Wallet for encryption (certifier's wallet)
    /// * `subject` - Subject's public key
    /// * `fields` - Plain text field values to encrypt
    /// * `_serial_number` - Certificate serial number (unused, for future use)
    /// * `originator` - Application originator
    ///
    /// # Returns
    /// Tuple of (encrypted_fields, master_keyring)
    pub async fn create_certificate_fields<W: WalletInterface>(
        creator_wallet: &W,
        subject: &PublicKey,
        fields: HashMap<String, String>,
        _serial_number: &[u8; 32],
        originator: &str,
    ) -> Result<(HashMap<String, Vec<u8>>, HashMap<String, Vec<u8>>)> {
        let protocol = Protocol::new(SecurityLevel::Counterparty, CERTIFICATE_FIELD_ENCRYPTION_PROTOCOL);

        let mut encrypted_fields = HashMap::new();
        let mut master_keyring = HashMap::new();

        for (field_name, plain_value) in fields {
            // Key ID for master encryption is just the field name
            let key_id = Certificate::get_field_encryption_key_id_master(&field_name);

            // Encrypt the field value
            let encrypt_result = creator_wallet
                .encrypt(
                    EncryptArgs {
                        plaintext: plain_value.as_bytes().to_vec(),
                        protocol_id: protocol.clone(),
                        key_id: key_id.clone(),
                        counterparty: Some(Counterparty::Other(subject.clone())),
                    },
                    originator,
                )
                .await?;

            encrypted_fields.insert(field_name.clone(), encrypt_result.ciphertext.clone());

            // The master keyring stores the encryption key info
            // For the subject to later create verifier keyrings
            master_keyring.insert(field_name, encrypt_result.ciphertext);
        }

        Ok((encrypted_fields, master_keyring))
    }

    /// Creates a keyring for a specific verifier.
    ///
    /// Enables selective disclosure by creating field-specific keys
    /// that the verifier can use to decrypt only revealed fields.
    ///
    /// # Arguments
    /// * `subject_wallet` - Subject's wallet for re-encryption
    /// * `certifier` - Certifier's public key
    /// * `verifier` - Verifier's public key
    /// * `fields_to_reveal` - List of field names to reveal
    /// * `encrypted_fields` - The encrypted field values
    /// * `serial_number` - Certificate serial number
    /// * `originator` - Application originator
    ///
    /// # Returns
    /// Keyring for the verifier: field_name -> encrypted_key
    pub async fn create_keyring_for_verifier<W: WalletInterface>(
        subject_wallet: &W,
        certifier: &PublicKey,
        verifier: &PublicKey,
        fields_to_reveal: &[String],
        encrypted_fields: &HashMap<String, Vec<u8>>,
        serial_number: &[u8; 32],
        originator: &str,
    ) -> Result<HashMap<String, Vec<u8>>> {
        let protocol = Protocol::new(SecurityLevel::Counterparty, CERTIFICATE_FIELD_ENCRYPTION_PROTOCOL);

        let mut keyring = HashMap::new();

        for field_name in fields_to_reveal {
            let encrypted_value = encrypted_fields.get(field_name).ok_or_else(|| {
                Error::AuthError(format!("Field '{}' not found in certificate", field_name))
            })?;

            // Decrypt the field using the master key
            let master_key_id = Certificate::get_field_encryption_key_id_master(field_name);
            let decrypted = subject_wallet
                .decrypt(
                    DecryptArgs {
                        ciphertext: encrypted_value.clone(),
                        protocol_id: protocol.clone(),
                        key_id: master_key_id,
                        counterparty: Some(Counterparty::Other(certifier.clone())),
                    },
                    originator,
                )
                .await?;

            // Re-encrypt for the verifier with the verifiable key ID
            let verifiable_key_id =
                Certificate::get_field_encryption_key_id_verifiable(field_name, serial_number);
            let re_encrypted = subject_wallet
                .encrypt(
                    EncryptArgs {
                        plaintext: decrypted.plaintext,
                        protocol_id: protocol.clone(),
                        key_id: verifiable_key_id,
                        counterparty: Some(Counterparty::Other(verifier.clone())),
                    },
                    originator,
                )
                .await?;

            keyring.insert(field_name.clone(), re_encrypted.ciphertext);
        }

        Ok(keyring)
    }

    /// Issues a new certificate for a subject.
    ///
    /// # Arguments
    /// * `certifier_wallet` - Certifier's wallet for signing and encryption
    /// * `certifier_key` - Certifier's private key for signing
    /// * `subject` - Subject's public key
    /// * `plain_fields` - Plain text field values
    /// * `cert_type` - Certificate type identifier
    /// * `serial_number` - Optional serial number (random if not provided)
    /// * `originator` - Application originator
    pub async fn issue_for_subject<W: WalletInterface>(
        certifier_wallet: &W,
        certifier_key: &crate::primitives::PrivateKey,
        subject: PublicKey,
        plain_fields: HashMap<String, String>,
        cert_type: [u8; 32],
        serial_number: Option<[u8; 32]>,
        originator: &str,
    ) -> Result<Self> {
        // Generate serial number if not provided
        let serial_number = serial_number.unwrap_or_else(|| {
            let mut serial = [0u8; 32];
            use rand::RngCore;
            rand::thread_rng().fill_bytes(&mut serial);
            serial
        });

        // Create encrypted fields and master keyring
        let (encrypted_fields, master_keyring) = Self::create_certificate_fields(
            certifier_wallet,
            &subject,
            plain_fields,
            &serial_number,
            originator,
        )
        .await?;

        // Build the certificate
        let mut certificate = Certificate::new(
            cert_type,
            serial_number,
            subject,
            certifier_key.public_key(),
        );
        certificate.fields = encrypted_fields;

        // Sign the certificate
        certificate.sign(certifier_key)?;

        Ok(Self {
            certificate,
            master_keyring,
        })
    }

    /// Decrypts a single field using the master keyring.
    ///
    /// # Arguments
    /// * `subject_wallet` - Subject's wallet for decryption
    /// * `certifier` - Certifier's public key
    /// * `field_name` - Name of the field to decrypt
    /// * `originator` - Application originator
    pub async fn decrypt_field<W: WalletInterface>(
        &self,
        subject_wallet: &W,
        certifier: &PublicKey,
        field_name: &str,
        originator: &str,
    ) -> Result<String> {
        let encrypted_value = self.certificate.fields.get(field_name).ok_or_else(|| {
            Error::AuthError(format!("Field '{}' not found in certificate", field_name))
        })?;

        let protocol = Protocol::new(SecurityLevel::Counterparty, CERTIFICATE_FIELD_ENCRYPTION_PROTOCOL);
        let key_id = Certificate::get_field_encryption_key_id_master(field_name);

        let decrypted = subject_wallet
            .decrypt(
                DecryptArgs {
                    ciphertext: encrypted_value.clone(),
                    protocol_id: protocol,
                    key_id,
                    counterparty: Some(Counterparty::Other(certifier.clone())),
                },
                originator,
            )
            .await?;

        String::from_utf8(decrypted.plaintext).map_err(|e| Error::InvalidUtf8(e.to_string()))
    }

    /// Decrypts all fields using the master keyring.
    pub async fn decrypt_fields<W: WalletInterface>(
        &self,
        subject_wallet: &W,
        certifier: &PublicKey,
        originator: &str,
    ) -> Result<HashMap<String, String>> {
        let mut decrypted = HashMap::new();

        for field_name in self.certificate.fields.keys() {
            let value = self
                .decrypt_field(subject_wallet, certifier, field_name, originator)
                .await?;
            decrypted.insert(field_name.clone(), value);
        }

        Ok(decrypted)
    }

    /// Verifies the certificate signature.
    pub fn verify(&self) -> Result<bool> {
        self.certificate.verify()
    }
}

impl std::ops::Deref for MasterCertificate {
    type Target = Certificate;

    fn deref(&self) -> &Self::Target {
        &self.certificate
    }
}

impl std::ops::DerefMut for MasterCertificate {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.certificate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_master_certificate_creation() {
        let certifier = crate::primitives::PrivateKey::random();
        let subject = crate::primitives::PrivateKey::random().public_key();

        let mut cert = Certificate::new([1u8; 32], [2u8; 32], subject, certifier.public_key());
        cert.sign(&certifier).unwrap();

        let master_keyring = HashMap::new();
        let master_cert = MasterCertificate::new(cert, master_keyring);

        assert!(master_cert.verify().unwrap());
    }

    #[test]
    fn test_deref_to_certificate() {
        let certifier = crate::primitives::PrivateKey::random();
        let subject = crate::primitives::PrivateKey::random().public_key();

        let mut cert = Certificate::new([1u8; 32], [2u8; 32], subject.clone(), certifier.public_key());
        cert.sign(&certifier).unwrap();

        let master_cert = MasterCertificate::new(cert, HashMap::new());

        // Should be able to access Certificate fields via Deref
        assert_eq!(master_cert.subject, subject);
        assert_eq!(master_cert.cert_type, [1u8; 32]);
    }
}
