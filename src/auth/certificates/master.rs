//! MasterCertificate with field encryption and keyring management.
//!
//! The master certificate contains the encryption keys for all fields,
//! allowing the subject to create keyrings for specific verifiers.

use super::{Certificate, CERTIFICATE_FIELD_ENCRYPTION_PROTOCOL};
use crate::primitives::{from_base64, to_base64, PublicKey, SymmetricKey};
use crate::wallet::wire::MAX_CERTIFICATE_FIELD_VALUE_BYTES;
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

    /// Master keyring: field_name -> the base64 text of the field's
    /// revelation key encrypted from certifier to subject, held as the
    /// reference's `Record<CertificateFieldNameUnder50Bytes, Base64String>`
    /// (`ts-stack@edf6e03` `MasterCertificate.ts:173`) and Go's
    /// `map[..]wallet.StringBase64` (`go-sdk@2ca481c`
    /// `auth/certificates/master.go:34`) hold it, and written so in JSON;
    /// decoded only where the wallet decrypts (#268).
    #[serde(default)]
    pub master_keyring: HashMap<String, String>,
}

impl MasterCertificate {
    /// Creates a new master certificate from a base certificate and keyring.
    pub fn new(certificate: Certificate, master_keyring: HashMap<String, String>) -> Self {
        Self {
            certificate,
            master_keyring,
        }
    }

    /// Creates encrypted certificate fields and master keyring, as the
    /// reference's `MasterCertificate.createCertificateFields` does
    /// (`ts-stack@edf6e03` `MasterCertificate.ts:254-310`): each field is
    /// encrypted under a fresh random symmetric key, the field value held is
    /// the base64 text of that ciphertext (its UTF-8 bytes, as BRC-52 signs
    /// and writes it, `0052.md:97`; #261), and the master keyring holds the
    /// symmetric key encrypted by the creator's wallet to the subject under
    /// protocol `[2, "certificate field encryption"]` and key ID the field
    /// name, as that ciphertext's base64 text (`:292-298`; #268).
    ///
    /// # Arguments
    /// * `creator_wallet` - Wallet for encryption (certifier's wallet)
    /// * `subject` - Subject's public key
    /// * `fields` - Plain text field values to encrypt
    /// * `privileged` - The reference's `privileged`, passed to each `encrypt`
    /// * `privileged_reason` - The reference's `privilegedReason`, likewise
    /// * `originator` - Application originator
    ///
    /// # Returns
    /// Tuple of (encrypted_fields, master_keyring)
    pub async fn create_certificate_fields<W: WalletInterface>(
        creator_wallet: &W,
        subject: &PublicKey,
        fields: HashMap<String, String>,
        privileged: Option<bool>,
        privileged_reason: Option<&str>,
        originator: &str,
    ) -> Result<(HashMap<String, String>, HashMap<String, String>)> {
        let mut encrypted_fields = HashMap::new();
        let mut master_keyring = HashMap::new();

        for (field_name, plain_value) in fields {
            let field_key = SymmetricKey::random();
            let encrypted_value = field_key.encrypt(plain_value.as_bytes())?;
            encrypted_fields.insert(field_name.clone(), to_base64(&encrypted_value));

            // The revelation key, encrypted to the subject under the field name.
            let encrypt_result = creator_wallet
                .encrypt(
                    EncryptArgs {
                        plaintext: field_key.as_bytes().to_vec(),
                        protocol_id: field_protocol(),
                        key_id: Certificate::get_field_encryption_key_id_master(&field_name),
                        counterparty: Some(Counterparty::Other(subject.clone())),
                        privileged,
                        privileged_reason: privileged_reason.map(str::to_owned),
                        ..Default::default()
                    },
                    originator,
                )
                .await?;
            master_keyring.insert(field_name, to_base64(&encrypt_result.ciphertext));
        }

        Ok((encrypted_fields, master_keyring))
    }

    /// Creates a keyring for a specific verifier, as the reference's
    /// `MasterCertificate.createKeyringForVerifier` does
    /// (`MasterCertificate.ts:325-414`): for each revealed field the subject
    /// decrypts the field's revelation key from the master keyring, checks
    /// that it decrypts the field, and encrypts it to the verifier under key
    /// ID `"<serial base64> <field>"`. The parameters are the reference's, in
    /// its order (`:325-346`), then `originator`.
    ///
    /// # Arguments
    /// * `subject_wallet` - Subject's wallet for re-encryption
    /// * `certifier` - Certifier's public key
    /// * `verifier` - Verifier's public key
    /// * `fields` - The certificate's field values (base64 text)
    /// * `fields_to_reveal` - List of field names to reveal
    /// * `master_keyring` - The master keyring (encrypted revelation keys,
    ///   base64 text)
    /// * `serial_number` - Certificate serial number
    /// * `privileged` - The reference's `privileged`, passed to each `decrypt`
    ///   and `encrypt` (`:384-402`)
    /// * `privileged_reason` - The reference's `privilegedReason`, likewise
    /// * `originator` - Application originator
    ///
    /// # Returns
    /// Keyring for the verifier: field_name -> the base64 text of the
    /// encrypted revelation key (`:405`; #268)
    #[allow(clippy::too_many_arguments)]
    pub async fn create_keyring_for_verifier<W: WalletInterface>(
        subject_wallet: &W,
        certifier: &PublicKey,
        verifier: &PublicKey,
        fields: &HashMap<String, String>,
        fields_to_reveal: &[String],
        master_keyring: &HashMap<String, String>,
        serial_number: &[u8; 32],
        privileged: Option<bool>,
        privileged_reason: Option<&str>,
        originator: &str,
    ) -> Result<HashMap<String, String>> {
        // Every field's text canonical base64 first, revealed or not, as the
        // reference's `createKeyringForVerifier` asks (`:351-357`; bsv-rs#275)
        for (field_name, field_value) in fields {
            field_ciphertext(field_name, field_value)?;
        }
        let mut keyring = HashMap::new();

        for field_name in fields_to_reveal {
            let field_value = fields.get(field_name).ok_or_else(|| {
                Error::AuthError(format!("Field '{}' not found in certificate", field_name))
            })?;

            let (revelation_key, _) = Self::decrypt_with_master_keyring(
                subject_wallet,
                master_keyring,
                certifier,
                field_name,
                field_value,
                privileged,
                privileged_reason,
                originator,
            )
            .await?;

            let verifiable_key_id =
                Certificate::get_field_encryption_key_id_verifiable(field_name, serial_number);
            let re_encrypted = subject_wallet
                .encrypt(
                    EncryptArgs {
                        plaintext: revelation_key,
                        protocol_id: field_protocol(),
                        key_id: verifiable_key_id,
                        counterparty: Some(Counterparty::Other(verifier.clone())),
                        privileged,
                        privileged_reason: privileged_reason.map(str::to_owned),
                        ..Default::default()
                    },
                    originator,
                )
                .await?;

            keyring.insert(field_name.clone(), to_base64(&re_encrypted.ciphertext));
        }

        Ok(keyring)
    }

    /// Decrypts a field's revelation key from the master keyring and the
    /// field value with it (the reference's `MasterCertificate.decryptField`,
    /// `MasterCertificate.ts:564-625`): the keyring entry's base64 text is
    /// decoded here, for the wallet's decrypt, and nowhere earlier (#268).
    /// Returns the revelation key, 32 bytes, and the plaintext.
    #[allow(clippy::too_many_arguments)]
    async fn decrypt_with_master_keyring<W: WalletInterface>(
        wallet: &W,
        master_keyring: &HashMap<String, String>,
        counterparty: &PublicKey,
        field_name: &str,
        field_value: &str,
        privileged: Option<bool>,
        privileged_reason: Option<&str>,
        originator: &str,
    ) -> Result<(Vec<u8>, String)> {
        let encrypted_key = master_keyring.get(field_name).ok_or_else(|| {
            Error::AuthError(format!(
                "Field '{}' not found in master keyring",
                field_name
            ))
        })?;
        let ciphertext = field_ciphertext(field_name, field_value)?;

        let decrypted = wallet
            .decrypt(
                DecryptArgs {
                    ciphertext: from_base64(encrypted_key)?,
                    protocol_id: field_protocol(),
                    key_id: Certificate::get_field_encryption_key_id_master(field_name),
                    counterparty: Some(Counterparty::Other(counterparty.clone())),
                    privileged,
                    privileged_reason: privileged_reason.map(str::to_owned),
                    ..Default::default()
                },
                originator,
            )
            .await?;

        let key = SymmetricKey::from_bytes(&decrypted.plaintext)?;
        let plaintext = decrypt_field_value(&key, &ciphertext)?;
        Ok((key.as_bytes().to_vec(), plaintext))
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
        // The reference's issueCertificateForSubject takes no privileged pair
        // (`MasterCertificate.ts:437-444`).
        let (encrypted_fields, master_keyring) = Self::create_certificate_fields(
            certifier_wallet,
            &subject,
            plain_fields,
            None,
            None,
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

    /// Decrypts a single field using the master keyring: the field's
    /// revelation key decrypted from `master_keyring`, then the field's base64
    /// text decoded and decrypted with it (decoded here and nowhere earlier,
    /// #261).
    ///
    /// # Arguments
    /// * `subject_wallet` - Subject's wallet for decryption
    /// * `certifier` - Certifier's public key
    /// * `field_name` - Name of the field to decrypt
    /// * `privileged` - The reference's `privileged`, passed to the `decrypt`
    ///   (`MasterCertificate.ts:564-597`)
    /// * `privileged_reason` - The reference's `privilegedReason`, likewise
    /// * `originator` - Application originator
    pub async fn decrypt_field<W: WalletInterface>(
        &self,
        subject_wallet: &W,
        certifier: &PublicKey,
        field_name: &str,
        privileged: Option<bool>,
        privileged_reason: Option<&str>,
        originator: &str,
    ) -> Result<String> {
        let field_value = self.certificate.fields.get(field_name).ok_or_else(|| {
            Error::AuthError(format!("Field '{}' not found in certificate", field_name))
        })?;

        let (_, plaintext) = Self::decrypt_with_master_keyring(
            subject_wallet,
            &self.master_keyring,
            certifier,
            field_name,
            field_value,
            privileged,
            privileged_reason,
            originator,
        )
        .await?;
        Ok(plaintext)
    }

    /// Decrypts all fields using the master keyring, `privileged` and
    /// `privileged_reason` passed to each `decrypt` as the reference's
    /// `MasterCertificate.decryptFields` passes them (`:512-555`).
    pub async fn decrypt_fields<W: WalletInterface>(
        &self,
        subject_wallet: &W,
        certifier: &PublicKey,
        privileged: Option<bool>,
        privileged_reason: Option<&str>,
        originator: &str,
    ) -> Result<HashMap<String, String>> {
        let mut decrypted = HashMap::new();

        for field_name in self.certificate.fields.keys() {
            let value = self
                .decrypt_field(
                    subject_wallet,
                    certifier,
                    field_name,
                    privileged,
                    privileged_reason,
                    originator,
                )
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

/// BRC-52's field encryption protocol: `[2, "certificate field encryption"]`.
pub(crate) fn field_protocol() -> Protocol {
    Protocol::new(
        SecurityLevel::Counterparty,
        CERTIFICATE_FIELD_ENCRYPTION_PROTOCOL,
    )
}

/// A field value's ciphertext: the value held is the ciphertext's base64
/// text (BRC-52 `0052.md:97`), decoded here, at decrypt time, and nowhere
/// earlier (#261), as the reference's `canonicalBase64` decodes it
/// (`ts-stack@edf6e03` `MasterCertificate.ts:63-74`, called at `:215-219`,
/// `:352-356`, `:534-538`, `:587-591`; `VerifiableCertificate.ts:41-52`,
/// `:187-191`): canonical base64 or refused (padded, no whitespace, no URL
/// alphabet, the unused bits zero, `WalletByteEncoding.ts:39-64`), and the
/// bytes 1 to 1 MiB, in its words (bsv-rs#275).
pub(crate) fn field_ciphertext(field_name: &str, field_value: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(field_value)
        .map_err(|_| {
            Error::CertificateValidationError(format!(
                "Certificate field {field_name} must use canonical base64 encoding"
            ))
        })?;
    if decoded.is_empty() || decoded.len() > MAX_CERTIFICATE_FIELD_VALUE_BYTES {
        return Err(Error::CertificateValidationError(format!(
            "Certificate field {field_name} is empty, oversized, or non-canonical"
        )));
    }
    Ok(decoded)
}

/// Decrypts a field's ciphertext ([`field_ciphertext`]) with its revelation
/// key; the plaintext is UTF-8, as the reference's `toUTF8Strict` asks
/// (`MasterCertificate.ts:619`).
pub(crate) fn decrypt_field_value(key: &SymmetricKey, ciphertext: &[u8]) -> Result<String> {
    let plaintext = key.decrypt(ciphertext)?;
    String::from_utf8(plaintext).map_err(|e| Error::InvalidUtf8(e.to_string()))
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

        let mut cert = Certificate::new(
            [1u8; 32],
            [2u8; 32],
            subject.clone(),
            certifier.public_key(),
        );
        cert.sign(&certifier).unwrap();

        let master_cert = MasterCertificate::new(cert, HashMap::new());

        // Should be able to access Certificate fields via Deref
        assert_eq!(master_cert.subject, subject);
        assert_eq!(master_cert.cert_type, [1u8; 32]);
    }
}
