//! VerifiableCertificate with verifier-specific keyring.
//!
//! A verifiable certificate includes a keyring that allows a specific
//! verifier to decrypt selected fields.

use super::bounds::{
    self, field_ciphertext, keyring_ciphertext, refused, verifiable_decrypt_failed,
    MAX_DECRYPTED_FIELD_BYTES, MAX_RECORD_ENTRIES,
};
use super::master::field_protocol;
use super::Certificate;
use crate::primitives::{PublicKey, SymmetricKey};
use crate::wallet::{Counterparty, DecryptArgs, WalletInterface};
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

    /// Keyring for this verifier: field_name -> the base64 text of the
    /// field's revelation key encrypted to the verifier, held as the
    /// reference's `Record<CertificateFieldNameUnder50Bytes, string>`
    /// (`ts-stack@edf6e03` `VerifiableCertificate.ts:90`) and Go's
    /// `map[..]wallet.StringBase64` (`go-sdk@2ca481c`
    /// `auth/certificates/verifiable.go:23`) hold it, and written so in JSON;
    /// decoded only where the wallet decrypts (#268). Only fields in the
    /// keyring can be decrypted.
    #[serde(default)]
    pub keyring: HashMap<String, String>,

    /// Cached decrypted field values.
    #[serde(skip)]
    decrypted_fields: Option<HashMap<String, String>>,
}

impl VerifiableCertificate {
    /// Creates a verifiable certificate from a base certificate and keyring.
    pub fn new(certificate: Certificate, keyring: HashMap<String, String>) -> Self {
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

    /// Decrypts a single field using the verifier keyring, as the
    /// reference's `VerifiableCertificate.decryptFields` does
    /// (`ts-stack@edf6e03` `VerifiableCertificate.ts:152-219`): the keyring
    /// entry is the field's revelation key encrypted to the verifier under
    /// key ID `"<serial base64> <field>"`, its base64 text decoded for the
    /// wallet's decrypt here and nowhere earlier (#268); the field's base64
    /// text is decoded and decrypted with that key here, and nowhere earlier
    /// (#261). The
    /// counterparty is the certificate's subject, read from the certificate
    /// as the reference reads `this.subject` (`:196`) and Go `vc.Subject`
    /// (`go-sdk@2ca481c` `auth/certificates/verifiable.go:76-99`).
    ///
    /// The field's decryption is `decryptFields`' loop body for that field,
    /// every failure in it refused as `decryptFields` refuses it
    /// (`Failed to decrypt selectively revealed certificate fields using
    /// keyring: <words>`, `:214-217`; bsv-rs#297); a field with no keyring
    /// entry, which that loop never reaches, is refused in this crate's
    /// words.
    ///
    /// # Arguments
    /// * `verifier_wallet` - Verifier's wallet for decryption
    /// * `field_name` - Name of the field to decrypt
    /// * `privileged` - The reference's `privileged`, passed to the `decrypt`
    ///   (`:154`, `:197`)
    /// * `privileged_reason` - The reference's `privilegedReason`, likewise
    /// * `originator` - Application originator
    pub async fn decrypt_field<W: WalletInterface>(
        &self,
        verifier_wallet: &W,
        field_name: &str,
        privileged: Option<bool>,
        privileged_reason: Option<&str>,
        originator: Option<&str>,
    ) -> Result<String> {
        let encrypted_key = self.keyring.get(field_name).ok_or_else(|| {
            Error::AuthError(format!(
                "Field '{}' not in keyring (not revealed for this verifier)",
                field_name
            ))
        })?;
        self.decrypt_keyring_field(
            verifier_wallet,
            field_name,
            encrypted_key,
            privileged,
            privileged_reason,
            originator,
        )
        .await
        .map_err(|e| verifiable_decrypt_failed(&e))
    }

    /// `decryptFields`' loop body for one keyring entry, in its order
    /// (`VerifiableCertificate.ts:174-211`): the name safe and 1 to 50 bytes,
    /// the entry canonical base64 of 1 to 2048 bytes, the field present and
    /// its text canonical base64 of 1 byte to 1 MiB, the wallet's decrypt,
    /// the key exactly 32 bytes, the plaintext at most 64 KiB and UTF-8.
    async fn decrypt_keyring_field<W: WalletInterface>(
        &self,
        verifier_wallet: &W,
        field_name: &str,
        encrypted_key: &str,
        privileged: Option<bool>,
        privileged_reason: Option<&str>,
        originator: Option<&str>,
    ) -> Result<String> {
        if !bounds::is_safe_field_name(field_name) {
            return Err(refused("Certificate keyring contains an unsafe field name"));
        }
        let encrypted_key =
            keyring_ciphertext("Certificate keyring field", field_name, encrypted_key)?;
        let field_value = self.certificate.fields.get(field_name).ok_or_else(|| {
            refused(format!(
                "Certificate field {field_name} must be an own string data property"
            ))
        })?;
        let ciphertext = field_ciphertext(field_name, field_value)?;

        let key_id = Certificate::get_field_encryption_key_id_verifiable(
            field_name,
            &self.certificate.serial_number,
        );

        let decrypted = verifier_wallet
            .decrypt(
                DecryptArgs {
                    ciphertext: encrypted_key,
                    protocol_id: field_protocol(),
                    key_id,
                    counterparty: Some(Counterparty::Other(self.certificate.subject.clone())),
                    privileged,
                    privileged_reason: privileged_reason.map(str::to_owned),
                    ..Default::default()
                },
                originator,
            )
            .await?;

        if decrypted.plaintext.len() != 32 {
            return Err(refused(
                "Certificate field revelation key must be a 32-byte array",
            ));
        }
        let key = SymmetricKey::from_bytes(&decrypted.plaintext)?;
        let plaintext = key.decrypt(&ciphertext)?;
        if plaintext.len() > MAX_DECRYPTED_FIELD_BYTES {
            return Err(refused("Decrypted certificate field is oversized"));
        }
        String::from_utf8(plaintext).map_err(|e| Error::InvalidUtf8(e.to_string()))
    }

    /// Decrypts all fields that have keys in the keyring, `privileged` and
    /// `privileged_reason` passed to each `decrypt` as the reference's
    /// `VerifiableCertificate.decryptFields` passes them (`:152-198`). An
    /// empty keyring is refused (`A keyring is required to decrypt
    /// certificate fields for the verifier.`, `:161-163`), one of more than
    /// 100 entries too (`Certificate keyring cannot contain more than 100
    /// fields`, `:164-166`), and every failure decrypting an entry is
    /// `Failed to decrypt selectively revealed certificate fields using
    /// keyring: <words>` (`:168-218`; bsv-rs#297). The entries are taken in
    /// byte order.
    ///
    /// Results are cached for subsequent calls.
    pub async fn decrypt_fields<W: WalletInterface>(
        &mut self,
        verifier_wallet: &W,
        privileged: Option<bool>,
        privileged_reason: Option<&str>,
        originator: Option<&str>,
    ) -> Result<HashMap<String, String>> {
        // Return cached result if available
        if let Some(ref cached) = self.decrypted_fields {
            return Ok(cached.clone());
        }

        if self.keyring.is_empty() {
            return Err(refused(
                "A keyring is required to decrypt certificate fields for the verifier.",
            ));
        }
        if self.keyring.len() > MAX_RECORD_ENTRIES {
            return Err(refused(format!(
                "Certificate keyring cannot contain more than {MAX_RECORD_ENTRIES} fields"
            )));
        }
        let mut entries: Vec<(&String, &String)> = self.keyring.iter().collect();
        entries.sort_unstable();
        let mut decrypted = HashMap::new();

        for (field_name, encrypted_key) in entries {
            let value = self
                .decrypt_keyring_field(
                    verifier_wallet,
                    field_name,
                    encrypted_key,
                    privileged,
                    privileged_reason,
                    originator,
                )
                .await
                .map_err(|e| verifiable_decrypt_failed(&e))?;
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

    /// Converts to a JSON-serializable format, the reference's shape: each
    /// field value its held base64 text (#261), the signature hex and the
    /// keyring's values their held base64 text (#268): the type's serde.
    pub fn to_json_value(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_default()
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

        let mut cert = Certificate::new(
            [1u8; 32],
            [2u8; 32],
            subject.clone(),
            certifier.public_key(),
        );
        cert.sign(&certifier).unwrap();

        let mut keyring = HashMap::new();
        keyring.insert("name".to_string(), "AQID".to_string());

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

        let mut cert = Certificate::new(
            [1u8; 32],
            [2u8; 32],
            subject.clone(),
            certifier.public_key(),
        );
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
        cert.set_field("email", "BAUG");
        cert.sign(&certifier).unwrap();

        let mut keyring = HashMap::new();
        keyring.insert("email".to_string(), "BwgJ".to_string());

        let verifiable = VerifiableCertificate::new(cert, keyring);
        let json = verifiable.to_json_value();

        assert!(json.get("type").is_some());
        assert!(json.get("serialNumber").is_some());
        assert!(json.get("keyring").is_some());
    }
}
