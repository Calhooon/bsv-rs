//! MasterCertificate with field encryption and keyring management.
//!
//! The master certificate contains the encryption keys for all fields,
//! allowing the subject to create keyrings for specific verifiers.

use super::bounds::{
    self, dense_bytes, field_ciphertext, keyring_ciphertext, refused, MASTER_FIELDS_DECRYPT_FAILED,
    MASTER_FIELD_DECRYPT_FAILED, MAX_DECRYPTED_FIELD_BYTES, MAX_KEYRING_VALUE_BYTES,
};
use super::{Certificate, CERTIFICATE_FIELD_ENCRYPTION_PROTOCOL};
use crate::primitives::{to_base64, PublicKey, SymmetricKey};
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
    /// Creates a new master certificate from a base certificate and keyring,
    /// refused as the reference's constructor refuses it
    /// (`ts-stack@edf6e03` `MasterCertificate.ts:195-233`): more than 100
    /// fields or keyring entries (`Certificate fields cannot contain more
    /// than 100 entries`), a name that is not 1 to 50 bytes or is unsafe, a
    /// field with no keyring entry or an empty one, a field's text that is
    /// not canonical base64 of 1 byte to 1 MiB, a keyring entry's not of 1
    /// to 2048 bytes (`Master certificate keyring field <name> is empty,
    /// oversized, or non-canonical`). `Result` since bsv-rs#297; go-sdk's
    /// `NewMasterCertificate` refuses an empty keyring and a missing entry
    /// alone (`go-sdk@2ca481c` `auth/certificates/master.go:39-60`).
    pub fn new(certificate: Certificate, master_keyring: HashMap<String, String>) -> Result<Self> {
        bounds::require_master_certificate(&certificate.fields, &master_keyring)?;
        Ok(Self {
            certificate,
            master_keyring,
        })
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
    /// The fields are snapshotted first (at most 100, each name safe and 1
    /// to 50 bytes, `Certificate plaintext fields cannot contain more than
    /// 100 entries`, `:261`), a plaintext over 64 KiB of UTF-8 is refused
    /// before it is encrypted (`Certificate plaintext field <name> exceeds
    /// the maximum of 65536 bytes`, `:271-276`), and a wallet's ciphertext
    /// outside 1 to 2048 bytes is refused (`Encrypted master keyring field
    /// <name> must be a non-empty byte array of at most 2048 bytes`,
    /// `:292-298`; bsv-rs#297). The fields are taken in byte order.
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
        bounds::snapshot_record(&fields, "Certificate plaintext fields")?;
        let mut encrypted_fields = HashMap::new();
        let mut master_keyring = HashMap::new();
        let mut fields: Vec<(String, String)> = fields.into_iter().collect();
        fields.sort_unstable();

        for (field_name, plain_value) in fields {
            if plain_value.len() > MAX_DECRYPTED_FIELD_BYTES {
                return Err(refused(format!(
                    "Certificate plaintext field {field_name} exceeds the maximum of {MAX_DECRYPTED_FIELD_BYTES} bytes"
                )));
            }
            let field_key = SymmetricKey::random();
            let encrypted_value = dense_bytes(
                field_key.encrypt(plain_value.as_bytes())?,
                &format!("Encrypted certificate field {field_name}"),
                MAX_CERTIFICATE_FIELD_VALUE_BYTES,
            )?;
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
            let entry = dense_bytes(
                encrypt_result.ciphertext,
                &format!("Encrypted master keyring field {field_name}"),
                MAX_KEYRING_VALUE_BYTES,
            )?;
            master_keyring.insert(field_name, to_base64(&entry));
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
    /// Refused, in the reference's order and words: `fields_to_reveal` over
    /// 100 names, with an unsafe name or one twice (`:125-146`); `fields` or
    /// `master_keyring` over 100 entries or with an unsafe name (`:349-350`);
    /// a field's text not canonical base64 of 1 byte to 1 MiB (`:351-357`,
    /// #275) and a keyring entry's not of 1 to 2048 bytes (`:358-364`), every
    /// one, revealed or not; a field to reveal absent or empty (`Fields to
    /// reveal must be a subset of the certificate fields. Missing the
    /// "<name>" field.`, `:371-380`); a field the subject cannot decrypt
    /// (`Failed to decrypt certificate field!`, `decryptField`'s wrapper,
    /// `:621-623`); the wallet's ciphertext for the verifier outside 1 to
    /// 2048 bytes (`Verifier keyring field <name> must be a non-empty byte
    /// array of at most 2048 bytes`, `:405-411`; bsv-rs#297).
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
        bounds::require_keyring_for_verifier_inputs(fields, fields_to_reveal, master_keyring)?;
        let mut keyring = HashMap::new();

        for field_name in fields_to_reveal {
            let field_value = bounds::field_to_reveal(fields, field_name)?;

            let (revelation_key, _) = Self::decrypt_field_wrapped(
                subject_wallet,
                master_keyring,
                certifier,
                field_name,
                Some(field_value),
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
            let entry = dense_bytes(
                re_encrypted.ciphertext,
                &format!("Verifier keyring field {field_name}"),
                MAX_KEYRING_VALUE_BYTES,
            )?;

            keyring.insert(field_name.clone(), to_base64(&entry));
        }

        Ok(keyring)
    }

    /// The reference's `MasterCertificate.decryptField`
    /// (`MasterCertificate.ts:564-624`): every failure under it is one
    /// refusal, `Failed to decrypt certificate field!` (`:621-623`;
    /// bsv-rs#297). `field_value` is `None` for a field the certificate
    /// does not carry, refused under the wrapper as the reference's
    /// `canonicalBase64` refuses an absent value.
    #[allow(clippy::too_many_arguments)]
    async fn decrypt_field_wrapped<W: WalletInterface>(
        wallet: &W,
        master_keyring: &HashMap<String, String>,
        counterparty: &PublicKey,
        field_name: &str,
        field_value: Option<&String>,
        privileged: Option<bool>,
        privileged_reason: Option<&str>,
        originator: &str,
    ) -> Result<(Vec<u8>, String)> {
        let field_value = field_value.ok_or_else(|| refused(MASTER_FIELD_DECRYPT_FAILED))?;
        Self::decrypt_with_master_keyring(
            wallet,
            master_keyring,
            counterparty,
            field_name,
            field_value,
            privileged,
            privileged_reason,
            originator,
        )
        .await
        .map_err(|_| refused(MASTER_FIELD_DECRYPT_FAILED))
    }

    /// Decrypts a field's revelation key from the master keyring and the
    /// field value with it, `decryptField`'s body in its order
    /// (`MasterCertificate.ts:574-620`): the name, the keyring snapshotted
    /// and not empty, the keyring entry canonical base64 of 1 to 2048 bytes
    /// and the field's of 1 byte to 1 MiB, the wallet's decrypt, the key 1
    /// to 32 bytes (a shorter one the historical minimal form, its leading
    /// zeros restored, `:600-611`), the plaintext 1 byte to 64 KiB
    /// (`:612-616`) and UTF-8. The keyring entry's base64 text is decoded
    /// here, for the wallet's decrypt, and nowhere earlier (#268). Returns
    /// the revelation key, 32 bytes, and the plaintext.
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
        bounds::require_master_field_name(field_name)?;
        bounds::snapshot_record(master_keyring, "Master certificate keyring")?;
        if master_keyring.is_empty() {
            return Err(refused(
                "A MasterCertificate must have a valid masterKeyring!",
            ));
        }
        let encrypted_key = keyring_ciphertext(
            "Master certificate keyring field",
            field_name,
            master_keyring.get(field_name).map_or("", String::as_str),
        )?;
        let ciphertext = field_ciphertext(field_name, field_value)?;

        let decrypted = wallet
            .decrypt(
                DecryptArgs {
                    ciphertext: encrypted_key,
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

        let key = dense_bytes(decrypted.plaintext, "Certificate field revelation key", 32)?;
        let key = SymmetricKey::from_bytes(&key)?;
        let plaintext = dense_bytes(
            key.decrypt(&ciphertext)?,
            "Decrypted certificate field",
            MAX_DECRYPTED_FIELD_BYTES,
        )?;
        let plaintext =
            String::from_utf8(plaintext).map_err(|e| Error::InvalidUtf8(e.to_string()))?;
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

        // Build the certificate through the constructor's checks, as the
        // reference's issuance does (`MasterCertificate.ts:474-483`)
        let certificate = Certificate::new(
            cert_type,
            serial_number,
            subject,
            certifier_key.public_key(),
        )
        .with_fields(encrypted_fields);
        let mut master = Self::new(certificate, master_keyring)?;

        // Sign the certificate
        master.certificate.sign(certifier_key)?;

        Ok(master)
    }

    /// Decrypts a single field using the master keyring: the field's
    /// revelation key decrypted from `master_keyring`, then the field's base64
    /// text decoded and decrypted with it (decoded here and nowhere earlier,
    /// #261). Every failure, a field the certificate does not carry with
    /// them, is `Failed to decrypt certificate field!`, the reference's
    /// `decryptField` wrapper (`MasterCertificate.ts:621-623`; bsv-rs#297).
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
        let (_, plaintext) = Self::decrypt_field_wrapped(
            subject_wallet,
            &self.master_keyring,
            certifier,
            field_name,
            self.certificate.fields.get(field_name),
            privileged,
            privileged_reason,
            originator,
        )
        .await?;
        Ok(plaintext)
    }

    /// Decrypts all fields using the master keyring, `privileged` and
    /// `privileged_reason` passed to each `decrypt` as the reference's
    /// `MasterCertificate.decryptFields` passes them (`:512-555`), in its
    /// sequence (bsv-rs#297): the keyring and the fields snapshotted (at
    /// most 100 entries, each name safe, `:520-521`), an empty keyring
    /// refused (`A MasterCertificate must have a valid masterKeyring!`,
    /// `:522-524`), then every keyring entry and every field's text checked
    /// before the first decrypt, and every failure from there on one
    /// refusal, `Failed to decrypt all master certificate fields.`
    /// (`:525-561`).
    pub async fn decrypt_fields<W: WalletInterface>(
        &self,
        subject_wallet: &W,
        certifier: &PublicKey,
        privileged: Option<bool>,
        privileged_reason: Option<&str>,
        originator: &str,
    ) -> Result<HashMap<String, String>> {
        let fields = &self.certificate.fields;
        bounds::snapshot_record(&self.master_keyring, "Master certificate keyring")?;
        bounds::snapshot_record(fields, "Certificate fields")?;
        if self.master_keyring.is_empty() {
            return Err(refused(
                "A MasterCertificate must have a valid masterKeyring!",
            ));
        }
        let all_failed = |_| refused(MASTER_FIELDS_DECRYPT_FAILED);
        for (field_name, entry) in &self.master_keyring {
            keyring_ciphertext("Master certificate keyring field", field_name, entry)
                .map_err(all_failed)?;
        }
        for (field_name, field_value) in fields {
            field_ciphertext(field_name, field_value).map_err(all_failed)?;
        }
        let mut decrypted = HashMap::new();
        for field_name in fields.keys() {
            let value = self
                .decrypt_field(
                    subject_wallet,
                    certifier,
                    field_name,
                    privileged,
                    privileged_reason,
                    originator,
                )
                .await
                .map_err(all_failed)?;
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
        let master_cert = MasterCertificate::new(cert, master_keyring).unwrap();

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

        let master_cert = MasterCertificate::new(cert, HashMap::new()).unwrap();

        // Should be able to access Certificate fields via Deref
        assert_eq!(master_cert.subject, subject);
        assert_eq!(master_cert.cert_type, [1u8; 32]);
    }
}
