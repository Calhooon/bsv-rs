//! Base Certificate type (BRC-52).
//!
//! A certificate binds identity attributes to a public key,
//! signed by a trusted certifier.

use crate::primitives::{bounded_capacity, sha256, PrivateKey, PublicKey, Signature};
use crate::wallet::types::Outpoint;
use crate::wallet::{Counterparty, KeyDeriver, Protocol, SecurityLevel};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Base certificate structure (BRC-52).
///
/// A certificate binds identity attributes to a public key,
/// signed by a trusted certifier. Fields are encrypted for
/// selective disclosure.
///
/// The struct is `#[non_exhaustive]` (#249): build one with
/// [`new`](Self::new) and the `with_*` methods, change one with the `set_*`
/// methods; a struct literal does not compile outside this crate.
///
/// ```
/// use bsv_rs::auth::Certificate;
/// use bsv_rs::primitives::PrivateKey;
/// use bsv_rs::wallet::types::Outpoint;
/// use std::collections::HashMap;
///
/// let certifier = PrivateKey::random();
/// let subject = PrivateKey::random().public_key();
/// let fields = HashMap::from([("email".to_string(), b"ZW1haWw=".to_vec())]);
/// let mut cert = Certificate::new([1u8; 32], [2u8; 32], subject, certifier.public_key())
///     .with_revocation_outpoint(Some(Outpoint::new([3u8; 32], 0)))
///     .with_fields(fields);
/// cert.sign(&certifier).unwrap();
/// assert_eq!(cert.verify(), Ok(true));
/// ```
///
/// ```compile_fail,E0639
/// use bsv_rs::auth::Certificate;
/// use bsv_rs::primitives::PrivateKey;
///
/// let key = PrivateKey::random().public_key();
/// let cert = Certificate {
///     cert_type: [1u8; 32],
///     serial_number: [2u8; 32],
///     subject: key.clone(),
///     certifier: key,
///     revocation_outpoint: None,
///     fields: Default::default(),
///     signature: None,
///     received_unsigned: None,
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Certificate {
    /// Certificate type (32 bytes, identifies the certificate schema).
    /// Base64 encoded in JSON.
    #[serde(with = "base64_32_bytes")]
    pub cert_type: [u8; 32],

    /// Unique serial number (32 bytes).
    /// Base64 encoded in JSON.
    #[serde(with = "base64_32_bytes")]
    pub serial_number: [u8; 32],

    /// Subject's identity public key.
    pub subject: PublicKey,

    /// Certifier's public key.
    pub certifier: PublicKey,

    /// Revocation outpoint (txid.output_index).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_outpoint: Option<Outpoint>,

    /// Encrypted field values (field_name -> encrypted_bytes).
    /// Values are base64 encoded in JSON.
    #[serde(default)]
    pub fields: HashMap<String, Vec<u8>>,

    /// Certificate signature (DER-encoded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<Vec<u8>>,

    /// The unsigned prefix as the issuer wrote it: set by
    /// [`from_binary`](Self::from_binary) and by [`sign`](Self::sign), never
    /// carried in JSON.
    #[serde(skip)]
    pub received_unsigned: Option<Vec<u8>>,
}

impl Certificate {
    /// Creates a new unsigned certificate.
    pub fn new(
        cert_type: [u8; 32],
        serial_number: [u8; 32],
        subject: PublicKey,
        certifier: PublicKey,
    ) -> Self {
        Self {
            cert_type,
            serial_number,
            subject,
            certifier,
            revocation_outpoint: None,
            fields: HashMap::new(),
            signature: None,
            received_unsigned: None,
        }
    }

    /// Returns the certificate with its revocation outpoint set.
    pub fn with_revocation_outpoint(mut self, revocation_outpoint: Option<Outpoint>) -> Self {
        self.set_revocation_outpoint(revocation_outpoint);
        self
    }

    /// Returns the certificate with its fields replaced.
    pub fn with_fields(mut self, fields: HashMap<String, Vec<u8>>) -> Self {
        self.set_fields(fields);
        self
    }

    /// Returns the certificate with its signature set.
    pub fn with_signature(mut self, signature: Option<Vec<u8>>) -> Self {
        self.set_signature(signature);
        self
    }

    /// Sets the revocation outpoint.
    pub fn set_revocation_outpoint(&mut self, revocation_outpoint: Option<Outpoint>) {
        self.revocation_outpoint = revocation_outpoint;
    }

    /// Replaces every field (already encrypted).
    pub fn set_fields(&mut self, fields: HashMap<String, Vec<u8>>) {
        self.fields = fields;
    }

    /// Sets the signature (DER-encoded).
    pub fn set_signature(&mut self, signature: Option<Vec<u8>>) {
        self.signature = signature;
    }

    /// Returns the certificate type as a base64 string.
    pub fn type_base64(&self) -> String {
        crate::primitives::to_base64(&self.cert_type)
    }

    /// Returns the serial number as a base64 string.
    pub fn serial_number_base64(&self) -> String {
        crate::primitives::to_base64(&self.serial_number)
    }

    /// Serializes the certificate to binary format.
    ///
    /// Binary format (compatible with TypeScript SDK):
    /// ```text
    /// [type: 32 bytes]
    /// [serial_number: 32 bytes]
    /// [subject: 33 bytes compressed pubkey]
    /// [certifier: 33 bytes compressed pubkey]
    /// [revocation_txid: 32 bytes]
    /// [revocation_index: varint]
    /// [field_count: varint]
    /// [fields: sorted by name, each with varint-prefixed name and value]
    /// [signature: raw DER bytes if included and present]
    /// ```
    ///
    /// # Arguments
    /// * `include_signature` - Whether to include signature in output
    pub fn to_binary(&self, include_signature: bool) -> Vec<u8> {
        let mut buf = Vec::new();

        // Type (32 bytes)
        buf.extend_from_slice(&self.cert_type);

        // Serial number (32 bytes)
        buf.extend_from_slice(&self.serial_number);

        // Subject pubkey (33 bytes)
        buf.extend_from_slice(&self.subject.to_compressed());

        // Certifier pubkey (33 bytes)
        buf.extend_from_slice(&self.certifier.to_compressed());

        // Revocation outpoint: TXID (32 bytes) + index (varint)
        // No marker byte - matches TypeScript SDK format
        // If no outpoint, use all-zeros TXID and index 0 as sentinel
        if let Some(ref outpoint) = self.revocation_outpoint {
            buf.extend_from_slice(&outpoint.txid);
            write_varint(&mut buf, outpoint.vout as u64);
        } else {
            // Sentinel value for "no outpoint": all zeros
            buf.extend_from_slice(&[0u8; 32]);
            write_varint(&mut buf, 0);
        }

        // Fields count (varint)
        write_varint(&mut buf, self.fields.len() as u64);

        // Fields (sorted by name for deterministic serialization)
        let mut field_names: Vec<_> = self.fields.keys().collect();
        field_names.sort();

        for name in field_names {
            let value = &self.fields[name];
            // Field name (length-prefixed string)
            write_varint(&mut buf, name.len() as u64);
            buf.extend_from_slice(name.as_bytes());
            // Field value (length-prefixed bytes)
            write_varint(&mut buf, value.len() as u64);
            buf.extend_from_slice(value);
        }

        // Signature: raw bytes, no length prefix (matches TypeScript SDK)
        if include_signature {
            if let Some(ref sig) = self.signature {
                buf.extend_from_slice(sig);
            }
            // If no signature, write nothing (not even a marker byte)
        }

        buf
    }

    /// Parses a certificate from binary format.
    ///
    /// Binary format (compatible with TypeScript SDK):
    /// ```text
    /// [type: 32 bytes]
    /// [serial_number: 32 bytes]
    /// [subject: 33 bytes compressed pubkey]
    /// [certifier: 33 bytes compressed pubkey]
    /// [revocation_txid: 32 bytes]
    /// [revocation_index: varint]
    /// [field_count: varint]
    /// [fields: sorted by name, each with varint-prefixed name and value]
    /// [signature: remaining bytes if present]
    /// ```
    pub fn from_binary(data: &[u8]) -> Result<Self> {
        let mut reader = BinaryReader::new(data);

        // Type (32 bytes)
        let mut cert_type = [0u8; 32];
        cert_type.copy_from_slice(reader.read_bytes(32)?);

        // Serial number (32 bytes)
        let mut serial_number = [0u8; 32];
        serial_number.copy_from_slice(reader.read_bytes(32)?);

        // Subject pubkey (33 bytes)
        let subject = PublicKey::from_bytes(reader.read_bytes(33)?)?;

        // Certifier pubkey (33 bytes)
        let certifier = PublicKey::from_bytes(reader.read_bytes(33)?)?;

        // Revocation outpoint: TXID (32 bytes) + index (varint)
        // No marker byte - matches TypeScript SDK format
        // All-zeros TXID with index 0 is treated as "no outpoint"
        let mut txid = [0u8; 32];
        txid.copy_from_slice(reader.read_bytes(32)?);
        let vout = reader.read_varint_index("revocation outpoint index")?;

        // Treat all-zeros TXID with index 0 as "no outpoint"
        let revocation_outpoint = if txid == [0u8; 32] && vout == 0 {
            None
        } else {
            Some(Outpoint::new(txid, vout))
        };

        // Fields
        let field_count = reader.read_len()?;
        // Each field is >= 2 bytes (name len varint + value len varint); bound
        // the pre-allocation so a bogus count cannot OOM-abort before any read.
        let mut fields =
            HashMap::with_capacity(bounded_capacity(field_count, reader.remaining(), 2));
        for _ in 0..field_count {
            let name_len = reader.read_len()?;
            let name = String::from_utf8(reader.read_bytes(name_len)?.to_vec())
                .map_err(|e| Error::InvalidUtf8(e.to_string()))?;
            let value_len = reader.read_len()?;
            let value = reader.read_bytes(value_len)?.to_vec();
            fields.insert(name, value);
        }

        // Signature: remaining bytes (no length prefix) - matches TypeScript SDK
        let signature = if reader.remaining() > 0 {
            Some(reader.read_remaining())
        } else {
            None
        };

        Ok(Self {
            cert_type,
            serial_number,
            subject,
            certifier,
            revocation_outpoint,
            fields,
            signature,
            received_unsigned: None,
        })
    }

    /// Gets the hash to sign (SHA-256 of binary without signature).
    pub fn signing_hash(&self) -> [u8; 32] {
        sha256(&self.to_binary(false))
    }

    /// The BRC-52 signature key ID: `"<type> <serialNumber>"`, the two
    /// base64 strings separated by one space (BRC-52 `0052.md:116`).
    pub fn signature_key_id(&self) -> String {
        format!("{} {}", self.type_base64(), self.serial_number_base64())
    }

    /// Signs the certificate with the certifier's child key under BRC-52's
    /// derivation: protocol `[2, "certificate signature"]`, key ID
    /// [`signature_key_id`](Self::signature_key_id), counterparty anyone
    /// (BRC-52 `0052.md:77,115-117`; the reference's `Certificate.sign`,
    /// `ts-stack@edf6e03` `Certificate.ts:458-462`; go-sdk@2ca481c
    /// `certificate.go:227-240`), over the SHA-256 of `to_binary(false)`.
    pub fn sign(&mut self, certifier_key: &PrivateKey) -> Result<()> {
        // Verify the certifier key matches
        if certifier_key.public_key() != self.certifier {
            return Err(Error::CryptoError(
                "Certifier key does not match certificate certifier".into(),
            ));
        }

        let child = KeyDeriver::new(Some(certifier_key.clone())).derive_private_key(
            &signature_protocol(),
            &self.signature_key_id(),
            &Counterparty::Anyone,
        )?;
        let hash = self.signing_hash();
        let sig = child.sign(&hash)?;
        self.signature = Some(sig.to_der());
        Ok(())
    }

    /// Verifies the certificate signature against the certifier's child key
    /// under BRC-52's derivation, derived with the anyone key as the
    /// reference derives it (`ts-stack@edf6e03` `Certificate.ts:428-431`;
    /// go-sdk@2ca481c `certificate.go:176-186`). A signature by the
    /// certifier's raw key is `Ok(false)` (#251).
    pub fn verify(&self) -> Result<bool> {
        let sig_bytes = self
            .signature
            .as_ref()
            .ok_or_else(|| Error::InvalidSignature("Certificate not signed".into()))?;

        let hash = self.signing_hash();
        let sig = Signature::from_der(sig_bytes)?;

        let child = KeyDeriver::new(None).derive_public_key(
            &signature_protocol(),
            &self.signature_key_id(),
            &Counterparty::Other(self.certifier.clone()),
            false,
        )?;
        Ok(child.verify(&hash, &sig))
    }

    /// Gets the encryption protocol details for a certificate field.
    ///
    /// For master certificates (encrypting from certifier to subject),
    /// the key ID is just the field name.
    ///
    /// Returns (protocol_name, key_id)
    pub fn get_field_encryption_key_id_master(field_name: &str) -> String {
        field_name.to_string()
    }

    /// Gets the encryption protocol details for a verifiable certificate field.
    ///
    /// For verifiable certificates (decrypting with verifier keyring),
    /// the key ID is "{serial_number} {field_name}".
    ///
    /// Returns (protocol_name, key_id)
    pub fn get_field_encryption_key_id_verifiable(
        field_name: &str,
        serial_number: &[u8; 32],
    ) -> String {
        let serial_b64 = crate::primitives::to_base64(serial_number);
        format!("{} {}", serial_b64, field_name)
    }

    /// Sets a field value (already encrypted).
    pub fn set_field(&mut self, name: impl Into<String>, encrypted_value: Vec<u8>) {
        self.fields.insert(name.into(), encrypted_value);
    }

    /// Gets a field value (encrypted).
    pub fn get_field(&self, name: &str) -> Option<&Vec<u8>> {
        self.fields.get(name)
    }

    /// Returns all field names.
    pub fn field_names(&self) -> Vec<&String> {
        self.fields.keys().collect()
    }

    /// Converts to wallet certificate format.
    pub fn to_wallet_certificate(&self) -> crate::wallet::types::Certificate {
        crate::wallet::types::Certificate {
            certificate_type: self.type_base64(),
            subject: self.subject.clone(),
            serial_number: self.serial_number_base64(),
            certifier: self.certifier.clone(),
            revocation_outpoint: self.revocation_outpoint.clone(),
            fields: self
                .fields
                .iter()
                .map(|(k, v)| (k.clone(), crate::primitives::to_base64(v)))
                .collect(),
            signature: self.signature.clone(),
        }
    }
}

/// BRC-52's signature protocol: `[2, "certificate signature"]`.
fn signature_protocol() -> Protocol {
    Protocol::new(
        SecurityLevel::Counterparty,
        super::CERTIFICATE_SIGNATURE_PROTOCOL,
    )
}

/// Writes a Bitcoin-style varint.
fn write_varint(buf: &mut Vec<u8>, n: u64) {
    if n < 0xfd {
        buf.push(n as u8);
    } else if n <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffffffff {
        buf.push(0xfe);
        buf.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&n.to_le_bytes());
    }
}

/// Simple binary reader for parsing.
struct BinaryReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> BinaryReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        // Compared to the bytes remaining, never `pos + n`: a length read
        // from the input near `usize::MAX` wrapped that sum past the check
        // (#108).
        let underflow = Error::ReaderUnderflow {
            needed: n,
            available: self.remaining(),
        };
        if n > self.remaining() {
            return Err(underflow);
        }
        let slice = self.data.get(self.pos..self.pos + n).ok_or(underflow)?;
        self.pos += n;
        Ok(slice)
    }

    /// Reads a varint length; one that does not fit `usize` (a 32-bit
    /// target) is refused, never truncated to a shorter length.
    fn read_len(&mut self) -> Result<usize> {
        let n = self.read_varint()?;
        usize::try_from(n).map_err(|_| Error::ReaderUnderflow {
            needed: usize::MAX,
            available: self.remaining(),
        })
    }

    fn read_u8(&mut self) -> Result<u8> {
        Ok(self.read_bytes(1)?[0])
    }

    fn read_remaining(&mut self) -> Vec<u8> {
        let remaining = self.data.get(self.pos..).unwrap_or_default().to_vec();
        self.pos = self.data.len();
        remaining
    }

    /// Reads a varint carrying an output index; above `u32::MAX` is refused
    /// with the field named, never truncated to another index.
    fn read_varint_index(&mut self, field: &str) -> Result<u32> {
        let value = self.read_varint()?;
        u32::try_from(value).map_err(|_| {
            Error::CertificateValidationError(format!(
                "invalid {}: expected at most {}, got {}",
                field,
                u32::MAX,
                value
            ))
        })
    }

    fn read_varint(&mut self) -> Result<u64> {
        let first = self.read_u8()?;
        match first {
            0..=0xfc => Ok(first as u64),
            0xfd => {
                let bytes = self.read_bytes(2)?;
                Ok(u16::from_le_bytes([bytes[0], bytes[1]]) as u64)
            }
            0xfe => {
                let bytes = self.read_bytes(4)?;
                Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64)
            }
            0xff => {
                let bytes = self.read_bytes(8)?;
                Ok(u64::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ]))
            }
        }
    }
}

/// Serde module for base64 encoding of 32-byte arrays.
mod base64_32_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&crate::primitives::to_base64(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = crate::primitives::from_base64(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom(format!(
                "expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        let certifier = PrivateKey::random();
        let subject = PrivateKey::random().public_key();

        let mut cert = Certificate::new([1u8; 32], [2u8; 32], subject, certifier.public_key());

        cert.sign(&certifier).unwrap();
        assert!(cert.verify().unwrap());
    }

    #[test]
    fn test_wrong_certifier_rejected() {
        let certifier = PrivateKey::random();
        let wrong_certifier = PrivateKey::random();
        let subject = PrivateKey::random().public_key();

        let mut cert = Certificate::new([1u8; 32], [2u8; 32], subject, certifier.public_key());

        // Trying to sign with wrong key should fail
        assert!(cert.sign(&wrong_certifier).is_err());
    }

    #[test]
    fn test_binary_roundtrip() {
        let certifier = PrivateKey::random();
        let subject = PrivateKey::random().public_key();

        let mut cert = Certificate::new([1u8; 32], [2u8; 32], subject, certifier.public_key());
        cert.fields
            .insert("name".to_string(), b"encrypted_value".to_vec());
        cert.sign(&certifier).unwrap();

        let binary = cert.to_binary(true);
        let parsed = Certificate::from_binary(&binary).unwrap();

        assert_eq!(cert.cert_type, parsed.cert_type);
        assert_eq!(cert.serial_number, parsed.serial_number);
        assert_eq!(cert.subject, parsed.subject);
        assert_eq!(cert.certifier, parsed.certifier);
        assert_eq!(cert.fields, parsed.fields);
        assert!(parsed.verify().unwrap());
    }

    #[test]
    fn test_binary_with_revocation_outpoint() {
        let certifier = PrivateKey::random();
        let subject = PrivateKey::random().public_key();

        let mut cert = Certificate::new([1u8; 32], [2u8; 32], subject, certifier.public_key());
        cert.revocation_outpoint = Some(Outpoint::new([3u8; 32], 5));
        cert.sign(&certifier).unwrap();

        let binary = cert.to_binary(true);
        let parsed = Certificate::from_binary(&binary).unwrap();

        assert!(parsed.revocation_outpoint.is_some());
        let outpoint = parsed.revocation_outpoint.unwrap();
        assert_eq!(outpoint.txid, [3u8; 32]);
        assert_eq!(outpoint.vout, 5);
    }

    #[test]
    fn test_json_roundtrip() {
        let certifier = PrivateKey::random();
        let subject = PrivateKey::random().public_key();

        let mut cert = Certificate::new([1u8; 32], [2u8; 32], subject, certifier.public_key());
        cert.fields
            .insert("name".to_string(), b"encrypted_value".to_vec());
        cert.sign(&certifier).unwrap();

        let json = serde_json::to_string(&cert).unwrap();
        let parsed: Certificate = serde_json::from_str(&json).unwrap();

        assert_eq!(cert.cert_type, parsed.cert_type);
        assert_eq!(cert.serial_number, parsed.serial_number);
        assert!(parsed.verify().unwrap());
    }

    #[test]
    fn test_field_encryption_key_ids() {
        let serial = [42u8; 32];

        let master_key_id = Certificate::get_field_encryption_key_id_master("email");
        assert_eq!(master_key_id, "email");

        let verifiable_key_id =
            Certificate::get_field_encryption_key_id_verifiable("email", &serial);
        assert!(verifiable_key_id.contains("email"));
        assert!(verifiable_key_id.contains(&crate::primitives::to_base64(&serial)));
    }

    #[test]
    fn a_revocation_outpoint_index_above_u32_max_is_refused_not_truncated() {
        let certifier = PrivateKey::random();
        let subject = PrivateKey::random().public_key();
        let mut cert = Certificate::new([1u8; 32], [2u8; 32], subject, certifier.public_key());
        cert.revocation_outpoint = Some(Outpoint::new([3u8; 32], u32::MAX));
        cert.sign(&certifier).unwrap();
        let binary = cert.to_binary(true);

        let parsed = Certificate::from_binary(&binary).unwrap();
        assert_eq!(
            parsed.revocation_outpoint,
            Some(Outpoint::new([3u8; 32], u32::MAX))
        );
        assert!(parsed.verify().unwrap());

        // type(32) serial(32) subject(33) certifier(33) txid(32), then the index
        let at = 32 + 32 + 33 + 33 + 32;
        let mut max = Vec::new();
        write_varint(&mut max, u32::MAX as u64);
        assert_eq!(&binary[at..at + 5], &max[..]);
        let mut over = binary[..at].to_vec();
        write_varint(&mut over, u32::MAX as u64 + 1);
        over.extend_from_slice(&binary[at + 5..]);

        let err = Certificate::from_binary(&over).unwrap_err();
        assert_eq!(
            err,
            Error::CertificateValidationError(
                "invalid revocation outpoint index: expected at most 4294967295, got 4294967296"
                    .to_string()
            )
        );
    }
}
