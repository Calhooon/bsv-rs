//! Base Certificate type (BRC-52).
//!
//! A certificate binds identity attributes to a public key,
//! signed by a trusted certifier.

use crate::primitives::{bounded_capacity, sha256, to_hex, PrivateKey, PublicKey, Signature};
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
/// Its JSON is the reference's (`ts-stack@edf6e03` `Certificate.ts:150-212`,
/// go-sdk@2ca481c `auth/certificates/certificate.go:32-52`): `type` and
/// `serialNumber` base64, `subject` and `certifier` hex, `revocationOutpoint`
/// `<txid>.<index>`, `fields` the base64 strings, `signature` the DER bytes
/// in hex (#268). A key the reader does not know is ignored, as the
/// reference's `fromObject` ignores it.
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
/// let fields = HashMap::from([("email".to_string(), "ZW1haWw=".to_string())]);
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
    /// Base64 encoded in JSON, under the reference's key `type` (#268).
    #[serde(rename = "type", with = "base64_32_bytes")]
    pub cert_type: [u8; 32],

    /// Unique serial number (32 bytes).
    /// Base64 encoded in JSON.
    #[serde(with = "base64_32_bytes")]
    pub serial_number: [u8; 32],

    /// Subject's identity public key.
    pub subject: PublicKey,

    /// Certifier's public key.
    pub certifier: PublicKey,

    /// Revocation outpoint (txid.output_index). `None` is the binary
    /// form's sentinel, 32 zero bytes and index 0, and its JSON is that
    /// sentinel's string, as the reference's `revocationOutpoint` is always a
    /// string (`Certificate.ts:174`, `:257-258`); the reader takes the
    /// sentinel, `null` (Go's nil, `certificate.go:46`) or no key as `None`
    /// (#268).
    #[serde(default, with = "revocation_outpoint_json")]
    pub revocation_outpoint: Option<Outpoint>,

    /// Field values (name -> base64 text), signed and written as the text's UTF-8 bytes
    /// (`brcs@5119a9b` `0052.md:41,97`; `ts-stack@edf6e03` `Certificate.ts:294-296`; `go-sdk@2ca481c` `wallet/interfaces.go:122`; #261).
    #[serde(default)]
    pub fields: HashMap<String, String>,

    /// Certificate signature (DER-encoded). Hex in JSON, as the
    /// reference's `HexString` (`Certificate.ts:184`) and Go's
    /// `util.ByteString` (`certificate.go:52`) write it (#268).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "signature_hex"
    )]
    pub signature: Option<Vec<u8>>,

    /// The unsigned prefix as the issuer wrote it: set by
    /// [`from_binary`](Self::from_binary) and by [`sign`](Self::sign), never
    /// carried in JSON. `verify`, `signing_hash` and `to_binary` use these
    /// bytes while they read back to the certificate's current values and
    /// the serializer's order otherwise; the `set_*` methods that change a
    /// value in the preimage clear it (#249).
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
    pub fn with_fields(mut self, fields: HashMap<String, String>) -> Self {
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
        self.received_unsigned = None;
        self.revocation_outpoint = revocation_outpoint;
    }

    /// Replaces every field, each value its base64 text (#261).
    pub fn set_fields(&mut self, fields: HashMap<String, String>) {
        self.received_unsigned = None;
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
    /// [fields: each with varint-prefixed name and value]
    /// [signature: raw DER bytes if included and present]
    /// ```
    ///
    /// The unsigned prefix is [`received_unsigned`](Self::received_unsigned)
    /// while those bytes read back to this certificate's values (the bytes
    /// the issuer signed, BRC-52 `0052.md:103`; #249), and the serializer's
    /// field order otherwise.
    ///
    /// # Arguments
    /// * `include_signature` - Whether to include signature in output
    pub fn to_binary(&self, include_signature: bool) -> Vec<u8> {
        let mut buf = self.unsigned_bytes();

        // Signature: raw bytes, no length prefix (matches TypeScript SDK)
        if include_signature {
            if let Some(ref sig) = self.signature {
                buf.extend_from_slice(sig);
            }
            // If no signature, write nothing (not even a marker byte)
        }

        buf
    }

    /// The unsigned prefix: the retained bytes when they bind to the
    /// current values, the serializer's otherwise.
    fn unsigned_bytes(&self) -> Vec<u8> {
        match self.received_unsigned {
            Some(ref bytes) if self.binds(bytes) => bytes.clone(),
            _ => self.serialize_unsigned(),
        }
    }

    /// Whether `bytes` parse, whole, to exactly this certificate's values:
    /// a value changed after the bytes were retained (through a public
    /// field as well as a setter) unbinds them, so they never authenticate
    /// values they do not carry (BRC-52 `0052.md:103`).
    fn binds(&self, bytes: &[u8]) -> bool {
        let mut reader = BinaryReader::new(bytes);
        match read_unsigned(&mut reader) {
            Ok(u) => {
                reader.remaining() == 0
                    && u.cert_type == self.cert_type
                    && u.serial_number == self.serial_number
                    && u.subject == self.subject
                    && u.certifier == self.certifier
                    && u.revocation_outpoint == self.revocation_outpoint
                    && u.fields == self.fields
            }
            Err(_) => false,
        }
    }

    /// The serializer's unsigned prefix.
    fn serialize_unsigned(&self) -> Vec<u8> {
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

        // Fields in the reference's order: `localeCompare` under Node's
        // default collation (`ts-stack@edf6e03` `Certificate.ts:282`), not
        // the bytes (#249; the residual is `collation.rs`'s), the wire
        // writer's order too (#246)
        let mut field_names: Vec<&str> = self.fields.keys().map(String::as_str).collect();
        crate::wallet::collation::sort_field_names(&mut field_names);

        for name in field_names {
            let value = &self.fields[name];
            // Field name (length-prefixed string)
            write_varint(&mut buf, name.len() as u64);
            buf.extend_from_slice(name.as_bytes());
            // Field value (length-prefixed bytes)
            write_varint(&mut buf, value.len() as u64);
            buf.extend_from_slice(value.as_bytes());
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
    /// [fields: in the issuer's order, each with varint-prefixed name and value]
    /// [signature: remaining bytes if present]
    /// ```
    ///
    /// The unsigned prefix is kept as received in
    /// [`received_unsigned`](Self::received_unsigned), so `verify` and
    /// `to_binary` use the issuer's bytes whatever order its fields came in
    /// (BRC-52 `0052.md:103`; #249). A repeated field name is refused, as
    /// the reference refuses it (`ts-stack@edf6e03` `Certificate.ts:374`):
    /// retaining bytes must not make one acceptable.
    pub fn from_binary(data: &[u8]) -> Result<Self> {
        let mut reader = BinaryReader::new(data);
        let unsigned = read_unsigned(&mut reader)?;
        let received_unsigned = data.get(..reader.pos).unwrap_or_default().to_vec();

        // Signature: remaining bytes (no length prefix) - matches TypeScript SDK
        let signature = if reader.remaining() > 0 {
            Some(reader.read_remaining())
        } else {
            None
        };

        Ok(Self {
            cert_type: unsigned.cert_type,
            serial_number: unsigned.serial_number,
            subject: unsigned.subject,
            certifier: unsigned.certifier,
            revocation_outpoint: unsigned.revocation_outpoint,
            fields: unsigned.fields,
            signature,
            received_unsigned: Some(received_unsigned),
        })
    }

    /// Gets the hash to sign (SHA-256 of binary without signature).
    pub fn signing_hash(&self) -> [u8; 32] {
        sha256(&self.unsigned_bytes())
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
    /// `certificate.go:227-240`), over the SHA-256 of the serializer's
    /// unsigned prefix, written afresh in the reference's field order as the
    /// reference's `sign` writes it (`Certificate.ts:458`): a received
    /// prefix in another order is not re-signed. The preimage it signed is
    /// kept in [`received_unsigned`](Self::received_unsigned) (#249).
    /// A certificate already signed is refused in the reference's words
    /// (`Certificate.ts:450-453`); clear it with
    /// [`set_signature(None)`](Self::set_signature) to re-sign (#262).
    pub fn sign(&mut self, certifier_key: &PrivateKey) -> Result<()> {
        if let Some(present) = self.signature.as_ref().filter(|s| !s.is_empty()) {
            return Err(Error::CertificateValidationError(format!(
                "Certificate has already been signed! Signature present: {}",
                to_hex(present)
            )));
        }

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
        let preimage = self.serialize_unsigned();
        let sig = child.sign(&sha256(&preimage))?;
        self.signature = Some(sig.to_der());
        self.received_unsigned = Some(preimage);
        Ok(())
    }

    /// Verifies the certificate signature against the certifier's child key
    /// under BRC-52's derivation, derived with the anyone key as the
    /// reference derives it (`ts-stack@edf6e03` `Certificate.ts:428-431`;
    /// go-sdk@2ca481c `certificate.go:176-186`). A signature by the
    /// certifier's raw key is `Ok(false)` (#251). The preimage is
    /// [`received_unsigned`](Self::received_unsigned) while it binds to the
    /// current values, never a re-sort of the issuer's fields (#249).
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

    /// Sets a field value: its base64 text, any string, as the reference takes it (#261).
    ///
    /// ```
    /// use bsv_rs::{auth::certificates::Certificate, primitives::{to_base64, PrivateKey}};
    /// let key = PrivateKey::random().public_key();
    /// let mut cert = Certificate::new([1; 32], [2; 32], key.clone(), key);
    /// cert.set_field("email", to_base64(&[0xff, 0xfe, 0x41]));
    /// assert!(cert.to_binary(false).windows(11).any(|w| w == b"\x05email\x04//5B"));
    /// ```
    pub fn set_field(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.received_unsigned = None;
        self.fields.insert(name.into(), value.into());
    }

    /// Gets a field value: its base64 text, as held.
    pub fn get_field(&self, name: &str) -> Option<&String> {
        self.fields.get(name)
    }

    /// Returns all field names.
    pub fn field_names(&self) -> Vec<&String> {
        self.fields.keys().collect()
    }

    /// Converts to wallet certificate format, each field its text (#261).
    pub fn to_wallet_certificate(&self) -> crate::wallet::types::Certificate {
        crate::wallet::types::Certificate {
            certificate_type: self.type_base64(),
            subject: self.subject.clone(),
            serial_number: self.serial_number_base64(),
            certifier: self.certifier.clone(),
            revocation_outpoint: self.revocation_outpoint.clone(),
            fields: self.fields.clone(),
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

/// The values of a certificate's unsigned prefix.
struct Unsigned {
    cert_type: [u8; 32],
    serial_number: [u8; 32],
    subject: PublicKey,
    certifier: PublicKey,
    revocation_outpoint: Option<Outpoint>,
    fields: HashMap<String, String>,
}

/// Reads a certificate's unsigned prefix, the reader left at the signature.
fn read_unsigned(reader: &mut BinaryReader<'_>) -> Result<Unsigned> {
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
    let mut fields = HashMap::with_capacity(bounded_capacity(field_count, reader.remaining(), 2));
    for _ in 0..field_count {
        let name_len = reader.read_len()?;
        let name = String::from_utf8(reader.read_bytes(name_len)?.to_vec())
            .map_err(|e| Error::InvalidUtf8(e.to_string()))?;
        if fields.contains_key(&name) {
            return Err(Error::CertificateValidationError(format!(
                "Duplicate certificate field name: {}",
                name
            )));
        }
        let value_len = reader.read_len()?;
        // UTF-8 or refused, as `toUTF8Strict` (`Certificate.ts:384`; BRC-52 `0052.md:103`; #261)
        let value = std::str::from_utf8(reader.read_bytes(value_len)?).map_err(|e| {
            Error::InvalidUtf8(format!(
                "certificate field {name} is not UTF-8 base64 text: {e}"
            ))
        })?;
        fields.insert(name, value.to_string());
    }

    Ok(Unsigned {
        cert_type,
        serial_number,
        subject,
        certifier,
        revocation_outpoint,
        fields,
    })
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
    /// with the field named, never truncated to another index (#122), in the
    /// bound refusal's one form (`integer_refusal`). The reference's reader
    /// has no words here: it reads the index with `readVarIntNumStrict(false)`
    /// and no bound (`ts-stack@edf6e03` `Certificate.ts:353`), so the field's
    /// name is this crate's (#258).
    fn read_varint_index(&mut self, field: &str) -> Result<u32> {
        let value = self.read_varint()?;
        u32::try_from(value).map_err(|_| {
            Error::CertificateValidationError(crate::wallet::wire::integer_refusal(
                field,
                value,
                0,
                u32::MAX.into(),
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

/// Reads a certificate's revocation outpoint from its text: `<txid>.<index>`,
/// or the txid alone as index 0, as the reference reads it
/// (`ts-stack@edf6e03` `Certificate.ts:261-262`, `MasterCertificate.ts:112-123`):
/// its default issuance writes the txid alone (`MasterCertificate.ts:442`).
/// go-sdk@2ca481c refuses the txid alone (`transaction/outpoint.go:50`).
pub(crate) fn revocation_outpoint_from_str(text: &str) -> Result<Outpoint> {
    if text.contains('.') {
        Outpoint::from_string(text)
    } else {
        Outpoint::from_string(&format!("{text}.0"))
    }
}

/// Serde module for the revocation outpoint: `None` written as the binary
/// form's sentinel string, read back from it, from `null` or from no key; a
/// txid alone read as index 0 (`revocation_outpoint_from_str`).
mod revocation_outpoint_json {
    use crate::wallet::types::Outpoint;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// The text the reference writes, or the object form `Outpoint` reads.
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Read {
        Text(String),
        Object(Outpoint),
    }

    pub fn serialize<S>(outpoint: &Option<Outpoint>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match outpoint {
            Some(outpoint) => outpoint.serialize(serializer),
            None => Outpoint::new([0u8; 32], 0).serialize(serializer),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Outpoint>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let outpoint = match Option::<Read>::deserialize(deserializer)? {
            Some(Read::Text(text)) => {
                Some(super::revocation_outpoint_from_str(&text).map_err(serde::de::Error::custom)?)
            }
            Some(Read::Object(outpoint)) => Some(outpoint),
            None => None,
        };
        Ok(outpoint.filter(|o| o.txid != [0u8; 32] || o.vout != 0))
    }
}

/// Serde module for the signature: its DER bytes as a hex string.
mod signature_hex {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(signature: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match signature {
            Some(bytes) => serializer.serialize_str(&crate::primitives::to_hex(bytes)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<String>::deserialize(deserializer)?
            .map(|hex| crate::primitives::from_hex(&hex).map_err(serde::de::Error::custom))
            .transpose()
    }
}

#[cfg(test)]
#[path = "certificate_tests.rs"]
mod tests;
