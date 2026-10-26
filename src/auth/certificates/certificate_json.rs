//! The JSON of [`Certificate`]: the reference's (`ts-stack@edf6e03`
//! `Certificate.ts:150-212`, go-sdk@2ca481c `auth/certificates/certificate.go:32-52`;
//! #268). `type` and `serialNumber` base64, the signature's DER bytes hex,
//! `revocationOutpoint` always a string (`Certificate.ts:174`, `:257-258`),
//! `None` the binary form's sentinel, the txid alone read as index 0
//! (`MasterCertificate.ts:112-123`, `:442`). The serde impls are a remote
//! derive over the struct's own fields.

use super::Certificate;
use crate::primitives::PublicKey;
use crate::wallet::types::Outpoint;
use crate::Result;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;

impl Serialize for Certificate {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        CertificateJson::serialize(self, serializer)
    }
}

impl<'de> Deserialize<'de> for Certificate {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        CertificateJson::deserialize(deserializer)
    }
}

/// [`Certificate`]'s fields and their serde attributes.
#[derive(Serialize, Deserialize)]
#[serde(
    remote = "Certificate",
    rename = "Certificate",
    rename_all = "camelCase"
)]
struct CertificateJson {
    #[serde(rename = "type", with = "base64_32_bytes")]
    cert_type: [u8; 32],

    #[serde(with = "base64_32_bytes")]
    serial_number: [u8; 32],

    subject: PublicKey,

    certifier: PublicKey,

    #[serde(default, with = "revocation_outpoint_json")]
    revocation_outpoint: Option<Outpoint>,

    #[serde(default)]
    fields: HashMap<String, String>,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "signature_hex"
    )]
    signature: Option<Vec<u8>>,

    #[serde(skip)]
    received_unsigned: Option<Vec<u8>>,
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
/// Only exactly 64 hex characters read as a txid alone (the reference's own
/// case, `MasterCertificate.ts:117`); every other text is `Outpoint`'s, with
/// its words.
pub(crate) fn revocation_outpoint_from_str(text: &str) -> Result<Outpoint> {
    if text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit()) {
        Outpoint::from_string(&format!("{text}.0"))
    } else {
        Outpoint::from_string(text)
    }
}

/// Serde module for the revocation outpoint: `None` written as the binary
/// form's sentinel string, read back from it, from `null` or from no key; a
/// txid alone read as index 0 (`revocation_outpoint_from_str`).
mod revocation_outpoint_json {
    use crate::wallet::types::Outpoint;
    use serde::de::value::MapAccessDeserializer;
    use serde::de::{self, MapAccess, Visitor};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// The text the reference writes, the object form `Outpoint` reads, or
    /// nothing; a refusal in `Outpoint`'s own words.
    struct Read;

    impl<'de> Visitor<'de> for Read {
        type Value = Option<Outpoint>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a string like 'txid.vout' or an object with txid and vout fields")
        }

        fn visit_str<E: de::Error>(self, text: &str) -> Result<Self::Value, E> {
            super::revocation_outpoint_from_str(text)
                .map(Some)
                .map_err(de::Error::custom)
        }

        fn visit_map<M: MapAccess<'de>>(self, map: M) -> Result<Self::Value, M::Error> {
            Outpoint::deserialize(MapAccessDeserializer::new(map)).map(Some)
        }

        fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_some<D: Deserializer<'de>>(
            self,
            deserializer: D,
        ) -> Result<Self::Value, D::Error> {
            deserializer.deserialize_any(Read)
        }
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
        let outpoint = deserializer.deserialize_any(Read)?;
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
