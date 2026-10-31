//! The JSON forms of the action and certificate shapes that are neither
//! serde's default nor the crate's hex helpers (#105): a transaction id as a
//! hex string where it may be absent, the signable transaction's reference as
//! base64, and `keyringRevealer` as `'certifier'` or the public key's hex, as
//! BRC-100 has them (`wallet/0100.md` at `5119a9b`, `:709`, `:716-719`,
//! `:1255`) and the reference's `HTTPWalletJSON` sends them
//! (`ts-stack@edf6e03` `Wallet.interfaces.ts:233`, `:340-356`, `:439`).

use super::KeyringRevealer;
use crate::primitives::PublicKey;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Serde helper for an optional transaction id as BRC-100's `TXIDHexString`.
/// Use with `#[serde(with = "hex_txid_option", skip_serializing_if = "Option::is_none", default)]`.
pub mod hex_txid_option {
    use super::super::{hex_txid, TxId};
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serializes the 32 bytes as one hex string, or none.
    pub fn serialize<S>(txid: &Option<TxId>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match txid {
            Some(txid) => hex_txid::serialize(txid, serializer),
            None => serializer.serialize_none(),
        }
    }

    /// Deserializes one hex string of 32 bytes, or none, into the array.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<TxId>, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Hex(#[serde(with = "hex_txid")] TxId);
        Ok(Option::<Hex>::deserialize(deserializer)?.map(|Hex(txid)| txid))
    }
}

/// Serde helper for bytes as BRC-100's `Base64String`.
/// Use with `#[serde(with = "base64_bytes")]` on `Vec<u8>` fields.
pub mod base64_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serializes the bytes as one base64 string.
    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&crate::primitives::to_base64(bytes))
    }

    /// Deserializes one base64 string into the bytes.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        crate::primitives::from_base64(&String::deserialize(deserializer)?)
            .map_err(serde::de::Error::custom)
    }
}

/// `'certifier'`, or the revealer's public key as a hex string.
impl Serialize for KeyringRevealer {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            KeyringRevealer::Certifier => serializer.serialize_str("certifier"),
            KeyringRevealer::PublicKey(key) => serializer.serialize_str(&key.to_hex()),
        }
    }
}

impl<'de> Deserialize<'de> for KeyringRevealer {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match String::deserialize(deserializer)?.as_str() {
            "certifier" => Ok(KeyringRevealer::Certifier),
            key => PublicKey::from_strict_hex(key)
                .map(KeyringRevealer::PublicKey)
                .map_err(|e| {
                    serde::de::Error::custom(format!(
                        "keyringRevealer is 'certifier' or a public key: {e}"
                    ))
                }),
        }
    }
}
