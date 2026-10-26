//! The two key-linkage results and their JSON shape: flat, the linkage and
//! its proof as arrays of byte numbers, the specific result's protocol as
//! `protocolID` and its key as `keyID`, as BRC-100 has them (`wallet/0100.md`
//! at `5119a9b`, `:1011-1018`, `:1043-1052`) and the reference's
//! `HTTPWalletJSON` reads them (`ts-stack@edf6e03` `Wallet.interfaces.ts:719-744`;
//! #105).

use super::{Protocol, SecurityLevel};
use crate::primitives::PublicKey;
use serde::{Deserialize, Serialize};

/// Result of revealing key linkage.
///
/// In JSON its fields sit flat in the two linkage results, the linkage and
/// its proof as arrays of byte numbers, as BRC-100's `Byte[]` (#105).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyLinkageResult {
    /// Encrypted linkage data.
    pub encrypted_linkage: Vec<u8>,
    /// Proof of encrypted linkage.
    pub encrypted_linkage_proof: Vec<u8>,
    /// The prover's public key.
    pub prover: PublicKey,
    /// The verifier's public key.
    pub verifier: PublicKey,
    /// The counterparty's public key.
    pub counterparty: PublicKey,
}

/// Result of revealing counterparty key linkage.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevealCounterpartyKeyLinkageResult {
    /// Base key linkage result; its fields flat in JSON (#105).
    #[serde(flatten)]
    pub linkage: KeyLinkageResult,
    /// Time of revelation (ISO timestamp).
    pub revelation_time: String,
}

/// Result of revealing specific key linkage.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevealSpecificKeyLinkageResult {
    /// Base key linkage result; its fields flat in JSON (#105).
    #[serde(flatten)]
    pub linkage: KeyLinkageResult,
    /// The protocol ID; `protocolID` in JSON, the `[level, name]` pair.
    #[serde(rename = "protocolID", with = "protocol_tuple")]
    pub protocol: Protocol,
    /// The key ID; `keyID` in JSON.
    #[serde(rename = "keyID")]
    pub key_id: String,
    /// The proof type.
    pub proof_type: u8,
}

/// Serde helper for a [`Protocol`] as BRC-100's `WalletProtocol`, the pair
/// `[securityLevel, protocolName]` with the level a number (`wallet/0100.md`
/// at `5119a9b`; `Wallet.interfaces.ts:227` at `ts-stack@edf6e03`).
mod protocol_tuple {
    use super::{Protocol, SecurityLevel};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(protocol: &Protocol, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        protocol.to_tuple().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Protocol, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (level, name) = <(u8, String)>::deserialize(deserializer)?;
        let security_level = SecurityLevel::from_u8(level).ok_or_else(|| {
            serde::de::Error::custom(format!("security level {level} is not 0, 1 or 2"))
        })?;
        Ok(Protocol::new(security_level, name))
    }
}
