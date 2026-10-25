//! The JSON bodies of the nine key-related calls, in the reference's names
//! (`HTTPWalletJSON` sends the args object as given), moved out of
//! `http_json.rs`.

use serde::{Deserialize, Serialize};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct JsonGetPublicKeyRequest {
    pub(super) identity_key: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) protocol_id: Option<(u8, String)>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) counterparty: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) for_self: Option<bool>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct JsonGetPublicKeyResponse {
    pub(super) public_key: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct JsonEncryptRequest {
    pub(super) protocol_id: (u8, String),
    pub(super) key_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) counterparty: Option<String>,
    pub(super) plaintext: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct JsonEncryptResponse {
    pub(super) ciphertext: Vec<u8>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct JsonDecryptRequest {
    pub(super) protocol_id: (u8, String),
    pub(super) key_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) counterparty: Option<String>,
    pub(super) ciphertext: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct JsonDecryptResponse {
    pub(super) plaintext: Vec<u8>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct JsonCreateHmacRequest {
    pub(super) protocol_id: (u8, String),
    pub(super) key_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) counterparty: Option<String>,
    pub(super) data: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct JsonCreateHmacResponse {
    pub(super) hmac: Vec<u8>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct JsonVerifyHmacRequest {
    pub(super) protocol_id: (u8, String),
    pub(super) key_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) counterparty: Option<String>,
    pub(super) data: Vec<u8>,
    pub(super) hmac: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct JsonVerifyHmacResponse {
    pub(super) valid: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct JsonCreateSignatureRequest {
    pub(super) protocol_id: (u8, String),
    pub(super) key_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) counterparty: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) data: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) hash_to_directly_sign: Option<String>, // hex
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct JsonCreateSignatureResponse {
    pub(super) signature: Vec<u8>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct JsonVerifySignatureRequest {
    pub(super) protocol_id: (u8, String),
    pub(super) key_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) counterparty: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) for_self: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) data: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) hash_to_directly_verify: Option<String>, // hex
    pub(super) signature: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct JsonVerifySignatureResponse {
    pub(super) valid: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct JsonRevealCounterpartyRequest {
    pub(super) counterparty: String, // hex pubkey
    pub(super) verifier: String,     // hex pubkey
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) privileged: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) privileged_reason: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct JsonRevealSpecificRequest {
    pub(super) counterparty: String, // "self", "anyone", or hex pubkey
    pub(super) verifier: String,     // hex pubkey
    pub(super) protocol_id: (u8, String), // (security_level, protocol_name)
    pub(super) key_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) privileged: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) privileged_reason: Option<String>,
}
