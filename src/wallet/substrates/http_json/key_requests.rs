//! The JSON bodies of the nine key-related calls, in the reference's names
//! (`HTTPWalletJSON` sends the args object as given), moved out of
//! `http_json.rs`: `protocolID` the `[level, name]` pair, `keyID`, and the
//! two direct hashes as arrays of byte numbers (BRC-100 at `5119a9b`
//! `wallet/0100.md:981-982`, `:1037-1038`, `:1182-1184`, `:1213-1216`;
//! `ts-stack@edf6e03` `Wallet.interfaces.ts:665-667`, `:798`, `:813`; #105).

use serde::{Deserialize, Serialize};

/// The permission fields of the seven key-related args, in the reference's
/// JSON names (`privileged`, `privilegedReason`, `seekPermission`;
/// `Wallet.interfaces.ts:663-672` at `ts-stack@edf6e03`), an absent one
/// omitted as `JSON.stringify` omits `undefined` (#193).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct JsonPermission {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) privileged: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) privileged_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) seek_permission: Option<bool>,
}

/// The permission fields of an args value, moved out of it.
macro_rules! permission {
    ($args:expr) => {
        JsonPermission {
            privileged: $args.privileged,
            privileged_reason: $args.privileged_reason,
            seek_permission: $args.seek_permission,
        }
    };
}
pub(super) use permission;

/// The protocol, key and counterparty of the six key-related requests that
/// require them, in BRC-100's names: `protocolID` the `[level, name]` pair,
/// `keyID` (#105).
#[derive(Serialize)]
pub(super) struct JsonKeyParams {
    #[serde(rename = "protocolID")]
    pub(super) protocol_id: (u8, String),
    #[serde(rename = "keyID")]
    pub(super) key_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) counterparty: Option<String>,
}

/// The key parameters of an args value, moved out of it.
macro_rules! key_params {
    ($args:expr) => {
        JsonKeyParams {
            protocol_id: protocol_to_json(&$args.protocol_id),
            key_id: $args.key_id,
            counterparty: $args.counterparty.as_ref().map(counterparty_to_string),
        }
    };
}
pub(super) use key_params;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct JsonGetPublicKeyRequest {
    /// Written only when true, as BRC-100's `identityKey?: true`
    /// (`wallet/0100.md:980`; `Wallet.interfaces.ts:683`; #105)
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub(super) identity_key: bool,
    #[serde(rename = "protocolID", skip_serializing_if = "Option::is_none")]
    pub(super) protocol_id: Option<(u8, String)>,
    #[serde(rename = "keyID", skip_serializing_if = "Option::is_none")]
    pub(super) key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) counterparty: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) for_self: Option<bool>,
    #[serde(flatten)]
    pub(super) permission: JsonPermission,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct JsonGetPublicKeyResponse {
    pub(super) public_key: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct JsonEncryptRequest {
    #[serde(flatten)]
    pub(super) key: JsonKeyParams,
    pub(super) plaintext: Vec<u8>,
    #[serde(flatten)]
    pub(super) permission: JsonPermission,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct JsonEncryptResponse {
    pub(super) ciphertext: Vec<u8>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct JsonDecryptRequest {
    #[serde(flatten)]
    pub(super) key: JsonKeyParams,
    pub(super) ciphertext: Vec<u8>,
    #[serde(flatten)]
    pub(super) permission: JsonPermission,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct JsonDecryptResponse {
    pub(super) plaintext: Vec<u8>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct JsonCreateHmacRequest {
    #[serde(flatten)]
    pub(super) key: JsonKeyParams,
    pub(super) data: Vec<u8>,
    #[serde(flatten)]
    pub(super) permission: JsonPermission,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct JsonCreateHmacResponse {
    pub(super) hmac: Vec<u8>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct JsonVerifyHmacRequest {
    #[serde(flatten)]
    pub(super) key: JsonKeyParams,
    pub(super) data: Vec<u8>,
    pub(super) hmac: Vec<u8>,
    #[serde(flatten)]
    pub(super) permission: JsonPermission,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct JsonVerifyHmacResponse {
    pub(super) valid: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct JsonCreateSignatureRequest {
    #[serde(flatten)]
    pub(super) key: JsonKeyParams,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) data: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) hash_to_directly_sign: Option<Vec<u8>>,
    #[serde(flatten)]
    pub(super) permission: JsonPermission,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct JsonCreateSignatureResponse {
    pub(super) signature: Vec<u8>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct JsonVerifySignatureRequest {
    #[serde(flatten)]
    pub(super) key: JsonKeyParams,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) for_self: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) data: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) hash_to_directly_verify: Option<Vec<u8>>,
    pub(super) signature: Vec<u8>,
    #[serde(flatten)]
    pub(super) permission: JsonPermission,
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
    #[serde(rename = "protocolID")]
    pub(super) protocol_id: (u8, String), // (security_level, protocol_name)
    #[serde(rename = "keyID")]
    pub(super) key_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) privileged: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) privileged_reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use crate::wallet::substrates::HttpWalletJson;
    use crate::wallet::{CreateSignatureArgs, Protocol, SecurityLevel};
    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// #193: createSignature's body carries the permission fields in the
    /// reference's names when they are set and omits them when they are not,
    /// and the answer reads back.
    #[tokio::test]
    async fn create_signature_sends_the_permission_fields_in_the_references_names() {
        let server = MockServer::start().await;
        let base = serde_json::json!({"protocolID": [1, "permission fields"], "keyID": "k",
            "data": [1, 2]});
        let mut with = base.clone();
        with["privileged"] = true.into();
        with["privilegedReason"] = "json reason".into();
        with["seekPermission"] = false.into();
        for (body, signature) in [(base, 1), (with, 2)] {
            Mock::given(method("POST"))
                .and(path("/createSignature"))
                .and(body_json(body))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(serde_json::json!({"signature": [signature]})),
                )
                .mount(&server)
                .await;
        }
        let client = HttpWalletJson::new(Some("app.example.com".into()), Some(server.uri()))
            .expect("the substrate is configured");
        let args = CreateSignatureArgs {
            data: Some(vec![1, 2]),
            protocol_id: Protocol::new(SecurityLevel::App, "permission fields"),
            key_id: "k".to_string(),
            ..Default::default()
        };
        let plain = client.create_signature(args.clone(), "").await.unwrap();
        let with = CreateSignatureArgs {
            privileged: Some(true),
            privileged_reason: Some("json reason".to_string()),
            seek_permission: Some(false),
            ..args
        };
        let privileged = client.create_signature(with, "").await.unwrap();
        assert_eq!((plain.signature, privileged.signature), (vec![1], vec![2]));
    }
}
