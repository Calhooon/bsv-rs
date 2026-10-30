//! HTTP and snapshot bounds, WalletResultValidation.ts:623-821.

use super::{record, Result};
use crate::Error;
#[cfg(feature = "http")]
use num_traits::ToPrimitive;
use serde_json::{value::RawValue, Value};

const MAX_BYTES: usize = 256 * 1024 * 1024;
/// The complete outgoing frame's bound, beside the response/byte-field cap.
const MAX_WIRE_REQUEST_BYTES: usize = 256 * 1024 * 1024;
const MAX_NODES: usize = 1_000_000;

pub(super) fn unsafe_key(key: &str) -> bool {
    matches!(key, "__proto__" | "constructor" | "prototype")
}

pub(crate) fn request(call: &str, body: &[u8]) -> Result<Value> {
    let raw: &RawValue = serde_json::from_slice(body)
        .map_err(|e| Error::WalletError(format!("failed to serialize request: {e}")))?;
    let fields = record(Some(raw), call, "request")?;
    let mut captured = serde_json::Map::new();
    for name in request_fields(call) {
        if let Some(raw) = fields.get(*name) {
            if matches!(*name, "attributes" | "spends") {
                let object = record(Some(raw), call, name)?;
                captured.insert(
                    format!("${name}Keys"),
                    Value::Array(object.keys().cloned().map(Value::String).collect()),
                );
            }
            let value =
                serde_json::from_str(raw.get()).map_err(|e| Error::WalletError(e.to_string()))?;
            captured.insert((*name).into(), value);
        }
    }
    let mut request = Value::Object(captured);
    request_keys(&request)?;
    if call == "createAction" {
        let sources =
            super::action_binding::capture_sources(fields.get("inputBEEF").copied(), &request)?;
        request["$sourceValues"] =
            serde_json::to_value(sources).map_err(|e| Error::WalletError(e.to_string()))?;
    }
    Ok(request)
}

fn request_fields(call: &str) -> &'static [&'static str] {
    match call {
        "createAction" => &["inputs", "outputs", "version", "lockTime", "options"],
        "signAction" => &["spends", "options"],
        "listActions" | "listOutputs" => &[
            "labels",
            "tags",
            "labelQueryMode",
            "tagQueryMode",
            "includeLabels",
            "includeTags",
            "includeInputs",
            "includeInputSourceLockingScripts",
            "includeInputUnlockingScripts",
            "includeOutputs",
            "includeOutputLockingScripts",
            "include",
            "limit",
        ],
        "listCertificates" => &["certifiers", "types", "limit"],
        "discoverByIdentityKey" => &["identityKey", "limit"],
        "discoverByAttributes" => &["attributes", "limit"],
        "revealCounterpartyKeyLinkage" | "revealSpecificKeyLinkage" => {
            &["verifier", "counterparty", "protocolID", "keyID"]
        }
        "acquireCertificate" => &[
            "type",
            "serialNumber",
            "subject",
            "certifier",
            "signature",
            "revocationOutpoint",
            "fields",
            "acquisitionProtocol",
        ],
        "proveCertificate" => &["fieldsToReveal", "certificate", "verifier"],
        _ => &[],
    }
}

fn request_keys(request: &Value) -> Result<()> {
    for field in [
        "labels",
        "tags",
        "certifiers",
        "types",
        "fieldsToReveal",
        "protocolID",
    ] {
        bounded_request_array(&request[field])?;
    }
    for field in ["sendWith", "knownTxids"] {
        bounded_request_array(&request["options"][field])?;
    }
    let mut pending = vec![request];
    while let Some(value) = pending.pop() {
        match value {
            Value::Object(object) => {
                if object.keys().any(|key| unsafe_key(key)) {
                    return Err(Error::WalletError(
                        "Wallet result request records must contain only safe string keys".into(),
                    ));
                }
                pending.extend(object.values());
            }
            Value::Array(array) => pending.extend(array),
            _ => {}
        }
    }
    Ok(())
}

fn bounded_request_array(value: &Value) -> Result<()> {
    if value.as_array().is_some_and(|a| a.len() > MAX_NODES) {
        return Err(Error::WalletError(
            "Wallet request arrays must have a bounded own length".into(),
        ));
    }
    Ok(())
}

#[cfg(feature = "http")]
pub(in crate::wallet::substrates) async fn response_bytes(
    mut response: reqwest::Response,
) -> Result<Vec<u8>> {
    if let Some(length) = response.headers().get("content-length") {
        let length = length
            .to_str()
            .ok()
            .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .ok_or_else(|| {
                Error::WalletError("HTTPWalletJSON response has an invalid Content-Length".into())
            })?;
        if length.parse::<u64>().map_or(true, |n| n > MAX_BYTES as u64) {
            return Err(too_large());
        }
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| super::super::http_json::request_error(e, "failed to parse JSON response"))?
    {
        if chunk.len() > MAX_BYTES - bytes.len() {
            return Err(too_large());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[cfg(feature = "http")]
fn too_large() -> Error {
    Error::WalletError("HTTPWalletJSON response exceeds the maximum permitted size".into())
}

/// The checked JSON integer `1.0` (and `-0`) must also decode into integer Rust fields.
#[cfg(feature = "http")]
pub(in crate::wallet::substrates) fn normalize_numbers(value: &mut Value) {
    // base64() checks the reference's grammar, which permits nonzero unused
    // pad bits. The public reference is bytes, so decode those bits here.
    use base64::{engine::general_purpose, Engine};
    if let Some(reference) = value
        .get_mut("signableTransaction")
        .and_then(|s| s.get_mut("reference"))
    {
        let engine = general_purpose::GeneralPurpose::new(
            &base64::alphabet::STANDARD,
            general_purpose::GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
        );
        if let Some(bytes) = reference.as_str().and_then(|s| engine.decode(s).ok()) {
            *reference = Value::String(general_purpose::STANDARD.encode(bytes));
        }
    }
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        match value {
            Value::Number(n) if n.is_f64() => {
                if let Some(x) = n.as_f64().filter(|x| x.fract() == 0.0) {
                    if let Some(n) = x.to_i64() {
                        *value = Value::from(n);
                    } else if let Some(n) = x.to_u64() {
                        *value = Value::from(n);
                    }
                }
            }
            Value::Array(a) => pending.extend(a),
            Value::Object(o) => pending.extend(o.values_mut()),
            _ => {}
        }
    }
}

/// `WalletWireTransceiver.ts:104-107` at `ts-stack@edf6e03`.
pub(crate) fn wire_request_length(length: usize) -> Result<()> {
    if length > MAX_WIRE_REQUEST_BYTES {
        return Err(Error::WalletError(
            "Wallet Wire request exceeds the maximum permitted size".into(),
        ));
    }
    Ok(())
}

/// The wire frame limit also bounds every individual result byte field.
pub(crate) fn wire_response_length(length: usize) -> Result<()> {
    if length > MAX_BYTES {
        return Err(Error::WalletError(
            "Wallet Wire response exceeds the maximum permitted size".into(),
        ));
    }
    Ok(())
}
