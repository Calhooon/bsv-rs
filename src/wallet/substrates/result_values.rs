//! `validateWalletResult` at ts-stack@edf6e03 (#408, #432).
//! Borrow JSON fields so a present null never becomes an absent optional field.
//! Checks run in reference order before the public types decode the result.

use crate::Error;
use indexmap::IndexMap;
use serde_json::value::RawValue;

mod action_binding;
mod actions;
mod beef;
mod boundary;
mod bytes;
mod certificate;
mod certificates;
mod identity;
mod lists;
mod raw_tree;
#[cfg(feature = "http")]
mod review_projection;
mod scalars;
pub(crate) mod timestamp;
mod wire;

pub(crate) use action_binding::input_sources;
#[cfg(feature = "http")]
pub(super) use boundary::{normalize_numbers, response_bytes};
pub(crate) use boundary::{request, wire_request_length, wire_response_length};
#[cfg(feature = "http")]
pub(super) use review_projection::body as review_body;
pub(crate) use wire::{signature as wire_signature, WireResult};

type Object<'a> = IndexMap<String, &'a RawValue>;
type Result<T> = std::result::Result<T, Error>;

fn invalid(call: &str, field: &str, expected: &str) -> Error {
    Error::WalletError(format!(
        "Invalid {call} result {field}: expected {expected}"
    ))
}

fn record<'a>(raw: Option<&'a RawValue>, call: &str, field: &str) -> Result<Object<'a>> {
    let mut object: Object<'a> = raw
        .and_then(|v| serde_json::from_str(v.get()).ok())
        .ok_or_else(|| invalid(call, field, "an object"))?;
    object.sort_by(|a, _, b, _| key_order(a).cmp(&key_order(b)));
    Ok(object)
}

fn key_order(key: &str) -> (bool, u32) {
    let index = key
        .parse::<u32>()
        .ok()
        .filter(|n| *n != u32::MAX && n.to_string() == key);
    (index.is_none(), index.unwrap_or(0))
}

fn request_keys<'a>(request: &'a serde_json::Value, field: &str) -> Vec<&'a str> {
    if let Some(keys) = request
        .get(format!("${field}Keys"))
        .and_then(serde_json::Value::as_array)
    {
        return keys.iter().filter_map(serde_json::Value::as_str).collect();
    }
    request[field]
        .as_object()
        .map(|fields| fields.keys().map(String::as_str).collect())
        .unwrap_or_default()
}

fn array<'a>(raw: Option<&'a RawValue>, call: &str, field: &str) -> Result<Vec<&'a RawValue>> {
    let values: Vec<&RawValue> = raw
        .and_then(|v| serde_json::from_str(v.get()).ok())
        .ok_or_else(|| invalid(call, field, "an array"))?;
    if values.len() > 100_000 {
        return Err(invalid(call, field, "at most 100000 entries"));
    }
    Ok(values)
}

fn member<'a>(object: &Object<'a>, key: &str) -> Option<&'a RawValue> {
    object.get(key).copied()
}

/// Keep syntax errors in serde's words; all result checks precede typed decoding.
#[cfg(feature = "http")]
pub(super) fn validate<'a>(
    call: &str,
    text: &'a [u8],
    request: &serde_json::Value,
) -> Result<Option<raw_tree::Snapshot<'a>>> {
    validate_context(
        call,
        text,
        request,
        &format!("HTTPWalletJSON {call} raw response"),
    )
}

#[cfg(feature = "http")]
fn validate_context<'a>(
    call: &str,
    text: &'a [u8],
    request: &serde_json::Value,
    context: &str,
) -> Result<Option<raw_tree::Snapshot<'a>>> {
    validate_with_bytes(call, text, request, context, &bytes::Fields::default())
}

fn validate_with_bytes<'a>(
    call: &str,
    text: &'a [u8],
    request: &serde_json::Value,
    context: &str,
    bytes: &bytes::Fields<'_>,
) -> Result<Option<raw_tree::Snapshot<'a>>> {
    let Ok(raw) = serde_json::from_slice::<&RawValue>(text) else {
        return Ok(None);
    };
    let snapshot = raw_tree::Snapshot::read(raw, context)?;
    let result = record(Some(raw), call, "value").map_err(|_| {
        Error::WalletError(format!(
            "Invalid HTTPWalletJSON {call} response: expected an object"
        ))
    })?;
    match call {
        "createAction" | "signAction" => actions::validate(&result, call, request, bytes),
        "encrypt" => bytes::read(
            member(&result, "ciphertext"),
            call,
            "ciphertext",
            None,
            None,
        )
        .map(|_| ()),
        "decrypt" => {
            bytes::read(member(&result, "plaintext"), call, "plaintext", None, None).map(|_| ())
        }
        "createHmac" => {
            bytes::read(member(&result, "hmac"), call, "hmac", Some(32), None).map(|_| ())
        }
        "createSignature" => signature(&result, call, bytes),
        "revealCounterpartyKeyLinkage" | "revealSpecificKeyLinkage" => {
            scalars::linkage(&result, call, request, bytes)
        }
        "listActions" => lists::actions(&result, call, request),
        "listOutputs" => lists::outputs(&result, call, request, bytes),
        "acquireCertificate" => certificates::acquire(raw, call, request),
        "listCertificates" | "discoverByIdentityKey" | "discoverByAttributes" => {
            certificates::list(&result, call, request)
        }
        "proveCertificate" => certificates::proof(&result, call, request),
        _ => scalars::validate(&result, call),
    }?;
    Ok(Some(snapshot))
}

#[cfg(feature = "http")]
pub(super) fn snapshot(call: &str, text: &[u8]) -> Result<()> {
    if let Ok(raw) = serde_json::from_slice::<&RawValue>(text) {
        raw_tree::Snapshot::read(raw, &format!("HTTPWalletJSON {call} raw response"))?;
    }
    Ok(())
}

fn signature(result: &Object<'_>, call: &str, bytes: &bytes::Fields<'_>) -> Result<()> {
    let encoded = bytes.read(
        member(result, "signature"),
        call,
        "signature",
        None,
        Some(72),
    )?;
    if !crate::wallet::validation::crypto::is_canonical_der_signature(&encoded) {
        return Err(invalid(
            call,
            "signature",
            "a canonical DER-encoded ECDSA signature",
        ));
    }
    Ok(())
}

/// Code-5 replies carry the same action facts under an explicit txid-only request.
#[cfg(feature = "http")]
pub(super) fn review(
    data: &serde_json::Map<String, serde_json::Value>,
    call: &str,
    request: &serde_json::Value,
) -> Result<()> {
    let mut request = request.clone();
    if !request["options"].is_object() {
        request["options"] = serde_json::json!({});
    }
    request["options"]["returnTXIDOnly"] = serde_json::Value::Bool(true);
    let action: serde_json::Map<_, _> = ["txid", "tx", "noSendChange", "sendWithResults"]
        .iter()
        .filter_map(|name| {
            data.get(*name)
                .map(|value| ((*name).to_string(), value.clone()))
        })
        .collect();
    let encoded = serde_json::to_vec(&action).map_err(|e| Error::WalletError(e.to_string()))?;
    validate(call, &encoded, &request).map(|_| ())
}
