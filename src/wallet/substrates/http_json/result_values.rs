//! The first #408 slice of `validateWalletResult` (`ts-stack@edf6e03`).
//! Borrow the JSON fields before serde can turn a present null into None.
//! Scalar and request-binding checks still outstanding are inventoried in
//! `../CLAUDE.md`; this reader covers bytes, container shapes and certificates.

use crate::Error;
use indexmap::IndexMap;
use serde_json::value::RawValue;

mod bytes;
mod certificate;
mod shapes;

type Object<'a> = IndexMap<String, &'a RawValue>;
type Result<T> = std::result::Result<T, Error>;

fn invalid(call: &str, field: &str, expected: &str) -> Error {
    Error::WalletError(format!(
        "Invalid {call} result {field}: expected {expected}"
    ))
}

fn record<'a>(raw: Option<&'a RawValue>, call: &str, field: &str) -> Result<Object<'a>> {
    raw.and_then(|v| serde_json::from_str(v.get()).ok())
        .ok_or_else(|| invalid(call, field, "an object"))
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

/// Keep syntax errors in serde's existing words. Valid JSON is checked even
/// when its typed deserializer would succeed (`Option` consumes null).
pub(super) fn validate(call: &str, text: &[u8]) -> Result<()> {
    let Ok(raw) = serde_json::from_slice::<&RawValue>(text) else {
        return Ok(());
    };
    let result = record(Some(raw), call, "value").map_err(|_| {
        Error::WalletError(format!(
            "Invalid HTTPWalletJSON {call} response: expected an object"
        ))
    })?;
    match call {
        "createAction" | "signAction" => shapes::action(&result, call),
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
        "createSignature" => signature(&result, call),
        "revealCounterpartyKeyLinkage" | "revealSpecificKeyLinkage" => linkage(&result, call),
        "listActions" => shapes::actions(&result, call),
        "listOutputs" => shapes::outputs(&result, call),
        "acquireCertificate" => certificate::validate(Some(raw), call, "certificate"),
        "listCertificates" | "discoverByIdentityKey" | "discoverByAttributes" => {
            shapes::certificates(&result, call)
        }
        "proveCertificate" => shapes::proof(&result, call),
        _ => Ok(()),
    }
}

fn signature(result: &Object<'_>, call: &str) -> Result<()> {
    let encoded = bytes::read(
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

fn linkage(result: &Object<'_>, call: &str) -> Result<()> {
    for field in ["encryptedLinkage", "encryptedLinkageProof"] {
        bytes::read(member(result, field), call, field, None, None)?;
    }
    if call == "revealSpecificKeyLinkage"
        && member(result, "protocolID")
            .and_then(|raw| serde_json::from_str::<Vec<serde::de::IgnoredAny>>(raw.get()).ok())
            .is_none_or(|tuple| tuple.len() != 2)
    {
        return Err(invalid(
            call,
            "protocolID",
            "a [securityLevel, protocolName] tuple",
        ));
    }
    Ok(())
}
