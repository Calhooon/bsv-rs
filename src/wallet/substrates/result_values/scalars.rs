//! Scalar predicates and linkage order, WalletResultValidation.ts:909-1010,2165-2306.

use super::{array, bytes, invalid, member, record, Object, Result};
use crate::primitives::{from_hex, PublicKey};
use serde_json::{value::RawValue, Value};

pub(super) fn string(
    raw: Option<&RawValue>,
    call: &str,
    field: &str,
    min: usize,
    max: Option<usize>,
) -> Result<String> {
    let text: String = raw
        .and_then(|v| serde_json::from_str(v.get()).ok())
        .ok_or_else(|| invalid(call, field, "a string"))?;
    if text.len() < min || max.is_some_and(|max| text.len() > max) {
        let range = max.map_or_else(|| format!("{min}+"), |max| format!("{min}–{max}"));
        return Err(invalid(call, field, &format!("{range} UTF-8 bytes")));
    }
    Ok(text)
}

pub(super) fn hex(
    raw: Option<&RawValue>,
    call: &str,
    field: &str,
    length: Option<usize>,
) -> Result<String> {
    let text = string(raw, call, field, 0, None)?;
    if text.len() % 2 != 0 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid(call, field, "an even-length hex string"));
    }
    if length.is_some_and(|len| text.len() != len * 2) {
        return Err(invalid(
            call,
            field,
            &format!("{} hexadecimal bytes", length.unwrap_or(0)),
        ));
    }
    Ok(text)
}

pub(super) fn key(raw: Option<&RawValue>, call: &str, field: &str) -> Result<String> {
    let text = hex(raw, call, field, Some(33))?;
    // isValidCompressedPublicKey refuses an x at or above p
    // (Secp256k1Validation.ts:15-22): the strict reader, not from_hex's (#498).
    if !matches!(text.get(..2), Some("02" | "03"))
        || from_hex(&text)
            .and_then(|bytes| PublicKey::from_bytes(&bytes))
            .is_err()
    {
        return Err(invalid(
            call,
            field,
            "a valid compressed secp256k1 public key",
        ));
    }
    Ok(text)
}

pub(super) fn integer(
    raw: Option<&RawValue>,
    call: &str,
    field: &str,
    min: i64,
    max: i64,
) -> Result<i64> {
    use num_traits::ToPrimitive;
    raw.and_then(|v| serde_json::from_str::<f64>(v.get()).ok())
        .filter(|n| n.fract() == 0.0)
        .and_then(|n| n.to_i64())
        .filter(|n| (min..=max).contains(n))
        .ok_or_else(|| invalid(call, field, &format!("an integer from {min} to {max}")))
}

pub(super) fn uint(raw: Option<&RawValue>, call: &str, field: &str, max: i64) -> Result<i64> {
    integer(raw, call, field, 0, max)
}

pub(super) fn boolean(
    raw: Option<&RawValue>,
    call: &str,
    field: &str,
    affirmative: bool,
) -> Result<()> {
    let value = raw.and_then(|v| serde_json::from_str::<bool>(v.get()).ok());
    if value.is_none() || (affirmative && value != Some(true)) {
        return Err(invalid(
            call,
            field,
            if affirmative { "true" } else { "a boolean" },
        ));
    }
    Ok(())
}

pub(super) fn outpoint(raw: Option<&RawValue>, call: &str, field: &str) -> Result<(String, u32)> {
    let text = string(raw, call, field, 0, None)?;
    parse_outpoint(&text).ok_or_else(|| invalid(call, field, "a canonical transaction outpoint"))
}

pub(super) fn parse_outpoint(text: &str) -> Option<(String, u32)> {
    let (txid, index) = text.split_once('.')?;
    if txid.len() != 64
        || !txid.bytes().all(|b| b.is_ascii_hexdigit())
        || index.is_empty()
        || (index.len() > 1 && index.starts_with('0'))
        || !index.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    Some((txid.to_ascii_lowercase(), index.parse().ok()?))
}

pub(super) fn base64(raw: Option<&RawValue>, call: &str, field: &str) -> Result<String> {
    let text = string(raw, call, field, 1, None)?;
    let data = text.trim_end_matches('=');
    let padding = text.len() - data.len();
    if text.len() % 4 != 0
        || padding > 2
        || !data
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
    {
        return Err(invalid(call, field, "a canonical base64 string"));
    }
    Ok(text)
}

pub(super) fn strings(
    raw: Option<&RawValue>,
    call: &str,
    field: &str,
) -> Result<Option<Vec<String>>> {
    raw.map(|raw| {
        array(Some(raw), call, field)?
            .iter()
            .enumerate()
            .map(|(i, raw)| string(Some(raw), call, &format!("{field}[{i}]"), 1, Some(300)))
            .collect()
    })
    .transpose()
}

pub(super) fn same(actual: &str, expected: &Value) -> bool {
    expected
        .as_str()
        .is_some_and(|expected| actual.eq_ignore_ascii_case(expected))
}

pub(super) fn validate(result: &Object<'_>, call: &str) -> Result<()> {
    match call {
        "abortAction" => boolean(member(result, "aborted"), call, "aborted", false),
        "internalizeAction" => boolean(member(result, "accepted"), call, "accepted", true),
        "relinquishOutput" | "relinquishCertificate" => {
            boolean(member(result, "relinquished"), call, "relinquished", true)
        }
        "verifyHmac" | "verifySignature" => boolean(member(result, "valid"), call, "valid", true),
        "isAuthenticated" | "waitForAuthentication" => {
            boolean(member(result, "authenticated"), call, "authenticated", true)
        }
        "getPublicKey" => key(member(result, "publicKey"), call, "publicKey").map(|_| ()),
        "getHeight" => {
            integer(member(result, "height"), call, "height", 1, u32::MAX.into()).map(|_| ())
        }
        "getHeaderForHeight" => hex(member(result, "header"), call, "header", Some(80)).map(|_| ()),
        "getNetwork" => {
            if !member(result, "network")
                .is_some_and(|v| matches!(v.get(), "\"mainnet\"" | "\"testnet\""))
            {
                let network = member(result, "network")
                    .and_then(|v| serde_json::from_str::<String>(v.get()).ok());
                if !matches!(network.as_deref(), Some("mainnet" | "testnet")) {
                    return Err(invalid(call, "network", "mainnet or testnet"));
                }
            }
            Ok(())
        }
        "getVersion" => string(member(result, "version"), call, "version", 7, Some(30)).map(|_| ()),
        _ => Ok(()),
    }
}

pub(super) fn linkage(
    result: &Object<'_>,
    call: &str,
    request: &Value,
    bytes: &bytes::Fields<'_>,
) -> Result<()> {
    let prover = key(member(result, "prover"), call, "prover")?;
    let verifier = key(member(result, "verifier"), call, "verifier")?;
    let counterparty = key(member(result, "counterparty"), call, "counterparty")?;
    for field in ["encryptedLinkage", "encryptedLinkageProof"] {
        bytes.read(member(result, field), call, field, None, None)?;
    }
    if call == "revealCounterpartyKeyLinkage" {
        timestamp(member(result, "revelationTime"), call)?;
    } else {
        specific_scalars(result, call)?;
    }
    if request.get("verifier").is_some_and(|v| !same(&verifier, v)) {
        return Err(invalid(call, "verifier", "the requested verifier"));
    }
    if let Some(expected) = request.get("counterparty") {
        let expectation = match (call, expected.as_str()) {
            ("revealSpecificKeyLinkage", Some("self"))
                if !counterparty.eq_ignore_ascii_case(&prover) =>
            {
                Some("the prover's identity key for counterparty self")
            }
            ("revealSpecificKeyLinkage", Some("anyone"))
                if !counterparty.eq_ignore_ascii_case(
                    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                ) =>
            {
                Some("the canonical anyone public key")
            }
            (_, Some("self" | "anyone")) if call == "revealSpecificKeyLinkage" => None,
            _ if !same(&counterparty, expected) => Some("the requested counterparty"),
            _ => None,
        };
        if let Some(expected) = expectation {
            return Err(invalid(call, "counterparty", expected));
        }
    }
    if call == "revealSpecificKeyLinkage" {
        for (field, expected) in [
            ("protocolID", "the requested protocol"),
            ("keyID", "the requested key ID"),
        ] {
            let actual: Option<Value> =
                member(result, field).and_then(|v| serde_json::from_str(v.get()).ok());
            if request.get(field).is_some_and(|v| {
                if matches!(field, "protocolID") {
                    actual
                        .as_ref()
                        .is_none_or(|a| a[0].as_f64() != v[0].as_f64() || a[1] != v[1])
                } else {
                    Some(v) != actual.as_ref()
                }
            }) {
                return Err(invalid(call, field, expected));
            }
        }
    }
    Ok(())
}

fn specific_scalars(result: &Object<'_>, call: &str) -> Result<()> {
    let tuple = member(result, "protocolID")
        .and_then(|v| serde_json::from_str::<Vec<&RawValue>>(v.get()).ok())
        .filter(|v| v.len() == 2)
        .ok_or_else(|| invalid(call, "protocolID", "a [securityLevel, protocolName] tuple"))?;
    uint(tuple.first().copied(), call, "protocolID[0]", 2)?;
    string(tuple.get(1).copied(), call, "protocolID[1]", 5, Some(400))?;
    string(member(result, "keyID"), call, "keyID", 1, Some(800))?;
    uint(member(result, "proofType"), call, "proofType", 255)?;
    Ok(())
}

fn timestamp(raw: Option<&RawValue>, call: &str) -> Result<()> {
    let text = string(raw, call, "revelationTime", 1, Some(64))?;
    super::timestamp::validate(&text, call, "revelationTime")
}

pub(super) fn string_record<'a>(
    raw: Option<&'a RawValue>,
    call: &str,
    field: &str,
    encoded: bool,
) -> Result<Object<'a>> {
    let object = record(raw, call, field)?;
    for (name, raw) in &object {
        if name.is_empty() || name.len() > 50 || super::boundary::unsafe_key(name) {
            return Err(invalid(
                call,
                &format!("{field} key"),
                "a safe 1–50 byte field name",
            ));
        }
        if encoded {
            base64(Some(raw), call, &format!("{field}.{name}"))?;
        } else {
            string(Some(raw), call, &format!("{field}.{name}"), 0, None)?;
        }
    }
    Ok(object)
}
