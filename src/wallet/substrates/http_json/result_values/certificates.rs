//! Certificate filters and proofs, WalletResultValidation.ts:1800-1916,2307-2363.

use super::{certificate, identity, invalid, lists, member, record, scalars as s, Object, Result};
use serde_json::{value::RawValue, Value};
use std::collections::HashSet;

fn text(object: &Object<'_>, key: &str) -> String {
    member(object, key)
        .and_then(|v| serde_json::from_str(v.get()).ok())
        .unwrap_or_default()
}

pub(super) fn acquire(raw: &RawValue, call: &str, request: &Value) -> Result<()> {
    certificate::validate(Some(raw), call, "certificate")?;
    let cert = record(Some(raw), call, "certificate")?;
    if request
        .get("type")
        .is_some_and(|v| v != &text(&cert, "type"))
    {
        return Err(invalid(
            call,
            "certificate.type",
            "the requested certificate type",
        ));
    }
    if request
        .get("certifier")
        .is_some_and(|v| !s::same(&text(&cert, "certifier"), v))
    {
        return Err(invalid(
            call,
            "certificate.certifier",
            "the requested certifier",
        ));
    }
    partial(
        &cert,
        request,
        call,
        "certificate",
        request["acquisitionProtocol"] != "issuance",
    )
}

fn partial(
    cert: &Object<'_>,
    request: &Value,
    call: &str,
    field: &str,
    values: bool,
) -> Result<()> {
    for key in ["type", "serialNumber", "subject", "certifier", "signature"] {
        if let Some(expected) = request.get(key) {
            let actual = text(cert, key);
            let same = if matches!(key, "type" | "serialNumber") {
                expected == &actual
            } else {
                s::same(&actual, expected)
            };
            if !same {
                return Err(invalid(
                    call,
                    &format!("{field}.{key}"),
                    &format!("the requested certificate {key}"),
                ));
            }
        }
    }
    if let Some(expected) = request.get("revocationOutpoint") {
        let actual = s::outpoint(
            member(cert, "revocationOutpoint"),
            call,
            &format!("{field}.revocationOutpoint"),
        )?;
        let expected = expected
            .as_str()
            .and_then(s::parse_outpoint)
            .ok_or_else(|| {
                invalid(
                    call,
                    &format!("request.{field}.revocationOutpoint"),
                    "a canonical transaction outpoint",
                )
            })?;
        if actual != expected {
            return Err(invalid(
                call,
                &format!("{field}.revocationOutpoint"),
                "the requested certificate revocation outpoint",
            ));
        }
    }
    partial_fields(cert, request, call, field, values)
}

fn partial_fields(
    cert: &Object<'_>,
    request: &Value,
    call: &str,
    field: &str,
    values: bool,
) -> Result<()> {
    if let Some(expected) = request.get("fields") {
        let actual: Option<Value> =
            member(cert, "fields").and_then(|v| serde_json::from_str(v.get()).ok());
        let same = if values {
            actual.as_ref() == Some(expected)
        } else {
            actual
                .as_ref()
                .and_then(Value::as_object)
                .zip(expected.as_object())
                .is_some_and(|(a, b)| a.len() == b.len() && b.keys().all(|key| a.contains_key(key)))
        };
        if !same {
            return Err(invalid(
                call,
                &format!("{field}.fields"),
                "the requested certificate fields",
            ));
        }
    }
    Ok(())
}

pub(super) fn list(result: &Object<'_>, call: &str, request: &Value) -> Result<()> {
    for (i, raw) in lists::page(result, call, "totalCertificates", "certificates", request)?
        .iter()
        .enumerate()
    {
        let field = format!("certificates[{i}]");
        certificate::validate(Some(raw), call, &field)?;
        let cert = record(Some(raw), call, &field)?;
        filters(&cert, call, &field, request)?;
        if let Some(raw) = member(&cert, "keyring") {
            s::string_record(Some(raw), call, &format!("{field}.keyring"), true)?;
        }
        if let Some(raw) = member(&cert, "verifier") {
            s::key(Some(raw), call, &format!("{field}.verifier"))?;
        }
        if call != "listCertificates" {
            discovery(&cert, call, &field, request)?;
        }
    }
    Ok(())
}

fn filters(cert: &Object<'_>, call: &str, field: &str, request: &Value) -> Result<()> {
    if call == "listCertificates" {
        for (filter, key, expected) in [
            ("certifiers", "certifier", "one of the requested certifiers"),
            ("types", "type", "one of the requested types"),
        ] {
            if let Some(options) = request[filter].as_array().filter(|v| !v.is_empty()) {
                let actual = text(cert, key);
                let matches = options.iter().any(|v| {
                    if key == "certifier" {
                        s::same(&actual, v)
                    } else {
                        v == &actual
                    }
                });
                if !matches {
                    return Err(invalid(call, &format!("{field}.{key}"), expected));
                }
            }
        }
    }
    if call == "discoverByIdentityKey"
        && request
            .get("identityKey")
            .is_some_and(|v| !s::same(&text(cert, "subject"), v))
    {
        return Err(invalid(
            call,
            &format!("{field}.subject"),
            "the requested identity key",
        ));
    }
    Ok(())
}

fn discovery(cert: &Object<'_>, call: &str, field: &str, request: &Value) -> Result<()> {
    let info_field = format!("{field}.certifierInfo");
    let info = record(member(cert, "certifierInfo"), call, &info_field)?;
    s::string(
        member(&info, "name"),
        call,
        &format!("{info_field}.name"),
        1,
        Some(100),
    )?;
    let icon = s::string(
        member(&info, "iconUrl"),
        call,
        &format!("{info_field}.iconUrl"),
        1,
        Some(500),
    )?;
    if !reqwest::Url::parse(&icon).is_ok_and(|u| matches!(u.scheme(), "http" | "https")) {
        return Err(invalid(
            call,
            &format!("{info_field}.iconUrl"),
            "an absolute HTTP(S) URL",
        ));
    }
    s::string(
        member(&info, "description"),
        call,
        &format!("{info_field}.description"),
        5,
        Some(50),
    )?;
    s::integer(
        member(&info, "trust"),
        call,
        &format!("{info_field}.trust"),
        1,
        10,
    )?;
    s::string_record(
        member(cert, "publiclyRevealedKeyring"),
        call,
        &format!("{field}.publiclyRevealedKeyring"),
        true,
    )?;
    let fields = s::string_record(
        member(cert, "decryptedFields"),
        call,
        &format!("{field}.decryptedFields"),
        false,
    )?;
    if call == "discoverByAttributes" {
        identity::bind(&fields, request, call, field)?;
    }
    Ok(())
}

pub(super) fn proof(result: &Object<'_>, call: &str, request: &Value) -> Result<()> {
    let keyring = s::string_record(
        member(result, "keyringForVerifier"),
        call,
        "keyringForVerifier",
        true,
    )?;
    let expected: HashSet<_> = request["fieldsToReveal"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    if keyring.len() != expected.len() || keyring.keys().any(|k| !expected.contains(k.as_str())) {
        return Err(invalid(
            call,
            "keyringForVerifier",
            "exactly the requested certificate fields",
        ));
    }
    if let Some(raw) = member(result, "certificate") {
        certificate::validate(Some(raw), call, "certificate")?;
        let cert = record(Some(raw), call, "certificate")?;
        partial(&cert, &request["certificate"], call, "certificate", true)?;
    }
    if let Some(raw) = member(result, "verifier") {
        let verifier = s::key(Some(raw), call, "verifier")?;
        if request
            .get("verifier")
            .is_some_and(|v| !s::same(&verifier, v))
        {
            return Err(invalid(call, "verifier", "the requested verifier"));
        }
    }
    Ok(())
}
