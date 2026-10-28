//! Container reads of the result dispatch. A missing optional member is
//! skipped; a present null, scalar or wrong container is never absence.

use super::{array, bytes, certificate, invalid, member, record, Object, Result};

pub(super) fn action(result: &Object<'_>, call: &str) -> Result<()> {
    if let Some(raw) = member(result, "tx") {
        bytes::read(Some(raw), call, "tx", None, None)?;
    }
    optional_array(result, call, "noSendChange")?;
    if let Some(raw) = member(result, "sendWithResults") {
        for (index, item) in array(Some(raw), call, "sendWithResults")?
            .iter()
            .enumerate()
        {
            record(Some(item), call, &format!("sendWithResults[{index}]"))?;
        }
    }
    if let Some(raw) = member(result, "signableTransaction") {
        if call != "createAction" {
            return Err(invalid(call, "signableTransaction", "an absent field"));
        }
        if result.contains_key("txid") || result.contains_key("tx") {
            return Err(invalid(
                call,
                "signableTransaction",
                "exclusive of txid and tx",
            ));
        }
        let signable = record(Some(raw), call, "signableTransaction")?;
        bytes::read(
            member(&signable, "tx"),
            call,
            "signableTransaction.tx",
            None,
            None,
        )?;
    }
    Ok(())
}

pub(super) fn actions(result: &Object<'_>, call: &str) -> Result<()> {
    for (index, raw) in array(member(result, "actions"), call, "actions")?
        .iter()
        .enumerate()
    {
        let field = format!("actions[{index}]");
        let action = record(Some(raw), call, &field)?;
        optional_array(&action, call, &format!("{field}.labels"))?;
        for name in ["inputs", "outputs"] {
            let path = format!("{field}.{name}");
            if let Some(raw) = member(&action, name) {
                for (index, raw) in array(Some(raw), call, &path)?.iter().enumerate() {
                    let path = format!("{path}[{index}]");
                    let entry = record(Some(raw), call, &path)?;
                    if name == "outputs" {
                        optional_array(&entry, call, &format!("{path}.tags"))?;
                    }
                }
            }
        }
    }
    Ok(())
}

pub(super) fn outputs(result: &Object<'_>, call: &str) -> Result<()> {
    let outputs = array(member(result, "outputs"), call, "outputs")?;
    if let Some(raw) = member(result, "BEEF") {
        bytes::read(Some(raw), call, "BEEF", None, None)?;
    }
    for (index, raw) in outputs.iter().enumerate() {
        let field = format!("outputs[{index}]");
        let output = record(Some(raw), call, &field)?;
        for name in ["tags", "labels"] {
            optional_array(&output, call, &format!("{field}.{name}"))?;
        }
    }
    Ok(())
}

pub(super) fn certificates(result: &Object<'_>, call: &str) -> Result<()> {
    for (index, raw) in array(member(result, "certificates"), call, "certificates")?
        .iter()
        .enumerate()
    {
        let field = format!("certificates[{index}]");
        certificate::validate(Some(raw), call, &field)?;
        let entry = record(Some(raw), call, &field)?;
        if let Some(raw) = member(&entry, "keyring") {
            record(Some(raw), call, &format!("{field}.keyring"))?;
        }
        if call != "listCertificates" {
            for name in [
                "certifierInfo",
                "publiclyRevealedKeyring",
                "decryptedFields",
            ] {
                record(member(&entry, name), call, &format!("{field}.{name}"))?;
            }
        }
    }
    Ok(())
}

pub(super) fn proof(result: &Object<'_>, call: &str) -> Result<()> {
    record(
        member(result, "keyringForVerifier"),
        call,
        "keyringForVerifier",
    )?;
    if let Some(raw) = member(result, "certificate") {
        certificate::validate(Some(raw), call, "certificate")?;
    }
    Ok(())
}

fn optional_array(result: &Object<'_>, call: &str, field: &str) -> Result<()> {
    let name = field.rsplit('.').next().unwrap_or(field);
    if let Some(raw) = member(result, name) {
        array(Some(raw), call, field)?;
    }
    Ok(())
}
