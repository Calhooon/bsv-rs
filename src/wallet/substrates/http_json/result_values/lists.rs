//! List totals, fields and request echoes, WalletResultValidation.ts:1919-2162.

use super::{array, beef, invalid, member, record, scalars as s, Object, Result};
use serde_json::{value::RawValue, Value};
use std::collections::HashSet;

const UINT: i64 = u32::MAX as i64;
const MONEY: i64 = 2_100_000_000_000_000;

pub(super) fn page<'a>(
    result: &Object<'a>,
    call: &str,
    total: &str,
    field: &str,
    request: &Value,
) -> Result<Vec<&'a RawValue>> {
    let total_count = s::uint(member(result, total), call, total, 9_007_199_254_740_991)?;
    let entries = array(member(result, field), call, field)?;
    if entries.len() as i64 > total_count {
        return Err(invalid(call, total, &format!("at least {}", entries.len())));
    }
    if request.is_object() {
        let limit = request
            .get("limit")
            .map(|v| {
                let raw = serde_json::value::to_raw_value(v)
                    .map_err(|e| crate::Error::WalletError(e.to_string()))?;
                s::uint(Some(&raw), call, "limit", 10000)
            })
            .transpose()?
            .unwrap_or(10);
        if entries.len() as i64 > limit {
            return Err(invalid(
                call,
                field,
                &format!("at most the requested limit of {limit}"),
            ));
        }
    }
    Ok(entries)
}

pub(super) fn actions(result: &Object<'_>, call: &str, request: &Value) -> Result<()> {
    for (i, raw) in page(result, call, "totalActions", "actions", request)?
        .iter()
        .enumerate()
    {
        let field = format!("actions[{i}]");
        let action = record(Some(raw), call, &field)?;
        action_fields(&action, call, &field, request)?;
        action_inputs(&action, call, &field, request)?;
        action_outputs(&action, call, &field, request)?;
    }
    Ok(())
}

fn description(raw: Option<&RawValue>, call: &str, field: &str) -> Result<()> {
    let value = s::string(raw, call, field, 0, None)?;
    let min = if value.is_empty() { 0 } else { 5 };
    s::string(raw, call, field, min, Some(2000)).map(|_| ())
}

fn action_fields(action: &Object<'_>, call: &str, field: &str, request: &Value) -> Result<()> {
    s::hex(
        member(action, "txid"),
        call,
        &format!("{field}.txid"),
        Some(32),
    )?;
    s::integer(
        member(action, "satoshis"),
        call,
        &format!("{field}.satoshis"),
        -MONEY,
        MONEY,
    )?;
    let status =
        member(action, "status").and_then(|v| serde_json::from_str::<String>(v.get()).ok());
    if !matches!(
        status.as_deref(),
        Some(
            "completed"
                | "unprocessed"
                | "sending"
                | "unproven"
                | "unsigned"
                | "nosend"
                | "nonfinal"
                | "failed"
        )
    ) {
        return Err(invalid(
            call,
            &format!("{field}.status"),
            "a supported action status",
        ));
    }
    s::boolean(
        member(action, "isOutgoing"),
        call,
        &format!("{field}.isOutgoing"),
        false,
    )?;
    description(
        member(action, "description"),
        call,
        &format!("{field}.description"),
    )?;
    action_labels(action, call, field, request)?;
    for name in ["version", "lockTime"] {
        s::uint(member(action, name), call, &format!("{field}.{name}"), UINT)?;
    }
    Ok(())
}

fn action_labels(action: &Object<'_>, call: &str, field: &str, request: &Value) -> Result<()> {
    let labels = s::strings(member(action, "labels"), call, &format!("{field}.labels"))?;
    required(
        request["includeLabels"] == true,
        labels.is_some(),
        call,
        &format!("{field}.labels"),
        "labels",
    )?;
    query(
        labels.as_deref(),
        request,
        "labels",
        "labelQueryMode",
        call,
        &format!("{field}.labels"),
        "label",
    )?;
    Ok(())
}

fn required(requested: bool, present: bool, call: &str, field: &str, name: &str) -> Result<()> {
    if requested && !present {
        return Err(invalid(
            call,
            field,
            &format!("the explicitly requested {name}"),
        ));
    }
    Ok(())
}

fn optional_hex(
    object: &Object<'_>,
    call: &str,
    field: &str,
    name: &str,
) -> Result<Option<String>> {
    member(object, name)
        .map(|raw| s::hex(Some(raw), call, &format!("{field}.{name}"), None))
        .transpose()
}

fn action_inputs(action: &Object<'_>, call: &str, field: &str, request: &Value) -> Result<()> {
    let path = format!("{field}.inputs");
    let inputs = member(action, "inputs")
        .map(|raw| array(Some(raw), call, &path))
        .transpose()?;
    let requested = [
        "includeInputs",
        "includeInputSourceLockingScripts",
        "includeInputUnlockingScripts",
    ]
    .iter()
    .any(|k| request[k] == true);
    required(requested, inputs.is_some(), call, &path, "inputs")?;
    for (i, raw) in inputs.iter().flatten().enumerate() {
        let field = format!("{path}[{i}]");
        let input = record(Some(raw), call, &field)?;
        s::outpoint(
            member(&input, "sourceOutpoint"),
            call,
            &format!("{field}.sourceOutpoint"),
        )?;
        s::uint(
            member(&input, "sourceSatoshis"),
            call,
            &format!("{field}.sourceSatoshis"),
            MONEY,
        )?;
        let locking = optional_hex(&input, call, &field, "sourceLockingScript")?;
        let unlocking = optional_hex(&input, call, &field, "unlockingScript")?;
        required(
            request["includeInputSourceLockingScripts"] == true,
            locking.is_some(),
            call,
            &format!("{field}.sourceLockingScript"),
            "source locking script",
        )?;
        required(
            request["includeInputUnlockingScripts"] == true,
            unlocking.is_some(),
            call,
            &format!("{field}.unlockingScript"),
            "unlocking script",
        )?;
        description(
            member(&input, "inputDescription"),
            call,
            &format!("{field}.inputDescription"),
        )?;
        s::uint(
            member(&input, "sequenceNumber"),
            call,
            &format!("{field}.sequenceNumber"),
            UINT,
        )?;
    }
    Ok(())
}

fn action_outputs(action: &Object<'_>, call: &str, field: &str, request: &Value) -> Result<()> {
    let path = format!("{field}.outputs");
    let outputs = member(action, "outputs")
        .map(|raw| array(Some(raw), call, &path))
        .transpose()?;
    required(
        request["includeOutputs"] == true || request["includeOutputLockingScripts"] == true,
        outputs.is_some(),
        call,
        &path,
        "outputs",
    )?;
    for (i, raw) in outputs.iter().flatten().enumerate() {
        let field = format!("{path}[{i}]");
        let output = record(Some(raw), call, &field)?;
        history_output(&output, call, &field, request)?;
    }
    Ok(())
}

fn history_output(output: &Object<'_>, call: &str, field: &str, request: &Value) -> Result<()> {
    s::uint(
        member(output, "satoshis"),
        call,
        &format!("{field}.satoshis"),
        MONEY,
    )?;
    let locking = optional_hex(output, call, field, "lockingScript")?;
    required(
        request["includeOutputLockingScripts"] == true,
        locking.is_some(),
        call,
        &format!("{field}.lockingScript"),
        "output locking script",
    )?;
    s::boolean(member(output, "spendable"), call, "spendable", false)?;
    if let Some(raw) = member(output, "customInstructions") {
        s::string(
            Some(raw),
            call,
            &format!("{field}.customInstructions"),
            0,
            None,
        )?;
    }
    s::strings(member(output, "tags"), call, &format!("{field}.tags"))?;
    s::uint(
        member(output, "outputIndex"),
        call,
        &format!("{field}.outputIndex"),
        UINT,
    )?;
    description(
        member(output, "outputDescription"),
        call,
        &format!("{field}.outputDescription"),
    )?;
    s::string(
        member(output, "basket"),
        call,
        &format!("{field}.basket"),
        0,
        Some(300),
    )?;
    Ok(())
}

pub(super) fn outputs(result: &Object<'_>, call: &str, request: &Value) -> Result<()> {
    let outputs = page(result, call, "totalOutputs", "outputs", request)?;
    let beef = member(result, "BEEF")
        .map(|raw| beef::read(Some(raw), call, "BEEF"))
        .transpose()?;
    if !outputs.is_empty() && request["include"] == "entire transactions" && beef.is_none() {
        return Err(invalid(
            call,
            "BEEF",
            "the requested complete output transactions",
        ));
    }
    let mut seen = HashSet::new();
    for (i, raw) in outputs.iter().enumerate() {
        let field = format!("outputs[{i}]");
        let output = record(Some(raw), call, &field)?;
        let point = s::outpoint(
            member(&output, "outpoint"),
            call,
            &format!("{field}.outpoint"),
        )?;
        if !seen.insert(point.clone()) {
            return Err(invalid(
                call,
                &format!("{field}.outpoint"),
                "a unique output in the result page",
            ));
        }
        output_value(&output, call, &field, request, beef.as_ref(), &point)?;
        output_metadata(&output, call, &field, request)?;
    }
    Ok(())
}

fn output_value(
    output: &Object<'_>,
    call: &str,
    field: &str,
    request: &Value,
    beef: Option<&beef::Envelope>,
    point: &(String, u32),
) -> Result<()> {
    let satoshis = s::uint(
        member(output, "satoshis"),
        call,
        &format!("{field}.satoshis"),
        MONEY,
    )?;
    s::boolean(
        member(output, "spendable"),
        call,
        &format!("{field}.spendable"),
        false,
    )?;
    let locking = optional_hex(output, call, field, "lockingScript")?;
    if request["include"] == "locking scripts" && locking.is_none() {
        return Err(invalid(
            call,
            &format!("{field}.lockingScript"),
            "the requested locking script",
        ));
    }
    if let Some(beef) = beef {
        let committed = beef
            .transactions
            .get(&point.0)
            .and_then(Option::as_ref)
            .and_then(|tx| tx.outputs.get(point.1 as usize))
            .ok_or_else(|| {
                invalid(
                    call,
                    &format!("{field}.outpoint"),
                    "an output contained in BEEF",
                )
            })?;
        if committed.satoshis != satoshis as u64 {
            return Err(invalid(
                call,
                &format!("{field}.satoshis"),
                "the amount committed by BEEF",
            ));
        }
        if locking.is_some_and(|s| !s.eq_ignore_ascii_case(&hex::encode(&committed.script))) {
            return Err(invalid(
                call,
                &format!("{field}.lockingScript"),
                "the script committed by BEEF",
            ));
        }
    }
    Ok(())
}

fn output_metadata(output: &Object<'_>, call: &str, field: &str, request: &Value) -> Result<()> {
    if let Some(raw) = member(output, "customInstructions") {
        s::string(
            Some(raw),
            call,
            &format!("{field}.customInstructions"),
            0,
            None,
        )?;
    }
    let tags = s::strings(member(output, "tags"), call, &format!("{field}.tags"))?;
    let labels = s::strings(member(output, "labels"), call, &format!("{field}.labels"))?;
    required(
        request["includeTags"] == true,
        tags.is_some(),
        call,
        &format!("{field}.tags"),
        "output tags",
    )?;
    required(
        request["includeLabels"] == true,
        labels.is_some(),
        call,
        &format!("{field}.labels"),
        "transaction labels",
    )?;
    query(
        tags.as_deref(),
        request,
        "tags",
        "tagQueryMode",
        call,
        &format!("{field}.tags"),
        "tag",
    )
}

fn query(
    actual: Option<&[String]>,
    request: &Value,
    name: &str,
    mode: &str,
    call: &str,
    field: &str,
    kind: &str,
) -> Result<()> {
    if let (Some(actual), Some(requested)) =
        (actual, request[name].as_array().filter(|v| !v.is_empty()))
    {
        let contains = |value: &Value| {
            value
                .as_str()
                .is_some_and(|s| actual.iter().any(|a| a == s))
        };
        let matches = if request[mode] == "all" {
            requested.iter().all(contains)
        } else {
            requested.iter().any(contains)
        };
        if !matches {
            return Err(invalid(call, field, &format!("the requested {kind} query")));
        }
    }
    Ok(())
}
