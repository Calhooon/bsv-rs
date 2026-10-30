//! Action-result order and member bindings, WalletResultValidation.ts:1242-1374.

use super::{action_binding, array, beef, bytes, invalid, member, record, scalars, Object, Result};
use serde_json::{value::RawValue, Value};
use std::collections::HashSet;

struct Action {
    txid: Option<String>,
    tx: Option<beef::Transaction>,
    signable: Option<beef::Transaction>,
    change: Option<Vec<(String, u32)>>,
    sends: Option<Vec<String>>,
}

pub(super) fn validate(
    result: &Object<'_>,
    call: &str,
    request: &Value,
    bytes: &bytes::Fields<'_>,
) -> Result<()> {
    let evidence = action_binding::sources(call, request)?;
    let action = read(result, call, bytes)?;
    request_shape(&action, call, request)?;
    if call == "createAction" {
        if let Some(tx) = &action.tx {
            action_binding::create(tx, call, request, &evidence, false, bytes.action)?;
        }
        if let Some(tx) = &action.signable {
            action_binding::create(tx, call, request, &evidence, true, bytes.action)?;
        }
    } else if let Some(tx) = &action.tx {
        action_binding::sign(tx, call, request)?;
        action_binding::conservation(tx, call, &evidence, false)?;
    }
    bind(&action, result, call, request)
}

fn read(result: &Object<'_>, call: &str, bytes: &bytes::Fields<'_>) -> Result<Action> {
    let txid = member(result, "txid")
        .map(|raw| scalars::hex(Some(raw), call, "txid", Some(32)))
        .transpose()?;
    let tx = member(result, "tx")
        .map(|raw| beef::transaction(Some(raw), call, "tx", txid.as_deref(), bytes))
        .transpose()?;
    if txid
        .as_ref()
        .zip(tx.as_ref())
        .is_some_and(|(id, tx)| !id.eq_ignore_ascii_case(&tx.txid))
    {
        return Err(invalid(call, "tx", "a BEEF transaction matching txid"));
    }
    let change = member(result, "noSendChange")
        .map(|raw| {
            array(Some(raw), call, "noSendChange")?
                .iter()
                .enumerate()
                .map(|(i, raw)| scalars::outpoint(Some(raw), call, &format!("noSendChange[{i}]")))
                .collect::<Result<Vec<_>>>()
        })
        .transpose()?;
    let sends = sends(member(result, "sendWithResults"), call)?;
    let signable = member(result, "signableTransaction")
        .map(|raw| {
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
            let object = record(Some(raw), call, "signableTransaction")?;
            let tx = beef::transaction(
                member(&object, "tx"),
                call,
                "signableTransaction.tx",
                None,
                bytes,
            )?;
            scalars::base64(
                member(&object, "reference"),
                call,
                "signableTransaction.reference",
            )?;
            Ok(tx)
        })
        .transpose()?;
    Ok(Action {
        txid,
        tx,
        signable,
        change,
        sends,
    })
}

fn sends(raw: Option<&RawValue>, call: &str) -> Result<Option<Vec<String>>> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let items = array(Some(raw), call, "sendWithResults")?;
    if items.len() > 1001 {
        return Err(invalid(
            call,
            "sendWithResults",
            "at most 1001 transaction results",
        ));
    }
    items
        .iter()
        .enumerate()
        .map(|(i, raw)| {
            let field = format!("sendWithResults[{i}]");
            let object = record(Some(raw), call, &field)?;
            let txid = scalars::hex(
                member(&object, "txid"),
                call,
                &format!("{field}.txid"),
                Some(32),
            )?;
            let status = member(&object, "status")
                .and_then(|raw| serde_json::from_str::<String>(raw.get()).ok());
            if !matches!(status.as_deref(), Some("unproven" | "sending" | "failed")) {
                return Err(invalid(
                    call,
                    &format!("{field}.status"),
                    "a supported status",
                ));
            }
            Ok(txid.to_ascii_lowercase())
        })
        .collect::<Result<Vec<_>>>()
        .map(Some)
}

fn request_shape(action: &Action, call: &str, request: &Value) -> Result<()> {
    if !request.is_object() {
        return Ok(());
    }
    if call == "signAction" {
        if action.txid.is_none() {
            return Err(invalid(call, "txid", "the completed signed transaction"));
        }
        return Ok(());
    }
    for field in ["inputs", "outputs"] {
        if request[field].as_array().is_some_and(|a| a.len() > 100_000) {
            return Err(invalid(
                call,
                &format!("request.{field}"),
                "at most 100000 entries",
            ));
        }
    }
    let inputs = request["inputs"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default();
    let creates = !inputs.is_empty()
        || request["outputs"].as_array().is_some_and(|v| !v.is_empty())
        || request["options"]["sendWith"]
            .as_array()
            .is_none_or(Vec::is_empty);
    let deferred = creates
        && (request["options"]["signAndProcess"] == false
            || inputs
                .iter()
                .any(|input| input.get("unlockingScript").is_none()));
    if deferred && action.signable.is_none() {
        return Err(invalid(
            call,
            "signableTransaction",
            "the requested deferred-signing transaction",
        ));
    }
    if creates && !deferred && action.txid.is_none() {
        return Err(invalid(call, "txid", "the requested completed transaction"));
    }
    if creates && !deferred && action.signable.is_some() {
        return Err(invalid(
            call,
            "signableTransaction",
            "absent for a completed transaction request",
        ));
    }
    Ok(())
}

fn bind(action: &Action, result: &Object<'_>, call: &str, request: &Value) -> Result<()> {
    let subject = action
        .txid
        .as_deref()
        .or_else(|| action.signable.as_ref().map(|tx| tx.txid.as_str()));
    if let Some(change) = &action.change {
        let subject = subject
            .ok_or_else(|| invalid(call, "noSendChange", "associated with a transaction"))?;
        for (i, (id, _)) in change.iter().enumerate() {
            if !id.eq_ignore_ascii_case(subject) {
                return Err(invalid(
                    call,
                    &format!("noSendChange[{i}]"),
                    "an outpoint of the returned transaction",
                ));
            }
        }
    }
    let mut allowed: HashSet<String> = subject.map(str::to_ascii_lowercase).into_iter().collect();
    if let Some(sends) = request["options"]["sendWith"].as_array() {
        allowed.extend(
            sends
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_ascii_lowercase),
        );
    }
    let mut seen = HashSet::new();
    for (i, id) in action.sends.iter().flatten().enumerate() {
        let field = format!("sendWithResults[{i}].txid");
        if !seen.insert(id) {
            return Err(invalid(call, &field, "a unique transaction"));
        }
        if !allowed.is_empty() && !allowed.contains(id) {
            return Err(invalid(call, &field, "a submitted or returned transaction"));
        }
    }
    outcome(action, result, call, request)
}

fn outcome(action: &Action, result: &Object<'_>, call: &str, request: &Value) -> Result<()> {
    if action.tx.is_some() && action.txid.is_none() {
        return Err(invalid(call, "txid", "present with tx"));
    }
    if request.is_object()
        && action.txid.is_some()
        && action.tx.is_none()
        && request["options"]["returnTXIDOnly"] != true
    {
        return Err(invalid(
            call,
            "tx",
            "transaction evidence unless returnTXIDOnly was explicitly requested",
        ));
    }
    if call == "signAction" && result.contains_key("noSendChange") {
        return Err(invalid(call, "noSendChange", "an absent field"));
    }
    if action.txid.is_none()
        && action.signable.is_none()
        && action.sends.as_ref().is_none_or(Vec::is_empty)
    {
        return Err(invalid(
            call,
            "outcome",
            "a transaction, signable transaction, or batch-send result",
        ));
    }
    Ok(())
}
