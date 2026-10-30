//! Transactions bound to their action requests, WalletResultValidation.ts:1036-1240.

use super::{beef, invalid, scalars, Result};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

const MAX_MONEY: u64 = 2_100_000_000_000_000;
type Sources = HashMap<String, u64>;

pub(super) fn sources(call: &str, request: &Value) -> Result<Sources> {
    if matches!(call, "createAction") {
        return request
            .get("$sourceValues")
            .map(|v| {
                serde_json::from_value(v.clone())
                    .map_err(|e| crate::Error::WalletError(e.to_string()))
            })
            .unwrap_or_else(|| Ok(HashMap::new()));
    }
    Ok(HashMap::new())
}

pub(super) fn capture_sources(
    raw: Option<&serde_json::value::RawValue>,
    request: &Value,
) -> Result<Sources> {
    let mut sources = HashMap::new();
    if let (Some(raw), Some(inputs)) = (raw, request["inputs"].as_array().filter(|a| !a.is_empty()))
    {
        let bytes = super::bytes::read(Some(raw), "createAction", "request.inputBEEF", None, None)?;
        let envelope = beef::parse(&bytes).map_err(|_| {
            invalid(
                "createAction",
                "request.inputBEEF",
                "an exactly framed BEEF envelope",
            )
        })?;
        for input in inputs {
            if let Some((id, index)) = input["outpoint"].as_str().and_then(scalars::parse_outpoint)
            {
                if let Some(output) = envelope
                    .transactions
                    .get(&id)
                    .and_then(Option::as_ref)
                    .and_then(|tx| tx.outputs.get(index as usize))
                {
                    sources.insert(format!("{id}.{index}"), output.satoshis);
                }
            }
        }
    }
    Ok(sources)
}

fn requested_uint(
    value: Option<&Value>,
    default: u64,
    call: &str,
    field: &str,
    max: u64,
) -> Result<u64> {
    use num_traits::ToPrimitive;
    let Some(value) = value else {
        return Ok(default);
    };
    value
        .as_f64()
        .filter(|n| n.fract() == 0.0)
        .and_then(|n| n.to_u64())
        .filter(|n| *n <= max)
        .ok_or_else(|| invalid(call, field, &format!("an integer from 0 to {max}")))
}

fn requested_hex(value: Option<&Value>, call: &str, field: &str) -> Result<String> {
    let text = value
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(call, field, "a string"))?;
    if text.len() % 2 != 0 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid(call, field, "an even-length hex string"));
    }
    Ok(text.to_ascii_lowercase())
}

pub(super) fn create(
    tx: &beef::Transaction,
    call: &str,
    request: &Value,
    sources: &Sources,
    deferred: bool,
) -> Result<()> {
    if request.is_object() {
        let version = requested_uint(
            request.get("version"),
            1,
            call,
            "request.version",
            u32::MAX.into(),
        )?;
        let lock_time = requested_uint(
            request.get("lockTime"),
            0,
            call,
            "request.lockTime",
            u32::MAX.into(),
        )?;
        if u64::from(tx.version) != version {
            return Err(invalid(
                call,
                "tx.version",
                "the requested transaction version",
            ));
        }
        if u64::from(tx.lock_time) != lock_time {
            return Err(invalid(
                call,
                "tx.lockTime",
                "the requested transaction lock time",
            ));
        }
        inputs(tx, call, request)?;
        outputs(tx, call, request)?;
    }
    conservation(tx, call, sources, deferred)
}

fn inputs(tx: &beef::Transaction, call: &str, request: &Value) -> Result<()> {
    let mut candidates = HashMap::new();
    for (i, input) in tx.inputs.iter().enumerate() {
        if candidates.insert(input.outpoint(), i).is_some() {
            return Err(invalid(
                call,
                &format!("tx.inputs[{i}]"),
                "a unique transaction input outpoint",
            ));
        }
    }
    let mut seen = HashSet::new();
    for (i, input) in request["inputs"]
        .as_array()
        .into_iter()
        .flatten()
        .enumerate()
    {
        let field = format!("request.inputs[{i}]");
        let (id, index) = input["outpoint"]
            .as_str()
            .and_then(scalars::parse_outpoint)
            .ok_or_else(|| {
                invalid(
                    call,
                    &format!("{field}.outpoint"),
                    "a canonical transaction outpoint",
                )
            })?;
        let outpoint = format!("{id}.{index}");
        if !seen.insert(outpoint.clone()) {
            return Err(invalid(
                call,
                &format!("{field}.outpoint"),
                "a unique requested input",
            ));
        }
        let i = *candidates
            .get(&outpoint)
            .ok_or_else(|| invalid(call, "tx.inputs", "every requested input exactly once"))?;
        match_input(&tx.inputs[i], input, i, &field, call)?;
    }
    Ok(())
}

fn match_input(
    candidate: &beef::Input,
    input: &Value,
    i: usize,
    field: &str,
    call: &str,
) -> Result<()> {
    let sequence = requested_uint(
        input.get("sequenceNumber"),
        u32::MAX.into(),
        call,
        &format!("{field}.sequenceNumber"),
        u32::MAX.into(),
    )?;
    if u64::from(candidate.sequence) != sequence {
        return Err(invalid(
            call,
            &format!("tx.inputs[{i}].sequence"),
            "the requested input sequence",
        ));
    }
    if let Some(script) = input.get("unlockingScript") {
        if hex::encode(&candidate.script)
            != requested_hex(Some(script), call, &format!("{field}.unlockingScript"))?
        {
            return Err(invalid(
                call,
                &format!("tx.inputs[{i}].unlockingScript"),
                "the requested unlocking script",
            ));
        }
    }
    Ok(())
}

fn outputs(tx: &beef::Transaction, call: &str, request: &Value) -> Result<()> {
    let mut available = HashMap::new();
    for (i, output) in tx.outputs.iter().enumerate() {
        amount(output.satoshis, call, &format!("tx.outputs[{i}].satoshis"))?;
        *available
            .entry((output.satoshis, hex::encode(&output.script)))
            .or_insert(0usize) += 1;
    }
    for (i, output) in request["outputs"]
        .as_array()
        .into_iter()
        .flatten()
        .enumerate()
    {
        let field = format!("request.outputs[{i}]");
        let amount = requested_uint(
            output.get("satoshis"),
            0,
            call,
            &format!("{field}.satoshis"),
            MAX_MONEY,
        )?;
        let script = requested_hex(
            output.get("lockingScript"),
            call,
            &format!("{field}.lockingScript"),
        )?;
        if request["options"]["randomizeOutputs"] == false {
            if tx
                .outputs
                .get(i)
                .is_none_or(|o| o.satoshis != amount || hex::encode(&o.script) != script)
            {
                return Err(invalid(
                    call,
                    &format!("tx.outputs[{i}]"),
                    "the requested output at the requested position",
                ));
            }
        } else {
            let count = available.entry((amount, script)).or_default();
            if *count == 0 {
                return Err(invalid(
                    call,
                    "tx.outputs",
                    "every requested output with its requested amount and script",
                ));
            }
            *count -= 1;
        }
    }
    Ok(())
}

fn amount(value: u64, call: &str, field: &str) -> Result<()> {
    if value > MAX_MONEY {
        return Err(invalid(
            call,
            field,
            "an integer from 0 to 2100000000000000",
        ));
    }
    Ok(())
}

pub(super) fn conservation(
    tx: &beef::Transaction,
    call: &str,
    sources: &Sources,
    deferred: bool,
) -> Result<()> {
    let mut input_value = 0u64;
    let mut unknown = false;
    let mut seen = HashSet::new();
    for (i, input) in tx.inputs.iter().enumerate() {
        let outpoint = input.outpoint();
        if !seen.insert(outpoint.clone()) {
            return Err(invalid(
                call,
                &format!("tx.inputs[{i}]"),
                "a unique transaction input outpoint",
            ));
        }
        let Some(value) = input.satoshis.or_else(|| sources.get(&outpoint).copied()) else {
            if !deferred {
                return Err(invalid(
                    call,
                    &format!("tx.inputs[{i}].sourceSatoshis"),
                    "source transaction evidence for every completed transaction input",
                ));
            }
            unknown = true;
            continue;
        };
        amount(value, call, &format!("tx.inputs[{i}].sourceSatoshis"))?;
        input_value = input_value
            .checked_add(value)
            .filter(|n| *n <= MAX_MONEY)
            .ok_or_else(|| invalid(call, "tx.inputs", "a valid total input value"))?;
    }
    let mut output_value = 0u64;
    for (i, output) in tx.outputs.iter().enumerate() {
        amount(output.satoshis, call, &format!("tx.outputs[{i}].satoshis"))?;
        output_value = output_value
            .checked_add(output.satoshis)
            .filter(|n| *n <= MAX_MONEY)
            .ok_or_else(|| invalid(call, "tx.outputs", "a valid total output value"))?;
    }
    if !unknown && output_value > input_value {
        return Err(invalid(
            call,
            "tx.outputs",
            "a total value no greater than the transaction inputs",
        ));
    }
    Ok(())
}

pub(super) fn sign(tx: &beef::Transaction, call: &str, request: &Value) -> Result<()> {
    if let Some(spends) = request["spends"].as_object() {
        for index in super::request_keys(request, "spends") {
            let spend = &spends[index];
            let field = format!("request.spends.{index}");
            if index.is_empty()
                || (index.len() > 1 && index.starts_with('0'))
                || !index.bytes().all(|b| b.is_ascii_digit())
            {
                return Err(invalid(call, &field, "a canonical input index"));
            }
            let input = index
                .parse::<usize>()
                .ok()
                .and_then(|i| tx.inputs.get(i))
                .ok_or_else(|| {
                    invalid(
                        call,
                        &format!("tx.inputs[{index}]"),
                        "the requested input index",
                    )
                })?;
            if hex::encode(&input.script)
                != requested_hex(
                    spend.get("unlockingScript"),
                    call,
                    &format!("{field}.unlockingScript"),
                )?
            {
                return Err(invalid(
                    call,
                    &format!("tx.inputs[{index}]"),
                    "the requested unlocking script",
                ));
            }
            if let Some(sequence) = spend.get("sequenceNumber") {
                if u64::from(input.sequence)
                    != requested_uint(
                        Some(sequence),
                        0,
                        call,
                        &format!("{field}.sequenceNumber"),
                        u32::MAX.into(),
                    )?
                {
                    return Err(invalid(
                        call,
                        &format!("tx.inputs[{index}].sequence"),
                        "the requested input sequence",
                    ));
                }
            }
        }
    }
    Ok(())
}
