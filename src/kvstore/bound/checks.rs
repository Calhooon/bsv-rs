//! The representable checks of completeBoundAction.ts:646-883 at edf6e03.
use crate::transaction::{Transaction, TransactionInput};
use crate::wallet::{CreateActionArgs, Outpoint};
use crate::{Error, Result};
use std::collections::{HashMap, HashSet};

pub(super) fn refusal(message: impl Into<String>) -> Error {
    Error::KvStoreError(message.into())
}

pub(super) fn input_outpoint(input: &TransactionInput) -> Result<Outpoint> {
    let embedded = input.source_transaction.as_ref().map(|tx| tx.id());
    if let (Some(txid), Some(source)) = (&input.source_txid, &embedded) {
        if !txid.eq_ignore_ascii_case(source) {
            return Err(refusal("Wallet transaction input source mismatch"));
        }
    }
    let txid = input
        .source_txid
        .as_ref()
        .or(embedded.as_ref())
        .ok_or_else(|| {
            refusal("Wallet input source TXID must be a 32-byte hexadecimal transaction ID")
        })?;
    Outpoint::from_string(&format!("{txid}.{}", input.source_output_index))
}

pub(super) fn bind_requested(args: &CreateActionArgs, tx: &Transaction) -> Result<Vec<usize>> {
    if tx.version != args.version.unwrap_or(1) {
        return Err(refusal(
            "Wallet transaction substituted the requested version",
        ));
    }
    if tx.lock_time != args.lock_time.unwrap_or(0) {
        return Err(refusal(
            "Wallet transaction substituted the requested lock time",
        ));
    }
    let indexes = bind_inputs(args, tx)?;
    let requested_value = bind_outputs(args, tx)?;
    bind_values(tx, &indexes, requested_value)?;
    Ok(indexes)
}

fn bind_inputs(args: &CreateActionArgs, tx: &Transaction) -> Result<Vec<usize>> {
    let mut candidates = HashMap::new();
    for (index, input) in tx.inputs.iter().enumerate() {
        if candidates.insert(input_outpoint(input)?, index).is_some() {
            return Err(refusal(
                "Wallet transaction contains a duplicate input outpoint",
            ));
        }
    }
    let mut requested = HashSet::new();
    let mut indexes = Vec::new();
    for input in args.inputs.iter().flatten() {
        if !requested.insert(&input.outpoint) {
            return Err(refusal(
                "Action requests the same input outpoint more than once",
            ));
        }
        let index = *candidates.get(&input.outpoint).ok_or_else(|| {
            refusal("Wallet transaction does not contain each requested input exactly once")
        })?;
        let candidate = &tx.inputs[index];
        if candidate.sequence != input.sequence_number.unwrap_or(u32::MAX) {
            return Err(refusal(
                "Wallet transaction substituted a requested input sequence",
            ));
        }
        if let Some(script) = &input.unlocking_script {
            if candidate
                .unlocking_script
                .as_ref()
                .map(crate::script::UnlockingScript::to_binary)
                .as_ref()
                != Some(script)
            {
                return Err(refusal(
                    "Wallet transaction substituted a requested unlocking script",
                ));
            }
        }
        indexes.push(index);
    }
    Ok(indexes)
}

fn bind_outputs(args: &CreateActionArgs, tx: &Transaction) -> Result<u64> {
    for (index, output) in tx.outputs.iter().enumerate() {
        amount(output.satoshis, &format!("Wallet output {index}"))?;
    }
    let ordered = args.options.as_ref().and_then(|o| o.randomize_outputs) == Some(false);
    let mut matched = HashSet::new();
    let mut total = 0;
    for (index, output) in args.outputs.iter().flatten().enumerate() {
        amount(output.satoshis, &format!("Requested output {index}"))?;
        let candidate = tx.outputs.iter().enumerate().find(|(i, candidate)| {
            (!ordered || *i == index)
                && !matched.contains(i)
                && candidate.satoshis == Some(output.satoshis)
                && candidate.locking_script.to_binary() == output.locking_script
        });
        let (index, _) = candidate.ok_or_else(|| {
            refusal(if ordered {
                "Wallet transaction substituted a requested output position"
            } else {
                "Wallet transaction omitted or substituted a requested output"
            })
        })?;
        matched.insert(index);
        total = add(total, output.satoshis, "Requested output value")?;
    }
    Ok(total)
}

fn amount(value: impl Into<Option<u64>>, label: &str) -> Result<u64> {
    let value = value.into().filter(|n| *n <= 2_100_000_000_000_000);
    let Some(value) = value else {
        return Err(refusal(format!("{label} must be a valid satoshi amount")));
    };
    Ok(value)
}

fn add(total: u64, value: u64, label: &str) -> Result<u64> {
    let next = total
        .checked_add(value)
        .filter(|n| *n <= 2_100_000_000_000_000);
    next.ok_or_else(|| refusal(format!("{label} exceeds the maximum transaction value")))
}

fn input_value(tx: &Transaction, index: usize) -> Result<u64> {
    let input = &tx.inputs[index];
    let output = input
        .source_transaction
        .as_ref()
        .and_then(|source| source.outputs.get(input.source_output_index as usize))
        .ok_or_else(|| refusal("Wallet signable transaction omitted an input source output"))?;
    amount(
        output.satoshis,
        &format!("Wallet input {index} source output"),
    )
}

fn bind_values(tx: &Transaction, requested: &[usize], requested_value: u64) -> Result<()> {
    let mut explicit = 0;
    for index in requested {
        explicit = add(explicit, input_value(tx, *index)?, "Requested input value")?;
    }
    let requested: HashSet<_> = requested.iter().copied().collect();
    let mut wallet = 0;
    for index in 0..tx.inputs.len() {
        if !requested.contains(&index) {
            wallet = add(wallet, input_value(tx, index)?, "Wallet-added input value")?;
        }
    }
    let mut outputs = 0;
    for output in &tx.outputs {
        outputs = add(
            outputs,
            amount(output.satoshis, "Wallet output")?,
            "Wallet output value",
        )?;
    }
    if outputs > add(explicit, wallet, "Wallet input value")? {
        return Err(refusal(
            "Wallet signable transaction spends more than its inputs",
        ));
    }
    if outputs - requested_value > wallet {
        return Err(refusal(
            "Wallet used a requested input to fund an unrequested output",
        ));
    }
    Ok(())
}

pub(super) fn same_template(partial: &Transaction, signed: &Transaction) -> Result<()> {
    if partial.version != signed.version
        || partial.lock_time != signed.lock_time
        || partial.inputs.len() != signed.inputs.len()
        || partial.outputs.len() != signed.outputs.len()
    {
        return Err(refusal(
            "Wallet signed transaction substituted the authorized template",
        ));
    }
    for (a, b) in partial.inputs.iter().zip(&signed.inputs) {
        if input_outpoint(a)? != input_outpoint(b)? || a.sequence != b.sequence {
            return Err(refusal(
                "Wallet signed transaction substituted an authorized input",
            ));
        }
    }
    for (a, b) in partial.outputs.iter().zip(&signed.outputs) {
        if a.satoshis != b.satoshis || a.locking_script.to_binary() != b.locking_script.to_binary()
        {
            return Err(refusal(
                "Wallet signed transaction substituted an authorized output",
            ));
        }
    }
    Ok(())
}
