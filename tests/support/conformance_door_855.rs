//! The door as a second runner over the evaluation corpus (#855): every
//! `node-script` vector and every input of every `node-transaction` vector
//! with its prevout, judged through `bsv_rs::transaction::verify_input` on
//! the spending transaction's bytes, against the `Spend` runner's answer
//! (`run_node_script`, `validate_tx_input`): valid where it is valid, refused
//! in its words where it refuses. No pinned total moves: this runner counts
//! its own cases and names each vector that differs.
//!
//! In the default mode the door runs the node's pay-to-script-hash step for a
//! coin locked by `a9 14 <20 bytes> 87` (GHSA-fr33-7jw7-mwwh): where the
//! `Spend` runner answers valid for such a coin, the door's answer is the
//! step's, built here by hand as a second `Spend::new` of the same input.

use bsv_rs::primitives::bsv::sighash::{TxInput, TxOutput};
use bsv_rs::script::{Script, Spend, SpendParams, UnlockingScript};
use bsv_rs::transaction::{
    verify_input, DefaultMode, InputRefusal, InputRules, Transaction, TransactionInput,
    TransactionOutput,
};
use serde_json::Value;

use super::{b, crediting_txid, n, run_node_script, s, validate_tx_input, LockingScript};

/// The step's scripts for a locking script of exactly `a9 14 <20 bytes> 87`:
/// the unlocking script without its last push, and that push's element as
/// the redeem script; the unlocking script whole (and the locking script)
/// when it is not push-only, for the step's push-only rule to refuse.
fn redeem_split(lock: &[u8], unlock: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    if !(lock.len() == 23 && lock[..2] == [0xa9, 0x14] && lock[22] == 0x87) {
        return None;
    }
    let script = Script::from_binary(unlock).ok()?;
    let mut chunks = script.chunks().to_vec();
    let pushes = script.is_push_only() && script.truncated_push().is_none();
    let Some(last) = chunks.pop().filter(|c| pushes && c.op != 0x50) else {
        return Some((unlock.to_vec(), lock.to_vec()));
    };
    let element = match last.op {
        0x4f => vec![0x81],
        0x51..=0x60 => vec![last.op - 0x50],
        _ => last.data.unwrap_or_default(),
    };
    Some((Script::from_chunks(chunks).to_binary(), element))
}

/// The step's `Spend` judged: push-only at every version, the Chronicle
/// opcodes off.
fn step_words(mut spend: Spend) -> Result<(), String> {
    spend.set_require_push_only(true);
    spend.set_utxo_after_chronicle(false);
    spend.validate().map(|_| ()).map_err(|e| e.message)
}

/// The `Spend` runner's answer for a node-script vector, with the step by
/// hand where the coin takes it.
fn node_script_expected(input: &Value) -> Result<(), String> {
    let first = run_node_script(input)
        .and_then(|valid| valid.then_some(()).ok_or_else(|| "Ok(false)".to_string()));
    let lock = bsv_rs::primitives::from_hex(s(input, "script_pubkey_hex")).unwrap_or_default();
    let unlock = bsv_rs::primitives::from_hex(s(input, "script_sig_hex")).unwrap_or_default();
    let (Ok(()), Some((before, redeem))) = (&first, redeem_split(&lock, &unlock)) else {
        return first;
    };
    let amount = n(input, "amount_satoshis") as u64;
    step_words(Spend::new(SpendParams {
        source_txid: crediting_txid(&LockingScript::from_binary(&lock).unwrap(), amount),
        source_output_index: 0,
        source_satoshis: amount,
        locking_script: LockingScript::from_binary(&redeem).unwrap(),
        transaction_version: n(input, "tx_version") as i32,
        other_inputs: vec![],
        outputs: vec![TxOutput {
            satoshis: amount,
            script: vec![],
        }],
        input_index: 0,
        unlocking_script: UnlockingScript::from_binary(&before).unwrap(),
        input_sequence: 0xffff_ffff,
        lock_time: 0,
        memory_limit: None,
        work_limit: None,
    }))
}

/// The `Spend` runner's answer for input `vin` of a node-transaction vector,
/// with the step by hand where the coin takes it.
fn node_transaction_expected(tx: &Transaction, vin: usize, prevout: &Value) -> Result<(), String> {
    let first = validate_tx_input(tx, vin, prevout);
    let txin = &tx.inputs()[vin];
    let lock = bsv_rs::primitives::from_hex(s(prevout, "script_pubkey_hex")).unwrap_or_default();
    let unlock = txin
        .unlocking_script
        .as_ref()
        .map(|u| u.to_binary())
        .unwrap_or_default();
    let (Ok(()), Some((before, redeem))) = (&first, redeem_split(&lock, &unlock)) else {
        return first;
    };
    let other_inputs = tx
        .inputs()
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != vin)
        .map(|(_, inp)| TxInput {
            txid: inp.get_source_txid_bytes().unwrap_or([0u8; 32]),
            output_index: inp.source_output_index,
            script: inp
                .unlocking_script
                .as_ref()
                .map(|u| u.to_binary())
                .unwrap_or_default(),
            sequence: inp.sequence,
        })
        .collect();
    let outputs = tx
        .outputs()
        .iter()
        .map(|o| TxOutput {
            satoshis: o.satoshis.unwrap_or(0),
            script: o.locking_script.to_binary(),
        })
        .collect();
    step_words(Spend::new(SpendParams {
        source_txid: txin.get_source_txid_bytes().map_err(|e| e.to_string())?,
        source_output_index: txin.source_output_index,
        source_satoshis: n(prevout, "amount_satoshis") as u64,
        locking_script: LockingScript::from_binary(&redeem).unwrap(),
        transaction_version: tx.version() as i32,
        other_inputs,
        outputs,
        input_index: vin,
        unlocking_script: UnlockingScript::from_binary(&before).unwrap(),
        input_sequence: txin.sequence,
        lock_time: tx.lock_time(),
        memory_limit: None,
        work_limit: None,
    }))
}

/// The door's answer as the `Spend` runner states it: `Ok(())` or the
/// interpreter's words.
fn door_words(
    answer: Result<bsv_rs::transaction::InputVerified, InputRefusal>,
) -> Result<(), String> {
    match answer {
        Ok(_) => Ok(()),
        Err(InputRefusal::Invalid(e)) | Err(InputRefusal::Declined(e)) => Err(e.message),
        Err(other) => Err(format!("refused before evaluation: {other}")),
    }
}

/// The spending transaction `run_node_script` builds by hand, as bytes.
fn node_script_door(input: &Value) -> Option<Result<(), String>> {
    let locking = LockingScript::from_hex(s(input, "script_pubkey_hex")).ok()?;
    let sig_hex = s(input, "script_sig_hex");
    let unlocking = if sig_hex.is_empty() {
        UnlockingScript::new()
    } else {
        UnlockingScript::from_hex(sig_hex).ok()?
    };
    let amount = n(input, "amount_satoshis") as u64;
    let mut source = crediting_txid(&locking, amount);
    source.reverse();
    let mut txin = TransactionInput::new(bsv_rs::primitives::to_hex(&source), 0);
    txin.set_unlocking_script(unlocking);
    let output = TransactionOutput::new(amount, LockingScript::new());
    let version = n(input, "tx_version") as i32 as u32;
    let bytes = Transaction::with_params(version, vec![txin], vec![output], 0).to_binary();
    let after_chronicle = input["flags"]
        .as_array()
        .is_some_and(|a| a.iter().any(|f| f.as_str() == Some("UTXO_AFTER_CHRONICLE")));
    let rules = InputRules::reference_default_with(
        DefaultMode::new().with_utxo_after_chronicle(after_chronicle),
    );
    Some(door_words(verify_input(
        &locking.to_binary(),
        amount,
        &bytes,
        0,
        &rules,
    )))
}

#[derive(Default)]
pub struct DoorCensus {
    pub scripts: usize,
    pub inputs: usize,
    pub not_expressed: Vec<String>,
    pub differences: Vec<String>,
}

fn node_transaction_door(id: &str, input: &Value, census: &mut DoorCensus) {
    let Ok(bytes) = bsv_rs::primitives::from_hex(s(input, "tx_hex")) else {
        return;
    };
    let Ok(tx) = Transaction::from_binary(&bytes) else {
        // The strict reader refuses it; the `Spend` runner reads no input of
        // it either (its parse or round trip fails).
        return;
    };
    let empty = vec![];
    let prevouts = input["prevouts"].as_array().unwrap_or(&empty);
    for (vin, txin) in tx.inputs().iter().enumerate() {
        let Some(prevout) = prevouts.iter().find(|p| {
            Some(s(p, "txid")) == txin.source_txid.as_deref()
                && (n(p, "vout") as u32) == txin.source_output_index
        }) else {
            continue;
        };
        let Ok(lock) = bsv_rs::primitives::from_hex(s(prevout, "script_pubkey_hex")) else {
            continue;
        };
        let amount = n(prevout, "amount_satoshis") as u64;
        let door = door_words(verify_input(
            &lock,
            amount,
            &bytes,
            vin,
            &InputRules::default(),
        ));
        let spend = node_transaction_expected(&tx, vin, prevout);
        census.inputs += 1;
        if door != spend {
            census
                .differences
                .push(format!("{id} input {vin}: door {door:?}, Spend {spend:?}"));
        }
    }
}

/// Runs every vector of the corpus file through the door beside its runner.
pub fn door_census(vectors: &[Value]) -> DoorCensus {
    let mut census = DoorCensus::default();
    for vector in vectors {
        let id = s(vector, "id");
        let parity = s(vector, "parity_class");
        if b(vector, "skip") || (!parity.is_empty() && parity != "required") {
            continue;
        }
        let input = &vector["input"];
        match s(input, "fixture_type") {
            "node-script" => {
                let Some(door) = node_script_door(input) else {
                    census.not_expressed.push(id.to_string());
                    continue;
                };
                let spend = node_script_expected(input);
                census.scripts += 1;
                if door != spend {
                    census
                        .differences
                        .push(format!("{id}: door {door:?}, Spend {spend:?}"));
                }
            }
            "node-transaction" => node_transaction_door(id, input, &mut census),
            _ => {}
        }
    }
    census
}
