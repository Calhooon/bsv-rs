//! The door as a second runner over the evaluation corpus (#855): every
//! `node-script` vector and every input of every `node-transaction` vector
//! with its prevout, judged through `bsv_rs::transaction::verify_input` on
//! the spending transaction's bytes, against the `Spend` runner's answer
//! (`run_node_script`, `validate_tx_input`): valid where it is valid, refused
//! in its words where it refuses. No pinned total moves: this runner counts
//! its own cases and names each vector that differs.

use bsv_rs::script::UnlockingScript;
use bsv_rs::transaction::{
    verify_input, DefaultMode, InputRefusal, InputRules, Transaction, TransactionInput,
    TransactionOutput,
};
use serde_json::Value;

use super::{b, crediting_txid, n, run_node_script, s, validate_tx_input, LockingScript};

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
    let mut txin = TransactionInput::new((bsv_rs::primitives::to_hex(&source)).parse().unwrap(), 0);
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
            txin.source_txid.is_some_and(|t| t == s(p, "txid"))
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
        let spend = validate_tx_input(&tx, vin, prevout);
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
                let spend = run_node_script(input)
                    .and_then(|valid| valid.then_some(()).ok_or_else(|| "Ok(false)".to_string()));
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
