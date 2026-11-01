//! Regression (#603): the default methods of `script::transaction`'s traits,
//! each pinned against the node's reading of a spend's transaction as the
//! sibling's Lean definition states it (`~/bsv/bsv-script-lean` at
//! `387dab35`, every rule citing bitcoin-sv by file and line).
//!
//! No implementor of `TransactionContext` exists in the crate, and the
//! sibling's harness reads none: under each of the seven surviving mutants of
//! the widened run 41327640129 no entry of its nine corpora (seed, flow,
//! arith, stack, crypto, bytes, eras, gen, tx) moves its verdict. The tests
//! are therefore hand tests over this crate's own transactions:
//! `TX_VALID_2` (`tests/transaction/vectors/tx_valid.rs`, two inputs and two
//! outputs, the mainnet transaction `8c9aa966...`) for the accessors and the
//! counts, and a two-input P2PKH spend built and signed by this crate's writer
//! for `validate_all_inputs`.
//!
//! * `input`: the input at `nIn`, none past the inputs (`Sighash.lean:127-128`,
//!   `inputAt`, and `TxContext.lean:45,56`, `tx.inputs[nIn]?`; the node's
//!   `vin[nIn]`).
//! * `output`: the output at `nIn`, none past the outputs (`Sighash.lean:164-170`,
//!   `bip143Outputs`' `tx.outputs[nIn]?`).
//! * `input_count`, `output_count`: the transaction's input and output counts
//!   (`Sighash.lean:134-137`, `serTx`'s `compactSize tx.inputs.length` and
//!   `tx.outputs.length`; `:259-263`, `sighashOriginal`'s
//!   `tx.inputs.length ≤ nIn` and `tx.outputs.length ≤ nIn` bounds;
//!   `Tx.lean:88-98`, the decoder's two counts).
//! * `validate_all_inputs`: every input judged in order and the first refusal
//!   the transaction's (`BsvChain/Utxo.lean:149-165`, `checkInputScripts`,
//!   `validation.cpp:2864-2868,2900-2924` at bitcoin-sv `6504a3af`).
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

#[path = "transaction/vectors/tx_valid.rs"]
mod tx_valid;

use bsv_rs::primitives::bsv::sighash::{parse_transaction, TxInput, TxOutput};
use bsv_rs::primitives::{from_hex, PrivateKey};
use bsv_rs::script::templates::P2PKH;
use bsv_rs::script::{
    LockingScript, ScriptEvaluationError, SignOutputs, SimpleUtxo, Spend, SpendParams,
    SpendValidation, TransactionContext, TransactionInputContext, TransactionOutputContext,
    UnlockingScript,
};
use bsv_rs::transaction::{Transaction, TransactionInput, TransactionOutput};

/// One input of the adapter: the outpoint, the sequence, the coin and the
/// unlocking script.
struct Input {
    txid: [u8; 32],
    index: u32,
    sequence: u32,
    satoshis: Option<u64>,
    locking: Option<LockingScript>,
    unlocking: UnlockingScript,
}

impl TransactionInputContext for Input {
    fn source_txid(&self) -> &[u8; 32] {
        &self.txid
    }
    fn source_output_index(&self) -> u32 {
        self.index
    }
    fn sequence(&self) -> u32 {
        self.sequence
    }
    fn source_satoshis(&self) -> Option<u64> {
        self.satoshis
    }
    fn source_locking_script(&self) -> Option<&LockingScript> {
        self.locking.as_ref()
    }
    fn unlocking_script(&self) -> &UnlockingScript {
        &self.unlocking
    }
}

/// A transaction read through the traits: only the four required methods are
/// implemented, so every other method is the trait's default under test.
struct Tx {
    version: i32,
    inputs: Vec<Input>,
    outputs: Vec<SimpleUtxo>,
    lock_time: u32,
}

impl TransactionContext for Tx {
    type Input = Input;
    type Output = SimpleUtxo;
    fn version(&self) -> i32 {
        self.version
    }
    fn inputs(&self) -> &[Input] {
        &self.inputs
    }
    fn outputs(&self) -> &[SimpleUtxo] {
        &self.outputs
    }
    fn lock_time(&self) -> u32 {
        self.lock_time
    }
}

impl SpendValidation for Tx {
    /// The input's scripts run by the interpreter in the SDK default mode,
    /// over the transaction as the slices hold it (no default method used, so
    /// a mutant of one cannot reach the verdict through here).
    fn validate_input(&self, index: usize) -> Result<bool, Box<ScriptEvaluationError>> {
        let input = &self.inputs[index];
        let other_inputs = self
            .inputs
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != index)
            .map(|(_, o)| TxInput {
                txid: o.txid,
                output_index: o.index,
                script: o.unlocking.to_binary(),
                sequence: o.sequence,
            })
            .collect();
        let outputs = self
            .outputs
            .iter()
            .map(|o| TxOutput {
                satoshis: o.satoshis,
                script: o.locking_script.to_binary(),
            })
            .collect();
        let mut spend = Spend::new(SpendParams {
            source_txid: input.txid,
            source_output_index: input.index,
            source_satoshis: input.satoshis.unwrap(),
            locking_script: input.locking.clone().unwrap(),
            transaction_version: self.version,
            other_inputs,
            outputs,
            input_index: index,
            unlocking_script: input.unlocking.clone(),
            input_sequence: input.sequence,
            lock_time: self.lock_time,
            memory_limit: None,
            work_limit: None,
        });
        spend.validate().map_err(Box::new)
    }
}

/// A raw transaction read by the node's decoder rule (`Tx.lean:88-98`), its
/// coins attached when known.
fn adapt(raw: &[u8], coins: &[(u64, LockingScript)]) -> Tx {
    let tx = parse_transaction(raw).unwrap();
    Tx {
        version: tx.version,
        inputs: tx
            .inputs
            .iter()
            .enumerate()
            .map(|(i, input)| Input {
                txid: input.txid,
                index: input.output_index,
                sequence: input.sequence,
                satoshis: coins.get(i).map(|c| c.0),
                locking: coins.get(i).map(|c| c.1.clone()),
                unlocking: UnlockingScript::from_binary(&input.script).unwrap(),
            })
            .collect(),
        outputs: tx
            .outputs
            .iter()
            .map(|o| SimpleUtxo {
                satoshis: o.satoshis,
                locking_script: LockingScript::from_binary(&o.script).unwrap(),
            })
            .collect(),
        lock_time: tx.locktime,
    }
}

fn tx_valid_2() -> Tx {
    adapt(&from_hex(tx_valid::TX_VALID_2).unwrap(), &[])
}

/// The internal-order txid of `TX_VALID_2`'s second input, as its bytes stand
/// in the vector (`a3195e7a...`, output index 2).
const TX_VALID_2_INPUT_1_TXID: &str =
    "a3195e7a1ab665473ff717814f6881485dc8759bebe97e31c301ffe7933a656f";

/// `Sighash.lean:127-128` (`inputAt`, `tx.inputs[nIn]?`) and
/// `TxContext.lean:45,56`: the input at an index of the transaction is that
/// input, and none past the last.
#[test]
fn input_at_nin_is_the_transactions_input_sighash_input_at_tx_valid_2() {
    let tx = tx_valid_2();
    let second = tx.input(1).expect("TX_VALID_2 has an input at index 1");
    assert_eq!(
        second.source_txid().to_vec(),
        from_hex(TX_VALID_2_INPUT_1_TXID).unwrap()
    );
    assert_eq!(second.source_output_index(), 2);
    assert_eq!(second.sequence(), 0xffff_ffff);
    let first = tx.input(0).expect("TX_VALID_2 has an input at index 0");
    assert_eq!(first.source_output_index(), 0);
    assert!(tx.input(2).is_none(), "no input past the two");
}

/// `Sighash.lean:164-170` (`bip143Outputs`, `tx.outputs[nIn]?` under SINGLE):
/// the output at an index of the transaction is that output, and none past
/// the last.
#[test]
fn output_at_nin_is_the_transactions_output_sighash_bip143_outputs_tx_valid_2() {
    let tx = tx_valid_2();
    let first = tx.output(0).expect("TX_VALID_2 has an output at index 0");
    assert_eq!(first.satoshis(), 0x0010_6b20);
    let second = tx.output(1).expect("TX_VALID_2 has an output at index 1");
    assert_eq!(second.satoshis(), 0x0001_caf0);
    assert_eq!(
        second.locking_script().to_hex(),
        "76a9149e3e2d23973a04ec1b02be97c30ab9f2f27c3b2c88ac"
    );
    assert!(tx.output(2).is_none(), "no output past the two");
}

/// `Sighash.lean:134-137` (`serTx`, `compactSize tx.inputs.length` and
/// `tx.outputs.length`), `:259-263` (`sighashOriginal`'s bounds on both) and
/// `Tx.lean:88-98` (the decoder's two counts): `TX_VALID_2` counts two inputs
/// and two outputs, the counts of its slices.
#[test]
fn input_and_output_counts_are_the_transactions_sighash_ser_tx_tx_valid_2() {
    let tx = tx_valid_2();
    assert_eq!(tx.input_count(), 2);
    assert_eq!(tx.output_count(), 2);
    assert_eq!(tx.input_count(), tx.inputs().len());
    assert_eq!(tx.output_count(), tx.outputs().len());
}

/// A two-input, two-output P2PKH spend built and signed by this crate's
/// writer, with its two coins.
fn signed_two_input_spend() -> (Vec<u8>, Vec<(u64, LockingScript)>) {
    let keys = [
        PrivateKey::from_hex(&"11".repeat(32)).unwrap(),
        PrivateKey::from_hex(&"22".repeat(32)).unwrap(),
    ];
    let mut funding = Transaction::new();
    let mut mined = TransactionInput::new("33".repeat(32), 0);
    mined.unlocking_script = Some(UnlockingScript::new());
    funding.add_input(mined).unwrap();
    for (key, sats) in keys.iter().zip([10_000u64, 20_000]) {
        let lock = P2PKH::lock_from_address(&key.public_key().to_address()).unwrap();
        funding
            .add_output(TransactionOutput::new(sats, lock))
            .unwrap();
    }
    let coins: Vec<(u64, LockingScript)> = funding
        .outputs
        .iter()
        .map(|o| (o.satoshis.unwrap(), o.locking_script.clone()))
        .collect();
    let mut spend = Transaction::new();
    for (vout, key) in keys.iter().enumerate() {
        let mut input = TransactionInput::with_source_transaction(funding.clone(), vout as u32);
        input.set_unlocking_script_template(P2PKH::unlock(key, SignOutputs::All, false));
        spend.add_input(input).unwrap();
    }
    for (key, sats) in keys.iter().zip([14_000u64, 15_000]) {
        spend
            .add_p2pkh_output(&key.public_key().to_address(), Some(sats))
            .unwrap();
    }
    futures::executor::block_on(spend.sign()).unwrap();
    (spend.to_binary(), coins)
}

/// `BsvChain/Utxo.lean:149-165` (`checkInputScripts`: every input judged, in
/// order, the first refusal the transaction's; `validation.cpp:2864-2868,
/// 2900-2924` at bitcoin-sv `6504a3af`): a spend whose two inputs pass is
/// valid, and the same spend with its second input's unlocking script
/// replaced by the first's (a key and signature for the other coin) is
/// refused at input 1, input 0 still passing.
#[test]
fn every_input_is_judged_and_the_first_refusal_is_the_transactions_utxo_check_input_scripts_603() {
    let (raw, coins) = signed_two_input_spend();
    let tx = adapt(&raw, &coins);
    assert!(tx.validate_input(0).unwrap(), "input 0 passes");
    assert!(tx.validate_input(1).unwrap(), "input 1 passes");
    assert!(tx.validate_all_inputs().is_ok(), "both inputs pass");

    let mut bad = adapt(&raw, &coins);
    bad.inputs[1].unlocking = bad.inputs[0].unlocking.clone();
    assert!(bad.validate_input(0).unwrap(), "input 0 passes");
    let at_one = bad.validate_input(1).expect_err("input 1 is refused alone");
    let whole = bad
        .validate_all_inputs()
        .expect_err("a refused input refuses the transaction");
    assert_eq!(
        whole.message, at_one.message,
        "the refusal is input 1's own"
    );
    assert_eq!(whole.program_counter, at_one.program_counter);
    assert_eq!(whole.context, at_one.context);
}
