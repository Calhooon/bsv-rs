//! `LockingScript`'s accessors on the sibling's corpus entries (#603): the
//! eight mutants of `src/script/locking_script.rs` the widened oracle left
//! (run 41327640129), each killed here by a vector of `bsv-script-lean` at
//! `387dab35`, copied by its id with the verdict that corpus records.
//!
//! The rules, from the sibling's Lean definition (`lean/BsvScript/Machine.lean`
//! at `387dab35`):
//!
//! * the instruction split is `getOpTail` (`:29-50`, `CScript::GetOp2`,
//!   `script.h:165-200`): the number of instructions a locking script holds,
//!   zero for the empty one;
//! * `isPushOnly` (`:52-59`, `CScript::IsPushOnly`, `script.cpp:209-220`) is a
//!   predicate over a script's bytes: every instruction parses and no opcode is
//!   above `OP_16`, the empty script push-only; `verifyScript` applies it to the
//!   scriptSig under SIGPUSHONLY (`:495-509`, the gate at `:500-503`);
//! * `verifyScript` evaluates the scriptPubKey's own bytes after the scriptSig
//!   (`:495-509`), so a conversion that hands the interpreter other bytes moves
//!   the verdict.
//!
//! A full-corpus run of each mutant (the sibling's `harness/run --impl bsv-rs
//! --corpus all --spec recorded`, nine corpora) moved no verdict: the harness
//! builds its locking script with `from_binary` and the interpreter reads it
//! through `as_script` and `chunks`. The vectors below reach the accessors.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use bsv_rs::primitives::bsv::sighash::{parse_transaction, TxOutput};
use bsv_rs::primitives::from_hex;
use bsv_rs::script::{
    LockingScript, ProtocolEra, Script, ScriptFlags, Spend, SpendParams, UnlockingScript,
};

/// A sibling corpus entry: one input, one output, the previous output's script
/// and the verdict recorded for this crate (`bsv-rs@0.7.0`, equal to `spec@cb7e46e`).
struct Entry {
    id: &'static str,
    tx_hex: &'static str,
    prevout_script_hex: &'static str,
    /// `None` valid; `Some(reason)` the recorded refusal's words.
    refused: Option<&'static str>,
}

/// `corpus/flow/flow.jsonl` `flow-01005` (`stack/final`): an empty scriptSig
/// under the lock `5151`, two instructions, push-only; valid at version 2.
const FLOW_01005: Entry = Entry {
    id: "flow-01005",
    tx_hex: "02000000010967130f5aa84275680f30589a52e9243547d8a3cd864ddea81c5ca9f5d064610000000000ffffffff010100000000000000015100000000",
    prevout_script_hex: "5151",
    refused: None,
};

/// `corpus/flow/flow.jsonl` `flow-01009` (`stack/final`): scriptSig `51` under
/// the empty lock; valid.
const FLOW_01009: Entry = Entry {
    id: "flow-01009",
    tx_hex: "020000000106edd410eb9662c34922a458807e9572292f3b85e65166e0ebc21b0eff635437000000000151ffffffff010100000000000000015100000000",
    prevout_script_hex: "",
    refused: None,
};

/// `corpus/flow/flow.jsonl` `flow-01011` (`stack/final`): an empty scriptSig
/// under the empty lock; invalid, the stack empty at the end.
const FLOW_01011: Entry = Entry {
    id: "flow-01011",
    tx_hex: "0200000001b0a3b5a55a32cfaee1699d3e16340b2001b16fe3eafd1dffa77ef62b59b963070000000000ffffffff010100000000000000015100000000",
    prevout_script_hex: "",
    refused: Some("The top stack element must be truthy after script evaluation (stack is empty)."),
};

/// `corpus/seed/seed.jsonl` `seed-000013` (`mutation/unlock`): an empty
/// scriptSig under the lock `8f5187` (`OP_NEGATE OP_1 OP_EQUAL`, three
/// instructions, `OP_NEGATE` above `OP_16`); invalid,
/// `SCRIPT_ERR_INVALID_STACK_OPERATION`.
const SEED_000013: Entry = Entry {
    id: "seed-000013",
    tx_hex: "0200000001d12e6b5d90ec013ae4048405caae5ff12a9c16ab73b16dd610434227206342e40000000000ffffffff010100000000000000015100000000",
    prevout_script_hex: "8f5187",
    refused: Some("OP_NEGATE requires at least one item to be on the stack."),
};

/// `corpus/flow/flow.jsonl` `flow-01061` (`flags/v1/sigpushonly/op16`, "OP_16
/// is the last push-type opcode"): scriptSig `60`; valid.
const FLOW_01061: Entry = Entry {
    id: "flow-01061",
    tx_hex: "0200000001d6865e04d5a671399124974d7e3d0951d6ebd9208654571b0b033fe7ad67280d000000000160ffffffff010100000000000000015100000000",
    prevout_script_hex: "6351675168",
    refused: None,
};

/// `corpus/flow/flow.jsonl` `flow-01092` (`flow/nonpush-unlock/v1`, "a non-push
/// opcode in the unlocking script"): scriptSig `5161` (`OP_1 OP_NOP`) at
/// version 1; invalid, `SCRIPT_ERR_SIG_PUSHONLY`.
const FLOW_01092: Entry = Entry {
    id: "flow-01092",
    tx_hex: "01000000018ac466263544651b7b01e0fb06730b13d9d321a9469c955cc07bde834eb808ef00000000025161ffffffff010100000000000000015100000000",
    prevout_script_hex: "51",
    refused: Some("Unlocking scripts can only contain push operations, and no other opcodes."),
};

/// The entry's scriptSig bytes, as the transaction carries them.
fn script_sig(e: &Entry) -> Vec<u8> {
    let tx = parse_transaction(&from_hex(e.tx_hex).unwrap()).expect("a parseable transaction");
    assert_eq!(tx.inputs.len(), 1, "{}: one input", e.id);
    tx.inputs[0].script.clone()
}

/// The entry's locking script, read from its recorded bytes.
fn lock(e: &Entry) -> LockingScript {
    LockingScript::from_binary(&from_hex(e.prevout_script_hex).unwrap()).unwrap()
}

/// Runs the entry's input with `locking` as the previous output's script under
/// the block word of the entry's era (`params`: post-chronicle, consensus,
/// spend height 967,896) and asserts the recorded verdict.
fn assert_recorded_verdict(e: &Entry, locking: LockingScript) {
    let tx = parse_transaction(&from_hex(e.tx_hex).unwrap()).unwrap();
    let input = &tx.inputs[0];
    let outputs: Vec<TxOutput> = tx
        .outputs
        .iter()
        .map(|o| TxOutput {
            satoshis: o.satoshis,
            script: o.script.clone(),
        })
        .collect();
    let mut spend = Spend::new(SpendParams {
        source_txid: input.txid,
        source_output_index: input.output_index,
        source_satoshis: 1000,
        locking_script: locking,
        transaction_version: tx.version,
        other_inputs: Vec::new(),
        outputs,
        input_index: 0,
        unlocking_script: UnlockingScript::from_binary(&input.script).unwrap(),
        input_sequence: input.sequence,
        lock_time: tx.locktime,
        memory_limit: None,
        work_limit: None,
    });
    spend.set_flags(ScriptFlags::block(ProtocolEra::PostChronicle));
    let got = spend.validate().map_err(|err| err.message);
    match e.refused {
        None => assert_eq!(got, Ok(true), "{}: the recorded verdict is valid", e.id),
        Some(reason) => {
            let msg = got.expect_err(&format!("{}: the recorded verdict is invalid", e.id));
            assert!(
                msg.contains(reason),
                "{}: expected {reason:?}, got {msg:?}",
                e.id
            );
        }
    }
}

/// `len` and `is_empty` count `getOpTail`'s instructions
/// (`lean/BsvScript/Machine.lean:29-50`): two for flow-01005's `5151`, three
/// for seed-000013's `8f5187`, none for flow-01009's empty lock. Kills
/// `len -> 0`, `len -> 1`, `is_empty -> true`, `is_empty -> false`.
#[test]
fn instruction_count_is_the_get_op_split_flow_01005_seed_000013_flow_01009() {
    let two = lock(&FLOW_01005);
    assert_eq!(two.len(), 2, "flow-01005: 51 51 is two instructions");
    assert!(!two.is_empty(), "flow-01005: a lock of two instructions");
    assert_recorded_verdict(&FLOW_01005, two);

    let three = lock(&SEED_000013);
    assert_eq!(
        three.len(),
        3,
        "seed-000013: 8f 51 87 is three instructions"
    );
    assert!(
        !three.is_empty(),
        "seed-000013: a lock of three instructions"
    );
    assert_recorded_verdict(&SEED_000013, three);

    let none = lock(&FLOW_01009);
    assert_eq!(none.len(), 0, "flow-01009: the empty lock");
    assert!(none.is_empty(), "flow-01009: the empty lock");
    assert_recorded_verdict(&FLOW_01009, none);
}

/// `is_push_only` is `isPushOnly` over the script's bytes
/// (`lean/BsvScript/Machine.lean:52-59`), the predicate `verifyScript`'s
/// SIGPUSHONLY gate applies (`:500-503`): `60` (OP_16, the last push-type
/// opcode) is push-only and flow-01061 accepts it as a scriptSig; `5161`
/// (`OP_1 OP_NOP`) is not, and flow-01092 refuses it at version 1 for that
/// rule; the empty lock is push-only (`isPushOnly [] = true`) and seed-000013's
/// `8f5187` is not (`OP_NEGATE` above `OP_16`). Kills `is_push_only -> false`
/// and `is_push_only -> true`.
#[test]
fn push_only_is_the_sig_pushonly_predicate_flow_01061_flow_01092() {
    let op16 = script_sig(&FLOW_01061);
    assert!(
        LockingScript::from_binary(&op16).unwrap().is_push_only(),
        "flow-01061: 60 is push-only"
    );
    assert_recorded_verdict(&FLOW_01061, lock(&FLOW_01061));

    let nop = script_sig(&FLOW_01092);
    assert!(
        !LockingScript::from_binary(&nop).unwrap().is_push_only(),
        "flow-01092: 51 61 is not push-only"
    );
    assert_recorded_verdict(&FLOW_01092, lock(&FLOW_01092));

    let empty = lock(&FLOW_01009);
    assert!(empty.is_push_only(), "flow-01009: the empty lock");
    assert_recorded_verdict(&FLOW_01009, empty);

    let negate = lock(&SEED_000013);
    assert!(!negate.is_push_only(), "seed-000013: 8f 51 87");
    assert_recorded_verdict(&SEED_000013, negate);
}

/// `into_script` and `From<Script>` keep the scriptPubKey's bytes, which
/// `verifyScript` evaluates as given (`lean/BsvScript/Machine.lean:495-509`):
/// flow-01005's `5151` round-tripped through `Script` still leaves a true top
/// under its empty scriptSig, valid as recorded. Kills `into_script ->
/// Default::default()` and `From<Script>::from -> Default::default()`: an empty
/// lock under an empty scriptSig is flow-01011, refused as recorded.
#[test]
fn script_conversions_keep_the_evaluated_bytes_flow_01005_flow_01011() {
    let bytes = from_hex(FLOW_01005.prevout_script_hex).unwrap();

    let script: Script = lock(&FLOW_01005).into_script();
    assert_eq!(
        script.to_binary(),
        bytes,
        "flow-01005: into_script keeps 5151"
    );
    assert_recorded_verdict(&FLOW_01005, LockingScript::from_script(script));

    let locking = LockingScript::from(Script::from_binary(&bytes).unwrap());
    assert_eq!(
        locking.to_binary(),
        bytes,
        "flow-01005: From<Script> keeps 5151"
    );
    assert_recorded_verdict(&FLOW_01005, locking);

    // What either mutant hands the interpreter, under flow-01011's empty
    // scriptSig: the empty lock, refused as that entry records.
    assert_eq!(script_sig(&FLOW_01011), script_sig(&FLOW_01005));
    assert_recorded_verdict(&FLOW_01011, LockingScript::default());
}
