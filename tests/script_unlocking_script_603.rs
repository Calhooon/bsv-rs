//! `UnlockingScript`'s accessors on the sibling's corpus entries (#603): the
//! eight mutants of `src/script/unlocking_script.rs` the widened oracle left
//! (run 41327640129), each killed here by a vector of `bsv-script-lean` at
//! `387dab35`, copied by its id with the verdict that corpus records.
//!
//! The rules, from the sibling's Lean definition (`lean/BsvScript/Machine.lean`
//! at `387dab35`):
//!
//! * the instruction split is `getOpTail` (`:29-50`, `CScript::GetOp2`,
//!   `script.h:165-200`): the number of instructions an unlocking script holds,
//!   zero for the empty one (`isPushOnly []`, `:55`);
//! * `verifyScript` evaluates the scriptSig's own bytes (`:499-509`), so a
//!   conversion that hands the interpreter other bytes moves the verdict.
//!
//! The reference's `UnlockingScript` (`ts-stack@edf6e03`
//! `packages/sdk/src/script/UnlockingScript.ts:12-30`) extends `Script` and
//! overrides only the two type predicates: its ASM, its chunks and its bytes
//! are `Script`'s.
//!
//! A full-corpus run of each mutant (the sibling's `harness/run --impl bsv-rs
//! --corpus all`) moved no verdict: the harness builds its unlocking script
//! with `from_binary` and the interpreter reads it through `chunks`,
//! `as_script` and `is_push_only`. The vectors below reach the accessors.
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

/// `corpus/flow/flow.jsonl` `flow-01013` (`stack/final`, "extra elements below
/// a true top"): scriptSig `000000`, three instructions; valid.
const FLOW_01013: Entry = Entry {
    id: "flow-01013",
    tx_hex: "0200000001388fc8aca84b903993c73b5123a0ad982c7c8948786777a90214474dcc82e7b50000000003000000ffffffff010100000000000000015100000000",
    prevout_script_hex: "51",
    refused: None,
};

/// `corpus/flow/flow.jsonl` `flow-01059` (`flags/v1/sigpushonly/reserved-in-unlock`,
/// "OP_RESERVED in the unlocking script passes IsPushOnly and fails when
/// executed"): scriptSig `5150`; invalid, `SCRIPT_ERR_BAD_OPCODE`.
const FLOW_01059: Entry = Entry {
    id: "flow-01059",
    tx_hex: "02000000014dfcc8267e9b13ecab35b4fafe4eb07da5ffb2ce1cd119487da3dd3e7fe715ae00000000025150ffffffff010100000000000000015100000000",
    prevout_script_hex: "51",
    refused: Some("Invalid opcode 80 (pc=1)."),
};

/// `corpus/seed/seed.jsonl` `seed-000013` (`mutation/unlock`, the unlock of
/// `arith/NEGATE/twin` removed): an empty scriptSig; invalid,
/// `SCRIPT_ERR_INVALID_STACK_OPERATION`.
const SEED_000013: Entry = Entry {
    id: "seed-000013",
    tx_hex: "0200000001d12e6b5d90ec013ae4048405caae5ff12a9c16ab73b16dd610434227206342e40000000000ffffffff010100000000000000015100000000",
    prevout_script_hex: "8f5187",
    refused: Some("OP_NEGATE requires at least one item to be on the stack."),
};

/// The entry's scriptSig bytes, as the transaction carries them.
fn script_sig(e: &Entry) -> Vec<u8> {
    let tx = parse_transaction(&from_hex(e.tx_hex).unwrap()).expect("a parseable transaction");
    assert_eq!(tx.inputs.len(), 1, "{}: one input", e.id);
    tx.inputs[0].script.clone()
}

/// Runs the entry's input with `unlocking` as its scriptSig under the block
/// word of the entry's era (`params`: post-chronicle, consensus, spend height
/// 967,896) and asserts the recorded verdict.
fn assert_recorded_verdict(e: &Entry, unlocking: UnlockingScript) {
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
        locking_script: LockingScript::from_hex(e.prevout_script_hex).unwrap(),
        transaction_version: tx.version,
        other_inputs: Vec::new(),
        outputs,
        input_index: 0,
        unlocking_script: unlocking,
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
/// (`lean/BsvScript/Machine.lean:29-50`; the empty script `:55`): three for
/// flow-01013's `000000`, none for seed-000013's empty scriptSig. Kills
/// `len -> 0`, `len -> 1`, `is_empty -> true`, `is_empty -> false`.
#[test]
fn instruction_count_is_the_get_op_split_flow_01013_seed_000013() {
    let three = UnlockingScript::from_binary(&script_sig(&FLOW_01013)).unwrap();
    assert_eq!(three.len(), 3, "flow-01013: 00 00 00 is three instructions");
    assert!(
        !three.is_empty(),
        "flow-01013: a script of three instructions"
    );
    assert_recorded_verdict(&FLOW_01013, three);

    let none = UnlockingScript::from_binary(&script_sig(&SEED_000013)).unwrap();
    assert_eq!(none.len(), 0, "seed-000013: the empty scriptSig");
    assert!(none.is_empty(), "seed-000013: the empty scriptSig");
    assert_recorded_verdict(&SEED_000013, none);
}

/// `into_script` and `From<Script>` keep the scriptSig's bytes, which
/// `verifyScript` evaluates as given (`lean/BsvScript/Machine.lean:495-509`):
/// flow-01059's `5150` round-tripped through `Script` still executes
/// OP_RESERVED and is refused as recorded. Kills `into_script ->
/// Default::default()` and `From<Script>::from -> Default::default()`: an
/// empty scriptSig under the `51` lock is valid.
#[test]
fn script_conversions_keep_the_evaluated_bytes_flow_01059() {
    let bytes = script_sig(&FLOW_01059);

    let script: Script = UnlockingScript::from_binary(&bytes).unwrap().into_script();
    assert_eq!(
        script.to_binary(),
        bytes,
        "flow-01059: into_script keeps 5150"
    );
    assert_recorded_verdict(&FLOW_01059, UnlockingScript::from_script(script));

    let unlocking = UnlockingScript::from(Script::from_binary(&bytes).unwrap());
    assert_eq!(
        unlocking.to_binary(),
        bytes,
        "flow-01059: From<Script> keeps 5150"
    );
    assert_recorded_verdict(&FLOW_01059, unlocking);
}

/// `to_asm` is `Script`'s (`UnlockingScript.ts:12-30` overrides no
/// serializer), and its text reads back to the bytes `verifyScript` evaluates
/// (`lean/BsvScript/Machine.lean:495-509`): flow-01059's ASM parsed again is
/// `5150`, refused as recorded. Kills `to_asm -> String::new()` (the empty
/// script, valid under `51`) and `to_asm -> "xyzzy".into()` (not `Script`'s
/// text).
#[test]
fn asm_is_the_scripts_and_reads_back_flow_01059() {
    let bytes = script_sig(&FLOW_01059);
    let unlocking = UnlockingScript::from_binary(&bytes).unwrap();
    let asm = unlocking.to_asm();
    assert_eq!(
        asm,
        Script::from_binary(&bytes).unwrap().to_asm(),
        "flow-01059: Script's ASM"
    );

    let read_back = UnlockingScript::from_asm(&asm).expect("flow-01059: the ASM reads back");
    assert_eq!(
        read_back.to_binary(),
        bytes,
        "flow-01059: the ASM reads back to 5150"
    );
    assert_recorded_verdict(&FLOW_01059, read_back);
}
