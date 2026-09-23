//! Regression: the five consensus divergences left after 0.3.26, on nine
//! witness transactions (Calhooon/bsv-rs#12).
//!
//! Each witness is a transaction (raw bytes, one input, one output) with the
//! previous output it spends, the smallest case of a divergence a differential
//! run against bitcoin-sv v1.2.2 (`879fc8b`) recorded. The rules:
//!
//! * `push.truncated`: a push that declares more bytes than the script holds
//!   is `SCRIPT_ERR_BAD_OPCODE` when the walk reaches it (`script.h:190-191`,
//!   `interpreter.cpp:450-451`); 0.3.26 clamped it to the bytes present.
//! * `flow.unknown-opcode`: `0xba`-`0xff` executed is `SCRIPT_ERR_BAD_OPCODE`
//!   (`interpreter.cpp:1795`); 0.3.26 treated them as NOPs.
//! * `flow.else`: a second `OP_ELSE` for one `OP_IF` is unbalanced after
//!   Genesis (`conditional_tracker.cpp:51-55`, `interpreter.cpp:829-831`).
//! * the post-Chronicle UTXO opcodes: `OP_VER` pushes the version, `OP_2MUL`
//!   and `OP_2DIV` compute, `0xb3`-`0xb7` are `OP_SUBSTR`, `OP_LEFT`,
//!   `OP_RIGHT`, `OP_LSHIFTNUM`, `OP_RSHIFTNUM` (`interpreter.cpp:360-375`,
//!   `598-812`, `1247-1254`); 0.3.26 disabled the first three and NOP'd the rest.
//! * `sighash.scriptcode.findanddelete`: a signature carrying `SIGHASH_FORKID`
//!   is not deleted from the scriptCode (`interpreter.cpp:255-263`, `1484`);
//!   0.3.26 deleted every signature, so a signature over the deleted
//!   scriptCode verified where the reference refuses it.
//!
//! Every witness is pinned under the block word (`ScriptFlags::block`, what a
//! mining node decides) and in the TypeScript default mode, where the same
//! consensus rules apply (the Chronicle opcodes follow the default's relaxed
//! branch, version > 1, as in that SDK). The 0.3.26 verdict is recorded beside
//! each; all nine move, by design: these rules were wrong in every mode.
//!
//! Every outpoint is synthetic; the previous outputs never existed on any chain.

use bsv_rs::primitives::bsv::sighash::{parse_transaction, TxInput, TxOutput};
use bsv_rs::primitives::from_hex;
use bsv_rs::script::{
    LockingScript, ProtocolEra, ScriptFlags, Spend, SpendParams, UnlockingScript,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Default,
    Block,
}

struct Witness {
    rule: &'static str,
    tx_hex: &'static str,
    prevout_script_hex: &'static str,
    /// The verdict 0.3.26 gave under the block word, as the differential recorded it.
    recorded_0_3_26: Result<(), &'static str>,
    block: Result<(), &'static str>,
    default: Result<(), &'static str>,
}

fn run(w: &Witness, mode: Mode) -> Result<bool, String> {
    let tx = parse_transaction(&from_hex(w.tx_hex).unwrap()).expect("a parseable transaction");
    assert_eq!(tx.inputs.len(), 1, "{}: one input", w.rule);
    let input = &tx.inputs[0];
    let other_inputs: Vec<TxInput> = Vec::new();
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
        locking_script: LockingScript::from_hex(w.prevout_script_hex).unwrap(),
        transaction_version: tx.version,
        other_inputs,
        outputs,
        input_index: 0,
        unlocking_script: UnlockingScript::from_binary(&input.script).unwrap(),
        input_sequence: input.sequence,
        lock_time: tx.locktime,
        memory_limit: None,
    });
    if mode == Mode::Block {
        spend.set_flags(ScriptFlags::block(ProtocolEra::PostChronicle));
    }
    spend.validate().map_err(|e| e.message)
}

fn check(w: &Witness, mode: Mode, want: Result<(), &'static str>) {
    let got = run(w, mode);
    match want {
        Ok(()) => assert_eq!(got, Ok(true), "{} under {:?}: expected valid", w.rule, mode),
        Err(fragment) => {
            let msg = got.expect_err(&format!("{} under {:?}: expected a refusal", w.rule, mode));
            assert!(
                msg.contains(fragment),
                "{} under {:?}: expected a refusal mentioning {:?}, got {:?}",
                w.rule,
                mode,
                fragment,
                msg
            );
        }
    }
}

fn check_all(w: &Witness) {
    check(w, Mode::Block, w.block);
    check(w, Mode::Default, w.default);
}

const TRUNCATED: &str = "A push declares more bytes than the script holds";
const BAD_OPCODE: &str = "Invalid opcode";
const SECOND_ELSE: &str = "OP_ELSE may only be used once";
const NEGATIVE_SHIFT: &str = "bits to shift must not be negative";
const NULLFAIL: &str = "requires failing signatures to be empty";
const EVAL_FALSE: &str = "The top stack element must be truthy";

/// Locking script `OP_1 03 01`: a 3-byte push with one byte present, after OP_1.
const PUSH_TRUNCATED_LOCK: Witness = Witness {
    rule: "push.truncated (a truncated direct push in the locking script)",
    tx_hex: "020000000182dd05380a1c756fbfdc6b522fcb7cd480c8472244ac197e126a9bd5d39789910000000000ffffffff010100000000000000015100000000",
    prevout_script_hex: "510301",
    recorded_0_3_26: Ok(()),
    block: Err(TRUNCATED),
    default: Err(TRUNCATED),
};

/// Unlocking script `4c`: a bare OP_PUSHDATA1 with no length byte, against
/// `OP_SIZE OP_0 OP_EQUALVERIFY OP_DROP OP_1` (which the clamped, empty push satisfied).
const PUSH_TRUNCATED_UNLOCK: Witness = Witness {
    rule: "push.truncated (a bare OP_PUSHDATA1 in the unlocking script)",
    tx_hex: "02000000010dba4deb3653d438ce0cc4d5a0b4112e1496ab22ee30acbf0753d197041e1b8c00000000014cffffffff010100000000000000015100000000",
    prevout_script_hex: "8200887551",
    recorded_0_3_26: Ok(()),
    block: Err(TRUNCATED),
    default: Err(TRUNCATED),
};

/// Locking script `ba 51`: the undefined opcode 0xba executed.
const UNKNOWN_OPCODE_BA: Witness = Witness {
    rule: "flow.unknown-opcode (0xba executed)",
    tx_hex: "02000000014a842a71f877ecc749b13a36de55936ef82c7e998f8686aa29aab6704ea7596d0000000000ffffffff010100000000000000015100000000",
    prevout_script_hex: "ba51",
    recorded_0_3_26: Ok(()),
    block: Err(BAD_OPCODE),
    default: Err(BAD_OPCODE),
};

/// Locking script `OP_SIZE OP_0 OP_EQUALVERIFY OP_5 cc` against `OP_0`: 0xcc executed.
const UNKNOWN_OPCODE_CC: Witness = Witness {
    rule: "flow.unknown-opcode (0xcc executed after a passing check)",
    tx_hex: "020000000142657e48a6999bda44d525ec6e8ceb50ba34eaa4855edde02ce0f4e6f5beb631000000000100ffffffff010100000000000000015100000000",
    prevout_script_hex: "82008855cc",
    recorded_0_3_26: Ok(()),
    block: Err(BAD_OPCODE),
    default: Err(BAD_OPCODE),
};

/// `OP_IF OP_1 OP_ELSE OP_1 OP_ELSE OP_1 OP_ENDIF` against `OP_1`: a second OP_ELSE.
const SECOND_ELSE_WITNESS: Witness = Witness {
    rule: "flow.else (a second OP_ELSE for one OP_IF)",
    tx_hex: "02000000014a3b5013f0ff6160ba06431b623d6287dffe247cc998f9296dbb3a23a7a56296000000000151ffffffff010100000000000000015100000000",
    prevout_script_hex: "63516751675168",
    recorded_0_3_26: Ok(()),
    block: Err(SECOND_ELSE),
    default: Err(SECOND_ELSE),
};

/// `OP_VER OP_IF OP_1 OP_ELSE OP_1 OP_ENDIF`, version 2: OP_VER pushes the
/// version, a true top; valid for a coin created after Chronicle.
const OP_VER_WITNESS: Witness = Witness {
    rule: "flow.ver (OP_VER pushes the transaction version after Chronicle)",
    tx_hex: "020000000157e400ef035a5ec00441508909c3a304b7720c1efe07c9a699e18ec66f24ff2b0000000000ffffffff010100000000000000015100000000",
    prevout_script_hex: "626351675168",
    recorded_0_3_26: Err("currently disabled"),
    block: Ok(()),
    default: Ok(()),
};

/// `OP_2DIV <-3> OP_EQUAL` against `<-7>`: -7 / 2 = -3, toward zero.
const OP_2DIV_WITNESS: Witness = Witness {
    rule: "num.arith.2div (-7 OP_2DIV is -3, toward zero)",
    tx_hex: "020000000102056a65bc967507f821a83b90d1f30811df10a12ae91d5430e8bf05485904c900000000020187ffffffff010100000000000000015100000000",
    prevout_script_hex: "8e018387",
    recorded_0_3_26: Err("currently disabled"),
    block: Ok(()),
    default: Ok(()),
};

/// `OP_2MUL OP_14 OP_EQUAL` against `OP_7`.
const OP_2MUL_WITNESS: Witness = Witness {
    rule: "num.arith.2mul (7 OP_2MUL is 14)",
    tx_hex: "02000000013100b5ccefe3be7a82899fbe94b056147fb9e05e5d50f1ea2a6aecb5d39153e0000000000157ffffffff010100000000000000015100000000",
    prevout_script_hex: "8d5e87",
    recorded_0_3_26: Err("currently disabled"),
    block: Ok(()),
    default: Ok(()),
};

/// `OP_MUL <11 bytes> b7` against two numbers: after Chronicle 0xb7 is
/// OP_RSHIFTNUM and its count operand (the 11-byte number, negative) is out of
/// range; 0.3.26 ran it as a NOP and accepted the spend.
const RSHIFTNUM_WITNESS: Witness = Witness {
    rule: "expansion.as-nop (0xb7 is OP_RSHIFTNUM after Chronicle; a negative count)",
    tx_hex: "0200000001e65259c10ecb129013caa49a90832860082c4388c71f439efd8424e9a092c914000000000d03c7488508ffffffffffffffffffffffff010100000000000000015100000000",
    prevout_script_hex: "950b3ab7faff87efff7f63a4ffb7",
    recorded_0_3_26: Ok(()),
    block: Err(NEGATIVE_SHIFT),
    default: Err(NEGATIVE_SHIFT),
};

/// Version 1: `<sig> OP_DROP <pubkey> OP_CHECKSIG` spent with the same `<sig>`,
/// a FORKID signature made over the scriptCode WITH its own push deleted. The
/// reference hashes the push in, so the signature fails: NULLFAIL under the
/// block word (a non-empty failing signature at version 1), a false top in the
/// default mode (no NULLFAIL there). 0.3.26 deleted the push and verified it.
const FINDANDDELETE_WITNESS: Witness = Witness {
    rule: "sighash.scriptcode.findanddelete (a FORKID signature's push stays in the scriptCode)",
    tx_hex: "010000000119239a29170d08984ceb22f40c43f5cbd99ebb2da95fdd313272a20741ea3338000000004847304402204c9195e05dc41a9119b4cf65f43e450a057818d74c12265faee6a21ae2e0ab87022051c94bb55d9c54d68efaa16785c6ba6a7958757745528974a92d8cddcb993c1241ffffffff010100000000000000015100000000",
    prevout_script_hex: "47304402204c9195e05dc41a9119b4cf65f43e450a057818d74c12265faee6a21ae2e0ab87022051c94bb55d9c54d68efaa16785c6ba6a7958757745528974a92d8cddcb993c12417521035935f55855afd8c999bdb5a8d08ae8e73b7618e200d4ef7687cd55d3c2e4c9d7ac",
    recorded_0_3_26: Ok(()),
    block: Err(NULLFAIL),
    default: Err(EVAL_FALSE),
};

const ALL: [&Witness; 10] = [
    &PUSH_TRUNCATED_LOCK,
    &PUSH_TRUNCATED_UNLOCK,
    &UNKNOWN_OPCODE_BA,
    &UNKNOWN_OPCODE_CC,
    &SECOND_ELSE_WITNESS,
    &OP_VER_WITNESS,
    &OP_2DIV_WITNESS,
    &OP_2MUL_WITNESS,
    &RSHIFTNUM_WITNESS,
    &FINDANDDELETE_WITNESS,
];

#[test]
fn push_truncated_a_direct_push_short_of_its_declared_bytes_is_refused_where_the_walk_reaches_it() {
    check_all(&PUSH_TRUNCATED_LOCK);
}

#[test]
fn push_truncated_a_bare_pushdata1_in_the_unlocking_script_is_refused() {
    check_all(&PUSH_TRUNCATED_UNLOCK);
}

#[test]
fn flow_unknown_opcode_0xba_executed_is_refused() {
    check_all(&UNKNOWN_OPCODE_BA);
}

#[test]
fn flow_unknown_opcode_0xcc_executed_is_refused() {
    check_all(&UNKNOWN_OPCODE_CC);
}

#[test]
fn flow_else_a_second_op_else_for_one_op_if_is_unbalanced_after_genesis() {
    check_all(&SECOND_ELSE_WITNESS);
}

#[test]
fn flow_ver_op_ver_pushes_the_transaction_version_for_a_coin_created_after_chronicle() {
    check_all(&OP_VER_WITNESS);
}

#[test]
fn num_arith_2div_divides_toward_zero_after_chronicle() {
    check_all(&OP_2DIV_WITNESS);
}

#[test]
fn num_arith_2mul_doubles_after_chronicle() {
    check_all(&OP_2MUL_WITNESS);
}

#[test]
fn expansion_0xb7_is_op_rshiftnum_after_chronicle_and_refuses_a_negative_count() {
    check_all(&RSHIFTNUM_WITNESS);
}

#[test]
fn sighash_scriptcode_a_forkid_signatures_push_is_not_deleted_so_it_cannot_verify_over_itself() {
    check_all(&FINDANDDELETE_WITNESS);
}

/// All nine recorded 0.3.26 verdicts move under the block word: these were
/// consensus rules wrong in every mode, not policy.
#[test]
fn every_recorded_0_3_26_verdict_moves_under_the_block_word() {
    for w in ALL {
        let unchanged = match (run(w, Mode::Block), w.recorded_0_3_26) {
            (Ok(true), Ok(())) => true,
            (Err(message), Err(fragment)) => message.contains(fragment),
            _ => false,
        };
        assert!(!unchanged, "{}: the 0.3.26 verdict did not move", w.rule);
    }
}
