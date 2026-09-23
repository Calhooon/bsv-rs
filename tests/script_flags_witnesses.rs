//! Regression: the interpreter's flag words on seven witness transactions.
//!
//! Each witness is a transaction (raw bytes, one input, one output) with the
//! previous output it spends, the smallest case of a divergence that a
//! differential run of bsv-rs 0.3.24 against the block-validation flag
//! derivation of bitcoin-sv v1.2.2 found (Calhooon/bsv-rs#10). Three rules,
//! each cited to the reference (`879fc8b`):
//!
//! * `flags.policy-as-consensus`: used as a consensus validator, 0.3.24
//!   judged a version-1 spend by MINIMALDATA, CLEANSTACK and NULLDUMMY, which
//!   no block word carries (`src/policy/policy.h:178-190`; the block word,
//!   `src/verify_script_flags.cpp:32-81`), so it rejected consensus-valid
//!   version-1 spends. Five witnesses, one per corpus the run had.
//! * `flags.version-gate.nulldummy`: NULLDUMMY was applied regardless of the
//!   transaction version; the reference gates it (`interpreter.cpp:1664-1670`
//!   under `EnforceNonMalleability`, `40-44`).
//! * `flags.version-gate.nullfail`: no NULLFAIL rule existed
//!   (`interpreter.cpp:1491-1497`, `1640-1646`).
//!
//! Every witness is run three ways and each column is pinned: under the block
//! word (what a mining node decides), under the standard word (what a relaying
//! node with default policy decides), and in the TypeScript default mode (no
//! word). The 0.3.24 verdict is recorded beside each; six of the seven default
//! verdicts are unchanged by the fix and the seventh (NULLDUMMY at version 2)
//! changed by design, which the last test pins.
//!
//! Every outpoint is synthetic; the previous outputs never existed on any
//! chain. A transaction is `bsv_rs::primitives::bsv::sighash::parse_transaction`'s.

use bsv_rs::primitives::bsv::sighash::{parse_transaction, TxInput, TxOutput};
use bsv_rs::primitives::from_hex;
use bsv_rs::script::{
    LockingScript, ProtocolEra, ScriptFlags, Spend, SpendParams, UnlockingScript,
};

/// How the interpreter is run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// No word: the TypeScript SDK's default evaluation mode.
    Default,
    /// `ScriptFlags::block(PostChronicle)`: the consensus word.
    Block,
    /// `ScriptFlags::standard(PostChronicle)`: the mempool-policy word.
    Standard,
}

/// A witness: the transaction, the previous output of its only input, and the
/// three pinned verdicts (`Ok(())` valid, `Err(fragment)` refused with a
/// message containing the fragment).
struct Witness {
    rule: &'static str,
    tx_hex: &'static str,
    prevout_script_hex: &'static str,
    prevout_satoshis: u64,
    /// The verdict bsv-rs 0.3.24 gave in its only mode (the default), as the
    /// differential recorded it.
    recorded_0_3_24: Result<(), &'static str>,
    block: Result<(), &'static str>,
    standard: Result<(), &'static str>,
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
        source_satoshis: w.prevout_satoshis,
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
    match mode {
        Mode::Default => {}
        Mode::Block => spend.set_flags(ScriptFlags::block(ProtocolEra::PostChronicle)),
        Mode::Standard => spend.set_flags(ScriptFlags::standard(ProtocolEra::PostChronicle)),
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
    check(w, Mode::Standard, w.standard);
    check(w, Mode::Default, w.default);
}

const CLEANSTACK: &str = "The clean stack rule requires exactly one item";
const MINENCODE: &str = "Invalid script number";
const NULLDUMMY: &str = "requires the extra stack item (dummy) to be empty";
const NULLFAIL: &str = "requires failing signatures to be empty";

/// A version-1 spend whose unlocking script leaves one element and whose
/// locking script `OP_DEPTH OP_1 OP_NUMEQUAL` leaves a second: two elements
/// at the end, the top true.
const POLICY_AS_CONSENSUS_SEED: Witness = Witness {
    rule: "flags.policy-as-consensus (seed)",
    tx_hex: "010000000118aa8f0c97a2c907dba310a0510069649fbf6f14541f8e7805f47cc179193eeb000000000151ffffffff010100000000000000015100000000",
    prevout_script_hex: "74519c",
    prevout_satoshis: 1000,
    recorded_0_3_24: Err(CLEANSTACK),
    block: Ok(()),
    standard: Err(CLEANSTACK),
    default: Err(CLEANSTACK),
};

/// A version-1 spend of `OP_1 OP_1` with an empty unlocking script: two true
/// elements at the end.
const POLICY_AS_CONSENSUS_FLOW: Witness = Witness {
    rule: "flags.policy-as-consensus (flow)",
    tx_hex: "01000000015a074d046d12192e54eb896dc387da43152728e64d45717563bf32913778fdca0000000000ffffffff010100000000000000015100000000",
    prevout_script_hex: "5151",
    prevout_satoshis: 1000,
    recorded_0_3_24: Err(CLEANSTACK),
    block: Ok(()),
    standard: Err(CLEANSTACK),
    default: Err(CLEANSTACK),
};

/// A version-1 spend shifting `-1` left by the non-minimally encoded count
/// `0x0100` (the number 1 with a padding byte): `OP_1NEGATE` against
/// `<0100> OP_LSHIFT OP_2 OP_EQUAL`.
const POLICY_AS_CONSENSUS_ARITH: Witness = Witness {
    rule: "flags.policy-as-consensus (arith)",
    tx_hex: "0100000001a451dff0f0bcb12cf6bfebd7087d0fadcf8d582a82696146c342d061bbbf7b5800000000014fffffffff010100000000000000015100000000",
    prevout_script_hex: "020100985287",
    prevout_satoshis: 1000,
    recorded_0_3_24: Err(MINENCODE),
    block: Ok(()),
    standard: Err(MINENCODE),
    default: Err(MINENCODE),
};

/// A version-1 spend running `OP_NUM2BIN` to the non-minimally encoded width
/// `0x0200` (the number 2 with a padding byte): `OP_1` against
/// `<0200> OP_NUM2BIN <0100> OP_EQUALVERIFY OP_DEPTH OP_0 OP_EQUAL`.
const POLICY_AS_CONSENSUS_STACK: Witness = Witness {
    rule: "flags.policy-as-consensus (stack)",
    tx_hex: "010000000183ac69b52ed41953764037f8c40171cb42db15455a985012c518c96d8a39434c000000000151ffffffff010100000000000000015100000000",
    prevout_script_hex: "0202008002010088740087",
    prevout_satoshis: 1000,
    recorded_0_3_24: Err(MINENCODE),
    block: Ok(()),
    standard: Err(MINENCODE),
    default: Err(MINENCODE),
};

/// A version-1 1-of-2 `OP_CHECKMULTISIG` spend with a valid signature and a
/// non-empty dummy (`OP_1`).
const POLICY_AS_CONSENSUS_CRYPTO: Witness = Witness {
    rule: "flags.policy-as-consensus (crypto)",
    tx_hex: "01000000016c26263dad04dd2e67792f528e4aed97e44215a8fb62268876fcac9fc00c1d43000000004a51483045022100bd1b71124c45382b8e5fbe8c7557d348c37c3136d05c9b429d5ef655fd4dbc4a022073e1e971936d97501550a94ef5b5a7e6c2e169346a2d8eaa1074d71bd8cbc12f41ffffffff010100000000000000015100000000",
    prevout_script_hex: "5121035935f55855afd8c999bdb5a8d08ae8e73b7618e200d4ef7687cd55d3c2e4c9d721036d55bf637ea936e58ddcaeefe4fd34246dc76957fd78d46db325a0a734205b9152ae",
    prevout_satoshis: 1000,
    recorded_0_3_24: Err(NULLDUMMY),
    block: Ok(()),
    standard: Err(NULLDUMMY),
    default: Err(NULLDUMMY),
};

/// The same 1-of-2 multisig shape at version 2 with a non-empty dummy: valid
/// under every word (the version gate switches NULLDUMMY off) and in the
/// TypeScript default mode (`shouldEnforceNullDummy` is `!isRelaxed()`).
/// 0.3.24 refused it: the one default-mode verdict this release changes.
const VERSION_GATE_NULLDUMMY: Witness = Witness {
    rule: "flags.version-gate.nulldummy",
    tx_hex: "02000000016b6be82fc7006b2819313376a56d1a3d5dd56e79ff0222fde4c9c3711edf6945000000004a51483045022100ef6e6b1b167f5bd72c11e24be9248685505e343f44ef9538f6d3ddf9e50794fd02204bcef553f6fe7fa0de853311f2a7fbd595f7256754993c882c4d0655e59a991d41ffffffff010100000000000000015100000000",
    prevout_script_hex: "5121035935f55855afd8c999bdb5a8d08ae8e73b7618e200d4ef7687cd55d3c2e4c9d721036d55bf637ea936e58ddcaeefe4fd34246dc76957fd78d46db325a0a734205b9152ae",
    prevout_satoshis: 1000,
    recorded_0_3_24: Err(NULLDUMMY),
    block: Ok(()),
    standard: Ok(()),
    default: Ok(()),
};

/// A version-1 spend of `<pubkey> OP_CHECKSIG OP_NOT` with a well-formed
/// signature that does not verify: without NULLFAIL the failed check is
/// negated into a true top element; NULLFAIL refuses the non-empty failing
/// signature under both words. The TypeScript default mode has no NULLFAIL
/// rule, so the default verdict stays valid, as 0.3.24's was.
const VERSION_GATE_NULLFAIL: Witness = Witness {
    rule: "flags.version-gate.nullfail",
    tx_hex: "0100000001be42934b64735827ac1fdf19a364495c97ea76b591dee2e1d14b2d343ca4de02000000004847304402204bbb723c10080132ef81641e0e9963eb77782bf50c149f0f15c6d7b8e263464e02207f18ea8fdff74fb4d4d2dc677555fb1c94cf6219fe4bb4c40162e1e270f8924941ffffffff010100000000000000015100000000",
    prevout_script_hex: "21035935f55855afd8c999bdb5a8d08ae8e73b7618e200d4ef7687cd55d3c2e4c9d7ac91",
    prevout_satoshis: 1000,
    recorded_0_3_24: Ok(()),
    block: Err(NULLFAIL),
    standard: Err(NULLFAIL),
    default: Ok(()),
};

const ALL: [&Witness; 7] = [
    &POLICY_AS_CONSENSUS_SEED,
    &POLICY_AS_CONSENSUS_FLOW,
    &POLICY_AS_CONSENSUS_ARITH,
    &POLICY_AS_CONSENSUS_STACK,
    &POLICY_AS_CONSENSUS_CRYPTO,
    &VERSION_GATE_NULLDUMMY,
    &VERSION_GATE_NULLFAIL,
];

#[test]
fn flags_policy_as_consensus_a_version_1_spend_leaving_two_stack_elements_is_valid_under_the_block_word(
) {
    check_all(&POLICY_AS_CONSENSUS_SEED);
}

#[test]
fn flags_policy_as_consensus_a_version_1_spend_leaving_two_true_elements_is_valid_under_the_block_word(
) {
    check_all(&POLICY_AS_CONSENSUS_FLOW);
}

#[test]
fn flags_policy_as_consensus_a_version_1_lshift_by_a_non_minimal_count_is_valid_under_the_block_word(
) {
    check_all(&POLICY_AS_CONSENSUS_ARITH);
}

#[test]
fn flags_policy_as_consensus_a_version_1_num2bin_to_a_non_minimal_width_is_valid_under_the_block_word(
) {
    check_all(&POLICY_AS_CONSENSUS_STACK);
}

#[test]
fn flags_policy_as_consensus_a_version_1_multisig_with_a_non_empty_dummy_is_valid_under_the_block_word(
) {
    check_all(&POLICY_AS_CONSENSUS_CRYPTO);
}

#[test]
fn flags_version_gate_nulldummy_a_non_empty_dummy_at_version_2_is_valid_under_every_word_and_by_default(
) {
    check_all(&VERSION_GATE_NULLDUMMY);
}

#[test]
fn flags_version_gate_nullfail_a_failing_non_empty_signature_at_version_1_is_refused_under_both_words(
) {
    check_all(&VERSION_GATE_NULLFAIL);
}

/// The default mode's verdicts are 0.3.24's, except the NULLDUMMY version
/// gate: the only default-mode behavior this release changes.
#[test]
fn the_default_mode_changes_exactly_one_recorded_verdict_the_nulldummy_version_gate() {
    let mut changed = Vec::new();
    for w in ALL {
        let unchanged = match (run(w, Mode::Default), w.recorded_0_3_24) {
            (Ok(true), Ok(())) => true,
            (Err(message), Err(fragment)) => message.contains(fragment),
            _ => false,
        };
        if !unchanged {
            changed.push(w.rule);
        }
    }
    assert_eq!(changed, vec!["flags.version-gate.nulldummy"]);
}

/// The two words differ on a version-1 witness exactly where a standard-only
/// rule bites, and agree on the version-2 one: `standard(era)` is
/// `block(era)` plus the four standard-only flags and nothing else.
#[test]
fn the_standard_word_refuses_what_the_block_word_accepts_only_by_a_standard_only_rule() {
    for w in ALL {
        let block = run(w, Mode::Block);
        let standard = run(w, Mode::Standard);
        if block == standard {
            continue;
        }
        assert_eq!(
            block,
            Ok(true),
            "{}: the block word is the looser one",
            w.rule
        );
        let msg = standard.unwrap_err();
        assert!(
            msg.contains(CLEANSTACK) || msg.contains(MINENCODE) || msg.contains(NULLDUMMY),
            "{}: a standard-only rule, got {:?}",
            w.rule,
            msg
        );
    }
}
