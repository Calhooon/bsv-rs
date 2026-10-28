//! The default mode runs the five Chronicle opcodes at every transaction
//! version, as the reference's default does, and refuses a non-minimal number
//! in the reference's words (bsv-rs#397, the keeper's word of 2026-10-28; the
//! reference at `ts-stack@edf6e03` `packages/sdk/src/script/Spend.ts`).
//!
//! The opcode gate of `0xb3`-`0xb7` (`OP_SUBSTR`, `OP_LEFT`,
//! `OP_RIGHT`, `OP_LSHIFTNUM`, `OP_RSHIFTNUM`): the reference's
//! `#skipUnavailablePreChronicleOpcode` returns false without explicit flags
//! (`:827-828`), so its default runs them at version 1; under a word the
//! word's `UTXO_AFTER_CHRONICLE` bit decides, the NOPs and the
//! DISCOURAGE_UPGRADABLE_NOPS refusal where it is off. The second fold extends
//! this gate to the other five opcodes (`script_chronicle_default_397.rs`);
//! the word's number length and the hash-type gate remain separate. A caller's
//! `set_utxo_after_chronicle` sets the opcodes and the word's number length.
//!
//! Each default-mode verdict below is the one the reference gives under
//! Node 22 for the same script (`@bsv/sdk` bundled at `edf6e03`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
use bsv_rs::primitives::from_hex;
use bsv_rs::script::{
    LockingScript, ProtocolEra, ScriptFlags, Spend, SpendParams, UnlockingScript,
};

fn spend(version: i32, unlock: &str, lock: &str) -> Spend {
    Spend::new(SpendParams {
        source_txid: [0u8; 32],
        source_output_index: 0,
        source_satoshis: 1,
        locking_script: LockingScript::from_binary(&from_hex(lock).unwrap()).unwrap(),
        transaction_version: version,
        other_inputs: vec![],
        outputs: vec![],
        input_index: 0,
        unlocking_script: UnlockingScript::from_binary(&from_hex(unlock).unwrap()).unwrap(),
        input_sequence: 0xffff_ffff,
        lock_time: 0,
        memory_limit: None,
        work_limit: None,
    })
}

fn verdict(mut s: Spend) -> Result<bool, String> {
    s.validate().map_err(|e| e.message)
}

/// The opcode ran as a NOP: its operands stayed, so the script ends false
/// (the top element) or, at version 1, unclean.
fn ran_as_nop(name: &str, got: Result<bool, String>) {
    let message = got.expect_err(name);
    assert!(
        message == "The top stack element must be truthy after script evaluation."
            || message.starts_with("The clean stack rule requires exactly one item"),
        "{name}: {message}"
    );
}

/// Each opcode with its operands and a lock valid only if it executes: run
/// as a NOP, the operands stay and the comparison leaves a false on top.
const FIVE: [(&str, &str, &str); 5] = [
    // "aabbcc" offset 1 length 1 is "bb"
    ("OP_SUBSTR", "03aabbcc5151", "b301bb87"),
    // the left 2 of "aabbcc"
    ("OP_LEFT", "03aabbcc52", "b402aabb87"),
    // the right 2 of "aabbcc"
    ("OP_RIGHT", "03aabbcc52", "b502bbcc87"),
    // 1 << 3 is 8
    ("OP_LSHIFTNUM", "5153", "b65887"),
    // 8 >> 3 is 1
    ("OP_RSHIFTNUM", "5853", "b75187"),
];

/// Reference: `ok true` for each at version 1 with no flags. Before #397 this
/// crate ran `0xb3`-`0xb7` as `OP_NOP4`-`OP_NOP8` at version 1 in the default
/// mode, and each script was invalid.
#[test]
fn issue_397_the_five_chronicle_opcodes_run_at_version_1_in_the_default_mode() {
    for (name, unlock, lock) in FIVE {
        assert_eq!(verdict(spend(1, unlock, lock)), Ok(true), "{name}");
    }
}

/// Version 2 was already post-Chronicle by default: unchanged.
#[test]
fn the_five_run_at_version_2_in_the_default_mode() {
    for (name, unlock, lock) in FIVE {
        assert_eq!(verdict(spend(2, unlock, lock)), Ok(true), "{name}");
    }
}

/// Under a word whose `UTXO_AFTER_CHRONICLE` bit is off, the five are NOPs
/// (the block word) or refused as discouraged (the standard word), as
/// before; with the bit on they run.
#[test]
fn under_a_word_the_gate_is_the_words_bit_as_before() {
    for (name, unlock, lock) in FIVE {
        let mut s = spend(1, unlock, lock);
        s.set_flags(ScriptFlags::block(ProtocolEra::PostGenesis));
        ran_as_nop(name, verdict(s));

        let mut s = spend(1, unlock, lock);
        s.set_flags(ScriptFlags::standard(ProtocolEra::PostGenesis));
        let nop = format!(
            "OP_NOP{}",
            4 + FIVE.iter().position(|f| f.0 == name).unwrap()
        );
        assert_eq!(
            verdict(s),
            Err(format!("{nop} is discouraged by verification flags.")),
            "{name}"
        );

        let mut s = spend(1, unlock, lock);
        s.set_flags(ScriptFlags::block(ProtocolEra::PostChronicle));
        assert_eq!(verdict(s), Ok(true), "{name}: post-Chronicle block");

        // the setter after a post-Chronicle word turns the bit off
        let mut s = spend(1, unlock, lock);
        s.set_flags(ScriptFlags::block(ProtocolEra::PostChronicle));
        s.set_utxo_after_chronicle(false);
        ran_as_nop(name, verdict(s));
    }
}

/// A caller who names the coin pre-Chronicle in the default mode gets the
/// NOPs: the setter sets both switches.
#[test]
fn in_the_default_mode_the_setter_names_the_coins_era_for_both_switches() {
    for (name, unlock, lock) in FIVE {
        let mut s = spend(1, unlock, lock);
        s.set_utxo_after_chronicle(false);
        ran_as_nop(name, verdict(s));
    }
}

/// A word's number length still follows its bit, the default mode reading
/// any length as the reference's
/// `#scriptNumMaxSize` does without flags (`Spend.ts:393-401`).
#[test]
fn the_words_number_length_still_follows_the_utxo_bit() {
    assert_eq!(spend(1, "", "51").max_script_num_length(), None);
    let mut s = spend(1, "", "51");
    s.set_flags(ScriptFlags::block(ProtocolEra::PostGenesis));
    assert_eq!(s.max_script_num_length(), Some(750_000));
    s.set_utxo_after_chronicle(true);
    assert_eq!(s.max_script_num_length(), Some(32_000_000));
    let mut s = spend(1, "", "51");
    s.set_flags(ScriptFlags::block(ProtocolEra::PostChronicle));
    assert_eq!(s.max_script_num_length(), Some(32_000_000));
}

/// A non-minimal number at five sites, version 1 (MINIMALDATA): an
/// arithmetic operand, `OP_PICK`'s index, `OP_SPLIT`'s position, `OP_LEFT`'s
/// length (the splice operand) and `OP_CHECKMULTISIG`'s key count.
const NON_MINIMAL: [(&str, &str, &str); 5] = [
    ("OP_ADD", "02010051", "935287"),
    ("OP_PICK", "51020000", "79517551"),
    ("OP_SPLIT", "03aabbcc020100", "7f757551"),
    ("OP_LEFT", "03aabbcc020100", "b47551"),
    ("OP_CHECKMULTISIG", "00020000", "ae"),
];

/// Reference: `non-minimally encoded script number` at each
/// (`Spend.ts:547`, `BigNumber.ts:1684`). Before #397:
/// `Invalid script number: script execution error: Non-minimally encoded
/// script number`.
#[test]
fn issue_397_a_non_minimal_number_is_refused_in_the_references_words() {
    for (site, unlock, lock) in NON_MINIMAL {
        assert_eq!(
            verdict(spend(1, unlock, lock)),
            Err("non-minimally encoded script number".to_string()),
            "{site}"
        );
    }
}

/// Under a word the words are this crate's reader's, as before.
#[test]
fn under_a_word_a_non_minimal_number_keeps_the_readers_words() {
    for (site, unlock, lock) in NON_MINIMAL {
        let mut s = spend(1, unlock, lock);
        s.set_flags(ScriptFlags::standard(ProtocolEra::PostChronicle));
        assert_eq!(
            verdict(s),
            Err(
                "Invalid script number: script execution error: Non-minimally encoded script number"
                    .to_string()
            ),
            "{site}"
        );
    }
}
