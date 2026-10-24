use super::*;
use crate::primitives::from_hex;
use crate::script::flags::ProtocolEra;

/// A compressed public key and a well-formed low-S signature with the
/// FORKID hash type that does not verify in any context below.
const PUBKEY: &str = "035935f55855afd8c999bdb5a8d08ae8e73b7618e200d4ef7687cd55d3c2e4c9d7";
const WRONG_SIG: &str = "304402204bbb723c10080132ef81641e0e9963eb77782bf50c149f0f15c6d7b8e263464e02207f18ea8fdff74fb4d4d2dc677555fb1c94cf6219fe4bb4c40162e1e270f8924941";

fn spend(lock_asm: &str, unlock_asm: &str, version: i32) -> Spend {
    Spend::new(SpendParams {
        source_txid: [0u8; 32],
        source_output_index: 0,
        source_satoshis: 1000,
        locking_script: LockingScript::from_asm(lock_asm).unwrap(),
        transaction_version: version,
        other_inputs: vec![],
        outputs: vec![],
        input_index: 0,
        unlocking_script: UnlockingScript::from_asm(unlock_asm).unwrap(),
        input_sequence: 0xffff_ffff,
        lock_time: 0,
        memory_limit: None,
        work_limit: None,
    })
}

fn with_flags(lock_asm: &str, unlock_asm: &str, version: i32, flags: ScriptFlags) -> Spend {
    let mut s = spend(lock_asm, unlock_asm, version);
    s.set_flags(flags);
    s
}

fn message(r: Result<bool, ScriptEvaluationError>) -> String {
    r.expect_err("expected a refusal").message
}

fn valid(r: Result<bool, ScriptEvaluationError>) -> bool {
    matches!(r, Ok(true))
}

fn block() -> ScriptFlags {
    ScriptFlags::block(ProtocolEra::PostChronicle)
}

fn standard() -> ScriptFlags {
    ScriptFlags::standard(ProtocolEra::PostChronicle)
}

#[test]
fn nullfail_refuses_a_failing_non_empty_checksig_signature_at_version_1_under_the_block_word() {
    let lock = format!("{PUBKEY} OP_CHECKSIG OP_NOT");
    // Version 1: NULLFAIL is mandatory and the gate is on.
    let msg = message(with_flags(&lock, WRONG_SIG, 1, block()).validate());
    assert_eq!(msg, "OP_CHECKSIG requires failing signatures to be empty.");
    // Version 2 post-Chronicle: the gate is off, the negated failure is a true top.
    assert!(valid(with_flags(&lock, WRONG_SIG, 2, block()).validate()));
    // Before Chronicle the gate is always on.
    assert!(with_flags(
        &lock,
        WRONG_SIG,
        2,
        ScriptFlags::block(ProtocolEra::PostGenesis)
    )
    .validate()
    .is_err());
    // An empty signature is what NULLFAIL asks for.
    assert!(valid(with_flags(&lock, "0", 1, block()).validate()));
    // The TypeScript default mode has no NULLFAIL rule.
    assert!(valid(spend(&lock, WRONG_SIG, 1).validate()));
}

#[test]
fn nullfail_refuses_a_failing_checkmultisig_with_any_non_empty_signature_at_version_1() {
    let lock = format!("OP_1 {PUBKEY} OP_1 OP_CHECKMULTISIG OP_NOT");
    let msg = message(with_flags(&lock, &format!("0 {WRONG_SIG}"), 1, block()).validate());
    assert_eq!(
        msg,
        "OP_CHECKMULTISIG requires failing signatures to be empty."
    );
    assert!(valid(with_flags(&lock, "0 0", 1, block()).validate()));
    assert!(valid(
        with_flags(&lock, &format!("0 {WRONG_SIG}"), 2, block()).validate()
    ));
    assert!(valid(spend(&lock, &format!("0 {WRONG_SIG}"), 1).validate()));
}

#[test]
fn nulldummy_is_a_standard_only_rule_gated_on_the_version() {
    // 0-of-0 multisig: only the dummy is consumed; OP_1 as the dummy.
    let lock = "OP_0 OP_0 OP_CHECKMULTISIG";
    // The block word never carries NULLDUMMY.
    assert!(valid(with_flags(lock, "OP_1", 1, block()).validate()));
    // The standard word does, under the gate: version 1 refused, version 2 accepted.
    let msg = message(with_flags(lock, "OP_1", 1, standard()).validate());
    assert_eq!(
        msg,
        "OP_CHECKMULTISIG requires the extra stack item (dummy) to be empty."
    );
    assert!(valid(with_flags(lock, "OP_1", 2, standard()).validate()));
    assert!(with_flags(
        lock,
        "OP_1",
        2,
        ScriptFlags::standard(ProtocolEra::PostGenesis)
    )
    .validate()
    .is_err());
    // The TypeScript default mode: strict at version 1, relaxed at version 2.
    assert!(spend(lock, "OP_1", 1).validate().is_err());
    assert!(valid(spend(lock, "OP_1", 2).validate()));
    // An empty dummy passes everywhere.
    assert!(valid(with_flags(lock, "0", 1, standard()).validate()));
}

#[test]
fn minimaldata_low_s_and_cleanstack_follow_the_word_and_the_gate() {
    // A non-minimal push of 1 (`01 01` instead of OP_1) leaves a true top.
    let non_minimal = UnlockingScript::from_binary(&[0x01, 0x01]).unwrap();
    let mut s = spend("OP_1 OP_EQUAL", "", 1);
    s = Spend::new(SpendParams {
        unlocking_script: non_minimal.clone(),
        ..params_of(&s)
    });
    assert!(
        s.validate().is_err(),
        "the default mode enforces MINIMALDATA at version 1"
    );
    let mut s = Spend::new(SpendParams {
        unlocking_script: non_minimal.clone(),
        ..params_of(&spend("OP_1 OP_EQUAL", "", 1))
    });
    s.set_flags(block());
    assert!(
        valid(s.validate()),
        "the block word never carries MINIMALDATA"
    );
    let mut s = Spend::new(SpendParams {
        unlocking_script: non_minimal,
        ..params_of(&spend("OP_1 OP_EQUAL", "", 1))
    });
    s.set_flags(standard());
    assert!(
        s.validate().is_err(),
        "the standard word carries it, and version 1 is gated on"
    );

    // Two elements at the end: CLEANSTACK.
    assert!(valid(with_flags("OP_1 OP_1", "", 1, block()).validate()));
    assert!(with_flags("OP_1 OP_1", "", 1, standard())
        .validate()
        .is_err());
    assert!(valid(with_flags("OP_1 OP_1", "", 2, standard()).validate()));
}

/// `SpendParams` for a fresh interpreter with the same context as `s`.
fn params_of(s: &Spend) -> SpendParams {
    let inputs = s.transaction.inputs();
    let ours = &inputs[s.input_index];
    SpendParams {
        source_txid: s.source_txid,
        source_output_index: s.source_output_index,
        source_satoshis: s.source_satoshis,
        locking_script: s.locking_script.clone(),
        transaction_version: s.transaction_version,
        other_inputs: inputs
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != s.input_index)
            .map(|(_, other)| other.clone())
            .collect(),
        outputs: s.transaction.outputs().to_vec(),
        input_index: s.input_index,
        unlocking_script: s.unlocking_script.clone(),
        input_sequence: ours.sequence,
        lock_time: s.transaction.locktime(),
        memory_limit: s.memory_limit,
        work_limit: None,
    }
}

#[test]
fn push_only_is_derived_from_the_word_and_the_version() {
    // A non-push opcode in the unlocking script.
    let lock = "OP_1 OP_EQUAL";
    let unlock = "OP_0 OP_1ADD";
    assert!(
        spend(lock, unlock, 2).validate().is_err(),
        "the default mode requires push-only at every version"
    );
    assert!(
        valid(with_flags(lock, unlock, 2, block()).validate()),
        "post-Chronicle, version 2: not required"
    );
    assert!(
        with_flags(lock, unlock, 1, block()).validate().is_err(),
        "post-Chronicle, version 1: required"
    );
    assert!(
        with_flags(
            lock,
            unlock,
            2,
            ScriptFlags::block(ProtocolEra::PostGenesis)
        )
        .validate()
        .is_err(),
        "pre-Chronicle: required at every version"
    );
    // The setter still overrides a derived rule.
    let mut s = with_flags(lock, unlock, 1, block());
    s.set_require_push_only(false);
    assert!(valid(s.validate()));
}

#[test]
fn discourage_upgradable_nops_refuses_an_executed_nop1_to_nop10_under_the_standard_word_only() {
    // 0xb0-0xb2 and 0xb8-0xb9 are NOPs in every era; 0xb3-0xb7 only for a coin created
    // before Chronicle (their Chronicle meanings live under UTXO_AFTER_CHRONICLE), so
    // those are tested under the post-Genesis words.
    for (nop, era) in [
        ("OP_NOP1", ProtocolEra::PostChronicle),
        ("OP_NOP2", ProtocolEra::PostChronicle),
        ("OP_NOP3", ProtocolEra::PostChronicle),
        ("OP_NOP4", ProtocolEra::PostGenesis),
        ("OP_NOP8", ProtocolEra::PostGenesis),
        ("OP_NOP9", ProtocolEra::PostChronicle),
        ("OP_NOP10", ProtocolEra::PostChronicle),
    ] {
        let lock = format!("{nop} OP_1");
        assert!(
            valid(with_flags(&lock, "", 2, ScriptFlags::block(era)).validate()),
            "{nop}: a NOP in a block"
        );
        let msg = message(with_flags(&lock, "", 2, ScriptFlags::standard(era)).validate());
        assert_eq!(msg, format!("{nop} is discouraged by verification flags."));
        assert!(
            valid(spend(&lock, "", 1).validate()),
            "{nop}: the default mode has no such rule"
        );
    }
    // Not executed: not discouraged (interpreter.cpp: the check is inside fExec).
    assert!(valid(
        with_flags("OP_0 OP_IF OP_NOP1 OP_ENDIF OP_1", "", 2, standard()).validate()
    ));
    // OP_NOP itself is never discouraged.
    assert!(valid(
        with_flags("OP_NOP OP_1", "", 2, standard()).validate()
    ));
}

#[test]
fn minimalif_requires_an_empty_or_0x01_argument_under_the_flag_and_the_gate() {
    let word = block() | ScriptFlags::MINIMALIF;
    let lock = "OP_IF OP_1 OP_ELSE OP_0 OP_ENDIF";
    assert!(valid(with_flags(lock, "OP_1", 1, word).validate()));
    let msg = message(with_flags(lock, "OP_2", 1, word).validate());
    assert_eq!(msg, "OP_IF and OP_NOTIF require minimal truth values.");
    assert!(
        valid(with_flags(lock, "OP_2", 2, word).validate()),
        "version 2 post-Chronicle: gated off"
    );
    assert!(
        valid(with_flags(lock, "OP_2", 1, block()).validate()),
        "not in the block word"
    );
    assert!(
        valid(spend(lock, "OP_2", 1).validate()),
        "not in the default mode"
    );
}

#[test]
fn compressed_pubkeytype_refuses_an_uncompressed_key_under_the_flag() {
    // A well-formed uncompressed key (the generator point) with an empty signature:
    // CHECKSIG fails cleanly to false, then OP_NOT makes it true.
    let g = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
    let lock = format!("{g} OP_CHECKSIG OP_NOT");
    assert!(valid(with_flags(&lock, "0", 1, block()).validate()));
    let msg =
        message(with_flags(&lock, "0", 1, block() | ScriptFlags::COMPRESSED_PUBKEYTYPE).validate());
    assert_eq!(msg, "The public key must be compressed.");
    let compressed = format!("{PUBKEY} OP_CHECKSIG OP_NOT");
    assert!(valid(
        with_flags(
            &compressed,
            "0",
            1,
            block() | ScriptFlags::COMPRESSED_PUBKEYTYPE
        )
        .validate()
    ));
}

#[test]
fn a_word_the_interpreter_cannot_honor_is_refused_by_validate_as_invalid_flags() {
    let word = block().without(ScriptFlags::SIGHASH_FORKID);
    let msg = message(with_flags("OP_1", "", 1, word).validate());
    assert!(
        msg.starts_with("Invalid verification flags: SIGHASH_FORKID is not set"),
        "{msg}"
    );
    let word = (standard() | ScriptFlags::CLEANSTACK).without(ScriptFlags::P2SH);
    let msg = message(with_flags("OP_1", "", 1, word).validate());
    assert!(msg.contains("CLEANSTACK without P2SH"), "{msg}");
    let s = with_flags("OP_1", "", 1, block());
    assert_eq!(s.flags(), Some(block()));
    assert_eq!(spend("OP_1", "", 1).flags(), None);
}

#[test]
fn set_flags_replaces_the_default_switches_and_the_setters_override_afterwards() {
    // The default mode at version 1 enforces MINIMALDATA; the block word does not;
    // `set_require_minimal(true)` after `set_flags` re-enables it.
    let non_minimal = UnlockingScript::from_binary(&[0x01, 0x01]).unwrap();
    let mut s = Spend::new(SpendParams {
        unlocking_script: non_minimal,
        ..params_of(&spend("OP_1 OP_EQUAL", "", 1))
    });
    s.set_flags(block());
    s.set_require_minimal(true);
    assert!(s.validate().is_err());
    let _ = from_hex; // used by the witnesses' integration test; keep the import honest
}
