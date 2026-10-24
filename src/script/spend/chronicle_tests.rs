#![cfg(test)]

use super::crypto::has_forkid_bit;
use super::*;
use crate::script::flags::ProtocolEra;
use crate::script::Script;

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

fn valid(r: Result<bool, ScriptEvaluationError>) -> bool {
    matches!(r, Ok(true))
}

fn message(r: Result<bool, ScriptEvaluationError>) -> String {
    r.expect_err("expected a refusal").message
}

#[test]
fn substr_left_and_right_take_ranges_after_chronicle_and_refuse_out_of_range_ones() {
    // 0xb3 OP_SUBSTR (data offset len), 0xb4 OP_LEFT, 0xb5 OP_RIGHT (data len)
    assert!(valid(
        spend("OP_1 OP_2 OP_NOP4 bbcc OP_EQUAL", "aabbccdd", 2).validate()
    ));
    assert!(valid(
        spend("OP_2 OP_NOP5 aabb OP_EQUAL", "aabbccdd", 2).validate()
    ));
    assert!(valid(
        spend("OP_2 OP_NOP6 ccdd OP_EQUAL", "aabbccdd", 2).validate()
    ));
    assert!(valid(
        spend("OP_0 OP_NOP5 OP_0 OP_EQUAL", "aabbccdd", 2).validate()
    ));
    assert_eq!(
        message(spend("OP_5 OP_NOP5", "aabbccdd", 2).validate()),
        "OP_LEFT length (5) must be in range [0, 4]"
    );
    assert_eq!(
        message(spend("OP_4 OP_0 OP_NOP4", "aabbccdd", 2).validate()),
        "OP_SUBSTR offset (4) must be in range [0, 4) and length (0) must be in range [0, 0]"
    );
    assert!(
        message(spend("OP_1 OP_4 OP_NOP4", "aabbccdd", 2).validate())
            .starts_with("OP_SUBSTR offset (1)")
    );
    assert!(
        message(spend("OP_1NEGATE OP_NOP6", "aabbccdd", 2).validate())
            .contains("OP_RIGHT length (-1)")
    );
}

#[test]
fn lshiftnum_and_rshiftnum_shift_script_numbers_toward_zero() {
    // 0xb6 OP_LSHIFTNUM, 0xb7 OP_RSHIFTNUM: (x n -- out) on numbers
    assert!(valid(
        spend("OP_1 OP_NOP7 OP_14 OP_EQUAL", "OP_7", 2).validate()
    ));
    assert!(valid(
        spend("OP_10 OP_NOP7 0004 OP_EQUAL", "OP_1", 2).validate()
    )); // 1 << 10 = 1024 = 0x0400 LE
        // -7 >> 1 is -3 (toward zero; 0x87 is -7, 0x83 is -3), not -4
    assert!(valid(spend("OP_1 OP_NOP8 83 OP_EQUAL", "87", 2).validate()));
    assert!(valid(
        spend("OP_1 OP_NOP8 OP_3 OP_EQUAL", "OP_7", 2).validate()
    ));
    // a shift past every bit is zero (the empty number)
    assert!(valid(
        spend("OP_16 OP_NOP8 OP_0 OP_EQUAL", "OP_7", 2).validate()
    ));
    assert!(valid(
        spend("OP_16 OP_NOP8 OP_0 OP_EQUAL", "87", 2).validate()
    ));
    // zero shifted left stays zero
    assert!(valid(
        spend("OP_16 OP_NOP7 OP_0 OP_EQUAL", "OP_0", 2).validate()
    ));
    assert_eq!(
        message(spend("OP_1NEGATE OP_NOP7", "OP_7", 2).validate()),
        "OP_LSHIFTNUM bits to shift must not be negative."
    );
    assert_eq!(
        message(spend("OP_1NEGATE OP_NOP8", "OP_7", 2).validate()),
        "OP_RSHIFTNUM bits to shift must not be negative."
    );
}

#[test]
fn lshiftnum_refuses_a_result_beyond_the_memory_budget_before_computing_it() {
    let mut s = Spend::new(SpendParams {
        source_txid: [0u8; 32],
        source_output_index: 0,
        source_satoshis: 1000,
        locking_script: LockingScript::from_asm("2823 OP_NOP7").unwrap(), // 0x2328 = 9000 bits
        transaction_version: 2,
        other_inputs: vec![],
        outputs: vec![],
        input_index: 0,
        unlocking_script: UnlockingScript::from_asm("OP_1").unwrap(),
        input_sequence: 0xffff_ffff,
        lock_time: 0,
        memory_limit: Some(1000),
        work_limit: None,
    });
    let err = s.validate().unwrap_err();
    assert!(err.is_resource_limit(), "{}", err.message);
    assert_eq!(
        err.resource_limit.unwrap().resource,
        ScriptResource::ElementSize
    );
}

#[test]
fn before_chronicle_0xb3_to_0xb7_are_nops_and_discouraged_under_the_standard_word() {
    // version 1 in the default mode: the UTXO is taken as pre-Chronicle
    assert!(valid(
        spend("OP_NOP4 OP_NOP5 OP_NOP6 OP_NOP7 OP_NOP8", "OP_1", 1).validate()
    ));
    let mut s = spend("OP_NOP7 OP_1", "", 2);
    s.set_flags(ScriptFlags::standard(ProtocolEra::PostGenesis));
    assert_eq!(
        message(s.validate()),
        "OP_NOP7 is discouraged by verification flags."
    );
    // the block word of a post-Chronicle coin turns them on even at version 1
    let mut s = spend("OP_1 OP_NOP7 OP_14 OP_EQUAL", "OP_7", 1);
    s.set_flags(ScriptFlags::block(ProtocolEra::PostChronicle));
    assert!(valid(s.validate()));
    // and the setter overrides either way
    let mut s = spend("OP_1 OP_NOP7 OP_14 OP_EQUAL", "OP_7", 1);
    s.set_utxo_after_chronicle(true);
    assert!(valid(s.validate()));
}

#[test]
fn op_ver_pushes_the_version_after_chronicle_and_is_refused_before() {
    assert!(valid(spend("OP_VER 02000000 OP_EQUAL", "", 2).validate()));
    assert_eq!(
        message(spend("OP_VER", "", 1).validate()),
        "OP_VER is disabled until Chronicle."
    );
    let mut s = spend("OP_VER 01000000 OP_EQUAL", "", 1);
    s.set_flags(ScriptFlags::block(ProtocolEra::PostChronicle));
    assert!(valid(s.validate()));
    // not executed: nothing happens, before or after Chronicle
    assert!(valid(
        spend("OP_0 OP_IF OP_VER OP_ENDIF OP_1", "", 1).validate()
    ));
}

#[test]
fn op_verif_compares_the_top_with_the_version_and_is_skipped_or_refused_before_chronicle() {
    assert!(valid(
        spend("OP_VERIF OP_1 OP_ELSE OP_0 OP_ENDIF", "02000000", 2).validate()
    ));
    assert!(!valid(
        spend("OP_VERIF OP_1 OP_ELSE OP_0 OP_ENDIF", "01000000", 2).validate()
    ));
    // only an exactly 4-byte element can match; OP_2 (one byte) does not
    assert!(valid(
        spend("OP_VERIF OP_0 OP_ELSE OP_1 OP_ENDIF", "OP_2", 2).validate()
    ));
    assert!(valid(
        spend("OP_VERNOTIF OP_1 OP_ELSE OP_0 OP_ENDIF", "01000000", 2).validate()
    ));
    assert!(valid(
        spend("OP_VERNOTIF OP_0 OP_ELSE OP_1 OP_ENDIF", "02000000", 2).validate()
    ));
    // before Chronicle: executed is refused, not executed is skipped (no conditional pushed)
    assert_eq!(
        message(spend("OP_VERIF OP_1 OP_ENDIF", "02000000", 1).validate()),
        "OP_VERIF is disabled until Chronicle."
    );
    assert!(valid(
        spend("OP_0 OP_IF OP_VERIF OP_ENDIF OP_1", "", 1).validate()
    ));
    assert!(valid(
        spend("OP_0 OP_IF OP_VERNOTIF OP_ENDIF OP_1", "", 1).validate()
    ));
}

#[test]
fn two_mul_and_two_div_are_disabled_before_chronicle_and_compute_after() {
    assert!(message(spend("OP_2MUL", "OP_7", 1).validate()).contains("currently disabled"));
    assert!(message(spend("OP_2DIV", "OP_7", 1).validate()).contains("currently disabled"));
    assert!(valid(spend("OP_2MUL OP_14 OP_EQUAL", "OP_7", 2).validate()));
    assert!(valid(spend("OP_2DIV OP_3 OP_EQUAL", "OP_7", 2).validate()));
    assert!(valid(spend("OP_2DIV 83 OP_EQUAL", "87", 2).validate())); // -7 / 2 = -3
    assert!(valid(spend("OP_2MUL 8e OP_EQUAL", "87", 2).validate())); // -7 * 2 = -14 (0x8e)
                                                                      // not executed: no refusal before Chronicle either (interpreter.cpp:458-459, post-Genesis)
    assert!(valid(
        spend("OP_0 OP_IF OP_2MUL OP_ENDIF OP_1", "", 1).validate()
    ));
}

#[test]
fn one_op_else_per_op_if_after_genesis() {
    assert!(valid(
        spend("OP_IF OP_1 OP_ELSE OP_0 OP_ENDIF", "OP_1", 2).validate()
    ));
    assert_eq!(
        message(spend("OP_IF OP_1 OP_ELSE OP_1 OP_ELSE OP_1 OP_ENDIF", "OP_1", 2).validate()),
        "OP_ELSE may only be used once for each OP_IF or OP_NOTIF after Genesis."
    );
    // one per level, nested
    assert!(valid(
        spend(
            "OP_IF OP_0 OP_IF OP_ELSE OP_ENDIF OP_ELSE OP_ENDIF OP_1",
            "OP_1",
            2
        )
        .validate()
    ));
    // in every mode: version 1 too
    assert!(
        message(spend("OP_IF OP_ELSE OP_ELSE OP_ENDIF OP_1", "OP_1", 1).validate())
            .contains("only be used once")
    );
}

#[test]
fn a_return_inside_a_conditional_stops_execution_but_the_balance_and_the_parse_still_hold() {
    // execution stops at the RETURN: the OP_0 after it never runs, the ENDIF still closes the IF
    assert!(valid(
        spend("OP_1 OP_IF OP_RETURN OP_0 OP_ENDIF", "OP_1", 2).validate()
    ));
    // the conditional must still balance
    assert!(message(spend("OP_1 OP_IF OP_RETURN", "OP_1", 2).validate())
        .contains("terminated with OP_ENDIF"));
    // an undefined opcode after the RETURN is not executed: fine
    let lock = LockingScript::from_binary(&[0x51, 0x63, 0x6a, 0x68, 0xba]).unwrap();
    let mut s = spend("OP_1", "OP_1", 2);
    s = Spend::new(SpendParams {
        locking_script: lock,
        ..params_of(&s)
    });
    assert!(valid(s.validate()));
    // a truncated push after the RETURN is still a parse failure
    let lock = LockingScript::from_binary(&[0x51, 0x63, 0x6a, 0x68, 0x03, 0x01]).unwrap();
    let mut s = Spend::new(SpendParams {
        locking_script: lock,
        ..params_of(&spend("OP_1", "OP_1", 2))
    });
    assert!(message(s.validate()).starts_with("A push declares more bytes"));
    // a top-level RETURN ends the script successfully, whatever follows
    let lock = LockingScript::from_binary(&[0x51, 0x6a, 0xba, 0x03, 0x01]).unwrap();
    let mut s = Spend::new(SpendParams {
        locking_script: lock,
        ..params_of(&spend("OP_1", "", 2))
    });
    assert!(valid(s.validate()));
}

#[test]
fn an_undefined_opcode_is_refused_only_when_executed() {
    assert!(message(spend("OP_1 OP_NOP77", "", 2).validate()).starts_with("Invalid opcode 252"));
    assert!(valid(
        spend("OP_0 OP_IF OP_NOP77 OP_ENDIF OP_1", "", 2).validate()
    ));
    let lock = LockingScript::from_binary(&[0x51, 0xba]).unwrap();
    let mut s = Spend::new(SpendParams {
        locking_script: lock,
        ..params_of(&spend("OP_1", "", 1))
    });
    assert!(message(s.validate()).starts_with("Invalid opcode 186"));
}

#[test]
fn a_truncated_push_is_refused_where_the_walk_reaches_it_even_unexecuted() {
    // OP_0 OP_IF <push 3 with 1 byte>: the branch does not execute, the parse still fails there
    let lock = LockingScript::from_binary(&[0x00, 0x63, 0x03, 0x01]).unwrap();
    assert_eq!(lock.as_script().truncated_push(), Some(2));
    let mut s = Spend::new(SpendParams {
        locking_script: lock,
        ..params_of(&spend("OP_1", "", 2))
    });
    assert!(message(s.validate()).contains("(pc=2)"));
    // a complete script has no truncated push; bytes after a top-level RETURN are data
    assert_eq!(
        Script::from_binary(&[0x51, 0x03, 0x01, 0x02, 0x03])
            .unwrap()
            .truncated_push(),
        None
    );
    assert_eq!(
        Script::from_binary(&[0x6a, 0x03, 0x01])
            .unwrap()
            .truncated_push(),
        None
    );
    assert_eq!(
        Script::from_binary(&[0x4c]).unwrap().truncated_push(),
        Some(0)
    );
    assert_eq!(
        Script::from_binary(&[0x51, 0x4d, 0x01])
            .unwrap()
            .truncated_push(),
        Some(1)
    );
    assert_eq!(
        Script::from_binary(&[0x4e, 0x01, 0x00, 0x00, 0x00])
            .unwrap()
            .truncated_push(),
        Some(0)
    );
    assert_eq!(
        Script::from_binary(&[0x4e, 0x01, 0x00, 0x00, 0x00, 0xaa])
            .unwrap()
            .truncated_push(),
        None
    );
    // an earlier failure wins: the walk never reaches the truncated push
    let lock = LockingScript::from_binary(&[0x69, 0x03, 0x01]).unwrap(); // OP_VERIFY on an empty stack
    let mut s = Spend::new(SpendParams {
        locking_script: lock,
        ..params_of(&spend("OP_1", "", 2))
    });
    assert!(message(s.validate()).contains("OP_VERIFY requires"));
}

#[test]
fn the_scriptcode_keeps_a_forkid_signatures_push_and_deletes_an_empty_ones_op_0() {
    let sig = "304402204c9195e05dc41a9119b4cf65f43e450a057818d74c12265faee6a21ae2e0ab87022051c94bb55d9c54d68efaa16785c6ba6a7958757745528974a92d8cddcb993c1241";
    let lock_asm = format!("{sig} OP_DROP OP_1");
    let mut s = spend(&lock_asm, "", 2);
    s.context = ExecutionContext::LockingScript;
    let sig_bytes = crate::primitives::from_hex(sig).unwrap();
    assert!(has_forkid_bit(&sig_bytes));
    let sub = s.build_subscript(&sig_bytes).unwrap();
    assert_eq!(
        sub.to_binary(),
        s.locking_script.to_binary(),
        "a FORKID signature's push stays"
    );
    // an empty signature carries no hash type: its OP_0 push is deleted, as on the reference
    let mut s = spend("OP_0 OP_1 OP_0", "", 2);
    s.context = ExecutionContext::LockingScript;
    assert!(!has_forkid_bit(&[]));
    let sub = s.build_subscript(&[]).unwrap();
    assert_eq!(sub.to_asm(), "OP_1");
    // a signature without the FORKID bit would be deleted (and is refused by the encoding check)
    assert!(!has_forkid_bit(&[
        0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01
    ]));
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
