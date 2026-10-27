#![cfg(test)]

use super::*;

#[test]
fn test_is_opcode_disabled() {
    assert!(is_opcode_disabled(OP_2MUL, false));
    assert!(is_opcode_disabled(OP_2DIV, false));
    assert!(!is_opcode_disabled(OP_2MUL, true));
    assert!(!is_opcode_disabled(OP_2DIV, true));
    // BAD_OPCODE in their arms, not "disabled" (interpreter.cpp:360-375)
    assert!(!is_opcode_disabled(OP_VER, false));
    assert!(!is_opcode_disabled(OP_VERIF, false));
    assert!(!is_opcode_disabled(OP_VERNOTIF, false));

    assert!(!is_opcode_disabled(OP_DUP, false));
    assert!(!is_opcode_disabled(OP_MUL, false));
    assert!(!is_opcode_disabled(OP_CAT, false));
}

#[test]
fn test_is_chunk_minimal_push() {
    // OP_0 for empty data
    let chunk = ScriptChunk::new(OP_0, Some(vec![]));
    assert!(is_chunk_minimal_push(&chunk));

    // Direct push for small data
    let chunk = ScriptChunk::new(3, Some(vec![1, 2, 3]));
    assert!(is_chunk_minimal_push(&chunk));

    // OP_1 for [1]
    let chunk = ScriptChunk::new(OP_1, Some(vec![1]));
    assert!(is_chunk_minimal_push(&chunk));

    // Non-minimal: using push opcode for [1] instead of OP_1
    let chunk = ScriptChunk::new(1, Some(vec![1]));
    assert!(!is_chunk_minimal_push(&chunk));
}

#[test]
fn test_simple_stack_script() {
    // Test: OP_1 OP_2 OP_ADD OP_3 OP_EQUAL
    // Should leave [1] on stack (true)
    let locking = LockingScript::from_asm("OP_ADD OP_3 OP_EQUAL").unwrap();
    let unlocking = UnlockingScript::from_asm("OP_1 OP_2").unwrap();

    let mut spend = Spend::new(SpendParams {
        source_txid: [0u8; 32],
        source_output_index: 0,
        source_satoshis: 0,
        locking_script: locking,
        transaction_version: 1,
        other_inputs: vec![],
        outputs: vec![],
        input_index: 0,
        unlocking_script: unlocking,
        input_sequence: 0xffffffff,
        lock_time: 0,
        memory_limit: None,
        work_limit: None,
    });

    let result = spend.validate();
    assert!(result.is_ok(), "Expected valid spend, got {:?}", result);
}

#[test]
fn test_if_else_endif() {
    // Test: OP_1 OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF
    // Should push 2 (true branch)
    let locking = LockingScript::from_asm("OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF").unwrap();
    let unlocking = UnlockingScript::from_asm("OP_1").unwrap();

    let mut spend = Spend::new(SpendParams {
        source_txid: [0u8; 32],
        source_output_index: 0,
        source_satoshis: 0,
        locking_script: locking,
        transaction_version: 1,
        other_inputs: vec![],
        outputs: vec![],
        input_index: 0,
        unlocking_script: unlocking,
        input_sequence: 0xffffffff,
        lock_time: 0,
        memory_limit: None,
        work_limit: None,
    });

    let result = spend.validate();
    assert!(result.is_ok(), "Expected valid spend, got {:?}", result);
}

#[test]
fn test_hash_operations() {
    // Test that hash operations work
    // SHA256 produces 32 bytes, we check the size is 32 (0x20)
    // Use NIP to remove the hash after SIZE, leaving just the size to compare
    let locking = LockingScript::from_asm("OP_SHA256 OP_SIZE OP_NIP 20 OP_EQUAL").unwrap();
    let unlocking = UnlockingScript::from_asm("00").unwrap();

    let mut spend = Spend::new(SpendParams {
        source_txid: [0u8; 32],
        source_output_index: 0,
        source_satoshis: 0,
        locking_script: locking,
        transaction_version: 1,
        other_inputs: vec![],
        outputs: vec![],
        input_index: 0,
        unlocking_script: unlocking,
        input_sequence: 0xffffffff,
        lock_time: 0,
        memory_limit: None,
        work_limit: None,
    });

    let result = spend.validate();
    assert!(result.is_ok(), "Expected valid spend, got {:?}", result);
}

#[test]
fn test_failing_script() {
    // Test: just OP_0 should fail (stack has falsy value)
    let locking = LockingScript::from_asm("OP_0").unwrap();
    let unlocking = UnlockingScript::new();

    let mut spend = Spend::new(SpendParams {
        source_txid: [0u8; 32],
        source_output_index: 0,
        source_satoshis: 0,
        locking_script: locking,
        transaction_version: 1,
        other_inputs: vec![],
        outputs: vec![],
        input_index: 0,
        unlocking_script: unlocking,
        input_sequence: 0xffffffff,
        lock_time: 0,
        memory_limit: None,
        work_limit: None,
    });

    let result = spend.validate();
    assert!(result.is_err(), "Expected failed validation");
}

/// With no local budget (`memory_limit: Some(usize::MAX)`, `Transaction::verify`'s
/// default since bsv-rs#331) an element the allocator cannot give is a decline,
/// never an abort: its limit the bytes both stacks held, its attempt those and
/// the size asked. No script reaches the allocator's refusal on a 64-bit host
/// (the default mode bounds an element at 1 GiB), so the helper is asked for
/// more than `isize::MAX` bytes, which every allocator refuses.
#[test]
fn an_allocation_the_allocator_refuses_is_a_decline_not_an_abort() {
    let mut spend = Spend::new(SpendParams {
        source_txid: [0u8; 32],
        source_output_index: 0,
        source_satoshis: 0,
        locking_script: LockingScript::from_asm("OP_DROP OP_1").unwrap(),
        transaction_version: 1,
        other_inputs: vec![],
        outputs: vec![],
        input_index: 0,
        unlocking_script: UnlockingScript::from_asm("OP_1").unwrap(),
        input_sequence: 0xffffffff,
        lock_time: 0,
        memory_limit: Some(usize::MAX),
        work_limit: None,
    });
    spend.push_stack(vec![0x01; 7]).unwrap();
    let asked = isize::MAX as usize + 1;
    let declined = spend.zeroed_element(0, asked).unwrap_err();
    assert_eq!(
        declined.resource_limit,
        Some(super::super::evaluation_error::ScriptResourceLimit {
            resource: ScriptResource::Stack,
            limit: 7,
            attempted: 7 + asked as u64,
            work_spent: None,
        })
    );
    assert!(declined.is_resource_limit());
    assert_eq!(declined.message, "Stack memory usage has exceeded 7 bytes");
    assert!(spend.copy_element(&[1, 2, 3]).is_ok());
}

/// An error's copy of the stacks, made fallibly since bsv-rs#331 (left empty
/// when the allocator refuses it), is the stacks' copy.
#[test]
fn an_error_snapshot_copies_the_stack() {
    assert_eq!(
        stack::snapshot(&[vec![1], vec![2, 3]]),
        vec![vec![1], vec![2, 3]]
    );
    assert!(stack::snapshot(&[]).is_empty());
}
