use super::*;
use crate::primitives::BigNumber;
use crate::script::ProtocolEra;
use crate::script::Script;

fn spend(standard: bool) -> Spend {
    spend_with_lock(standard, LockingScript::new())
}

fn spend_with_lock(standard: bool, locking_script: LockingScript) -> Spend {
    let mut s = Spend::new(SpendParams {
        source_txid: [0; 32],
        source_output_index: 0,
        source_satoshis: 1,
        locking_script,
        transaction_version: 2,
        other_inputs: vec![],
        outputs: vec![],
        input_index: 0,
        unlocking_script: UnlockingScript::new(),
        input_sequence: u32::MAX,
        lock_time: 0,
        memory_limit: None,
        work_limit: None,
    });
    s.set_flags(if standard {
        ScriptFlags::standard(ProtocolEra::PostChronicle)
    } else {
        ScriptFlags::block(ProtocolEra::PostChronicle)
    });
    s
}

fn assert_number_error(s: &Spend, bytes: &[u8]) {
    let error = s.read_splice_operand(bytes).unwrap_err();
    assert!(
        error.message.starts_with("Script number overflow"),
        "{error}"
    );
    assert!(!error.is_resource_limit());
}

#[test]
fn fixed_width_nine_byte_operands_respect_the_sign_byte() {
    for standard in [false, true] {
        let s = spend(standard);
        assert_eq!(
            s.read_splice_operand(&[4, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap(),
            4
        );
        assert_eq!(
            s.read_splice_operand(&[4, 0, 0, 0, 0, 0, 0, 0, 0x80])
                .unwrap(),
            -4
        );
        assert_eq!(s.read_splice_operand(&[0; 9]).unwrap(), 0);
        assert_eq!(
            s.read_splice_operand(&[0, 0, 0, 0, 0, 0, 0, 0, 0x80])
                .unwrap(),
            0
        );
    }
}

#[test]
fn fixed_width_ninth_byte_must_be_a_pure_sign() {
    for standard in [false, true] {
        let s = spend(standard);
        for sign in [1, 0x7f, 0x81, 0xff] {
            assert_number_error(&s, &[4, 0, 0, 0, 0, 0, 0, 0, sign]);
        }
    }
}

#[test]
fn fixed_width_ten_byte_operands_are_refused() {
    for standard in [false, true] {
        let s = spend(standard);
        assert_number_error(&s, &[4, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_number_error(&s, &[0; 10]);
    }
}

#[test]
fn fixed_width_signed_minimum_is_decoded_then_saturated_by_getint() {
    for standard in [false, true] {
        let s = spend(standard);
        let bytes = ScriptNum::to_bytes(&BigNumber::from_i64(i64::MIN));
        assert_eq!(bytes, [0, 0, 0, 0, 0, 0, 0, 0x80, 0x80]);
        assert_eq!(s.read_splice_operand(&bytes).unwrap(), i64::from(i32::MIN));
        assert_eq!(
            s.read_splice_operand(&ScriptNum::to_bytes(&BigNumber::from_i64(i64::MAX)))
                .unwrap(),
            i64::from(i32::MAX)
        );
    }
}

#[test]
fn fixed_width_nine_byte_magnitudes_must_fit_the_signed_range() {
    for standard in [false, true] {
        let s = spend(standard);
        assert_number_error(&s, &[0, 0, 0, 0, 0, 0, 0, 0x80, 0]);
        for sign in [0, 0x80] {
            assert_number_error(&s, &[1, 0, 0, 0, 0, 0, 0, 0x80, sign]);
            assert_number_error(&s, &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, sign]);
        }
    }
}

#[test]
fn fixed_width_checks_follow_era_width_and_minimal_encoding_checks() {
    let mut s = spend(true);
    s.set_require_minimal(true);
    s.set_script_num_length_policy(8);
    let bytes = [0; 10];
    assert_eq!(
        s.read_splice_operand(&bytes).unwrap_err().message,
        "Script number overflow: 10 bytes, the limit is 8 bytes."
    );
    s.set_script_num_length_policy(0);
    assert!(s
        .read_splice_operand(&bytes)
        .unwrap_err()
        .message
        .starts_with("Invalid script number"));
    s.set_require_minimal(false);
    assert_number_error(&s, &bytes);
}

#[test]
fn fixed_width_rule_leaves_arithmetic_numbers_unrestricted() {
    let s = spend(false);
    let bytes = [4, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(s.read_number(&bytes).unwrap().to_i64(), Some(4));
}

#[test]
fn every_splice_operand_uses_the_fixed_width_decoder() {
    let data: Vec<u8> = (0..16).collect();
    let cases: &[(&[u8], Option<&str>)] = &[
        (&[4, 0, 0, 0, 0, 0, 0, 0, 0], None),
        (&[4, 0, 0, 0, 0, 0, 0, 0, 0x80], Some("must be in range")),
        (&[4, 0, 0, 0, 0, 0, 0, 0, 1], Some("Script number overflow")),
        (
            &[4, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            Some("Script number overflow"),
        ),
        (&[0, 0, 0, 0, 0, 0, 0, 0x80, 0x80], Some("must be in range")),
        (
            &[0, 0, 0, 0, 0, 0, 0, 0x80, 0],
            Some("Script number overflow"),
        ),
    ];
    for standard in [false, true] {
        for (opcode, offset_operand) in [
            (OP_NOP4, true),
            (OP_NOP4, false),
            (OP_NOP5, false),
            (OP_NOP6, false),
        ] {
            for &(bytes, refusal) in cases {
                let mut lock = Script::new();
                lock.write_bin(&data);
                if opcode == OP_NOP4 && !offset_operand {
                    lock.write_number(4);
                }
                lock.write_bin(bytes);
                if offset_operand {
                    lock.write_number(4);
                }
                lock.write_opcode(opcode);
                let expected = match opcode {
                    OP_NOP4 => &data[4..8],
                    OP_NOP5 => &data[..4],
                    _ => &data[12..],
                };
                lock.write_bin(expected).write_opcode(OP_EQUAL);
                let mut s = spend_with_lock(standard, LockingScript::from_script(lock));
                if let Some(message) = refusal {
                    let error = s.validate().unwrap_err();
                    assert!(error.message.contains(message), "{error}");
                    assert!(!error.is_resource_limit());
                } else {
                    assert!(s.validate().unwrap());
                }
            }
        }
    }
}

#[test]
fn substr_checks_length_before_offset() {
    let mut lock = Script::new();
    lock.write_bin(&[1, 2, 3, 4])
        .write_bin(&[1; 10])
        .write_bin(&[0, 0])
        .write_opcode(OP_NOP4);
    let mut s = spend_with_lock(true, LockingScript::from_script(lock));
    s.set_require_minimal(true);
    assert!(s
        .validate()
        .unwrap_err()
        .message
        .starts_with("Invalid script number"));
}

#[test]
fn split_position_accepts_int32_max_and_refuses_int32_max_plus_one() {
    // Exercise the OP_SPLIT range check with a synthetic data length:
    // no multi-gigabyte stack element is needed to test the position bound.
    let max = i32::MAX as usize;
    for standard in [false, true] {
        let s = spend(standard);
        assert_eq!(
            s.split_position(&BigNumber::from_i64(max as i64), max)
                .unwrap(),
            max
        );
        let error = s
            .split_position(&BigNumber::from_i64(max as i64 + 1), max + 1)
            .unwrap_err();
        assert!(error
            .message
            .starts_with("OP_SPLIT requires the first stack item"));
        assert!(!error.is_resource_limit());
        assert!(s
            .split_position(&BigNumber::from_i64(max as i64), max - 1)
            .is_err());
        assert!(s.split_position(&BigNumber::from_i64(-1), max).is_err());
    }
}
