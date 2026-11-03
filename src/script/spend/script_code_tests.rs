#![cfg(test)]
//! `find_and_delete` against the node's own `FindAndDelete` unit cases
//! (bitcoin-sv v1.2.3 `src/test/script_tests.cpp`, as the sibling's Lean
//! states them, `lean/BsvScript/Sighash.lean:323-341` at `387dab35`), and the
//! walk through a top-level `OP_RETURN` the chunk parser folds (#654); the
//! writer's and the walker's push-size boundaries and the walk's bound, read
//! at bitcoin-sv `879fc8b` (`src/script/script.h`: `operator<<` at 102-130,
//! `GetOp2` at 163-198, `FindAndDelete` at 200-224), the survivors and
//! timeouts of the complete mutation run (#681).

use super::{find_and_delete, push_of};

#[test]
fn find_and_delete_answers_the_nodes_unit_cases_654() {
    let cases: &[(&[u8], &[u8], &[u8])] = &[
        (&[0x51, 0x52], &[], &[0x51, 0x52]),
        (&[0x51, 0x52, 0x53], &[0x52], &[0x51, 0x53]),
        (
            &[0x53, 0x51, 0x53, 0x53, 0x54, 0x53],
            &[0x53],
            &[0x51, 0x54],
        ),
        (&[0x03, 0x02, 0xff, 0x03], &[0x03, 0x02, 0xff, 0x03], &[]),
        (
            &[0x03, 0x02, 0xff, 0x03, 0x03, 0x02, 0xff, 0x03],
            &[0x03, 0x02, 0xff, 0x03],
            &[],
        ),
        (
            &[0x03, 0x02, 0xff, 0x03, 0x03, 0x02, 0xff, 0x03],
            &[0x02],
            &[0x03, 0x02, 0xff, 0x03, 0x03, 0x02, 0xff, 0x03],
        ),
        (
            &[0x03, 0x02, 0xff, 0x03, 0x03, 0x02, 0xff, 0x03],
            &[0x03],
            &[0x02, 0xff, 0x03, 0x02, 0xff, 0x03],
        ),
        (
            &[0x02, 0xfe, 0xed, 0x51, 0x69],
            &[0xfe, 0xed, 0x51],
            &[0x02, 0xfe, 0xed, 0x51, 0x69],
        ),
        (
            &[0x02, 0xfe, 0xed, 0x51, 0x69],
            &[0x02, 0xfe, 0xed, 0x51],
            &[0x69],
        ),
        (
            &[0x51, 0x69, 0x02, 0xfe, 0xed, 0x51, 0x69],
            &[0xfe, 0xed, 0x51],
            &[0x51, 0x69, 0x02, 0xfe, 0xed, 0x51, 0x69],
        ),
        (
            &[0x51, 0x69, 0x02, 0xfe, 0xed, 0x51, 0x69],
            &[0x02, 0xfe, 0xed, 0x51],
            &[0x51, 0x69, 0x69],
        ),
        (&[0x00, 0x00, 0x51, 0x51], &[0x00, 0x51], &[0x00, 0x51]),
        (
            &[0x00, 0x00, 0x51, 0x00, 0x51, 0x51],
            &[0x00, 0x51],
            &[0x00, 0x51],
        ),
        (&[0x00, 0x03, 0xfe, 0xed], &[0x03, 0xfe, 0xed], &[0x00]),
    ];
    for (script, b, expected) in cases {
        assert_eq!(
            &find_and_delete(script, b),
            expected,
            "{script:02x?} - {b:02x?}"
        );
    }
}

#[test]
fn find_and_delete_reads_past_a_top_level_op_return_and_keeps_a_cut_push_654() {
    // OP_RETURN, then a push of the pattern: the node's walk reads it.
    assert_eq!(
        find_and_delete(&[0x6a, 0x01, 0x00, 0x51], &[0x01, 0x00]),
        [0x6a, 0x51]
    );
    // A push cut short ends the walk; the bytes after it are kept as they are.
    assert_eq!(
        find_and_delete(&[0x51, 0x4c, 0x05, 0x51, 0x51], &[0x51]),
        [0x4c, 0x05, 0x51, 0x51]
    );
}

/// The node's `CScript() << vchSig` header for a push of `len` bytes
/// (`script.h:102-130`): direct below `OP_PUSHDATA1` (76), `OP_PUSHDATA1` to
/// 0xff, `OP_PUSHDATA2` to 0xffff, `OP_PUSHDATA4` above, lengths little-endian.
fn header_of(len: usize) -> Vec<u8> {
    let mut push = push_of(&vec![0xab; len]);
    assert_eq!(push.split_off(push.len() - len), vec![0xab; len], "{len}");
    push
}

#[test]
fn a_push_of_75_bytes_is_direct_and_of_76_takes_pushdata1_681() {
    assert_eq!(header_of(0), [0x00]);
    assert_eq!(header_of(1), [0x01]);
    assert_eq!(header_of(75), [0x4b]);
    assert_eq!(header_of(76), [0x4c, 0x4c]);
}

#[test]
fn a_push_of_255_bytes_takes_pushdata1_and_of_256_pushdata2_681() {
    assert_eq!(header_of(255), [0x4c, 0xff]);
    assert_eq!(header_of(256), [0x4d, 0x00, 0x01]);
}

#[test]
fn a_push_of_65535_bytes_takes_pushdata2_and_of_65536_pushdata4_681() {
    assert_eq!(header_of(65535), [0x4d, 0xff, 0xff]);
    assert_eq!(header_of(65536), [0x4e, 0x00, 0x00, 0x01, 0x00]);
}

/// A copy of the pattern inside a push's data is not at an instruction
/// boundary, and the node's walk steps over it (`GetOp2`'s length read at
/// `script.h:172-193`, `FindAndDelete`'s walk at `:206-215`); the copy after
/// the push is deleted. A walker that misreads the length lands inside the
/// data or stops before the copy.
fn the_walk_steps_over(push: &[u8]) {
    let mut script = push.to_vec();
    script.extend_from_slice(&[0x51, 0x52]);
    let mut expected = push.to_vec();
    expected.push(0x52);
    assert_eq!(
        find_and_delete(&script, &[0x51]),
        expected,
        "{:02x?}",
        &push[..push.len().min(6)]
    );
}

#[test]
fn the_walk_steps_over_a_direct_push_at_75_bytes_and_a_pushdata1_at_76_681() {
    for len in [1, 2, 75] {
        the_walk_steps_over(&push_of(&vec![0x51; len]));
    }
    for len in [76, 77, 255] {
        the_walk_steps_over(&push_of(&vec![0x51; len]));
    }
    // A non-minimal PUSHDATA1 of two bytes, read as the node reads it.
    the_walk_steps_over(&[0x4c, 0x02, 0x51, 0x51]);
}

#[test]
fn the_walk_steps_over_a_pushdata2_at_256_and_65535_bytes_681() {
    for len in [256, 65535] {
        the_walk_steps_over(&push_of(&vec![0x51; len]));
    }
    the_walk_steps_over(&[0x4d, 0x02, 0x00, 0x51, 0x51]);
}

#[test]
fn the_walk_steps_over_a_pushdata4_at_65536_bytes_681() {
    the_walk_steps_over(&push_of(&vec![0x51; 65536]));
    the_walk_steps_over(&[0x4e, 0x02, 0x00, 0x00, 0x00, 0x51, 0x51]);
}

#[test]
fn a_pushdata2_of_0x0100_is_256_bytes_not_1_681() {
    // `ReadLE16` (`script.h:183`): 0x00 0x01 is 256. Read big-endian it is 1,
    // and the walk would delete the data's copies from its second byte on.
    let mut push = vec![0x4d, 0x00, 0x01];
    push.extend_from_slice(&[0x51; 256]);
    the_walk_steps_over(&push);
    let mut push = vec![0x4e, 0x00, 0x01, 0x00, 0x00];
    push.extend_from_slice(&[0x51; 256]);
    the_walk_steps_over(&push);
}

#[test]
fn a_one_byte_push_cut_short_at_the_last_byte_is_kept_681() {
    // `GetOp2` fails on the push (`script.h:189-190`), the walk ends and the
    // bytes from it on are kept (`:217-220`).
    assert_eq!(find_and_delete(&[0x51, 0x01], &[0x51]), [0x01]);
    assert_eq!(find_and_delete(&[0x51, 0x4c], &[0x51]), [0x4c]);
}

#[test]
fn a_copy_after_two_instructions_is_deleted_by_a_walk_that_advances_681() {
    // The walk reaches the copy only by advancing; a walker that returns its
    // own position, or one behind it, is ended by the bound and answers
    // another script, never a hang (#681).
    assert_eq!(find_and_delete(&[0x52, 0x53, 0x51], &[0x51]), [0x52, 0x53]);
    assert_eq!(
        find_and_delete(&[0x52, 0x53, 0x51, 0x54], &[0x51]),
        [0x52, 0x53, 0x54]
    );
}

#[test]
fn the_bound_never_cuts_short_a_walk_of_one_byte_steps_681() {
    // The longest walks the bound admits: every byte a copy, and every byte
    // an instruction with the copy last.
    assert_eq!(find_and_delete(&[0x51; 64], &[0x51]), Vec::<u8>::new());
    let mut script = vec![0x52; 64];
    script.push(0x51);
    assert_eq!(find_and_delete(&script, &[0x51]), vec![0x52; 64]);
    assert_eq!(find_and_delete(&[0x00; 9], &[0x00]), Vec::<u8>::new());
}
