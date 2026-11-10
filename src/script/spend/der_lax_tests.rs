//! `der_lax::parse` branch by branch against `ecdsa_signature_parse_der_lax`
//! (bitcoin-sv v1.2.2 `src/pubkey.cpp:32-175`), the expected values read from
//! the node's code at each cited line.

use super::{parse, ORDER};

fn one(v: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[31] = v;
    out
}

const ZERO: ([u8; 32], [u8; 32]) = ([0; 32], [0; 32]);

#[test]
fn the_tags_and_lengths_the_node_returns_zero_on() {
    // `:41-46`, `:48-51`, `:62-65`, `:67-71`, `:95-97`, `:102-105`, `:107-111`, `:135-137`
    for input in [
        &[][..],
        &[0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],
        &[0x30],
        &[0x30, 0x06, 0x03, 0x01, 0x01, 0x02, 0x01, 0x01],
        &[0x30, 0x06, 0x02],
        &[0x30, 0x06, 0x02, 0x05, 0x01],
        &[0x30, 0x06, 0x02, 0x01, 0x01, 0x03, 0x01, 0x01],
        &[0x30, 0x06, 0x02, 0x01, 0x01, 0x02],
        &[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x02, 0x01],
        // a long-form sequence length whose count runs past the input (`:54-58`)
        &[0x30, 0x85, 0x00],
        // a long-form R length of eight bytes after its zeros (`:83-85`)
        &[0x30, 0x00, 0x02, 0x88, 1, 0, 0, 0, 0, 0, 0, 0],
        // a long-form R length whose count runs past the input (`:76-78`)
        &[0x30, 0x00, 0x02, 0x82, 0x00],
        // a long-form R length past the bytes left (`:95-97`)
        &[0x30, 0x00, 0x02, 0x81, 0x09, 0x01],
    ] {
        assert_eq!(parse(input), None, "{input:02x?}");
    }
}

#[test]
fn the_sequence_length_is_skipped_and_bytes_after_s_are_ignored() {
    // `:48-60`: any short length, a long form of any count within the input.
    for seq in [
        vec![0x30, 0x00],
        vec![0x30, 0x7f],
        vec![0x30, 0x80],
        vec![0x30, 0x82, 0xff, 0xff],
    ] {
        let mut input = seq;
        input.extend_from_slice(&[0x02, 0x01, 0x05, 0x02, 0x01, 0x07, 0xaa, 0xbb]);
        assert_eq!(parse(&input), Some((one(5), one(7))), "{input:02x?}");
    }
}

#[test]
fn long_form_integer_lengths_and_padding_are_read() {
    // `:74-91`: `81 01`, `82 00 01`, `80` (a count of none: length 0).
    assert_eq!(
        parse(&[0x30, 0x00, 0x02, 0x81, 0x01, 0x05, 0x02, 0x82, 0x00, 0x01, 0x07]),
        Some((one(5), one(7)))
    );
    assert_eq!(
        parse(&[0x30, 0x00, 0x02, 0x80, 0x02, 0x01, 0x07]),
        Some(([0; 32], one(7)))
    );
    // `:139-162`: leading zeros ignored, a negative byte read as its magnitude.
    assert_eq!(
        parse(&[0x30, 0x00, 0x02, 0x03, 0x00, 0x00, 0x05, 0x02, 0x01, 0x87]),
        Some((one(5), one(0x87)))
    );
    // A lone zero and an empty integer are zero, not an overflow.
    assert_eq!(
        parse(&[0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x00]),
        Some((one(5), [0; 32]))
    );
    assert_eq!(
        parse(&[0x30, 0x05, 0x02, 0x00, 0x02, 0x01, 0x07]),
        Some(([0; 32], one(7)))
    );
}

#[test]
fn a_value_past_32_bytes_or_at_the_order_is_the_all_zero_signature() {
    // `:146-150`, `:159-163`: 33 bytes after the zeros overflow; 33 with a
    // leading zero do not.
    let mut r33 = vec![0x01];
    r33.extend_from_slice(&[0x11; 32]);
    let mut input = vec![0x30, 0x00, 0x02, 33];
    input.extend_from_slice(&r33);
    input.extend_from_slice(&[0x02, 0x01, 0x07]);
    assert_eq!(parse(&input), Some(ZERO));
    let mut padded = vec![0x30, 0x00, 0x02, 34, 0x00];
    padded.extend_from_slice(&r33);
    padded.extend_from_slice(&[0x02, 0x01, 0x07]);
    assert_eq!(parse(&padded), Some(ZERO));
    let mut s33 = vec![0x30, 0x00, 0x02, 0x01, 0x05, 0x02, 33];
    s33.extend_from_slice(&r33);
    assert_eq!(parse(&s33), Some(ZERO));
    let mut fits = vec![0x30, 0x00, 0x02, 33, 0x00];
    fits.extend_from_slice(&[0x11; 32]);
    fits.extend_from_slice(&[0x02, 0x01, 0x07]);
    assert_eq!(parse(&fits), Some(([0x11; 32], one(7))));
    // `:165-167`: R or S at the order overflows; one below does not.
    for (r, s, zero) in [
        (ORDER, one(1), true),
        (one(1), ORDER, true),
        (
            {
                let mut below = ORDER;
                below[31] -= 1;
                below
            },
            one(1),
            false,
        ),
    ] {
        let mut input = vec![0x30, 0x00, 0x02, 33, 0x00];
        input.extend_from_slice(&r);
        input.extend_from_slice(&[0x02, 33, 0x00]);
        input.extend_from_slice(&s);
        assert_eq!(parse(&input), Some(if zero { ZERO } else { (r, s) }));
    }
}

#[test]
fn no_input_panics() {
    // Every prefix and single-byte change of a long-form signature.
    let base = [
        0x30, 0x81, 0x09, 0x02, 0x82, 0x00, 0x01, 0x05, 0x02, 0x01, 0x07, 0xaa,
    ];
    for cut in 0..=base.len() {
        let _ = parse(&base[..cut]);
        for at in 0..cut {
            for b in [0x00, 0x7f, 0x80, 0x81, 0x88, 0xff] {
                let mut v = base[..cut].to_vec();
                v[at] = b;
                let _ = parse(&v);
            }
        }
    }
}
