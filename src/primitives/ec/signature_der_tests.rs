#![cfg(test)]

//! `signature_der::read` against the reference's `Signature.fromDER`
//! (`Signature.ts:44-97` at `ts-stack@edf6e03`), cell by cell (#842). The
//! recorded cells are `tests/vectors/signature_der_842.json`, asserted by
//! `tests/signature_der_842.rs`; these name the reader's own branches.

use super::*;

fn words(hex_text: &str) -> &'static str {
    match read(&hex::decode(hex_text).unwrap()) {
        Ok(_) => "ok",
        Err(words) => words,
    }
}

fn integers(hex_text: &str) -> (String, String) {
    let der = hex::decode(hex_text).unwrap();
    let read = read(&der).unwrap();
    (hex::encode(read.r), hex::encode(read.s))
}

#[test]
fn the_empty_input_and_a_lone_byte_take_the_reference_words() {
    assert_eq!(words(""), NOT_A_SEQUENCE);
    assert_eq!(words("31"), NOT_A_SEQUENCE);
    // `getLength` of `undefined` is `undefined`; `undefined + 2` is `NaN`.
    assert_eq!(words("30"), INVALID);
}

#[test]
fn a_sequence_length_other_than_the_bytes_after_it_is_invalid() {
    assert_eq!(words("3006020101020101"), "ok");
    assert_eq!(words("3005020101020101"), INVALID);
    assert_eq!(words("3007020101020101"), INVALID);
    assert_eq!(words("300602010102010100"), INVALID);
}

#[test]
fn every_long_form_length_is_refused_before_the_comparison() {
    assert_eq!(words("3081060201010201"), LONG_FORM_LENGTH);
    assert_eq!(words("300602810101020101"), INVALID);
    assert_eq!(words("3007028101010201010000"), INVALID);
    assert_eq!(words("300702810101020101"), LONG_FORM_LENGTH);
    assert_eq!(words("300702010102810101"), LONG_FORM_LENGTH);
}

#[test]
fn a_read_past_the_end_takes_the_words_of_the_next_check() {
    // R's length missing: the next tag is read at `NaN`.
    assert_eq!(words("300102"), INVALID);
    // R's bytes run past the end: S's tag is `undefined`.
    assert_eq!(words("30020205"), INVALID);
    // S's length missing: the S length check throws.
    assert_eq!(words("3003020002"), S_LENGTH);
    // S's bytes run past the end: the S length check throws.
    assert_eq!(words("300602000203aabb"), S_LENGTH);
    assert_eq!(words("3005020002030a"), S_LENGTH);
}

#[test]
fn a_tag_other_than_an_integer_is_invalid() {
    assert_eq!(words("3006030101020101"), INVALID);
    assert_eq!(words("3006020101030101"), INVALID);
}

#[test]
fn a_zero_is_kept_only_before_a_high_bit_and_r_is_judged_before_s() {
    assert_eq!(integers("30080202008002020080"), ("80".into(), "80".into()));
    assert_eq!(words("3008020200010202007f"), R_PADDED);
    assert_eq!(words("300702010102020001"), S_PADDED);
    assert_eq!(words("3006020100020101"), R_PADDED);
    assert_eq!(words("3006020101020100"), S_PADDED);
}

#[test]
fn an_empty_integer_is_zero_and_the_shortest_signature_is_six_bytes() {
    assert_eq!(integers("300402000200"), (String::new(), String::new()));
    assert_eq!(words("3004020002"), INVALID);
}

#[test]
fn a_negative_and_a_long_integer_are_read_as_given() {
    // No sign rule and no length bound in the reference's reader.
    assert_eq!(integers("3006020180020181"), ("80".into(), "81".into()));
    let long = format!("3026022101{}020101", "00".repeat(32));
    assert_eq!(integers(&long).0, format!("01{}", "00".repeat(32)));
}

/// The length edges of `getLength` (`Signature.ts:45-52`): `0x7f` the last
/// short form, `0x80` the first long form, at the sequence, at R and at S,
/// against the fold's recording (`tests/vectors/script_signature_der_842.json`,
/// `der_lengths`, the reference's `fromDER`). The 129-byte DER whose sequence
/// length is `0x7f` is read whole, R of 61 bytes and S of 62, as the reference
/// reads it (`from_der` then refuses its 32-byte slot, the stated cell).
#[test]
fn the_length_edges_are_read_as_the_reference_reads_them_842() {
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/vectors/script_signature_der_842.json"
    ))
    .unwrap();
    for case in vector["der_lengths"].as_array().unwrap() {
        let der = case["der"].as_str().unwrap();
        let recorded = case["from_der"].as_str().unwrap();
        match recorded.strip_prefix("ERR:") {
            Some(refusal) => assert_eq!(words(der), refusal, "{case}"),
            None => {
                let (r, s) = integers(der);
                // The reference writes `BigNumber.toString(16)`, no leading zero.
                let mut fields = recorded.split(' ').skip(1);
                assert_eq!(Some(r.trim_start_matches('0')), fields.next(), "{case}");
                assert_eq!(Some(s.trim_start_matches('0')), fields.next(), "{case}");
            }
        }
    }
}
