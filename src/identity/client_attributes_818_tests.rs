#![cfg(test)]
//! #818: three rules of the #751 matcher that no recorded case held (a
//! one-line mutation of each passed every test), each read here by name from
//! the cases `tests/support/identity_attributes_751.mjs` added to
//! `tests/vectors/identity_attributes_751.json` (the reference's
//! `filterCertificatesByAttributes` at `ts-stack@edf6e03` under Node
//! v22.18.0), `kept` the reference's answer:
//! - a repeated token is searched from where the last match ended
//!   (`identityUtils.ts:154-158`, `cursor = found.index + found[0].length`):
//!   `a a` needs two occurrences, so `a` and `ba` are not kept;
//! - U+2029 ends a line as U+2028 does (`:147`), so tokens either side of it
//!   are on two lines;
//! - `Object.entries` walks ahead only a canonical array index (an integer
//!   below 2^32 - 1 in its shortest decimal form): `4294967295`, `01` and
//!   `+1` keep the place they were inserted at.
//!
//! The fold's five (the strength read's S1 to S5: a mutation of each step
//! passed every test above), recorded the same way:
//! - the cursor moves by the token's length (`:156`): `ab bc` is not in `abc`;
//! - a lone CR ends a line and takes no unit after it (`:147`, `\r\n?`);
//! - each line is searched from its start (`:152`, the cursor declared inside
//!   the line's loop);
//! - `4294967294` is an array index, the largest;
//! - two index names are walked in ascending numeric order, `9` before `10`.
#![allow(clippy::expect_used)]

use super::keeps;
use indexmap::IndexMap;
use serde_json::Value;

fn pairs(value: &Value) -> IndexMap<String, String> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|pair| Some((pair[0].as_str()?.to_string(), pair[1].as_str()?.to_string())))
        .collect()
}

/// The recorded case `name`: the indices [`keeps`] keeps, the reference's,
/// and its record count.
fn judged(name: &str) -> (Vec<u64>, Vec<u64>, usize) {
    let vector: Value = serde_json::from_str(include_str!(
        "../../tests/vectors/identity_attributes_751.json"
    ))
    .expect("the vector parses");
    let case = vector["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|case| case["name"] == name)
        .unwrap_or_else(|| panic!("no case {name}"));
    let attributes = pairs(&case["attributes"]);
    let records = case["records"].as_array().expect("records");
    let kept = (0u64..)
        .zip(records)
        .filter(|(_, record)| keeps(&attributes, &pairs(record)))
        .map(|(index, _)| index)
        .collect();
    let expected = case["kept"]
        .as_array()
        .expect("kept")
        .iter()
        .filter_map(Value::as_u64)
        .collect();
    (kept, expected, records.len())
}

#[test]
fn a_repeated_token_needs_a_second_occurrence_818() {
    let (kept, reference, records) = judged("fuzzy_repeated_token");
    // the recording itself discriminates: `a` and `ba` hold one occurrence
    assert_eq!((reference.as_slice(), records), ([1, 2].as_slice(), 4));
    assert_eq!(kept, reference);
}

#[test]
fn a_paragraph_separator_ends_a_line_818() {
    let (kept, reference, records) = judged("fuzzy_paragraph_separator");
    assert_eq!((reference.as_slice(), records), ([1].as_slice(), 2));
    assert_eq!(kept, reference);
}

#[test]
fn a_name_that_is_no_array_index_keeps_its_place_818() {
    // every name judged before the assertion, so each wrong one is named
    let mut wrong = Vec::new();
    for (name, recorded) in [
        ("any_index_name_u32_max", [0].as_slice()),
        ("any_index_name_leading_zero", [0, 1].as_slice()),
        ("any_index_name_plus_sign", [0, 1].as_slice()),
    ] {
        let (kept, reference, records) = judged(name);
        assert_eq!((reference.as_slice(), records), (recorded, 2), "{name}");
        if kept != reference {
            wrong.push(format!(
                "{name}: {kept:?} where the reference keeps {reference:?}"
            ));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

#[test]
fn a_token_moves_the_cursor_by_its_length_818() {
    let (kept, reference, records) = judged("fuzzy_token_longer_than_one_unit");
    // `abc` holds `ab` and `bc` only overlapping
    assert_eq!((reference.as_slice(), records), ([1, 2].as_slice(), 3));
    assert_eq!(kept, reference);
}

#[test]
fn a_lone_carriage_return_ends_a_line_and_takes_nothing_after_it_818() {
    let (kept, reference, records) = judged("fuzzy_lone_carriage_return");
    assert_eq!((reference.as_slice(), records), ([0].as_slice(), 2));
    assert_eq!(kept, reference);
}

#[test]
fn each_line_is_searched_from_its_start_818() {
    let (kept, reference, records) = judged("fuzzy_second_line_from_its_start");
    assert_eq!((reference.as_slice(), records), ([0].as_slice(), 2));
    assert_eq!(kept, reference);
}

#[test]
fn the_largest_array_index_is_walked_ahead_818() {
    let (kept, reference, records) = judged("any_index_name_below_u32_max");
    assert_eq!((reference.as_slice(), records), ([0].as_slice(), 2));
    assert_eq!(kept, reference);
}

#[test]
fn two_index_names_are_walked_in_ascending_numeric_order_818() {
    let (kept, reference, records) = judged("any_two_index_names");
    assert_eq!((reference.as_slice(), records), ([0, 1].as_slice(), 3));
    assert_eq!(kept, reference);
}
