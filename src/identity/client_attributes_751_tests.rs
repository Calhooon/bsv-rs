#![cfg(test)]
//! #751's unit pin: every case of `tests/vectors/identity_attributes_751.json`
//! (recorded by `tests/support/identity_attributes_751.mjs`, the reference's
//! `filterCertificatesByAttributes` at `ts-stack@edf6e03` under Node
//! v22.18.0) judged by [`keeps`] to the reference's kept indices.
#![allow(clippy::expect_used)]

use super::keeps;
use indexmap::IndexMap;

fn pairs(value: &serde_json::Value) -> IndexMap<String, String> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|pair| Some((pair[0].as_str()?.to_string(), pair[1].as_str()?.to_string())))
        .collect()
}

#[test]
fn every_recorded_attribute_case_keeps_the_references_certificates_751() {
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../tests/vectors/identity_attributes_751.json"
    ))
    .expect("the vector parses");
    let cases = vector["cases"].as_array().expect("cases");
    assert_eq!(cases.len(), 42, "the recorded cases");
    let mut wrong = Vec::new();
    for case in cases {
        let attributes = pairs(&case["attributes"]);
        let records = case["records"].as_array().expect("records");
        let kept: Vec<u64> = (0u64..)
            .zip(records)
            .filter(|(_, record)| keeps(&attributes, &pairs(record)))
            .map(|(index, _)| index)
            .collect();
        let expected: Vec<u64> = case["kept"]
            .as_array()
            .expect("kept")
            .iter()
            .filter_map(serde_json::Value::as_u64)
            .collect();
        if kept != expected {
            wrong.push(format!(
                "{}: {kept:?} where the reference keeps {expected:?}",
                case["name"]
            ));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}
