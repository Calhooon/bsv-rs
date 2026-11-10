#![cfg(test)]
//! #730: the evidence check's unit pins. Each BEEF of
//! `tests/vectors/identity_evidence_730.json` rebuilt by this crate's writer
//! (`tests/support/identity_evidence_730.rs`) to the recorded SHA-256 and
//! judged by [`parse_evidence`] to the reference `parseEvidence`'s code and
//! line (`ts-stack@edf6e03` `TransactionEvidence.ts`, recorded under Node
//! v22.18.0 by `tests/support/identity_evidence_730.mjs`), or to its
//! selected txid; the #725 and #728 vectors' shapes the same, by the line
//! their `refused_at` names; the `sourceTXID` check (`:145-146`) unreached
//! from bytes on both sides.

use super::*;
use crate as sdk;
use crate::primitives::{from_hex, sha256, to_hex, Writer};

#[path = "../../tests/support/identity_evidence_730.rs"]
mod build;

/// The recorded code, or `None` for a read.
fn code_of(case: &serde_json::Value) -> Option<Code> {
    match case["code"].as_str() {
        None => None,
        Some("invalid-evidence") => Some(Code::InvalidEvidence),
        Some("limit") => Some(Code::Limit),
        Some(other) => panic!("unknown code {other}"),
    }
}

/// `parse_evidence`'s answer as the vector writes it: the code and line, or
/// the selected txid.
fn judged(bytes: &[u8], output_index: u32) -> (Option<Code>, Option<String>, String) {
    match parse_evidence(bytes, output_index) {
        Ok(tx) => (None, None, tx.id()),
        Err(r) => (
            Some(r.code),
            Some(r.site.to_string()),
            format!("refused: Transaction evidence: {}", r.code.as_str()),
        ),
    }
}

#[test]
fn each_730_shape_is_judged_as_the_reference_parse_evidence_judges_it_730() {
    let v = build::vector();
    let shapes = v["shapes"].as_array().unwrap();
    assert_eq!(shapes.len(), 12);
    for case in shapes {
        let name = case["name"].as_str().unwrap();
        let size = case["size"].as_u64().map(|n| n as usize);
        let built = build::build(name, size);
        assert_eq!(
            (built.beef.len() as u64, to_hex(&sha256(&built.beef))),
            (
                case["beef_bytes"].as_u64().unwrap(),
                case["beef_sha256"].as_str().unwrap().to_string()
            ),
            "{name}: this crate's writer and the reference's recorded bytes"
        );
        assert_eq!(
            built.subject,
            case["subject_txid"].as_str().unwrap(),
            "{name}"
        );
        let index = case["output_index"].as_u64().unwrap() as u32;
        let (code, site, selected) = judged(&built.beef, index);
        assert_eq!(code, code_of(case), "{name}: the code");
        assert_eq!(site.as_deref(), case["site"].as_str(), "{name}: the line");
        assert_eq!(selected, case["selected_txid"].as_str().unwrap(), "{name}");
    }
}

/// The #725 and #728 shapes: the line `refused_at` names (the text before
/// its second colon) and the selected txid, at each shape's index.
#[test]
fn the_725_and_728_shapes_are_judged_at_the_reference_lines_730() {
    for text in [
        include_str!("../../tests/vectors/identity_beef_subject_725.json"),
        include_str!("../../tests/vectors/identity_beef_subject_728.json"),
    ] {
        let v: serde_json::Value = serde_json::from_str(text).unwrap();
        for case in v["shapes"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let bytes = from_hex(case["beef"].as_str().unwrap()).unwrap();
            let index = case["output_index"].as_u64().unwrap_or(0) as u32;
            let (_, site, selected) = judged(&bytes, index);
            let recorded = case["refused_at"]
                .as_str()
                .map(|t| t.splitn(3, ':').take(2).collect::<Vec<_>>().join(":"));
            assert_eq!(site, recorded, "{name}: the line");
            assert_eq!(selected, case["selected_txid"].as_str().unwrap(), "{name}");
        }
    }
}

/// `:145-146` compares an input's `sourceTXID` with its source's id; both
/// SDKs find the source under the txid its bytes hash to, so no BEEF reaches
/// it: the recorder's three script forms keep their index txid equal to the
/// transaction's id there, and here.
#[test]
fn the_source_txid_check_is_unreached_from_bytes_on_both_sides_730() {
    let v = build::vector();
    let probe = &v["source_txid_probe"];
    assert_eq!(probe["reached_from_bytes"], false);
    for form in probe["forms"].as_array().unwrap() {
        let lock = form["locking_script"].as_str().unwrap();
        assert_eq!(
            form["index_txid"], form["transaction_id"],
            "{lock}: the reference"
        );
        let mut writer = Writer::new();
        writer.write_u32_le(1).write_var_int(1);
        writer.write_bytes(&from_hex(&"22".repeat(32)).unwrap());
        writer.write_u32_le(0).write_var_int(1).write_u8(0x51);
        writer
            .write_u32_le(0xffff_ffff)
            .write_var_int(1)
            .write_u64_le(1);
        let script = from_hex(lock).unwrap();
        writer
            .write_var_int(script.len() as u64)
            .write_bytes(&script);
        writer.write_u32_le(0);
        let raw = writer.into_bytes();
        let mut beef = sdk::transaction::Beef::new();
        beef.merge_raw_tx(raw, None)
            .expect("the bytes are one transaction");
        let parsed =
            sdk::transaction::Beef::from_binary(&beef.to_binary().expect("the BEEF is writable"))
                .unwrap();
        let entry = parsed
            .find_txid(form["raw_hash"].as_str().unwrap())
            .unwrap();
        assert_eq!(
            entry.tx().unwrap().id(),
            form["raw_hash"].as_str().unwrap(),
            "{lock}"
        );
    }
}

/// The door: a refused output skipped, a limit the reference's words.
#[test]
fn admit_skips_invalid_evidence_and_refuses_a_limit_in_the_reference_words_730() {
    let v = build::vector();
    for name in ["second_spend_in_graph", "transactions_over_bound"] {
        let case = v["shapes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["name"] == name)
            .unwrap();
        let built = build::build(name, case["size"].as_u64().map(|n| n as usize));
        let output = OutputListItem {
            beef: built.beef,
            output_index: 0,
            context: None,
            txid: None,
        };
        let expected = match case["outcome"].as_str().unwrap() {
            "skipped" => Ok(None),
            words => Err(Error::IdentityError(
                words.trim_start_matches("refused: ").to_string(),
            )),
        };
        assert_eq!(
            admit(&output, &Default::default()).map(|t| t.map(|t| t.id())),
            expected,
            "{name}"
        );
    }
}
