//! #429: re-judge every former missing-FORKID mismatch, plus #417's
//! low-S and undefined-type rows and #397's empty-word Chronicle row.

use super::{corpus_dir, load_json, run_node_script, s, validate_tx_input};
use bsv_rs::script::{ScriptFlags, ScriptFlagsError};
use bsv_rs::transaction::Transaction;
use serde_json::Value;

fn run(input: &Value) -> Result<bool, String> {
    if s(input, "fixture_type") == "node-script" {
        return run_node_script(input);
    }
    let tx = Transaction::from_hex(s(input, "tx_hex")).unwrap();
    let prevouts = input["prevouts"].as_array().unwrap();
    for (vin, txin) in tx.inputs.iter().enumerate() {
        let prevout = prevouts
            .iter()
            .find(|p| {
                Some(s(p, "txid")) == txin.source_txid.as_deref()
                    && p["vout"].as_u64() == Some(u64::from(txin.source_output_index))
            })
            .unwrap();
        validate_tx_input(&tx, vin, prevout)?;
    }
    Ok(true)
}

#[test]
fn issue_429_former_forkid_mismatches_and_empty_word_rows_match_recorded_defaults() {
    let Some(dir) = corpus_dir() else { return };
    let corpus = load_json(&dir.join("vectors/sdk/scripts/evaluation.json"));
    let recording: Value =
        serde_json::from_str(include_str!("../vectors/script_forkid_census_429.json")).unwrap();
    assert_eq!(
        s(&recording, "reference"),
        "ts-stack@edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9"
    );
    assert_eq!(s(&recording, "node"), "v22.18.0");
    let cases = recording["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 66);
    for case in cases {
        let id = s(case, "id");
        let vector = corpus["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| s(v, "id") == id)
            .unwrap();
        let want = match case["default"]["valid"].as_bool() {
            Some(valid) => Ok(valid),
            None if id == "node.tx-valid.shared.0097" => {
                // Rust's existing CHECKMULTISIG wrapper differs from the
                // SDK's DER wrapper. Pin both texts without changing verdicts.
                assert_eq!(
                    s(&case["default"], "error"),
                    "Script evaluation error: The signature format is invalid."
                );
                Err(
                    "OP_CHECKMULTISIG requires correct encoding for the public key and signature."
                        .to_owned(),
                )
            }
            None => Err(s(&case["default"], "error")
                .strip_prefix("Script evaluation error: ")
                .unwrap()
                .to_owned()),
        };
        assert_eq!(
            run(&vector["input"]),
            want,
            "{id}: default verdict and words"
        );
        for word in case["words"].as_array().unwrap() {
            let flags = ScriptFlags::from_names(
                word["flags"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|f| f.as_str().unwrap()),
            )
            .unwrap();
            // These reference words all lack FORKID. Rust refuses them before
            // execution, independently of the reference's recorded verdict.
            assert!(!flags.contains(ScriptFlags::SIGHASH_FORKID), "{id}");
            assert_eq!(
                flags.check(),
                Err(ScriptFlagsError::NotApplicable(
                    "SIGHASH_FORKID is not set: this interpreter requires it in a flag word"
                )),
                "{id}: {flags:?} verdict and words"
            );
        }
    }
}
