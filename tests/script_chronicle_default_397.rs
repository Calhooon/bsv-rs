//! #397's second fold: all Chronicle opcodes run without a word, while the
//! Chronicle hash type needs transaction version > 1. Recorded from the
//! unmodified ts-stack@edf6e03 under Node 22 by the adjacent support recorder.
//! The keeper requires the hash gate's own words (Spend.ts:591); the reference
//! catches that error at :622-625 and exposes its generic DER error instead.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::primitives::bsv::sighash::{
    compute_sighash_dispatched_for_signing, SighashParams, TxInput,
};
use bsv_rs::primitives::{from_hex, to_hex};
use bsv_rs::script::op::OP_EQUAL;
use bsv_rs::script::{
    LockingScript, ProtocolEra, Script, ScriptFlags, Spend, SpendParams, UnlockingScript,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Recording {
    reference: String,
    node: String,
    opcodes: Vec<Case>,
    signatures: Vec<Case>,
}

#[derive(Clone, Deserialize)]
struct Case {
    name: String,
    version: Option<i32>,
    unlock: String,
    lock: String,
    valid: Option<bool>,
    error: Option<String>,
    stack: Vec<String>,
    digest: Option<String>,
}

fn recording() -> Recording {
    let r: Recording =
        serde_json::from_str(include_str!("vectors/script_chronicle_default_397.json")).unwrap();
    assert_eq!(
        r.reference,
        "ts-stack@edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9"
    );
    assert_eq!(r.node, "v22.18.0");
    r
}

fn spend(c: &Case) -> Spend {
    Spend::new(SpendParams {
        source_txid: [0; 32],
        source_output_index: 0,
        source_satoshis: 1,
        locking_script: LockingScript::from_hex(&c.lock).unwrap(),
        // The Rust API requires a version. JS's missing version bitwise-coerces
        // to zero, covered by the same raw bytes as an explicit zero here.
        transaction_version: c.version.unwrap_or(0),
        other_inputs: vec![],
        outputs: vec![],
        input_index: 0,
        unlocking_script: UnlockingScript::from_hex(&c.unlock).unwrap(),
        input_sequence: u32::MAX,
        lock_time: 0,
        memory_limit: None,
        work_limit: None,
    })
}

fn reference_case(c: &Case) {
    let result = spend(c).validate();
    if let Some(error) = &c.error {
        let got = result.expect_err(&c.name);
        assert!(!got.is_resource_limit());
        assert_eq!(
            got.message,
            error.strip_prefix("Script evaluation error: ").unwrap(),
            "{} v{:?}",
            c.name,
            c.version
        );
        assert_eq!(
            got.stack.iter().map(|v| to_hex(v)).collect::<Vec<_>>(),
            c.stack,
            "{}",
            c.name
        );
    } else {
        assert_eq!(
            result.map_err(|e| e.message),
            Ok(c.valid.unwrap()),
            "{} v{:?}",
            c.name,
            c.version
        );
        if c.digest.is_some() {
            return; // A signature commits to the original locking script.
        }
        // Verify the bytes even when other truthy byte arrays would pass.
        assert_eq!(c.stack.len(), 1);
        let mut lock = Script::from_hex(&c.lock).unwrap();
        push_expected(&mut lock, &from_hex(&c.stack[0]).unwrap());
        lock.write_opcode(OP_EQUAL);
        let mut exact = Case {
            lock: lock.to_hex(),
            ..c.clone()
        };
        exact.stack = vec!["01".into()];
        assert_eq!(
            spend(&exact).validate().map_err(|e| e.message),
            Ok(true),
            "{} bytes",
            c.name
        );
    }
}

fn push_expected(lock: &mut Script, bytes: &[u8]) {
    match bytes {
        [] => {
            lock.write_number(0);
        }
        [n @ 1..=16] => {
            lock.write_number(i64::from(*n));
        }
        [0x81] => {
            lock.write_number(-1);
        }
        _ => {
            lock.write_bin(bytes);
        }
    }
}

fn opcode(name: &str) {
    let cases: Vec<_> = recording()
        .opcodes
        .into_iter()
        .filter(|c| c.name == name || c.name.starts_with(&format!("{name}-")))
        .collect();
    assert!(!cases.is_empty());
    for c in cases {
        reference_case(&c);
    }
}

#[test]
fn issue_397_op_ver_runs_at_every_version_and_pushes_four_raw_bytes() {
    opcode("OP_VER");
}

#[test]
fn issue_397_op_verif_runs_at_version_1_and_compares_exactly_four_bytes() {
    opcode("OP_VERIF");
}

#[test]
fn issue_397_op_vernotif_runs_at_version_1_and_inverts_the_byte_comparison() {
    opcode("OP_VERNOTIF");
}

#[test]
fn issue_397_op_2mul_runs_at_version_1_and_reads_a_script_number() {
    opcode("OP_2MUL");
}

#[test]
fn issue_397_op_2div_runs_at_version_1_and_truncates_toward_zero() {
    opcode("OP_2DIV");
}

/// The reference's visible text: the gate's own words (`Spend.ts:586-591`)
/// are rethrown by the DER wrapper's catch (`:622-625`).
const HASH_GATE: &str = "The signature format is invalid.";

#[test]
fn issue_397_default_chronicle_hash_type_is_invalid_at_version_1_in_the_reference_visible_words() {
    let r = recording();
    let c = r
        .signatures
        .iter()
        .find(|c| c.version == Some(1) && c.name == "CHECKSIG-61")
        .unwrap();
    let recorded = c.error.as_deref().unwrap();
    for era in [None, Some(false), Some(true)] {
        let mut s = spend(c);
        if let Some(after) = era {
            s.set_utxo_after_chronicle(after);
        }
        let error = s.validate().unwrap_err();
        assert!(!error.is_resource_limit());
        assert_eq!(error.message, HASH_GATE);
        assert_eq!(error.to_string().lines().next(), Some(recorded));
    }
}

#[test]
fn default_chronicle_hash_type_is_valid_at_version_2_and_uses_the_original_digest() {
    let r = recording();
    for c in &r.signatures {
        let input = TxInput {
            txid: [0; 32],
            output_index: 0,
            script: vec![],
            sequence: u32::MAX,
        };
        let scope = if c.name == "CHECKSIG-61" { 0x61 } else { 0x41 };
        let digest = compute_sighash_dispatched_for_signing(&SighashParams {
            version: c.version.unwrap(),
            inputs: &[input],
            outputs: &[],
            locktime: 0,
            input_index: 0,
            subscript: &from_hex(&c.lock).unwrap(),
            satoshis: 1,
            scope,
        });
        assert_eq!(to_hex(&digest), c.digest.as_ref().unwrap().as_str());
        if c.error.is_some() {
            continue;
        }
        reference_case(c);
        let mut s = spend(c);
        s.set_utxo_after_chronicle(false);
        assert_eq!(s.validate().map_err(|e| e.message), Ok(true));
    }
}

#[test]
fn under_a_word_the_five_opcode_gates_and_hash_type_bit_are_unchanged() {
    let r = recording();
    for name in [
        "OP_VER",
        "OP_VERIF-equal",
        "OP_VERNOTIF-different",
        "OP_2MUL-positive",
        "OP_2DIV-positive",
    ] {
        let c = r
            .opcodes
            .iter()
            .find(|c| c.name == name && c.version == Some(1))
            .unwrap();
        let mut pre = spend(c);
        pre.set_flags(ScriptFlags::block(ProtocolEra::PostGenesis));
        let message = pre.validate().unwrap_err().message;
        assert!(message.contains("disabled"), "{name}: {message}");
        let mut post = spend(c);
        post.set_flags(ScriptFlags::block(ProtocolEra::PostChronicle));
        assert_eq!(post.validate().map_err(|e| e.message), Ok(true), "{name}");
    }
    for c in r.signatures.iter().filter(|c| c.name == "CHECKSIG-61") {
        let mut pre = spend(c);
        pre.set_flags(ScriptFlags::block(ProtocolEra::PostGenesis));
        assert_eq!(
            pre.validate().unwrap_err().message,
            "The signature must not use SIGHASH_CHRONICLE before Chronicle."
        );
        let mut post = spend(c);
        post.set_flags(ScriptFlags::block(ProtocolEra::PostChronicle));
        post.set_utxo_after_chronicle(false);
        assert_eq!(post.validate().map_err(|e| e.message), Ok(true));
    }
}
