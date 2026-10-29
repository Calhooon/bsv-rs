//! #417: version-1 signature refusals in the reference's visible words.
//! The adjacent Node 22 recorder observes hash-type checks before low-S and
//! records the DER-off word separately: that state has no default-mode API.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::script::{
    LockingScript, ProtocolEra, ScriptFlags, Spend, SpendParams, UnlockingScript,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Recording {
    reference: String,
    node: String,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    version: i32,
    mode: String,
    unlock: String,
    lock: String,
    #[serde(rename = "lowSChecks")]
    low_s_checks: usize,
    valid: Option<bool>,
    error: Option<String>,
}

fn cases() -> Vec<Case> {
    let r: Recording =
        serde_json::from_str(include_str!("vectors/script_signature_words_417.json")).unwrap();
    assert_eq!(
        r.reference,
        "ts-stack@edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9"
    );
    assert_eq!(r.node, "v22.18.0");
    assert_eq!(r.cases.len(), 9);
    r.cases
}

fn case(name: &str) -> Case {
    cases().into_iter().find(|c| c.name == name).unwrap()
}

fn spend(c: &Case) -> Spend {
    Spend::new(SpendParams {
        source_txid: [0; 32],
        source_output_index: 0,
        source_satoshis: 1,
        locking_script: LockingScript::from_hex(&c.lock).unwrap(),
        transaction_version: c.version,
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

fn refusal(name: &str) {
    let c = case(name);
    assert_eq!(c.version, 1);
    assert_eq!(c.mode, "default");
    assert_eq!(
        c.error.as_deref(),
        Some("Script evaluation error: The signature format is invalid.")
    );
    let error = spend(&c).validate().unwrap_err();
    assert!(!error.is_resource_limit());
    assert_eq!(
        error.to_string().lines().next(),
        c.error.as_deref(),
        "{name}"
    );
    assert_eq!(error.message, "The signature format is invalid.");
}

#[test]
fn issue_417_undefined_hash_type_at_version_1_uses_the_reference_visible_words() {
    refusal("undefined-hash-type");
}

#[test]
fn issue_417_high_s_at_version_1_uses_the_reference_visible_words() {
    refusal("high-s");
}

#[test]
fn issue_417_hash_type_before_low_s_uses_the_reference_visible_words() {
    refusal("undefined-hash-type-and-high-s");
}

#[test]
fn issue_417_reference_checks_hash_type_before_calling_the_low_s_predicate() {
    for name in [
        "undefined-hash-type",
        "undefined-hash-type-and-high-s",
        "chronicle-at-version-1",
    ] {
        assert_eq!(case(name).low_s_checks, 0, "{name}");
    }
    assert_eq!(case("high-s").low_s_checks, 1);
}

#[test]
fn issue_417_valid_signatures_and_the_chronicle_refusal_keep_their_verdicts() {
    refusal("chronicle-at-version-1");
    for name in ["defined-low-s", "high-s-at-version-2"] {
        let c = case(name);
        assert_eq!(
            spend(&c).validate().map_err(|e| e.message),
            Ok(c.valid.unwrap()),
            "{name}"
        );
    }
}

#[test]
fn issue_417_a_word_keeps_the_node_low_s_before_hash_type_and_its_words() {
    for (name, message) in [
        (
            "undefined-hash-type",
            "The signature's hash type (0x44) has no defined base type.",
        ),
        ("high-s", "The signature must have a low S value."),
        (
            "undefined-hash-type-and-high-s",
            "The signature must have a low S value.",
        ),
    ] {
        let c = case(name);
        for word in [
            ScriptFlags::block(ProtocolEra::PostChronicle),
            ScriptFlags::standard(ProtocolEra::PostChronicle),
        ] {
            let mut s = spend(&c);
            s.set_flags(word);
            assert_eq!(s.validate().unwrap_err().message, message, "{name}");
        }
    }
}

#[test]
fn issue_417_der_off_requires_a_word_which_this_crate_refuses() {
    for c in cases().iter().filter(|c| c.mode == "der-off") {
        // Neither reference enforces DER with an empty word. Default mode
        // always does; this crate exposes no independent DER-off switch.
        assert_eq!(c.valid, Some(true), "{}", c.name);
        let mut s = spend(c);
        assert_eq!(s.flags(), None);
        for (word, message) in [
            (ScriptFlags::NONE, "Invalid verification flags: SIGHASH_FORKID is not set: a word without it is not implemented by this interpreter (it requires SIGHASH_FORKID, GENESIS and UTXO_AFTER_GENESIS)."),
            (ScriptFlags::SIGHASH_FORKID, "Invalid verification flags: GENESIS is not set: a word without it is not implemented by this interpreter (it requires SIGHASH_FORKID, GENESIS and UTXO_AFTER_GENESIS)."),
            (ScriptFlags::SIGHASH_FORKID | ScriptFlags::GENESIS, "Invalid verification flags: UTXO_AFTER_GENESIS is not set: a word without it is not implemented by this interpreter (it requires SIGHASH_FORKID, GENESIS and UTXO_AFTER_GENESIS)."),
        ] {
            s.set_flags(word);
            let error = s.validate().unwrap_err();
            assert!(!error.is_resource_limit());
            assert_eq!(error.message, message, "{}: {word:?}", c.name);
        }
    }
}
