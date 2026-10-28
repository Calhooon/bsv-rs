//! #429: the SDK default verifies a no-FORKID signature over the original
//! digest; an explicit word retains the node's mandatory FORKID check.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::script::{LockingScript, ScriptFlags, Spend, SpendParams, UnlockingScript};
use serde::Deserialize;

#[derive(Deserialize)]
struct Recording {
    reference: String,
    node: String,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Case {
    name: String,
    version: i32,
    mode: String,
    scope: u32,
    unlock: String,
    lock: String,
    signed_digest: String,
    original_digest: String,
    bip143_digest: String,
    valid: Option<bool>,
    error: Option<String>,
}

fn recording() -> Recording {
    let r: Recording =
        serde_json::from_str(include_str!("vectors/script_forkid_gate_429.json")).unwrap();
    assert_eq!(
        r.reference,
        "ts-stack@edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9"
    );
    assert_eq!(r.node, "v22.18.0");
    assert_eq!(r.cases.len(), 12);
    r
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

fn default_case(version: i32, digest: &str) {
    let r = recording();
    let c = r
        .cases
        .iter()
        .find(|c| c.version == version && c.mode == "default" && c.signed_digest == digest)
        .unwrap();
    assert_eq!(c.scope, 0x01);
    assert_ne!(c.original_digest, c.bip143_digest);
    let result = spend(c).validate();
    if digest == "original" {
        assert_eq!(c.valid, Some(true));
        assert_eq!(result.map_err(|e| e.message), Ok(true), "{}", c.name);
    } else {
        let error = result.unwrap_err();
        assert!(!error.is_resource_limit());
        assert_eq!(
            error.message,
            "The top stack element must be truthy after script evaluation."
        );
        assert_eq!(
            error.to_string().lines().next(),
            c.error.as_deref(),
            "{}",
            c.name
        );
    }
}

#[test]
fn issue_429_default_version_1_accepts_no_forkid_over_the_original_digest() {
    default_case(1, "original");
}

#[test]
fn issue_429_default_version_1_refuses_the_wrong_digest_in_reference_words() {
    default_case(1, "bip143");
}

#[test]
fn issue_429_default_version_2_also_uses_the_original_digest_without_forkid() {
    default_case(2, "original");
    default_case(2, "bip143");
}

#[test]
fn issue_429_a_word_requires_forkid_in_both_versions_even_without_explicit_strictenc() {
    for c in recording().cases.iter().filter(|c| c.mode != "default") {
        let mut s = spend(c);
        let mut word =
            ScriptFlags::GENESIS | ScriptFlags::UTXO_AFTER_GENESIS | ScriptFlags::SIGHASH_FORKID;
        if c.mode == "forkid-strict-word" {
            word |= ScriptFlags::STRICTENC;
            assert_eq!(
                c.error.as_deref(),
                Some("Script evaluation error: The signature format is invalid.")
            );
        }
        s.set_flags(word);
        let error = s.validate().unwrap_err();
        assert!(!error.is_resource_limit());
        assert_eq!(
            error.message, "The signature must use SIGHASH_FORKID.",
            "{}",
            c.name
        );
    }
}

#[test]
fn issue_429_both_sdk_pins_agree_without_a_word_but_differ_on_implied_strictenc() {
    let sdk: Recording =
        serde_json::from_str(include_str!("vectors/script_forkid_gate_429_ts_sdk.json")).unwrap();
    assert_eq!(
        sdk.reference,
        "ts-sdk@9e3ede6b6302480005259ca36cbc73d9b6509d53"
    );
    assert_eq!(sdk.node, "v22.18.0");
    assert_eq!(sdk.cases.len(), 12);
    for (stack, sdk) in recording().cases.iter().zip(&sdk.cases) {
        assert_eq!(stack.name, sdk.name);
        assert_eq!(stack.unlock, sdk.unlock);
        if stack.mode == "forkid-implied-word" {
            assert_eq!(
                sdk.error.as_deref(),
                Some("Script evaluation error: The signature format is invalid.")
            );
        } else {
            assert_eq!(stack.valid, sdk.valid, "{}", stack.name);
            assert_eq!(stack.error, sdk.error, "{}", stack.name);
        }
    }
}
