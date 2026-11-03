//! #657: a badly encoded public key (and a badly encoded signature) is
//! refused at both signature sites in the reference's words. The reference's
//! `Spend` throws from `#checkSignatureEncoding` and `#checkPublicKeyEncoding`
//! (`ts-stack@edf6e03` `Spend.ts:606-629`, `:687-718`), so its CHECKMULTISIG
//! wrapper sentence (`:1813`) is never reached; the node returns the helper's
//! own error at both sites too (`bitcoin-sv` v1.2.3 `interpreter.cpp:1465`,
//! `:1611`, `SCRIPT_ERR_PUBKEYTYPE`). Recorded under Node 22 by
//! `support/pubkey_words_657.mjs`; every script rebuilt by this crate's writer.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::primitives::{from_hex, to_hex};
use bsv_rs::script::{LockingScript, Script, ScriptFlags, Spend, SpendParams, UnlockingScript};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Recording {
    reference: String,
    node: String,
    field_prime: String,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    mode: String,
    version: i32,
    flags: Option<Vec<String>>,
    opcode: String,
    /// The public key's bytes as pushed (hex).
    point: String,
    sig: String,
    lock: String,
    unlock: String,
    valid: Option<bool>,
    error: Option<String>,
}

/// The one shape both sides refuse in other words: a compressed key whose x
/// is the field prime plus one. The reference reduces x modulo p
/// (`Point.ts:365-367`), passes the encoding check and fails the signature;
/// this crate's `PublicKey::from_bytes` refuses the key (#183's residue).
const READ_OTHERWISE: &str = "compressed-x-p-plus-1";

fn recording() -> Recording {
    let r: Recording = serde_json::from_str(include_str!("vectors/pubkey_words_657.json")).unwrap();
    assert_eq!(
        r.reference,
        "ts-stack@edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9"
    );
    assert_eq!(r.node, "v22.18.0");
    assert_eq!(r.cases.len(), 348);
    r
}

fn opcode(name: &str) -> u8 {
    match name {
        "OP_CHECKSIG" => 0xac,
        "OP_CHECKSIGVERIFY" => 0xad,
        "OP_CHECKMULTISIG" => 0xae,
        "OP_CHECKMULTISIGVERIFY" => 0xaf,
        other => panic!("{other}"),
    }
}

/// The recorded scripts, rebuilt by this crate's writer.
fn scripts(c: &Case) -> (LockingScript, UnlockingScript) {
    let op = opcode(&c.opcode);
    let multisig = op == 0xae || op == 0xaf;
    let mut lock = Script::new();
    if multisig {
        lock.write_opcode(0x51);
    }
    lock.write_bin(&from_hex(&c.point).unwrap());
    if multisig {
        lock.write_opcode(0x51);
    }
    lock.write_opcode(op);
    if op == 0xad || op == 0xaf {
        lock.write_opcode(0x51);
    }
    let mut unlock = Script::new();
    if multisig {
        unlock.write_opcode(0x00);
    }
    unlock.write_bin(&from_hex(&c.sig).unwrap());
    assert_eq!(to_hex(&lock.to_binary()), c.lock, "{}", c.name);
    assert_eq!(to_hex(&unlock.to_binary()), c.unlock, "{}", c.name);
    (LockingScript::from(lock), UnlockingScript::from(unlock))
}

fn run(c: &Case) -> Result<bool, String> {
    assert!(c.name.starts_with(&c.mode), "{}", c.name);
    let (locking_script, unlocking_script) = scripts(c);
    let mut spend = Spend::new(SpendParams {
        source_txid: [0; 32],
        source_output_index: 0,
        source_satoshis: 1,
        locking_script,
        transaction_version: c.version,
        other_inputs: vec![],
        outputs: vec![],
        input_index: 0,
        unlocking_script,
        input_sequence: u32::MAX,
        lock_time: 0,
        memory_limit: None,
        work_limit: None,
    });
    if let Some(flags) = &c.flags {
        spend.set_flags(ScriptFlags::from_names(flags.iter().map(String::as_str)).unwrap());
    }
    spend.validate().map_err(|e| {
        assert!(!e.is_resource_limit(), "{}", c.name);
        e.message
    })
}

fn want(c: &Case) -> Result<bool, String> {
    match (&c.valid, &c.error) {
        (Some(valid), None) => Ok(*valid),
        (None, Some(error)) => Err(error
            .strip_prefix("Script evaluation error: ")
            .unwrap()
            .to_owned()),
        _ => panic!("{}", c.name),
    }
}

fn key_shape(c: &Case) -> &str {
    c.name.split('/').nth(2).unwrap()
}

fn multisig(c: &Case) -> bool {
    c.opcode.starts_with("OP_CHECKMULTISIG")
}

#[test]
fn a_badly_encoded_public_key_at_checkmultisig_is_refused_in_the_reference_words_657() {
    let r = recording();
    let mut judged = 0;
    for c in r.cases.iter().filter(|c| {
        multisig(c)
            && c.sig != "3006020101020141"
            && !key_shape(c).ends_with("-control")
            && key_shape(c) != READ_OTHERWISE
    }) {
        let words = want(c).unwrap_err();
        assert!(!words.starts_with("OP_CHECKMULTISIG"), "{}", c.name);
        assert_eq!(run(c), Err(words), "{}", c.name);
        judged += 1;
    }
    // Ten bad key shapes, two signatures, two opcodes, three modes.
    assert_eq!(judged, 120);
}

#[test]
fn a_badly_encoded_signature_at_checkmultisig_is_refused_in_the_reference_words_657() {
    let r = recording();
    let mut judged = 0;
    for c in r
        .cases
        .iter()
        .filter(|c| multisig(c) && c.sig == "3006020101020141")
    {
        // The signature is judged before the key, as on both references.
        assert_eq!(
            want(c),
            Err("The signature format is invalid.".to_owned()),
            "{}",
            c.name
        );
        assert_eq!(run(c), want(c), "{}", c.name);
        judged += 1;
    }
    assert_eq!(judged, 18);
}

#[test]
fn checksig_already_refuses_in_the_reference_words_657() {
    let r = recording();
    let mut judged = 0;
    for c in r
        .cases
        .iter()
        .filter(|c| !multisig(c) && key_shape(c) != READ_OTHERWISE)
    {
        assert_eq!(run(c), want(c), "{}", c.name);
        judged += 1;
    }
    assert_eq!(judged, 162);
}

#[test]
fn every_recorded_case_is_judged_as_the_reference_judges_it_save_one_shape_657() {
    let r = recording();
    assert_eq!(
        r.field_prime,
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
    );
    let mut otherwise = 0;
    for c in &r.cases {
        if key_shape(c) == READ_OTHERWISE {
            // Both refuse; the reference after the signature check, here at
            // the key's encoding.
            assert!(want(c).is_err(), "{}", c.name);
            assert_eq!(
                run(c),
                Err("The public key is in an unknown format.".to_owned()),
                "{}",
                c.name
            );
            otherwise += 1;
        } else {
            assert_eq!(run(c), want(c), "{}", c.name);
        }
    }
    assert_eq!(otherwise, 24);
}
