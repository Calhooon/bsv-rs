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

/// The two shapes #660 states as a divergence (`CHANGELOG.md`'s #660 entry,
/// its parity paragraph; `CLAUDE.md`'s row for #660): a 33- or 65-byte key
/// with the right prefix whose point is off the curve. The reference's
/// `#checkPublicKeyEncoding` parses the point and refuses it
/// (`Spend.ts:687-718`, `The public key is in an unknown format.`, the
/// recorded words, kept as recorded); this crate reads the length and the
/// prefix alone, as the node's `IsCompressedOrUncompressedPubKey` does
/// (`interpreter.cpp:132-152` at v1.2.3), and the signature check answers
/// false (`pubkey.cpp:183-194`): the node's verdict, the control key's with
/// the same signature. The vector's one shape at or past p, `02` with x = p + 1,
/// is no longer read otherwise: the reference reduces x and fails the
/// signature, this crate fails the signature, so the verdict and the words
/// are the reference's on all 24 of its cases (#183's residue closed by #660).
/// The claim is bounded by the vector: it carries no signature made for the
/// reduced point (x = 1), which the reference verifies and this crate fails
/// (k256 refuses x at or past p), the #660 entry's stated divergence.
const NODE_READ_660: [&str; 2] = ["compressed-off-curve", "uncompressed-off-curve"];

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

fn node_read_660(c: &Case) -> bool {
    NODE_READ_660.contains(&key_shape(c))
}

/// The node's verdict on a #660 shape: the recorded verdict of the control
/// key of the same form, with the same signature, mode and opcode (the
/// signature verifies for neither key), never a refusal at the encoding check.
fn assert_the_node_verdict_660(r: &Recording, c: &Case) {
    assert_eq!(
        want(c),
        Err("The public key is in an unknown format.".to_owned()),
        "{}",
        c.name
    );
    let control_name = c.name.replace("-off-curve", "-control");
    let control = r.cases.iter().find(|k| k.name == control_name).unwrap();
    assert_eq!(control.sig, c.sig, "{}", c.name);
    let got = run(c);
    assert_ne!(
        got,
        Err("The public key is in an unknown format.".to_owned()),
        "{}",
        c.name
    );
    assert_eq!(got, want(control), "{}", c.name);
}

#[test]
fn a_badly_encoded_public_key_at_checkmultisig_is_refused_in_the_reference_words_657() {
    let r = recording();
    let (mut judged, mut node_read) = (0, 0);
    for c in r.cases.iter().filter(|c| {
        multisig(c)
            && c.sig != "3006020101020141"
            && !key_shape(c).ends_with("-control")
            && key_shape(c) != "compressed-x-p-plus-1"
    }) {
        if node_read_660(c) {
            assert_the_node_verdict_660(&r, c);
            node_read += 1;
            continue;
        }
        let words = want(c).unwrap_err();
        assert!(!words.starts_with("OP_CHECKMULTISIG"), "{}", c.name);
        assert_eq!(run(c), Err(words), "{}", c.name);
        judged += 1;
    }
    // Eight bad key shapes, two signatures, two opcodes, three modes; the
    // two off-curve shapes the node's verdict (#660).
    assert_eq!(judged, 96);
    assert_eq!(node_read, 24);
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
    let (mut judged, mut node_read) = (0, 0);
    for c in r.cases.iter().filter(|c| !multisig(c)) {
        if node_read_660(c) {
            assert_the_node_verdict_660(&r, c);
            node_read += 1;
        } else {
            assert_eq!(run(c), want(c), "{}", c.name);
            judged += 1;
        }
    }
    // x = p + 1 among the judged since #660 (12 cases).
    assert_eq!(judged, 150);
    assert_eq!(node_read, 24);
}

#[test]
fn every_recorded_case_is_judged_as_the_reference_judges_it_save_the_shapes_660_states_657() {
    let r = recording();
    assert_eq!(
        r.field_prime,
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
    );
    let mut node_read = 0;
    for c in &r.cases {
        if node_read_660(c) {
            assert_the_node_verdict_660(&r, c);
            node_read += 1;
        } else {
            assert_eq!(run(c), want(c), "{}", c.name);
        }
    }
    // Two shapes, two signatures, four opcodes, three modes.
    assert_eq!(node_read, 48);
}
