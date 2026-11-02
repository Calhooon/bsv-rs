//! #660: the public key encoding check reads a key's length and prefix byte
//! alone, as the node's `CheckPubKeyEncoding` does under STRICTENC (bitcoin-sv
//! v1.2.3 `interpreter.cpp:132-152,312-327`); a key whose point is off the
//! curve, or whose x is at or past p, passes it and fails the signature check
//! (`CheckSig`, `interpreter.cpp:2133-2163`; `CPubKey::Verify` failing
//! `secp256k1_ec_pubkey_parse`, `pubkey.cpp:183-194`). With an empty signature
//! no NULLFAIL applies (`interpreter.cpp:1491-1497,1641-1646`), so `<key>
//! OP_CHECKSIG OP_NOT` and its CHECKMULTISIG form are valid there. Until #660
//! this crate refused 120 such spends under the words at its encoding check.
//!
//! The vector `tests/vectors/pubkey_encoding_660.json` carries the cells this
//! file's writer builds, the node's verdict derived from its code, the sibling's
//! Lean evaluator's verdict under each word and the reference's under its
//! default (`ts-stack@edf6e03` under Node 22), recorded by
//! `tests/support/pubkey_encoding_660.mjs` from the cells
//! `record_the_cells_660` writes.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::primitives::bsv::sighash::{
    compute_sighash_dispatched_for_signing, SighashParams, TxInput,
};
use bsv_rs::primitives::ec::PrivateKey;
use bsv_rs::primitives::from_hex;
use bsv_rs::script::op::{OP_0, OP_1, OP_CHECKMULTISIG, OP_CHECKSIG, OP_NOT};
use bsv_rs::script::{
    LockingScript, ProtocolEra, Script, ScriptFlags, Spend, SpendParams, UnlockingScript,
};
use serde::Deserialize;

const P: &str = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
const P1: &str = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30";
const MAX: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
const GX: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
// G.y + 1: off the curve.
const GY1: &str = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b9";
const X5: &str = "0000000000000000000000000000000000000000000000000000000000000005";
// A strict-DER, low-S signature (r = 1, s = 1) with ALL|FORKID: it verifies
// against no key.
const SIG: &str = "300602010102010141";
const NULLFAIL: [&str; 2] = [
    "OP_CHECKSIG requires failing signatures to be empty.",
    "OP_CHECKMULTISIG requires failing signatures to be empty.",
];

/// The points: the control on the curve, then the six the node's encoding
/// check passes and its signature check fails.
fn points() -> Vec<(&'static str, String)> {
    vec![
        ("02||G.x", format!("02{GX}")),
        ("02||5", format!("02{X5}")),
        ("03||5", format!("03{X5}")),
        ("02||p", format!("02{P}")),
        ("02||p+1", format!("02{P1}")),
        ("03||max", format!("03{MAX}")),
        ("04||G.x||G.y+1", format!("04{GX}{GY1}")),
    ]
}

/// The four shapes, by this crate's writer: (name, unlock, lock).
fn shapes(point: &str) -> Vec<(&'static str, String, String)> {
    let key = from_hex(point).unwrap();
    let sig = from_hex(SIG).unwrap();
    let checksig = Script::new()
        .write_bin(&key)
        .write_opcode(OP_CHECKSIG)
        .write_opcode(OP_NOT)
        .to_hex();
    let multisig = Script::new()
        .write_opcode(OP_1)
        .write_bin(&key)
        .write_opcode(OP_1)
        .write_opcode(OP_CHECKMULTISIG)
        .write_opcode(OP_NOT)
        .to_hex();
    let empty = Script::new().write_opcode(OP_0).to_hex();
    let der = Script::new().write_bin(&sig).to_hex();
    let dummy_empty = Script::new().write_opcode(OP_0).write_opcode(OP_0).to_hex();
    let dummy_der = Script::new().write_opcode(OP_0).write_bin(&sig).to_hex();
    vec![
        ("checksig-not-empty", empty, checksig.clone()),
        ("checksig-not-der", der, checksig),
        ("checkmultisig-not-empty", dummy_empty, multisig.clone()),
        ("checkmultisig-not-der", dummy_der, multisig),
    ]
}

const MODES: [&str; 5] = [
    "default",
    "block-post-genesis",
    "standard-post-genesis",
    "block-post-chronicle",
    "standard-post-chronicle",
];

fn spend(unlock: &str, lock: &str, mode: &str, version: i32) -> Spend {
    let mut spend = Spend::new(SpendParams {
        source_txid: [7u8; 32],
        source_output_index: 0,
        source_satoshis: 1000,
        locking_script: LockingScript::from_hex(lock).unwrap(),
        transaction_version: version,
        other_inputs: vec![],
        outputs: vec![],
        input_index: 0,
        unlocking_script: UnlockingScript::from_hex(unlock).unwrap(),
        input_sequence: u32::MAX,
        lock_time: 0,
        memory_limit: None,
        work_limit: None,
    });
    if mode != "default" {
        let era = if mode.ends_with("post-chronicle") {
            ProtocolEra::PostChronicle
        } else {
            ProtocolEra::PostGenesis
        };
        let word = if mode.starts_with("block") {
            ScriptFlags::block(era)
        } else {
            ScriptFlags::standard(era)
        };
        spend.set_flags(word);
        spend.set_utxo_after_chronicle(era == ProtocolEra::PostChronicle);
    }
    spend
}

fn run(unlock: &str, lock: &str, mode: &str, version: i32) -> Result<bool, String> {
    spend(unlock, lock, mode, version)
        .validate()
        .map_err(|e| e.message)
}

/// The node's verdict, derived from its code: the empty signature always
/// valid; a non-empty one fails NULLFAIL unless Chronicle relaxes it for a
/// version-2 transaction (`interpreter.cpp:40-44`). `None` in the default.
fn node_valid(shape: &str, mode: &str, version: i32) -> Option<bool> {
    if mode == "default" {
        return None;
    }
    if shape.ends_with("empty") {
        return Some(true);
    }
    Some(mode.ends_with("post-chronicle") && version >= 2)
}

/// The default mode's verdict under the reading `key_point.rs` selects: the
/// node's, so every cell is valid (no NULLFAIL without a word). A fold to the
/// reference's reading changes this function: an off-curve point refused in
/// `The public key is in an unknown format.` (the CHECKMULTISIG form in its
/// own wrapper's words), the others valid.
fn default_valid(_point: &str, _shape: &str) -> Result<bool, String> {
    Ok(true)
}

#[test]
fn an_off_curve_or_over_range_key_fails_the_signature_check_not_the_encoding_check_660() {
    let mut cells = 0;
    let mut valid = 0;
    for (name, point) in points().into_iter().skip(1) {
        for (shape, unlock, lock) in shapes(&point) {
            for mode in &MODES[1..] {
                for version in [1, 2] {
                    let got = run(&unlock, &lock, mode, version);
                    let want = node_valid(shape, mode, version).unwrap();
                    let at = format!("{name} | {shape} | {mode} v{version}");
                    if want {
                        assert_eq!(got, Ok(true), "{at}");
                        valid += 1;
                    } else {
                        let words = got.expect_err(&at);
                        assert!(NULLFAIL.contains(&words.as_str()), "{at}: {words}");
                    }
                    cells += 1;
                }
            }
        }
    }
    assert_eq!((cells, valid), (192, 120));
}

#[test]
fn the_default_mode_reads_the_point_as_the_node_reads_it_660() {
    for (name, point) in points() {
        for (shape, unlock, lock) in shapes(&point) {
            for version in [1, 2] {
                assert_eq!(
                    run(&unlock, &lock, "default", version),
                    default_valid(name, shape),
                    "{name} | {shape} | v{version}"
                );
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Vector {
    reference: String,
    node: String,
    spec: String,
    cells: Vec<Cell>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Cell {
    name: String,
    point: String,
    shape: String,
    unlock: String,
    lock: String,
    mode: String,
    version: i32,
    node_valid: Option<bool>,
    lean: Option<String>,
    lean_error: Option<String>,
    reference_valid: Option<bool>,
    reference_error: Option<String>,
}

fn vector() -> Vector {
    let v: Vector = serde_json::from_str(include_str!("vectors/pubkey_encoding_660.json")).unwrap();
    assert_eq!(
        v.reference,
        "ts-stack@edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9"
    );
    assert_eq!(v.node, "v22.18.0");
    assert_eq!(v.spec, "spec@387dab35");
    assert_eq!(v.cells.len(), 280);
    v
}

#[test]
fn the_vector_carries_this_crates_cells_and_the_lean_agrees_with_the_node_660() {
    let mut expected = Vec::new();
    for (name, point) in points() {
        for (shape, unlock, lock) in shapes(&point) {
            for mode in MODES {
                for version in [1, 2] {
                    expected.push((
                        name,
                        point.clone(),
                        shape,
                        unlock.clone(),
                        lock.clone(),
                        mode,
                        version,
                    ));
                }
            }
        }
    }
    let v = vector();
    for (c, e) in v.cells.iter().zip(&expected) {
        let at = format!("{} | {} | {} v{}", c.name, c.shape, c.mode, c.version);
        assert_eq!(
            (
                c.name.as_str(),
                &c.point,
                c.shape.as_str(),
                &c.unlock,
                &c.lock,
                c.mode.as_str(),
                c.version
            ),
            (e.0, &e.1, e.2, &e.3, &e.4, e.5, e.6),
            "{at}"
        );
        assert_eq!(
            c.node_valid,
            node_valid(&c.shape, &c.mode, c.version),
            "{at}"
        );
        let got = run(&c.unlock, &c.lock, &c.mode, c.version);
        if c.mode == "default" {
            assert_eq!((&c.lean, &c.lean_error), (&None, &None), "{at}");
            continue;
        }
        assert_eq!(
            (&c.reference_valid, &c.reference_error),
            (&None, &None),
            "{at}"
        );
        let lean_valid = c.lean.as_deref() == Some("valid");
        assert_eq!(
            Some(lean_valid),
            c.node_valid,
            "{at}: the Lean against the node"
        );
        assert_eq!(got.is_ok(), lean_valid, "{at}: {got:?}");
        if !lean_valid {
            assert_eq!(
                c.lean_error.as_deref(),
                Some("SCRIPT_ERR_SIG_NULLFAIL"),
                "{at}"
            );
            assert!(NULLFAIL.contains(&got.unwrap_err().as_str()), "{at}");
        }
    }
}

/// The reference's default refuses an off-curve point at its encoding check
/// (`Spend.ts:711-715`) and reduces an x at or past p (`Point.ts:365-367`);
/// the node's reading accepts both spends. The divergence, pinned so it
/// cannot move unseen: the off-curve cells alone.
#[test]
fn the_reference_default_refuses_an_off_curve_point_a_stated_divergence_660() {
    let mut differ = Vec::new();
    let v = vector();
    for c in v.cells.iter().filter(|c| c.mode == "default") {
        let reference = match (c.reference_valid, &c.reference_error) {
            (Some(valid), None) => Ok(valid),
            (None, Some(words)) => Err(words.clone()),
            other => panic!("{other:?}"),
        };
        let got = run(&c.unlock, &c.lock, &c.mode, c.version);
        if got != reference {
            assert_eq!(
                reference,
                Err("Script evaluation error: The public key is in an unknown format.".into()),
                "{} | {}",
                c.name,
                c.shape
            );
            differ.push(c.name.as_str());
        }
    }
    differ.dedup();
    assert_eq!(differ, ["02||5", "03||5", "02||p", "04||G.x||G.y+1"]);
}

/// The refusals the encoding check keeps, in their words, in every mode.
#[test]
fn a_wrong_length_or_prefix_is_still_refused_at_the_encoding_check_660() {
    let cases = [
        ("", "Public key is empty."),
        (
            "0202",
            "The public key is too short, it must be at least 33 bytes.",
        ),
        (
            &format!("02{GX}00")[..],
            "The compressed public key must be 33 bytes.",
        ),
        (
            &format!("04{GX}")[..],
            "The non-compressed public key must be 65 bytes.",
        ),
        (
            &format!("05{GX}")[..],
            "The public key is in an unknown format.",
        ),
        (
            &format!("06{GX}{GY1}")[..],
            "The public key is in an unknown format.",
        ),
    ];
    for (point, words) in cases {
        let lock = Script::new()
            .write_bin(&from_hex(point).unwrap())
            .write_opcode(OP_CHECKSIG)
            .write_opcode(OP_NOT)
            .to_hex();
        for mode in MODES {
            for version in [1, 2] {
                assert_eq!(
                    run("00", &lock, mode, version),
                    Err(words.to_string()),
                    "{point} | {mode} v{version}"
                );
            }
        }
    }
}

/// The signature check's own pins: a key that parses, its signature valid
/// and a wrong one, unchanged by #660.
#[test]
fn a_key_on_the_curve_verifies_its_signature_and_refuses_a_wrong_one_660() {
    let key = PrivateKey::from_hex(&format!("{:064x}", 7)).unwrap();
    let lock = Script::new()
        .write_bin(&key.public_key().to_compressed())
        .write_opcode(OP_CHECKSIG)
        .to_hex();
    for mode in MODES {
        for version in [1, 2] {
            let digest = compute_sighash_dispatched_for_signing(&SighashParams {
                version,
                inputs: &[TxInput {
                    txid: [7u8; 32],
                    output_index: 0,
                    script: vec![],
                    sequence: u32::MAX,
                }],
                outputs: &[],
                locktime: 0,
                input_index: 0,
                subscript: &from_hex(&lock).unwrap(),
                satoshis: 1000,
                scope: 0x41,
            });
            let mut sig = key.sign(&digest).unwrap().to_der();
            sig.push(0x41);
            let unlock = Script::new().write_bin(&sig).to_hex();
            assert_eq!(
                run(&unlock, &lock, mode, version),
                Ok(true),
                "{mode} v{version}"
            );
            let wrong = Script::new().write_bin(&from_hex(SIG).unwrap()).to_hex();
            let got = run(&wrong, &lock, mode, version);
            // NULLFAIL under a word, relaxed by Chronicle at version 2.
            if mode == "default" || (mode.ends_with("post-chronicle") && version >= 2) {
                let falsy = "The top stack element must be truthy after script evaluation.";
                assert_eq!(got, Err(falsy.into()), "{mode} v{version}");
            } else {
                assert_eq!(got, Err(NULLFAIL[0].into()), "{mode} v{version}");
            }
        }
    }
}

/// Writes the cells the recorder reads to `$PUBKEY_ENCODING_660_CELLS`:
/// `cargo test --test pubkey_encoding_660 -- --ignored record_the_cells_660`.
#[test]
#[ignore = "a recorder: writes the cells for tests/support/pubkey_encoding_660.mjs"]
fn record_the_cells_660() {
    let mut cells = Vec::new();
    for (name, point) in points() {
        for (shape, unlock, lock) in shapes(&point) {
            for mode in MODES {
                for version in [1, 2] {
                    cells.push(serde_json::json!({
                        "name": name, "point": point, "shape": shape, "unlock": unlock,
                        "lock": lock, "mode": mode, "version": version,
                        "nodeValid": node_valid(shape, mode, version),
                    }));
                }
            }
        }
    }
    let path = std::env::var("PUBKEY_ENCODING_660_CELLS").unwrap();
    std::fs::write(path, serde_json::to_string(&cells).unwrap()).unwrap();
    assert_eq!(cells.len(), 280);
}
