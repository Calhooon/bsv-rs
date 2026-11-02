//! #660, the adversarial read: the key shapes and spend forms the lane's file
//! (`tests/pubkey_encoding_660.rs`) does not build, each against the node's
//! verdict derived from bitcoin-sv v1.2.3 (`6504a3a`):
//!
//! - `CheckPubKeyEncoding` (`interpreter.cpp:312-327`) under STRICTENC, which
//!   every word carries (`standard.h:55-68`), reads `IsCompressedOrUncompressedPubKey`
//!   (`:132-152`): length at least 33, `04` at 65, `02`/`03` at 33, any other
//!   prefix refused (`SCRIPT_ERR_PUBKEYTYPE`).
//! - `CheckSignatureEncoding` (`:265-310`) runs before it at both sites
//!   (`:1459-1469`, `:1605-1615`).
//! - `CheckSig` (`:2133-2163`): `CPubKey::IsValid` is the length and prefix
//!   again (`pubkey.h:54-78,157`), then `CPubKey::Verify` (`pubkey.cpp:183-194`)
//!   answers false when `secp256k1_ec_pubkey_parse` refuses: a coordinate at or
//!   past p (`secp256k1_fe_set_b32_limit`), an x with no square root, a 65-byte
//!   point off the curve. libsecp256k1 never reduces a coordinate modulo p.
//! - NULLFAIL (`:1491-1497`, `:1641-1646`) under `EnforceNonMalleability`
//!   (`:40-44`, relaxed by Chronicle at version 2); the VERIFY refusals
//!   (`SCRIPT_ERR_CHECKSIGVERIFY`, `SCRIPT_ERR_CHECKMULTISIGVERIFY`) after it.
//!
//! Which x have a square root and which point has y = 1 are computed with
//! Euler's criterion and a cube root modulo p; the derivation is in the file's
//! comments at each constant.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::primitives::bsv::sighash::{
    compute_sighash_dispatched_for_signing, SighashParams, TxInput,
};
use bsv_rs::primitives::ec::{PrivateKey, PublicKey};
use bsv_rs::primitives::from_hex;
use bsv_rs::script::op::{
    OP_0, OP_1, OP_2, OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY, OP_CHECKSIG, OP_CHECKSIGVERIFY,
    OP_NOT,
};
use bsv_rs::script::{
    LockingScript, ProtocolEra, Script, ScriptFlags, Spend, SpendParams, UnlockingScript,
};

const P: &str = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
const P_MINUS_1: &str = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e";
const P1: &str = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30";
const MAX: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const ONE: &str = "0000000000000000000000000000000000000000000000000000000000000001";
const X5: &str = "0000000000000000000000000000000000000000000000000000000000000005";
const GX: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
// G.y is even, so `06||G.x||G.y` is the hybrid form libsecp256k1 would parse.
const GY: &str = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
const GY1: &str = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b9";
// The x whose point has y = 1: x^3 = 1 - 7 (mod p), the cube root of -6 by
// (p-1)/3's inverse of 3. So `04||X_Y1||(p+1)` is on the curve once y is
// reduced, and refused by libsecp256k1 because y >= p.
const X_Y1: &str = "1fe1e5ef3fceb5c135ab7741333ce5a6e80d68167653f6b2b24bcbcfaaaff507";
// Strict DER, low S (r = 1, s = 1), ALL|FORKID: verifies against no key.
const SIG: &str = "300602010102010141";
// Not DER (the sequence length 7 over 6 bytes): refused by
// `IsValidSignatureEncoding` (`SCRIPT_ERR_SIG_DER`).
const BAD_SIG: &str = "300702010102010141";

const MODES: [&str; 5] = [
    "default",
    "block-post-genesis",
    "standard-post-genesis",
    "block-post-chronicle",
    "standard-post-chronicle",
];

/// Keys that pass the node's encoding check and are no point to
/// `secp256k1_ec_pubkey_parse`, with whether a reader reducing mod p (the
/// reference's `fromDER`, this crate's `PublicKey::from_hex`) reads a point.
fn non_points() -> Vec<(&'static str, String, bool)> {
    vec![
        // 0^3 + 7 = 7 is no square mod p.
        ("02||0", format!("02{ZERO}"), false),
        // (p-1)^3 + 7 = 6 is no square mod p.
        ("02||p-1", format!("02{P_MINUS_1}"), false),
        ("03||5", format!("03{X5}"), false),
        ("03||p", format!("03{P}"), false),
        // p+1 reduces to x = 1, and 8 is a square: a point to a reducing reader.
        ("03||p+1", format!("03{P1}"), true),
        ("03||max", format!("03{MAX}"), true),
        ("04||G.x||G.y+1", format!("04{GX}{GY1}"), false),
        ("04||5||G.y", format!("04{X5}{GY}"), false),
        ("04||p||G.y", format!("04{P}{GY}"), false),
        ("04||max||1", format!("04{MAX}{ONE}"), false),
        ("04||G.x||p", format!("04{GX}{P}"), false),
        ("04||G.x||max", format!("04{GX}{MAX}"), false),
        ("04||x(y=1)||p+1", format!("04{X_Y1}{P1}"), true),
        ("04||0||0", format!("04{ZERO}{ZERO}"), false),
    ]
}

/// Points both libsecp256k1 and this crate read: every on-curve x with both
/// parity bytes, and the uncompressed y = 1 point.
fn points() -> Vec<(&'static str, String)> {
    vec![
        ("02||G.x", format!("02{GX}")),
        ("03||G.x", format!("03{GX}")),
        ("02||1", format!("02{ONE}")),
        ("03||1", format!("03{ONE}")),
        ("04||G.x||G.y", format!("04{GX}{GY}")),
        ("04||x(y=1)||1", format!("04{X_Y1}{ONE}")),
    ]
}

/// Wrong length or prefix: the node refuses each under every word at
/// `IsCompressedOrUncompressedPubKey` (`SCRIPT_ERR_PUBKEYTYPE`); this crate's
/// words, the same in the default mode (the contract: TS's mode runs the
/// encoding check too).
fn wrong_encodings() -> Vec<(&'static str, String, &'static str)> {
    let unknown = "The public key is in an unknown format.";
    let short = "The public key is too short, it must be at least 33 bytes.";
    vec![
        ("empty", String::new(), "Public key is empty."),
        // One byte (0x00 to 0x10 push minimally as an opcode, not a key).
        ("one byte ff", "ff".into(), short),
        ("32 bytes", GX.into(), short),
        ("06||G.x||G.y", format!("06{GX}{GY}"), unknown),
        ("07||G.x||G.y", format!("07{GX}{GY}"), unknown),
        ("65 zeros", format!("00{ZERO}{ZERO}"), unknown),
        (
            "33-byte 04",
            format!("04{GX}"),
            "The non-compressed public key must be 65 bytes.",
        ),
        (
            "34-byte 04",
            format!("04{GX}00"),
            "The non-compressed public key must be 65 bytes.",
        ),
        (
            "65-byte 02",
            format!("02{GX}{GY}"),
            "The compressed public key must be 33 bytes.",
        ),
        (
            "34-byte 02",
            format!("02{GX}00"),
            "The compressed public key must be 33 bytes.",
        ),
        (
            "34-byte 03",
            format!("03{GX}00"),
            "The compressed public key must be 33 bytes.",
        ),
    ]
}

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

/// NULLFAIL enforced: a word, and not Chronicle's version-2 relaxation.
fn null_fail(mode: &str, version: i32) -> bool {
    mode != "default" && !(mode.ends_with("post-chronicle") && version >= 2)
}

/// A signature by `key` over `lock` as the whole scriptCode, ALL|FORKID.
fn sign(key: &PrivateKey, lock: &str, version: i32) -> Vec<u8> {
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
        subscript: &from_hex(lock).unwrap(),
        satoshis: 1000,
        scope: 0x41,
    });
    let mut sig = key.sign(&digest).unwrap().to_der();
    sig.push(0x41);
    sig
}

fn push(bytes: &[u8]) -> String {
    Script::new().write_bin(bytes).to_hex()
}

/// The point reader the signature check uses refuses every non-point the
/// node's parser refuses, reduction or not, and reads every point it reads.
#[test]
fn the_signature_key_reads_a_point_as_libsecp256k1_parses_it_660_adv() {
    for (name, key, reduced_is_point) in non_points() {
        let bytes = from_hex(&key).unwrap();
        assert!(PublicKey::from_bytes(&bytes).is_err(), "{name}");
        // A reducing reader would see a point in these; the node does not.
        assert_eq!(
            PublicKey::from_hex(&key).is_ok(),
            reduced_is_point,
            "{name}"
        );
    }
    for (name, key) in points() {
        assert!(
            PublicKey::from_bytes(&from_hex(&key).unwrap()).is_ok(),
            "{name}"
        );
    }
}

/// Every non-point in eight spend forms, five modes, two versions: the
/// node's verdict at each cell.
#[test]
fn a_non_point_key_in_every_spend_form_reads_as_the_node_660_adv() {
    let empty = Script::new().write_opcode(OP_0).to_hex();
    let der = push(&from_hex(SIG).unwrap());
    let mut cells = 0;
    for (name, key, _) in non_points() {
        let k = from_hex(&key).unwrap();
        let checksig_not = Script::new()
            .write_bin(&k)
            .write_opcode(OP_CHECKSIG)
            .write_opcode(OP_NOT)
            .to_hex();
        let multisig_not = Script::new()
            .write_opcode(OP_1)
            .write_bin(&k)
            .write_opcode(OP_1)
            .write_opcode(OP_CHECKMULTISIG)
            .write_opcode(OP_NOT)
            .to_hex();
        let checksigverify = Script::new()
            .write_bin(&k)
            .write_opcode(OP_CHECKSIGVERIFY)
            .write_opcode(OP_1)
            .to_hex();
        let multisigverify = Script::new()
            .write_opcode(OP_1)
            .write_bin(&k)
            .write_opcode(OP_1)
            .write_opcode(OP_CHECKMULTISIGVERIFY)
            .write_opcode(OP_1)
            .to_hex();
        let dummy_empty = format!("00{empty}");
        let dummy_der = format!("00{der}");
        for mode in MODES {
            for version in [1, 2] {
                let nf = null_fail(mode, version);
                let at = |form: &str| format!("{name} | {form} | {mode} v{version}");
                let csv = "OP_CHECKSIGVERIFY requires that a valid signature is provided.";
                let cmsv = "OP_CHECKMULTISIGVERIFY requires that a sufficient number of valid signatures are provided.";
                let want: [(&str, &str, &str, Result<bool, String>); 8] = [
                    ("checksig-not-empty", &empty, &checksig_not, Ok(true)),
                    (
                        "checksig-not-der",
                        &der,
                        &checksig_not,
                        if nf {
                            Err("OP_CHECKSIG requires failing signatures to be empty.".into())
                        } else {
                            Ok(true)
                        },
                    ),
                    ("multisig-not-empty", &dummy_empty, &multisig_not, Ok(true)),
                    (
                        "multisig-not-der",
                        &dummy_der,
                        &multisig_not,
                        if nf {
                            Err("OP_CHECKMULTISIG requires failing signatures to be empty.".into())
                        } else {
                            Ok(true)
                        },
                    ),
                    (
                        "checksigverify-empty",
                        &empty,
                        &checksigverify,
                        Err(csv.into()),
                    ),
                    (
                        "checksigverify-der",
                        &der,
                        &checksigverify,
                        Err(if nf {
                            "OP_CHECKSIGVERIFY requires failing signatures to be empty.".into()
                        } else {
                            csv.into()
                        }),
                    ),
                    (
                        "multisigverify-empty",
                        &dummy_empty,
                        &multisigverify,
                        Err(cmsv.into()),
                    ),
                    (
                        "multisigverify-der",
                        &dummy_der,
                        &multisigverify,
                        Err(if nf {
                            "OP_CHECKMULTISIGVERIFY requires failing signatures to be empty.".into()
                        } else {
                            cmsv.into()
                        }),
                    ),
                ];
                for (form, unlock, lock, verdict) in want {
                    assert_eq!(run(unlock, lock, mode, version), verdict, "{}", at(form));
                    cells += 1;
                }
            }
        }
    }
    assert_eq!(cells, 14 * 8 * 5 * 2);
}

/// A non-point key among valid ones in a CHECKMULTISIG: the node checks it,
/// gets false, moves on (`interpreter.cpp:1605-1636`).
#[test]
fn a_non_point_among_valid_multisig_keys_is_a_failed_check_and_the_algorithm_moves_on_660_adv() {
    let good = PrivateKey::from_hex(&format!("{:064x}", 7)).unwrap();
    let good_pub = good.public_key().to_compressed();
    for (name, key, _) in non_points() {
        let bad = from_hex(&key).unwrap();
        for mode in MODES {
            for version in [1, 2] {
                let at = format!("{name} | {mode} v{version}");
                // 1-of-2, the non-point pushed last and so checked before the
                // good key (the node's ikey from the top): false, then true.
                let lock = Script::new()
                    .write_opcode(OP_1)
                    .write_bin(&good_pub)
                    .write_bin(&bad)
                    .write_opcode(OP_2)
                    .write_opcode(OP_CHECKMULTISIG)
                    .to_hex();
                let unlock = format!("00{}", push(&sign(&good, &lock, version)));
                assert_eq!(run(&unlock, &lock, mode, version), Ok(true), "1-of-2 {at}");

                // 2-of-2 with the non-point: the threshold cannot be met. The
                // top signature (empty) is checked against the non-point,
                // false, and the loop exits; NULLFAIL reads every signature,
                // the unchecked valid one non-empty.
                let lock = Script::new()
                    .write_opcode(OP_2)
                    .write_bin(&good_pub)
                    .write_bin(&bad)
                    .write_opcode(OP_2)
                    .write_opcode(OP_CHECKMULTISIG)
                    .write_opcode(OP_NOT)
                    .to_hex();
                let unlock = format!("00{}00", push(&sign(&good, &lock, version)));
                let want = if null_fail(mode, version) {
                    Err("OP_CHECKMULTISIG requires failing signatures to be empty.".into())
                } else {
                    Ok(true)
                };
                assert_eq!(run(&unlock, &lock, mode, version), want, "2-of-2 {at}");
                // Every signature empty: false, no NULLFAIL, NOT valid.
                assert_eq!(
                    run("000000", &lock, mode, version),
                    Ok(true),
                    "2-of-2 empty {at}"
                );
            }
        }
    }
}

/// The node checks the signature's encoding before the key's at both sites:
/// a bad DER signature with a non-point or a wrong-length key is refused in
/// the signature's words.
#[test]
fn a_bad_signature_encoding_is_refused_before_the_key_is_read_660_adv() {
    let bad_sig = push(&from_hex(BAD_SIG).unwrap());
    let keys = [
        format!("02{ZERO}"),
        format!("04{GX}{GY1}"),
        "0202".to_string(),
        format!("06{GX}{GY}"),
    ];
    for key in &keys {
        let k = from_hex(key).unwrap();
        let checksig = Script::new()
            .write_bin(&k)
            .write_opcode(OP_CHECKSIG)
            .write_opcode(OP_NOT)
            .to_hex();
        let multisig = Script::new()
            .write_opcode(OP_1)
            .write_bin(&k)
            .write_opcode(OP_1)
            .write_opcode(OP_CHECKMULTISIG)
            .write_opcode(OP_NOT)
            .to_hex();
        for mode in MODES {
            for version in [1, 2] {
                let at = format!("{key} | {mode} v{version}");
                assert_eq!(
                    run(&bad_sig, &checksig, mode, version),
                    Err("The signature format is invalid.".into()),
                    "{at}"
                );
                // The CHECKMULTISIG wrapper names neither (this crate's
                // words since before #660): the verdict, refused, is the node's.
                assert_eq!(
                    run(&format!("00{bad_sig}"), &multisig, mode, version),
                    Err("OP_CHECKMULTISIG requires correct encoding for the public key and signature.".into()),
                    "{at}"
                );
            }
        }
    }
}

/// A wrong length or prefix, the hybrid `06`/`07` included (a point to
/// libsecp256k1, refused at the prefix under STRICTENC): refused in every
/// mode with an empty signature, at CHECKSIG and at CHECKMULTISIG.
#[test]
fn a_wrong_length_or_prefix_is_refused_at_the_encoding_check_in_every_mode_660_adv() {
    for (name, key, words) in wrong_encodings() {
        let k = from_hex(&key).unwrap();
        let checksig = Script::new()
            .write_bin(&k)
            .write_opcode(OP_CHECKSIG)
            .write_opcode(OP_NOT)
            .to_hex();
        let multisig = Script::new()
            .write_opcode(OP_1)
            .write_bin(&k)
            .write_opcode(OP_1)
            .write_opcode(OP_CHECKMULTISIG)
            .write_opcode(OP_NOT)
            .to_hex();
        for mode in MODES {
            for version in [1, 2] {
                let at = format!("{name} | {mode} v{version}");
                assert_eq!(
                    run("00", &checksig, mode, version),
                    Err(words.into()),
                    "{at}"
                );
                assert_eq!(
                    run("0000", &multisig, mode, version),
                    Err("OP_CHECKMULTISIG requires correct encoding for the public key and signature.".into()),
                    "{at}"
                );
            }
        }
    }
}

/// The control: every on-curve x has both parities. `03||G.x` is -G, the
/// key of n-1; its signature verifies, and the key of 1's does not.
#[test]
fn both_parities_of_an_on_curve_x_are_points_and_verify_their_own_key_660_adv() {
    let n_minus_1 = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140";
    let neg = PrivateKey::from_hex(n_minus_1).unwrap();
    assert_eq!(hex(&neg.public_key().to_compressed()), format!("03{GX}"));
    let one = PrivateKey::from_hex(ONE).unwrap();
    assert_eq!(hex(&one.public_key().to_compressed()), format!("02{GX}"));
    let lock = Script::new()
        .write_bin(&from_hex(&format!("03{GX}")).unwrap())
        .write_opcode(OP_CHECKSIG)
        .to_hex();
    for mode in MODES {
        for version in [1, 2] {
            let at = format!("{mode} v{version}");
            assert_eq!(
                run(&push(&sign(&neg, &lock, version)), &lock, mode, version),
                Ok(true),
                "{at}"
            );
            let wrong = run(&push(&sign(&one, &lock, version)), &lock, mode, version);
            if null_fail(mode, version) {
                assert_eq!(
                    wrong,
                    Err("OP_CHECKSIG requires failing signatures to be empty.".into()),
                    "{at}"
                );
            } else {
                assert_eq!(
                    wrong,
                    Err("The top stack element must be truthy after script evaluation.".into()),
                    "{at}"
                );
            }
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
