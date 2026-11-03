#![cfg(test)]

//! The key's point at the two signature sites (#660), in the library's own
//! tests so the nightly's scope reaches them (#681): the encoding check reads
//! the length and the prefix alone, a key that is no point is the signature
//! check's false, never a refusal, under every word and in the default mode.
//! The node at `879fc8b`: `IsCompressedOrUncompressedPubKey`
//! (`src/script/interpreter.cpp:132-152`) behind `CheckPubKeyEncoding`
//! (`:312-317`, `SCRIPT_ERR_PUBKEYTYPE`), reached at `:1465` and `:1611`; the
//! point read by `CPubKey::Verify`'s `secp256k1_ec_pubkey_parse`
//! (`src/pubkey.cpp:183-194`), a false check.

use crate::primitives::from_hex;
use crate::script::evaluation_error::ScriptEvaluationError;
use crate::script::flags::{ProtocolEra, ScriptFlags};
use crate::script::op::{OP_1, OP_CHECKMULTISIG, OP_CHECKSIG, OP_NOT};
use crate::script::spend::{Spend, SpendParams};
use crate::script::{LockingScript, Script, UnlockingScript};

const P: &str = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
const P_MINUS_1: &str = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e";
const P1: &str = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30";
const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const X5: &str = "0000000000000000000000000000000000000000000000000000000000000005";
const GX: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const GY: &str = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
const GY1: &str = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b9";

/// The default mode, then the block and the standard word at both eras.
fn modes() -> Vec<(&'static str, Option<(ScriptFlags, bool)>)> {
    let mut modes = vec![("default", None)];
    for (name, era) in [
        ("post-genesis", ProtocolEra::PostGenesis),
        ("post-chronicle", ProtocolEra::PostChronicle),
    ] {
        let chronicle = era == ProtocolEra::PostChronicle;
        modes.push((name, Some((ScriptFlags::block(era), chronicle))));
        modes.push((name, Some((ScriptFlags::standard(era), chronicle))));
    }
    modes
}

fn spend(unlock: &Script, lock: &Script, word: Option<(ScriptFlags, bool)>, version: i32) -> Spend {
    let mut spend = Spend::new(SpendParams {
        source_txid: [7u8; 32],
        source_output_index: 0,
        source_satoshis: 1000,
        locking_script: LockingScript::from_binary(&lock.to_binary()).unwrap(),
        transaction_version: version,
        other_inputs: vec![],
        outputs: vec![],
        input_index: 0,
        unlocking_script: UnlockingScript::from_binary(&unlock.to_binary()).unwrap(),
        input_sequence: u32::MAX,
        lock_time: 0,
        memory_limit: None,
        work_limit: None,
    });
    if let Some((word, chronicle)) = word {
        spend.set_flags(word);
        spend.set_utxo_after_chronicle(chronicle);
    }
    spend
}

/// `<key> OP_CHECKSIG OP_NOT` and `OP_1 <key> OP_1 OP_CHECKMULTISIG OP_NOT`,
/// each under an empty signature (NULLFAIL's one allowed failing signature).
fn both_sites(key: &[u8]) -> [(Script, Script); 2] {
    let mut checksig = Script::new();
    checksig
        .write_bin(key)
        .write_opcode(OP_CHECKSIG)
        .write_opcode(OP_NOT);
    let mut multisig = Script::new();
    multisig
        .write_opcode(OP_1)
        .write_bin(key)
        .write_opcode(OP_1)
        .write_opcode(OP_CHECKMULTISIG)
        .write_opcode(OP_NOT);
    let mut one = Script::new();
    one.write_bin(&[]);
    let mut two = Script::new();
    two.write_bin(&[]).write_bin(&[]);
    [(one, checksig), (two, multisig)]
}

fn run(
    key: &[u8],
    word: Option<(ScriptFlags, bool)>,
    version: i32,
) -> [Result<bool, ScriptEvaluationError>; 2] {
    both_sites(key).map(|(unlock, lock)| spend(&unlock, &lock, word, version).validate())
}

/// Kills `&&` to `||` in `check_public_key_point` and `reads_the_reference_point`
/// to `true` (#681): either refuses at the encoding check the keys below that
/// the reference's `fromDER` cannot read (`02||0`, `02||p-1`, `03||5`,
/// `03||p`, the uncompressed ones), where the node's encoding check passes
/// them on length and prefix and its signature check answers false, so the
/// spend is valid.
#[test]
fn a_key_that_is_no_point_passes_the_encoding_check_and_checks_false_in_every_mode_681() {
    let non_points = [
        // 0^3 + 7 = 7 and (p-1)^3 + 7 = 6 are no square mod p.
        format!("02{ZERO}"),
        format!("02{P_MINUS_1}"),
        format!("03{X5}"),
        format!("03{P}"),
        // A point to a reader reducing mod p (x = 1, 8 a square), not to the node.
        format!("03{P1}"),
        format!("04{GX}{GY1}"),
        format!("04{P}{GY}"),
    ];
    for key in non_points {
        let bytes = from_hex(&key).unwrap();
        for (mode, word) in modes() {
            for version in [1, 2] {
                let [checksig, multisig] = run(&bytes, word, version);
                assert!(
                    matches!(checksig, Ok(true)),
                    "CHECKSIG {key} | {mode} v{version}: {checksig:?}"
                );
                assert!(
                    matches!(multisig, Ok(true)),
                    "CHECKMULTISIG {key} | {mode} v{version}: {multisig:?}"
                );
            }
        }
    }
}

/// Kills `reads_the_reference_point` to `true` (#681) at `signature_key`
/// alone: `03||p+1` passes both readings' encoding check, and the reference's
/// reading reduces x to 1, a point, where the node's `secp256k1_ec_pubkey_parse`
/// refuses x at or past p (the documenting line: the switch's rustdoc,
/// "`false` is the node's reading in every mode", and `src/script/CLAUDE.md`'s
/// `key_point.rs` row). The control `02||G.x` is a key to both.
#[test]
fn an_x_past_the_field_prime_is_no_signature_key_in_every_mode_681() {
    let past = from_hex(&format!("03{P1}")).unwrap();
    let generator = from_hex(&format!("02{GX}")).unwrap();
    let (unlock, lock) = &both_sites(&past)[0];
    for (mode, word) in modes() {
        for version in [1, 2] {
            let spend = spend(unlock, lock, word, version);
            assert!(
                spend.check_public_key_point(&past).is_ok(),
                "{mode} v{version}"
            );
            assert!(spend.signature_key(&past).is_none(), "{mode} v{version}");
            assert!(
                spend.signature_key(&generator).is_some(),
                "{mode} v{version}"
            );
        }
    }
}

/// The issue's reading (#681), the error class beside the verdict: a key of
/// the wrong length or prefix is refused at the encoding check, an error of
/// the script's own class (no resource limit), where a false check would have
/// left `OP_NOT` valid. The node's `IsCompressedOrUncompressedPubKey`
/// (`interpreter.cpp:132-152`); this crate's reading in every mode. These
/// keys never reach `check_public_key_point` (`check_public_key_encoding`
/// refuses them before it), so this pin kills none of `key_point.rs`'s
/// mutants: its `Ok(())` replacement is a stated equivalence candidate.
#[test]
fn a_wrong_length_or_prefix_is_refused_as_the_scripts_error_in_every_mode_681() {
    let wrong = [format!("04{GX}"), format!("02{GX}{GY}"), GX.to_string()];
    for key in wrong {
        let bytes = from_hex(&key).unwrap();
        for (mode, word) in modes() {
            for version in [1, 2] {
                for result in run(&bytes, word, version) {
                    let error = result.expect_err(&format!("{key} | {mode} v{version}"));
                    assert_eq!(error.resource_limit, None, "{key} | {mode} v{version}");
                }
            }
        }
    }
}
