//! #842 and its fold (#847): the interpreter reads a signature as its judge
//! does. `Signature::from_der` is the reference's strict reader (#842); the
//! interpreter does not read through it under a word. After the strict
//! encoding check (`is_valid_signature_encoding`, the node's BIP 66
//! `IsValidSignatureEncoding`, bitcoin-sv v1.2.2 `interpreter.cpp:177-245`,
//! run in every mode: every word carries SIGHASH_FORKID and the node then
//! forces STRICTENC, `:2315-2318`), a signature is read
//!
//! - under a word by the node's lax parse, ported whole
//!   (`src/script/spend/der_lax.rs`, `ecdsa_signature_parse_der_lax`,
//!   `pubkey.cpp:32-175`), the reading `CheckLowS` (`:353-363`) and
//!   `CPubKey::Verify` (`:183-214`) give it;
//! - without a word by the reference's `fromDER` (`Spend.ts:606-629` at
//!   `ts-stack@edf6e03`), whose verdicts on these spends are recorded in
//!   `vectors/script_signature_der_842.json` (`support/script_signature_der_842.mjs`,
//!   Node v22.18.0, two runs byte-identical).
//!
//! The cells: this crate's signer's signature over each lock, and built from
//! it a lone-zero R, a lone-zero S (`02 01 00`: BIP 66 forbids a leading
//! zero only when the length is above 1, `:225-227`, `:238-242`), an R and an
//! S past 32 bytes (`01` before the 32), and the shapes of #842 (bytes after
//! the DER, either wrong sequence length, a long-form length at the
//! sequence, R or S, an unneeded zero before R or S, six bytes), each in the
//! default mode at versions 1 and 2, under `ScriptFlags::block(era)` and
//! `ScriptFlags::standard(era)` of both eras and each era's block word with
//! DERSIG, STRICTENC and LOW_S cleared, at versions 1 and 2.
//!
//! The node's verdict under a word, from its lines:
//! - a shape of #842 fails BIP 66: `SCRIPT_ERR_SIG_DER` at
//!   `CheckSignatureEncoding` (`interpreter.cpp:275-279`), `The signature
//!   format is invalid.` here;
//! - the four integers pass BIP 66; the lax parse reads a lone zero as zero
//!   and a value past 32 bytes as the all-zero signature
//!   (`pubkey.cpp:139-173`), low for `CheckLowS` (`pubkey.cpp:353-363`,
//!   `interpreter.cpp:282-289`); the hash type `0x41` is defined and carries
//!   FORKID (`interpreter.cpp:291-307`); `CheckSig` answers false
//!   (`interpreter.cpp:2133-2163`; secp256k1 verifies no zero scalar);
//!   NULLFAIL then refuses a non-empty failing signature where the word
//!   enforces non-malleability (`interpreter.cpp:1489-1497`, `:1640-1646`;
//!   `EnforceNonMalleability`, `:34-44`: every word here save the
//!   post-Chronicle words at version 2), in this crate's words `<op> requires
//!   failing signatures to be empty.`; at version 2 after Chronicle the false
//!   is pushed: `OP_CHECKSIG` false (`SCRIPT_ERR_EVAL_FALSE`, `:2375`),
//!   `OP_CHECKSIG OP_NOT` valid, the VERIFY forms their own failure
//!   (`SCRIPT_ERR_CHECKSIGVERIFY` at `:1506`, `SCRIPT_ERR_CHECKMULTISIGVERIFY`
//!   at `:1680`).
//!
//! The base `2c464e81` read a lone zero leniently as zero, the node's
//! verdict, and refused an integer past 32 bytes in every mode; `4b3fe10d`
//! (#842 before this fold) refused all four in every mode. After the fold no
//! verdict or word under a word differs from the base save the integers past
//! 32 bytes, where the base was wrong against the node (#847, fixed here).
//! Each test gathers every differing cell before it asserts, so a red run
//! lists them.
#![cfg(feature = "script")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::primitives::bsv::sighash::{
    compute_sighash_dispatched_for_signing, SighashParams, TxInput,
};
use bsv_rs::primitives::ec::PrivateKey;
use bsv_rs::script::op::{
    OP_0, OP_1, OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY, OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_NOT,
};
use bsv_rs::script::{
    LockingScript, ProtocolEra, Script, ScriptFlags, Spend, SpendParams, UnlockingScript,
};

const REFUSED: &str = "The signature format is invalid.";
const FALSE: &str = "The top stack element must be truthy after script evaluation.";
const RECORDED: &str = include_str!("vectors/script_signature_der_842.json");

/// The words: the default mode, both words of both eras, and each era's
/// block word with the three encoding flags cleared (the node forces
/// STRICTENC back).
fn words() -> Vec<(&'static str, ScriptFlags)> {
    let cleared = ScriptFlags::DERSIG
        .union(ScriptFlags::STRICTENC)
        .union(ScriptFlags::LOW_S);
    let mut out = vec![];
    for (name, era) in [
        ("post-genesis", ProtocolEra::PostGenesis),
        ("post-chronicle", ProtocolEra::PostChronicle),
    ] {
        out.push((name, ScriptFlags::block(era)));
        out.push((name, ScriptFlags::standard(era)));
        out.push((name, ScriptFlags::block(era).without(cleared)));
    }
    out
}

fn key() -> PrivateKey {
    PrivateKey::from_bytes(&[0x2b; 32]).unwrap()
}

/// The five locks: the signature opcode, and whether its failure is read
/// through `OP_NOT` or a VERIFY.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Lock {
    Sig,
    SigNot,
    SigVerify,
    MultiSigNot,
    MultiSigVerify,
}

const LOCKS: [Lock; 5] = [
    Lock::Sig,
    Lock::SigNot,
    Lock::SigVerify,
    Lock::MultiSigNot,
    Lock::MultiSigVerify,
];

impl Lock {
    fn script(self) -> String {
        let pubkey = key().public_key().to_compressed();
        let mut s = Script::new();
        match self {
            Lock::Sig | Lock::SigNot | Lock::SigVerify => {
                s.write_bin(&pubkey);
            }
            Lock::MultiSigNot | Lock::MultiSigVerify => {
                s.write_opcode(OP_1).write_bin(&pubkey).write_opcode(OP_1);
            }
        }
        match self {
            Lock::Sig => s.write_opcode(OP_CHECKSIG),
            Lock::SigNot => s.write_opcode(OP_CHECKSIG).write_opcode(OP_NOT),
            Lock::SigVerify => s.write_opcode(OP_CHECKSIGVERIFY).write_opcode(OP_1),
            Lock::MultiSigNot => s.write_opcode(OP_CHECKMULTISIG).write_opcode(OP_NOT),
            Lock::MultiSigVerify => s.write_opcode(OP_CHECKMULTISIGVERIFY).write_opcode(OP_1),
        };
        s.to_hex()
    }

    fn opcode(self) -> &'static str {
        match self {
            Lock::Sig | Lock::SigNot => "OP_CHECKSIG",
            Lock::SigVerify => "OP_CHECKSIGVERIFY",
            Lock::MultiSigNot => "OP_CHECKMULTISIG",
            Lock::MultiSigVerify => "OP_CHECKMULTISIGVERIFY",
        }
    }

    /// The verdict when the signature check answers `true`.
    fn passing(self) -> Result<bool, String> {
        match self {
            Lock::SigNot | Lock::MultiSigNot => Err(FALSE.into()),
            _ => Ok(true),
        }
    }

    /// The verdict when the check answers `false` and NULLFAIL does not
    /// apply.
    fn failing(self) -> Result<bool, String> {
        match self {
            Lock::Sig => Err(FALSE.into()),
            Lock::SigNot | Lock::MultiSigNot => Ok(true),
            Lock::SigVerify => {
                Err("OP_CHECKSIGVERIFY requires that a valid signature is provided.".into())
            }
            Lock::MultiSigVerify => Err(
                "OP_CHECKMULTISIGVERIFY requires that a sufficient number of valid signatures are provided."
                    .into(),
            ),
        }
    }
}

/// This crate's signer's DER over the lock's digest (ALL|FORKID).
fn der(lock: &str, version: i32) -> Vec<u8> {
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
        subscript: &hex::decode(lock).unwrap(),
        satoshis: 1000,
        scope: 0x41,
    });
    key().sign(&digest).unwrap().to_der()
}

fn run(der: &[u8], lock: Lock, word: Option<ScriptFlags>, version: i32) -> Result<bool, String> {
    let mut checksig = der.to_vec();
    checksig.push(0x41);
    let mut unlock = Script::new();
    if matches!(lock, Lock::MultiSigNot | Lock::MultiSigVerify) {
        unlock.write_opcode(OP_0);
    }
    unlock.write_bin(&checksig);
    let mut spend = Spend::new(SpendParams {
        source_txid: [7u8; 32],
        source_output_index: 0,
        source_satoshis: 1000,
        locking_script: LockingScript::from_hex(&lock.script()).unwrap(),
        transaction_version: version,
        other_inputs: vec![],
        outputs: vec![],
        input_index: 0,
        unlocking_script: UnlockingScript::from_hex(&unlock.to_hex()).unwrap(),
        input_sequence: u32::MAX,
        lock_time: 0,
        memory_limit: None,
        work_limit: None,
    });
    if let Some(word) = word {
        spend.set_flags(word);
        spend.set_utxo_after_chronicle(word.contains(ScriptFlags::CHRONICLE));
    }
    spend.validate().map_err(|e| e.message)
}

/// The DER's parts: R and S as written.
fn parts(der: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let r_len = usize::from(der[3]);
    (der[4..4 + r_len].to_vec(), der[6 + r_len..].to_vec())
}

fn sequence(r: &[u8], s: &[u8]) -> Vec<u8> {
    let mut body = vec![0x02, r.len() as u8];
    body.extend_from_slice(r);
    body.extend_from_slice(&[0x02, s.len() as u8]);
    body.extend_from_slice(s);
    let mut out = vec![0x30, body.len() as u8];
    out.extend(body);
    out
}

fn strip(v: &[u8]) -> Vec<u8> {
    v.iter().copied().skip_while(|b| *b == 0).collect()
}

/// `01` then the value in 32 bytes: 33 bytes past the sign byte.
fn past_32(v: &[u8]) -> Vec<u8> {
    let tail = strip(v);
    let mut out = vec![1u8];
    out.extend(std::iter::repeat_n(0u8, 32 - tail.len()));
    out.extend(tail);
    out
}

/// The cells, by the recorder's names, each built from the canonical DER.
fn shapes(der: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
    let (r, s) = parts(der);
    let long_r = {
        let mut body = vec![0x02, 0x81, r.len() as u8];
        body.extend_from_slice(&r);
        body.extend_from_slice(&[0x02, s.len() as u8]);
        body.extend_from_slice(&s);
        [vec![0x30, body.len() as u8], body].concat()
    };
    let long_s = {
        let mut body = vec![0x02, r.len() as u8];
        body.extend_from_slice(&r);
        body.extend_from_slice(&[0x02, 0x81, s.len() as u8]);
        body.extend_from_slice(&s);
        [vec![0x30, body.len() as u8], body].concat()
    };
    vec![
        ("canonical", der.to_vec()),
        ("r_lone_zero", sequence(&[0], &s)),
        ("s_lone_zero", sequence(&r, &[0])),
        ("r_past_32_bytes", sequence(&past_32(&r), &s)),
        ("s_past_32_bytes", sequence(&r, &past_32(&s))),
        ("suffix_1", [der, &[0]].concat()),
        ("suffix_2", [der, &[0, 1]].concat()),
        ("suffix_33", [der, &(0..33).collect::<Vec<u8>>()].concat()),
        (
            "sequence_length_short",
            [&[0x30, der[1] - 1][..], &der[2..]].concat(),
        ),
        (
            "sequence_length_long_over_a_byte",
            [&[0x30, der[1] + 1][..], &der[2..], &[0]].concat(),
        ),
        (
            "long_form_sequence",
            [&[0x30, 0x81][..], &der[1..]].concat(),
        ),
        ("long_form_r", long_r),
        ("long_form_s", long_s),
        (
            "r_padded",
            sequence(&[&[0, 0][..], &strip(&r)].concat(), &s),
        ),
        ("s_padded", sequence(&r, &[&[0][..], &s].concat())),
        ("six_bytes", vec![0x30, 0x04, 0x02, 0x00, 0x02, 0x00]),
    ]
}

const FOUR: [&str; 4] = [
    "r_lone_zero",
    "s_lone_zero",
    "r_past_32_bytes",
    "s_past_32_bytes",
];

/// The node's verdict under `word` at `version` (the module's lines).
fn node(cell: &str, lock: Lock, word: ScriptFlags, version: i32) -> Result<bool, String> {
    if cell == "canonical" {
        return lock.passing();
    }
    if !FOUR.contains(&cell) {
        return Err(REFUSED.into());
    }
    if word.enforce_non_malleability(version) {
        Err(format!(
            "{} requires failing signatures to be empty.",
            lock.opcode()
        ))
    } else {
        lock.failing()
    }
}

/// The base `2c464e81`'s verdict: the node's save an integer past 32 bytes,
/// which `from_checksig_format` refused in every mode.
fn base(cell: &str, lock: Lock, word: ScriptFlags, version: i32) -> Result<bool, String> {
    if cell.ends_with("past_32_bytes") {
        return Err(REFUSED.into());
    }
    node(cell, lock, word, version)
}

/// Every cell named by `select` under every word at versions 1 and 2:
/// this crate's verdict and words against the node's, and against the
/// base's save the cells `differs_from_base` names.
fn assert_cells_under_words(select: &[&str], differs_from_base: bool) {
    let mut wrong = vec![];
    for version in [1, 2] {
        for lock in LOCKS {
            let der = der(&lock.script(), version);
            for (name, shaped) in shapes(&der) {
                if !select.contains(&name) {
                    continue;
                }
                for (era, word) in words() {
                    let got = run(&shaped, lock, Some(word), version);
                    let want = node(name, lock, word, version);
                    let was = base(name, lock, word, version);
                    if got != want || (got != was) != differs_from_base {
                        wrong.push(format!(
                            "{name} {lock:?} {era} {:#x} v{version}: got {got:?}, node {want:?}, base {was:?}",
                            word.bits()
                        ));
                    }
                }
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "{} cells:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

#[test]
fn the_canonical_signature_verifies_under_every_word_and_lock_842() {
    assert_cells_under_words(&["canonical"], false);
}

/// A lone-zero R or S passes BIP 66 and the node reads zero: a failed check,
/// NULLFAIL's words where NULLFAIL applies, valid under `OP_NOT` after
/// Chronicle at version 2. The base's verdicts; `4b3fe10d` refused them.
#[test]
fn a_lone_zero_r_or_s_is_a_failed_check_under_a_word_as_the_node_reads_it_842() {
    assert_cells_under_words(&["r_lone_zero", "s_lone_zero"], false);
}

/// An R or S past 32 bytes passes BIP 66 and the node's lax parse reads the
/// all-zero signature: the same failed check (#847, fixed by this fold; the
/// base refused it as a format in every mode).
#[test]
fn an_integer_past_32_bytes_is_a_failed_check_under_a_word_as_the_node_reads_it_847() {
    assert_cells_under_words(&["r_past_32_bytes", "s_past_32_bytes"], true);
}

/// The shapes of #842 fail BIP 66 under every word, at every signature
/// opcode, before any reader: the base's verdict and words, unmoved.
#[test]
fn the_shapes_of_842_are_refused_at_the_encoding_check_under_every_word_842() {
    assert_cells_under_words(
        &[
            "suffix_1",
            "suffix_2",
            "suffix_33",
            "sequence_length_short",
            "sequence_length_long_over_a_byte",
            "long_form_sequence",
            "long_form_r",
            "long_form_s",
            "r_padded",
            "s_padded",
            "six_bytes",
        ],
        false,
    );
}

/// The default mode is the reference's: every recorded cell (the four
/// integers and the shapes, `OP_CHECKSIG` and under `OP_NOT`, versions 1 and
/// 2), the DER this crate's signer's and shapes' bytes. Moved against the
/// base: a lone-zero R or S, valid under `OP_NOT` on the base, refused in the
/// reference's words (#842); an R past 32 bytes at either version and an S
/// past 32 bytes at version 2, refused on the base, valid under `OP_NOT`
/// (#847); an S past 32 bytes at version 1 refused on both, the reference's
/// low-S check inside its wrapper's words.
#[test]
fn the_default_mode_answers_as_the_reference_recorded_842_847() {
    let recorded: serde_json::Value = serde_json::from_str(RECORDED).unwrap();
    let cells = recorded["spend"].as_array().unwrap();
    assert_eq!(cells.len(), 64);
    let mut wrong = vec![];
    for cell in cells {
        let version = i32::try_from(cell["version"].as_i64().unwrap()).unwrap();
        let lock = match cell["lock"].as_str().unwrap() {
            "checksig" => Lock::Sig,
            "checksig_not" => Lock::SigNot,
            other => panic!("{other}"),
        };
        let name = cell["name"].as_str().unwrap();
        let shaped = shapes(&der(&lock.script(), version))
            .into_iter()
            .find(|(n, _)| *n == name)
            .unwrap()
            .1;
        assert_eq!(
            hex::encode(&shaped),
            cell["der"].as_str().unwrap(),
            "{name} {lock:?} v{version}: the recorded bytes"
        );
        let want = match cell["default"].as_str().unwrap() {
            "true" => Ok(true),
            words => Err(words.strip_prefix("ERR:").unwrap().to_string()),
        };
        let got = run(&shaped, lock, None, version);
        if got != want {
            wrong.push(format!(
                "{name} {lock:?} v{version}: got {got:?}, recorded {want:?}"
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} cells:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}
