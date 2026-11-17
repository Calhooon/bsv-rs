//! #654: the scriptCode of a signature check built from the script's bytes as
//! bitcoin-sv v1.2.3 builds it (`interpreter.cpp:1470-1484`, `1566-1579`):
//! the executing script from its last executed `OP_CODESEPARATOR` to its end,
//! then, for a check in the unlocking script under `SCRIPT_CHRONICLE`, the
//! locking script's bytes (`scriptCode += *checksigData`), then
//! `CleanupScriptCode`'s `FindAndDelete` for a signature without FORKID
//! (`:255-263`, `script.h:201-224`), every instruction read by `GetOp` with
//! no fold. Until #654 the scriptCode went through the chunk serializer, which
//! stops at an `OP_RETURN` chunk holding data, so the locking script behind a
//! data-carrying top-level `OP_RETURN` in the unlocking script was dropped
//! (U2: `ac6a0100` here where the node signs `ac6a01006951`), and the locking
//! script was appended under a pre-Chronicle word, where the node signs the
//! unlocking script alone (P1).
//!
//! Every transaction here: one input of 10,000 satoshis spending the synthetic
//! outpoint `5a..5a:0`, one output of 9,000 satoshis to `51`, lock time 0,
//! sequence `ffffffff`, key `11..11`. Signatures are this crate's (RFC 6979),
//! so the cases are built by this crate's own writer; the vector
//! `tests/vectors/sighash_scriptcode_654.json` records them with the verdicts
//! of this crate, of the sibling's Lean evaluator (the node's rules) and of
//! the TypeScript reference's default `Spend` (`tests/support/sighash_scriptcode_654.mjs`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::primitives::bsv::sighash::{
    compute_sighash_dispatched_for_signing, SighashParams, TxInput, TxOutput,
};
use bsv_rs::primitives::bsv::TransactionSignature;
use bsv_rs::primitives::{from_hex, to_hex, PrivateKey};
use bsv_rs::script::{
    LockingScript, ProtocolEra, Script, ScriptFlags, Spend, SpendParams, UnlockingScript,
};
use serde::Deserialize;

const TXID: [u8; 32] = [0x5a; 32];
const SATS: u64 = 10_000;
const LOCK: [u8; 2] = [0x69, 0x51]; // OP_VERIFY OP_1

fn outputs() -> Vec<TxOutput> {
    vec![TxOutput {
        satoshis: 9_000,
        script: vec![0x51],
    }]
}

fn push(b: &[u8]) -> Vec<u8> {
    let mut s = Script::new();
    s.write_bin(b);
    s.to_binary()
}

fn key() -> PrivateKey {
    PrivateKey::from_hex(&"11".repeat(32)).unwrap()
}

fn pubkey() -> Vec<u8> {
    key().public_key().to_compressed().to_vec()
}

/// A signature over `code` as the node's `SignatureHash` dispatches it.
fn sign(version: i32, code: &[u8], scope: u32) -> Vec<u8> {
    let inputs = [TxInput {
        txid: TXID,
        output_index: 0,
        script: vec![],
        sequence: 0xffff_ffff,
    }];
    let digest = compute_sighash_dispatched_for_signing(&SighashParams {
        version,
        inputs: &inputs,
        outputs: &outputs(),
        locktime: 0,
        input_index: 0,
        subscript: code,
        satoshis: SATS,
        scope,
    });
    TransactionSignature::new(key().sign(&digest).unwrap(), scope).to_checksig_format()
}

/// One spend: its shape's name, its version, its scripts, the scriptCode its
/// signature is taken over, and the scriptCode of its check three ways: the
/// node's under a Chronicle word (and this crate's default mode), the node's
/// under a pre-Chronicle word, this crate's in every mode before #654.
struct Case {
    name: &'static str,
    version: i32,
    lock: Vec<u8>,
    unlock: Vec<u8>,
    signed_over: Vec<u8>,
    scope: u32,
    codes: [Vec<u8>; 3],
}

/// The shapes, at the version given. `tail` follows the `OP_CODESEPARATOR`.
fn cases_at(version: i32) -> Vec<Case> {
    let p = pubkey();
    let mut cases = Vec::new();
    // L1: a non-FORKID signature in the locking script behind its own
    // OP_RETURN; the node's scriptCode deletes its push: `<P> ac 6a`.
    let l1_code = [push(&p), vec![0xac, 0x6a]].concat();
    let l1_sig = sign(version, &l1_code, 0x01);
    cases.push(Case {
        name: "L1",
        version,
        lock: [l1_code.clone(), push(&l1_sig)].concat(),
        unlock: push(&l1_sig),
        signed_over: l1_code.clone(),
        scope: 0x01,
        codes: [
            l1_code.clone(),
            l1_code.clone(),
            [l1_code, push(&l1_sig)].concat(),
        ],
    });
    // U1: a non-FORKID signature in the unlocking script, its push repeated
    // behind an OP_RETURN; the node's post-Chronicle scriptCode deletes both.
    let u1_code = [push(&p), vec![0xac, 0x6a], LOCK.to_vec()].concat();
    let u1_sig = sign(version, &u1_code, 0x01);
    cases.push(Case {
        name: "U1",
        version,
        lock: LOCK.to_vec(),
        unlock: [push(&u1_sig), push(&p), vec![0xac, 0x6a], push(&u1_sig)].concat(),
        signed_over: u1_code.clone(),
        scope: 0x01,
        codes: [
            u1_code,
            [push(&p), vec![0xac, 0x6a]].concat(),
            [push(&p), vec![0xac, 0x6a], push(&u1_sig)].concat(),
        ],
    });
    // U2: `<sig> <P> OP_CODESEPARATOR OP_CHECKSIG OP_RETURN 01 00`; the
    // node's post-Chronicle scriptCode `ac6a01006951`, this crate's until
    // #654 `ac6a0100`.
    let u2_tail = vec![0xac, 0x6a, 0x01, 0x00];
    let unlocking =
        |sig: &[u8], tail: &[u8]| [push(sig), push(&p), vec![0xab], tail.to_vec()].concat();
    for (name, scope, code) in [
        (
            "U2 0x41 node-signed",
            0x41,
            [u2_tail.clone(), LOCK.to_vec()].concat(),
        ),
        (
            "U2 0x61 node-signed",
            0x61,
            [u2_tail.clone(), LOCK.to_vec()].concat(),
        ),
        ("U2 0x41 old-signed", 0x41, u2_tail.clone()),
    ] {
        let sig = sign(version, &code, scope);
        cases.push(Case {
            name,
            version,
            lock: LOCK.to_vec(),
            unlock: unlocking(&sig, &u2_tail),
            signed_over: code,
            scope,
            codes: [
                [u2_tail.clone(), LOCK.to_vec()].concat(),
                u2_tail.clone(),
                u2_tail.clone(),
            ],
        });
    }
    // U3: a bare OP_RETURN ends the unlocking script; the scriptCode
    // `ac6a6951` here, at the node and here before #654.
    let u3_tail = vec![0xac, 0x6a];
    let u3_code = [u3_tail.clone(), LOCK.to_vec()].concat();
    let u3_sig = sign(version, &u3_code, 0x41);
    cases.push(Case {
        name: "U3",
        version,
        lock: LOCK.to_vec(),
        unlock: unlocking(&u3_sig, &u3_tail),
        signed_over: u3_code.clone(),
        scope: 0x41,
        codes: [u3_code.clone(), u3_tail, u3_code],
    });
    // M2: U2's form through OP_CHECKMULTISIG:
    // `OP_0 <sig> OP_1 <P> OP_1 OP_CODESEPARATOR OP_CHECKMULTISIG OP_RETURN 01 00`.
    let m2_tail = vec![0xae, 0x6a, 0x01, 0x00];
    for (name, code) in [
        ("M2 node-signed", [m2_tail.clone(), LOCK.to_vec()].concat()),
        ("M2 old-signed", m2_tail.clone()),
    ] {
        let sig = sign(version, &code, 0x41);
        let unlock = [
            vec![0x00],
            push(&sig),
            vec![0x51],
            push(&p),
            vec![0x51, 0xab],
            m2_tail.clone(),
        ]
        .concat();
        cases.push(Case {
            name,
            version,
            lock: LOCK.to_vec(),
            unlock,
            signed_over: code,
            scope: 0x41,
            codes: [
                [m2_tail.clone(), LOCK.to_vec()].concat(),
                m2_tail.clone(),
                m2_tail.clone(),
            ],
        });
    }
    // P1: `<sig> <P> OP_CODESEPARATOR OP_CHECKSIG`, no OP_RETURN: the node
    // signs `ac` under a pre-Chronicle word, `ac6951` under a Chronicle one.
    for (name, code) in [
        ("P1 pre-Chronicle-signed", vec![0xac]),
        ("P1 Chronicle-signed", vec![0xac, 0x69, 0x51]),
    ] {
        let sig = sign(version, &code, 0x41);
        cases.push(Case {
            name,
            version,
            lock: LOCK.to_vec(),
            unlock: unlocking(&sig, &[0xac]),
            signed_over: code,
            scope: 0x41,
            codes: [vec![0xac, 0x69, 0x51], vec![0xac], vec![0xac, 0x69, 0x51]],
        });
    }
    cases
}

fn all_cases() -> Vec<Case> {
    let mut cases = cases_at(1);
    cases.extend(cases_at(2));
    cases
}

/// The modes every case runs in.
const MODES: [&str; 7] = [
    "default",
    "default_no_push_only",
    "block_post_genesis",
    "standard_post_genesis",
    "block_post_genesis_no_sigpushonly",
    "block_post_chronicle",
    "standard_post_chronicle",
];

/// The word of a mode, `None` for the default mode.
fn word(mode: &str) -> Option<ScriptFlags> {
    match mode {
        "default" | "default_no_push_only" => None,
        "block_post_genesis" => Some(ScriptFlags::block(ProtocolEra::PostGenesis)),
        "standard_post_genesis" => Some(ScriptFlags::standard(ProtocolEra::PostGenesis)),
        "block_post_genesis_no_sigpushonly" => {
            Some(ScriptFlags::block(ProtocolEra::PostGenesis).without(ScriptFlags::SIGPUSHONLY))
        }
        "block_post_chronicle" => Some(ScriptFlags::block(ProtocolEra::PostChronicle)),
        "standard_post_chronicle" => Some(ScriptFlags::standard(ProtocolEra::PostChronicle)),
        other => panic!("no mode {other}"),
    }
}

fn run(case: &Case, mode: &str) -> Result<bool, String> {
    let mut s = Spend::new(SpendParams {
        source_txid: TXID,
        source_output_index: 0,
        source_satoshis: SATS,
        locking_script: LockingScript::from_binary(&case.lock).unwrap(),
        transaction_version: case.version,
        other_inputs: vec![],
        outputs: outputs(),
        input_index: 0,
        unlocking_script: UnlockingScript::from_binary(&case.unlock).unwrap(),
        input_sequence: 0xffff_ffff,
        lock_time: 0,
        memory_limit: None,
        work_limit: None,
    });
    if let Some(flags) = word(mode) {
        s.set_flags(flags);
    }
    if mode == "default_no_push_only" {
        s.set_require_push_only(false);
    }
    s.validate().map_err(|e| e.message)
}

fn verdict(case: &Case, mode: &str) -> String {
    match run(case, mode) {
        Ok(b) => format!("Ok({b})"),
        Err(e) => format!("Err({e})"),
    }
}

fn case(name: &str, version: i32) -> Case {
    all_cases()
        .into_iter()
        .find(|c| c.name == name && c.version == version)
        .unwrap()
}

const OP_VERIFY_FAILS: &str = "OP_VERIFY requires the top stack value to be truthy.";
/// NULLFAIL's refusal (`interpreter.cpp:1491-1497`).
const NULLFAIL: &str = "OP_CHECKSIG requires failing signatures to be empty.";

#[test]
fn an_unlocking_checksig_signs_the_locking_script_past_a_top_level_op_return_654() {
    for mode in ["block_post_chronicle", "standard_post_chronicle"] {
        // The spends signed over the node's scriptCode `ac6a01006951`, both
        // scopes (ALL|FORKID over BIP143, ALL|FORKID|CHRONICLE over the
        // original digest), are accepted.
        for name in ["U2 0x41 node-signed", "U2 0x61 node-signed"] {
            let c = case(name, 2);
            assert_eq!(c.signed_over, from_hex("ac6a01006951").unwrap());
            assert_eq!(run(&c, mode), Ok(true), "{name} {mode}");
        }
        // The one signed over the scriptCode without the locking script, this
        // crate's until #654, is refused: CHECKSIG false, then OP_VERIFY.
        let c = case("U2 0x41 old-signed", 2);
        assert_eq!(run(&c, mode), Err(OP_VERIFY_FAILS.to_string()), "{mode}");
    }
}

#[test]
fn an_unlocking_checkmultisig_signs_the_locking_script_past_a_top_level_op_return_654() {
    for mode in ["block_post_chronicle", "standard_post_chronicle"] {
        assert_eq!(run(&case("M2 node-signed", 2), mode), Ok(true), "{mode}");
        assert_eq!(
            run(&case("M2 old-signed", 2), mode),
            Err(OP_VERIFY_FAILS.to_string()),
            "{mode}"
        );
    }
}

#[test]
fn a_bare_op_return_ending_the_unlocking_script_keeps_the_locking_script_654() {
    // `ac6a6951`: the same scriptCode before and after #654, and the node's.
    let c = case("U3", 2);
    for mode in [
        "block_post_chronicle",
        "standard_post_chronicle",
        "default_no_push_only",
    ] {
        assert_eq!(run(&c, mode), Ok(true), "{mode}");
    }
}

#[test]
fn an_unlocking_checksig_under_a_pre_chronicle_word_signs_the_unlocking_script_alone_654() {
    // `SCRIPT_CHRONICLE` unset: the node appends no locking script
    // (`interpreter.cpp:1475`); a word without SIGPUSHONLY reaches it.
    let mode = "block_post_genesis_no_sigpushonly";
    for version in [1, 2] {
        assert_eq!(
            run(&case("P1 pre-Chronicle-signed", version), mode),
            Ok(true)
        );
        // The scriptCode with the locking script fails NULLFAIL, enforced
        // before Chronicle at every version.
        assert_eq!(
            run(&case("P1 Chronicle-signed", version), mode),
            Err(NULLFAIL.to_string())
        );
        // U2 there signs `ac6a0100`, the unlocking script's bytes to its end.
        assert_eq!(run(&case("U2 0x41 old-signed", version), mode), Ok(true));
        assert_eq!(
            run(&case("U2 0x41 node-signed", version), mode),
            Err(NULLFAIL.to_string())
        );
    }
    // Under the post-Chronicle words the same spends read the other way.
    for mode in ["block_post_chronicle", "standard_post_chronicle"] {
        assert_eq!(run(&case("P1 Chronicle-signed", 2), mode), Ok(true));
        assert_eq!(
            run(&case("P1 pre-Chronicle-signed", 2), mode),
            Err(OP_VERIFY_FAILS.to_string())
        );
    }
}

#[test]
fn a_non_forkid_signature_is_refused_by_the_words_before_its_script_code_654() {
    // FORKID forces STRICTENC (`interpreter.cpp:2315-2318`): a signature
    // without the bit is refused at its encoding, whichever scriptCode.
    for name in ["L1", "U1"] {
        for version in [1, 2] {
            let c = case(name, version);
            for mode in [
                "block_post_genesis",
                "standard_post_genesis",
                "block_post_genesis_no_sigpushonly",
                "block_post_chronicle",
                "standard_post_chronicle",
            ] {
                let v = verdict(&c, mode);
                assert!(
                    v == "Err(Unlocking scripts can only contain push operations, and no other opcodes.)"
                        || v.contains("FORKID"),
                    "{name} v{version} {mode}: {v}"
                );
            }
        }
    }
    // The default mode verifies a 0x01 signature over the original digest
    // (#429), its push deleted from the node's scriptCode read through the
    // OP_RETURN: L1 is valid at both versions here (the reference's stop
    // keeps the push, false there: the parity note of #654).
    assert_eq!(run(&case("L1", 1), "default"), Ok(true));
    assert_eq!(run(&case("L1", 2), "default"), Ok(true));
    assert_eq!(run(&case("U1", 2), "default_no_push_only"), Ok(true));
}

/// The chunk serializer's stop stays: it is the reference's writer
/// (`Script.ts:450-484` at `ts-stack@edf6e03`, `#serializeChunksToBytes`
/// breaks after an `OP_RETURN` chunk holding data), the parser folds every
/// byte after a top-level `OP_RETURN` into that one chunk, so a script read
/// from bytes writes its bytes back, and since #654 no scriptCode is built
/// through it. Only chunks a caller puts behind such a chunk are not written.
#[test]
fn the_chunk_serializer_keeps_the_references_stop_and_a_read_script_its_bytes_654() {
    let unlock = case("U2 0x41 node-signed", 2).unlock;
    let read = Script::from_binary(&unlock).unwrap();
    let rebuilt = Script::from_chunks(read.chunks().to_vec());
    assert_eq!(rebuilt.to_binary(), unlock);
    let mut chunks = Script::from_binary(&[0x6a, 0x01, 0x00])
        .unwrap()
        .chunks()
        .to_vec();
    chunks.extend_from_slice(Script::from_binary(&LOCK).unwrap().chunks());
    assert_eq!(Script::from_chunks(chunks).to_binary(), [0x6a, 0x01, 0x00]);
}

#[derive(Deserialize)]
struct Recording {
    cases: Vec<RecordedCase>,
}

#[derive(Deserialize)]
struct RecordedCase {
    name: String,
    version: i32,
    lock: String,
    unlock: String,
    signed_over: String,
    script_code_chronicle: String,
    script_code_pre_chronicle: String,
    script_code_before_654: String,
    rust: std::collections::BTreeMap<String, String>,
    lean: std::collections::BTreeMap<String, String>,
    ts_default: String,
}

#[test]
fn the_vector_holds_the_cases_this_crate_writes_and_their_verdicts_654() {
    let text = std::fs::read_to_string("tests/vectors/sighash_scriptcode_654.json").unwrap();
    let recording: Recording = serde_json::from_str(&text).unwrap();
    let cases = all_cases();
    assert_eq!(recording.cases.len(), cases.len());
    for (rec, c) in recording.cases.iter().zip(&cases) {
        assert_eq!((rec.name.as_str(), rec.version), (c.name, c.version));
        assert_eq!(rec.lock, to_hex(&c.lock), "{}", rec.name);
        assert_eq!(rec.unlock, to_hex(&c.unlock), "{}", rec.name);
        assert_eq!(rec.signed_over, to_hex(&c.signed_over), "{}", rec.name);
        let codes = [
            &rec.script_code_chronicle,
            &rec.script_code_pre_chronicle,
            &rec.script_code_before_654,
        ];
        for (recorded, built) in codes.iter().zip(&c.codes) {
            assert_eq!(**recorded, to_hex(built), "{}", rec.name);
        }
        for mode in MODES {
            assert_eq!(
                rec.rust[mode],
                verdict(c, mode),
                "{} v{} {mode}",
                rec.name,
                c.version
            );
        }
        // The node's rules (the Lean evaluator, under each word) agree with
        // this crate's verdict, valid or invalid, under every word.
        for (mode, lean) in &rec.lean {
            let ours = run(c, mode).unwrap_or(false);
            assert_eq!(
                lean,
                &ours.to_string(),
                "{} v{} {mode}",
                rec.name,
                c.version
            );
        }
        assert!(rec.ts_default.starts_with("Ok(") || rec.ts_default.starts_with("Err("));
    }
}

/// The spending transaction's bytes, for the Lean evaluator's `--tx`.
fn spending_tx(c: &Case) -> Vec<u8> {
    let mut tx = c.version.to_le_bytes().to_vec();
    tx.push(1);
    tx.extend_from_slice(&TXID);
    tx.extend_from_slice(&0u32.to_le_bytes());
    assert!(c.unlock.len() < 0xfd);
    tx.push(c.unlock.len() as u8);
    tx.extend_from_slice(&c.unlock);
    tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    tx.push(1);
    tx.extend_from_slice(&9_000u64.to_le_bytes());
    tx.extend_from_slice(&[1, 0x51]);
    tx.extend_from_slice(&0u32.to_le_bytes());
    tx
}

/// Writes the cases and this crate's verdicts for the recorder
/// (`tests/support/sighash_scriptcode_654.mjs`) to the path in
/// `SIGHASH_SCRIPTCODE_654_OUT`.
#[test]
#[ignore = "recorder: run by hand before tests/support/sighash_scriptcode_654.mjs"]
fn record_sighash_scriptcode_654_cases() {
    let out = std::env::var("SIGHASH_SCRIPTCODE_654_OUT").unwrap();
    let cases: Vec<serde_json::Value> = all_cases()
        .iter()
        .map(|c| {
            let rust: serde_json::Map<String, serde_json::Value> = MODES
                .iter()
                .map(|m| (m.to_string(), verdict(c, m).into()))
                .collect();
            serde_json::json!({
                "name": c.name,
                "version": c.version,
                "lock": to_hex(&c.lock),
                "unlock": to_hex(&c.unlock),
                "signed_over": to_hex(&c.signed_over),
                "scope": c.scope,
                "script_code_chronicle": to_hex(&c.codes[0]),
                "script_code_pre_chronicle": to_hex(&c.codes[1]),
                "script_code_before_654": to_hex(&c.codes[2]),
                "tx": to_hex(&spending_tx(c)),
                "rust": rust,
            })
        })
        .collect();
    let words: serde_json::Map<String, serde_json::Value> = MODES
        .iter()
        .filter_map(|m| word(m).map(|w| (m.to_string(), w.bits().into())))
        .collect();
    let recording = serde_json::json!({ "words": words, "cases": cases });
    std::fs::write(out, serde_json::to_string(&recording).unwrap()).unwrap();
}
