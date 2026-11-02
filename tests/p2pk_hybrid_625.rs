//! #625: a hybrid (`06`/`07`) public key at the P2PK lock, and a key tagged
//! neither `02` nor `03` at the Multisig lock where every spend reaches it.
//!
//! The reference has no P2PK or Multisig template (`ts-stack@edf6e03`
//! `packages/sdk/src/script/templates/index.ts`: P2PKH, RPuzzle, PushDrop;
//! go-sdk at `2ca481c` neither). Its doors for a hybrid key are the parser,
//! which reads `07` + x + y for an odd y and refuses `06` for it (`Point.fromDER`
//! `src/primitives/Point.ts:303-330`), and the interpreter, which refuses both
//! under its default flags (`Spend.#checkPublicKeyEncoding` `Spend.ts:687-716`:
//! "The public key is in an unknown format."), as the node refuses them under
//! `SCRIPT_VERIFY_STRICTENC` (bitcoin-sv v1.2.3 `6504a3a`
//! `src/script/interpreter.cpp:132-152` `IsCompressedOrUncompressedPubKey`,
//! `:312-316` `CheckPubKeyEncoding`, `SCRIPT_ERR_PUBKEYTYPE`) and as every
//! column of the sibling's corpus refuses `crypto-00014` (`bsv-script-lean@5dc337e1`
//! `corpus/crypto/cases.jsonl`). Every word this crate builds carries
//! STRICTENC (the block word and the standard word name it; `SIGHASH_FORKID`,
//! which `ScriptFlags::check` requires, forces it, `interpreter.cpp:2315-2318`),
//! so no spend of such a P2PK lock passes any mode here: the template refuses
//! to write it (a stated divergence: the reference has no template door, and
//! its `Script` writer pushes the key as given). CHECKMULTISIG checks only
//! the keys it reaches (from the last pushed down, ending at the threshold's
//! last match), so a Multisig lock with a bad key is refused only when every
//! spend reaches one (the #625 fold; the vector's `multisig` sweep).
//!
//! The vector is `vectors/p2pk_hybrid_625.json`, written by
//! `support/p2pk_hybrid_625.mjs` under Node v22.18.0; the key is the corpus's
//! `key("a")`, whose y is odd.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use bsv_rs::primitives::bsv::sighash::{parse_transaction, TxOutput};
use bsv_rs::primitives::ec::{PrivateKey, PublicKey};
use bsv_rs::primitives::from_hex;
use bsv_rs::primitives::hash::sha256;
use bsv_rs::script::op::{OP_1, OP_CHECKMULTISIG, OP_CHECKSIG};
use bsv_rs::script::template::{ScriptTemplate, SignOutputs, SigningContext};
use bsv_rs::script::templates::{Multisig, P2PK};
use bsv_rs::script::{
    LockingScript, ProtocolEra, Script, ScriptFlags, Spend, SpendParams, UnlockingScript,
};
use bsv_rs::Error;
use serde_json::Value;

fn vector() -> Value {
    serde_json::from_str(include_str!("vectors/p2pk_hybrid_625.json")).unwrap()
}

fn case<'a>(v: &'a Value, name: &str) -> &'a Value {
    v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("case {name}"))
}

/// The corpus's signer `key("a")` (`crypto_cases.rs:100-103`).
fn key_a(v: &Value) -> PrivateKey {
    PrivateKey::from_bytes(&sha256(v["key_label"].as_str().unwrap().as_bytes())).unwrap()
}

/// The recorded transaction with its one input's unlocking script emptied.
fn unsigned(tx: &[u8]) -> Vec<u8> {
    assert_eq!(tx[4], 1, "one input");
    let len = tx[41] as usize;
    assert!(len < 0xfd);
    let mut out = tx[..41].to_vec();
    out.push(0);
    out.extend_from_slice(&tx[42 + len..]);
    out
}

/// `unsigned` with `unlock` written as input 0's script (a four-signature
/// Multisig unlock passes 252 bytes: its length a `0xfd` varint).
fn with_unlock(unsigned: &[u8], unlock: &[u8]) -> Vec<u8> {
    let mut out = unsigned[..41].to_vec();
    match u8::try_from(unlock.len()) {
        Ok(len) if len < 0xfd => out.push(len),
        _ => {
            out.push(0xfd);
            out.extend_from_slice(&u16::try_from(unlock.len()).unwrap().to_le_bytes());
        }
    }
    out.extend_from_slice(unlock);
    out.extend_from_slice(&unsigned[42..]);
    out
}

/// The five modes a spend is judged in: the default (TS's), and the block
/// word and the standard word of the post-Genesis and post-Chronicle eras.
/// The default mode's version is the transaction's (each spend runs at
/// versions 1 and 2).
#[derive(Clone, Copy, Debug)]
enum Mode {
    Default,
    Block(ProtocolEra),
    Standard(ProtocolEra),
}

const MODES: [Mode; 5] = [
    Mode::Default,
    Mode::Block(ProtocolEra::PostGenesis),
    Mode::Standard(ProtocolEra::PostGenesis),
    Mode::Block(ProtocolEra::PostChronicle),
    Mode::Standard(ProtocolEra::PostChronicle),
];

fn verdict(
    tx: &[u8],
    satoshis: u64,
    lock: &LockingScript,
    unlock: &UnlockingScript,
    mode: Mode,
) -> Result<bool, String> {
    let tx = parse_transaction(tx).unwrap();
    let input = &tx.inputs[0];
    let outputs: Vec<TxOutput> = tx
        .outputs
        .iter()
        .map(|o| TxOutput {
            satoshis: o.satoshis,
            script: o.script.clone(),
        })
        .collect();
    let mut spend = Spend::new(SpendParams {
        source_txid: input.txid,
        source_output_index: input.output_index,
        source_satoshis: satoshis,
        locking_script: lock.clone(),
        transaction_version: tx.version,
        other_inputs: vec![],
        outputs,
        input_index: 0,
        unlocking_script: unlock.clone(),
        input_sequence: input.sequence,
        lock_time: tx.locktime,
        memory_limit: None,
        work_limit: None,
    });
    match mode {
        Mode::Default => {}
        Mode::Block(era) => spend.set_flags(ScriptFlags::block(era)),
        Mode::Standard(era) => spend.set_flags(ScriptFlags::standard(era)),
    }
    spend.validate().map_err(|e| e.message)
}

/// The words the reference's `Spend` throws, before its context lines.
fn reference_words(verdict: &Value) -> Option<String> {
    verdict["message"].as_str().map(|m| {
        m.lines()
            .next()
            .unwrap()
            .trim_start_matches("Script evaluation error: ")
            .to_string()
    })
}

/// The reference reads `07` + x + y (y odd) to the compressed key and refuses
/// `06` for it at the parser; this crate's reference reader (`from_hex`, #498)
/// reads both as it does, and `from_bytes`, the interpreter's, refuses both.
/// Green before and after #625: the parser is not the door that moved.
#[test]
fn the_reference_parser_reads_the_hybrid_tag_y_names_and_no_template_carries_it_625() {
    let v = vector();
    assert_eq!(v["reference_has_p2pk_template"], false);
    assert_eq!(v["y_odd"], true);
    for name in ["uncompressed", "hybrid_06", "hybrid_07"] {
        let c = case(&v, name);
        let key = c["point"].as_str().unwrap();
        let reference = &c["public_key_from_string"];
        assert_eq!(
            c["public_key_from_der"], *reference,
            "{name}: fromDER and fromString read alike"
        );
        match PublicKey::from_hex(key) {
            Ok(k) => {
                assert_eq!(reference["ok"], true, "{name}");
                assert_eq!(k.to_hex(), reference["compressed"].as_str().unwrap());
            }
            Err(e) => assert_eq!(reference["ok"], false, "{name}: {e}"),
        }
        let strict = PublicKey::from_bytes(&from_hex(key).unwrap());
        assert_eq!(strict.is_ok(), name == "uncompressed", "{name}");
    }
}

/// The P2PK template refuses a hybrid key, either tag, at `lock`, naming the
/// node's rule, since no word lets its spend pass (below); the uncompressed
/// key is locked to the reference writer's bytes. RED before #625: both
/// hybrid keys locked.
#[test]
fn a_hybrid_key_is_refused_at_the_p2pk_lock_625() {
    let v = vector();
    for name in ["hybrid_06", "hybrid_07"] {
        let key = from_hex(case(&v, name)["point"].as_str().unwrap()).unwrap();
        assert_eq!(
            P2PK::new().lock(&key).map(|l| l.to_hex()),
            Err(Error::InvalidPublicKey(format!(
                "a hybrid public key (tag 0x{:02x}) is neither compressed nor uncompressed: \
                 its spend fails under STRICTENC (IsCompressedOrUncompressedPubKey)",
                key[0]
            ))),
            "{name}"
        );
    }
    let c = case(&v, "uncompressed");
    let key = from_hex(c["point"].as_str().unwrap()).unwrap();
    assert_eq!(
        P2PK::new().lock(&key).unwrap().to_hex(),
        c["lock"].as_str().unwrap()
    );
}

/// The spend of `<key> OP_CHECKSIG`, the lock written by this crate's `Script`
/// writer to the reference's bytes and signed by `P2PK::sign_with_sighash` to
/// the reference's transaction byte for byte (RFC 6979), at versions 1 and 2:
/// the uncompressed control valid in the default mode and under the block
/// and standard words of both eras, as the reference's default and its explicit
/// `SIGHASH_FORKID` word record; each hybrid key refused in every mode in the
/// reference's words, as both its records refuse it. The version-2 `07` spend
/// is the corpus's `crypto-00014` transaction. Green before and after #625:
/// the interpreter is the door the reference and the node share.
#[test]
fn the_spend_of_a_hybrid_lock_is_refused_under_every_word_625() {
    let v = vector();
    let a = key_a(&v);
    let satoshis = v["satoshis"].as_u64().unwrap();
    for name in ["uncompressed", "hybrid_06", "hybrid_07"] {
        let c = case(&v, name);
        let key = from_hex(c["point"].as_str().unwrap()).unwrap();
        let mut script = Script::new();
        script.write_bin(&key).write_opcode(OP_CHECKSIG);
        let lock = LockingScript::from_script(script);
        assert_eq!(lock.to_hex(), c["lock"].as_str().unwrap(), "{name}");
        for spend in c["spends"].as_array().unwrap() {
            let version = spend["version"].as_u64().unwrap();
            let recorded = from_hex(spend["tx"].as_str().unwrap()).unwrap();
            let raw = unsigned(&recorded);
            let sighash = SigningContext::new(&raw, 0, satoshis, lock.as_script())
                .compute_sighash(0x41)
                .unwrap();
            let unlock = P2PK::sign_with_sighash(&a, &sighash, SignOutputs::All, false).unwrap();
            assert_eq!(
                unlock.to_hex(),
                spend["unlock"].as_str().unwrap(),
                "{name} v{version}"
            );
            let tx = with_unlock(&raw, &unlock.to_binary());
            assert_eq!(tx, recorded, "{name} v{version}");
            for verdict_of in ["default_flags", "explicit_sighash_forkid"] {
                assert_eq!(
                    reference_words(&spend[verdict_of]),
                    if name == "uncompressed" {
                        None
                    } else {
                        Some("The public key is in an unknown format.".to_string())
                    },
                    "{name} v{version} {verdict_of}"
                );
            }
            for mode in MODES {
                let got = verdict(&tx, satoshis, &lock, &unlock, mode);
                if name == "uncompressed" {
                    assert_eq!(got, Ok(true), "{name} v{version} {mode:?}");
                } else {
                    assert_eq!(
                        got,
                        Err("The public key is in an unknown format.".to_string()),
                        "{name} v{version} {mode:?}"
                    );
                }
            }
        }
    }
}

/// The Multisig sweep's private key `i` (`multisig_label` + i).
fn multisig_key(v: &Value, i: usize) -> PrivateKey {
    let label = format!("{}{i}", v["multisig_label"].as_str().unwrap());
    PrivateKey::from_bytes(&sha256(label.as_bytes())).unwrap()
}

/// `n` compressed keys of the sweep, the indices in `bad` retagged `tag`.
fn multisig_params(v: &Value, n: usize, bad: &[usize], tag: u8) -> Vec<u8> {
    let mut params = Vec::new();
    for i in 0..n {
        let mut key = multisig_key(v, i).public_key().to_compressed();
        if bad.contains(&i) {
            key[0] = tag;
        }
        params.extend_from_slice(&key);
    }
    params
}

/// The reachability rule: CHECKMULTISIG walks the keys from the last pushed
/// (index n - 1) down and stops at the threshold's last match (bitcoin-sv
/// v1.2.3 `interpreter.cpp:1538-1633`, `ikey` from the stack's second item;
/// this crate's `op_checkmultisig` pops the keys in that order), refusing a
/// bad key it reaches; a spend avoids the bad keys when the n - 1 - j keys
/// after the highest bad index j meet m.
fn avoidable(m: usize, n: usize, bad: &[usize]) -> bool {
    bad.iter().max().is_none_or(|&j| n - 1 - j >= m)
}

fn dead_lock_words(j: usize, tag: u8, after: usize, m: usize) -> Error {
    Error::InvalidPublicKey(format!(
        "public key {j} has tag 0x{tag:02x}, not a compressed key's 0x02 or 0x03, \
         and the {after} key(s) after it cannot meet the threshold {m}: \
         every spend reaches it and fails under STRICTENC \
         (IsCompressedOrUncompressedPubKey)"
    ))
}

/// A Multisig lock a bad key makes dead (every spend reaches it) is refused
/// at `lock` naming the highest bad index and the rule: 1-of-1, 2-of-2 with
/// either key bad, 1-of-2 with the last key bad, 2-of-3 with the middle key
/// crowding m, 2-of-4 with keys 0 and 3 bad; the tags `00`, `04`, `05`, `06`,
/// `07`. A lock whose bad key the walk can avoid is written (below), and both
/// compressed tags lock. RED before #625: every 33-byte key locked.
#[test]
fn a_multisig_lock_a_bad_key_makes_dead_is_refused_at_the_lock_625() {
    let v = vector();
    let dead: [(usize, usize, &[usize]); 6] = [
        (1, 1, &[0]),
        (2, 2, &[0]),
        (2, 2, &[1]),
        (1, 2, &[1]),
        (2, 3, &[1]),
        (2, 4, &[0, 3]),
    ];
    for tag in [0x00u8, 0x04, 0x05, 0x06, 0x07] {
        for (m, n, bad) in dead {
            assert!(!avoidable(m, n, bad));
            let j = *bad.iter().max().unwrap();
            assert_eq!(
                Multisig::new(m as u8)
                    .lock(&multisig_params(&v, n, bad, tag))
                    .map(|l| l.to_hex()),
                Err(dead_lock_words(j, tag, n - 1 - j, m)),
                "{m}-of-{n} bad {bad:?} tag {tag:02x}"
            );
        }
    }
    let mut both_tags = multisig_params(&v, 2, &[], 0);
    both_tags[0] ^= 0x01;
    for params in [multisig_params(&v, 2, &[], 0), both_tags] {
        assert!(Multisig::new(2).lock(&params).is_ok());
    }
}

/// A one-of-two lock whose key 0 is bad (`04`, `06`, `07`) is written, to the
/// reference writer's bytes, and spent by key 1 alone, the walk checking key
/// 1 and stopping at its match: valid in the default mode at versions 1 and
/// 2 and under the block and standard words of the post-Genesis and
/// post-Chronicle eras, as the reference's default and explicit
/// `SIGHASH_FORKID` records are. RED before the #625 fold: the lock refused.
#[test]
fn an_unreached_bad_key_lock_is_written_and_spent_under_every_word_625() {
    let v = vector();
    let satoshis = v["satoshis"].as_u64().unwrap();
    for tag in [0x04u8, 0x06, 0x07] {
        let c = v["multisig"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| {
                c["m"] == 1 && c["n"] == 2 && c["tag"] == tag && c["bad"] == serde_json::json!([0])
            })
            .unwrap();
        assert_eq!(c["signers"], serde_json::json!([1]));
        let lock = Multisig::new(1)
            .lock(&multisig_params(&v, 2, &[0], tag))
            .unwrap();
        assert_eq!(lock.to_hex(), c["lock"].as_str().unwrap(), "tag {tag:02x}");
        for (version, spend) in c["spends"].as_array().unwrap().iter().enumerate() {
            let recorded = from_hex(
                case(&v, "uncompressed")["spends"][version]["tx"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
            let raw = unsigned(&recorded);
            let sighash = SigningContext::new(&raw, 0, satoshis, lock.as_script())
                .compute_sighash(0x41)
                .unwrap();
            let unlock = Multisig::sign_with_sighash(
                &[multisig_key(&v, 1)],
                &sighash,
                SignOutputs::All,
                false,
            )
            .unwrap();
            assert_eq!(unlock.to_hex(), spend["unlock"].as_str().unwrap());
            for verdict_of in ["default_flags", "explicit_sighash_forkid"] {
                assert_eq!(spend[verdict_of]["ok"], true, "tag {tag:02x} {verdict_of}");
            }
            let tx = with_unlock(&raw, &unlock.to_binary());
            for mode in MODES {
                assert_eq!(
                    verdict(&tx, satoshis, &lock, &unlock, mode),
                    Ok(true),
                    "tag {tag:02x} v{} {mode:?}",
                    spend["version"]
                );
            }
        }
    }
}

/// The sweep: m-of-n for n from 1 to 4 and every m, a bad key (`04`, `06`,
/// `07`) at each index and `07` at each pair, 125 shapes. For each, the
/// reference's verdict at versions 1 and 2 under its default and explicit
/// `SIGHASH_FORKID` flags is the reachability rule's (35 avoidable shapes
/// valid, 90 dead refused); this crate's lock writes the reference's bytes
/// exactly where the rule says avoidable and refuses the rest naming the
/// highest bad index; the recorded spend (the m highest good keys, a bad
/// index's own key filling the count) signed to the reference's unlock byte
/// for byte and judged in the five modes as the rule says.
#[test]
fn the_multisig_sweep_follows_the_reachability_rule_and_the_reference_625() {
    let v = vector();
    let satoshis = v["satoshis"].as_u64().unwrap();
    let shapes = v["multisig"].as_array().unwrap();
    let ints = |x: &Value| -> Vec<usize> {
        x.as_array()
            .unwrap()
            .iter()
            .map(|i| i.as_u64().unwrap() as usize)
            .collect()
    };
    let mut counts = (0, 0);
    for c in shapes {
        let m = c["m"].as_u64().unwrap() as usize;
        let n = c["n"].as_u64().unwrap() as usize;
        let tag = c["tag"].as_u64().unwrap() as u8;
        let bad = ints(&c["bad"]);
        let alive = avoidable(m, n, &bad);
        if alive {
            counts.0 += 1;
        } else {
            counts.1 += 1;
        }
        let at = format!("{m}-of-{n} bad {bad:?} tag {tag:02x}");
        let lock = LockingScript::from_hex(c["lock"].as_str().unwrap()).unwrap();
        let written = Multisig::new(m as u8).lock(&multisig_params(&v, n, &bad, tag));
        if alive {
            assert_eq!(written.map(|l| l.to_hex()), Ok(lock.to_hex()), "{at}");
        } else {
            let j = *bad.iter().max().unwrap();
            assert_eq!(
                written.map(|l| l.to_hex()),
                Err(dead_lock_words(j, tag, n - 1 - j, m)),
                "{at}"
            );
        }
        let signers: Vec<PrivateKey> = ints(&c["signers"])
            .into_iter()
            .map(|i| multisig_key(&v, i))
            .collect();
        for (version, spend) in c["spends"].as_array().unwrap().iter().enumerate() {
            for verdict_of in ["default_flags", "explicit_sighash_forkid"] {
                assert_eq!(
                    spend[verdict_of]["ok"],
                    alive,
                    "{at} v{} {verdict_of}",
                    version + 1
                );
            }
            let recorded = from_hex(
                case(&v, "uncompressed")["spends"][version]["tx"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
            let raw = unsigned(&recorded);
            let sighash = SigningContext::new(&raw, 0, satoshis, lock.as_script())
                .compute_sighash(0x41)
                .unwrap();
            let unlock =
                Multisig::sign_with_sighash(&signers, &sighash, SignOutputs::All, false).unwrap();
            assert_eq!(unlock.to_hex(), spend["unlock"].as_str().unwrap(), "{at}");
            let tx = with_unlock(&raw, &unlock.to_binary());
            for mode in MODES {
                let got = verdict(&tx, satoshis, &lock, &unlock, mode);
                assert_eq!(
                    got == Ok(true),
                    alive,
                    "{at} v{} {mode:?}: {got:?}",
                    version + 1
                );
            }
        }
    }
    assert_eq!(counts, (35, 90));
}

/// The spend a Multisig lock of a key retagged `06`/`07` would write, its
/// one-of-one `OP_1 <key> OP_1 OP_CHECKMULTISIG` written by this crate's
/// `Script` writer and signed by `Multisig::sign_with_sighash`: refused in
/// every mode, as the node checks each key it compares
/// (`interpreter.cpp:1611`); the compressed control valid in every mode.
/// Green before and after #625. The words are this crate's CHECKMULTISIG
/// wrapper's; the reference's visible words are its key check's, `The public
/// key is in an unknown format.` (`Spend.ts:1808-1814`, the check throwing
/// before the wrapper; the sweep's dead shapes record them), a difference of
/// words left to #657. `ScriptEvaluationError` carries no variant for the
/// refusal (its `message` is the verdict's only name), so the words stay
/// here: #657's fix changes them and this assertion with it.
#[test]
fn the_spend_of_a_retagged_multisig_lock_is_refused_under_every_word_625() {
    let v = vector();
    let a = key_a(&v);
    let satoshis = v["satoshis"].as_u64().unwrap();
    let compressed = a.public_key().to_compressed();
    let recorded = from_hex(
        case(&v, "uncompressed")["spends"][1]["tx"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let raw = unsigned(&recorded);
    for tag in [0x02u8, 0x03, 0x06, 0x07] {
        let mut key = compressed;
        key[0] = tag;
        let mut script = Script::new();
        script
            .write_opcode(OP_1)
            .write_bin(&key)
            .write_opcode(OP_1)
            .write_opcode(OP_CHECKMULTISIG);
        let lock = LockingScript::from_script(script);
        let sighash = SigningContext::new(&raw, 0, satoshis, lock.as_script())
            .compute_sighash(0x41)
            .unwrap();
        let unlock = Multisig::sign_with_sighash(
            std::slice::from_ref(&a),
            &sighash,
            SignOutputs::All,
            false,
        )
        .unwrap();
        let tx = with_unlock(&raw, &unlock.to_binary());
        for mode in MODES {
            let got = verdict(&tx, satoshis, &lock, &unlock, mode);
            match tag {
                0x03 => assert_eq!(got, Ok(true), "tag {tag:02x} {mode:?}"),
                // The other parity names another point: a valid encoding
                // whose signature does not verify (NULLFAIL under a word)
                0x02 => assert!(got.is_err(), "tag {tag:02x} {mode:?}"),
                // #657: the words move to the reference's when it lands
                _ => assert_eq!(
                    got,
                    Err(
                        "OP_CHECKMULTISIG requires correct encoding for the public key and signature."
                            .to_string()
                    ),
                    "tag {tag:02x} {mode:?}"
                ),
            }
        }
    }
}
