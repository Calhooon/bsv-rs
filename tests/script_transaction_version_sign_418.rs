//! #418: a transaction version at or above 2^31. The reference reads the
//! version unsigned (`ts-stack@edf6e03` `Transaction.ts:471`, `readUInt32LE`)
//! and relaxes its rules at `transactionVersion > 1` (`Spend.ts:319-321`;
//! under explicit flags `:343-345`), so 0x80000000 and 0xFFFFFFFF are relaxed
//! there in both modes. The node reads `int32_t` (bitcoin-sv v1.2.2
//! `primitives/transaction.h:273`; `IsMalleableTxnVersion`, `version > 1`,
//! `interpreter.cpp:34-44`), so under a Chronicle word they are negative and
//! strict. This crate's default mode is the reference's (relaxed), a word the
//! node's (strict); the reference's explicit flags diverge from consensus
//! there, a stated finding. Recorded from the unmodified reference under
//! Node 22 by `support/script_transaction_version_sign_418.mjs`.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::primitives::bsv::sighash::{
    compute_sighash_dispatched_for_signing, SighashParams, TxInput,
};
use bsv_rs::primitives::bsv::tx_signature::TransactionSignature;
use bsv_rs::primitives::{to_hex, PrivateKey};
use bsv_rs::script::{
    LockingScript, ProtocolEra, Script, ScriptFlags, SigningContext, Spend, SpendParams,
    UnlockingScript,
};
use bsv_rs::transaction::{
    MerklePath, MockChainTracker, Transaction, TransactionInput, TransactionOutput,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Recording {
    reference: String,
    node: String,
    flags: Vec<String>,
    cases: Vec<Case>,
    reads: Vec<Read>,
    fold_cases: Vec<Case>,
}

#[derive(Clone, Deserialize)]
struct Case {
    rule: String,
    version: u32,
    mode: String,
    unlock: String,
    lock: String,
    valid: Option<bool>,
    error: Option<String>,
    stack: Vec<String>,
    digest: Option<String>,
}

#[derive(Deserialize)]
struct Read {
    bytes: String,
    hex: String,
    version: u32,
}

const PREFIX: &str = "Script evaluation error: ";
const ABOVE: [u32; 2] = [0x8000_0000, 0xFFFF_FFFF];

fn recording() -> Recording {
    let r: Recording = serde_json::from_str(include_str!(
        "vectors/script_transaction_version_sign_418.json"
    ))
    .unwrap();
    assert_eq!(
        r.reference,
        "ts-stack@edf6e03dad39bd7bc4fc6e73e64de3a2b6f805c9"
    );
    assert_eq!(r.node, "v22.18.0");
    // The reference's explicit flags are the node's post-Chronicle mempool word.
    assert_eq!(
        r.flags,
        ScriptFlags::standard(ProtocolEra::PostChronicle).names()
    );
    assert_eq!(r.cases.len(), 60);
    assert_eq!(r.fold_cases.len(), 24);
    r
}

/// The spend as the reference's `Spend` received it, its version the wire's
/// four bytes held in the `i32` parameter.
fn spend(c: &Case, version: u32, word: Option<ScriptFlags>) -> Spend {
    let mut s = Spend::new(SpendParams {
        source_txid: [0; 32],
        source_output_index: 0,
        source_satoshis: 1,
        locking_script: LockingScript::from_hex(&c.lock).unwrap(),
        transaction_version: version as i32,
        other_inputs: vec![],
        outputs: vec![],
        input_index: 0,
        unlocking_script: UnlockingScript::from_hex(&c.unlock).unwrap(),
        input_sequence: u32::MAX,
        lock_time: 0,
        memory_limit: None,
        work_limit: None,
    });
    if let Some(word) = word {
        s.set_flags(word);
    }
    s
}

/// `Ok(valid)` or `Err(message)` without the reference's prefix.
fn verdict(s: &mut Spend) -> Result<bool, String> {
    s.validate().map_err(|e| {
        assert!(!e.is_resource_limit(), "{}", e.message);
        e.message
    })
}

fn recorded(c: &Case) -> Result<bool, String> {
    match &c.error {
        Some(error) => Err(error.strip_prefix(PREFIX).unwrap().to_string()),
        None => Ok(c.valid.unwrap()),
    }
}

fn find<'a>(r: &'a Recording, rule: &str, version: u32, mode: &str) -> &'a Case {
    r.cases
        .iter()
        .find(|c| c.rule == rule && c.version == version && c.mode == mode)
        .unwrap()
}

/// Every default-mode cell the reference recorded, verdict, words and the
/// stack: at 0x80000000 and 0xFFFFFFFF the four rules and the Chronicle hash
/// type are relaxed, as at 2. RED on `7a047467` (strict there: the version
/// read as negative).
#[test]
fn a_version_at_or_above_2_31_is_relaxed_in_the_default_mode_as_the_reference_reads_it_418() {
    let r = recording();
    for c in r.cases.iter().filter(|c| c.mode == "default") {
        let mut s = spend(c, c.version, None);
        let got = verdict(&mut s);
        assert_eq!(got, recorded(c), "{} v{:#x}", c.rule, c.version);
        if c.error.is_some() {
            let stack: Vec<String> = s
                .validate()
                .unwrap_err()
                .stack
                .iter()
                .map(|v| to_hex(v))
                .collect();
            assert_eq!(stack, c.stack, "{} v{:#x}", c.rule, c.version);
        }
    }
    for version in ABOVE {
        for rule in [
            "MINIMALDATA",
            "CLEANSTACK",
            "NULLDUMMY",
            "LOW_S",
            "CHRONICLE_HASH_TYPE",
        ] {
            let c = find(&r, rule, version, "default");
            assert_eq!(c.valid, Some(true), "{rule} v{version:#x}");
            assert_eq!(
                verdict(&mut spend(c, version, None)),
                Ok(true),
                "{rule} v{version:#x}"
            );
        }
    }
}

/// Under a word the node's `int32_t`: at 0x80000000 and 0xFFFFFFFF each rule
/// the word carries is enforced in the words it gives at version 1, where the
/// reference's explicit flags (the same word's names) are relaxed, its
/// `transactionVersion > 1` on the unsigned number. At 2 and 0x7FFFFFFF the
/// word and the reference's flags agree (relaxed). A pin: GREEN on
/// `7a047467` (the word already read the version signed).
#[test]
fn a_version_at_or_above_2_31_is_strict_under_a_word_as_the_node_reads_int32_418() {
    let r = recording();
    let standard = ScriptFlags::standard(ProtocolEra::PostChronicle);
    let block = ScriptFlags::block(ProtocolEra::PostChronicle);
    for rule in [
        "MINIMALDATA",
        "CLEANSTACK",
        "NULLDUMMY",
        "LOW_S",
        "CHRONICLE_HASH_TYPE",
    ] {
        for word in [standard, block] {
            let one = find(&r, rule, 1, "flags");
            let at_one = verdict(&mut spend(one, 1, Some(word)));
            for version in ABOVE {
                let c = find(&r, rule, version, "flags");
                assert_eq!(
                    verdict(&mut spend(c, version, Some(word))),
                    at_one,
                    "{rule} v{version:#x} {:#x}",
                    word.bits()
                );
                // The reference's explicit flags: relaxed (the divergence).
                assert_eq!(recorded(c), Ok(true), "{rule} v{version:#x}");
            }
            for version in [2, 0x7FFF_FFFF] {
                let c = find(&r, rule, version, "flags");
                assert_eq!(recorded(c), Ok(true), "{rule} v{version:#x}");
                assert_eq!(
                    verdict(&mut spend(c, version, Some(word))),
                    Ok(true),
                    "{rule} v{version:#x} {:#x}",
                    word.bits()
                );
            }
        }
        // At version 1 the mempool word and the reference's flags agree.
        let one = find(&r, rule, 1, "flags");
        assert_eq!(
            verdict(&mut spend(one, 1, Some(standard))).is_ok(),
            recorded(one).is_ok(),
            "{rule} v1"
        );
    }
    // What the mempool word enforces at 2^31 and above: the four rules.
    for rule in ["MINIMALDATA", "CLEANSTACK", "NULLDUMMY", "LOW_S"] {
        for version in ABOVE {
            let c = find(&r, rule, version, "flags");
            assert!(
                verdict(&mut spend(c, version, Some(standard))).is_err(),
                "{rule} v{version:#x}"
            );
        }
    }
    // The block word carries LOW_S, not the three standard-only rules.
    for version in ABOVE {
        let c = find(&r, "LOW_S", version, "flags");
        assert!(verdict(&mut spend(c, version, Some(block))).is_err());
    }
}

/// OP_VER writes the version's four little-endian bytes in every mode, the
/// reference's (`Spend.ts:984-990`): `00000080` is negative zero, false, at
/// 0x80000000; `ffffffff` true. 0x7FFFFFFF relaxed in every mode.
#[test]
fn op_ver_pushes_the_four_bytes_and_0x7fffffff_is_relaxed_in_every_mode_418() {
    let r = recording();
    for c in r.cases.iter().filter(|c| c.rule == "OP_VER") {
        let mut s = spend(c, c.version, None);
        assert_eq!(verdict(&mut s), recorded(c), "default v{:#x}", c.version);
        for word in [
            ScriptFlags::standard(ProtocolEra::PostChronicle),
            ScriptFlags::block(ProtocolEra::PostChronicle),
        ] {
            let mut s = spend(c, c.version, Some(word));
            let expected = match c.version {
                0x8000_0000 => {
                    Err("The top stack element must be truthy after script evaluation.".to_string())
                }
                _ => Ok(true),
            };
            assert_eq!(verdict(&mut s), expected, "word v{:#x}", c.version);
        }
    }
    for c in r.cases.iter().filter(|c| c.version == 0x7FFF_FFFF) {
        assert_eq!(recorded(c), Ok(true), "{} {}", c.rule, c.mode);
        let mut words = vec![None];
        words.push(Some(ScriptFlags::standard(ProtocolEra::PostChronicle)));
        words.push(Some(ScriptFlags::block(ProtocolEra::PostChronicle)));
        for word in words {
            assert_eq!(
                verdict(&mut spend(c, c.version, word)),
                Ok(true),
                "{} {}",
                c.rule,
                c.mode
            );
        }
    }
}

/// The two signed rules' digests are this crate's sighash at the version's
/// four bytes, the reference's `formatBytes` (the version a preimage field).
#[test]
fn the_signed_cells_digests_are_this_crates_sighash_at_each_version_418() {
    let r = recording();
    for c in r.cases.iter().filter(|c| c.digest.is_some()) {
        let script = UnlockingScript::from_hex(&c.unlock).unwrap();
        let sig = script.chunks()[0].data.clone().unwrap();
        let digest = compute_sighash_dispatched_for_signing(&SighashParams {
            version: c.version as i32,
            inputs: &[TxInput {
                txid: [0; 32],
                output_index: 0,
                script: vec![],
                sequence: u32::MAX,
            }],
            outputs: &[],
            locktime: 0,
            input_index: 0,
            subscript: &Script::from_hex(&c.lock).unwrap().to_binary(),
            satoshis: 1,
            scope: u32::from(*sig.last().unwrap()),
        });
        assert_eq!(
            Some(to_hex(&digest)),
            c.digest,
            "{} v{:#x}",
            c.rule,
            c.version
        );
    }
}

/// The reference's `Transaction.fromHex` reads `00000080` as 2147483648 and
/// `ffffffff` as 4294967295; this crate's `u32` the same, written back.
#[test]
fn the_version_bytes_read_unsigned_as_the_reference_reads_them_418() {
    let r = recording();
    assert_eq!(r.reads.len(), 2);
    for read in &r.reads {
        let tx = Transaction::from_hex(&read.hex).unwrap();
        assert_eq!(tx.version(), read.version, "{}", read.bytes);
        assert_eq!(tx.to_hex(), read.hex);
    }
}

/// One transaction at version 0x80000000, built, written and read back, its
/// input a `ALL|FORKID|CHRONICLE` signature this crate makes: valid through
/// `Transaction::verify` and the direct `Spend` in the default mode, as the
/// reference's `Transaction.verify` passes `transactionVersion: tx.version`
/// (`Transaction.ts:1446`) to a relaxed `Spend`; refused at version 1 in the
/// reference's visible words. RED on `7a047467` at 0x80000000.
#[test]
fn transaction_verify_at_version_2_31_admits_the_chronicle_hash_type_as_the_reference_does_418() {
    assert_eq!(chronicle_child(0x8000_0000), Ok(true));
    assert_eq!(chronicle_child(0xFFFF_FFFF), Ok(true));
    let refused = chronicle_child(1).unwrap_err();
    assert!(
        refused.contains("The signature format is invalid."),
        "{refused}"
    );
}

fn chronicle_child(version: u32) -> Result<bool, String> {
    let key = PrivateKey::from_bytes(&[7u8; 32]).unwrap();
    let mut lock = Script::new();
    lock.write_bin(&key.public_key().to_compressed())
        .write_opcode(0xac);
    let lock = LockingScript::from_script(lock);

    let mut source = Transaction::new();
    source
        .add_input({
            let mut input = TransactionInput::new("11".repeat(32).parse().unwrap(), 0);
            input.set_unlocking_script(UnlockingScript::from_hex("51").unwrap());
            input
        })
        .unwrap();
    source
        .add_output(TransactionOutput::new(1_000, lock.clone()))
        .unwrap();
    source.merkle_path = Some(MerklePath::from_coinbase_txid(&source.id(), 900_000));

    // `to_binary` caches its bytes, so each form is built afresh.
    let build = |unlocking: UnlockingScript| {
        let mut child = Transaction::new();
        child.set_version(version);
        let mut input = TransactionInput::with_source_transaction(source.clone(), 0);
        input.set_unlocking_script(unlocking);
        child.add_input(input).unwrap();
        child
            .add_output(TransactionOutput::new(900, lock.clone()))
            .unwrap();
        child
    };
    let scope = 0x61;
    let unsigned = build(UnlockingScript::new()).to_binary();
    let digest = SigningContext::new(&unsigned, 0, 1_000, lock.as_script())
        .compute_sighash(scope)
        .unwrap();
    let sig = TransactionSignature::new(key.sign(&digest).unwrap(), scope);
    let mut unlock = Script::new();
    unlock.write_bin(&sig.to_checksig_format());
    let child = build(UnlockingScript::from_script(unlock));

    // Written and read back: the four bytes, the same number.
    let mut read = Transaction::from_binary(&child.to_binary()).unwrap();
    assert_eq!(read.version(), version);
    assert_eq!(read.to_binary()[..4], version.to_le_bytes());
    read.inputs_mut()[0].source_transaction = Some(Box::new(source));

    // The direct Spend beside it, the version's bits in the `i32` parameter.
    let direct = Spend::new(SpendParams {
        source_txid: read.inputs()[0].get_source_txid_bytes().unwrap(),
        source_output_index: 0,
        source_satoshis: 1_000,
        locking_script: lock.clone(),
        transaction_version: read.version() as i32,
        other_inputs: vec![],
        outputs: vec![bsv_rs::primitives::bsv::sighash::TxOutput {
            satoshis: 900,
            script: lock.to_binary(),
        }],
        input_index: 0,
        unlocking_script: read.inputs()[0].unlocking_script.clone().unwrap(),
        input_sequence: read.inputs()[0].sequence,
        lock_time: read.lock_time(),
        memory_limit: None,
        work_limit: None,
    })
    .validate()
    .map_err(|e| e.message);

    // The tracker 100 blocks above the lone-leaf proof at 900,000: an
    // offset-0 proof under 100 deep is not proven (#734, `MerklePath.ts:476-500`).
    let whole = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(read.verify(&MockChainTracker::always_valid(900_100), None, None))
        .map_err(|e| e.to_string());
    assert_eq!(
        whole.is_ok(),
        direct.is_ok(),
        "v{version:#x}: {whole:?} {direct:?}"
    );
    whole
}

fn find_fold<'a>(r: &'a Recording, rule: &str, version: u32, mode: &str) -> &'a Case {
    r.fold_cases
        .iter()
        .find(|c| c.rule == rule && c.version == version && c.mode == mode)
        .unwrap()
}

/// The strength read's version-0 cell: 0 is not above 1, so it is strict in
/// every mode, as at 1. The default mode equals every recorded verdict, word
/// and stack at version 0; under both words the version-1 verdict, the
/// reference's flags agreeing (strict there too), save `OP_VER`, whose push
/// is the version's own bytes (false at 0, the recorded words). A pin of
/// `relaxed_by_default`'s `> 1` (`hash_type.rs`): RED with it planted as
/// `!= 1` in a scratch copy of the tip.
#[test]
fn a_version_of_0_is_strict_in_every_mode_as_at_1_418() {
    let r = recording();
    // The six rules of `cases` at 0; the undefined hash type and push-only
    // cells at 0 are their own tests'.
    for c in r
        .fold_cases
        .iter()
        .filter(|c| c.version == 0 && c.rule != "UNDEFINED_HASH_TYPE" && c.rule != "SIGPUSHONLY")
    {
        if c.mode == "default" {
            let mut s = spend(c, 0, None);
            assert_eq!(verdict(&mut s), recorded(c), "{} v0 default", c.rule);
            if c.error.is_some() {
                let stack: Vec<String> = s
                    .validate()
                    .unwrap_err()
                    .stack
                    .iter()
                    .map(|v| to_hex(v))
                    .collect();
                assert_eq!(stack, c.stack, "{} v0", c.rule);
            }
            continue;
        }
        if c.rule == "OP_VER" {
            // OP_VER pushes the version's bytes, `00000000` false at 0 in
            // every mode: the recorded words under both words.
            for word in [
                ScriptFlags::standard(ProtocolEra::PostChronicle),
                ScriptFlags::block(ProtocolEra::PostChronicle),
            ] {
                assert_eq!(
                    verdict(&mut spend(c, 0, Some(word))),
                    recorded(c),
                    "OP_VER v0"
                );
            }
            continue;
        }
        let one = find(&r, &c.rule, 1, "flags");
        assert_eq!(
            recorded(c).is_ok(),
            recorded(one).is_ok(),
            "{} v0 flags",
            c.rule
        );
        for word in [
            ScriptFlags::standard(ProtocolEra::PostChronicle),
            ScriptFlags::block(ProtocolEra::PostChronicle),
        ] {
            assert_eq!(
                verdict(&mut spend(c, 0, Some(word))),
                verdict(&mut spend(one, 1, Some(word))),
                "{} v0 {:#x}",
                c.rule,
                word.bits()
            );
        }
        assert_eq!(
            verdict(&mut spend(
                c,
                0,
                Some(ScriptFlags::standard(ProtocolEra::PostChronicle))
            ))
            .is_ok(),
            recorded(c).is_ok(),
            "{} v0 standard",
            c.rule
        );
    }
    // The four rules refused at 0 in the default mode, as the reference does.
    for rule in ["MINIMALDATA", "CLEANSTACK", "NULLDUMMY", "LOW_S"] {
        let c = find_fold(&r, rule, 0, "default");
        assert!(verdict(&mut spend(c, 0, None)).is_err(), "{rule} v0");
    }
}

/// The strength read's undefined-hash-type cell: a signature of scope 0x44
/// (base type 4, FORKID) in the default mode. At 0 and 1 the refusal is the
/// reference's DER wrapper (#417, `Spend.ts:609-625`), the recorded words; at
/// 2, `0x7FFFFFFF`, `0x80000000` and `0xFFFFFFFF` this crate's version-2
/// sentence (#23's), where the reference keeps its wrapper at every version:
/// the #417 stated difference, the same above 2^31 as at 2. A pin of
/// `signature_encoding.rs`'s `relaxed_by_default` arm: RED with it planted
/// back as the signed `transaction_version <= 1` in a scratch copy of the tip.
#[test]
fn an_undefined_hash_type_at_or_above_2_31_is_refused_in_the_version_2_words_418() {
    let r = recording();
    let wrapper = Err("The signature format is invalid.".to_string());
    let sentence = Err("The signature's hash type (0x44) has no defined base type.".to_string());
    for version in [0, 1] {
        let c = find_fold(&r, "UNDEFINED_HASH_TYPE", version, "default");
        assert_eq!(recorded(c), wrapper, "v{version:#x}");
        assert_eq!(
            verdict(&mut spend(c, version, None)),
            wrapper,
            "v{version:#x}"
        );
    }
    for version in [2, 0x7FFF_FFFF, 0x8000_0000, 0xFFFF_FFFF] {
        let c = find_fold(&r, "UNDEFINED_HASH_TYPE", version, "default");
        // The reference's words: its wrapper at every version.
        assert_eq!(recorded(c), wrapper, "v{version:#x}");
        assert_eq!(
            verdict(&mut spend(c, version, None)),
            sentence,
            "v{version:#x}"
        );
    }
}

/// The strength read's push-only cell: `OP_1 OP_DROP` before `OP_1`, an
/// unlocking script that is not push-only, under the post-Chronicle mempool
/// word (the one carrying `SIGPUSHONLY`). The node requires push-only at
/// `tx_version <= 1` on its `int32_t` (`interpreter.cpp:2321-2334` at v1.2.2),
/// so 0, 1, `0x80000000` and `0xFFFFFFFF` are refused in the version-1 words
/// and 2 and `0x7FFFFFFF` run it; the reference's flags relax at and above
/// 2^31 on its unsigned number (`Spend.ts:364-368`), the stated divergence.
/// A pin of `ScriptFlags::requires_push_only`'s signed comparison
/// (`flags.rs`): RED with it planted as `tx_version as u32 <= 1` in a scratch
/// copy of the tip. The default mode's push-only rule is outside #418 (#816
/// relaxed it above version 1, pinned by `script_push_only_default_816.rs`)
/// and not asserted here.
#[test]
fn a_non_push_only_unlocking_script_at_or_above_2_31_is_refused_under_a_word_418() {
    let r = recording();
    let standard = ScriptFlags::standard(ProtocolEra::PostChronicle);
    assert!(standard.contains(ScriptFlags::SIGPUSHONLY));
    let one = find_fold(&r, "SIGPUSHONLY", 1, "flags");
    let at_one = verdict(&mut spend(one, 1, Some(standard)));
    assert!(at_one.is_err(), "{at_one:?}");
    for version in [0, 1] {
        let c = find_fold(&r, "SIGPUSHONLY", version, "flags");
        assert!(recorded(c).is_err(), "v{version:#x}");
        assert_eq!(
            verdict(&mut spend(c, version, Some(standard))),
            at_one,
            "v{version:#x}"
        );
    }
    for version in ABOVE {
        let c = find_fold(&r, "SIGPUSHONLY", version, "flags");
        assert_eq!(
            verdict(&mut spend(c, version, Some(standard))),
            at_one,
            "v{version:#x}"
        );
        // The reference's explicit flags: relaxed (the divergence).
        assert_eq!(recorded(c), Ok(true), "v{version:#x}");
    }
    for version in [2, 0x7FFF_FFFF] {
        let c = find_fold(&r, "SIGPUSHONLY", version, "flags");
        assert_eq!(recorded(c), Ok(true), "v{version:#x}");
        assert_eq!(
            verdict(&mut spend(c, version, Some(standard))),
            Ok(true),
            "v{version:#x}"
        );
    }
}
