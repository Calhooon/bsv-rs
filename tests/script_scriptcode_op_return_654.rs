//! A signature check's scriptCode is built from the executing script's bytes,
//! not the chunk serializer, so a top-level data-carrying `OP_RETURN` in the
//! scriptCode region no longer drops everything after it — including the
//! locking script appended to an unlocking-script check (public issue #654).
//!
//! bitcoin-sv v1.2.3 builds the scriptCode as `CScript{pbegincodehash, pend}`,
//! the executing script's bytes from the last executed `OP_CODESEPARATOR` to
//! its end, then — inside the unlocking script under a Chronicle word (and in
//! the reference's default `Spend`) — the locking script's bytes, then
//! `CleanupScriptCode`'s `FindAndDelete` of each non-FORKID signature's push
//! (`interpreter.cpp:1470-1484`, `1566-1579`, `255-263`; `script.h:201-224`).
//! Until #654 the scriptCode went through the chunk serializer, which stops at
//! a data-carrying `OP_RETURN` chunk (`Script::serialize_chunks_to_bytes`): the
//! locking script behind such an `OP_RETURN` in the unlocking script was
//! dropped, so a check signed `ac6a0100` where the node signs `ac6a01006951`.
//!
//! The witness U2 is `<sig> <P> OP_CODESEPARATOR OP_CHECKSIG OP_RETURN 01 00`
//! spending `OP_VERIFY OP_1`. Under a post-Chronicle word a spend signed over
//! the node's scriptCode `ac6a01006951` is valid; a spend signed over the old
//! folded scriptCode `ac6a0100` — which this crate ACCEPTED on 0.8.13 (a
//! wrong-digest spend verified where the node refuses it) — is now refused.
//! M2 is the same shape through OP_CHECKMULTISIG. The push-only paths cannot
//! reach a non-push-only unlocking script, so the word is the reachable door
//! (a consensus block word runs it; `bsv-wallet-toolbox-rs` runs the standard
//! word). Signatures are this crate's own (RFC 6979), so the forging side is
//! built by this crate's writers; every outpoint is synthetic.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a failed unwrap is the test failing

use bsv_rs::primitives::bsv::sighash::{
    compute_sighash_dispatched_for_signing, SighashParams, TxInput, TxOutput,
};
use bsv_rs::primitives::bsv::TransactionSignature;
use bsv_rs::primitives::{from_hex, PrivateKey};
use bsv_rs::script::{
    LockingScript, ProtocolEra, Script, ScriptFlags, Spend, SpendParams, UnlockingScript,
};

const TXID: [u8; 32] = [0x5a; 32];
const SATS: u64 = 10_000;
const LOCK: [u8; 2] = [0x69, 0x51]; // OP_VERIFY OP_1
const VERSION: i32 = 2;

/// NULLFAIL's / OP_VERIFY's refusals when the check fails (the fold or the
/// wrong digest leaves a false check).
const OP_VERIFY_FAILS: &str = "OP_VERIFY requires the top stack value to be truthy.";

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
fn sign(code: &[u8], scope: u32) -> Vec<u8> {
    let inputs = [TxInput {
        txid: TXID,
        output_index: 0,
        script: vec![],
        sequence: 0xffff_ffff,
    }];
    let digest = compute_sighash_dispatched_for_signing(&SighashParams {
        version: VERSION,
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

fn run(lock: &[u8], unlock: &[u8], word: ScriptFlags) -> Result<bool, String> {
    let mut s = Spend::new(SpendParams {
        source_txid: TXID,
        source_output_index: 0,
        source_satoshis: SATS,
        locking_script: LockingScript::from_binary(lock).unwrap(),
        transaction_version: VERSION,
        other_inputs: vec![],
        outputs: outputs(),
        input_index: 0,
        unlocking_script: UnlockingScript::from_binary(unlock).unwrap(),
        input_sequence: 0xffff_ffff,
        lock_time: 0,
        memory_limit: None,
        work_limit: None,
    });
    s.set_flags(word);
    s.validate().map_err(|e| e.message)
}

fn words() -> [(&'static str, ScriptFlags); 2] {
    [
        (
            "block_post_chronicle",
            ScriptFlags::block(ProtocolEra::PostChronicle),
        ),
        (
            "standard_post_chronicle",
            ScriptFlags::standard(ProtocolEra::PostChronicle),
        ),
    ]
}

/// `<sig> <P> OP_CODESEPARATOR OP_CHECKSIG OP_RETURN 01 00`.
fn u2_unlock(sig: &[u8]) -> Vec<u8> {
    [
        push(sig),
        push(&pubkey()),
        vec![0xab, 0xac, 0x6a, 0x01, 0x00],
    ]
    .concat()
}

/// THE SECURITY ROW (false-VALID on 0.8.13): a spend signed over the OLD folded
/// scriptCode `ac6a0100` — the locking script dropped behind the OP_RETURN — is
/// now refused. On 0.8.13 this verified (Ok(true)); this assertion is RED there.
#[test]
fn a_wrong_digest_spend_over_a_folded_op_return_is_refused_654() {
    let sig = sign(&from_hex("ac6a0100").unwrap(), 0x41);
    for (name, word) in words() {
        assert_eq!(
            run(&LOCK, &u2_unlock(&sig), word),
            Err(OP_VERIFY_FAILS.to_string()),
            "{name}"
        );
    }
}

/// The complement (false-INVALID on 0.8.13): a spend signed over the node's
/// full scriptCode `ac6a01006951` is accepted, both scopes (ALL|FORKID over
/// BIP143, and ALL|FORKID|CHRONICLE over the original digest). On 0.8.13 the
/// fold dropped the locking script, so these were refused.
#[test]
fn a_node_valid_spend_past_a_top_level_op_return_is_accepted_654() {
    for (name, word) in words() {
        for scope in [0x41u32, 0x61u32] {
            let sig = sign(&from_hex("ac6a01006951").unwrap(), scope);
            assert_eq!(
                run(&LOCK, &u2_unlock(&sig), word),
                Ok(true),
                "{name} {scope:#x}"
            );
        }
    }
}

/// `OP_0 <sig> OP_1 <P> OP_1 OP_CODESEPARATOR OP_CHECKMULTISIG OP_RETURN 01 00`:
/// the same fold through OP_CHECKMULTISIG. Node-signed accepted, old-signed
/// refused.
#[test]
fn an_unlocking_checkmultisig_past_a_top_level_op_return_654() {
    let m2_tail = [0xae, 0x6a, 0x01, 0x00]; // OP_CHECKMULTISIG OP_RETURN 01 00
                                            // OP_0 <sig> OP_1 <P> OP_1 OP_CODESEPARATOR <tail>
    let unlock = |sig: &[u8]| {
        [
            vec![0x00],
            push(sig),
            vec![0x51],
            push(&pubkey()),
            vec![0x51, 0xab],
            m2_tail.to_vec(),
        ]
        .concat()
    };
    for (name, word) in words() {
        let node_sig = sign(&[m2_tail.as_slice(), &LOCK].concat(), 0x41);
        assert_eq!(
            run(&LOCK, &unlock(&node_sig), word),
            Ok(true),
            "{name} node"
        );
        let old_sig = sign(&m2_tail, 0x41);
        assert_eq!(
            run(&LOCK, &unlock(&old_sig), word),
            Err(OP_VERIFY_FAILS.to_string()),
            "{name} old"
        );
    }
}

/// The append is gated on the word: a pre-Chronicle word signs the unlocking
/// script's bytes alone, where this crate ALWAYS appended the locking script
/// until #654 (a second false-VALID of the same door). `<sig> <P>
/// OP_CODESEPARATOR OP_CHECKSIG` spending `OP_VERIFY OP_1`, under a
/// pre-Chronicle block word with SIGPUSHONLY cleared (so the non-push-only
/// unlocking runs): the node's scriptCode is `ac`, not `ac6951`. A spend signed
/// over `ac6951` — accepted on 0.8.13 — is refused; one signed over `ac` is
/// accepted (refused on 0.8.13). Mutating the append gate to always-append
/// fails the `ac`-signed row.
#[test]
fn a_pre_chronicle_word_signs_the_unlocking_bytes_alone_654() {
    let word = ScriptFlags::block(ProtocolEra::PostGenesis).without(ScriptFlags::SIGPUSHONLY);
    let p = pubkey();
    let unlock = |sig: &[u8]| [push(sig), push(&p), vec![0xab, 0xac]].concat(); // <sig> <P> OP_CODESEPARATOR OP_CHECKSIG
    let node_sig = sign(&from_hex("ac").unwrap(), 0x41);
    assert_eq!(
        run(&LOCK, &unlock(&node_sig), word),
        Ok(true),
        "node-signed ac"
    );
    let old_sig = sign(&from_hex("ac6951").unwrap(), 0x41);
    assert_eq!(
        run(&LOCK, &unlock(&old_sig), word),
        Err("OP_CHECKSIG requires failing signatures to be empty.".to_string()),
        "old-signed ac6951"
    );
}

/// INVARIANT (honest callers do not move): a plain P2PK spend with no
/// data-carrying OP_RETURN has the same scriptCode before and after #654 and
/// verifies. `<sig>` unlocking, `<P> OP_CHECKSIG` locking; the scriptCode is
/// the appended locking script `<P> ac`.
#[test]
fn a_plain_p2pk_spend_is_unchanged_654() {
    let p = pubkey();
    let lock = [push(&p), vec![0xac]].concat();
    let code = lock.clone(); // unlocking empty of code; scriptCode = appended locking
    let sig = sign(&code, 0x41);
    for (name, word) in words() {
        assert_eq!(run(&lock, &push(&sig), word), Ok(true), "{name}");
    }
}
