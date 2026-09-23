//! Regression: a signature whose `s` equals the curve order (Calhooon/bsv-rs#14).
//!
//! The reference's low-S check parses the signature laxly
//! (`ecdsa_signature_parse_der_lax`, `pubkey.cpp:146-173`): an `r` or `s` at
//! or above the order becomes the all-zero signature, which is low, so
//! `CPubKey::CheckLowS` (`356-365`) passes and the signature then fails to
//! verify; under version 1 with NULLFAIL the script is `SCRIPT_ERR_SIG_NULLFAIL`
//! (`interpreter.cpp:1491-1497`). 0.3.24 through 0.3.27 refused such a signature
//! as high-S before verifying it. Both verdicts are invalid; the rule and the
//! message differ, and a caller that matches on the message takes another path.
//!
//! The witness: a version-1 P2PK spend whose DER signature has `r` = the
//! generator's x and `s` = the order, with the FORKID hash type, from the same
//! differential run against bitcoin-sv v1.2.2 (`879fc8b`). Every outpoint is
//! synthetic.

use bsv_rs::primitives::bsv::sighash::{parse_transaction, TxOutput};
use bsv_rs::primitives::from_hex;
use bsv_rs::script::{
    LockingScript, ProtocolEra, ScriptFlags, Spend, SpendParams, UnlockingScript,
};

const TX: &str = "0100000001586418026012a16c2afa38a375d6be2b79338481af51127fda90d048ed7057640000000049483045022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036414141ffffffff010100000000000000015100000000";
const LOCK: &str = "21035935f55855afd8c999bdb5a8d08ae8e73b7618e200d4ef7687cd55d3c2e4c9d7ac";

fn run(word: Option<ScriptFlags>) -> Result<bool, String> {
    let tx = parse_transaction(&from_hex(TX).unwrap()).unwrap();
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
        source_satoshis: 1000,
        locking_script: LockingScript::from_hex(LOCK).unwrap(),
        transaction_version: tx.version,
        other_inputs: vec![],
        outputs,
        input_index: 0,
        unlocking_script: UnlockingScript::from_binary(&input.script).unwrap(),
        input_sequence: input.sequence,
        lock_time: tx.locktime,
        memory_limit: None,
    });
    if let Some(w) = word {
        spend.set_flags(w);
    }
    spend.validate().map_err(|e| e.message)
}

/// Under the block word at version 1: NULLFAIL, as on the reference
/// (0.3.27 said `The signature must have a low S value.`).
#[test]
fn a_signature_with_s_at_the_order_is_nullfail_under_the_block_word_at_version_1() {
    let msg = run(Some(ScriptFlags::block(ProtocolEra::PostChronicle))).unwrap_err();
    assert_eq!(msg, "OP_CHECKSIG requires failing signatures to be empty.");
}

/// In the default mode at version 1 (low-S required, no NULLFAIL): the check
/// passes and the failed CHECKSIG leaves a false top.
#[test]
fn a_signature_with_s_at_the_order_is_a_false_top_in_the_default_mode() {
    let msg = run(None).unwrap_err();
    assert!(
        msg.starts_with("The top stack element must be truthy"),
        "{msg}"
    );
}

/// Under the standard word the same: the low-S rule is the reference's.
#[test]
fn the_standard_word_agrees_with_the_block_word_here() {
    let msg = run(Some(ScriptFlags::standard(ProtocolEra::PostChronicle))).unwrap_err();
    assert_eq!(msg, "OP_CHECKSIG requires failing signatures to be empty.");
}
