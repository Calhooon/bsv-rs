//! The script-number length limit on a witness from the differential run
//! against bitcoin-sv v1.2.2 (`879fc8b`), Calhooon/bsv-rs#17: a version-2
//! spend of a coin created after Genesis and before Chronicle, in a block
//! after Chronicle, whose locking script
//! `<0x01> <0x00> (OP_DUP OP_CAT)×20 OP_CAT OP_1ADD OP_DROP OP_1` makes
//! `OP_1ADD` read the number 1 followed by 2^20 zero bytes: 1,048,577 bytes.
//! The reference: `SCRIPT_ERR_SCRIPTNUM_OVERFLOW` on the block path (750,000
//! bytes for the coin's era, `consensus.h:64`) and on the mempool path (the
//! policy default of 10,000, `policy.h:156`). 0.3.27: valid under the block
//! word, the standard word and the default mode.
use bsv_rs::primitives::bsv::sighash::{parse_transaction, TxOutput};
use bsv_rs::primitives::from_hex;
use bsv_rs::script::{
    LockingScript, ProtocolEra, ScriptFlags, Spend, SpendParams, UnlockingScript,
};

const TX: &str = "02000000010195b06741c6515a231d36e4e8a92fc7fd8d8232fb9506689abeb3ed47fbf2180000000000ffffffff010100000000000000015100000000";
const LOCK: &str = "01010100767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e767e7e8b7551";

fn run(word: Option<ScriptFlags>, utxo_after_chronicle: Option<bool>) -> Result<bool, String> {
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
    if let Some(after) = utxo_after_chronicle {
        spend.set_utxo_after_chronicle(after);
    }
    spend.validate().map_err(|e| e.message)
}

/// The block path for a coin created before Chronicle: 1,048,577 > 750,000.
#[test]
fn the_witness_overflows_under_the_block_word_for_a_coin_created_before_chronicle() {
    assert_eq!(
        run(
            Some(ScriptFlags::block(ProtocolEra::PostChronicle)),
            Some(false)
        ),
        Err("Script number overflow: 1048577 bytes, the limit is 750000 bytes.".to_string())
    );
}

/// The mempool path: 1,048,577 > 10,000, the policy default.
#[test]
fn the_witness_overflows_under_the_standard_word() {
    assert_eq!(
        run(
            Some(ScriptFlags::standard(ProtocolEra::PostChronicle)),
            Some(false)
        ),
        Err("Script number overflow: 1048577 bytes, the limit is 10000 bytes.".to_string())
    );
}

/// The default mode reads a number of any length, as the TypeScript SDK does
/// (0.3.27's verdict under every word).
#[test]
fn the_witness_is_valid_in_the_default_mode() {
    assert_eq!(run(None, None), Ok(true));
}

/// The same coin created after Chronicle: 1,048,577 < 32,000,000.
#[test]
fn the_same_coin_created_after_chronicle_is_within_the_limit_under_the_block_word() {
    assert_eq!(
        run(
            Some(ScriptFlags::block(ProtocolEra::PostChronicle)),
            Some(true)
        ),
        Ok(true)
    );
}
