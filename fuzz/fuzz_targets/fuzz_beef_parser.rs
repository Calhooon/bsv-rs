#![no_main]
#![allow(deprecated)]
use std::collections::HashMap;

use bsv_rs::primitives::bsv::sighash::{TxInput, TxOutput};
use bsv_rs::script::{LockingScript, Script, Spend, SpendParams, UnlockingScript};
use bsv_rs::transaction::beef_stream::{ChainTip, Hash32, Headers};
use bsv_rs::transaction::{
    verify_stream, verify_stream_structure, Beef, BeefLimits, Kind, MerklePath, Transaction,
    Verdict,
};
use libfuzzer_sys::fuzz_target;

/// Every root carried, at a tip past every chain's Genesis: the reader runs
/// the scripts of whatever the bytes prove.
struct EveryRoot;
impl Headers for EveryRoot {
    fn carries(&self, _: u64, _: &Hash32) -> bool {
        true
    }
    fn mining_tip(&self) -> Option<ChainTip> {
        Some(ChainTip {
            height: 900_099,
            median_time_past: 1_700_000_000,
            genesis_height: 620_538,
            csv_height: 419_328,
            next_block_time: None,
        })
    }
}

/// The node's pay-to-script-hash step built by hand for input `vin` of `tx`
/// spending `lock` (GHSA-fr33-7jw7-mwwh): `None` for another shape, else
/// whether the last push, run as a script on the pushes before it, succeeds.
fn redeem_by_hand(tx: &Transaction, vin: usize, lock: &[u8], satoshis: u64) -> Option<bool> {
    if !(lock.len() == 23 && lock[..2] == [0xa9, 0x14] && lock[22] == 0x87) {
        return None;
    }
    let input = &tx.inputs[vin];
    let script = Script::from_binary(&input.unlocking_script.as_ref()?.to_binary()).ok()?;
    let mut chunks = script.chunks();
    if !script.is_push_only() || script.truncated_push().is_some() {
        return Some(false);
    }
    let last = chunks.pop()?;
    let redeem = match last.op {
        0x4f => vec![0x81],
        0x51..=0x60 => vec![last.op - 0x50],
        _ => last.data.unwrap_or_default(),
    };
    let other_inputs = (tx.inputs.iter().enumerate())
        .filter(|(i, _)| *i != vin)
        .map(|(_, i)| TxInput {
            txid: i.get_source_txid_bytes().unwrap_or([0; 32]),
            output_index: i.source_output_index,
            script: Vec::new(),
            sequence: i.sequence,
        })
        .collect();
    let outputs = (tx.outputs.iter())
        .map(|o| TxOutput {
            satoshis: o.satoshis.unwrap_or(0),
            script: o.locking_script.to_binary(),
        })
        .collect();
    let mut spend = Spend::new(SpendParams {
        source_txid: input.get_source_txid_bytes().ok()?,
        source_output_index: input.source_output_index,
        source_satoshis: satoshis,
        locking_script: LockingScript::from_binary(&redeem).ok()?,
        transaction_version: tx.version as i32,
        other_inputs,
        outputs,
        input_index: vin,
        unlocking_script: UnlockingScript::from_chunks(chunks),
        input_sequence: input.sequence,
        lock_time: tx.lock_time,
        memory_limit: None,
        work_limit: None,
    });
    spend.set_require_push_only(true);
    spend.set_utxo_after_chronicle(false);
    Some(spend.validate().is_ok())
}

fuzz_target!(|data: &[u8]| {
    // A raw entry is refused in a held kind exactly when the strict parse
    // refuses its bytes, with and without a BUMP index (#852); `NoInputs`,
    // named ahead of the held kind, when the input count is 0. Every verdict
    // door is held to it: `verify_structure`, `sort_txs` alone (the entry in
    // `not_valid`, its `is_valid` field false), `is_valid` and `verify_valid`.
    let parsed = Transaction::from_binary(data);
    let refused = parsed.is_err();
    let no_outputs = matches!(&parsed, Ok(tx) if !tx.inputs.is_empty() && tx.outputs.is_empty());
    for bump_index in [None, Some(0)] {
        let mut one = Beef::new();
        one.merge_raw_tx(data.to_vec(), bump_index);
        let no_inputs = one.txs[0].has_no_inputs();
        let txid = one.txs[0].txid();
        let verdict = one.clone().verify_structure();
        let held = matches!(
            verdict,
            Err(Kind::TrailingBytes | Kind::Truncated | Kind::BadVarint)
        );
        if refused {
            assert!(
                held || (no_inputs && verdict == Err(Kind::NoInputs)),
                "{verdict:?}"
            );
            assert!(!one.is_valid(false) && !one.is_valid(true));
            assert!(!one.verify_valid(false).valid);
        } else {
            assert!(!held, "{verdict:?} for one transaction");
        }

        let mut sorted = one.clone();
        let sr = sorted.sort_txs();
        assert_eq!(sr.not_valid.contains(&txid), refused, "sort_txs");
        let field = Some(bump_index.is_some() && !refused);
        assert_eq!(sorted.txs[0].is_valid, field, "the is_valid field");

        // Under a BUMP index over the entry's own hash the entry is valid
        // exactly when it is one transaction with an input and an output.
        if bump_index.is_some() {
            let mut proven = Beef::new();
            proven.merge_bump(MerklePath::from_coinbase_txid(&txid, 1));
            proven.merge_raw_tx(data.to_vec(), bump_index);
            let want = !refused && !no_inputs && !no_outputs;
            assert_eq!(proven.clone().is_valid(false), want, "is_valid(false)");
            assert_eq!(proven.clone().is_valid(true), want, "is_valid(true)");
            assert_eq!(proven.verify_valid(false).valid, want, "verify_valid");
        }
    }

    // The hinted parse reads exactly what the parse reads.
    let hints = BeefLimits {
        max_txs: 64,
        max_bumps: 8,
    };
    let hinted = Beef::from_binary_with_limits(data, &hints);

    // The streaming reader gives a verdict on any bytes and never panics;
    // with no header it accepts no BUMP.
    let headers: HashMap<u64, [u8; 32]> = HashMap::new();
    if let Ok(Verdict::Valid { roots, .. }) = verify_stream_structure(data, &headers, None) {
        assert!(roots.is_empty(), "a root was accepted with no header");
    }

    // Fuzz the BEEF parse and every walk over it - none may panic
    let Ok(mut beef) = Beef::from_binary(data) else {
        assert!(
            hinted.is_err(),
            "the hinted parse accepted what the parse refused"
        );
        return;
    };
    let hinted = hinted.expect("the hinted parse refused what the parse accepted");
    assert_eq!(hinted.txs.len(), beef.txs.len());

    // Link every subject (the iterative walk), serialize, clone and drop it
    let txids: Vec<String> = beef.txs.iter().map(|t| t.txid()).collect();
    for txid in &txids {
        if let Some(tx) = beef.find_atomic_transaction(txid) {
            let _ = tx.to_beef(true);
            let _ = tx.to_atomic_beef(true);
            let copy = tx.clone();
            drop(tx);
            let _ = copy.id();
        }
    }

    // Sort, validate and round-trip
    let _ = beef.verify_valid(true);
    let bytes = beef.to_binary();
    let _ = Beef::from_binary(&bytes);
    // The writer's order (BRC-62): a transaction read from a BEEF carries
    // its linked sources, and the BEEF its door writes ends with it — the
    // no-txid read of those bytes takes the same transaction back; the atomic
    // door's closure ends with the subject (the sorted closure, the subject
    // moved last), so the same read of them takes it too.
    if let Ok(tx) = Transaction::from_beef(data, None) {
        let id = tx.id();
        if let Ok(door) = tx.to_beef(true) {
            assert_eq!(
                Transaction::from_beef(&door, None).map(|t| t.id()),
                Ok(id.clone()),
                "the transaction door's BEEF ends with the transaction"
            );
        }
        if let Ok(bytes) = tx.to_atomic_beef(true) {
            assert_eq!(
                Transaction::from_beef(&bytes, None).map(|t| t.id()),
                Ok(id.clone()),
                "the atomic door's BEEF ends with the transaction"
            );
            assert_eq!(
                Beef::from_binary(&bytes).map(|b| b.txs.last().map(|t| t.txid())),
                Ok(Some(id)),
                "the atomic door's closure ends with the transaction"
            );
        }
    }
    let _ = Transaction::from_atomic_beef(data);

    // The reader that runs scripts, every root carried: a valid verdict
    // spends a coin locked by `a9 14 <20 bytes> 87` only where the node's
    // pay-to-script-hash step, built by hand, succeeds (GHSA-fr33-7jw7-mwwh).
    if let (Ok(Verdict::Valid { .. }), Ok(beef)) = (
        verify_stream(data, &EveryRoot, None),
        Beef::from_binary(data),
    ) {
        let parsed = |e: &bsv_rs::transaction::BeefTx| {
            (e.tx().cloned()).or_else(|| Transaction::from_binary(e.raw_tx()?).ok())
        };
        for tx in beef
            .txs
            .iter()
            .filter(|e| !e.has_proof())
            .filter_map(parsed)
        {
            for (vin, input) in tx.inputs.iter().enumerate() {
                let source = (input.source_txid.as_deref())
                    .and_then(|id| beef.find_txid(id))
                    .and_then(parsed);
                let Some(coin) = source.and_then(|s| {
                    let output = s.outputs.get(input.source_output_index as usize)?;
                    Some((
                        output.locking_script.to_binary(),
                        output.satoshis.unwrap_or(0),
                    ))
                }) else {
                    continue;
                };
                let step = redeem_by_hand(&tx, vin, &coin.0, coin.1);
                assert_ne!(
                    step,
                    Some(false),
                    "a P2SH-shaped coin spent valid without its step"
                );
            }
        }
    }
});
