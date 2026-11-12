#![no_main]
#![allow(deprecated)]
use std::collections::HashMap;

use bsv_rs::transaction::{
    verify_stream_structure, Beef, BeefLimits, Kind, MerklePath, Transaction, Verdict,
};
use libfuzzer_sys::fuzz_target;

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
});
