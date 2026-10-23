#![no_main]
#![allow(deprecated)]
use std::collections::HashMap;

use bsv_rs::transaction::{
    verify_stream, verify_stream_structure, Beef, BeefLimits, Headers, Transaction, Verdict,
};
use libfuzzer_sys::fuzz_target;

/// Headers that carry every root, so a BUMP's root is never the refusal and
/// the reader walks on to the doors after it (the Lean's `Reason`s).
struct EveryRoot;

impl Headers for EveryRoot {
    fn carries(&self, _height: u64, _root: &[u8; 32]) -> bool {
        true
    }
}

fuzz_target!(|data: &[u8]| {
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
    let _ = verify_stream_structure(data, EveryRoot, None);
    let _ = verify_stream(data, EveryRoot, None);

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
    let _ = Transaction::from_beef(data, None);
    let _ = Transaction::from_atomic_beef(data);
});
