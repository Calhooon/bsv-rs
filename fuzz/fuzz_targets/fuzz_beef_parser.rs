#![no_main]
use bsv_rs::transaction::{Beef, BeefLimits, Transaction};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The bounded parse must agree with the unbounded one inside its limits.
    let limits = BeefLimits {
        max_txs: 64,
        max_bumps: 8,
        max_bytes: data.len(),
    };
    let bounded = Beef::from_binary_with_limits(data, &limits);

    // Fuzz the BEEF parse and every walk over it - none may panic
    let Ok(mut beef) = Beef::from_binary(data) else {
        assert!(bounded.is_err(), "the bounded parse accepted what the parse refused");
        return;
    };
    if let Ok(b) = bounded {
        assert_eq!(b.txs.len(), beef.txs.len());
    }

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
