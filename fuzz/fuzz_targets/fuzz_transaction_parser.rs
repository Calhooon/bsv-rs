#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz transaction parsing - should never panic
    if let Ok(tx) = bsv_rs::primitives::bsv::sighash::parse_transaction(data) {
        // If parsing succeeded, exercise fields
        let _ = tx.version;
        let _ = tx.locktime;
        let _ = tx.inputs.len();
        let _ = tx.outputs.len();
    }

    // Fuzz Transaction::from_binary
    if let Ok(tx) = bsv_rs::transaction::Transaction::from_binary(data) {
        // Roundtrip
        let binary = tx.to_binary();
        let _ = bsv_rs::transaction::Transaction::from_binary(&binary);

        // Exercise methods
        let _ = tx.id();
        let _ = tx.to_hex();
    }

    // Fuzz MerklePath parsing
    if let Ok(mp) = bsv_rs::transaction::MerklePath::from_binary(data) {
        let _ = mp.to_binary();
    }
});
