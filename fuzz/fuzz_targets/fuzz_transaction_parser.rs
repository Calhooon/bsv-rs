#![no_main]
use libfuzzer_sys::fuzz_target;

#[path = "support/identity_law.rs"]
mod identity_law;

/// Every output amount below 2^53 (#844).
fn assert_safe_amounts(tx: &bsv_rs::transaction::Transaction) {
    for output in tx.outputs() {
        assert!(
            output.satoshis.is_none_or(|s| s < 1 << 53),
            "a reader accepted an output of 2^53 satoshis or more (#844)"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    // Fuzz transaction parsing - should never panic
    if let Ok(tx) = bsv_rs::primitives::bsv::sighash::parse_transaction(data) {
        // If parsing succeeded, exercise fields
        let _ = tx.version;
        let _ = tx.locktime;
        let _ = tx.inputs.len();
        let _ = tx.outputs.len();
    }

    // Fuzz Transaction::from_binary: a transaction it returns is exactly the
    // buffer, so it serializes to the buffer and its txid is the buffer's
    // hash (#840: bytes after the lock time were kept and hashed).
    if let Ok(tx) = bsv_rs::transaction::Transaction::from_binary(data) {
        let binary = tx.to_binary();
        assert_eq!(
            binary, data,
            "from_binary returned a transaction other than its buffer"
        );
        let fresh = bsv_rs::transaction::Transaction::with_params(
            tx.version(),
            tx.inputs().to_vec(),
            tx.outputs().to_vec(),
            tx.lock_time(),
        );
        assert_eq!(
            fresh.to_binary(),
            data,
            "the fields serialize to the buffer"
        );
        assert_eq!(fresh.id(), tx.id(), "the txid is the fields' hash");
        let again = bsv_rs::transaction::Transaction::from_binary(&binary)
            .expect("a transaction's own bytes read back");
        assert_eq!(again.id(), tx.id());
        let _ = tx.to_hex();
        // No accepted transaction holds an amount the reference cannot
        // hold (#844: 2^53 satoshis or more is refused in its words).
        assert_safe_amounts(&tx);
        // #843's law under edits the input chooses (#869's fold).
        identity_law::edits_keep_the_law(tx, data);
    }

    // The reader form reads one transaction from the front and leaves the
    // rest: what it read is a prefix of the buffer, and that prefix alone
    // reads to the same transaction (#840).
    let mut reader = bsv_rs::primitives::Reader::new(data);
    if let Ok(tx) = bsv_rs::transaction::Transaction::from_reader(&mut reader) {
        assert_safe_amounts(&tx);
        let used = data.len() - reader.remaining();
        assert_eq!(
            tx.to_binary(),
            &data[..used],
            "the reader form's bytes are the prefix read"
        );
        let alone = bsv_rs::transaction::Transaction::from_binary(&data[..used])
            .expect("the prefix the reader form read is one transaction");
        assert_eq!(alone.id(), tx.id());
        assert_eq!(
            bsv_rs::transaction::Transaction::from_binary(data).is_ok(),
            reader.remaining() == 0,
            "from_binary accepts exactly the buffers the reader form reads whole"
        );
    }

    // The hex door is the binary door over the decoded bytes: the buffer's
    // hex (either case) reads to the same verdict and the same transaction
    // (#840's fold: `from_hex` was not fuzzed directly).
    let hex = bsv_rs::primitives::to_hex(data);
    let by_binary = bsv_rs::transaction::Transaction::from_binary(data);
    for text in [hex.clone(), hex.to_uppercase()] {
        let by_hex = bsv_rs::transaction::Transaction::from_hex(&text);
        assert_eq!(
            by_hex.is_ok(),
            by_binary.is_ok(),
            "from_hex agrees with from_binary"
        );
        if let (Ok(a), Ok(b)) = (&by_hex, &by_binary) {
            assert_eq!(a.id(), b.id());
            assert_eq!(a.to_hex(), hex, "from_hex caches the lower-case text");
        }
    }
    // Arbitrary text through both hex doors: never a panic.
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = bsv_rs::transaction::Transaction::from_hex(text);
        let _ = bsv_rs::transaction::Transaction::from_hex_ef(text);
    }

    // EF (BRC-30): a transaction `from_ef` returns is exactly its buffer, so
    // `to_ef` writes the buffer back (every field is read and written in the
    // same order, the varints canonical, the scripts held as read, the
    // source amount and script on the placeholder source at the index read),
    // and its plain form reads back to the same txid; `from_hex_ef` over the
    // buffer's hex agrees (#840's fold: no target reached the EF doors).
    let by_ef = bsv_rs::transaction::Transaction::from_ef(data);
    let by_hex_ef = bsv_rs::transaction::Transaction::from_hex_ef(&hex);
    assert_eq!(
        by_hex_ef.is_ok(),
        by_ef.is_ok(),
        "from_hex_ef agrees with from_ef"
    );
    if let Ok(tx) = by_ef {
        assert_safe_amounts(&tx);
        for input in tx.inputs() {
            assert!(
                input.source_satoshis().is_none_or(|s| s < 1 << 53),
                "from_ef accepted a source amount of 2^53 or more (#844)"
            );
        }
        let ef = tx
            .to_ef()
            .expect("a transaction read from EF carries every source EF writes");
        assert_eq!(
            ef, data,
            "from_ef returned a transaction other than its buffer"
        );
        let plain = bsv_rs::transaction::Transaction::from_binary(&tx.to_binary())
            .expect("an EF transaction's plain bytes read back");
        assert_eq!(plain.id(), tx.id());
        assert_eq!(by_hex_ef.expect("agreed above").id(), tx.id());
    }

    // Fuzz MerklePath parsing
    if let Ok(mp) = bsv_rs::transaction::MerklePath::from_binary(data) {
        mp.to_binary()
            .expect("a path the reader accepted holds only states a BUMP writes (#817)");
    }

    // Metered cursors carry the transaction work total across a resume (#519).
    if let Ok(cursor) = bsv_rs::transaction::Cursor::from_binary(data) {
        let _ = bsv_rs::transaction::Cursor::from_binary(&cursor.to_binary());
    }
});
