#![no_main]
//! `MerklePath` (BRC-74 BUMP) on arbitrary bytes: the binary and hex parsers,
//! then every walk a parsed path offers (each leaf's root, `combine` with
//! itself, `trim`, `contains`). The assertion is that each returns; the
//! target also checks a round trip: a parsed path's bytes parse again, to the
//! same bytes and the same root for each txid.
use bsv_rs::transaction::MerklePath;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = MerklePath::from_hex(text);
    }
    let Ok(path) = MerklePath::from_binary(data) else {
        return;
    };

    let bytes = path.to_binary();
    let again = MerklePath::from_binary(&bytes).expect("a path's own bytes parse");
    assert_eq!(again.to_binary(), bytes, "the bytes are not a fixed point");
    assert_eq!(
        MerklePath::from_hex(&path.to_hex())
            .map(|p| p.to_binary())
            .ok(),
        Some(bytes)
    );

    let txids = path.txids();
    let _ = path.compute_root(None);
    for txid in &txids {
        let root = path.compute_root(Some(txid));
        assert_eq!(
            root.as_ref().ok(),
            again.compute_root(Some(txid)).as_ref().ok()
        );
        assert!(path.contains(txid));
    }
    let _ = path.compute_root(Some("00"));
    let _ = path.compute_root(Some(&"ab".repeat(32)));

    let mut combined = path.clone();
    let _ = combined.combine(&again);
    let _ = combined.to_binary();
    let mut trimmed = path.clone();
    trimmed.trim();
    let _ = trimmed.to_binary();
    if let [txid, ..] = &txids[..] {
        let mut marked = path.clone();
        let _ = marked.contains_and_mark(txid);
        let _ = marked.compute_root(Some(txid));
    }
});
