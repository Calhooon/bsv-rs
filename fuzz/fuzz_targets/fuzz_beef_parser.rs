#![no_main]
#![allow(deprecated)]
use std::collections::HashMap;

use bsv_rs::transaction::{
    verify_stream, verify_stream_structure, Beef, BeefLimits, BeefStream, Element, Headers, Kind,
    Transaction, Verdict,
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

/// The root of the leading BUMP at each height: the one root a chain
/// carries there, the rule the whole path reads from the BEEF alone.
fn leading_roots(data: &[u8]) -> HashMap<u64, [u8; 32]> {
    let mut roots = HashMap::new();
    for element in BeefStream::new(data) {
        match element {
            // A chain's heights: the in-memory height is a `u32`.
            Ok(Element::Bump(bump)) if u32::try_from(bump.block_height).is_ok() => {
                roots.entry(bump.block_height).or_insert(bump.root);
            }
            Ok(Element::Bump(_)) => {}
            _ => break,
        }
    }
    roots
}

fn display(hash: &[u8; 32]) -> String {
    let mut bytes = *hash;
    bytes.reverse();
    bsv_rs::primitives::to_hex(&bytes)
}

/// The kind and offset a parse refusal names, in the stream's words.
fn named(text: &str) -> Option<(u64, Kind)> {
    let rest = &text[text.find("invalid BEEF at byte ")? + "invalid BEEF at byte ".len()..];
    let (offset, reason) = rest.split_once(": ")?;
    let name: String = reason
        .chars()
        .take_while(char::is_ascii_alphanumeric)
        .collect();
    let kind = Kind::ALL.into_iter().find(|k| format!("{k:?}") == name)?;
    Some((offset.parse().ok()?, kind))
}

/// The two entry points agree (bsv-rs#86; `tests/beef_two_readers_agree.rs`):
/// `Beef::from_binary` then `verify_structure`, and `verify_stream_structure`
/// under the leading roots, accept the same inputs with the same roots and
/// refuse the rest with the same kind, at the same offset when the parse
/// names one. No difference is stated: an input naming a parent held after
/// it is refused by both.
fn the_two_readers_agree(data: &[u8]) {
    let stream = verify_stream_structure(data, &leading_roots(data), None).expect("a slice reads");
    let parsed = Beef::from_binary(data);
    match (parsed, &stream) {
        (Err(e), Verdict::Invalid { offset, kind, .. }) => {
            let text = e.to_string();
            assert_eq!(
                named(&text),
                Some((*offset, *kind)),
                "the parse refuses as the stream: {text}; {stream:?}"
            );
        }
        (Err(e), _) => panic!("the parse refused what the stream accepts: {e}; {stream:?}"),
        (Ok(mut beef), _) => match (beef.verify_structure(), &stream) {
            (Ok(roots), Verdict::Valid { roots: streamed, .. }) => {
                let mut whole: Vec<(u64, String)> =
                    roots.into_iter().map(|(h, r)| (u64::from(h), r)).collect();
                let mut streamed: Vec<(u64, String)> =
                    streamed.iter().map(|(h, r)| (*h, display(r))).collect();
                whole.sort();
                streamed.sort();
                streamed.dedup();
                assert_eq!(whole, streamed, "the roots");
            }
            (Err(kind), Verdict::Invalid { kind: k, .. }) => {
                assert_eq!(kind, *k, "the structure refuses as the stream");
            }
            (answer, _) => panic!("the two readers disagree: {answer:?}; {stream:?}"),
        },
    }
}

fuzz_target!(|data: &[u8]| {
    the_two_readers_agree(data);

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
