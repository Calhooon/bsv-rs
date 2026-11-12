#![no_main]
#![allow(deprecated)]
use std::collections::HashMap;

use bsv_rs::transaction::{
    verify_stream, verify_stream_structure, Beef, BeefLimits, BeefStream, BeefTx, Element, Headers,
    Kind, MerklePathLeaf, Transaction, Verdict,
};
use libfuzzer_sys::fuzz_target;

#[path = "support/identity_law.rs"]
mod identity_law;

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
            (
                Ok(roots),
                Verdict::Valid {
                    roots: streamed, ..
                },
            ) => {
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

/// `merge_beef`'s verdict from its pre-pass is the literal round trip's
/// (#621, after #817): the oracle (`Beef::merge_snapshot_oracle`, built
/// under the `internal-test-doors` feature this crate turns on, #869's
/// second fold) refuses in the same words, and after an `Ok`
/// the target merged from the source writes the bytes of the target merged
/// from the oracle's snapshot.
fn the_pre_pass_is_the_round_trip(source: &Beef) {
    let oracle = source.merge_snapshot_oracle();
    let mut merged = Beef::new();
    let ours = merged.merge_beef(source);
    match (ours, oracle) {
        (Ok(()), Ok(snapshot)) => {
            let mut by_snapshot = Beef::new();
            by_snapshot
                .merge_beef(&snapshot)
                .expect("the snapshot read back merges");
            assert_eq!(
                merged.to_binary().expect("a merged BEEF writes"),
                by_snapshot.to_binary().expect("a merged BEEF writes"),
                "the merged bytes are the snapshot's (#621)"
            );
        }
        (Err(ours), Err(oracle)) => assert_eq!(ours, oracle, "the refusal (#621)"),
        (ours, oracle) => panic!(
            "the pre-pass {ours:?} where the round trip {:?} (#621)",
            oracle.map(drop)
        ),
    }
}

/// The states a source can be put in through its public fields, chosen by
/// the input's bytes: a BUMP the reader refuses (no levels, an empty level 0,
/// 65 levels, a second leaf at an offset, an offset outside the tree, a
/// duplicate at an even offset, a leaf removed), a BUMP of a held height
/// with another root ahead of a refused one, a bad version word, a txid-only
/// entry of 62 digits, an entry edited through the deprecated door, a
/// parsed entry whose cached bytes are a held transaction twice (#621's
/// fold: the state `Transaction::from_binary` of such a buffer left until
/// #840, built since through `Transaction::with_cached_bytes_for_test`,
/// under `cfg(fuzzing)` alone; put in by `merge_transaction` and by a hand
/// push), and an output of 2^53 satoshis or more in an entry edited through
/// `edit_tx`, merged by `merge_transaction` and pushed by hand (#844).
fn hand_states(beef: &Beef, data: &[u8]) -> Vec<Beef> {
    let pick = |i: usize| data.get(i).copied().unwrap_or(0) as usize;
    let mut states = Vec::new();
    let n = beef.bumps.len();
    if n > 0 {
        let at = pick(0) % n;
        for k in 0..7 {
            let mut b = beef.clone();
            let path = &mut b.bumps[at].path;
            match k {
                0 => path.clear(),
                1 => {
                    if let Some(level) = path.first_mut() {
                        level.clear();
                    }
                }
                2 => path.resize_with(65, Vec::new),
                3 => {
                    let level = pick(1) % path.len().max(1);
                    if let Some(leaves) = path.get_mut(level) {
                        if let Some(leaf) = leaves.first().cloned() {
                            leaves.push(leaf);
                        }
                    }
                }
                4 => {
                    if let Some(leaf) = path.first_mut().and_then(|l| l.last_mut()) {
                        leaf.offset = u64::MAX >> (pick(2) % 64);
                    }
                }
                5 => {
                    if let Some(level) = path.first_mut() {
                        level.push(MerklePathLeaf::new_duplicate((pick(3) as u64) * 2));
                    }
                }
                _ => {
                    let height = pick(4) % path.len().max(1);
                    if let Some(level) = path.get_mut(height) {
                        if !level.is_empty() {
                            let i = pick(5) % level.len();
                            level.remove(i);
                        }
                    }
                }
            }
            states.push(b);
        }
        let mut b = beef.clone();
        let mut other = b.bumps[at].clone();
        if let Some(leaf) = other
            .path
            .first_mut()
            .and_then(|l| l.iter_mut().find(|l| l.hash.is_some()))
        {
            leaf.hash = Some("11".repeat(32));
        }
        let mut broken = b.bumps[at].clone();
        broken.path.clear();
        b.bumps.push(other);
        b.bumps.push(broken);
        states.push(b);
    }
    let mut b = beef.clone();
    b.version = 0xEFBE_0003;
    states.push(b);
    let mut b = beef.clone();
    b.merge_txid_only("ab".repeat(31));
    states.push(b);
    let mut b = beef.clone();
    if let Some(entry) = b.txs.iter_mut().find(|t| !t.is_txid_only()) {
        if let Some(tx) = entry.tx_mut() {
            tx.set_lock_time(tx.lock_time() ^ 1);
        }
        states.push(b);
    }
    if let Some(raw) = beef.txs.iter().find_map(|t| t.raw_tx().map(<[u8]>::to_vec)) {
        // A parsed entry caching a transaction and more (#621's fold): the
        // state `Transaction::from_binary` left on a doubled buffer until
        // #840, built through the fuzzing-only cache door since no public
        // door reaches it.
        let doubled = [raw.as_slice(), raw.as_slice()].concat();
        for door in 0..2 {
            let tx = Transaction::from_binary(&raw)
                .expect("a raw entry the reader collected is one transaction")
                .with_cached_bytes_for_test(doubled.clone());
            let mut b = beef.clone();
            if door == 0 {
                b.merge_transaction(tx);
            } else {
                b.txs.push(BeefTx::from_tx(tx, None));
            }
            states.push(b);
        }
    }
    // An output of 2^53 satoshis or more (#844), its amount from the input's
    // bytes: a read entry edited through `edit_tx`, and a transaction built
    // by hand merged as a parsed entry and pushed by hand.
    let amount = (1u64 << 53) + (pick(6) as u64) * (pick(7) as u64 + 1);
    let mut b = beef.clone();
    let edited = b
        .txs
        .iter()
        .find(|t| t.tx().is_some_and(|tx| !tx.outputs().is_empty()))
        .map(BeefTx::txid);
    if let Some(txid) = edited {
        if b.edit_tx(&txid, |tx| tx.outputs_mut()[0].satoshis = Some(amount))
            .is_ok()
        {
            states.push(b);
        }
    }
    if let Some(tx) = beef.txs.iter().find_map(|t| t.tx()) {
        let mut outputs = tx.outputs().to_vec();
        outputs.push(bsv_rs::transaction::TransactionOutput::new(
            amount,
            bsv_rs::script::LockingScript::new(),
        ));
        let by_hand =
            Transaction::with_params(tx.version(), tx.inputs().to_vec(), outputs, tx.lock_time());
        let mut b = beef.clone();
        b.merge_transaction(by_hand.clone());
        states.push(b);
        let mut b = beef.clone();
        b.txs.push(BeefTx::from_tx(by_hand, None));
        states.push(b);
    }
    states
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

    // #817: every BEEF the parse returns writes `Ok`, an `Ok` write reads
    // back to the same entries and BUMPs and is a fixed point, and so the
    // BEEF merges (`merge_beef`'s verdict is that round trip).
    let written = beef
        .to_binary()
        .expect("a BEEF the parse returned is refused by the writer (#817)");
    let mut back = Beef::from_binary(&written).expect("an Ok write does not read back (#817)");
    assert_eq!(back.txs.len(), beef.txs.len(), "the entries read back");
    assert_eq!(back.bumps.len(), beef.bumps.len(), "the BUMPs read back");
    assert_eq!(
        back.to_binary().expect("the read-back BEEF writes"),
        written,
        "a write of the read-back BEEF is the same bytes"
    );
    Beef::new()
        .merge_beef(&beef)
        .expect("a BEEF the parse returned merges (#817)");
    the_pre_pass_is_the_round_trip(&beef);
    for state in hand_states(&beef, data) {
        the_pre_pass_is_the_round_trip(&state);
    }

    // #843's law over every copy the BEEF stores, merged or not (#869's
    // second fold).
    identity_law::beef_copies_keep_the_law(&beef);

    // Link every subject (the iterative walk), serialize, clone and drop it
    let txids: Vec<String> = beef.txs.iter().map(|t| t.txid()).collect();
    for txid in &txids {
        if let Some(tx) = beef.find_atomic_transaction(txid) {
            let _ = tx.to_beef(true);
            let _ = tx.to_atomic_beef(true);
            let copy = tx.clone();
            drop(tx);
            // #843's law on the linked transaction under edits the input
            // chooses, its linked sources included (#869's fold).
            identity_law::edits_keep_the_law(copy, data);
        }
    }

    // Sort, validate and round-trip
    let _ = beef.verify_valid(true);
    if let Ok(bytes) = beef.to_binary() {
        Beef::from_binary(&bytes).expect("an Ok write does not read back (#817)");
    }
    // The writer's order (BRC-62): a transaction read from a BEEF carries
    // its linked sources, and the BEEF its door writes ends with it — the
    // no-txid read of those bytes takes the same transaction back; the atomic
    // door's closure ends with the subject (the sorted closure, the subject
    // moved last; 0.8.8's fold), so the same read of them takes it too.
    if let Ok(tx) = Transaction::from_beef(data, None) {
        let id = tx.id();
        if let Ok(bytes) = tx.to_beef(true) {
            assert_eq!(
                Transaction::from_beef(&bytes, None).map(|t| t.id()),
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
