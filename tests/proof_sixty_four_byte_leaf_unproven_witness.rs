//! A transaction that serializes to exactly 64 bytes has a txid that cannot be
//! told from a merkle inner node (two concatenated 32-byte child hashes hashed
//! the same way), so a merkle path binding such a transaction to a block by
//! its txid alone is indistinguishable from a path over a shallower tree.
//! CVE-2017-12842.
//!
//! The rule the SPV/BEEF proof doors share is NOT a refusal of the length: a
//! transaction of this length is never taken as PROVEN by its path. At every
//! door it is judged as an UNPROVEN transaction is — its inputs' sources must
//! be present and verify — and the path offered for it is simply not used. A
//! forged entry of this shape (its serialized input prevout pinned by its own
//! bytes to a value no supplied source can carry) then meets the door's own
//! answer for an unproven transaction whose input names no reachable source: a
//! refusal. An honest holder of a genuine 64-byte transaction still verifies
//! it by supplying its input's source, the way any unproven transaction's is.
//!
//! The fixtures are built by the crate's own codec (`Transaction::from_binary`
//! round-tripped by `to_binary`, `MerklePath::compute_root`) and a
//! `MockChainTracker` of the test's own making that confirms exactly one root.
//! No network, no wall clock, no path or line-ending dependence.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a failed unwrap is the test failing

use bsv_rs::transaction::{
    verify_stream, Beef, BeefTx, MerklePath, MerklePathLeaf, MockChainTracker, Transaction,
};

// A genuine, valid transaction that serializes to exactly 64 bytes: 1 input
// (empty script, prevout 0x11..11), 1 output (4-byte script), locktime.
// 4 + 1 + (32+4+1+4) + 1 + (8+1+4) + 4 = 64. Its input's source (txid 0x11..11)
// is a value no transaction can be produced for without a second preimage, so
// a forged entry of this shape can never supply it.
const SIXTYFOUR_BYTE_TX: &str = concat!(
    "01000000",
    "01",
    "1111111111111111111111111111111111111111111111111111111111111111",
    "00000000",
    "00",
    "ffffffff",
    "01",
    "0000000000000000",
    "04",
    "51525354",
    "00000000",
);

// A genuine transaction one byte longer (65 bytes): a 5-byte output script. Its
// proof is honest and is used as a proof, exactly as before the rule.
const SIXTYFIVE_BYTE_TX: &str = concat!(
    "01000000",
    "01",
    "1111111111111111111111111111111111111111111111111111111111111111",
    "00000000",
    "00",
    "ffffffff",
    "01",
    "0000000000000000",
    "05",
    "5152535455",
    "00000000",
);

// A proven parent of 61 bytes: 1 input, 1 output of 1000 satoshis with an
// anyone-can-spend (OP_TRUE) locking script. Not 64 bytes, so its own proof is
// used normally.
const PARENT_TX: &str = concat!(
    "01000000",
    "01",
    "2222222222222222222222222222222222222222222222222222222222222222",
    "00000000",
    "00",
    "ffffffff",
    "01",
    "e803000000000000",
    "01",
    "51",
    "00000000",
);

fn hex_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn tx_from_hex(hex: &str) -> Transaction {
    let bytes = hex_bytes(hex);
    let tx = Transaction::from_binary(&bytes).expect("a valid transaction parses");
    assert_eq!(
        tx.to_binary().len(),
        bytes.len(),
        "re-serializes to its length"
    );
    tx
}

fn leaf_txid(offset: u64, hash: &str) -> MerklePathLeaf {
    MerklePathLeaf::new_txid(offset, hash.to_string())
}
fn leaf_hash(offset: u64, hash: &str) -> MerklePathLeaf {
    MerklePathLeaf::new(offset, hash.to_string())
}
fn path(bh: u32, levels: Vec<Vec<MerklePathLeaf>>) -> MerklePath {
    MerklePath::new(bh, levels.clone())
        .unwrap_or_else(|_| MerklePath::new_unchecked(bh, levels).unwrap())
}

// A short, single-level path that treats `leaf` at offset 0 as a level-0 txid,
// siblinged by a hash, and a tracker that confirms that path's root at `bh`,
// deep enough that the offset-0 coinbase-maturity rule (#734) does not fire.
fn short_proof(leaf: &str, bh: u32) -> (MerklePath, MockChainTracker) {
    let m = "ab".repeat(32);
    let p = path(bh, vec![vec![leaf_txid(0, leaf), leaf_hash(1, &m)]]);
    let root = p.compute_root(Some(leaf)).expect("root");
    let mut tracker = MockChainTracker::new(bh + 100_000);
    tracker.add_root(bh, root);
    (p, tracker)
}

// Build F spending parent P's output 0 with an empty unlocking script; F
// serializes to exactly 64 bytes whatever P's txid is (the length does not
// depend on the prevout value).
fn child_spending(parent: &Transaction) -> Transaction {
    let mut wire = hex_bytes(&parent.id()); // display (big-endian) order
    wire.reverse(); // the wire carries the prevout in internal order
    let prevout: String = wire.iter().map(|b| format!("{b:02x}")).collect();
    let f_hex = format!(
        "{}{}{}{}{}{}{}{}{}{}{}",
        "01000000",
        "01",
        prevout,
        "00000000",
        "00",
        "ffffffff",
        "01",
        "0000000000000000",
        "04",
        "51525354",
        "00000000",
    );
    let mut f = tx_from_hex(&f_hex);
    assert_eq!(f.to_binary().len(), 64, "the child is 64 bytes");
    f.inputs_mut()[0].source_transaction = Some(Box::new(parent.clone()));
    f
}

#[test]
fn a_sixty_four_byte_transaction_id_equals_a_merkle_inner_node() {
    let f = tx_from_hex(SIXTYFOUR_BYTE_TX);
    let bytes = f.to_binary();
    assert_eq!(bytes.len(), 64);
    let mut a = bytes[0..32].to_vec();
    a.reverse();
    let a = a.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let mut b = bytes[32..64].to_vec();
    b.reverse();
    let b = b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let parent = path(800_000, vec![vec![leaf_txid(0, &a), leaf_hash(1, &b)]])
        .compute_root(Some(&a))
        .expect("parent");
    assert_eq!(
        parent,
        f.id(),
        "a 64-byte transaction's id equals a merkle inner node"
    );
}

// --- The forgery is refused at every bytes-holding door (RED before the rule:
// the base accepts it as proven). ---

#[tokio::test]
async fn a_forged_sixty_four_byte_proven_leaf_is_refused_at_transaction_verify() {
    let mut f = tx_from_hex(SIXTYFOUR_BYTE_TX);
    let (p, tracker) = short_proof(&f.id(), 800_000);
    f.merkle_path = Some(p);
    let verdict = f.verify(&tracker, None, None).await;
    assert!(
        verdict.is_err(),
        "a forged 64-byte proven leaf (no input source) must be refused, got {verdict:?}"
    );
}

#[test]
fn a_forged_sixty_four_byte_proven_leaf_is_refused_at_beef_verify_valid() {
    let f = tx_from_hex(SIXTYFOUR_BYTE_TX);
    let (p, _tracker) = short_proof(&f.id(), 800_000);
    let mut beef = Beef::new();
    beef.bumps.push(p);
    beef.txs.push(BeefTx::from_tx(f, Some(0)));
    assert!(
        !beef.verify_valid(false).valid,
        "the in-memory BEEF verdict door must refuse a forged 64-byte proven leaf"
    );
}

// This door the length-refusal fix could NOT close on the stable line (its
// verdict set is sealed); the unproven rule closes it with an existing answer.
#[test]
fn a_forged_sixty_four_byte_proven_leaf_is_refused_by_the_streaming_reader() {
    let f = tx_from_hex(SIXTYFOUR_BYTE_TX);
    let (p, tracker) = short_proof(&f.id(), 800_000);
    let mut beef = Beef::new();
    beef.bumps.push(p);
    beef.txs.push(BeefTx::from_tx(f, Some(0)));
    let bytes = beef.to_binary().expect("beef bytes");
    let verdict = verify_stream(&bytes[..], &tracker, None).expect("a slice never fails to read");
    assert!(
        !verdict.is_valid(),
        "the streaming verifier must not say Valid for a forged 64-byte proven leaf, got {verdict:?}"
    );
}

#[test]
fn a_forged_sixty_four_byte_proven_leaf_is_refused_by_the_structure_reader() {
    let f = tx_from_hex(SIXTYFOUR_BYTE_TX);
    let (p, _tracker) = short_proof(&f.id(), 800_000);
    let mut beef = Beef::new();
    beef.bumps.push(p);
    beef.txs.push(BeefTx::from_tx(f, Some(0)));
    assert!(
        beef.verify_structure().is_err(),
        "the in-memory structure reader must refuse a forged 64-byte proven leaf"
    );
}

// --- The honest holder of a genuine 64-byte transaction. ---

// With its input's source supplied and proven, it verifies as an unproven
// transaction (its path is not used, its spend of the real parent is checked).
#[tokio::test]
async fn a_genuine_sixty_four_byte_transaction_verifies_when_its_input_source_is_supplied() {
    let mut parent = tx_from_hex(PARENT_TX);
    let (pp, tracker) = short_proof(&parent.id(), 700_000);
    parent.merkle_path = Some(pp);
    let f = child_spending(&parent);
    let verdict = f.verify(&tracker, None, None).await;
    assert_eq!(
        verdict.ok(),
        Some(true),
        "a genuine 64-byte transaction verifies when its source is supplied and proven"
    );
}

// With its merkle proof ALONE (no input source supplied), it is not proven: it
// is judged as unproven, and its input names no reachable source — refused,
// the same answer any unproven transaction gets. (RED before: the base accepts
// the proof.)
#[tokio::test]
async fn a_genuine_sixty_four_byte_transaction_with_its_proof_alone_is_not_proven() {
    let mut f = tx_from_hex(SIXTYFOUR_BYTE_TX);
    let (p, tracker) = short_proof(&f.id(), 800_000);
    f.merkle_path = Some(p);
    let verdict = f.verify(&tracker, None, None).await;
    assert!(
        verdict.is_err(),
        "a 64-byte transaction with its proof alone is not proven, got {verdict:?}"
    );
}

// --- Nothing is taken from an honest caller whose transaction is not 64 bytes:
// its proof is used exactly as before, at every door. ---

#[tokio::test]
async fn an_honest_proof_of_a_non_sixty_four_byte_transaction_still_verifies() {
    let mut f = tx_from_hex(SIXTYFIVE_BYTE_TX);
    assert_eq!(f.to_binary().len(), 65);
    let (p, tracker) = short_proof(&f.id(), 800_000);
    f.merkle_path = Some(p.clone());
    assert_eq!(
        f.verify(&tracker, None, None).await.ok(),
        Some(true),
        "an honest 65-byte proof still verifies at Transaction::verify"
    );

    let mut beef = Beef::new();
    beef.bumps.push(p);
    beef.txs
        .push(BeefTx::from_tx(tx_from_hex(SIXTYFIVE_BYTE_TX), Some(0)));
    let bytes = beef.to_binary().expect("beef bytes");
    assert!(
        beef.verify_valid(false).valid,
        "an honest 65-byte leaf is still valid in memory"
    );
    assert!(
        verify_stream(&bytes[..], &tracker, None)
            .expect("read")
            .is_valid(),
        "an honest 65-byte leaf is still valid at the streaming reader"
    );
}

// A 64-byte entry carried as RAW BYTES ALONE (a `from_raw_tx` entry, no parsed
// transaction in hand) — the shape `merge_beef`'s source entries and a
// framed-bytes reader take. The length rule reads such an entry's length from
// its raw bytes (the raw-bytes arm of `BeefTx::serialized_len`), not from a
// parse, so the forged entry is judged unproven and its absent input source
// refuses it. Without that arm the entry's length would read as unknown, its
// proof would wrongly vouch, and the forgery would be accepted here.
#[test]
fn a_forged_sixty_four_byte_raw_only_entry_is_refused_at_beef_verify_valid() {
    let raw = hex_bytes(SIXTYFOUR_BYTE_TX);
    assert_eq!(raw.len(), 64);
    let txid = tx_from_hex(SIXTYFOUR_BYTE_TX).id();
    let (p, _tracker) = short_proof(&txid, 800_000);
    let mut beef = Beef::new();
    beef.bumps.push(p);
    beef.txs
        .push(BeefTx::from_raw_tx(raw, Some(0)).expect("framed as one transaction"));
    assert!(
        !beef.verify_valid(false).valid,
        "a 64-byte entry carried as raw bytes alone is judged unproven by the \
         raw-bytes arm of the length rule; its absent input source refuses it"
    );
}
