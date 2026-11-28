#![cfg(test)]
//! CVE-2017-12842 at the identity lookup-evidence door.
//!
//! The evidence walk ([`assert_unconfirmed_graph`]) stops requiring an entry's
//! parents the moment a BUMP of the BEEF names its txid
//! (`beef.find_bump(&id).is_some()`). A transaction that serializes to exactly
//! 64 bytes has a txid that cannot be told from a merkle inner node, so a BUMP
//! naming it is not proof that it is in a block any more than at the
//! transaction proof doors. This door reads the same shared rule
//! (`crate::transaction::proof_ambiguity::is_ambiguous_merkle_leaf`): a 64-byte
//! entry is judged as unproven here too — its parents are required, like any
//! unconfirmed transaction's — so a forged 64-byte subject named only by a BUMP
//! is refused
//! with the door's own `invalid-evidence`. A genuine subject of any other
//! length is admitted exactly as before; an honest holder of a genuine 64-byte
//! confirmed ancestor supplies that ancestor's own parents.

use super::*;
use crate::transaction::{MerklePath, MerklePathLeaf};

// A valid transaction serializing to exactly 64 bytes: 1 input (empty script,
// prevout 0x11..11, a value no source can be produced for without a second
// preimage), 1 output (4-byte script), locktime. 4+1+(32+4+1+4)+1+(8+1+4)+4=64.
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

// A genuine transaction one byte longer (65 bytes): a 5-byte output script.
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

fn hex_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

// A single-level BUMP that names `txid` at offset 0, siblinged by a hash. The
// evidence door only asks whether a BUMP names the txid (`find_bump`), not that
// its root is confirmed, so the sibling hash and block height are arbitrary.
fn bump_naming(txid: &str) -> MerklePath {
    let m = "ab".repeat(32);
    let levels = vec![vec![
        MerklePathLeaf::new_txid(0, txid.to_string()),
        MerklePathLeaf::new(1, m),
    ]];
    MerklePath::new(800_000, levels.clone())
        .unwrap_or_else(|_| MerklePath::new_unchecked(800_000, levels).unwrap())
}

// A BEEF whose only entry is `tx_hex`, named by a BUMP — the shape an evidence
// subject takes when a lookup host claims it confirmed with a merkle proof and
// supplies none of its parents.
fn beef_with_bumped_subject(tx_hex: &str) -> Vec<u8> {
    let raw = hex_bytes(tx_hex);
    let tx = Transaction::from_binary(&raw).expect("a valid transaction parses");
    assert_eq!(
        tx.to_binary().len(),
        raw.len(),
        "re-serializes to its length"
    );
    let bump = bump_naming(&tx.id());
    let mut beef = Beef::new();
    beef.bumps.push(bump);
    beef.txs.push(BeefTx::from_tx(tx, Some(0)));
    beef.to_binary().expect("the BEEF is writable")
}

#[test]
fn a_forged_sixty_four_byte_bump_named_subject_is_refused_by_the_evidence_walk() {
    let bytes = beef_with_bumped_subject(SIXTYFOUR_BYTE_TX);
    let verdict = parse_evidence(&bytes, 0);
    assert!(
        verdict.is_err(),
        "a 64-byte subject named only by a BUMP (no parents supplied) must not be \
         taken as confirmed by the evidence walk, got {verdict:?}"
    );
    assert_eq!(
        verdict.unwrap_err().code,
        Code::InvalidEvidence,
        "it is refused with the door's own invalid-evidence, the way any unproven \
         subject whose parents are absent is"
    );
}

#[test]
fn a_genuine_sixty_five_byte_bump_named_subject_is_still_admitted() {
    let bytes = beef_with_bumped_subject(SIXTYFIVE_BYTE_TX);
    let verdict = parse_evidence(&bytes, 0);
    assert!(
        verdict.is_ok(),
        "a subject of any length other than 64 bytes, named by a BUMP, is admitted \
         exactly as before the rule — nothing taken from an honest caller, got {verdict:?}"
    );
}
