//! A BEEF is judged in the order held (bsv-rs#240, the keeper's reading of
//! 2026-10-26): parents before children, as BRC-62 writes it (`5119a9b`
//! `transactions/0062.md:43`, `:72-74`, the validation process `:172-191`,
//! whose step 2.4.1 asks that a transaction without a path name a txid
//! already "in memory, and ... marked as valid"). A child written ahead of
//! the parent it spends is `InputNamesNoElement` at the child's input, from
//! all three readers: the stream (`verify_stream`, and
//! `verify_stream_structure`), `Beef::from_binary` then `verify_structure`,
//! and `Beef::verify_valid`.
//!
//! The reference accepts the children-first BEEF: `@bsv/sdk`'s
//! `Beef.verifyValid` sorts ahead of judging (`ts-stack@edf6e03`
//! `packages/sdk/src/transaction/Beef.ts:1054-1065`, `sortTxs` at `:1065`).
//! This crate does not follow it: the reference's writer sorts before it
//! serializes (`#ensureSortedForSerialization`, `:354-358`), so every BEEF it
//! writes is in BRC-62 order and the read-side sort is a leniency beside its
//! own writer; the stream cannot sort what it has not read, and the whole
//! path is a mode of the stream's reader (bsv-rs#86), one reading. 0.8's
//! `verify_valid` sorted ahead of judging and accepted this BEEF; 0.9.0 does
//! not. No behavior moves here: this file pins the reading.
//!
//! Both BEEFs are this crate's writer's: `Beef::to_binary` sorts before it
//! writes (parents before children, whatever order the entries were merged
//! in), so the children-first bytes are `Beef::to_writer` on the entries in
//! the order held, the child moved ahead of its parent.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use std::collections::HashMap;

use bsv_rs::primitives::{sha256d, Writer};
use bsv_rs::transaction::{
    verify_stream, verify_stream_structure, Beef, Kind, MerklePath, Reason, Verdict, BEEF_V1,
    BEEF_V2,
};

#[path = "support/beef_chain.rs"]
mod beef_chain;

use beef_chain::Hash32;

/// The parent (the deep chain's funding transaction) and the child that
/// spends its output 0 with an empty unlock of an `OP_TRUE` lock.
fn parent_and_child() -> (Vec<u8>, Vec<u8>) {
    let parent = beef_chain::funding();
    let child = beef_chain::spend(&sha256d(&parent), 1);
    (parent, child)
}

/// The parent's BUMP, built by this crate: a one-transaction block at the
/// chain's height.
fn parent_bump(parent: &[u8]) -> MerklePath {
    let mut txid = sha256d(parent);
    txid.reverse();
    MerklePath::from_coinbase_txid(
        &bsv_rs::primitives::to_hex(&txid),
        beef_chain::HEIGHT as u32,
    )
}

/// The headers: the parent's root (its txid, the block of one) at the height.
fn headers(parent: &[u8]) -> HashMap<u64, Hash32> {
    HashMap::from([(beef_chain::HEIGHT, sha256d(parent))])
}

/// The two entries merged children-first into a BEEF of `version`, the
/// parent proven by its BUMP.
fn merged_children_first(version: u32) -> Beef {
    let (parent, child) = parent_and_child();
    let mut beef = Beef::with_version(version);
    let bump = beef.merge_bump(parent_bump(&parent));
    beef.merge_raw_tx(child, None);
    beef.merge_raw_tx(parent, Some(bump));
    beef
}

/// The BEEF as this crate's writer writes it: `to_binary`, which sorts.
fn brc62_order(version: u32) -> Vec<u8> {
    merged_children_first(version).to_binary()
}

/// The same entries written in the order held, the child ahead of its parent:
/// `to_writer`, which does not sort.
fn children_first(version: u32) -> Vec<u8> {
    let beef = merged_children_first(version);
    let (parent, child) = parent_and_child();
    assert_eq!(
        beef.txs.iter().map(|t| t.txid()).collect::<Vec<_>>(),
        [&child, &parent].map(|raw| {
            let mut id = sha256d(raw);
            id.reverse();
            bsv_rs::primitives::to_hex(&id)
        }),
        "the entries are held child, then parent"
    );
    let mut writer = Writer::new();
    beef.to_writer(&mut writer);
    writer.into_bytes()
}

/// The stream offset of the child's one input (its previous txid): the
/// child's raw bytes in the BEEF, past their version and input count.
fn child_input_at(bytes: &[u8]) -> u64 {
    let (_, child) = parent_and_child();
    let at = bytes
        .windows(child.len())
        .position(|w| w == child.as_slice())
        .expect("the child's bytes are in the BEEF");
    (at + 4 + 1) as u64
}

#[test]
fn the_writer_puts_the_parent_ahead_of_the_child_whatever_the_merge_order() {
    for version in [BEEF_V1, BEEF_V2] {
        let sorted = brc62_order(version);
        let held = children_first(version);
        assert_eq!(sorted.len(), held.len(), "the same entries");
        assert_ne!(sorted, held, "two orders");
        let (parent, child) = parent_and_child();
        let find = |bytes: &[u8], raw: &[u8]| {
            bytes
                .windows(raw.len())
                .position(|w| w == raw)
                .expect("the entry")
        };
        assert!(find(&sorted, &parent) < find(&sorted, &child));
        assert!(find(&held, &child) < find(&held, &parent));
    }
}

#[test]
fn a_beef_in_brc62_order_passes_the_three_readers() {
    for version in [BEEF_V1, BEEF_V2] {
        let bytes = brc62_order(version);
        let (parent, _) = parent_and_child();
        let roots = vec![(beef_chain::HEIGHT, sha256d(&parent))];

        for verdict in [
            verify_stream(bytes.as_slice(), headers(&parent), None).unwrap(),
            verify_stream_structure(bytes.as_slice(), headers(&parent), None).unwrap(),
        ] {
            assert_eq!(
                verdict,
                Verdict::Valid {
                    subject: None,
                    roots: roots.clone()
                },
                "version {version:#x}"
            );
        }

        let mut beef = Beef::from_binary(&bytes).unwrap();
        let expected = HashMap::from([(
            beef_chain::HEIGHT as u32,
            sha256d(&parent)
                .iter()
                .rev()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
        )]);
        assert_eq!(beef.verify_structure(), Ok(expected.clone()));
        let mut beef = Beef::from_binary(&bytes).unwrap();
        let result = beef.verify_valid(false);
        assert!(result.valid, "version {version:#x}");
        assert_eq!(result.roots, expected);
    }
}

/// The reference (`Beef.ts:1065`) sorts and accepts this BEEF; the three
/// readers here judge it in the order held and refuse the child's input.
#[test]
fn a_child_written_ahead_of_its_parent_is_refused_by_the_three_readers() {
    for version in [BEEF_V1, BEEF_V2] {
        let bytes = children_first(version);
        let (parent, _) = parent_and_child();
        let refusal = Verdict::Invalid {
            offset: child_input_at(&bytes),
            kind: Kind::InputNamesNoElement,
            reason: Reason::InputNamesNoElement {
                txid: sha256d(&parent),
            },
        };

        assert_eq!(
            verify_stream(bytes.as_slice(), headers(&parent), None).unwrap(),
            refusal,
            "verify_stream, version {version:#x}"
        );
        assert_eq!(
            verify_stream_structure(bytes.as_slice(), headers(&parent), None).unwrap(),
            refusal,
            "verify_stream_structure, version {version:#x}"
        );

        // The parse judges the frame; the order is judged after it.
        let mut beef = Beef::from_binary(&bytes).expect("the frame parses");
        assert_eq!(
            beef.verify_structure(),
            Err(Kind::InputNamesNoElement),
            "verify_structure, version {version:#x}"
        );
        let mut beef = Beef::from_binary(&bytes).unwrap();
        let result = beef.verify_valid(false);
        assert!(!result.valid, "verify_valid, version {version:#x}");
        assert!(result.roots.is_empty());
    }
}
