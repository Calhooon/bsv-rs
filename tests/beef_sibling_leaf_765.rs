//! A BEEF entry whose txid a BUMP holds only as an unflagged level-0 leaf
//! takes that BUMP, the leaf flagged on the way (#765).
//!
//! The reference's `#tryToValidateBumpIndex` reads an index of every level-0
//! hash of every BUMP, the last winning, and flags the leaf it finds
//! (`ts-stack@edf6e03` `packages/sdk/src/transaction/Beef.ts:576-585`,
//! `:1329-1340`, `:1334-1338`); `#mergeBumpEntry` gives an entry without an
//! index the merged BUMP through `#tryMarkTxProvenByBump`, which does the same
//! (`:774-786`, `:813-822`); go-sdk@2ca481c's `bumpProves`, `FindBumpByHash`
//! and `MergeBump` take any level-0 hash (`transaction/beef.go:67-83`,
//! `:620-630`, `:780-785`). BRC-74's flag `00` is "data follows, not a client
//! txid" (`transactions/0074.md:75`), and a level-0 leaf of a BUMP is a txid
//! of that block whose path computes the same root. From v0.3.5
//! (`ef98e246`) to #765 this crate's `try_to_validate_bump_index` and
//! `update_bump_indices` took a flagged leaf only.
//!
//! The witness is the p25 shape (the keeper's word of 2026-11-04 12:2xZ,
//! from LOW's decision ledger of 2026-09-04): two drain inputs mined as
//! siblings, the walk merging A's BUMP (B's txid in it as a plain leaf) and
//! then B raw with no index, B's parent not in the BEEF; the strict linker
//! left B unproven and the BEEF was refused for a missing input. Beside it,
//! the seven arrangements #763's fold rebuilt of the shape `ef98e246`
//! describes, and the two it found refused, each for its own reason.
//!
//! Every transaction, BUMP and BEEF is written by this crate's writers; the
//! block's root is computed here from the leaves.
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use bsv_rs::primitives::{from_hex, sha256d, to_hex};
use bsv_rs::script::{LockingScript, UnlockingScript};
use bsv_rs::transaction::beef_stream::{verify_stream_structure, Hash32, HeadersFn, Kind};
use bsv_rs::transaction::{
    Beef, MerklePath, MerklePathLeaf, Transaction, TransactionInput, TransactionOutput,
};

const HEIGHT: u32 = 964_422;

/// A transaction spending each `(txid, vout)` with `OP_1`, one `OP_1`
/// output of `sats`.
fn tx(inputs: &[(&str, u32)], sats: u64) -> Transaction {
    let mut t = Transaction::new();
    for (txid, vout) in inputs {
        let mut input = TransactionInput::new(txid.parse().unwrap(), *vout);
        input.unlocking_script = Some(UnlockingScript::from_hex("51").unwrap());
        t.inputs_mut().push(input);
    }
    let lock = LockingScript::from_hex("51").unwrap();
    t.outputs_mut().push(TransactionOutput::new(sats, lock));
    t
}

/// The internal node over two display-hex hashes, in display hex.
fn node(left: &str, right: &str) -> String {
    let wire = |h: &str| from_hex(h).unwrap().into_iter().rev();
    let bytes: Vec<u8> = wire(left).chain(wire(right)).collect();
    let mut hash = sha256d(&bytes);
    hash.reverse();
    to_hex(&hash)
}

/// A block of four at `HEIGHT`: `x` and `d` at offsets 0 and 1, A and B,
/// siblings, at 2 and 3. A's BUMP flags A and holds B as a plain leaf (flag
/// `00`); D's BUMP flags `d`.
struct Block {
    a: Transaction,
    a_bump: MerklePath,
    d_bump: MerklePath,
    root: String,
}

fn block(b: &str) -> Block {
    let a = tx(&[(&"dd".repeat(32), 0)], 4_000);
    let (x, d) = ("ee".repeat(32), "d1".repeat(32));
    let root = node(&node(&x, &d), &node(&a.id(), b));
    let a_bump = MerklePath::new(
        HEIGHT,
        vec![
            vec![
                MerklePathLeaf::new_txid(2, a.id()),
                MerklePathLeaf::new(3, b.to_string()),
            ],
            vec![MerklePathLeaf::new(0, node(&x, &d))],
        ],
    )
    .unwrap();
    let d_bump = MerklePath::new(
        HEIGHT,
        vec![
            vec![MerklePathLeaf::new(0, x), MerklePathLeaf::new_txid(1, d)],
            vec![MerklePathLeaf::new(1, node(&a.id(), b))],
        ],
    )
    .unwrap();
    assert_eq!(a_bump.compute_root(Some(b)).unwrap(), root);
    assert_eq!(d_bump.compute_root(None).unwrap(), root);
    Block {
        a,
        a_bump,
        d_bump,
        root,
    }
}

/// B's leaf as written: offset 3, the flag byte, the wire hash.
fn leaf_bytes(b: &str, flag: &str) -> String {
    let wire: String = (0..32).rev().map(|i| &b[2 * i..2 * i + 2]).collect();
    format!("03{flag}{wire}")
}

/// This crate's refusal in the shape of the door's: the kind, the proven
/// entries, the missing inputs, the transactions missing them, the counts.
fn refusal(beef: &Beef) -> Option<String> {
    let mut held = beef.clone();
    let kind = held.verify_structure().err()?;
    let sorted = held.clone().sort_txs();
    Some(format!(
        "BEEF structure is invalid ({kind:?}): roots {:?}; missing inputs {:?}; \
         transactions with missing inputs {:?}; {} tx(s), {} bump(s), {} bytes",
        sorted.valid,
        sorted.missing_inputs,
        sorted.with_missing_inputs,
        held.txs.len(),
        held.bumps.len(),
        held.to_binary().expect("the BEEF is writable").len()
    ))
}

/// The structure on both readers and the walk `from_beef` gives `subject`:
/// valid, B carrying the BUMP at `HEIGHT` with the block's root.
fn assert_links(beef: &mut Beef, subject: &str, b: &str, root: &str) {
    assert_eq!(refusal(beef), None);
    let bytes = beef.to_binary().expect("the BEEF is writable");
    let mut read = Beef::from_binary(&bytes).unwrap();
    assert!(read.verify_valid(false).valid, "the bytes read back");
    let any = HeadersFn(|_: u64, _: &Hash32| true);
    let verdict = verify_stream_structure(bytes.as_slice(), &any, None).unwrap();
    assert!(verdict.is_valid(), "{verdict:?}");
    let mut stack = vec![Transaction::from_beef(&bytes, Some(subject)).unwrap()];
    while let Some(t) = stack.pop() {
        if t.id() == b {
            let mp = t.merkle_path.as_ref().expect("B's BUMP attached");
            assert_eq!(
                (mp.block_height, mp.compute_root(Some(b)).unwrap()),
                (HEIGHT, root.into())
            );
            return;
        }
        stack.extend(
            t.inputs()
                .iter()
                .filter_map(|i| i.source_transaction.as_deref().cloned()),
        );
    }
    panic!("B not reached from {subject}");
}

/// p25: the BUMP, A raw (its flagged leaf), B raw with no index (the
/// toolbox's "a BUMP already proves this" shortcut), the drain C spending
/// both; B's parent P is not in the BEEF. Under v0.3.5's strict match B took
/// no index and the BEEF was refused for P (at `81c312e2`: `InputNamesNoElement`,
/// missing inputs `[P]`, transactions with missing inputs `[B]`); under the
/// any-hash rule B takes the BUMP, its leaf flagged and written `02`.
#[test]
fn a_sibling_mined_input_merged_without_an_index_links_to_the_bump_holding_it_765() {
    let p = "26".repeat(32);
    let b = tx(&[(&p, 0)], 3_000);
    let blk = block(&b.id());
    let c = tx(&[(&blk.a.id(), 0), (&b.id(), 0)], 6_500);
    let mut beef = Beef::new();
    beef.merge_bump(blk.a_bump.clone());
    beef.merge_raw_tx(blk.a.to_binary(), None)
        .expect("the bytes are one transaction");
    beef.merge_raw_tx(b.to_binary(), None)
        .expect("the bytes are one transaction");
    beef.merge_raw_tx(c.to_binary(), None)
        .expect("the bytes are one transaction");

    assert_eq!(refusal(&beef), None, "the p25 BEEF");
    assert_eq!(beef.find_txid(&b.id()).unwrap().bump_index(), Some(0));
    assert_eq!(beef.bumps[0].txids(), vec![blk.a.id(), b.id()]);
    let hex = beef.to_hex().expect("the BEEF is writable");
    assert!(
        hex.contains(&leaf_bytes(&b.id(), "02")),
        "B's leaf written 02"
    );
    assert!(!hex.contains(&leaf_bytes(&b.id(), "00")));
    assert!(hex.contains(&format!("0100{}", b.to_hex())), "B's index 0");
    assert_links(&mut beef, &c.id(), &b.id(), &blk.root);
}

/// The control: a txid no BUMP holds stays unproven, the any-hash rule
/// claiming nothing absent; the refusal is the p25 door's shape.
#[test]
fn a_txid_no_bump_holds_stays_unproven_and_its_missing_parent_refused_765() {
    let p = "26".repeat(32);
    let b = tx(&[(&p, 0)], 3_000);
    let blk = block(&"b0".repeat(32));
    let c = tx(&[(&blk.a.id(), 0), (&b.id(), 0)], 6_500);
    let mut beef = Beef::new();
    beef.merge_bump(blk.a_bump);
    for t in [&blk.a, &b, &c] {
        beef.merge_raw_tx(t.to_binary(), None)
            .expect("the bytes are one transaction");
    }
    assert_eq!(beef.find_txid(&b.id()).unwrap().bump_index(), None);
    let text = refusal(&beef).expect("refused");
    assert!(
        text.starts_with("BEEF structure is invalid (InputNamesNoElement)"),
        "{text}"
    );
    let tail = format!(
        "missing inputs [{p:?}]; transactions with missing inputs [{:?}]",
        b.id()
    );
    assert!(text.contains(&tail), "{text}");
}

/// The shape `ef98e246` describes: S, a sibling leaf of A's BUMP, spent by a
/// chain of unproven transactions U1, U2; S's parent not in the BEEF.
struct Chain {
    blk: Block,
    s: Transaction,
    u1: Transaction,
    u2: Transaction,
}

fn chain(parent: &str) -> Chain {
    let s = tx(&[(parent, 0)], 3_000);
    let blk = block(&s.id());
    let u1 = tx(&[(&s.id(), 0)], 2_900);
    let u2 = tx(&[(&u1.id(), 0), (&blk.a.id(), 0)], 6_800);
    Chain { blk, s, u1, u2 }
}

fn merge_raw(beef: &mut Beef, txs: &[&Transaction]) {
    for t in txs {
        beef.merge_raw_tx(t.to_binary(), None)
            .expect("the bytes are one transaction");
    }
}

/// The seven arrangements of #763's fold, each linking under the any-hash
/// rule on both readers and `from_beef`: the BUMP before the entries and
/// after them, through `merge_beef` both ways, at another BUMP's height (two
/// BUMPs of the block, combined), the entries newest to oldest, and the sibling
/// mid-chain (its own parent proven at the height below).
#[test]
fn the_seven_arrangements_of_a_txid_held_as_a_sibling_leaf_link_765() {
    let k = chain(&"27".repeat(32));
    let (a, s, u1, u2) = (&k.blk.a, &k.s, &k.u1, &k.u2);
    let mut cases: Vec<(&str, Beef)> = Vec::new();

    let mut beef = Beef::new();
    beef.merge_bump(k.blk.a_bump.clone());
    merge_raw(&mut beef, &[a, s, u1, u2]);
    cases.push(("the BUMP before the entries", beef));

    let mut beef = Beef::new();
    merge_raw(&mut beef, &[a, s, u1, u2]);
    beef.merge_bump(k.blk.a_bump.clone());
    cases.push(("the BUMP after the entries", beef));

    let mut proof = Beef::new();
    proof.merge_bump(k.blk.a_bump.clone());
    merge_raw(&mut proof, &[a]);
    let mut spends = Beef::new();
    merge_raw(&mut spends, &[s, u1, u2]);
    let mut beef = spends.clone();
    beef.merge_beef(&proof)
        .expect("the source BEEF writes and reads back");
    cases.push(("merge_beef: the proof into the chain", beef));
    let mut beef = proof.clone();
    beef.merge_beef(&spends)
        .expect("the source BEEF writes and reads back");
    cases.push(("merge_beef: the chain into the proof", beef));

    let mut beef = Beef::new();
    beef.merge_bump(k.blk.d_bump.clone());
    beef.merge_bump(k.blk.a_bump.clone());
    merge_raw(&mut beef, &[a, s, u1, u2]);
    assert_eq!(beef.bumps.len(), 1, "two BUMPs of one block combined");
    cases.push(("at another BUMP's height", beef));

    let mut beef = Beef::new();
    beef.merge_bump(k.blk.a_bump.clone());
    merge_raw(&mut beef, &[u2, u1, s, a]);
    cases.push(("the entries newest to oldest", beef));

    for (name, mut beef) in cases {
        assert_eq!(
            beef.find_txid(&s.id()).unwrap().bump_index(),
            Some(0),
            "{name}"
        );
        assert!(
            beef.bumps[0].txids().contains(&s.id()),
            "{name}: the leaf flagged"
        );
        assert_links(&mut beef, &u2.id(), &s.id(), &k.blk.root);
    }

    // Mid-chain: S's parent M0 held raw and proven one block below.
    let m0 = tx(&[(&"28".repeat(32), 0)], 3_100);
    let k = chain(&m0.id());
    let mut beef = Beef::new();
    beef.merge_bump(MerklePath::from_coinbase_txid(&m0.id(), HEIGHT - 1));
    beef.merge_bump(k.blk.a_bump.clone());
    merge_raw(&mut beef, &[&m0, &k.blk.a, &k.s, &k.u1, &k.u2]);
    assert_eq!(beef.find_txid(&k.s.id()).unwrap().bump_index(), Some(1));
    assert_links(&mut beef, &k.u2.id(), &k.s.id(), &k.blk.root);
}

/// The two the fold found refused on v0.3.4, neither the match's to decide.
/// A txid-only S: v0.3.4 refused every txid-only entry under
/// `allow_txid_only = false`; since 0.4.2 the flag decides nothing and an
/// entry a BUMP proves is valid, so S is valid either way. Two roots at one
/// height: `RootNotCarried`, the headers carrying one root a height, with or
/// without the sibling.
#[test]
fn a_txid_only_sibling_and_two_roots_at_one_height_answer_for_their_own_reasons_765() {
    let k = chain(&"29".repeat(32));
    let mut beef = Beef::new();
    beef.merge_bump(k.blk.a_bump.clone());
    beef.merge_txid_only(k.s.id());
    merge_raw(&mut beef, &[&k.blk.a, &k.u1, &k.u2]);
    assert_eq!(beef.find_txid(&k.s.id()).unwrap().bump_index(), Some(0));
    assert!(beef.verify_valid(false).valid && beef.verify_valid(true).valid);
    let mut read = Beef::from_binary(&beef.to_binary().expect("the BEEF is writable")).unwrap();
    assert!(read.verify_valid(false).valid, "the txid-only S read back");

    let other = tx(&[(&"2a".repeat(32), 0)], 1_000);
    for with_sibling in [true, false] {
        let mut beef = Beef::new();
        if with_sibling {
            beef.merge_bump(k.blk.a_bump.clone());
        }
        beef.merge_bump(MerklePath::from_coinbase_txid(&other.id(), HEIGHT));
        merge_raw(&mut beef, &[&other]);
        if with_sibling {
            merge_raw(&mut beef, &[&k.blk.a, &k.s, &k.u1, &k.u2]);
        } else {
            beef.merge_bump(MerklePath::from_coinbase_txid(&k.blk.a.id(), HEIGHT));
            merge_raw(&mut beef, &[&k.blk.a]);
        }
        assert_eq!(beef.bumps.len(), 2);
        assert_eq!(beef.verify_structure().err(), Some(Kind::RootNotCarried));
    }
}
