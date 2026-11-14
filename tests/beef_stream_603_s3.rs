//! #603, shard S3: `src/transaction/beef_stream.rs`'s index sizes, roots and
//! finish (`BeefIndex::spec_size`, `BeefIndex::finish`, `BeefIndex::roots`,
//! `BeefIndex::deferred`, `bump_root`) against the sibling's rules and
//! vectors, inside the BEEF surface's mutation selection.
//!
//! The counts are the sibling's definition's (bsv-stack-lean@9a69056
//! `lean/BeefOfAnySize.lean`): `Index.size` (:860-861) is what
//! `spec_size` reports and `finish` (:990-1002) adds the atomic end's work
//! to the cost model's count. Two sources give the expected numbers: the
//! sibling's own `#guard_msgs` summary of the 10,000-link atomic chain
//! (`lean/BeefOfAnySize/Scenarios.lean:145-150`), and
//! `vectors/beef_stream_603_s3.json`, a row its scenarios do not carry
//! (two BUMPs carrying one txid, so the index's (txid, BUMP) pairs count it
//! twice) recorded from the same definition by
//! `support/beef_stream_603_s3.lean`. No count reads a digest's value, only
//! the equalities of the txids, so the shape under SHA-256 here has the
//! Lean's counts; each fixture is built by this crate's writers, its length
//! checked against the Lean's.
//!
//! The roots by BUMP position (`roots`) are the Lean index's `bumps`
//! (`BumpEntry`'s height and root, :838-850); the transactions held for a
//! parent (`deferred`) are bsv-rs#240's rule on its recorded witness
//! (`vectors/beef_order_240.json`, the reference's `Beef.verifyValid` at
//! `ts-stack@edf6e03`); a node computed from a duplicate on the left is no
//! node (the sibling bsv-script-lean@5dc337e1
//! `lean/BsvChain/Views/Wire/BUMP.lean:295-306`, `Bump.nodeAt` computes a
//! node only from a word on the left), on #167's recorded shapes
//! (`vectors/merkle_path_even_offset_duplicate_167.json`).
#![cfg(feature = "transaction")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

#[path = "support/beef_chain.rs"]
mod beef_chain;

use std::collections::HashMap;

use beef_chain::{varint, Hash32};
use bsv_rs::primitives::{from_hex, sha256d, to_hex};
use bsv_rs::script::{LockingScript, UnlockingScript};
use bsv_rs::transaction::{
    verify_stream_structure, BeefStream, Element, MerklePath, MerklePathLeaf, Progress,
    StreamVerifier, Transaction, TransactionInput, TransactionOutput, Verdict,
};
use serde::Deserialize;

/// The Atomic BEEF prefix (BRC-95) and the BEEF V1 version word.
const ATOMIC_BEEF: u32 = 0x0101_0101;
const BEEF_V1: u32 = 0xEFBE_0001;

/// What the reader holds after a whole reading: the Lean's `summary` less
/// the elements (bytes, steps, work, index entries, accepted).
#[derive(Debug, PartialEq, Eq)]
struct Summary {
    bytes: u64,
    steps: u64,
    work: u64,
    index_size: u64,
    accepted: bool,
}

/// Reads `bytes` to its verdict on the structure-only reader (the Lean's
/// `readBytes` checks no script) and returns the summary, the roots the
/// index holds by BUMP position and the verdict.
fn read(bytes: &[u8], headers: &HashMap<u64, Hash32>) -> (Summary, Vec<(u64, Hash32)>, Verdict) {
    let mut reader = StreamVerifier::structure_only(bytes, headers, None);
    let verdict = loop {
        if let Progress::Verdict(v) = reader.step().unwrap() {
            break v;
        }
    };
    let index = reader.index();
    (
        Summary {
            bytes: bytes.len() as u64,
            steps: index.steps(),
            work: index.model_work(),
            index_size: index.spec_size(),
            accepted: verdict.is_valid(),
        },
        index.roots().to_vec(),
        verdict,
    )
}

fn wire(display: &str) -> Hash32 {
    let mut h: Hash32 = from_hex(display).unwrap().try_into().unwrap();
    h.reverse();
    h
}

fn display(wire: &Hash32) -> String {
    let mut h = *wire;
    h.reverse();
    to_hex(&h)
}

/// The Lean's `rawTx`: version 1, the inputs with empty unlocking scripts,
/// `n_out` outputs of one satoshi with empty locking scripts, lock time 0
/// (`Scenarios.lean:45-50`), written by this crate's writer.
fn raw_tx(inputs: &[(Hash32, u32)], n_out: usize) -> Vec<u8> {
    let mut tx = Transaction::new();
    for (prev, vout) in inputs {
        let mut input = TransactionInput::new(display(prev).parse().unwrap(), *vout);
        input.unlocking_script = Some(UnlockingScript::new());
        tx.inputs_mut().push(input);
    }
    for _ in 0..n_out {
        tx.outputs_mut()
            .push(TransactionOutput::new(1, LockingScript::new()));
    }
    tx.to_binary()
}

/// A level-0 leaf carrying a client txid, or the duplicate marker.
fn txid_leaf(offset: u64, txid: &Hash32) -> MerklePathLeaf {
    MerklePathLeaf {
        offset,
        hash: Some(display(txid)),
        txid: true,
        duplicate: false,
    }
}

fn duplicate_leaf(offset: u64) -> MerklePathLeaf {
    MerklePathLeaf {
        offset,
        hash: None,
        txid: false,
        duplicate: true,
    }
}

// ---------------------------------------------------------------------------
// The sibling's two-BUMP row: Index.size, finish's work and the roots
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct Recorded {
    sibling: String,
    rows: Vec<Row>,
}

#[derive(Deserialize)]
struct Row {
    name: String,
    bytes: u64,
    verdict: String,
    steps: u64,
    work: u64,
    index_size: u64,
}

fn recorded(name: &str) -> Summary {
    let data = std::fs::read_to_string("tests/vectors/beef_stream_603_s3.json").unwrap();
    let recorded: Recorded = serde_json::from_str(&data).unwrap();
    assert_eq!(
        recorded.sibling,
        "bsv-stack-lean@9a69056314a0d7bebc84ed9b16af6fdf081fcca5"
    );
    let row = recorded
        .rows
        .into_iter()
        .find(|r| r.name == name)
        .unwrap_or_else(|| panic!("no recorded row {name}"));
    Summary {
        bytes: row.bytes,
        steps: row.steps,
        work: row.work,
        index_size: row.index_size,
        accepted: row.verdict == "accepted",
    }
}

/// The recorder's shape (`support/beef_stream_603_s3.lean`) under SHA-256:
/// BUMP A at 800,000 (a block of four: the anchor at 0, two proven txids at
/// 1 and 2, the duplicate marker at 3, nothing above), BUMP B at 800,006
/// (the anchor again at 0, the duplicate at 1), the anchor under BUMP A
/// and the subject, unproven, spending the anchor's two outputs. The plain
/// BEEF, the atomic one, the headers carrying both roots, and the roots.
struct TwoBumps {
    plain: Vec<u8>,
    atomic: Vec<u8>,
    headers: HashMap<u64, Hash32>,
    roots: Vec<(u64, Hash32)>,
}

fn two_bumps_one_txid() -> TwoBumps {
    // The Lean's `anchorTx`: one input naming a txid the BEEF does not carry
    // (its proof vouches for it), two outputs (`Scenarios.lean:108-109`).
    let anchor = raw_tx(&[([0x2A; 32], 0)], 2);
    let anchor_txid = sha256d(&anchor);
    let proven_one = sha256d(&[0x51]);
    let proven_two = sha256d(&[0x52]);
    let bump_a = MerklePath::new(
        800_000,
        vec![
            vec![
                txid_leaf(0, &anchor_txid),
                txid_leaf(1, &proven_one),
                txid_leaf(2, &proven_two),
                duplicate_leaf(3),
            ],
            vec![],
        ],
    )
    .unwrap();
    let bump_b = MerklePath::new(
        800_006,
        vec![vec![txid_leaf(0, &anchor_txid), duplicate_leaf(1)]],
    )
    .unwrap();
    let root_a = wire(&bump_a.compute_root(Some(&display(&anchor_txid))).unwrap());
    let root_b = wire(&bump_b.compute_root(Some(&display(&anchor_txid))).unwrap());
    let subject = raw_tx(&[(anchor_txid, 0), (anchor_txid, 1)], 1);
    let subject_txid = sha256d(&subject);

    let mut plain = BEEF_V1.to_le_bytes().to_vec();
    plain.push(2);
    plain.extend(
        bump_a
            .to_binary()
            .expect("the path holds only states a BUMP writes (#817)"),
    );
    plain.extend(
        bump_b
            .to_binary()
            .expect("the path holds only states a BUMP writes (#817)"),
    );
    plain.push(2);
    plain.extend_from_slice(&anchor);
    plain.extend_from_slice(&[1, 0]);
    plain.extend_from_slice(&subject);
    plain.push(0);
    let mut atomic = ATOMIC_BEEF.to_le_bytes().to_vec();
    atomic.extend_from_slice(&subject_txid);
    atomic.extend_from_slice(&plain);

    TwoBumps {
        plain,
        atomic,
        headers: HashMap::from([(800_000, root_a), (800_006, root_b)]),
        roots: vec![(800_000, root_a), (800_006, root_b)],
    }
}

/// `Index.size` on two BUMPs that carry one txid (bsv-stack-lean@9a69056
/// `lean/BeefOfAnySize.lean:860-861`): each BUMP and its own level-0 set
/// (1 + 3 and 1 + 1), the two transactions, their three inputs (the
/// edges, one per input of a raw transaction) and the three distinct
/// proven txids once more, 14; the cost model's work 405, the steps 4.
/// RED on every replacement of `spec_size`'s arithmetic (`1864`, `1865`),
/// the anchor's second count (the (txid, BUMP) pair of BUMP B) among them.
#[test]
fn index_size_counts_a_txid_two_bumps_carry_twice_beef_of_any_size_two_bumps_one_txid() {
    let row = two_bumps_one_txid();
    let (summary, _, verdict) = read(&row.plain, &row.headers);
    assert_eq!(summary, recorded("two_bumps_one_txid"), "{verdict:?}");
}

/// `finish` under the subject (`lean/BeefOfAnySize.lean:990-1002`, `budget`
/// :982): one pass over the two entries and the walk's fuel three times,
/// 2 + 3 * (2 + 3 + 2) = 23 units over the plain reading's 405, 428; the
/// index unchanged, 14. RED on every replacement of `finish`'s work line
/// (`2292`).
#[test]
fn finish_adds_one_pass_and_three_times_the_walks_fuel_beef_of_any_size_two_bumps_one_txid_atomic()
{
    let row = two_bumps_one_txid();
    let (summary, _, verdict) = read(&row.atomic, &row.headers);
    assert_eq!(
        summary,
        recorded("two_bumps_one_txid_atomic"),
        "{verdict:?}"
    );
    let (plain, _, _) = read(&row.plain, &row.headers);
    assert_eq!(summary.work - plain.work, 2 + 3 * (2 + 3 + 2));
}

/// The roots the index holds are the Lean index's `bumps`, by position: each
/// BUMP's block height and the root its leaves climb to, the root the
/// headers carry (`lean/BeefOfAnySize.lean:838-850`, `rootCarried` :874);
/// the verdict names the same. RED on `roots`' three replacements (`1900`).
#[test]
fn the_roots_are_each_bumps_height_and_root_in_wire_order_beef_of_any_size_two_bumps_one_txid() {
    let row = two_bumps_one_txid();
    for bytes in [&row.plain, &row.atomic] {
        let (_, roots, verdict) = read(bytes, &row.headers);
        assert_eq!(roots, row.roots);
        match verdict {
            Verdict::Valid { roots, .. } => assert_eq!(roots, row.roots),
            other => panic!("{other:?}"),
        }
    }
}

// ---------------------------------------------------------------------------
// The sibling's guarded summary: the atomic chain of 10,000 links
// ---------------------------------------------------------------------------

/// The Lean's `chain n true` (`Scenarios.lean:103-134`): the anchor proven
/// by a BUMP of height 1 at 800,000 and `n` links, each spending output 0
/// of the one before, atomic on the last; V1.
fn lean_chain_atomic(n: usize) -> (Vec<u8>, HashMap<u64, Hash32>) {
    let anchor = raw_tx(&[([0x2A; 32], 0)], 2);
    let anchor_txid = sha256d(&anchor);
    let bump = MerklePath::new(
        800_000,
        vec![vec![txid_leaf(0, &anchor_txid), duplicate_leaf(1)]],
    )
    .unwrap();
    let root = wire(&bump.compute_root(Some(&display(&anchor_txid))).unwrap());
    let mut links = Vec::with_capacity(n);
    let mut prev = anchor_txid;
    for _ in 0..n {
        let link = raw_tx(&[(prev, 0)], 1);
        prev = sha256d(&link);
        links.push(link);
    }
    let mut bytes = ATOMIC_BEEF.to_le_bytes().to_vec();
    bytes.extend_from_slice(&prev);
    bytes.extend_from_slice(&BEEF_V1.to_le_bytes());
    bytes.push(1);
    bytes.extend(
        bump.to_binary()
            .expect("the path holds only states a BUMP writes (#817)"),
    );
    bytes.extend(varint(n as u64 + 1));
    bytes.extend_from_slice(&anchor);
    bytes.extend_from_slice(&[1, 0]);
    for link in &links {
        bytes.extend_from_slice(link);
        bytes.push(0);
    }
    (bytes, HashMap::from([(800_000, root)]))
}

/// `#eval summary (run stub chainHeaders (chain 10000 true))`, checked by
/// the sibling's build (bsv-stack-lean@9a69056
/// `lean/BeefOfAnySize/Scenarios.lean:145-150`: `(10002, 600112, 10002,
/// 740145, 20005, true)`): 10,002 steps, the work with the atomic end
/// (10,001 entries, 10,001 edges and two, three times, and the pass),
/// 20,005 entries. RED on `spec_size`'s and `finish`'s replacements but
/// `1864:31` `/` and `1864:51` `-` (one proven txid, no pair counted twice:
/// the two-BUMP row's).
#[test]
fn the_leans_atomic_chain_of_10000_has_the_leans_counts_beef_of_any_size_chain_10000_atomic() {
    let (bytes, headers) = lean_chain_atomic(10_000);
    let (summary, _, verdict) = read(&bytes, &headers);
    assert_eq!(
        (
            summary.steps,
            summary.work,
            summary.index_size,
            summary.accepted
        ),
        (10_002, 740_145, 20_005, true),
        "{verdict:?}"
    );
}

// ---------------------------------------------------------------------------
// The transactions held for a parent (bsv-rs#240)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct OrderVectors {
    witnesses: Vec<OrderWitness>,
}

#[derive(Deserialize)]
struct OrderWitness {
    name: String,
    hex: String,
    reference_valid: bool,
}

/// `reversed_chain_40` of `vectors/beef_order_240.json` (the 40-link chain
/// written newest first, the proven funding transaction last; the
/// reference's `Beef.verifyValid` valid at `ts-stack@edf6e03`): each
/// unproven link is read ahead of its parent and held until it arrives
/// (bsv-rs#240), every one of them at the peak, none at the verdict, which
/// is the reference's. RED on `deferred`'s four replacements (`1895`).
#[test]
fn every_unproven_link_is_held_until_the_funding_arrives_beef_order_240_reversed_chain_40() {
    let data = std::fs::read_to_string("tests/vectors/beef_order_240.json").unwrap();
    let vectors: OrderVectors = serde_json::from_str(&data).unwrap();
    let witness = vectors
        .witnesses
        .into_iter()
        .find(|w| w.name == "reversed_chain_40")
        .unwrap();
    assert!(witness.reference_valid);
    let bytes = from_hex(&witness.hex).unwrap();
    // The headers carry each BUMP's root; the unproven links are counted.
    let mut headers = HashMap::new();
    let mut unproven = 0u64;
    for element in BeefStream::new(bytes.as_slice()) {
        match element.unwrap() {
            Element::Bump(bump) => {
                headers.insert(bump.block_height, bump.root);
            }
            Element::Tx {
                bump_index: None, ..
            } => unproven += 1,
            _ => {}
        }
    }
    assert_eq!(unproven, 39);

    let mut reader = StreamVerifier::structure_only(bytes.as_slice(), &headers, None);
    let mut peak = (0, 0);
    let verdict = loop {
        match reader.step().unwrap() {
            Progress::Stepped => {
                let held = reader.index().deferred();
                if held.0 > peak.0 {
                    peak = held;
                }
            }
            Progress::Verdict(v) => break v,
        }
    };
    assert_eq!(verdict.is_valid(), witness.reference_valid, "{verdict:?}");
    assert_eq!(peak.0, unproven);
    assert!(peak.1 > 0, "a held transaction's entry holds bytes");
    assert_eq!(reader.index().deferred().0, 0);
}

// ---------------------------------------------------------------------------
// A node computed from a duplicate on the left (bsv-rs#167)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct EvenOffsetVectors {
    shapes: Vec<Shape>,
}

#[derive(Deserialize)]
struct Shape {
    name: String,
    block_height: u64,
    hex: String,
    verdict: RefVerdict,
}

#[derive(Deserialize)]
struct RefVerdict {
    accepted: bool,
    root: Option<String>,
}

/// This crate's refusal for each shape the reference refuses
/// (`tests/merkle_path_even_offset_duplicate.rs`'s table), in its words.
fn refused_here(name: &str) -> &'static str {
    match name {
        "two-txids-the-left-duplicate-node-carried-wrong" => {
            "MismatchedNode { level: 1, offset: 0 }"
        }
        "two-txids-a-node-computed-from-the-left-duplicate" => {
            "LeftDuplicateBelow { level: 1, offset: 0 }"
        }
        "two-paths-level-3-computed-from-the-left-duplicate" => {
            "LeftDuplicateBelow { level: 3, offset: 0 }"
        }
        "two-paths-a-right-child-computed-from-the-left-duplicate" => {
            "LeftDuplicateBelow { level: 2, offset: 0 }"
        }
        "a-duplicate-at-the-path-nodes-own-offset" => "MismatchedNode { level: 1, offset: 0 }",
        other => panic!("no refusal stated for {other}"),
    }
}

/// The nine shapes of `vectors/merkle_path_even_offset_duplicate_167.json`
/// streamed as a BEEF of one BUMP: the reference's root where it accepts,
/// carried by the headers and valid; where a path needs a node computed
/// from a duplicate on the left (`Bump.nodeAt`, BUMP.lean:295-306: the left
/// child must be a word; the reference's `Missing hash`), the walk's
/// refusal at that node. RED on `bump_root`'s `476:27` `|=` and `476:32`
/// `/`: a duplicate at offset 2 (`two-paths-a-right-child-computed-from-
/// the-left-duplicate`) marks the node above it not whole only as `s % 2`
/// reads the offset.
#[test]
fn a_node_computed_from_a_left_duplicate_is_no_node_bump_nodeat_even_offset_duplicate_167() {
    let data = std::fs::read_to_string("tests/vectors/merkle_path_even_offset_duplicate_167.json")
        .unwrap();
    let vectors: EvenOffsetVectors = serde_json::from_str(&data).unwrap();
    assert_eq!(vectors.shapes.len(), 9);
    for shape in &vectors.shapes {
        let mut beef = vec![0x02, 0x00, 0xbe, 0xef, 0x01];
        beef.extend(from_hex(&shape.hex).unwrap());
        beef.push(0);
        let headers: HashMap<u64, Hash32> = match &shape.verdict.root {
            Some(root) => HashMap::from([(shape.block_height, wire(root))]),
            None => HashMap::new(),
        };
        let verdict = verify_stream_structure(beef.as_slice(), &headers, None).unwrap();
        if shape.verdict.accepted {
            assert!(verdict.is_valid(), "{}: {verdict:?}", shape.name);
        } else {
            match verdict {
                Verdict::Invalid { reason, .. } => assert_eq!(
                    format!("{reason:?}"),
                    refused_here(&shape.name),
                    "{}",
                    shape.name
                ),
                other => panic!("{}: {other:?}", shape.name),
            }
        }
    }
}
