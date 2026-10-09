//! The rows of the Lean definition `BeefOfAnySize` (bsv-stack-lean,
//! `lean/BeefOfAnySize/Scenarios.lean`, the no-limits program NL-1), replayed
//! through the streaming reader under SHA-256: the same shapes from the same
//! encoders, so the same byte layout and the same offsets.
//!
//! Each refusal row asserts the offset of the byte the refusal names and its
//! kind. The rows run for the BEEF's structure alone (the Lean's validity:
//! its shapes carry empty scripts); the spend rows at the end run with
//! scripts. Where the Lean wrote an element's offset by hand (40, 999) the
//! row asserts the offset the wire gives.
#![cfg(feature = "transaction")]

use std::collections::HashMap;

use bsv_rs::primitives::{from_hex, sha256, sha256d};
use bsv_rs::transaction::beef_stream::{
    display_hex, AsyncByteSource, BeefDecoder, Hash32, HeadersFn, Progress, SpendRefusal, Step,
};
use bsv_rs::transaction::{
    referenced_outpoints, resume, verify_stream, verify_stream_async, verify_stream_structure,
    verify_stream_two_pass, Beef, BeefStream, Cursor, Element, Kind, MerklePath, MockChainTracker,
    Reason, StreamVerifier, Verdict,
};

// ---------------------------------------------------------------------------
// The encoders (the Lean's `varintBytes`, `rawTx`, `bumpBytes`)
// ---------------------------------------------------------------------------

const V1: u32 = 0xEFBE_0001;
const V2: u32 = 0xEFBE_0002;
const ATOMIC: u32 = 0x0101_0101;

fn varint(n: u64) -> Vec<u8> {
    if n < 0xFD {
        vec![n as u8]
    } else if n < 0x1_0000 {
        let mut v = vec![0xFD];
        v.extend_from_slice(&(n as u16).to_le_bytes());
        v
    } else if n < 0x1_0000_0000 {
        let mut v = vec![0xFE];
        v.extend_from_slice(&(n as u32).to_le_bytes());
        v
    } else {
        let mut v = vec![0xFF];
        v.extend_from_slice(&n.to_le_bytes());
        v
    }
}

/// A raw transaction: version 1, the inputs with the given unlocking
/// scripts, the outputs, locktime 0.
fn tx_with(inputs: &[(Hash32, u32, &[u8])], outputs: &[(u64, &[u8])]) -> Vec<u8> {
    let mut v = 1u32.to_le_bytes().to_vec();
    v.extend(varint(inputs.len() as u64));
    for (prev, vout, script) in inputs {
        v.extend_from_slice(prev);
        v.extend_from_slice(&vout.to_le_bytes());
        v.extend(varint(script.len() as u64));
        v.extend_from_slice(script);
        v.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    }
    v.extend(varint(outputs.len() as u64));
    for (satoshis, script) in outputs {
        v.extend_from_slice(&satoshis.to_le_bytes());
        v.extend(varint(script.len() as u64));
        v.extend_from_slice(script);
    }
    v.extend_from_slice(&0u32.to_le_bytes());
    v
}

/// The Lean's `rawTx`: empty unlocking scripts, `n_out` outputs of one
/// satoshi with empty locking scripts.
fn raw_tx(inputs: &[(Hash32, u32)], n_out: usize) -> Vec<u8> {
    let inputs: Vec<(Hash32, u32, &[u8])> = inputs.iter().map(|(p, v)| (*p, *v, &[][..])).collect();
    let outputs: Vec<(u64, &[u8])> = (0..n_out).map(|_| (1u64, &[][..])).collect();
    tx_with(&inputs, &outputs)
}

fn txid(raw: &[u8]) -> Hash32 {
    sha256d(raw)
}

#[derive(Clone)]
enum LeafSpec {
    Hash(u64, Hash32, bool),
    Dup(u64),
}

fn bump_bytes(block_height: u64, tree_height: u8, levels: &[Vec<LeafSpec>]) -> Vec<u8> {
    let mut v = varint(block_height);
    v.push(tree_height);
    for level in levels {
        v.extend(varint(level.len() as u64));
        for leaf in level {
            match leaf {
                LeafSpec::Hash(offset, hash, client) => {
                    v.extend(varint(*offset));
                    v.push(if *client { 2 } else { 0 });
                    v.extend_from_slice(hash);
                }
                LeafSpec::Dup(offset) => {
                    v.extend(varint(*offset));
                    v.push(1);
                }
            }
        }
    }
    v
}

/// A transaction as the frame writes it.
#[derive(Clone)]
enum Entry {
    /// A raw transaction and its BUMP index.
    Raw(Vec<u8>, Option<u64>),
    /// A txid-only entry (V2).
    TxidOnly(Hash32),
}

/// The wire of a BEEF and the stream offset of each transaction entry (the
/// raw transaction's leading byte, or the 32 bytes of a txid-only entry).
fn wire(
    version: u32,
    subject: Option<Hash32>,
    bumps: &[Vec<u8>],
    txs: &[Entry],
) -> (Vec<u8>, Vec<u64>) {
    let mut v = Vec::new();
    if let Some(subject) = subject {
        v.extend_from_slice(&ATOMIC.to_le_bytes());
        v.extend_from_slice(&subject);
    }
    v.extend_from_slice(&version.to_le_bytes());
    v.extend(varint(bumps.len() as u64));
    for bump in bumps {
        v.extend_from_slice(bump);
    }
    v.extend(varint(txs.len() as u64));
    let mut offsets = Vec::new();
    for entry in txs {
        match entry {
            Entry::Raw(raw, index) if version == V1 => {
                offsets.push(v.len() as u64);
                v.extend_from_slice(raw);
                match index {
                    Some(j) => {
                        v.push(1);
                        v.extend(varint(*j));
                    }
                    None => v.push(0),
                }
            }
            Entry::Raw(raw, index) => {
                match index {
                    Some(j) => {
                        v.push(1);
                        v.extend(varint(*j));
                    }
                    None => v.push(0),
                }
                offsets.push(v.len() as u64);
                v.extend_from_slice(raw);
            }
            Entry::TxidOnly(txid) => {
                v.push(2);
                offsets.push(v.len() as u64);
                v.extend_from_slice(txid);
            }
        }
    }
    (v, offsets)
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

/// The elements of a stream, or the refusal that stopped it.
fn elements(bytes: &[u8]) -> Result<Vec<Element>, (u64, Reason)> {
    let mut out = Vec::new();
    for element in BeefStream::new(bytes) {
        match element {
            Ok(e) => out.push(e),
            Err(bsv_rs::transaction::beef_stream::StreamError::Refused(r)) => {
                return Err((r.offset, r.reason))
            }
            Err(e) => panic!("a slice does not fail: {e}"),
        }
    }
    Ok(out)
}

/// The root a BUMP's bytes compute (wire order).
fn root_of(bump: &[u8]) -> Hash32 {
    let (bytes, _) = wire(V1, None, &[bump.to_vec()], &[]);
    match elements(&bytes).expect("the BUMP reads").as_slice() {
        [Element::Bump(b)] => b.root,
        other => panic!("one BUMP expected, got {other:?}"),
    }
}

fn one_header(height: u64, root: Hash32) -> HashMap<u64, Hash32> {
    HashMap::from([(height, root)])
}

fn structure(bytes: &[u8], headers: &HashMap<u64, Hash32>) -> Verdict {
    verify_stream_structure(bytes, headers, None).expect("a slice does not fail")
}

fn refusal(verdict: Verdict) -> (u64, Reason) {
    match verdict {
        Verdict::Invalid {
            offset,
            kind,
            reason,
        } => {
            assert_eq!(kind, reason.kind());
            (offset, reason)
        }
        other => panic!("a refusal expected, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// The chain: a proven anchor and `n` links (the Lean's `chain`)
// ---------------------------------------------------------------------------

struct Chain {
    bytes: Vec<u8>,
    /// The anchor, then each link: the txid and the stream offset.
    txs: Vec<(Hash32, u64)>,
    headers: HashMap<u64, Hash32>,
    anchor_root: Hash32,
}

/// The anchor (the Lean's `anchorTx`): one input naming a transaction the
/// BEEF does not carry, which its proof vouches for, and two outputs.
fn anchor_tx() -> Vec<u8> {
    raw_tx(&[([0x2A; 32], 0)], 2)
}

/// The anchor's BUMP: height 1, the anchor at offset 0, the duplicate marker
/// at offset 1.
fn anchor_bump() -> Vec<u8> {
    bump_bytes(
        800_000,
        1,
        &[vec![
            LeafSpec::Hash(0, txid(&anchor_tx()), true),
            LeafSpec::Dup(1),
        ]],
    )
}

/// The chain's entries: the anchor with BUMP index 0, then `n` links.
fn chain_entries(n: usize) -> Vec<Entry> {
    let mut entries = vec![Entry::Raw(anchor_tx(), Some(0))];
    let mut prev = txid(&anchor_tx());
    for _ in 0..n {
        let link = raw_tx(&[(prev, 0)], 1);
        prev = txid(&link);
        entries.push(Entry::Raw(link, None));
    }
    entries
}

fn chain_of(entries: &[Entry], subject: Option<Hash32>) -> Chain {
    let (bytes, offsets) = wire(V1, subject, &[anchor_bump()], entries);
    let txs = entries
        .iter()
        .zip(offsets)
        .map(|(e, at)| match e {
            Entry::Raw(raw, _) => (txid(raw), at),
            Entry::TxidOnly(t) => (*t, at),
        })
        .collect();
    let anchor_root = root_of(&anchor_bump());
    Chain {
        bytes,
        txs,
        headers: one_header(800_000, anchor_root),
        anchor_root,
    }
}

fn chain(n: usize, atomic: bool) -> Chain {
    let entries = chain_entries(n);
    let last = match entries.last().unwrap() {
        Entry::Raw(raw, _) => txid(raw),
        Entry::TxidOnly(t) => *t,
    };
    chain_of(&entries, atomic.then_some(last))
}

#[test]
fn the_nineteen_kinds_are_nineteen_and_distinct() {
    let all: std::collections::HashSet<Kind> = Kind::ALL.into_iter().collect();
    assert_eq!(Kind::ALL.len(), 19);
    assert_eq!(all.len(), 19);
}

#[test]
fn the_small_chain_is_accepted_one_step_per_element() {
    // The Lean's `small`: five elements, five steps (`small_accepted`).
    let c = chain(3, false);
    let mut reader = StreamVerifier::structure_only(c.bytes.as_slice(), &c.headers, None);
    let mut steps = 0;
    let verdict = loop {
        match reader.step().unwrap() {
            Progress::Stepped => steps += 1,
            Progress::Verdict(v) => break v,
        }
    };
    assert_eq!(steps, 5);
    assert_eq!(reader.index().steps(), 5);
    assert_eq!(
        verdict,
        Verdict::Valid {
            subject: None,
            roots: vec![(800_000, c.anchor_root)]
        }
    );
    // The Lean's layout: the BUMP at 5, 43 bytes; the anchor at 49.
    assert_eq!(c.txs[0].1, 49);

    // Atomic on the last link (`small_atomic_accepted`).
    let a = chain(3, true);
    let last = a.txs.last().unwrap().0;
    assert_eq!(
        structure(&a.bytes, &a.headers),
        Verdict::Valid {
            subject: Some(last),
            roots: vec![(800_000, a.anchor_root)]
        }
    );
}

// ---------------------------------------------------------------------------
// The BUMPs
// ---------------------------------------------------------------------------

fn tag(bytes: &[u8]) -> Hash32 {
    sha256(bytes)
}

/// The Lean's `wideBump`: every position of a block of `2^k` at level 0,
/// nothing above.
fn wide_bump(k: u8) -> Vec<u8> {
    let mut levels = vec![(0..1u64 << k)
        .map(|i| LeafSpec::Hash(i, tag(&(i as u32).to_le_bytes()), true))
        .collect::<Vec<_>>()];
    levels.resize(k as usize, Vec::new());
    bump_bytes(800_001, k, &levels)
}

#[test]
fn the_wide_bump_of_four_leaves_is_accepted() {
    // `wide_small_accepted`.
    let bump = wide_bump(2);
    let (bytes, _) = wire(V1, None, std::slice::from_ref(&bump), &[]);
    let leaves: Vec<Hash32> = (0..4u32).map(|i| tag(&i.to_le_bytes())).collect();
    let pair = |a: &Hash32, b: &Hash32| sha256d(&[a.as_slice(), b.as_slice()].concat());
    let root = pair(&pair(&leaves[0], &leaves[1]), &pair(&leaves[2], &leaves[3]));
    assert_eq!(root_of(&bump), root);
    assert!(structure(&bytes, &one_header(800_001, root)).is_valid());
}

/// The Lean's `compoundLevels`: two txids of interest in a block of 16, every
/// sibling the paths need carried.
fn compound_levels() -> Vec<Vec<LeafSpec>> {
    vec![
        vec![
            LeafSpec::Hash(5, tag(&[5]), true),
            LeafSpec::Hash(4, tag(&[4]), false),
            LeafSpec::Hash(9, tag(&[9]), true),
            LeafSpec::Hash(8, tag(&[8]), false),
        ],
        vec![
            LeafSpec::Hash(3, tag(&[1, 3]), false),
            LeafSpec::Hash(5, tag(&[1, 5]), false),
        ],
        vec![
            LeafSpec::Hash(0, tag(&[2, 0]), false),
            LeafSpec::Hash(3, tag(&[2, 3]), false),
        ],
        vec![],
    ]
}

#[test]
fn the_compound_bump_is_accepted_and_a_missing_sibling_is_named() {
    // `compound_accepted`.
    let bump = bump_bytes(800_002, 4, &compound_levels());
    let headers = one_header(800_002, root_of(&bump));
    let (bytes, _) = wire(V1, None, &[bump], &[]);
    assert!(structure(&bytes, &headers).is_valid());

    // `broken_refused`: the level-1 sibling at offset 3 dropped. The refusal
    // names the level-0 leaf whose path breaks (the leading leaf, at stream
    // offset 12) and the node that is missing; never a duplicate assumed.
    let mut levels = compound_levels();
    levels[1] = vec![LeafSpec::Hash(5, tag(&[1, 5]), false)];
    let (bytes, _) = wire(V1, None, &[bump_bytes(800_002, 4, &levels)], &[]);
    assert_eq!(
        refusal(structure(&bytes, &headers)),
        (
            12,
            Reason::MissingSibling {
                level: 1,
                offset: 3
            }
        )
    );
}

#[test]
fn a_tree_height_byte_of_65_is_refused_at_its_offset_and_64_reads() {
    // `height65_refused`, `height65_wire_refused`: the BUMP at 5, a five-byte
    // block height, the tree-height byte at 10.
    let bump = bump_bytes(800_003, 65, &[vec![LeafSpec::Hash(0, tag(&[0]), true)]]);
    let (bytes, _) = wire(V1, None, &[bump], &[]);
    assert_eq!(
        refusal(structure(&bytes, &HashMap::new())),
        (10, Reason::TreeHeightOver64 { height: 65 })
    );

    // `height64_parses`: the format's bound, not a size rule.
    let mut levels = vec![vec![LeafSpec::Hash(0, tag(&[0]), true), LeafSpec::Dup(1)]];
    levels.resize(64, vec![LeafSpec::Dup(1)]);
    let bump = bump_bytes(800_003, 64, &levels);
    let headers = one_header(800_003, root_of(&bump));
    let (bytes, _) = wire(V1, None, &[bump], &[]);
    match elements(&bytes).unwrap().as_slice() {
        [Element::Bump(b)] => assert_eq!(b.levels.len(), 64),
        other => panic!("one BUMP expected, got {other:?}"),
    }
    assert!(structure(&bytes, &headers).is_valid());

    // A tree height of 0 has no level 0.
    let (bytes, _) = wire(V1, None, &[bump_bytes(800_003, 0, &[])], &[]);
    assert_eq!(
        refusal(structure(&bytes, &HashMap::new())),
        (10, Reason::TreeHeightZero)
    );
}

#[test]
fn a_leaf_outside_its_level_and_a_flag_outside_its_table_are_named() {
    // Level 0 of a tree of height 2 is four wide: offset 4 is outside it.
    let bump = bump_bytes(
        800_003,
        2,
        &[vec![LeafSpec::Hash(4, tag(&[0]), true)], vec![]],
    );
    let (bytes, _) = wire(V1, None, &[bump], &[]);
    assert_eq!(
        refusal(structure(&bytes, &HashMap::new())),
        (
            12,
            Reason::OffsetOutsideTree {
                level: 0,
                offset: 4
            }
        )
    );

    // A leaf flag of 3, at the flag's own byte.
    let mut bump = varint(800_003);
    bump.extend_from_slice(&[1, 1, 0, 3]);
    let (bytes, _) = wire(V1, None, &[bump], &[]);
    assert_eq!(
        refusal(structure(&bytes, &HashMap::new())),
        (13, Reason::BadFlag { byte: 3 })
    );

    // A level 0 with no hash proves nothing.
    let bump = bump_bytes(800_003, 1, &[vec![LeafSpec::Dup(1)]]);
    let (bytes, _) = wire(V1, None, &[bump], &[]);
    assert_eq!(
        refusal(structure(&bytes, &HashMap::new())),
        (5, Reason::NoTxidAtLevelZero)
    );

    // A node the level below determines differs from the one carried.
    let bump = bump_bytes(
        800_003,
        2,
        &[
            vec![
                LeafSpec::Hash(0, tag(&[0]), true),
                LeafSpec::Hash(1, tag(&[1]), false),
            ],
            vec![LeafSpec::Hash(0, tag(&[9]), false), LeafSpec::Dup(1)],
        ],
    );
    let (bytes, _) = wire(V1, None, &[bump], &[]);
    assert_eq!(
        refusal(structure(&bytes, &HashMap::new())),
        (
            12,
            Reason::MismatchedNode {
                level: 1,
                offset: 0
            }
        )
    );
}

// ---------------------------------------------------------------------------
// The refusals the charter names, each with its offset
// ---------------------------------------------------------------------------

#[test]
fn an_input_naming_no_element_is_refused_at_its_32_bytes() {
    // `orphan_refused`: the transaction at 6, the previous txid at 11.
    let stranger = tag(&[42]);
    let orphan = raw_tx(&[(stranger, 0)], 1);
    let (bytes, offsets) = wire(V1, None, &[], &[Entry::Raw(orphan.clone(), None)]);
    assert_eq!(offsets, vec![6]);
    assert_eq!(
        refusal(structure(&bytes, &HashMap::new())),
        (11, Reason::InputNamesNoElement { txid: stranger })
    );

    // `proven_orphan_accepted`: the same transaction proven by a BUMP; its
    // proof vouches for its inputs (0062.md:178-183).
    let bump = bump_bytes(
        800_004,
        1,
        &[vec![
            LeafSpec::Hash(0, txid(&orphan), true),
            LeafSpec::Dup(1),
        ]],
    );
    let headers = one_header(800_004, root_of(&bump));
    let (bytes, _) = wire(V1, None, &[bump], &[Entry::Raw(orphan, Some(0))]);
    assert!(structure(&bytes, &headers).is_valid());
}

#[test]
fn a_root_the_headers_do_not_carry_is_refused_at_the_bump() {
    // `root_not_carried_refused`, `no_header_refused`.
    let c = chain(3, false);
    let expected = (
        5,
        Reason::RootNotCarried {
            height: 800_000,
            root: c.anchor_root,
        },
    );
    let mut other = c.anchor_root;
    other[0] ^= 1;
    assert_eq!(
        refusal(structure(&c.bytes, &one_header(800_000, other))),
        expected
    );
    assert_eq!(
        refusal(structure(&c.bytes, &one_header(1, [0u8; 32]))),
        expected
    );
}

#[test]
fn a_subject_that_is_not_the_tip_is_refused() {
    // `wrong_subject_refused`: the second link as the subject of the
    // three-link chain; the subject's 32 bytes sit at offset 4.
    let entries = chain_entries(3);
    let second = match &entries[2] {
        Entry::Raw(raw, _) => txid(raw),
        Entry::TxidOnly(_) => unreachable!(),
    };
    let c = chain_of(&entries, Some(second));
    assert_eq!(
        refusal(structure(&c.bytes, &c.headers)),
        (4, Reason::SubjectMissing { subject: second })
    );
}

/// The Lean's `withSide`: the three-link chain with a side transaction, which
/// spends the anchor's other output and which nothing spends, before the last
/// link.
fn with_side() -> (Vec<Entry>, Hash32, Hash32) {
    let mut entries = chain_entries(3);
    let anchor = txid(&anchor_tx());
    let side = raw_tx(&[(anchor, 1)], 1);
    let side_txid = txid(&side);
    let last = match entries.last().unwrap() {
        Entry::Raw(raw, _) => txid(raw),
        Entry::TxidOnly(_) => unreachable!(),
    };
    entries.insert(3, Entry::Raw(side, None));
    (entries, side_txid, last)
}

#[test]
fn an_unrelated_transaction_is_refused_at_its_offset() {
    // `unrelated_refused`.
    let (entries, side, last) = with_side();
    let c = chain_of(&entries, Some(last));
    let side_at = c.txs[3].1;
    assert_eq!(c.txs[3].0, side);
    assert_eq!(
        refusal(structure(&c.bytes, &c.headers)),
        (side_at, Reason::UnrelatedTransaction { txid: side })
    );

    // `side_without_subject_accepted`: the atomic rule's concern alone.
    let c = chain_of(&entries, None);
    assert!(structure(&c.bytes, &c.headers).is_valid());
}

#[test]
fn a_txid_only_entry_is_accepted_when_a_bump_proves_it() {
    // `stub_proven`, `stub_not_proven`: V2, the BUMP at 5 (43 bytes), the
    // count at 48, the format byte at 49, the 32 bytes at 50.
    let anchor = txid(&anchor_tx());
    let headers = one_header(800_000, root_of(&anchor_bump()));
    let (bytes, offsets) = wire(V2, None, &[anchor_bump()], &[Entry::TxidOnly(anchor)]);
    assert_eq!(offsets, vec![50]);
    assert!(structure(&bytes, &headers).is_valid());

    let stranger = tag(&[42]);
    let (bytes, _) = wire(V2, None, &[anchor_bump()], &[Entry::TxidOnly(stranger)]);
    assert_eq!(
        refusal(structure(&bytes, &headers)),
        (50, Reason::StubNotProven { txid: stranger })
    );

    // A V2 format byte of 3.
    let mut bytes = V2.to_le_bytes().to_vec();
    bytes.extend_from_slice(&[0, 1, 3]);
    assert_eq!(
        refusal(structure(&bytes, &headers)),
        (6, Reason::BadFlag { byte: 3 })
    );
}

#[test]
fn a_bump_index_is_held_to_the_bump_it_names() {
    // `bad_index_refused`, `not_in_bump_refused`: the transaction at 49.
    let headers = one_header(800_000, root_of(&anchor_bump()));
    let (bytes, offsets) = wire(
        V1,
        None,
        &[anchor_bump()],
        &[Entry::Raw(anchor_tx(), Some(1))],
    );
    assert_eq!(offsets, vec![49]);
    assert_eq!(
        refusal(structure(&bytes, &headers)),
        (49, Reason::BumpIndexNamesNoBump { index: 1 })
    );

    let side = raw_tx(&[(txid(&anchor_tx()), 1)], 1);
    let (bytes, _) = wire(
        V1,
        None,
        &[anchor_bump()],
        &[Entry::Raw(side.clone(), Some(0))],
    );
    assert_eq!(
        refusal(structure(&bytes, &headers)),
        (
            49,
            Reason::TxidNotInBump {
                index: 0,
                txid: txid(&side)
            }
        )
    );

    // A has-BUMP byte of 2 (V1), at the byte.
    let (mut bytes, _) = wire(V1, None, &[anchor_bump()], &[Entry::Raw(anchor_tx(), None)]);
    let last = bytes.len() - 1;
    bytes[last] = 2;
    assert_eq!(
        refusal(structure(&bytes, &headers)),
        (last as u64, Reason::BadFlag { byte: 2 })
    );
}

#[test]
fn a_claimed_count_is_read_and_the_refusal_is_for_the_bytes() {
    // `huge_count_refused_for_bytes`: nBUMPs of 4,294,967,295 over an empty
    // stream is a bad varint at 9, where the BUMP's block height was due.
    let mut bytes = V1.to_le_bytes().to_vec();
    bytes.extend_from_slice(&[0xFE, 0xFF, 0xFF, 0xFF, 0xFF]);
    assert_eq!(
        refusal(structure(&bytes, &HashMap::new())),
        (9, Reason::BadVarint)
    );

    // The same for nTransactions, and for a count of 2^64 - 1: a truncated
    // version field at 14, where the transaction was due.
    let mut bytes = V1.to_le_bytes().to_vec();
    bytes.push(0);
    bytes.push(0xFF);
    bytes.extend_from_slice(&u64::MAX.to_le_bytes());
    assert_eq!(
        refusal(structure(&bytes, &HashMap::new())),
        (14, Reason::Truncated { needed: 4 })
    );

    // `bad_version_refused`.
    let mut bytes = 7u32.to_le_bytes().to_vec();
    bytes.extend_from_slice(&[0, 0]);
    assert_eq!(
        refusal(structure(&bytes, &HashMap::new())),
        (0, Reason::BadVersion { word: 7 })
    );
    // Behind the atomic prefix the version word sits at 36.
    let mut bytes = ATOMIC.to_le_bytes().to_vec();
    bytes.extend_from_slice(&[0u8; 32]);
    bytes.extend_from_slice(&7u32.to_le_bytes());
    assert_eq!(
        refusal(structure(&bytes, &HashMap::new())),
        (36, Reason::BadVersion { word: 7 })
    );
    // An empty stream: the version word was due.
    assert_eq!(
        refusal(structure(&[], &HashMap::new())),
        (0, Reason::Truncated { needed: 4 })
    );
}

// ---------------------------------------------------------------------------
// The resumption at `k`
// ---------------------------------------------------------------------------

/// The cursor after `k` elements, through its bytes.
fn cursor_at(
    bytes: &[u8],
    headers: &HashMap<u64, Hash32>,
    k: u64,
    scripts: bool,
) -> Option<Cursor> {
    let mut reader = if scripts {
        StreamVerifier::new(bytes, headers, None)
    } else {
        StreamVerifier::structure_only(bytes, headers, None)
    };
    for _ in 0..k {
        match reader.step().unwrap() {
            Progress::Stepped => {}
            Progress::Verdict(_) => return None,
        }
    }
    let cursor = reader.cursor();
    assert_eq!(cursor.elements_read(), k);
    let stored = cursor.to_binary();
    let restored = Cursor::from_binary(&stored).expect("the cursor's bytes read back");
    assert_eq!(restored, cursor);
    assert_eq!(restored.to_binary(), stored);
    Some(restored)
}

fn resumes_at(bytes: &[u8], headers: &HashMap<u64, Hash32>, k: u64) -> bool {
    let whole = structure(bytes, headers);
    let Some(cursor) = cursor_at(bytes, headers, k, false) else {
        return false;
    };
    let rest = &bytes[cursor.offset() as usize..];
    resume(cursor, rest, headers).unwrap() == whole
}

#[test]
fn a_cursor_at_every_k_resumes_to_the_whole_verdict() {
    // `small_resumes`: every k of the five elements.
    let c = chain(3, false);
    assert!(structure(&c.bytes, &c.headers).is_valid());
    for k in 0..=5 {
        assert!(resumes_at(&c.bytes, &c.headers, k), "k = {k}");
    }
    // `small_atomic_resumes`.
    let a = chain(3, true);
    assert!(structure(&a.bytes, &a.headers).is_valid());
    for k in 0..=5 {
        assert!(resumes_at(&a.bytes, &a.headers, k), "atomic, k = {k}");
    }
    // `refusing_resumes`: a cursor into a reading that refuses later yields
    // the same refusal.
    let (entries, side, last) = with_side();
    let c = chain_of(&entries, Some(last));
    assert_eq!(
        structure(&c.bytes, &c.headers),
        Verdict::Invalid {
            offset: c.txs[3].1,
            kind: Kind::UnrelatedTransaction,
            reason: Reason::UnrelatedTransaction { txid: side }
        }
    );
    for k in 0..=6 {
        assert!(resumes_at(&c.bytes, &c.headers, k), "refusing, k = {k}");
    }
    // A reading that refuses inside an element: the cursor before it resumes
    // to the same refusal at the same offset.
    let c = chain(3, false);
    let wrong = one_header(800_000, [7u8; 32]);
    assert!(resumes_at(&c.bytes, &wrong, 0));
}

// ---------------------------------------------------------------------------
// The BRC-62 example at the pin (BRCs@ed1b015 transactions/0062.md:150-154)
// ---------------------------------------------------------------------------

const BRC62_EXAMPLE: &str = concat!(
    "0100beef01fe636d0c0007021400fe507c0c7aa754cef1f7889d5fd395cf1f785dd7de98eed895dbedfe4e5b",
    "c70d1502ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e010b00bc4ff395ef",
    "d11719b277694cface5aa50d085a0bb81f613f70313acd28cf4557010400574b2d9142b8d28b61d88e3b2c3f",
    "44d858411356b49a28a4643b6d1a6a092a5201030051a05fc84d531b5d250c23f4f886f6812f9fe3f402d616",
    "07f977b4ecd2701c19010000fd781529d58fc2523cf396a7f25440b409857e7e221766c57214b1d38c7b481f",
    "01010062f542f45ea3660f86c013ced80534cb5fd4c19d66c56e7e8c5d4bf2d40acc5e010100b121e91836fd",
    "7cd5102b654e9f72f3cf6fdbfd0b161c53a9c54b12c841126331020100000001cd4e4cac3c7b56920d1e7655",
    "e7e260d31f29d9a388d04910f1bbd72304a79029010000006b483045022100e75279a205a547c445719420aa",
    "3138bf14743e3f42618e5f86a19bde14bb95f7022064777d34776b05d816daf1699493fcdf2ef5a5ab1ad710",
    "d9c97bfb5b8f7cef3641210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76",
    "ffffffff013e660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac0000000001",
    "000100000001ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e000000006a47",
    "304402203a61a2e931612b4bda08d541cfb980885173b8dcf64a3471238ae7abcd368d6402204cbf24f04b9a",
    "a2256d8901f0ed97866603d2be8324c2bfb7a37bf8fc90edd5b441210263e2dee22b1ddc5e11f6fab8bcd237",
    "8bdd19580d640501ea956ec0e786f93e76ffffffff013c660000000000001976a9146bfd5c7fbe21529d4580",
    "3dbcf0c87dd3c71efbc288ac0000000000",
);

fn example() -> Vec<u8> {
    from_hex(BRC62_EXAMPLE).unwrap()
}

#[test]
fn the_brc62_example_is_cut_as_the_lean_cuts_it_and_is_accepted() {
    let bytes = example();
    assert_eq!(bytes.len(), 677);
    // `example_cut`: one BUMP of 285 bytes at 5, the parent (192 bytes, BUMP
    // index 0) at 291, the payment (191 bytes) at 485.
    let els = elements(&bytes).unwrap();
    let shape: Vec<(u64, u64, Option<u64>)> = els
        .iter()
        .map(|e| {
            let index = match e {
                Element::Tx { bump_index, .. } => *bump_index,
                _ => None,
            };
            (e.offset(), e.wire_len(), index)
        })
        .collect();
    assert_eq!(
        shape,
        vec![(5, 285, None), (291, 192, Some(0)), (485, 191, None)]
    );

    // The in-memory reader agrees on the root and on the txids.
    let mut beef = Beef::from_binary(&bytes).unwrap();
    let Element::Bump(bump) = &els[0] else {
        panic!("a BUMP leads")
    };
    assert_eq!(bump.block_height, 814_435);
    assert_eq!(
        display_hex(&bump.root),
        beef.bumps[0].compute_root(None).unwrap()
    );
    assert_eq!(
        bump.to_merkle_path().unwrap().to_binary(),
        beef.bumps[0].to_binary()
    );
    let stream_txids: Vec<String> = els
        .iter()
        .filter_map(|e| match e {
            Element::Tx { txid, .. } => Some(display_hex(txid)),
            _ => None,
        })
        .collect();
    let memory_txids: Vec<String> = beef.txs.iter().map(|t| t.txid()).collect();
    assert_eq!(stream_txids, memory_txids);
    assert!(beef.verify_valid(false).valid);

    // `example_accepted`, under SHA-256: the parent's txid is the hash the
    // BUMP carries, and the payment's signature spends the parent's output.
    let headers = one_header(814_435, bump.root);
    let roots = vec![(814_435, bump.root)];
    assert_eq!(
        structure(&bytes, &headers),
        Verdict::Valid {
            subject: None,
            roots: roots.clone()
        }
    );
    assert_eq!(
        verify_stream(bytes.as_slice(), &headers, None).unwrap(),
        Verdict::Valid {
            subject: None,
            roots: roots.clone()
        }
    );

    // `atomic_example_accepted`, `atomic_example_wrong_subject`.
    let (Element::Tx { txid: parent, .. }, Element::Tx { txid: payment, .. }) = (&els[1], &els[2])
    else {
        panic!("two transactions follow")
    };
    let atomic = |subject: &Hash32| {
        let mut v = ATOMIC.to_le_bytes().to_vec();
        v.extend_from_slice(subject);
        v.extend_from_slice(&bytes);
        v
    };
    assert_eq!(
        verify_stream(atomic(payment).as_slice(), &headers, None).unwrap(),
        Verdict::Valid {
            subject: Some(*payment),
            roots
        }
    );
    assert_eq!(
        refusal(verify_stream(atomic(parent).as_slice(), &headers, None).unwrap()),
        (4, Reason::SubjectMissing { subject: *parent })
    );

    // `trailing_refused`.
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        refusal(verify_stream(trailing.as_slice(), &headers, None).unwrap()),
        (677, Reason::TrailingBytes)
    );

    // A subject the caller names, without the prefix: the payment is the tip;
    // the parent is not, and the refusal names the transaction that is.
    assert!(verify_stream(bytes.as_slice(), &headers, Some(*payment))
        .unwrap()
        .is_valid());
    assert_eq!(
        refusal(verify_stream(bytes.as_slice(), &headers, Some(*parent)).unwrap()),
        (485, Reason::SubjectMissing { subject: *parent })
    );
    // A subject the caller names against a prefix that names another.
    assert_eq!(
        refusal(verify_stream(atomic(payment).as_slice(), &headers, Some(*parent)).unwrap()),
        (4, Reason::SubjectMissing { subject: *parent })
    );
}

#[test]
fn the_example_reads_the_same_in_chunks_of_every_size_and_resumes_at_every_k() {
    let bytes = example();
    let whole = elements(&bytes).unwrap();
    for size in 1..=64usize {
        let mut decoder = BeefDecoder::new();
        let mut got = Vec::new();
        for chunk in bytes.chunks(size) {
            let mut input = chunk;
            while let Step::Element(e) = decoder.next(&mut input).unwrap() {
                got.push(e);
            }
            assert!(input.is_empty());
        }
        decoder.finish().unwrap();
        assert_eq!(got, whole, "chunks of {size}");
        assert_eq!(decoder.offset(), 677);
    }

    // With scripts: a cursor after each element carries the parent's output
    // the payment spends.
    let Element::Bump(bump) = &whole[0] else {
        panic!("a BUMP leads")
    };
    let headers = one_header(814_435, bump.root);
    let verdict = verify_stream(bytes.as_slice(), &headers, None).unwrap();
    assert!(verdict.is_valid());
    for k in 0..=3 {
        let cursor = cursor_at(&bytes, &headers, k, true).unwrap();
        if k == 2 {
            assert_eq!(cursor.index().retained_outputs(), (1, 25));
        }
        if k == 3 {
            // The parent's one output is spent and gone; the payment's waits.
            assert_eq!(cursor.index().retained_outputs(), (1, 25));
        }
        let rest = &bytes[cursor.offset() as usize..];
        assert_eq!(resume(cursor, rest, &headers).unwrap(), verdict, "k = {k}");
    }
}

#[test]
fn every_truncation_of_the_example_is_a_refusal_at_the_field_that_ran_out() {
    let bytes = example();
    let els = elements(&bytes).unwrap();
    let Element::Bump(bump) = &els[0] else {
        panic!("a BUMP leads")
    };
    let headers = one_header(814_435, bump.root);
    for len in 0..bytes.len() {
        let (offset, reason) = refusal(verify_stream(&bytes[..len], &headers, None).unwrap());
        assert!(
            matches!(reason, Reason::Truncated { .. } | Reason::BadVarint),
            "cut at {len}: {reason:?}"
        );
        assert!(offset <= len as u64, "cut at {len}: named {offset}");
    }
}

// ---------------------------------------------------------------------------
// The one-transaction block: accepted here, refused by the Lean definition
// ---------------------------------------------------------------------------

#[test]
fn a_block_of_one_transaction_has_a_one_leaf_bump_whose_root_is_the_txid() {
    // `MerklePath::from_coinbase_txid` writes one level holding the one leaf
    // (the reference: ts-stack@edf6e03 MerklePath.ts:345,390-391). The root
    // is the txid. The Lean's climb answers `missingSibling 0 1` for these
    // bytes; this reader follows the reference.
    // The one transaction of such a block is its coinbase: one input, the
    // null outpoint (the Lean's `loneTx`).
    let coinbase = raw_tx(&[([0u8; 32], 0xFFFF_FFFF)], 1);
    let id = txid(&coinbase);
    let path = MerklePath::from_coinbase_txid(&display_hex(&id), 800_010);
    assert_eq!(path.compute_root(None).unwrap(), display_hex(&id));
    let bump = path.to_binary();
    assert_eq!(root_of(&bump), id);
    let (bytes, _) = wire(V1, None, &[bump], &[Entry::Raw(coinbase, Some(0))]);
    assert!(structure(&bytes, &one_header(800_010, id)).is_valid());

    // The one leaf at offset 1 is not that shape: the Lean's rule stands.
    let bump = bump_bytes(800_010, 1, &[vec![LeafSpec::Hash(1, id, true)]]);
    let (bytes, _) = wire(V1, None, &[bump], &[]);
    assert_eq!(
        refusal(structure(&bytes, &HashMap::new())),
        (
            12,
            Reason::MissingSibling {
                level: 0,
                offset: 0
            }
        )
    );
}

// ---------------------------------------------------------------------------
// The spends: the interpreter's verdict, never one of the nineteen kinds
// ---------------------------------------------------------------------------

const OP_TRUE: &[u8] = &[0x51];
const OP_FALSE: &[u8] = &[0x00];

/// A proven funding transaction with the given outputs, and its BUMP.
fn funded(outputs: &[(u64, &[u8])]) -> (Vec<u8>, Vec<u8>, HashMap<u64, Hash32>) {
    let funding = tx_with(&[([0xAA; 32], 0, &[])], outputs);
    let bump = bump_bytes(
        800_000,
        1,
        &[vec![
            LeafSpec::Hash(0, txid(&funding), true),
            LeafSpec::Dup(1),
        ]],
    );
    let headers = one_header(800_000, root_of(&bump));
    (funding, bump, headers)
}

fn scripts(bytes: &[u8], headers: &HashMap<u64, Hash32>) -> Verdict {
    verify_stream(bytes, headers, None).unwrap()
}

#[test]
fn a_spend_the_script_allows_is_valid_and_one_it_refuses_is_a_spend_refusal() {
    let (funding, bump, headers) = funded(&[(1_000, OP_TRUE), (1_000, OP_FALSE)]);
    let f = txid(&funding);

    let good = tx_with(&[(f, 0, &[])], &[(1_000, OP_TRUE)]);
    let (bytes, _) = wire(
        V1,
        None,
        std::slice::from_ref(&bump),
        &[Entry::Raw(funding.clone(), Some(0)), Entry::Raw(good, None)],
    );
    assert!(scripts(&bytes, &headers).is_valid());

    // The second output is locked by OP_FALSE: the script refuses, and the
    // structure alone is still a valid BEEF.
    let bad = tx_with(&[(f, 1, &[])], &[(1_000, OP_TRUE)]);
    let (bytes, offsets) = wire(
        V1,
        None,
        std::slice::from_ref(&bump),
        &[
            Entry::Raw(funding.clone(), Some(0)),
            Entry::Raw(bad.clone(), None),
        ],
    );
    match scripts(&bytes, &headers) {
        Verdict::SpendRefused {
            offset,
            txid: spender,
            input,
            why: SpendRefusal::Script(_),
        } => {
            assert_eq!(offset, offsets[1] + 5);
            assert_eq!(spender, txid(&bad));
            assert_eq!(input, Some(0));
        }
        other => panic!("a spend refusal expected, got {other:?}"),
    }
    assert!(structure(&bytes, &headers).is_valid());

    // More out than in.
    let rich = tx_with(&[(f, 0, &[])], &[(1_001, OP_TRUE)]);
    let (bytes, offsets) = wire(
        V1,
        None,
        std::slice::from_ref(&bump),
        &[Entry::Raw(funding.clone(), Some(0)), Entry::Raw(rich, None)],
    );
    assert!(matches!(
        scripts(&bytes, &headers),
        Verdict::SpendRefused { offset, input: None, why: SpendRefusal::CreatesValue, .. }
            if offset == offsets[1]
    ));

    // An output index the parent does not have.
    let far = tx_with(&[(f, 2, &[])], &[(1, OP_TRUE)]);
    let (bytes, _) = wire(
        V1,
        None,
        &[bump],
        &[Entry::Raw(funding, Some(0)), Entry::Raw(far, None)],
    );
    assert!(matches!(
        scripts(&bytes, &headers),
        Verdict::SpendRefused {
            why: SpendRefusal::OutputNotAvailable { vout: 2 },
            ..
        }
    ));
}

#[test]
fn an_output_is_kept_until_it_is_spent_and_spent_once() {
    let (funding, bump, headers) = funded(&[(1_000, OP_TRUE), (1_000, OP_TRUE)]);
    let f = txid(&funding);
    let first = tx_with(&[(f, 0, &[])], &[(1_000, OP_TRUE)]);
    let second = tx_with(&[(f, 0, &[])], &[(999, OP_TRUE)]);
    let (bytes, offsets) = wire(
        V1,
        None,
        std::slice::from_ref(&bump),
        &[
            Entry::Raw(funding.clone(), Some(0)),
            Entry::Raw(first.clone(), None),
            Entry::Raw(second, None),
        ],
    );
    // Two transactions spending one output: the second finds it gone.
    assert!(matches!(
        scripts(&bytes, &headers),
        Verdict::SpendRefused { offset, why: SpendRefusal::OutputNotAvailable { vout: 0 }, .. }
            if offset == offsets[2] + 5
    ));
    // The structure alone, which is the Lean's validity, has no such rule.
    assert!(structure(&bytes, &headers).is_valid());

    // The same transaction written twice is read once: judged at its
    // earliest entry, not held to have spent its own inputs.
    let (bytes, _) = wire(
        V1,
        None,
        std::slice::from_ref(&bump),
        &[
            Entry::Raw(funding.clone(), Some(0)),
            Entry::Raw(first.clone(), None),
            Entry::Raw(first.clone(), None),
        ],
    );
    assert!(scripts(&bytes, &headers).is_valid());

    // What the index keeps: after the funding transaction two outputs; after
    // the spend of one, the other and the spender's.
    let (bytes, _) = wire(
        V1,
        None,
        std::slice::from_ref(&bump),
        &[
            Entry::Raw(funding.clone(), Some(0)),
            Entry::Raw(first, None),
        ],
    );
    assert_eq!(
        cursor_at(&bytes, &headers, 2, true)
            .unwrap()
            .index()
            .retained_outputs(),
        (2, 2)
    );
    assert_eq!(
        cursor_at(&bytes, &headers, 3, true)
            .unwrap()
            .index()
            .retained_outputs(),
        (2, 2)
    );
    assert_eq!(
        cursor_at(&bytes, &headers, 3, false)
            .unwrap()
            .index()
            .retained_outputs(),
        (0, 0)
    );

    // A parent that is a txid-only entry has no output to run a script on.
    let child = tx_with(&[(f, 0, &[])], &[(1, OP_TRUE)]);
    let (bytes, _) = wire(
        V2,
        None,
        &[bump],
        &[Entry::TxidOnly(f), Entry::Raw(child, None)],
    );
    assert!(matches!(
        scripts(&bytes, &headers),
        Verdict::SpendRefused {
            why: SpendRefusal::ParentIsTxidOnly,
            ..
        }
    ));
    assert!(structure(&bytes, &headers).is_valid());
}

/// One pass keeps every unspent output, since it cannot know which will be
/// spent; two passes keep the outputs that are spent and no others.
#[test]
fn two_passes_keep_only_the_outputs_that_are_spent() {
    // A funding transaction with a spendable output and a 5,000-byte output
    // nothing spends (a data carrier: OP_FALSE OP_RETURN and its payload).
    let mut carrier = vec![0x00, 0x6a, 0x4d, 0x84, 0x13];
    carrier.resize(5 + 4_996, 0xEE);
    let (funding, bump, headers) = funded(&[(1_000, OP_TRUE), (0, &carrier)]);
    let f = txid(&funding);
    let child = tx_with(&[(f, 0, &[])], &[(1_000, OP_TRUE), (0, &carrier)]);
    let tip = tx_with(&[(txid(&child), 0, &[])], &[(1_000, OP_TRUE)]);
    let (bytes, _) = wire(
        V1,
        None,
        &[bump],
        &[
            Entry::Raw(funding, Some(0)),
            Entry::Raw(child, None),
            Entry::Raw(tip, None),
        ],
    );

    let one_pass = verify_stream(bytes.as_slice(), &headers, None).unwrap();
    assert!(one_pass.is_valid());
    let two_pass = verify_stream_two_pass(std::io::Cursor::new(&bytes), &headers, None).unwrap();
    assert_eq!(two_pass, one_pass);

    // One pass, after every element: both carriers and the tip's output.
    let kept = cursor_at(&bytes, &headers, 4, true).unwrap();
    assert_eq!(kept.index().retained_outputs(), (3, 2 * 5_001 + 1));
    assert_eq!(kept.index().wanted_outpoints(), None);

    // Two passes: the first names the two outpoints that are spent; the
    // second keeps each until its spender arrives and never a carrier.
    let referenced = referenced_outpoints(bytes.as_slice()).unwrap();
    assert_eq!(referenced.len(), 2);
    let mut reader =
        StreamVerifier::retaining(bytes.as_slice(), &headers, None, referenced.clone());
    let mut kept = Vec::new();
    loop {
        match reader.step().unwrap() {
            Progress::Stepped => kept.push((
                reader.index().retained_outputs(),
                reader.index().wanted_outpoints(),
            )),
            Progress::Verdict(v) => {
                assert_eq!(v, one_pass);
                break;
            }
        }
    }
    assert_eq!(
        kept,
        vec![
            ((0, 0), Some(2)),
            ((1, 1), Some(2)),
            ((1, 1), Some(1)),
            ((0, 0), Some(0)),
        ]
    );

    // A cursor carries the outpoints still waited for.
    let mut reader = StreamVerifier::retaining(bytes.as_slice(), &headers, None, referenced);
    reader.step().unwrap();
    reader.step().unwrap();
    let cursor = Cursor::from_binary(&reader.cursor().to_binary()).unwrap();
    assert_eq!(cursor, reader.cursor());
    assert_eq!(cursor.index().wanted_outpoints(), Some(2));
    let rest = &bytes[cursor.offset() as usize..];
    assert_eq!(resume(cursor, rest, &headers).unwrap(), one_pass);

    // A set that names nothing keeps nothing: the spend is refused, never
    // accepted.
    let empty = referenced_outpoints(&wire(V1, None, &[], &[]).0[..]).unwrap();
    assert!(empty.is_empty());
    assert!(matches!(
        StreamVerifier::retaining(bytes.as_slice(), &headers, None, empty)
            .run()
            .unwrap(),
        Verdict::SpendRefused {
            why: SpendRefusal::OutputNotAvailable { vout: 0 },
            ..
        }
    ));
}

// ---------------------------------------------------------------------------
// The other sources: a function as the headers, the mock tracker, async
// ---------------------------------------------------------------------------

struct Chunks {
    bytes: Vec<u8>,
    at: usize,
    size: usize,
}

impl AsyncByteSource for Chunks {
    async fn next_chunk(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        if self.at == self.bytes.len() {
            return Ok(None);
        }
        let end = (self.at + self.size).min(self.bytes.len());
        let chunk = self.bytes[self.at..end].to_vec();
        self.at = end;
        Ok(Some(chunk))
    }
}

#[tokio::test]
async fn the_asynchronous_reader_gives_the_verdict_of_the_synchronous_one() {
    let bytes = example();
    let Element::Bump(bump) = &elements(&bytes).unwrap()[0] else {
        panic!("a BUMP leads")
    };
    let mut tracker = MockChainTracker::new(900_000);
    tracker.add_root(814_435, display_hex(&bump.root));
    let expected = verify_stream(bytes.as_slice(), &tracker, None).unwrap();
    assert!(expected.is_valid());
    assert_eq!(
        verify_stream(
            bytes.as_slice(),
            HeadersFn(|h, r: &Hash32| h == 814_435 && *r == bump.root),
            None
        )
        .unwrap(),
        expected
    );
    for size in [1, 7, 100, 4096] {
        let mut source = Chunks {
            bytes: bytes.clone(),
            at: 0,
            size,
        };
        let got = verify_stream_async(&mut source, &tracker, None)
            .await
            .unwrap();
        assert_eq!(got, expected, "chunks of {size}");
    }

    // A tracker without the root: the same refusal from both.
    let empty = MockChainTracker::new(900_000);
    let expected = verify_stream(bytes.as_slice(), &empty, None).unwrap();
    assert_eq!(refusal(expected.clone()).1.kind(), Kind::RootNotCarried);
    let mut source = Chunks {
        bytes: bytes.clone(),
        at: 0,
        size: 33,
    };
    assert_eq!(
        verify_stream_async(&mut source, &empty, None)
            .await
            .unwrap(),
        expected
    );
}

// ---------------------------------------------------------------------------
// A transaction with no input: invalid bytes (bsv-stack-lean #58)
// ---------------------------------------------------------------------------

/// The BEEF the middleware's door met (bsv-middleware-rs 0.4.0,
/// `a_transaction_with_no_input_and_no_proof_anchors_nothing`): a proven
/// stranger with its BUMP, an unproven transaction with no input, and a
/// payment spending it. Every root it carries is the header's.
fn beside_a_proven_stranger(version: u32) -> (Vec<u8>, Vec<u64>, HashMap<u64, Hash32>, Hash32) {
    let (stranger, bump, headers) = funded(&[(7, &[0x53])]);
    let parent = tx_with(&[], &[(100, OP_TRUE)]);
    let payment = tx_with(&[(txid(&parent), 0, &[])], &[(100, OP_TRUE)]);
    let subject = txid(&payment);
    let (bytes, offsets) = wire(
        version,
        None,
        &[bump],
        &[
            Entry::Raw(stranger, Some(0)),
            Entry::Raw(parent, None),
            Entry::Raw(payment, None),
        ],
    );
    (bytes, offsets, headers, subject)
}

/// The offset of a refusal whose kind is `NoInputs`.
fn no_inputs_at(verdict: Verdict) -> u64 {
    let (offset, reason) = refusal(verdict);
    assert_eq!(reason, Reason::NoInputs);
    assert_eq!(reason.kind(), Kind::NoInputs);
    offset
}

#[test]
fn a_transaction_with_no_input_is_invalid_bytes_at_its_offset() {
    for version in [V1, V2] {
        let (bytes, offsets, headers, subject) = beside_a_proven_stranger(version);
        let at = offsets[1];

        // With the scripts run, for the structure alone, and under a named
        // subject: the transaction with no input, at its leading byte.
        assert_eq!(no_inputs_at(scripts(&bytes, &headers)), at);
        assert_eq!(no_inputs_at(structure(&bytes, &headers)), at);
        assert_eq!(
            no_inputs_at(verify_stream(bytes.as_slice(), &headers, Some(subject)).unwrap()),
            at
        );
        assert_eq!(
            no_inputs_at(
                verify_stream_two_pass(std::io::Cursor::new(&bytes), &headers, None).unwrap()
            ),
            at
        );

        // The stream refuses the element itself: no index, no header.
        assert_eq!(elements(&bytes).unwrap_err(), (at, Reason::NoInputs));

        // The whole-BEEF path refuses the same bytes.
        let mut beef = Beef::from_binary(&bytes).unwrap();
        assert!(!beef.verify_valid(false).valid);
        assert!(!beef.is_valid(true));
    }
}

#[test]
fn a_transaction_with_no_input_is_invalid_under_a_bump_too() {
    // A BUMP that carries the txid does not make it a transaction: the node
    // would not have mined it, so no block holds it and no proof of it is a
    // proof. The refusal is the same one, at the transaction, with the BUMP
    // read and its root carried.
    let nothing_in = raw_tx(&[], 2);
    let bump = bump_bytes(
        800_000,
        1,
        &[vec![
            LeafSpec::Hash(0, txid(&nothing_in), true),
            LeafSpec::Dup(1),
        ]],
    );
    let headers = one_header(800_000, root_of(&bump));
    for version in [V1, V2] {
        let (bytes, offsets) = wire(
            version,
            None,
            std::slice::from_ref(&bump),
            &[Entry::Raw(nothing_in.clone(), Some(0))],
        );
        assert_eq!(no_inputs_at(scripts(&bytes, &headers)), offsets[0]);
        assert_eq!(no_inputs_at(structure(&bytes, &headers)), offsets[0]);
        let mut beef = Beef::from_binary(&bytes).unwrap();
        assert!(!beef.verify_valid(false).valid);
    }

    // The control: the same frame around a transaction with one input, which
    // its proof vouches for.
    let one_in = raw_tx(&[([0x11; 32], 0)], 2);
    let bump = bump_bytes(
        800_000,
        1,
        &[vec![
            LeafSpec::Hash(0, txid(&one_in), true),
            LeafSpec::Dup(1),
        ]],
    );
    let headers = one_header(800_000, root_of(&bump));
    let (bytes, _) = wire(V1, None, &[bump], &[Entry::Raw(one_in, Some(0))]);
    assert!(scripts(&bytes, &headers).is_valid());
    assert!(Beef::from_binary(&bytes).unwrap().verify_valid(false).valid);
}

#[tokio::test]
async fn the_asynchronous_reader_refuses_a_transaction_with_no_input() {
    let (bytes, offsets, headers, _) = beside_a_proven_stranger(V1);
    let (_, bump, _) = funded(&[(7, &[0x53])]);
    let mut tracker = MockChainTracker::new(900_000);
    tracker.add_root(800_000, display_hex(&root_of(&bump)));
    let expected = verify_stream(bytes.as_slice(), &headers, None).unwrap();
    let mut source = Chunks {
        bytes: bytes.clone(),
        at: 0,
        size: 7,
    };
    let got = verify_stream_async(&mut source, &tracker, None)
        .await
        .unwrap();
    assert_eq!(got, expected);
    assert_eq!(no_inputs_at(got), offsets[1]);
}
