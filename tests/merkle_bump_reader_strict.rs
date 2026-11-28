//! The standalone BUMP reader refuses the malformed flags, offsets and
//! trailing bytes the streaming/BEEF decoder already refuses, instead of
//! masking a flag, ignoring an off-path leaf or leaving bytes after the
//! frame and handing back a (meaningless) root. One meaning for a BUMP
//! wherever this crate reads it (the 0.9 line's #167 reader-unification,
//! ported to the stable line).
//!
//! Each malformed fixture is an honest BUMP built by this crate's own
//! writer, then altered; the honest case is kept to show no answer moves.
#![cfg(feature = "transaction")]

use bsv_rs::primitives::Reader;
use bsv_rs::transaction::{MerklePath, MerklePathLeaf};

const TXID0: &str = "f5eedbcaed2b12685bfc046c04ae7827e47ba6b75cb09342a5ec062ee4c4997f";
const H1: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

/// An honest two-leaf BUMP (block height 100, so its height varint is one
/// byte and the layout is fixed): level 0 holds the txid at offset 0 and its
/// sibling at offset 1. Returns the path and its serialized bytes.
#[allow(clippy::expect_used)] // a helper of the #[test] fns below; a failure here is a test failure
fn honest_two_leaf() -> (MerklePath, Vec<u8>) {
    let path = MerklePath::new(
        100,
        vec![vec![
            MerklePathLeaf::new_txid(0, TXID0.to_string()),
            MerklePathLeaf::new(1, H1.to_string()),
        ]],
    )
    .expect("honest two-leaf path builds");
    let bytes = path.to_binary();
    // [height=0x64][treeHeight=0x01][nLeaves=0x02][off0=0x00][flag0=0x02]
    // [hash0 32][off1=0x01][flag1=0x00][hash1 32]
    assert_eq!(bytes.len(), 1 + 1 + 1 + 1 + 1 + 32 + 1 + 1 + 32);
    assert_eq!(bytes[4], 0x02, "leaf0 flag is the client-txid flag");
    assert_eq!(bytes[38], 0x00, "leaf1 flag is a plain hash");
    (path, bytes)
}

const H2: &str = "aabbccddeeff00112233445566778899aabbccddeeff001122334455667788ff";

/// An honest two-level BUMP (tree height 2, block height 100): level 0 holds
/// the txid at offset 0 and its sibling at offset 1; level 1 holds the one
/// node needed at offset 1. Returns the path and its serialized bytes.
#[allow(clippy::expect_used)] // a helper of the #[test] fns below; a failure here is a test failure
fn honest_two_level() -> (MerklePath, Vec<u8>) {
    let path = MerklePath::new(
        100,
        vec![
            vec![
                MerklePathLeaf::new_txid(0, TXID0.to_string()),
                MerklePathLeaf::new(1, H1.to_string()),
            ],
            vec![MerklePathLeaf::new(1, H2.to_string())],
        ],
    )
    .expect("honest two-level path builds");
    let bytes = path.to_binary();
    // ...[treeHeight=0x02]... L1 count byte sits at index 71 for a 1-byte height.
    assert_eq!(bytes[1], 0x02, "tree height is 2");
    assert_eq!(bytes[71], 0x01, "level 1 holds one leaf");
    (path, bytes)
}

fn is_merkle_err(r: &Result<MerklePath, bsv_rs::Error>) -> bool {
    matches!(r, Err(bsv_rs::Error::MerklePathError(_)))
}

#[test]
fn a_flag_byte_outside_its_table_is_refused_by_from_binary() {
    let (_, mut bytes) = honest_two_leaf();
    bytes[4] = 0x04; // a bit outside {duplicate, txid}
    let r = MerklePath::from_binary(&bytes);
    assert!(
        is_merkle_err(&r),
        "from_binary must refuse a bad flag: {r:?}"
    );
}

#[test]
fn a_flag_byte_outside_its_table_is_refused_by_from_hex() {
    let (_, mut bytes) = honest_two_leaf();
    bytes[4] = 0x04;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let r = MerklePath::from_hex(&hex);
    assert!(is_merkle_err(&r), "from_hex must refuse a bad flag: {r:?}");
}

#[test]
fn a_flag_byte_outside_its_table_is_refused_by_from_reader() {
    let (_, mut bytes) = honest_two_leaf();
    bytes[4] = 0x04;
    let r = MerklePath::from_reader(&mut Reader::new(&bytes));
    assert!(
        is_merkle_err(&r),
        "from_reader must refuse a bad flag: {r:?}"
    );
}

#[test]
fn a_flag_with_both_duplicate_and_txid_bits_is_refused() {
    let (_, mut bytes) = honest_two_leaf();
    bytes[4] = 0x03; // duplicate AND txid: contradictory, no table entry
    let r = MerklePath::from_binary(&bytes);
    assert!(is_merkle_err(&r), "flag byte 3 must be refused: {r:?}");
}

#[test]
fn an_off_path_leaf_outside_its_level_is_refused_not_ignored() {
    let (_, bytes) = honest_two_leaf();
    // Add a third leaf at offset 2, outside a level of width 2. The 0.8.x
    // reader ignored it and still computed a root from the txid.
    let mut m = bytes.clone();
    m[2] = 0x03; // nLeaves 2 -> 3
    m.push(0x02); // offset 2
    m.push(0x00); // flag: plain hash
    m.extend_from_slice(&[0u8; 32]); // its hash
    let r = MerklePath::from_binary(&m);
    assert!(
        is_merkle_err(&r),
        "a leaf outside its level must be refused: {r:?}"
    );
}

#[test]
fn bytes_after_the_bump_frame_are_refused_by_from_binary() {
    let (_, bytes) = honest_two_leaf();
    let mut m = bytes.clone();
    m.push(0x00); // one trailing byte
    let r = MerklePath::from_binary(&m);
    assert!(is_merkle_err(&r), "trailing bytes must be refused: {r:?}");
}

#[test]
fn a_repeated_offset_in_a_level_is_still_refused() {
    let (_, bytes) = honest_two_leaf();
    // A second leaf at offset 0.
    let mut m = bytes.clone();
    m[2] = 0x03; // nLeaves 2 -> 3
    m.push(0x00); // offset 0 again
    m.push(0x00); // flag
    m.extend_from_slice(&[0u8; 32]);
    let r = MerklePath::from_binary(&m);
    assert!(
        is_merkle_err(&r),
        "a repeated offset must be refused: {r:?}"
    );
}

#[test]
fn the_standalone_reader_hands_no_root_for_malformed_bytes() {
    // The finding's exposure: from_binary(untrusted).compute_root() trusted
    // without a tracker check. After the fix the parse refuses, so no root is
    // produced from the malformed bytes at all.
    let (_, mut bytes) = honest_two_leaf();
    bytes[4] = 0x04;
    match MerklePath::from_binary(&bytes) {
        Ok(p) => panic!(
            "malformed bytes parsed; compute_root would hand a root: {:?}",
            p.compute_root(None)
        ),
        Err(bsv_rs::Error::MerklePathError(_)) => {}
        Err(e) => panic!("unexpected error class: {e:?}"),
    }
}

#[test]
fn an_honest_bump_still_parses_and_computes_the_same_root() {
    let (path, bytes) = honest_two_leaf();
    let expected = path.compute_root(Some(TXID0)).expect("honest root");
    for parsed in [
        MerklePath::from_binary(&bytes),
        MerklePath::from_hex(&bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()),
        MerklePath::from_reader(&mut Reader::new(&bytes)),
    ] {
        let parsed = parsed.expect("honest bump parses");
        assert_eq!(parsed.block_height, 100);
        assert_eq!(
            parsed.compute_root(Some(TXID0)).expect("root"),
            expected,
            "honest root unchanged"
        );
        assert_eq!(parsed.to_binary(), bytes, "honest bytes round-trip");
    }
}

#[test]
fn an_off_path_leaf_at_a_higher_level_outside_its_level_is_refused() {
    // A leaf at level 1 offset 5 (a level of width 2). The 0.8.x single-txid
    // walk never visits it and computed a root anyway.
    let (_, bytes) = honest_two_level();
    let mut m = bytes.clone();
    m[71] = 0x02; // level 1 count 1 -> 2
    m.push(0x05); // offset 5, outside the level
    m.push(0x00); // flag
    m.extend_from_slice(&[0u8; 32]);
    let r = MerklePath::from_binary(&m);
    assert!(
        is_merkle_err(&r),
        "a higher-level off-path leaf must be refused: {r:?}"
    );
}

#[test]
fn an_interior_node_that_disagrees_with_its_children_is_refused() {
    // A leaf at level 1 offset 0 (the parent position) carrying a hash that
    // contradicts the node computed from level 0. The 0.8.x walk computed the
    // node and never read the contradicting leaf.
    let (_, bytes) = honest_two_level();
    let mut m = bytes.clone();
    m[71] = 0x02; // level 1 count 1 -> 2
    m.push(0x00); // offset 0 at level 1 (a legal offset)
    m.push(0x00); // flag
    m.extend_from_slice(&[0x11u8; 32]); // a hash that is not the computed node
    let r = MerklePath::from_binary(&m);
    assert!(
        is_merkle_err(&r),
        "a contradicting interior node must be refused: {r:?}"
    );
}

#[test]
fn from_reader_reads_one_bump_and_leaves_the_bytes_after_it() {
    let (_, bytes) = honest_two_leaf();
    let mut framed = bytes.clone();
    let tail = [0xaa, 0xbb, 0xcc];
    framed.extend_from_slice(&tail);
    let mut reader = Reader::new(&framed);
    let path = MerklePath::from_reader(&mut reader).expect("one bump read");
    assert!(path.compute_root(Some(TXID0)).is_ok());
    // The cursor stops after the BUMP; the caller still sees the tail.
    assert_eq!(
        reader.read_remaining(),
        &tail[..],
        "bytes after the BUMP are left"
    );
}

// A BUMP the writer cannot build: a duplicate at an even offset. Height 2,
// level 0 = [hash@0, hash@1, duplicate@2, hash@3], level 1 = []. The duplicate
// at even offset 2 is the LEFT child of the node at level-1 offset 1, which the
// walk needs as the sibling of the node at offset 0. The 0.9 unified reader
// refuses it (LeftDuplicateBelow); the 0.8.x standalone reader computed a root.
// Hand-built because MerklePath::new refuses an even-offset duplicate.
const LEFT_DUP_BELOW: &str = "6402040002\
f5eedbcaed2b12685bfc046c04ae7827e47ba6b75cb09342a5ec062ee4c4997f0100\
00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff02010300\
f5eedbcaed2b12685bfc046c04ae7827e47ba6b75cb09342a5ec062ee4c4997f00";

#[test]
fn an_even_offset_duplicate_below_a_needed_node_is_refused() {
    let r = MerklePath::from_hex(LEFT_DUP_BELOW);
    assert!(
        is_merkle_err(&r),
        "a duplicate at an even offset below a needed node must be refused: {r:?}"
    );
}

// A duplicate at an even offset that is only ever used as a sibling (never a
// node computed from it) is accepted, matching the 0.9 unified reader: height
// 1, level 0 = [duplicate@0, txid@1]. The working hash is paired with itself;
// no higher node needs the duplicate's position. The fix is not over-strict.
const EVEN_DUP_AT_TOP: &str = "6401020001\
0102f5eedbcaed2b12685bfc046c04ae7827e47ba6b75cb09342a5ec062ee4c4997f";

#[test]
fn an_even_offset_duplicate_used_only_as_a_sibling_is_accepted() {
    let r = MerklePath::from_hex(EVEN_DUP_AT_TOP);
    assert!(
        r.is_ok(),
        "an even-offset duplicate used only as a sibling is accepted (0.9 parity): {r:?}"
    );
}

/// A full-height (64-level) BUMP: level 0 holds the txid at offset 0 and a
/// duplicate sibling at offset 1, and every higher level holds the duplicate
/// sibling the climb needs at offset 1. Its root computes through the
/// duplicates, so the reader accepts it, and the off-path width check reaches
/// the top level (`shift == tree_height == 64`), where a level-0 offset is
/// always inside a 64-bit offset's range. The check's `shift < 64` guard keeps
/// it from evaluating `offset >> 64`, which is a shift overflow -- in a debug
/// build a panic (on wasm32 an abort no caller can catch), in a release build a
/// mask back to `offset >> 0`. Pins that guard: with it removed the reader
/// overflows on this honest full-height BUMP instead of reading it. Built by
/// the crate's own writer so the fixture cannot drift from the wire format.
#[allow(clippy::expect_used)] // a #[test] fn; a failure here is a test failure
#[test]
fn a_full_height_bump_is_read_without_an_offset_shift_overflow() {
    let mut path: Vec<Vec<MerklePathLeaf>> = Vec::with_capacity(64);
    path.push(vec![
        MerklePathLeaf::new_txid(0, TXID0.to_string()),
        MerklePathLeaf::new_duplicate(1),
    ]);
    for _ in 1..64 {
        path.push(vec![MerklePathLeaf::new_duplicate(1)]);
    }
    let built = MerklePath::new_unchecked(100, path).expect("a 64-level duplicate tower builds");
    let bytes = built.to_binary();
    assert_eq!(bytes[1], 0x40, "the tree height byte is 64");
    let root = built
        .compute_root(Some(TXID0))
        .expect("the tower computes a root");

    // The reader accepts the full-height BUMP and climbs to the same root; it
    // does not overflow at the top level's `offset >> 64`.
    let read =
        MerklePath::from_binary(&bytes).expect("the full-height BUMP is read, not overflown");
    assert_eq!(
        read.compute_root(Some(TXID0))
            .expect("the read BUMP's root"),
        root,
        "an honest full-height BUMP round-trips to the same root"
    );
}
