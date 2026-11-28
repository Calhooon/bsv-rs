//! The standalone BUMP reader (finding-4's fix). `MerklePath::from_binary`,
//! `from_hex` and `from_reader` read a BUMP through [`read_bump`], which keeps
//! this line's own reader structure and refusal words for every shape the
//! 0.8.x reader already refused (an empty path, a missing sibling, a repeated
//! offset, roots that disagree, read through [`MerklePath::new_unchecked`]),
//! and adds the refusals the 0.8.x reader lacked, so the standalone reader
//! refuses the malformed BUMPs the crate's own streaming/BEEF decoder refuses:
//!
//! - a leaf flag byte outside `00`/`01`/`02` (the 0.8.x reader masked it to
//!   its low two bits);
//! - a leaf at an offset outside its level, or an off-path leaf no txid's walk
//!   reaches, or an interior node that disagrees with its children (the 0.8.x
//!   single-txid walk ignored these), through the crate's strict walk
//!   [`beef_stream::bump_root`];
//! - a duplicate at an even offset below a node the walk needs (the 0.8.x
//!   walk paired a duplicate with its working hash regardless of parity; the
//!   0.9 line's `LeftDuplicateBelow`), through [`left_duplicate_below`];
//! - and, for `from_binary`/`from_hex`, a byte after the BUMP frame.
//!
//! The reader stays consistent with the constructors: a shape
//! `MerklePath::new_unchecked` refuses is refused here with the same words, so
//! a BUMP read from bytes and a BUMP built from the same leaves refuse alike.

use std::collections::HashMap;

use super::beef_stream::{bump_root, Hash32, Leaf, Node, Reason};
use super::merkle_path::{tree_height_error, MerklePath, MerklePathLeaf, MAX_TREE_HEIGHT};
use crate::primitives::{from_hex, to_hex, Reader};

/// One BUMP read strictly from `reader`, one frame, the cursor left after it.
/// The structural refusals of [`MerklePath::new_unchecked`] (empty path,
/// missing sibling, repeated offset, disagreeing roots) keep this line's words;
/// the refusals the 0.8.x reader lacked (a bad flag, an off-path or
/// out-of-level leaf, an even-offset duplicate below a needed node) are added.
pub(crate) fn read_bump(reader: &mut Reader) -> crate::Result<MerklePath> {
    let block_height = reader.read_var_int_num()? as u32;
    let tree_height = reader.read_u8()? as usize;
    if tree_height > MAX_TREE_HEIGHT {
        return Err(tree_height_error(tree_height));
    }

    let mut path: Vec<Vec<MerklePathLeaf>> = vec![Vec::new(); tree_height];
    for level in path.iter_mut() {
        let n_leaves = reader.read_var_int_num()?;
        for _ in 0..n_leaves {
            let offset = reader.read_var_int_num()? as u64;
            let flags = reader.read_u8()?;
            // A flag byte outside its table: bit 0 duplicate, bit 1 txid, no
            // other bit and not both (a `03` or any high bit). The 0.8.x
            // reader masked it; the stream decoder refuses it.
            if flags > 2 {
                return Err(reason(&Reason::BadFlag { byte: flags }));
            }
            let leaf = if flags & 1 != 0 {
                MerklePathLeaf::new_duplicate(offset)
            } else {
                // A 32-byte hash in little-endian, kept in display order.
                let mut hash = reader.read_bytes(32)?.to_vec();
                hash.reverse();
                MerklePathLeaf {
                    offset,
                    hash: Some(to_hex(&hash)),
                    txid: flags & 2 != 0,
                    duplicate: false,
                }
            };
            level.push(leaf);
        }
        level.sort_by_key(|l| l.offset);
    }

    // The structural check and root agreement, this line's own (empty path,
    // missing sibling, repeated offset, disagreeing roots), so a read BUMP and
    // a built one refuse alike.
    let merkle_path = MerklePath::new_unchecked(block_height, path)?;

    // The refusals the 0.8.x reader lacked: an off-path or out-of-level leaf
    // (the strict walk leaves a node the tree cannot carry), and a duplicate
    // at an even offset below a node the walk needs.
    check_no_off_path_leaf(&merkle_path)?;
    if let Some((level, offset)) = left_duplicate_below(&merkle_path.path) {
        // The 0.9 line's `Reason::LeftDuplicateBelow`, which this line's
        // `Reason` enum does not carry (a public, non-exhaustive enum: a new
        // variant would be a semver-minor break), written in its words.
        return Err(crate::Error::MerklePathError(format!(
            "LeftDuplicateBelow {{ level: {level}, offset: {offset} }}"
        )));
    }

    Ok(merkle_path)
}

/// A refusal in this reader's words: the stream's reason without the stream's
/// byte-offset prefix, so a read BUMP and a built one (whose refusals carry no
/// byte offset) read alike.
fn reason(r: &Reason) -> crate::Error {
    crate::Error::MerklePathError(format!("{r:?}"))
}

/// The display hash as the stream's wire-order [`Hash32`], or `None` for a hash
/// that is not 32 bytes of hex (the reader always writes 64 hex digits, so this
/// is `Some` for every leaf the reader built).
fn wire_hash(hex: &str) -> Option<Hash32> {
    let mut bytes = from_hex(hex).ok()?;
    bytes.reverse();
    bytes.try_into().ok()
}

/// Refuse a leaf the tree cannot carry: one at an offset outside its level, or
/// an off-path leaf no level-0 txid's walk reaches, or an interior node that
/// disagrees with its children. The crate's strict walk ([`bump_root`]) ends
/// with exactly one root for a whole tree; a leftover or disagreeing node is a
/// leaf the single-txid walk of `new_unchecked` ignored. A path
/// `new_unchecked` accepted whose every leaf is on a txid's path passes here
/// unchanged (honest BUMPs included).
fn check_no_off_path_leaf(path: &MerklePath) -> crate::Result<()> {
    // A leaf outside its level (offset >= 2 ^ (tree height - level)). The
    // 0.8.x single-txid walk ignored such a leaf when it was not on the
    // proven path; `new_unchecked` has already refused the lone-leaf and the
    // level-0 out-of-level cases (its walk needs their sibling), so this fires
    // only for an off-path leaf at a higher level the walk never visited.
    let tree_height = path.path.len();
    for (level_idx, level) in path.path.iter().enumerate() {
        let shift = tree_height - level_idx;
        for leaf in level {
            if shift < 64 && leaf.offset >> shift != 0 {
                return Err(reason(&Reason::OffsetOutsideTree {
                    level: level_idx as u8,
                    offset: leaf.offset,
                }));
            }
        }
    }
    let levels: Vec<Vec<Leaf>> = path
        .path
        .iter()
        .map(|level| {
            level
                .iter()
                .filter_map(|l| {
                    let node = if l.duplicate {
                        Node::Duplicate
                    } else {
                        Node::Hash(wire_hash(l.hash.as_deref()?)?)
                    };
                    Some(Leaf {
                        at: 0,
                        offset: l.offset,
                        node,
                        client: l.txid,
                    })
                })
                .collect()
        })
        .collect();
    match bump_root(0, &levels) {
        Ok(_) => Ok(()),
        Err(refusal) => Err(reason(&refusal.reason)),
    }
}

/// The first `LeftDuplicateBelow` in the BUMP, or `None`: `(level, sibling
/// offset)`. This is the 0.9 line's `bump_root` `whole` tracking, reduced to
/// the verdict it alone adds over this line's `bump_root`. A level-0 hash is
/// whole; a parent computed with a duplicate on its left (an even sibling
/// offset) is not whole; a node that needs a non-whole computed sibling is
/// `LeftDuplicateBelow`. The node hashes are not compared here: every
/// mismatched node, missing sibling, bad flag and out-of-level offset is
/// refused ahead of this. A non-whole node at the root is accepted, as the
/// 0.9 walk accepts it.
fn left_duplicate_below(levels: &[Vec<MerklePathLeaf>]) -> Option<(u8, u64)> {
    // (offset, whole)
    let mut needed: Vec<(u64, bool)> = levels
        .first()?
        .iter()
        .filter_map(|l| (!l.duplicate && l.hash.is_some()).then_some((l.offset, true)))
        .collect();
    if needed.is_empty() {
        return None;
    }
    for (level, leaves) in levels.iter().enumerate() {
        let level = level as u8;
        let mut given: HashMap<u64, bool> = HashMap::with_capacity(leaves.len());
        for l in leaves {
            // true = a hash, false = a duplicate.
            given.entry(l.offset).or_insert(!l.duplicate);
        }
        let mut computed: HashMap<u64, bool> = HashMap::with_capacity(needed.len());
        for &(off, whole) in &needed {
            computed.insert(off, whole);
        }
        let mut parents: HashMap<u64, ()> = HashMap::with_capacity(needed.len());
        let mut next: Vec<(u64, bool)> = Vec::with_capacity(needed.len());
        for &(off, mut whole) in &needed {
            if given.get(&off) == Some(&true) {
                whole = true;
            }
            let s = off ^ 1;
            match given.get(&s) {
                Some(true) => {}
                // A duplicate on the left (even sibling offset) is no hash: the
                // node above is not whole.
                Some(false) => whole &= s % 2 == 1,
                None => match computed.get(&s) {
                    Some(true) => {}
                    Some(false) => return Some((level, s)),
                    None => {} // a missing sibling is refused ahead of this
                },
            }
            let up = off / 2;
            if parents.insert(up, ()).is_none() {
                next.push((up, whole));
            }
        }
        needed = next;
    }
    None
}
