//! The cached walk from a level-0 leaf to the root, the reference's
//! `computeRootCached` (`ts-stack@edf6e03` `MerklePath.ts:335-366`), and
//! `hash_pair`: the walk the constructors' root check and `compute_root`
//! share, moved out of `merkle_path.rs` unchanged (#93 P0).

use std::collections::HashMap;

use super::merkle_path::{offset_at_height, MerklePathLeaf};
use crate::primitives::{from_hex, sha256d, to_hex};
use crate::Result;

/// A level of at most this many leaves is scanned, not indexed: a single
/// `compute_root` over a typical BUMP stays as fast as the 0.3.34 scan.
const SCAN_MAX: usize = 16;

/// A node found at its offset or computed from the level below.
#[derive(Clone)]
struct Node {
    hash: Option<String>,
    duplicate: bool,
}

/// The walk from a level-0 leaf to the root, sharing every node it finds or
/// computes with the walks after it (the reference's `computeRootCached`,
/// `cachedFindLeaf` and `cachedMerkleRoot`). Each level is indexed by offset
/// once, each node is found or computed once (an error included: it depends
/// only on the node), and a walk that reaches a node an earlier walk passed
/// through stops there: the rest of its walk is the earlier one's.
pub(super) struct RootWalker<'a> {
    path: &'a [Vec<MerklePathLeaf>],
    /// Each level's offsets, to the first leaf at that offset; `None` for a
    /// level short enough to scan (a scan finds the same first leaf).
    index: Vec<Option<HashMap<u64, usize>>>,
    /// Every sibling found or computed, keyed by (height, offset).
    nodes: HashMap<(usize, u64), std::result::Result<Node, String>>,
    /// The working hash a finished walk carried through (height, offset).
    walked: HashMap<(usize, u64), String>,
    /// The root of the first finished walk.
    root: Option<String>,
    /// Whether walks meet: false for a single `compute_root`.
    shared: bool,
}

impl<'a> RootWalker<'a> {
    pub(super) fn new(path: &'a [Vec<MerklePathLeaf>]) -> Self {
        let index = path
            .iter()
            .map(|level| {
                if level.len() <= SCAN_MAX {
                    return None;
                }
                let mut at = HashMap::with_capacity(level.len());
                for (i, leaf) in level.iter().enumerate() {
                    at.entry(leaf.offset).or_insert(i);
                }
                Some(at)
            })
            .collect();
        Self {
            path,
            index,
            nodes: HashMap::new(),
            walked: HashMap::new(),
            root: None,
            shared: false,
        }
    }

    /// A walker whose walks stop where they meet an earlier one (the root
    /// check of every level-0 leaf).
    pub(super) fn shared(path: &'a [Vec<MerklePathLeaf>]) -> Self {
        Self {
            shared: true,
            ..Self::new(path)
        }
    }

    /// The root computed from `txid` at level-0 offset `index`. Every walk on
    /// one walker must finish with the same root: a walk that differs from an
    /// earlier one where they meet is refused as `Mismatched roots`.
    pub(super) fn root_from(&mut self, txid: &str, index: u64) -> Result<String> {
        let mut working_hash = txid.to_string();

        // A block with one transaction has its lone leaf at offset 0.
        // Match the BEEF reader; TS returns the txid at any offset
        // (ts-stack@edf6e03 MerklePath.ts:345,390-391).
        if self.path.len() == 1 && self.path[0].len() == 1 {
            if index != 0 {
                return Err(crate::Error::MerklePathError(format!(
                    "{:?}",
                    super::beef_stream::Reason::MissingSibling {
                        level: 0,
                        offset: index ^ 1,
                    }
                )));
            }
            return Ok(working_hash);
        }

        let mut passed = Vec::new();
        for height in 0..self.path.len() {
            let node = (height, offset_at_height(index, height));
            let seen = if self.shared {
                self.walked.get(&node)
            } else {
                None
            };
            if let (Some(seen), Some(root)) = (seen, self.root.as_ref()) {
                if *seen != working_hash {
                    return Err(crate::Error::MerklePathError(
                        "Mismatched roots".to_string(),
                    ));
                }
                let root = root.clone();
                self.walked.extend(passed);
                return Ok(root);
            }
            if self.shared {
                passed.push((node, working_hash.clone()));
            }

            let offset = node.1 ^ 1;
            let leaf = self
                .find_or_compute(height, offset)
                .map_err(crate::Error::MerklePathError)?;

            let paired = if leaf.duplicate {
                hash_pair(&working_hash, &working_hash)
            } else if offset % 2 != 0 {
                // Odd offset means sibling is on the RIGHT, working_hash is on the LEFT
                hash_pair(&working_hash, leaf.hash.as_deref().unwrap_or(""))
            } else {
                // Even offset means sibling is on the LEFT, working_hash is on the RIGHT
                hash_pair(leaf.hash.as_deref().unwrap_or(""), &working_hash)
            };
            working_hash = paired.map_err(crate::Error::MerklePathError)?;
        }

        // Only a finished walk that agrees with the first marks its nodes.
        match &self.root {
            None => self.root = Some(working_hash.clone()),
            Some(root) if *root != working_hash => return Ok(working_hash),
            Some(_) => {}
        }
        self.walked.extend(passed);
        Ok(working_hash)
    }

    /// Finds the node at `height` and `offset`, or computes it from the level
    /// below, once.
    fn find_or_compute(&mut self, height: usize, offset: u64) -> std::result::Result<Node, String> {
        // Try to find existing leaf
        let stored = match &self.index[height] {
            Some(at) => at.get(&offset).copied(),
            None => self.path[height].iter().position(|l| l.offset == offset),
        };
        if let Some(i) = stored {
            let leaf = &self.path[height][i];
            return Ok(Node {
                hash: leaf.hash.clone(),
                duplicate: leaf.duplicate,
            });
        }
        if let Some(found) = self.nodes.get(&(height, offset)) {
            return found.clone();
        }
        let found = self.find_or_compute_once(height, offset);
        self.nodes.insert((height, offset), found.clone());
        found
    }

    fn find_or_compute_once(
        &mut self,
        height: usize,
        offset: u64,
    ) -> std::result::Result<Node, String> {
        // Not stored (`find_or_compute` looked); can't compute at level 0
        if height == 0 {
            return Err(format!("Missing hash at height 0, offset {}", offset));
        }

        // Compute from level below
        let h = height - 1;
        let l = offset << 1;

        // A duplicate on the left (an even offset) has no hash to pair, as
        // the reference's walk gives up there (`ts-stack@edf6e03`
        // `MerklePath.ts:437`); through 0.8.3 an empty hash stood in (#167).
        let leaf0 = self.find_or_compute(h, l)?;
        if leaf0.hash.is_none() {
            return Err(format!("Missing hash at height {}, offset {}", h, l));
        }

        let leaf1 = self.find_or_compute(h, l + 1)?;

        let working_hash = if leaf1.duplicate {
            let h0 = leaf0.hash.as_deref().unwrap_or("");
            hash_pair(h0, h0)?
        } else {
            // h0 is at offset l (even, LEFT), h1 is at offset l+1 (odd, RIGHT)
            let h0 = leaf0.hash.as_deref().unwrap_or("");
            let h1 = leaf1.hash.as_deref().unwrap_or("");
            hash_pair(h0, h1)?
        };

        Ok(Node {
            hash: Some(working_hash),
            duplicate: false,
        })
    }
}

/// The reference's refusal of a hash text that is not hex, `assertValidHex`'s
/// words (`ts-stack@edf6e03` `primitives/hex.ts:6-17`, the pattern
/// `/^[0-9a-fA-F]*$/`, the empty text allowed), thrown by its `hashPair`
/// (`MerklePath.ts:30-32`) and by its writer (`:289`) (#817).
pub(super) const INVALID_HEX: &str = "Invalid hex string";

/// Whether `text` is hex as the reference's `assertValidHex` reads it: ASCII
/// hex digits of either case, any length, the empty text included (#817).
pub(super) fn is_reference_hex(text: &str) -> bool {
    text.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Computes the double SHA-256 of concatenated hashes (for merkle tree).
///
/// A text with a character that is not a hex digit is refused in the
/// reference's words, as its `hashPair` throws on the concatenation
/// (`MerklePath.ts:30-32`, `utils.ts:113-118`); through #817 it was dropped and
/// the rest hashed. Every other text is read as the reference's `hashPair`
/// reads it: `hashPair(right, left)` there (the callers pass the sides in the
/// other order), the two texts concatenated as text, one leading `0` when the
/// total length is odd (`utils.ts:125-128`), decoded once and reversed whole.
/// For two even-length texts that is each side's bytes reversed, `left` first;
/// until #817 each side was decoded alone and a side of odd length dropped.
pub(super) fn hash_pair(left: &str, right: &str) -> std::result::Result<String, String> {
    if !is_reference_hex(left) || !is_reference_hex(right) {
        return Err(INVALID_HEX.to_string());
    }
    let mut text = String::with_capacity(left.len() + right.len() + 1);
    if !(left.len() + right.len()).is_multiple_of(2) {
        text.push('0');
    }
    text.push_str(right);
    text.push_str(left);
    let mut data = from_hex(&text).map_err(|_| INVALID_HEX.to_string())?;
    data.reverse();

    // Two 32-byte hashes share the block primitive; bytes of any other
    // length are hashed whole, as the reference's `hash256` hashes them.
    let pair = data.split_at_checked(32).and_then(|(left, right)| {
        Some((
            <&[u8; 32]>::try_from(left).ok()?,
            <&[u8; 32]>::try_from(right).ok()?,
        ))
    });
    let hash = if let Some((left, right)) = pair {
        crate::block::merkle_parent(left, right)
    } else {
        sha256d(&data)
    };

    // Reverse back to display format
    let mut result = hash.to_vec();
    result.reverse();
    Ok(to_hex(&result))
}
