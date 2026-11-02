//! The legal offsets of a path's levels above 0 (`ts-stack@edf6e03`
//! `MerklePath.ts:220-235`): each level-0 leaf that is no duplicate names, at
//! every level above it, the sibling of its ancestor. A leaf above level 0 at
//! another offset is refused in the reference's words, the legal offsets
//! listed in the order level 0's leaves first name them, as its `Set`
//! iterates (#631).

use std::collections::HashSet;

use super::merkle_path::offset_at_height;
use crate::Result;

/// Per level, the legal offsets as a set and in the order first named.
pub(super) struct LegalOffsets(Vec<(HashSet<u64>, Vec<u64>)>);

impl LegalOffsets {
    /// No legal offset yet, on each of `levels` levels.
    pub(super) fn new(levels: usize) -> Self {
        Self(vec![(HashSet::new(), Vec::new()); levels])
    }

    /// A level-0 leaf at `offset` names its ancestors' siblings legal.
    pub(super) fn name(&mut self, offset: u64) {
        for (h, (set, order)) in self.0.iter_mut().enumerate().skip(1) {
            let legal = offset_at_height(offset, h) ^ 1;
            if set.insert(legal) {
                order.push(legal);
            }
        }
    }

    /// A leaf at `offset` on level `height` above 0, refused unless legal.
    pub(super) fn check(&self, offset: u64, height: usize) -> Result<()> {
        let (set, order) = &self.0[height];
        if set.contains(&offset) {
            return Ok(());
        }
        let legal: Vec<String> = order.iter().map(u64::to_string).collect();
        Err(crate::Error::MerklePathError(format!(
            "Invalid offset: {}, at height: {}, with legal offsets: {}",
            offset,
            height,
            legal.join(", ")
        )))
    }
}

/// The root check's end (`ts-stack@edf6e03` `MerklePath.ts:241-263`): a
/// level 0 of duplicates alone has no hashed leaf to climb from, and the
/// reference's constructor throws where `computeRootCached` finds none
/// (`:342-343`), with `legalOffsetsOnly` or without, after the offset checks;
/// `new` and `new_unchecked` refuse it in its words (#641).
pub(super) fn rooted(root: Option<String>, path: super::MerklePath) -> Result<super::MerklePath> {
    match root {
        Some(_) => Ok(path),
        None => Err(crate::Error::MerklePathError(
            "Transaction ID is undefined".to_string(),
        )),
    }
}

/// The 0.3.34 offset refusal (`Invalid offset: N, at height: H`, kept verbatim
/// by the root check's equivalence tests) in #631's words, its list computed
/// from `path`'s level 0 apart from [`LegalOffsets`]; any other text as given.
#[cfg(test)]
pub(super) fn with_legal_offsets(path: &[Vec<super::MerklePathLeaf>], words: String) -> String {
    let Some(height) = words.strip_prefix("Invalid offset: ") else {
        return words;
    };
    let height: u32 = height.rsplit(' ').next().unwrap().parse().unwrap();
    let mut legal: Vec<String> = Vec::new();
    for leaf in path[0].iter().filter(|leaf| !leaf.duplicate) {
        let offset = ((leaf.offset >> height) ^ 1).to_string();
        if !legal.contains(&offset) {
            legal.push(offset);
        }
    }
    format!("{words}, with legal offsets: {}", legal.join(", "))
}

/// #641's ruling on an answer of the 0.3.34 forms: a level 0 with no hashed
/// leaf, which the 0.3.34 constructor accepted, refused in the reference's
/// words, as [`rooted`] refuses it.
#[cfg(test)]
pub(super) fn with_a_hashed_leaf<T>(path: &[Vec<super::MerklePathLeaf>], value: T) -> Result<T> {
    if path[0].iter().any(|leaf| leaf.hash.is_some()) {
        return Ok(value);
    }
    Err(crate::Error::MerklePathError(
        "Transaction ID is undefined".to_string(),
    ))
}

/// A path with no levels, refused by both constructors in the reference's
/// sentence (`ts-stack@edf6e03` `MerklePath.ts:198-200`) with this crate's
/// bound, BRC-74's 64 where the reference holds 54 (#603's stated
/// divergence) (#649).
pub(super) fn no_levels() -> crate::Error {
    crate::Error::MerklePathError(format!(
        "Merkle Path must contain between 1 and {} levels",
        super::merkle_path::MAX_TREE_HEIGHT
    ))
}

impl super::MerklePath {
    /// Level 0's leaves, none for a path with no levels: every walk reads
    /// level 0 through this, never `path[0]`, so a path held with no levels
    /// through the public fields panics nowhere (`compute_root` refusing it
    /// as the reference's `computeRoot` refuses a level 0 with no leaf,
    /// `MerklePath.ts:375-382`, where the reference's own walks throw the
    /// runtime's `TypeError`) (#649).
    pub(super) fn level0(&self) -> &[super::MerklePathLeaf] {
        self.path.first().map_or(&[], Vec::as_slice)
    }
}
