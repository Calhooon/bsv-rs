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
