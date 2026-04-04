//! MerklePath (BRC-74 BUMP format) for SPV proofs.
//!
//! The MerklePath represents a Merkle proof for one or more transactions in a block.
//! It is used for Simplified Payment Verification (SPV) to prove that a transaction
//! is included in a block without needing the full block data.
//!
//! # BRC-74 Binary Format
//!
//! ```text
//! [varint]  block height
//! [1]       tree height (number of levels)
//! For each level:
//!   [varint]  leaf count
//!   For each leaf:
//!     [varint]  offset
//!     [1]       flags (bit0=duplicate, bit1=txid)
//!     [32]      hash (if not duplicate, little-endian)
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use bsv_rs::transaction::MerklePath;
//!
//! // Parse from hex
//! let merkle_path = MerklePath::from_hex("...")?;
//!
//! // Compute the merkle root
//! let root = merkle_path.compute_root(Some("txid..."))?;
//!
//! // Verify against chain tracker
//! let is_valid = merkle_path.verify("txid...", &chain_tracker).await?;
//! ```

use std::collections::HashSet;

use crate::primitives::{from_hex, sha256d, to_hex, Reader, Writer};
use crate::Result;

/// A leaf node in the Merkle path tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerklePathLeaf {
    /// The offset position in this level of the tree.
    pub offset: u64,
    /// The hash at this position (None if duplicate).
    pub hash: Option<String>,
    /// True if this leaf represents a transaction ID in the path.
    pub txid: bool,
    /// True if this hash is a duplicate of its sibling.
    pub duplicate: bool,
}

impl MerklePathLeaf {
    /// Creates a new MerklePathLeaf with the given offset and hash.
    pub fn new(offset: u64, hash: String) -> Self {
        Self {
            offset,
            hash: Some(hash),
            txid: false,
            duplicate: false,
        }
    }

    /// Creates a new txid leaf.
    pub fn new_txid(offset: u64, hash: String) -> Self {
        Self {
            offset,
            hash: Some(hash),
            txid: true,
            duplicate: false,
        }
    }

    /// Creates a duplicate leaf.
    pub fn new_duplicate(offset: u64) -> Self {
        Self {
            offset,
            hash: None,
            txid: false,
            duplicate: true,
        }
    }
}

/// Represents a Merkle Path (BRC-74 BUMP format) for SPV verification.
///
/// A MerklePath provides a compact proof that a transaction is included in a block.
/// It contains the block height and a tree structure of hashes needed to compute
/// the merkle root from a transaction ID.
#[derive(Debug, Clone)]
pub struct MerklePath {
    /// The height of the block containing the transaction(s).
    pub block_height: u32,
    /// The merkle path tree structure. Each level contains leaves sorted by offset.
    pub path: Vec<Vec<MerklePathLeaf>>,
}

impl MerklePath {
    /// Creates a new MerklePath from block height and path data.
    ///
    /// Validates that:
    /// - Level 0 is not empty
    /// - No duplicate offsets at the same level
    /// - All non-level-0 offsets are legal (derivable from level 0 txids)
    /// - All txids compute to the same root
    ///
    /// # Arguments
    ///
    /// * `block_height` - The block height
    /// * `path` - The merkle path tree structure
    ///
    /// # Errors
    ///
    /// Returns an error if the path is invalid.
    pub fn new(block_height: u32, path: Vec<Vec<MerklePathLeaf>>) -> Result<Self> {
        Self::new_internal(block_height, path, true)
    }

    /// Creates a new MerklePath without strict offset validation.
    ///
    /// Used during parsing when the path may have been trimmed.
    pub fn new_unchecked(block_height: u32, path: Vec<Vec<MerklePathLeaf>>) -> Result<Self> {
        Self::new_internal(block_height, path, false)
    }

    fn new_internal(
        block_height: u32,
        path: Vec<Vec<MerklePathLeaf>>,
        legal_offsets_only: bool,
    ) -> Result<Self> {
        if path.is_empty() {
            return Err(crate::Error::MerklePathError(
                "Path cannot be empty".to_string(),
            ));
        }

        if path[0].is_empty() {
            return Err(crate::Error::MerklePathError(
                "Empty level at height: 0".to_string(),
            ));
        }

        // Compute legal offsets based on level 0 txid positions
        let mut legal_offsets: Vec<HashSet<u64>> = vec![HashSet::new(); path.len()];

        for (height, leaves) in path.iter().enumerate() {
            let mut offsets_at_height = HashSet::new();

            for leaf in leaves {
                // Check for duplicate offsets
                if offsets_at_height.contains(&leaf.offset) {
                    return Err(crate::Error::MerklePathError(format!(
                        "Duplicate offset: {}, at height: {}",
                        leaf.offset, height
                    )));
                }
                offsets_at_height.insert(leaf.offset);

                // For level 0 non-duplicate leaves, compute legal offsets for higher levels
                if height == 0 && !leaf.duplicate {
                    #[allow(clippy::needless_range_loop)]
                    for h in 1..path.len() {
                        legal_offsets[h].insert((leaf.offset >> h) ^ 1);
                    }
                } else if height > 0
                    && legal_offsets_only
                    && !legal_offsets[height].contains(&leaf.offset)
                {
                    return Err(crate::Error::MerklePathError(format!(
                        "Invalid offset: {}, at height: {}",
                        leaf.offset, height
                    )));
                }
            }
        }

        let merkle_path = Self { block_height, path };

        // Verify all txids compute to the same root
        let mut root: Option<String> = None;
        for leaf in &merkle_path.path[0] {
            if let Some(ref hash) = leaf.hash {
                let computed = merkle_path.compute_root(Some(hash))?;
                if let Some(ref expected) = root {
                    if &computed != expected {
                        return Err(crate::Error::MerklePathError(
                            "Mismatched roots".to_string(),
                        ));
                    }
                } else {
                    root = Some(computed);
                }
            }
        }

        Ok(merkle_path)
    }

    /// Creates a MerklePath from binary data.
    ///
    /// # Arguments
    ///
    /// * `bin` - The binary data in BRC-74 format
    ///
    /// # Returns
    ///
    /// The parsed MerklePath.
    pub fn from_binary(bin: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bin);
        Self::from_reader(&mut reader)
    }

    /// Creates a MerklePath from a hex string.
    ///
    /// # Arguments
    ///
    /// * `hex` - The hex-encoded BRC-74 data
    ///
    /// # Returns
    ///
    /// The parsed MerklePath.
    pub fn from_hex(hex: &str) -> Result<Self> {
        let bin = from_hex(hex)?;
        Self::from_binary(&bin)
    }

    /// Creates a MerklePath from a Reader.
    pub fn from_reader(reader: &mut Reader) -> Result<Self> {
        let block_height = reader.read_var_int_num()? as u32;
        let tree_height = reader.read_u8()? as usize;

        let mut path: Vec<Vec<MerklePathLeaf>> = vec![Vec::new(); tree_height];

        #[allow(clippy::needless_range_loop)]
        for level in 0..tree_height {
            let n_leaves = reader.read_var_int_num()?;

            for _ in 0..n_leaves {
                let offset = reader.read_var_int_num()? as u64;
                let flags = reader.read_u8()?;

                let leaf = if (flags & 1) != 0 {
                    // Duplicate flag set
                    MerklePathLeaf::new_duplicate(offset)
                } else {
                    // Read 32-byte hash in little-endian
                    let hash_slice = reader.read_bytes(32)?;
                    let mut hash_bytes = hash_slice.to_vec();
                    hash_bytes.reverse(); // Convert from LE to display format
                    let hash = to_hex(&hash_bytes);

                    let txid = (flags & 2) != 0;
                    MerklePathLeaf {
                        offset,
                        hash: Some(hash),
                        txid,
                        duplicate: false,
                    }
                };

                path[level].push(leaf);
            }

            // Sort leaves by offset
            path[level].sort_by_key(|l| l.offset);
        }

        Self::new_unchecked(block_height, path)
    }

    /// Creates a MerklePath for a coinbase transaction in a block with no other transactions.
    ///
    /// This is an edge case for blocks containing only the coinbase.
    ///
    /// # Arguments
    ///
    /// * `txid` - The coinbase transaction ID
    /// * `height` - The block height
    ///
    /// # Returns
    ///
    /// A MerklePath for the coinbase.
    pub fn from_coinbase_txid(txid: &str, height: u32) -> Self {
        Self {
            block_height: height,
            path: vec![vec![MerklePathLeaf::new_txid(0, txid.to_string())]],
        }
    }

    /// Serializes the MerklePath to binary format.
    pub fn to_binary(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        self.to_writer(&mut writer);
        writer.into_bytes()
    }

    /// Writes the MerklePath to a Writer.
    pub fn to_writer(&self, writer: &mut Writer) {
        writer.write_var_int(self.block_height as u64);
        writer.write_u8(self.path.len() as u8);

        for level in &self.path {
            writer.write_var_int(level.len() as u64);

            for leaf in level {
                writer.write_var_int(leaf.offset);

                let mut flags: u8 = 0;
                if leaf.duplicate {
                    flags |= 1;
                }
                if leaf.txid {
                    flags |= 2;
                }
                writer.write_u8(flags);

                if !leaf.duplicate {
                    if let Some(ref hash) = leaf.hash {
                        // Write hash in little-endian
                        let mut hash_bytes = from_hex(hash).unwrap_or_default();
                        hash_bytes.reverse();
                        writer.write_bytes(&hash_bytes);
                    }
                }
            }
        }
    }

    /// Serializes the MerklePath to a hex string.
    pub fn to_hex(&self) -> String {
        to_hex(&self.to_binary())
    }

    /// Returns the index (offset) of a transaction in the path.
    fn index_of(&self, txid: &str) -> Result<u64> {
        for leaf in &self.path[0] {
            if leaf.hash.as_deref() == Some(txid) {
                return Ok(leaf.offset);
            }
        }
        Err(crate::Error::MerklePathError(format!(
            "Transaction ID {} not found in the Merkle Path",
            txid
        )))
    }

    /// Computes the Merkle root from a transaction ID.
    ///
    /// # Arguments
    ///
    /// * `txid` - Optional transaction ID. If None, uses the first available hash.
    ///
    /// # Returns
    ///
    /// The computed Merkle root as a hex string.
    pub fn compute_root(&self, txid: Option<&str>) -> Result<String> {
        // Get the txid to work with
        let txid = match txid {
            Some(t) => t.to_string(),
            None => {
                // Find the first valid hash
                self.path[0]
                    .iter()
                    .find_map(|l| l.hash.clone())
                    .ok_or_else(|| {
                        crate::Error::MerklePathError(
                            "No valid leaf found in the Merkle Path".to_string(),
                        )
                    })?
            }
        };

        let index = self.index_of(&txid)?;
        let mut working_hash = txid;

        // Special case for blocks with only one transaction
        if self.path.len() == 1 && self.path[0].len() == 1 {
            return Ok(working_hash);
        }

        for height in 0..self.path.len() {
            let offset = (index >> height) ^ 1;
            let leaf = self.find_or_compute_leaf(height, offset)?;

            working_hash = if leaf.duplicate {
                hash_pair(&working_hash, &working_hash)
            } else if offset % 2 != 0 {
                // Odd offset means sibling is on the RIGHT, working_hash is on the LEFT
                hash_pair(&working_hash, leaf.hash.as_deref().unwrap_or(""))
            } else {
                // Even offset means sibling is on the LEFT, working_hash is on the RIGHT
                hash_pair(leaf.hash.as_deref().unwrap_or(""), &working_hash)
            };
        }

        Ok(working_hash)
    }

    /// Finds a leaf at the given height and offset, or computes it from lower levels.
    fn find_or_compute_leaf(&self, height: usize, offset: u64) -> Result<MerklePathLeaf> {
        // Try to find existing leaf
        if let Some(leaf) = self.path[height].iter().find(|l| l.offset == offset) {
            return Ok(leaf.clone());
        }

        // Can't compute at level 0
        if height == 0 {
            return Err(crate::Error::MerklePathError(format!(
                "Missing hash at height 0, offset {}",
                offset
            )));
        }

        // Compute from level below
        let h = height - 1;
        let l = offset << 1;

        let leaf0 = self.find_or_compute_leaf(h, l)?;
        if leaf0.hash.is_none() && !leaf0.duplicate {
            return Err(crate::Error::MerklePathError(format!(
                "Missing hash at height {}, offset {}",
                h, l
            )));
        }

        let leaf1 = self.find_or_compute_leaf(h, l + 1)?;

        let working_hash = if leaf1.duplicate {
            let h0 = leaf0.hash.as_deref().unwrap_or("");
            hash_pair(h0, h0)
        } else {
            // h0 is at offset l (even, LEFT), h1 is at offset l+1 (odd, RIGHT)
            let h0 = leaf0.hash.as_deref().unwrap_or("");
            let h1 = leaf1.hash.as_deref().unwrap_or("");
            hash_pair(h0, h1)
        };

        Ok(MerklePathLeaf::new(offset, working_hash))
    }

    /// Combines this MerklePath with another to create a compound proof.
    ///
    /// Both paths must have the same block height and compute to the same root.
    ///
    /// # Arguments
    ///
    /// * `other` - Another MerklePath to combine with this one
    ///
    /// # Errors
    ///
    /// Returns an error if the paths have different heights or roots.
    pub fn combine(&mut self, other: &MerklePath) -> Result<()> {
        if self.block_height != other.block_height {
            return Err(crate::Error::MerklePathError(
                "Cannot combine paths with different block heights".to_string(),
            ));
        }

        let root1 = self.compute_root(None)?;
        let root2 = other.compute_root(None)?;
        if root1 != root2 {
            return Err(crate::Error::MerklePathError(
                "Cannot combine paths with different roots".to_string(),
            ));
        }

        // Ensure path has enough levels
        while self.path.len() < other.path.len() {
            self.path.push(Vec::new());
        }

        // Merge leaves from other
        for (h, other_level) in other.path.iter().enumerate() {
            for other_leaf in other_level {
                let existing = self.path[h]
                    .iter_mut()
                    .find(|l| l.offset == other_leaf.offset);
                match existing {
                    Some(leaf) => {
                        // Preserve txid flag if set in either
                        if other_leaf.txid {
                            leaf.txid = true;
                        }
                    }
                    None => {
                        self.path[h].push(other_leaf.clone());
                    }
                }
            }
        }

        // Sort all levels
        for level in &mut self.path {
            level.sort_by_key(|l| l.offset);
        }

        // Trim unnecessary nodes
        self.trim();

        Ok(())
    }

    /// Removes all internal nodes that are not required by level zero txid nodes.
    ///
    /// After trimming, all levels are sorted by increasing offset.
    pub fn trim(&mut self) {
        // Sort all levels first
        for level in &mut self.path {
            level.sort_by_key(|l| l.offset);
        }

        // Compute which offsets at each level can be computed from level 0
        let mut computed_offsets: Vec<u64> = Vec::new();
        let mut drop_offsets: Vec<u64> = Vec::new();

        // Process level 0
        for leaf in &self.path[0] {
            if leaf.txid {
                // txid nodes enable computing their parent
                let parent_offset = leaf.offset >> 1;
                if computed_offsets.is_empty() || *computed_offsets.last().unwrap() != parent_offset
                {
                    computed_offsets.push(parent_offset);
                }
            } else {
                // Non-txid level 0 nodes without a txid peer can be dropped
                let is_odd = leaf.offset % 2 == 1;
                let peer_offset = if is_odd {
                    leaf.offset - 1
                } else {
                    leaf.offset + 1
                };
                let peer = self.path[0].iter().find(|l| l.offset == peer_offset);
                if let Some(p) = peer {
                    if !p.txid
                        && (drop_offsets.is_empty() || *drop_offsets.last().unwrap() != p.offset)
                    {
                        drop_offsets.push(p.offset);
                    }
                }
            }
        }

        // Remove non-txid pairs from level 0
        self.path[0].retain(|l| !drop_offsets.contains(&l.offset));

        // Process higher levels
        for h in 1..self.path.len() {
            drop_offsets = computed_offsets.clone();
            computed_offsets = drop_offsets.iter().map(|o| o >> 1).collect();
            computed_offsets.dedup();

            self.path[h].retain(|l| !drop_offsets.contains(&l.offset));
        }
    }

    /// Returns true if this path contains the given txid in its leaf level.
    pub fn contains(&self, txid: &str) -> bool {
        self.path[0]
            .iter()
            .any(|l| l.hash.as_deref() == Some(txid))
    }

    /// Returns true if this path contains the given txid, and marks the
    /// matching leaf as `txid = true`. This is used during BEEF merging
    /// to both check containment and ensure the leaf is properly flagged
    /// for subsequent validation. Matches the TS SDK's pattern where
    /// `tryToValidateBumpIndex` sets `node.txid = true` after finding a match.
    pub fn contains_and_mark(&mut self, txid: &str) -> bool {
        for leaf in &mut self.path[0] {
            if leaf.hash.as_deref() == Some(txid) {
                leaf.txid = true;
                return true;
            }
        }
        false
    }

    /// Returns all txids in this path.
    pub fn txids(&self) -> Vec<String> {
        self.path[0]
            .iter()
            .filter(|l| l.txid)
            .filter_map(|l| l.hash.clone())
            .collect()
    }
}

/// Computes the double SHA-256 of concatenated hashes (for merkle tree).
fn hash_pair(left: &str, right: &str) -> String {
    let mut data = Vec::with_capacity(64);

    // Parse hashes from hex and reverse to internal byte order
    if let Ok(mut left_bytes) = from_hex(left) {
        left_bytes.reverse();
        data.extend_from_slice(&left_bytes);
    }
    if let Ok(mut right_bytes) = from_hex(right) {
        right_bytes.reverse();
        data.extend_from_slice(&right_bytes);
    }

    // Double SHA-256
    let hash = sha256d(&data);

    // Reverse back to display format
    let mut result = hash.to_vec();
    result.reverse();
    to_hex(&result)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vector from ts-sdk
    const BUMP_HEX_1: &str = "fed79f0c000c02fd3803029b490d9c8358ff11afaf45628417c9eb52c1a1fd404078a101b4f71dbba06aa9fd390300fe82f2768edc3d0cfe4d06b7f390dcb0b7e61cca7f70117d83be0f023204d8ef01fd9d010060893ac65c8a8e6b9ef7ed5e05dc3bd25aa904812c09853c5dbf423b58a75d0e01cf0012c3c76d9c332e4701b27bfe7013e7963b92d1851d59c56955b35aecabbc8bae0166000894384f86a5c4d0d294f9b9441c3ee3d13afa094cca4515d32813b3fa4fdf3601320002aac507f74c9ff2676705eee1e70897a8baeecaf30c5f49bb22a0c5ce5fda9a01180021f7e27a08d61245be893a238853d72340881cbd47e0a390895231fa1cc44db9010d004d7a12738a1654777867182ee6f6efc4d692209badfa5ba9bb126d08da18ed880107004f8e96b4ee6154bd44b7709f3fb4041bf4426d5f5a594408345605e254af7cdd010200ec7d8b185bc7c096b9b88de6f63ab22baf738d5fc4cbc328f2e00644749acf520100007fd48b1d2b678907ba045b07132003db8116468cd6a3d4764e0df4a644ea0a220101009bb8ffc1a6ed2ba80ea1b09ff797387115a7129d19e93c003a74e3a20ed6ce590101001106e6ece3f70a16de42d0f87b459c71a2440201728bd8541334933726807921";

    const BUMP_HEX_2: &str = "feb39d0c000c02fd340700ed4cb1fdd81916dabb69b63bcd378559cf40916205cd004e7f5381cc2b1ea6acfd350702957998e38434782b1c40c63a4aca0ffaf4d5d9bc3385f0e9e396f4dd3238f0df01fd9b030012f77e65627c341a3aaea3a0ed645c0082ef53995f446ab9901a27e4622fd1cc01fdcc010074026299a4ba40fbcf33cc0c64b384f0bb2fb17c61125609a666b546539c221c01e700730f99f8cf10fccd30730474449172c5f97cde6a6cf65163359e778463e9f2b9017200a202c78dee487cf96e1a6a04d51faec4debfad09eea28cc624483f2d6fa53d54013800b51ecabaa590b6bd1805baf4f19fc0eae0dedb533302603579d124059b374b1e011d00a0f36640f32a43d790bb4c3e7877011aa8ae25e433b2b83c952a16f8452b6b79010f005d68efab62c6c457ce0bb526194cc16b27f93f8a4899f6d59ffffdddc06e345c01060099f66a0ef693d151bbe9aeb10392ac5a7712243406f9e821219fd13d1865f569010200201fa17c98478675a96703ded42629a3c7bf32b45d0bff25f8be6849d02889ae010000367765c2d68e0c926d81ecdf9e3c86991ccf5a52e97c49ad5cf584c8ab030427010100237b58d3217709b6ebc3bdc093413ba788739f052a0b5b3a413e65444b146bc1";

    #[test]
    fn test_parse_bump_hex() {
        let path = MerklePath::from_hex(BUMP_HEX_1).unwrap();
        // Just verify it parses and has expected structure
        assert!(path.block_height > 0);
        assert_eq!(path.path.len(), 12);
    }

    #[test]
    fn test_roundtrip() {
        let path = MerklePath::from_hex(BUMP_HEX_1).unwrap();
        let hex = path.to_hex();
        let path2 = MerklePath::from_hex(&hex).unwrap();
        assert_eq!(path.block_height, path2.block_height);
        assert_eq!(path.path.len(), path2.path.len());
    }

    #[test]
    fn test_parse_bump_hex_2() {
        let path = MerklePath::from_hex(BUMP_HEX_2).unwrap();
        // Just verify it parses and has expected structure
        assert!(path.block_height > 0);
        assert_eq!(path.path.len(), 12);
    }

    #[test]
    fn test_compute_root() {
        let path = MerklePath::from_hex(BUMP_HEX_1).unwrap();
        let root = path.compute_root(None).unwrap();
        assert_eq!(root.len(), 64); // 32 bytes = 64 hex chars
    }

    #[test]
    fn test_coinbase_path() {
        let txid = "0000000000000000000000000000000000000000000000000000000000000000";
        let path = MerklePath::from_coinbase_txid(txid, 100);
        assert_eq!(path.block_height, 100);
        assert_eq!(path.path.len(), 1);
        assert_eq!(path.path[0].len(), 1);
        assert!(path.path[0][0].txid);
    }

    #[test]
    fn test_to_binary_from_binary() {
        let path = MerklePath::from_hex(BUMP_HEX_1).unwrap();
        let binary = path.to_binary();
        let path2 = MerklePath::from_binary(&binary).unwrap();
        assert_eq!(path.block_height, path2.block_height);
    }

    #[test]
    fn test_contains_matches_txid_leaf() {
        let path = MerklePath::from_hex(BUMP_HEX_1).unwrap();
        // Find the first leaf that IS a txid
        let txid_leaf = path.path[0].iter().find(|l| l.txid).unwrap();
        let txid = txid_leaf.hash.as_ref().unwrap();
        assert!(path.contains(txid));
        assert!(!path.contains("nonexistent"));
    }

    #[test]
    fn test_contains_matches_any_hash() {
        // contains() matches any hash in path[0] (backward compatible)
        let txid_hash = "a".repeat(64);
        let sibling_hash = "b".repeat(64);

        let path = MerklePath {
            block_height: 100,
            path: vec![vec![
                MerklePathLeaf {
                    offset: 0,
                    hash: Some(txid_hash.clone()),
                    txid: true,
                    duplicate: false,
                },
                MerklePathLeaf {
                    offset: 1,
                    hash: Some(sibling_hash.clone()),
                    txid: false,
                    duplicate: false,
                },
            ]],
        };

        assert!(path.contains(&txid_hash));
        assert!(path.contains(&sibling_hash)); // contains matches ALL hashes
        // txids() only returns flagged txids
        assert_eq!(path.txids(), vec![txid_hash]);
    }

    #[test]
    fn test_contains_and_mark_sets_txid_flag() {
        let txid_hash = "a".repeat(64);
        let sibling_hash = "b".repeat(64);

        let mut path = MerklePath {
            block_height: 100,
            path: vec![vec![
                MerklePathLeaf {
                    offset: 0,
                    hash: Some(txid_hash.clone()),
                    txid: false, // Not yet marked
                    duplicate: false,
                },
                MerklePathLeaf {
                    offset: 1,
                    hash: Some(sibling_hash.clone()),
                    txid: false,
                    duplicate: false,
                },
            ]],
        };

        // Before marking: txids() is empty
        assert!(path.txids().is_empty());

        // contains_and_mark sets the flag
        assert!(path.contains_and_mark(&txid_hash));
        assert_eq!(path.txids(), vec![txid_hash.clone()]);

        // Sibling can also be marked if needed
        assert!(path.contains_and_mark(&sibling_hash));
        assert_eq!(path.txids().len(), 2);

        // Non-existent hash returns false
        assert!(!path.contains_and_mark(&"c".repeat(64)));
    }

    #[test]
    fn test_combine_same_path() {
        let mut path1 = MerklePath::from_hex(BUMP_HEX_1).unwrap();
        let path2 = MerklePath::from_hex(BUMP_HEX_1).unwrap();
        assert!(path1.combine(&path2).is_ok());
    }
}
