//! List roots: bitcoin-sv@6504a3af `src/consensus/merkle.cpp:247-282,312-319`,
//! through bsv-script-lean@50d437b `lean/BsvChain/Merkle.lean:19-52` (#63, #65).

use crate::primitives::{sha256d, Hash32};

/// A list root and the equal-sibling indication.
/// ```
/// let result = bsv_rs::block::merkle_root(&[]);
/// assert_eq!(result.root, [0; 32]);
/// assert!(!result.mutated);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MerkleRoot {
    /// Root digest in internal order.
    pub root: Hash32,
    /// True when actual siblings were equal at any level.
    pub mutated: bool,
}

/// Double SHA-256 of two internal-order hashes concatenated left to right.
/// ```
/// use bsv_rs::{block::merkle_parent, primitives::sha256d};
/// assert_eq!(merkle_parent(&[0; 32], &[0; 32]), sha256d(&[0; 64]));
/// ```
pub fn merkle_parent(left: &Hash32, right: &Hash32) -> Hash32 {
    let mut bytes = [0; 64];
    bytes[..32].copy_from_slice(left);
    bytes[32..].copy_from_slice(right);
    sha256d(&bytes)
}

/// Compute a block-order list root using one O(n) working buffer.
/// Empty gives zero; one leaf gives itself. Odd padding does not set `mutated`.
/// A caller accepting a transaction list must refuse a mutated result:
/// bitcoin-sv@6504a3af `src/consensus/merkle.cpp:18-50` (CVE-2012-2459).
/// ```
/// use bsv_rs::block::merkle_root;
/// assert_eq!(merkle_root(&[[1; 32]]).root, [1; 32]);
/// assert!(merkle_root(&[[1; 32], [1; 32]]).mutated);
/// ```
pub fn merkle_root(leaves: &[Hash32]) -> MerkleRoot {
    reduce(leaves.to_vec())
}

fn reduce(mut level: Vec<Hash32>) -> MerkleRoot {
    if level.is_empty() {
        return MerkleRoot {
            root: [0; 32],
            mutated: false,
        };
    }
    let mut mutated = false;
    while level.len() > 1 {
        let width = level.len();
        for i in 0..width.div_ceil(2) {
            let left = level[2 * i];
            let right = level.get(2 * i + 1).copied().unwrap_or(left);
            mutated |= 2 * i + 1 < width && left == right;
            level[i] = merkle_parent(&left, &right);
        }
        level.truncate(width.div_ceil(2));
    }
    MerkleRoot {
        root: level[0],
        mutated,
    }
}

/// Hash the transactions in block order, then compute their root and mutation flag.
/// ```
/// use bsv_rs::block::block_merkle_root;
/// assert_eq!(block_merkle_root(&[]).root, [0; 32]);
/// ```
#[cfg(feature = "transaction")]
pub fn block_merkle_root(txs: &[crate::transaction::Transaction]) -> MerkleRoot {
    reduce(txs.iter().map(|tx| tx.hash()).collect())
}
