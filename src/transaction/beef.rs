//! BEEF format (BRC-62/95/96) for SPV transaction proofs.
//!
//! BEEF (Background Evaluation Extended Format) is the standard format for
//! exchanging SPV (Simplified Payment Verification) transaction proofs.
//!
//! # Supported Standards
//!
//! - **BRC-62**: BEEF V1 format
//! - **BRC-74**: BUMP (BSV Unified Merkle Path) format for merkle proofs
//! - **BRC-95**: Atomic BEEF for single-transaction proofs
//! - **BRC-96**: BEEF V2 with TXID-only extension
//!
//! # Example
//!
//! ```rust,ignore
//! use bsv_sdk::transaction::Beef;
//!
//! // Parse from hex
//! let beef = Beef::from_hex("...")?;
//!
//! // Validate structure
//! assert!(beef.is_valid(false));
//!
//! // Find a transaction
//! if let Some(tx) = beef.find_txid("abc123...") {
//!     println!("Found transaction");
//! }
//!
//! // Serialize back
//! let hex = beef.to_hex();
//! ```

use std::collections::HashMap;

use crate::primitives::{from_hex, to_hex, Reader, Writer};
use crate::Result;

use super::beef_tx::{BeefTx, ATOMIC_BEEF, BEEF_V1, BEEF_V2};
use super::merkle_path::MerklePath;
use super::transaction::Transaction;

/// Result of sorting transactions in a BEEF.
#[derive(Debug, Clone, Default)]
pub struct SortResult {
    /// TXIDs of inputs that are missing from the BEEF.
    pub missing_inputs: Vec<String>,
    /// TXIDs of transactions that are not valid (no proof and don't chain to proofs).
    pub not_valid: Vec<String>,
    /// TXIDs of valid transactions.
    pub valid: Vec<String>,
    /// TXIDs of transactions that have missing inputs.
    pub with_missing_inputs: Vec<String>,
    /// TXIDs of txid-only transactions.
    pub txid_only: Vec<String>,
}

/// Result of BEEF validation.
#[derive(Debug, Clone)]
pub struct BeefValidationResult {
    /// Whether the BEEF is structurally valid.
    pub valid: bool,
    /// Merkle roots keyed by block height (to be verified by chain tracker).
    pub roots: HashMap<u32, String>,
}

/// BEEF (Background Evaluation Extended Format) for SPV proofs.
///
/// A BEEF contains:
/// - A list of BUMPs (merkle paths) proving transactions are in blocks
/// - A list of transactions (full or txid-only)
///
/// Transactions must be sorted in dependency order (oldest first).
#[derive(Debug, Clone)]
pub struct Beef {
    /// Merkle paths (BUMPs) for proving transactions.
    pub bumps: Vec<MerklePath>,
    /// Transactions in the BEEF.
    pub txs: Vec<BeefTx>,
    /// BEEF format version (V1 or V2).
    pub version: u32,
    /// For Atomic BEEF, the target transaction ID.
    pub atomic_txid: Option<String>,
    /// Index of txids to BeefTx for fast lookup.
    txid_index: HashMap<String, usize>,
    /// Whether the transactions need sorting.
    needs_sort: bool,
}

impl Beef {
    /// Creates a new empty BEEF with V2 format.
    pub fn new() -> Self {
        Self::with_version(BEEF_V2)
    }

    /// Creates a new empty BEEF with the specified version.
    pub fn with_version(version: u32) -> Self {
        Self {
            bumps: Vec::new(),
            txs: Vec::new(),
            version,
            atomic_txid: None,
            txid_index: HashMap::new(),
            needs_sort: true,
        }
    }

    /// Marks the BEEF as needing re-sort.
    fn mark_mutated(&mut self) {
        self.needs_sort = true;
    }

    /// Rebuilds the txid index.
    fn rebuild_index(&mut self) {
        self.txid_index.clear();
        for (i, tx) in self.txs.iter().enumerate() {
            self.txid_index.insert(tx.txid(), i);
        }
    }

    /// Finds a BeefTx by txid.
    pub fn find_txid(&self, txid: &str) -> Option<&BeefTx> {
        self.txid_index.get(txid).map(|&i| &self.txs[i])
    }

    /// Finds a BeefTx by txid (mutable).
    pub fn find_txid_mut(&mut self, txid: &str) -> Option<&mut BeefTx> {
        self.txid_index.get(txid).map(|&i| &mut self.txs[i])
    }

    /// Finds a MerklePath that contains the given txid.
    pub fn find_bump(&self, txid: &str) -> Option<&MerklePath> {
        self.bumps.iter().find(|b| b.contains(txid))
    }

    /// Finds a transaction and populates its input source transactions from this BEEF.
    pub fn find_transaction_for_signing(&self, txid: &str) -> Option<Transaction> {
        let beef_tx = self.find_txid(txid)?;
        let tx = beef_tx.tx()?.clone();
        // Would need to populate source transactions - simplified for now
        Some(tx)
    }

    /// Builds the proof tree rooted at a specific transaction.
    pub fn find_atomic_transaction(&self, txid: &str) -> Option<Transaction> {
        let beef_tx = self.find_txid(txid)?;
        beef_tx.tx().cloned()
    }

    /// Merges a MerklePath into this BEEF.
    ///
    /// If a path with the same block height and root already exists, combines them.
    ///
    /// # Returns
    ///
    /// The index of the merged bump.
    pub fn merge_bump(&mut self, bump: MerklePath) -> usize {
        // Check for existing bump with same block height and root
        for (i, existing) in self.bumps.iter_mut().enumerate() {
            if existing.block_height == bump.block_height {
                if let (Ok(root1), Ok(root2)) =
                    (existing.compute_root(None), bump.compute_root(None))
                {
                    if root1 == root2 {
                        // Combine the bumps
                        let _ = existing.combine(&bump);
                        self.update_bump_indices(i);
                        return i;
                    }
                }
            }
        }

        // Add as new bump
        let index = self.bumps.len();
        self.bumps.push(bump);
        self.update_bump_indices(index);
        index
    }

    /// Updates bump indices for transactions proven by a bump.
    fn update_bump_indices(&mut self, bump_index: usize) {
        let bump = &self.bumps[bump_index];
        for tx in &mut self.txs {
            if tx.bump_index().is_none() {
                let txid = tx.txid();
                if bump.contains(&txid) {
                    tx.set_bump_index(Some(bump_index));
                }
            }
        }
    }

    /// Merges a transaction into this BEEF.
    ///
    /// If the transaction has a merkle path, it's also merged.
    /// Replaces any existing transaction with the same txid.
    pub fn merge_transaction(&mut self, tx: Transaction) -> &BeefTx {
        let txid = tx.id();
        self.remove_existing_txid(&txid);

        let bump_index = None; // Could be set if tx has merklePath

        let new_tx = BeefTx::from_tx(tx, bump_index);
        self.txs.push(new_tx);

        let idx = self.txs.len() - 1;
        self.txid_index.insert(txid.clone(), idx);
        self.try_to_validate_bump_index(idx);
        self.mark_mutated();

        &self.txs[idx]
    }

    /// Merges raw transaction bytes into this BEEF.
    pub fn merge_raw_tx(&mut self, raw_tx: Vec<u8>, bump_index: Option<usize>) -> &BeefTx {
        let new_tx = BeefTx::from_raw_tx(raw_tx, bump_index);
        let txid = new_tx.txid();
        self.remove_existing_txid(&txid);

        self.txs.push(new_tx);

        let idx = self.txs.len() - 1;
        self.txid_index.insert(txid, idx);
        self.try_to_validate_bump_index(idx);
        self.mark_mutated();

        &self.txs[idx]
    }

    /// Merges a txid-only entry into this BEEF.
    pub fn merge_txid_only(&mut self, txid: String) -> &BeefTx {
        if let Some(&idx) = self.txid_index.get(&txid) {
            return &self.txs[idx];
        }

        let new_tx = BeefTx::from_txid(txid.clone());
        self.txs.push(new_tx);

        let idx = self.txs.len() - 1;
        self.txid_index.insert(txid, idx);
        self.try_to_validate_bump_index(idx);
        self.mark_mutated();

        &self.txs[idx]
    }

    /// Converts an existing transaction to txid-only format.
    ///
    /// This is used to trim known transactions from BEEF before returning to caller,
    /// reducing the BEEF size when the recipient already has the full transaction.
    ///
    /// Returns the modified BeefTx if found, None if txid not in BEEF.
    pub fn make_txid_only(&mut self, txid: &str) -> Option<&BeefTx> {
        let idx = *self.txid_index.get(txid)?;

        // If already txid-only, just return it
        if self.txs[idx].is_txid_only() {
            return Some(&self.txs[idx]);
        }

        // Replace with txid-only version
        let new_tx = BeefTx::from_txid(txid.to_string());
        self.txs[idx] = new_tx;
        self.mark_mutated();

        Some(&self.txs[idx])
    }

    /// Removes an existing transaction by txid.
    fn remove_existing_txid(&mut self, txid: &str) {
        if let Some(&idx) = self.txid_index.get(txid) {
            self.txs.remove(idx);
            self.rebuild_index();
            self.mark_mutated();
        }
    }

    /// Tries to validate a bump index for a new transaction.
    fn try_to_validate_bump_index(&mut self, tx_idx: usize) {
        if self.txs[tx_idx].bump_index().is_some() {
            return;
        }

        let txid = self.txs[tx_idx].txid();
        for (i, bump) in self.bumps.iter().enumerate() {
            if bump.contains(&txid) {
                self.txs[tx_idx].set_bump_index(Some(i));
                return;
            }
        }
    }

    /// Merges another BEEF into this one.
    pub fn merge_beef(&mut self, other: &Beef) {
        for bump in &other.bumps {
            self.merge_bump(bump.clone());
        }

        for tx in &other.txs {
            if tx.is_txid_only() {
                self.merge_txid_only(tx.txid());
            } else if let Some(t) = tx.tx() {
                self.merge_transaction(t.clone());
            }
        }
    }

    /// Checks if this BEEF is structurally valid.
    ///
    /// Does NOT verify merkle roots against a chain tracker.
    ///
    /// # Arguments
    ///
    /// * `allow_txid_only` - If true, txid-only transactions are considered valid
    pub fn is_valid(&mut self, allow_txid_only: bool) -> bool {
        self.verify_valid(allow_txid_only).valid
    }

    /// Validates the BEEF structure and returns roots to verify.
    pub fn verify_valid(&mut self, allow_txid_only: bool) -> BeefValidationResult {
        let sr = self.sort_txs();

        if !sr.missing_inputs.is_empty()
            || !sr.not_valid.is_empty()
            || (!sr.txid_only.is_empty() && !allow_txid_only)
            || !sr.with_missing_inputs.is_empty()
        {
            return BeefValidationResult {
                valid: false,
                roots: HashMap::new(),
            };
        }

        let mut roots: HashMap<u32, String> = HashMap::new();
        let mut valid_txids: HashMap<String, bool> = HashMap::new();

        // Mark txid-only as valid if allowed
        for tx in &self.txs {
            if tx.is_txid_only() {
                if !allow_txid_only {
                    return BeefValidationResult {
                        valid: false,
                        roots: HashMap::new(),
                    };
                }
                valid_txids.insert(tx.txid(), true);
            }
        }

        // Validate bumps and collect roots
        for bump in &self.bumps {
            for leaf in &bump.path[0] {
                if leaf.txid {
                    if let Some(ref hash) = leaf.hash {
                        valid_txids.insert(hash.clone(), true);

                        // Compute and verify root
                        if let Ok(root) = bump.compute_root(Some(hash)) {
                            let height = bump.block_height;
                            if let Some(existing) = roots.get(&height) {
                                if existing != &root {
                                    return BeefValidationResult {
                                        valid: false,
                                        roots: HashMap::new(),
                                    };
                                }
                            } else {
                                roots.insert(height, root);
                            }
                        }
                    }
                }
            }
        }

        // Verify all txs with bump_index have matching leaf
        for tx in &self.txs {
            if let Some(bump_idx) = tx.bump_index() {
                if bump_idx >= self.bumps.len() {
                    return BeefValidationResult {
                        valid: false,
                        roots: HashMap::new(),
                    };
                }
                if !self.bumps[bump_idx].contains(&tx.txid()) {
                    return BeefValidationResult {
                        valid: false,
                        roots: HashMap::new(),
                    };
                }
            }
        }

        // Verify dependency order
        for tx in &self.txs {
            for input_txid in &tx.input_txids {
                if !valid_txids.contains_key(input_txid) {
                    return BeefValidationResult {
                        valid: false,
                        roots: HashMap::new(),
                    };
                }
            }
            valid_txids.insert(tx.txid(), true);
        }

        BeefValidationResult { valid: true, roots }
    }

    /// Sorts transactions by dependency order.
    pub fn sort_txs(&mut self) -> SortResult {
        let mut result = SortResult::default();
        let mut valid_txids: HashMap<String, bool> = HashMap::new();
        let mut txid_to_idx: HashMap<String, usize> = HashMap::new();

        for (i, tx) in self.txs.iter().enumerate() {
            txid_to_idx.insert(tx.txid(), i);
        }

        // Separate transactions by type
        let mut with_proof: Vec<usize> = Vec::new();
        let mut txid_only: Vec<usize> = Vec::new();
        let mut queue: Vec<usize> = Vec::new();

        for (i, tx) in self.txs.iter_mut().enumerate() {
            tx.is_valid = Some(tx.has_proof());
            if tx.has_proof() {
                valid_txids.insert(tx.txid(), true);
                with_proof.push(i);
            } else if tx.is_txid_only() && tx.input_txids.is_empty() {
                valid_txids.insert(tx.txid(), true);
                txid_only.push(i);
                result.txid_only.push(tx.txid());
            } else {
                queue.push(i);
            }
        }

        // Check for missing inputs
        let mut with_missing: Vec<usize> = Vec::new();
        let mut pending: Vec<usize> = Vec::new();

        for &i in &queue {
            let mut has_missing = false;
            for input_txid in &self.txs[i].input_txids {
                if !txid_to_idx.contains_key(input_txid) {
                    result.missing_inputs.push(input_txid.clone());
                    has_missing = true;
                }
            }
            if has_missing {
                with_missing.push(i);
                result.with_missing_inputs.push(self.txs[i].txid());
            } else {
                pending.push(i);
            }
        }

        // Process pending transactions
        let mut sorted_pending: Vec<usize> = Vec::new();
        while !pending.is_empty() {
            let old_len = pending.len();
            pending.retain(|&i| {
                let all_inputs_valid = self.txs[i]
                    .input_txids
                    .iter()
                    .all(|txid| valid_txids.contains_key(txid));
                if all_inputs_valid {
                    valid_txids.insert(self.txs[i].txid(), true);
                    sorted_pending.push(i);
                    false
                } else {
                    true
                }
            });
            if pending.len() == old_len {
                break;
            }
        }

        // Remaining are not valid
        for &i in &pending {
            result.not_valid.push(self.txs[i].txid());
        }

        // Collect valid txids
        result.valid = valid_txids.keys().cloned().collect();

        // Reorder transactions - build new order indices
        let mut new_order: Vec<usize> = Vec::new();
        new_order.extend(&with_missing);
        new_order.extend(&pending);
        new_order.extend(&txid_only);
        new_order.extend(&with_proof);
        new_order.extend(&sorted_pending);

        // Rebuild txs in new order
        let old_txs = std::mem::take(&mut self.txs);
        let old_len = old_txs.len();

        // Convert to a vector we can index into
        let old_vec: Vec<BeefTx> = old_txs;

        // Build new txs in order
        for &i in &new_order {
            if i < old_len {
                self.txs.push(old_vec[i].clone());
            }
        }

        // If we didn't add all txs (due to dedup in order), add remaining
        if self.txs.len() < old_len {
            for (i, tx) in old_vec.into_iter().enumerate() {
                if !new_order.contains(&i) {
                    self.txs.push(tx);
                }
            }
        }

        self.needs_sort = false;
        self.rebuild_index();

        result
    }

    /// Parses a BEEF from binary data.
    pub fn from_binary(bin: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bin);
        Self::from_reader(&mut reader)
    }

    /// Parses a BEEF from a hex string.
    pub fn from_hex(hex: &str) -> Result<Self> {
        let bin = from_hex(hex)?;
        Self::from_binary(&bin)
    }

    /// Parses a BEEF from a Reader.
    pub fn from_reader(reader: &mut Reader) -> Result<Self> {
        let mut version = reader.read_u32_le()?;
        let mut atomic_txid = None;

        // Check for Atomic BEEF prefix
        if version == ATOMIC_BEEF {
            let txid_slice = reader.read_bytes(32)?;
            let mut txid_bytes = txid_slice.to_vec();
            txid_bytes.reverse();
            atomic_txid = Some(to_hex(&txid_bytes));
            version = reader.read_u32_le()?;
        }

        if version != BEEF_V1 && version != BEEF_V2 {
            return Err(crate::Error::BeefError(format!(
                "Invalid BEEF version: 0x{:08X}",
                version
            )));
        }

        let mut beef = Self::with_version(version);
        beef.atomic_txid = atomic_txid;

        // Read bumps
        let bump_count = reader.read_var_int_num()?;
        for _ in 0..bump_count {
            let bump = MerklePath::from_reader(reader)?;
            beef.bumps.push(bump);
        }

        // Read transactions
        let tx_count = reader.read_var_int_num()?;
        for _ in 0..tx_count {
            let tx = BeefTx::from_reader(reader, version)?;
            let txid = tx.txid();
            beef.txs.push(tx);
            let idx = beef.txs.len() - 1;
            beef.txid_index.insert(txid, idx);
        }

        beef.needs_sort = true;
        Ok(beef)
    }

    /// Serializes this BEEF to binary.
    pub fn to_binary(&mut self) -> Vec<u8> {
        if self.needs_sort {
            self.sort_txs();
        }

        let mut writer = Writer::new();
        self.to_writer(&mut writer);
        writer.into_bytes()
    }

    /// Serializes this BEEF to a hex string.
    pub fn to_hex(&mut self) -> String {
        to_hex(&self.to_binary())
    }

    /// Writes this BEEF to a Writer.
    pub fn to_writer(&self, writer: &mut Writer) {
        writer.write_u32_le(self.version);

        writer.write_var_int(self.bumps.len() as u64);
        for bump in &self.bumps {
            bump.to_writer(writer);
        }

        writer.write_var_int(self.txs.len() as u64);
        for tx in &self.txs {
            tx.to_writer(writer, self.version);
        }
    }

    /// Serializes this BEEF as Atomic BEEF for a specific transaction.
    pub fn to_binary_atomic(&mut self, txid: &str) -> Result<Vec<u8>> {
        if self.needs_sort {
            self.sort_txs();
        }

        if self.find_txid(txid).is_none() {
            return Err(crate::Error::BeefError(format!(
                "{} does not exist in this Beef",
                txid
            )));
        }

        let mut writer = Writer::new();
        writer.write_u32_le(ATOMIC_BEEF);

        // Write txid (reversed)
        let txid_bytes = from_hex(txid)?;
        let mut reversed = txid_bytes;
        reversed.reverse();
        writer.write_bytes(&reversed);

        self.to_writer(&mut writer);
        Ok(writer.into_bytes())
    }

    /// Returns true if this is an Atomic BEEF.
    pub fn is_atomic(&self) -> bool {
        self.atomic_txid.is_some()
    }

    /// Returns a shallow clone of this BEEF.
    pub fn clone_shallow(&self) -> Self {
        Self {
            bumps: self.bumps.clone(),
            txs: self.txs.clone(),
            version: self.version,
            atomic_txid: self.atomic_txid.clone(),
            txid_index: self.txid_index.clone(),
            needs_sort: self.needs_sort,
        }
    }

    /// Returns a summary string of this BEEF.
    pub fn to_log_string(&mut self) -> String {
        let mut log = format!(
            "BEEF with {} BUMPs and {} Transactions, isValid {}\n",
            self.bumps.len(),
            self.txs.len(),
            self.is_valid(false)
        );

        for (i, bump) in self.bumps.iter().enumerate() {
            log.push_str(&format!("  BUMP {}\n", i));
            log.push_str(&format!("    block: {}\n", bump.block_height));
            let txids: Vec<String> = bump.txids();
            if !txids.is_empty() {
                log.push_str("    txids: [\n");
                for txid in txids {
                    log.push_str(&format!("      '{}'\n", txid));
                }
                log.push_str("    ]\n");
            }
        }

        for (i, tx) in self.txs.iter().enumerate() {
            log.push_str(&format!("  TX {}\n", i));
            log.push_str(&format!("    txid: {}\n", tx.txid()));
            if let Some(bump_idx) = tx.bump_index() {
                log.push_str(&format!("    bumpIndex: {}\n", bump_idx));
            }
            if tx.is_txid_only() {
                log.push_str("    txidOnly\n");
            } else {
                log.push_str(&format!(
                    "    rawTx length={}\n",
                    tx.raw_tx().map(|r| r.len()).unwrap_or(0)
                ));
            }
            if !tx.input_txids.is_empty() {
                log.push_str("    inputs: [\n");
                for input_txid in &tx.input_txids {
                    log.push_str(&format!("      '{}'\n", input_txid));
                }
                log.push_str("    ]\n");
            }
        }

        log
    }
}

impl Default for Beef {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_beef() {
        let beef = Beef::new();
        assert_eq!(beef.version, BEEF_V2);
        assert!(beef.bumps.is_empty());
        assert!(beef.txs.is_empty());
    }

    #[test]
    fn test_beef_v1_version() {
        let beef = Beef::with_version(BEEF_V1);
        assert_eq!(beef.version, BEEF_V1);
    }

    #[test]
    fn test_merge_txid_only() {
        let mut beef = Beef::new();
        let txid = "a".repeat(64);
        beef.merge_txid_only(txid.clone());
        assert_eq!(beef.txs.len(), 1);
        assert!(beef.txs[0].is_txid_only());
        assert!(beef.find_txid(&txid).is_some());
    }

    #[test]
    fn test_make_txid_only() {
        let mut beef = Beef::new();

        // Create a simple raw transaction (minimal valid tx)
        // Version (4) + input count (1) + input (41) + output count (1) + output (9) + locktime (4)
        let raw_tx = vec![
            0x01, 0x00, 0x00, 0x00, // version
            0x01, // input count
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // prev txid (32 bytes)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, // vout
            0x00, // script length
            0xff, 0xff, 0xff, 0xff, // sequence
            0x01, // output count
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // satoshis
            0x00, // script length
            0x00, 0x00, 0x00, 0x00, // locktime
        ];

        let beef_tx = beef.merge_raw_tx(raw_tx, None);
        let txid = beef_tx.txid();

        // Verify it's not txid-only
        assert!(!beef.txs[0].is_txid_only());

        // Convert to txid-only
        let result = beef.make_txid_only(&txid);
        assert!(result.is_some());
        assert!(beef.txs[0].is_txid_only());

        // Verify the txid is still findable
        assert!(beef.find_txid(&txid).is_some());

        // Converting again should succeed (already txid-only)
        let result2 = beef.make_txid_only(&txid);
        assert!(result2.is_some());

        // Non-existent txid should return None
        let fake_txid = "b".repeat(64);
        assert!(beef.make_txid_only(&fake_txid).is_none());
    }

    #[test]
    fn test_merge_bump() {
        let mut beef = Beef::new();
        let bump = MerklePath::from_coinbase_txid(&"a".repeat(64), 100);
        let idx = beef.merge_bump(bump);
        assert_eq!(idx, 0);
        assert_eq!(beef.bumps.len(), 1);
    }

    #[test]
    fn test_is_valid_empty() {
        let mut beef = Beef::new();
        // Empty BEEF should be valid
        assert!(beef.is_valid(false));
    }

    #[test]
    fn test_default() {
        let beef = Beef::default();
        assert_eq!(beef.version, BEEF_V2);
    }
}
