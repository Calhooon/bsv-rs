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
//! use bsv_rs::transaction::Beef;
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
    /// Only assigns the bump if the txid appears as a flagged leaf (txid=true).
    /// This prevents a tx from being claimed by a bump where it appears only
    /// as a sibling hash. Matches TS SDK behavior where the txid flag is
    /// checked/set during bump index assignment.
    fn update_bump_indices(&mut self, bump_index: usize) {
        let bump = &self.bumps[bump_index];
        for tx in &mut self.txs {
            if tx.bump_index().is_none() {
                let txid = tx.txid();
                // Only assign if the leaf has txid=true (a proper proven tx,
                // not just a sibling hash used for proof computation)
                let is_txid_leaf = bump.path[0]
                    .iter()
                    .any(|l| l.txid && l.hash.as_deref() == Some(&txid));
                if is_txid_leaf {
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
    ///
    /// STRICT MATCHING ONLY: assigns `bump_index` if-and-only-if some bump's
    /// level-0 leaf has `txid=true` AND `hash == tx.txid()`. If no such leaf
    /// exists, `bump_index` remains `None`.
    ///
    /// A previous iteration of this function included a permissive second
    /// pass that matched ANY leaf hash at level 0 (including sibling hashes
    /// used only for merkle computation) and mutated the leaf's `txid` flag
    /// to `true`. That was incorrect: a tx's txid can legitimately appear as
    /// a sibling hash in an unrelated bump, and marking it as a txid-leaf
    /// there would claim a proof that does not belong to it.
    ///
    /// The Go SDK (`go-sdk/transaction/beef.go:tryToValidateBumpIndex`) only
    /// validates/discards already-assigned paths and does not auto-discover
    /// from siblings. This matches that strict semantics. The TS SDK still
    /// has the permissive variant; fixing it there is a separate effort.
    fn try_to_validate_bump_index(&mut self, tx_idx: usize) {
        if self.txs[tx_idx].bump_index().is_some() {
            return;
        }

        let txid = self.txs[tx_idx].txid();

        // Strict match: leaf has txid=true AND hash == tx.txid().
        for (i, bump) in self.bumps.iter().enumerate() {
            let is_txid_leaf = bump
                .path
                .first()
                .map(|level0| {
                    level0
                        .iter()
                        .any(|l| l.txid && l.hash.as_deref() == Some(&txid))
                })
                .unwrap_or(false);
            if is_txid_leaf {
                self.txs[tx_idx].set_bump_index(Some(i));
                return;
            }
        }
    }

    /// Merges another BEEF into this one.
    ///
    /// Bumps are merged first and may receive new indices in self. Transactions
    /// are then merged WITHOUT passing bump indices from the source — instead,
    /// `try_to_validate_bump_index` discovers the correct index by scanning
    /// self.bumps. This matches the TypeScript SDK's `mergeBeefTx` behavior.
    pub fn merge_beef(&mut self, other: &Beef) {
        for bump in &other.bumps {
            self.merge_bump(bump.clone());
        }

        for tx in &other.txs {
            if tx.is_txid_only() {
                self.merge_txid_only(tx.txid());
            } else if let Some(raw) = tx.raw_tx() {
                // Do NOT pass tx.bump_index() — it's the old index from
                // `other` which is invalid after bumps were re-indexed.
                // merge_raw_tx calls try_to_validate_bump_index to discover
                // the correct index by scanning self.bumps.
                self.merge_raw_tx(raw.to_vec(), None);
            } else if let Some(t) = tx.tx() {
                self.merge_transaction(t.clone());
            }
        }
    }

    /// Trims ancestor transactions that are no longer needed because their
    /// dependents now have merkle proofs (BUMPs).
    ///
    /// In BEEF, a transaction with a BUMP is self-proving via its merkle path
    /// and does not require its ancestor transactions to also be present.
    /// This method walks the dependency graph from tip transactions (those not
    /// spent by any other tx in the BEEF) and removes any transaction that is
    /// only reachable through proven (bumped) transactions.
    ///
    /// This is useful after upgrading previously-unproven transactions with
    /// newly-available merkle proofs, allowing their deep ancestor chains to
    /// be removed.
    pub fn trim_known_proven(&mut self) {
        use std::collections::{HashSet, VecDeque};

        let all_txids: HashSet<String> = self.txs.iter().map(|tx| tx.txid()).collect();

        // Find which txids are referenced as inputs by other txs in the BEEF.
        // Note: proven txs have empty input_txids (cleared by set_bump_index),
        // so we also parse their raw tx bytes to recover the full reference graph.
        let mut referenced_as_input: HashSet<String> = HashSet::new();
        for tx in &mut self.txs {
            let input_refs: Vec<String> = if !tx.input_txids.is_empty() {
                tx.input_txids.clone()
            } else if let Some(parsed) = tx.tx_mut() {
                parsed
                    .inputs
                    .iter()
                    .filter_map(|inp| inp.get_source_txid().ok())
                    .collect::<Vec<String>>()
            } else {
                Vec::new()
            };
            for input_txid in &input_refs {
                if all_txids.contains(input_txid) {
                    referenced_as_input.insert(input_txid.clone());
                }
            }
        }

        // Tip transactions: not referenced as an input by any other tx in the BEEF
        let tips: Vec<String> = all_txids
            .iter()
            .filter(|txid| !referenced_as_input.contains(*txid))
            .cloned()
            .collect();

        // BFS from tips: mark needed txids, stop at proven txs
        let mut needed: HashSet<String> = HashSet::new();
        let mut queue: VecDeque<String> = VecDeque::from(tips);

        while let Some(txid) = queue.pop_front() {
            if needed.contains(&txid) {
                continue;
            }
            needed.insert(txid.clone());

            if let Some(tx) = self.find_txid(&txid) {
                // Proven tx is self-sufficient — don't need its ancestors
                if tx.bump_index().is_some() {
                    continue;
                }
                // Unproven — need its input txids too
                for input_txid in tx.input_txids.clone() {
                    if all_txids.contains(&input_txid) && !needed.contains(&input_txid) {
                        queue.push_back(input_txid);
                    }
                }
            }
        }

        // Nothing to trim
        if needed.len() == self.txs.len() {
            return;
        }

        // Remove unneeded transactions
        self.txs.retain(|tx| needed.contains(&tx.txid()));
        self.rebuild_index();

        // Clean up unused BUMPs and remap indices
        let used_bump_indices: HashSet<usize> =
            self.txs.iter().filter_map(|tx| tx.bump_index()).collect();

        if used_bump_indices.len() < self.bumps.len() {
            let mut new_bumps = Vec::new();
            let mut index_map: HashMap<usize, usize> = HashMap::new();

            for (old_idx, bump) in self.bumps.iter().enumerate() {
                if used_bump_indices.contains(&old_idx) {
                    let new_idx = new_bumps.len();
                    index_map.insert(old_idx, new_idx);
                    new_bumps.push(bump.clone());
                }
            }

            self.bumps = new_bumps;

            for tx in &mut self.txs {
                if let Some(old_idx) = tx.bump_index() {
                    if let Some(&new_idx) = index_map.get(&old_idx) {
                        tx.set_bump_index(Some(new_idx));
                    }
                }
            }
        }

        self.mark_mutated();
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
    use crate::transaction::MerklePathLeaf;

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
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, // vout
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

    #[test]
    fn test_trim_known_proven_removes_deep_ancestors() {
        // Build a BEEF with chain: TX_A (proven) <- TX_B (unproven) <- TX_C (unproven, tip)
        // Then prove TX_B. After trim, TX_A should be removed since TX_B is now self-sufficient.
        let mut beef = Beef::new();

        // TX_A: a "coinbase-like" tx (no real inputs for our purposes)
        let tx_a_raw = vec![
            0x01, 0x00, 0x00, 0x00, // version
            0x01, // input count
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, // prev txid (all zeros = coinbase)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
            0x00, // script length
            0xff, 0xff, 0xff, 0xff, // sequence
            0x01, // output count
            0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 1000 satoshis
            0x00, // script length
            0x00, 0x00, 0x00, 0x00, // locktime
        ];
        let tx_a_id = {
            let btx = beef.merge_raw_tx(tx_a_raw.clone(), None);
            btx.txid()
        };

        // Give TX_A a proof (BUMP)
        let bump_a = MerklePath::from_coinbase_txid(&tx_a_id, 100);
        let bump_idx_a = beef.merge_bump(bump_a);
        beef.find_txid_mut(&tx_a_id)
            .unwrap()
            .set_bump_index(Some(bump_idx_a));

        // TX_B: spends TX_A (input references tx_a_id)
        let tx_a_id_bytes = from_hex(&tx_a_id).unwrap();
        let mut tx_b_raw = vec![0x01, 0x00, 0x00, 0x00, 0x01]; // version + 1 input
                                                               // prev txid (reversed tx_a_id)
        let mut prev_txid = tx_a_id_bytes.clone();
        prev_txid.reverse();
        tx_b_raw.extend_from_slice(&prev_txid);
        tx_b_raw.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // vout
        tx_b_raw.push(0x00); // script length
        tx_b_raw.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]); // sequence
        tx_b_raw.push(0x01); // output count
        tx_b_raw.extend_from_slice(&[0xd0, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // 2000 sats
        tx_b_raw.push(0x00); // script length
        tx_b_raw.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // locktime
        let tx_b_id = {
            let btx = beef.merge_raw_tx(tx_b_raw, None);
            btx.txid()
        };

        // TX_C: spends TX_B (tip, unproven)
        let tx_b_id_bytes = from_hex(&tx_b_id).unwrap();
        let mut tx_c_raw = vec![0x01, 0x00, 0x00, 0x00, 0x01];
        let mut prev_txid_b = tx_b_id_bytes.clone();
        prev_txid_b.reverse();
        tx_c_raw.extend_from_slice(&prev_txid_b);
        tx_c_raw.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        tx_c_raw.push(0x00);
        tx_c_raw.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]);
        tx_c_raw.push(0x01);
        tx_c_raw.extend_from_slice(&[0xb8, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        tx_c_raw.push(0x00);
        tx_c_raw.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        let _tx_c_id = {
            let btx = beef.merge_raw_tx(tx_c_raw, None);
            btx.txid()
        };

        // Before trim: 3 txs (A proven, B unproven, C unproven)
        assert_eq!(beef.txs.len(), 3);

        // Now "prove" TX_B
        let bump_b = MerklePath::from_coinbase_txid(&tx_b_id, 101);
        let bump_idx_b = beef.merge_bump(bump_b);
        beef.find_txid_mut(&tx_b_id)
            .unwrap()
            .set_bump_index(Some(bump_idx_b));

        // Trim: TX_A should be removed (only ancestor of now-proven TX_B)
        beef.trim_known_proven();

        assert_eq!(beef.txs.len(), 2); // TX_B and TX_C remain
        assert!(beef.find_txid(&tx_b_id).is_some()); // TX_B kept (proven, needed by TX_C)
        assert!(beef.find_txid(&_tx_c_id).is_some()); // TX_C kept (tip)
        assert!(beef.find_txid(&tx_a_id).is_none()); // TX_A removed (unnecessary)

        // BUMP for TX_A's block should be removed, BUMP for TX_B's block kept
        assert_eq!(beef.bumps.len(), 1);
        assert_eq!(beef.bumps[0].block_height, 101);
    }

    #[test]
    fn test_beef_v1_binary_roundtrip_preserves_bytes() {
        // Simple P2PKH transaction
        let tx_hex = "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000";
        let tx = Transaction::from_hex(tx_hex).unwrap();
        let tx_bytes = tx.to_binary();

        // Build BEEF V1 manually
        let mut writer = Writer::new();
        writer.write_u32_le(BEEF_V1);
        writer.write_var_int(0); // 0 bumps
        writer.write_var_int(1); // 1 tx
        writer.write_bytes(&tx_bytes); // raw tx
        writer.write_u8(0); // no bump
        let original = writer.into_bytes();

        // Round-trip
        let mut beef = Beef::from_binary(&original).unwrap();
        let reserialized = beef.to_binary();

        assert_eq!(
            original, reserialized,
            "BEEF V1 round-trip must preserve exact bytes"
        );
    }

    #[test]
    fn test_beef_v2_binary_roundtrip_preserves_bytes() {
        // Simple P2PKH transaction
        let tx_hex = "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000";
        let tx = Transaction::from_hex(tx_hex).unwrap();
        let tx_bytes = tx.to_binary();

        // Build BEEF V2 manually
        let mut writer = Writer::new();
        writer.write_u32_le(BEEF_V2);
        writer.write_var_int(0); // 0 bumps
        writer.write_var_int(1); // 1 tx
        writer.write_u8(0); // RawTx format
        writer.write_bytes(&tx_bytes);
        let original = writer.into_bytes();

        let mut beef = Beef::from_binary(&original).unwrap();
        let reserialized = beef.to_binary();

        assert_eq!(
            original, reserialized,
            "BEEF V2 round-trip must preserve exact bytes"
        );
    }

    /// Helper: builds a raw transaction that spends a given previous txid at vout 0.
    /// If `prev_txid` is None, creates a coinbase-like tx (all-zero prev hash).
    /// `satoshis` controls the output value.
    /// `extra_script_bytes` can be provided to inflate the locking script.
    fn make_raw_tx(
        prev_txid: Option<&str>,
        satoshis: u64,
        extra_script_bytes: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut raw = vec![0x01, 0x00, 0x00, 0x00]; // version
        raw.push(0x01); // 1 input

        // prev txid (reversed for wire format) or all zeros
        match prev_txid {
            Some(txid_hex) => {
                let mut txid_bytes = from_hex(txid_hex).unwrap();
                txid_bytes.reverse();
                raw.extend_from_slice(&txid_bytes);
            }
            None => {
                raw.extend_from_slice(&[0u8; 32]);
            }
        }
        raw.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // vout=0
        raw.push(0x00); // empty unlocking script
        raw.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]); // sequence

        raw.push(0x01); // 1 output
        raw.extend_from_slice(&satoshis.to_le_bytes()); // satoshis

        // locking script
        match extra_script_bytes {
            Some(script) => {
                // write script length as varint
                let len = script.len() as u64;
                if len < 0xFD {
                    raw.push(len as u8);
                } else if len <= 0xFFFF {
                    raw.push(0xFD);
                    raw.extend_from_slice(&(len as u16).to_le_bytes());
                } else {
                    raw.push(0xFE);
                    raw.extend_from_slice(&(len as u32).to_le_bytes());
                }
                raw.extend_from_slice(script);
            }
            None => {
                raw.push(0x00); // empty script
            }
        }
        raw.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // locktime
        raw
    }

    /// Helper: adds a raw tx to a beef and returns its txid.
    fn add_raw_tx(beef: &mut Beef, raw: Vec<u8>, bump_index: Option<usize>) -> String {
        beef.merge_raw_tx(raw, bump_index).txid()
    }

    /// Helper: adds a raw tx to a beef, creates a coinbase-style BUMP for it, and
    /// sets the bump index. Returns the txid.
    fn add_proven_tx(beef: &mut Beef, raw: Vec<u8>, block_height: u32) -> String {
        let txid = add_raw_tx(beef, raw, None);
        let bump = MerklePath::from_coinbase_txid(&txid, block_height);
        let bi = beef.merge_bump(bump);
        beef.find_txid_mut(&txid).unwrap().set_bump_index(Some(bi));
        txid
    }

    // ── Test 1: merge_beef preserves raw tx bytes ────────────────────────

    #[test]
    fn test_merge_beef_preserves_raw_tx_bytes() {
        // Create BEEF A with a large-script tx (simulating PushDrop-style data).
        let mut beef_a = Beef::new();
        let big_script: Vec<u8> = (0..512).map(|i| (i % 256) as u8).collect();
        let raw_a = make_raw_tx(None, 5000, Some(&big_script));
        let txid_a = add_proven_tx(&mut beef_a, raw_a.clone(), 100);

        // Create BEEF B with a different tx.
        let mut beef_b = Beef::new();
        let raw_b = make_raw_tx(None, 3000, None);
        let txid_b = add_proven_tx(&mut beef_b, raw_b.clone(), 101);

        // Merge B into A.
        beef_a.merge_beef(&beef_b);

        // Serialize, parse back.
        let bin = beef_a.to_binary();
        let parsed = Beef::from_binary(&bin).unwrap();

        // Verify raw bytes of both txs survived the round-trip.
        let found_a = parsed.find_txid(&txid_a).unwrap();
        assert_eq!(
            found_a.raw_tx().unwrap(),
            &raw_a,
            "TX A raw bytes differ after merge round-trip"
        );

        let found_b = parsed.find_txid(&txid_b).unwrap();
        assert_eq!(
            found_b.raw_tx().unwrap(),
            &raw_b,
            "TX B raw bytes differ after merge round-trip"
        );
    }

    // ── Test 2: trim with 5 txs, 2 deep ancestors removed ───────────────

    #[test]
    fn test_trim_known_proven_removes_deep_ancestors_5tx() {
        // Chain: A0 (proven) <- A1 (unproven) <- B (unproven) <- C (unproven) <- D (tip, unproven)
        // Then prove B. After trim, A0 and A1 (deep ancestors of proven B) should be removed.
        // Remaining: B, C, D (3 txs).
        let mut beef = Beef::new();

        let raw_a0 = make_raw_tx(None, 10_000, None);
        let txid_a0 = add_proven_tx(&mut beef, raw_a0, 100);

        let raw_a1 = make_raw_tx(Some(&txid_a0), 9000, None);
        let txid_a1 = add_raw_tx(&mut beef, raw_a1, None);

        let raw_b = make_raw_tx(Some(&txid_a1), 8000, None);
        let txid_b = add_raw_tx(&mut beef, raw_b, None);

        let raw_c = make_raw_tx(Some(&txid_b), 7000, None);
        let txid_c = add_raw_tx(&mut beef, raw_c, None);

        let raw_d = make_raw_tx(Some(&txid_c), 6000, None);
        let txid_d = add_raw_tx(&mut beef, raw_d, None);

        assert_eq!(beef.txs.len(), 5);

        // Now prove B.
        let bump_b = MerklePath::from_coinbase_txid(&txid_b, 200);
        let bi = beef.merge_bump(bump_b);
        beef.find_txid_mut(&txid_b)
            .unwrap()
            .set_bump_index(Some(bi));

        beef.trim_known_proven();

        assert_eq!(beef.txs.len(), 3, "Should keep B, C, D only");
        assert!(beef.find_txid(&txid_a0).is_none(), "A0 should be trimmed");
        assert!(beef.find_txid(&txid_a1).is_none(), "A1 should be trimmed");
        assert!(
            beef.find_txid(&txid_b).is_some(),
            "B should remain (proven)"
        );
        assert!(beef.find_txid(&txid_c).is_some(), "C should remain");
        assert!(beef.find_txid(&txid_d).is_some(), "D should remain (tip)");
    }

    // ── Test 3: V1 <-> V2 round-trip preserving data ────────────────────

    #[test]
    fn test_beef_v1_v2_roundtrip() {
        // Build a V2 BEEF with 2 txs.
        let mut beef_v2 = Beef::with_version(BEEF_V2);
        let raw_1 = make_raw_tx(None, 1000, None);
        let txid_1 = add_proven_tx(&mut beef_v2, raw_1.clone(), 50);
        let raw_2 = make_raw_tx(Some(&txid_1), 500, None);
        let txid_2 = add_raw_tx(&mut beef_v2, raw_2.clone(), None);

        // Serialize as V2, parse back.
        let v2_bin = beef_v2.to_binary();
        let mut parsed_v2 = Beef::from_binary(&v2_bin).unwrap();
        assert_eq!(parsed_v2.version, BEEF_V2);
        assert_eq!(parsed_v2.txs.len(), 2);

        // Switch to V1, serialize, parse back.
        parsed_v2.version = BEEF_V1;
        let v1_bin = parsed_v2.to_binary();
        let parsed_v1 = Beef::from_binary(&v1_bin).unwrap();

        assert_eq!(parsed_v1.version, BEEF_V1);
        assert_eq!(parsed_v1.txs.len(), 2);

        // Verify both txids present and raw bytes preserved.
        let found_1 = parsed_v1.find_txid(&txid_1).unwrap();
        assert_eq!(found_1.raw_tx().unwrap(), &raw_1);
        let found_2 = parsed_v1.find_txid(&txid_2).unwrap();
        assert_eq!(found_2.raw_tx().unwrap(), &raw_2);

        // Verify bump is preserved.
        assert_eq!(parsed_v1.bumps.len(), 1);
        assert!(parsed_v1.bumps[0].contains(&txid_1));
    }

    // ── Test 4: V1 serialization format (raw_tx BEFORE has_bump) ────────

    #[test]
    fn test_beef_v1_serialization_format() {
        let mut beef = Beef::with_version(BEEF_V1);
        let raw_tx = make_raw_tx(None, 2000, None);
        let txid = add_proven_tx(&mut beef, raw_tx.clone(), 300);
        let _ = txid; // used indirectly via the bump

        let bin = beef.to_binary();

        // V1 format:
        //   4 bytes: version (0x0100BEEF LE -> 01 00 BE EF)
        //   varint:  bump count
        //   bumps...
        //   varint:  tx count
        //   For each tx:
        //     raw_tx bytes
        //     1 byte: has_bump (0 or 1)
        //     [varint bump_index if has_bump == 1]
        //
        // Verify the version marker.
        assert_eq!(&bin[0..4], &[0x01, 0x00, 0xBE, 0xEF]);

        // After version + bumps + tx-count varint, we should find raw_tx bytes
        // followed by has_bump=1 and bump_index=0.
        // Find the raw_tx inside the serialized BEEF.
        let tx_start = bin
            .windows(raw_tx.len())
            .position(|w| w == raw_tx.as_slice())
            .expect("raw tx bytes not found in BEEF binary");

        let after_tx = tx_start + raw_tx.len();
        // has_bump byte should be 1 (proven).
        assert_eq!(bin[after_tx], 0x01, "has_bump should be 1 for proven tx");
        // bump index should be 0 (varint encoding of 0).
        assert_eq!(bin[after_tx + 1], 0x00, "bump index should be 0");
    }

    // ── Test 5: Large OP_PUSHDATA2 script round-trip ────────────────────

    #[test]
    fn test_beef_large_pushdata_scripts() {
        // Create a transaction with a locking script > 256 bytes (needs OP_PUSHDATA2).
        let mut beef = Beef::new();

        // 400-byte script filled with a recognizable pattern.
        let script: Vec<u8> = (0..400).map(|i| ((i * 7 + 3) % 256) as u8).collect();
        let raw_tx = make_raw_tx(None, 10_000, Some(&script));
        let txid = add_raw_tx(&mut beef, raw_tx.clone(), None);

        // Round-trip through serialization.
        let bin = beef.to_binary();
        let parsed = Beef::from_binary(&bin).unwrap();

        let found = parsed.find_txid(&txid).unwrap();
        let recovered_raw = found.raw_tx().unwrap();
        assert_eq!(
            recovered_raw, &raw_tx,
            "raw tx with large script should survive round-trip"
        );

        // Verify the script bytes are embedded in the raw tx.
        let script_pos = recovered_raw
            .windows(script.len())
            .position(|w| w == script.as_slice())
            .expect("script bytes not found in recovered raw tx");
        assert!(
            script_pos > 0,
            "script should be at a nonzero offset in the tx"
        );
    }

    // ── Test 6: merge_beef remaps bump indices correctly ────────────────

    #[test]
    fn test_merge_beef_bump_indices_remapped() {
        // BEEF A: tx_a proven at block 100 (bump index 0 in A).
        let mut beef_a = Beef::new();
        let raw_a = make_raw_tx(None, 1000, None);
        let txid_a = add_proven_tx(&mut beef_a, raw_a, 100);

        // BEEF B: tx_b proven at block 200 (bump index 0 in B — different from A).
        let mut beef_b = Beef::new();
        let raw_b = make_raw_tx(None, 2000, None);
        let txid_b = add_proven_tx(&mut beef_b, raw_b, 200);

        // Before merge, both have bump index 0 in their respective BEEFs.
        assert_eq!(beef_a.find_txid(&txid_a).unwrap().bump_index(), Some(0));
        assert_eq!(beef_b.find_txid(&txid_b).unwrap().bump_index(), Some(0));

        // Merge B into A.
        beef_a.merge_beef(&beef_b);

        // After merge, A should have 2 bumps.
        assert_eq!(beef_a.bumps.len(), 2);

        // tx_a should still reference the bump at block 100.
        let btx_a = beef_a.find_txid(&txid_a).unwrap();
        let bump_a = btx_a.bump_index().unwrap();
        assert_eq!(beef_a.bumps[bump_a].block_height, 100);
        assert!(beef_a.bumps[bump_a].contains(&txid_a));

        // tx_b should reference the bump at block 200 (remapped index).
        let btx_b = beef_a.find_txid(&txid_b).unwrap();
        let bump_b = btx_b.bump_index().unwrap();
        assert_eq!(beef_a.bumps[bump_b].block_height, 200);
        assert!(beef_a.bumps[bump_b].contains(&txid_b));

        // The bump indices should be different.
        assert_ne!(bump_a, bump_b, "Bump indices should differ after merge");
    }

    // ── Test 7: trim reduces size for ARC compatibility ─────────────────

    #[test]
    fn test_trim_reduces_size_for_arc_compatibility() {
        // Build a BEEF:
        //   A0 (proven, block 10) <- A1 (proven, block 11) <- B (unproven)
        //                                                      <- C (unproven, tip)
        // Also add an unrelated proven tx D at block 12.
        // Total: 4 txs. After trim, A0 should be removed (deep ancestor of
        // proven A1). Remaining: A1, B, C, D => but A1 is proven, B depends on
        // A1 (unproven), C depends on B.
        // Actually let's build a cleaner chain:
        //   A0 (proven) <- A1 (unproven) <- A2 (unproven) <- tip
        // Then prove A1. After trim, A0 removed. Remaining: A1, A2, tip (3 txs).
        let mut beef = Beef::new();

        let raw_a0 = make_raw_tx(None, 50_000, None);
        let txid_a0 = add_proven_tx(&mut beef, raw_a0, 10);

        let raw_a1 = make_raw_tx(Some(&txid_a0), 40_000, None);
        let txid_a1 = add_raw_tx(&mut beef, raw_a1, None);

        let raw_a2 = make_raw_tx(Some(&txid_a1), 30_000, None);
        let txid_a2 = add_raw_tx(&mut beef, raw_a2, None);

        // Add two more unrelated proven txs to bulk up.
        let raw_d = make_raw_tx(None, 20_000, None);
        let txid_d = add_proven_tx(&mut beef, raw_d, 12);

        let raw_e = make_raw_tx(None, 15_000, None);
        let txid_e = add_proven_tx(&mut beef, raw_e, 13);

        assert_eq!(beef.txs.len(), 5);

        let size_before = beef.to_binary().len();

        // Prove A1.
        let bump_a1 = MerklePath::from_coinbase_txid(&txid_a1, 11);
        let bi = beef.merge_bump(bump_a1);
        beef.find_txid_mut(&txid_a1)
            .unwrap()
            .set_bump_index(Some(bi));

        beef.trim_known_proven();

        let size_after = beef.to_binary().len();

        // A0 removed, bump for block 10 removed.
        assert!(beef.find_txid(&txid_a0).is_none(), "A0 should be trimmed");
        assert!(beef.find_txid(&txid_a1).is_some());
        assert!(beef.find_txid(&txid_a2).is_some());
        assert!(beef.find_txid(&txid_d).is_some());
        assert!(beef.find_txid(&txid_e).is_some());
        assert_eq!(beef.txs.len(), 4);
        assert!(
            size_after < size_before,
            "Trimmed BEEF ({} bytes) should be smaller than original ({} bytes)",
            size_after,
            size_before
        );
    }

    // ── BEEF-to-EF extraction tests ────────────────────────────────────

    /// Helper: builds a raw transaction with 2 inputs spending two different
    /// previous txids at vout 0. Both use empty unlocking scripts.
    fn make_raw_tx_2_inputs(prev_txid_a: &str, prev_txid_b: &str, satoshis: u64) -> Vec<u8> {
        let mut raw = vec![0x01, 0x00, 0x00, 0x00]; // version
        raw.push(0x02); // 2 inputs

        // Input 0: prev_txid_a
        let mut txid_a = from_hex(prev_txid_a).unwrap();
        txid_a.reverse();
        raw.extend_from_slice(&txid_a);
        raw.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // vout=0
        raw.push(0x00); // empty unlocking script
        raw.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]); // sequence

        // Input 1: prev_txid_b
        let mut txid_b = from_hex(prev_txid_b).unwrap();
        txid_b.reverse();
        raw.extend_from_slice(&txid_b);
        raw.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // vout=0
        raw.push(0x00); // empty unlocking script
        raw.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]); // sequence

        raw.push(0x01); // 1 output
        raw.extend_from_slice(&satoshis.to_le_bytes());
        raw.push(0x00); // empty locking script
        raw.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // locktime
        raw
    }

    #[test]
    fn test_beef_to_ef_basic() {
        use crate::script::UnlockingScript;

        // Create a BEEF with 1 proven parent + 1 new (unproven) tx
        let mut beef = Beef::new();

        // Parent tx: coinbase-like, output of 10000 sats
        let parent_raw = make_raw_tx(None, 10_000, None);
        let parent_txid = add_proven_tx(&mut beef, parent_raw.clone(), 100);

        // New tx: spends parent's output
        let new_raw = make_raw_tx(Some(&parent_txid), 9000, None);
        let new_txid = add_raw_tx(&mut beef, new_raw.clone(), None);

        // Parse the new tx from raw bytes
        let mut new_tx = Transaction::from_binary(&new_raw).unwrap();
        assert_eq!(new_tx.id(), new_txid);

        // Parse the parent from raw bytes and attach as source_transaction
        let parent_tx = Transaction::from_binary(&parent_raw).unwrap();
        new_tx.inputs[0].source_transaction = Some(Box::new(parent_tx));

        // Set an empty unlocking script (required by to_ef)
        new_tx.inputs[0].unlocking_script = Some(UnlockingScript::new());

        // Call to_ef()
        let ef_bytes = new_tx.to_ef().unwrap();

        // Verify EF bytes start with version (4 bytes) then EF marker
        assert_eq!(
            &ef_bytes[0..4],
            &[0x01, 0x00, 0x00, 0x00],
            "version should be 1"
        );
        assert_eq!(
            &ef_bytes[4..10],
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0xEF],
            "EF marker should follow version"
        );

        // Round-trip: parse with from_ef(), verify txid matches
        let parsed = Transaction::from_ef(&ef_bytes).unwrap();
        assert_eq!(parsed.id(), new_txid, "EF round-trip should preserve txid");

        // Verify the source satoshis are embedded
        let source_sats = parsed.inputs[0].source_satoshis().unwrap();
        assert_eq!(
            source_sats, 10_000,
            "source satoshis should be from parent output"
        );
    }

    #[test]
    fn test_beef_to_ef_multiple_inputs() {
        use crate::script::UnlockingScript;

        // Create a BEEF with 2 proven parents + 1 new tx with 2 inputs
        let mut beef = Beef::new();

        let parent_a_raw = make_raw_tx(None, 5000, None);
        let parent_a_txid = add_proven_tx(&mut beef, parent_a_raw.clone(), 100);

        let parent_b_raw = make_raw_tx(None, 7000, None);
        let parent_b_txid = add_proven_tx(&mut beef, parent_b_raw.clone(), 101);

        // New tx spends both parents
        let new_raw = make_raw_tx_2_inputs(&parent_a_txid, &parent_b_txid, 11_000);
        let new_txid = add_raw_tx(&mut beef, new_raw.clone(), None);

        // Parse and attach source_transactions
        let mut new_tx = Transaction::from_binary(&new_raw).unwrap();
        assert_eq!(new_tx.inputs.len(), 2);

        let parent_a_tx = Transaction::from_binary(&parent_a_raw).unwrap();
        let parent_b_tx = Transaction::from_binary(&parent_b_raw).unwrap();

        new_tx.inputs[0].source_transaction = Some(Box::new(parent_a_tx));
        new_tx.inputs[0].unlocking_script = Some(UnlockingScript::new());

        new_tx.inputs[1].source_transaction = Some(Box::new(parent_b_tx));
        new_tx.inputs[1].unlocking_script = Some(UnlockingScript::new());

        // Call to_ef() — should succeed with both inputs
        let ef_bytes = new_tx.to_ef().unwrap();

        // Verify EF marker
        assert_eq!(&ef_bytes[4..10], &[0x00, 0x00, 0x00, 0x00, 0x00, 0xEF]);

        // Round-trip through from_ef()
        let parsed = Transaction::from_ef(&ef_bytes).unwrap();
        assert_eq!(parsed.id(), new_txid, "EF round-trip txid mismatch");
        assert_eq!(parsed.inputs.len(), 2, "should have 2 inputs");

        // Verify both parent outputs are embedded
        assert_eq!(
            parsed.inputs[0].source_satoshis().unwrap(),
            5000,
            "input 0 should embed parent A's 5000 sats"
        );
        assert_eq!(
            parsed.inputs[1].source_satoshis().unwrap(),
            7000,
            "input 1 should embed parent B's 7000 sats"
        );
    }

    #[test]
    fn test_beef_to_ef_large_pushdata_script() {
        use crate::script::UnlockingScript;

        // Parent has a PushDrop-style locking script > 256 bytes
        let mut beef = Beef::new();
        let big_script: Vec<u8> = (0..400).map(|i| ((i * 13 + 7) % 256) as u8).collect();
        let parent_raw = make_raw_tx(None, 20_000, Some(&big_script));
        let parent_txid = add_proven_tx(&mut beef, parent_raw.clone(), 200);

        // New tx spends the parent
        let new_raw = make_raw_tx(Some(&parent_txid), 19_000, None);
        let _new_txid = add_raw_tx(&mut beef, new_raw.clone(), None);

        let mut new_tx = Transaction::from_binary(&new_raw).unwrap();
        let parent_tx = Transaction::from_binary(&parent_raw).unwrap();

        // Verify parent has the big script in its output
        let parent_script_bytes = parent_tx.outputs[0].locking_script.to_binary();
        assert_eq!(parent_script_bytes.len(), big_script.len());

        new_tx.inputs[0].source_transaction = Some(Box::new(parent_tx));
        new_tx.inputs[0].unlocking_script = Some(UnlockingScript::new());

        let ef_bytes = new_tx.to_ef().unwrap();

        // Round-trip and verify the full script is preserved
        let parsed = Transaction::from_ef(&ef_bytes).unwrap();
        let embedded_script = parsed.inputs[0]
            .source_locking_script()
            .unwrap()
            .to_binary();
        assert_eq!(
            embedded_script, big_script,
            "EF should preserve the full >256-byte locking script"
        );
    }

    #[test]
    fn test_beef_to_ef_missing_parent_fails() {
        // Create a new tx that spends a parent, but DON'T attach source_transaction
        let mut beef = Beef::new();

        let parent_raw = make_raw_tx(None, 10_000, None);
        let parent_txid = add_proven_tx(&mut beef, parent_raw.clone(), 100);

        let new_raw = make_raw_tx(Some(&parent_txid), 9000, None);
        let _new_txid = add_raw_tx(&mut beef, new_raw.clone(), None);

        // Parse the new tx but do NOT attach source_transaction
        let mut new_tx = Transaction::from_binary(&new_raw).unwrap();
        // Set unlocking script so we get past that check
        new_tx.inputs[0].unlocking_script = Some(crate::script::UnlockingScript::new());

        // to_ef() should fail because source_transaction is missing
        let result = new_tx.to_ef();
        assert!(
            result.is_err(),
            "to_ef() should fail without source_transaction"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("source transactions"),
            "Error should mention source transactions, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_trim_known_proven_noop_when_nothing_to_trim() {
        let mut beef = Beef::new();

        // Single proven tx — nothing to trim
        let raw = vec![
            0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00,
            0xff, 0xff, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let txid = beef.merge_raw_tx(raw, None).txid();
        let bump = MerklePath::from_coinbase_txid(&txid, 100);
        let bi = beef.merge_bump(bump);
        beef.find_txid_mut(&txid).unwrap().set_bump_index(Some(bi));

        beef.trim_known_proven();
        assert_eq!(beef.txs.len(), 1); // Still there
    }

    #[test]
    fn test_merge_beef_bump_index_not_assigned_from_sibling() {
        // Reproduces the production bug where tx[1] gets assigned bump[0]
        // because tx[1]'s txid appears as a SIBLING hash in bump[0]'s path.
        //
        // Setup: Two independent proven txs (TX_A and TX_B) in separate BEEFs.
        // TX_B's txid appears as a sibling in TX_A's merkle path.
        // After merge_beef, TX_B must reference its OWN bump, not TX_A's.

        let tx_a_raw = make_raw_tx(None, 1000, None);
        let tx_b_raw = make_raw_tx(None, 2000, Some(&[0x01])); // different script → different txid

        let tx_a_id = BeefTx::from_raw_tx(tx_a_raw.clone(), None).txid();
        let tx_b_id = BeefTx::from_raw_tx(tx_b_raw.clone(), None).txid();

        // Build BEEF 1 with TX_A proven. Its merkle path has TX_B's txid as a sibling.
        let mut beef1 = Beef::new();
        add_raw_tx(&mut beef1, tx_a_raw, None);

        let bump_a = MerklePath {
            block_height: 100,
            path: vec![vec![
                MerklePathLeaf {
                    offset: 0,
                    hash: Some(tx_a_id.clone()),
                    txid: true,
                    duplicate: false,
                },
                MerklePathLeaf {
                    offset: 1,
                    hash: Some(tx_b_id.clone()), // TX_B appears as sibling!
                    txid: false,                 // NOT a txid — just a sibling hash
                    duplicate: false,
                },
            ]],
        };
        let bi_a = beef1.merge_bump(bump_a);
        beef1
            .find_txid_mut(&tx_a_id)
            .unwrap()
            .set_bump_index(Some(bi_a));

        // Build BEEF 2 with TX_B proven in a different block.
        let mut beef2 = Beef::new();
        add_raw_tx(&mut beef2, tx_b_raw, None);

        let bump_b = MerklePath::from_coinbase_txid(&tx_b_id, 200);
        let bi_b = beef2.merge_bump(bump_b);
        beef2
            .find_txid_mut(&tx_b_id)
            .unwrap()
            .set_bump_index(Some(bi_b));

        // Merge BEEF 2 into BEEF 1.
        beef1.merge_beef(&beef2);

        // TX_A should still point to bump[0] (height=100)
        let tx_a = beef1.find_txid(&tx_a_id).unwrap();
        assert_eq!(tx_a.bump_index(), Some(0), "TX_A should keep bump[0]");

        // TX_B must point to its OWN bump (height=200), NOT bump[0].
        let tx_b = beef1.find_txid(&tx_b_id).unwrap();
        let tx_b_bump_idx = tx_b.bump_index().expect("TX_B should have a bump index");
        assert_eq!(
            beef1.bumps[tx_b_bump_idx].block_height, 200,
            "TX_B's bump must be at height 200 (its own proof), not height 100 (where it's a sibling)"
        );

        // The BEEF should be valid
        assert!(beef1.is_valid(false), "Merged BEEF should be valid");
    }

    #[test]
    fn test_try_to_validate_bump_index_strict_no_sibling_fallback() {
        // When a tx's txid only appears as a SIBLING hash (txid=false) in an
        // unrelated bump, `try_to_validate_bump_index` must leave the tx's
        // bump_index as None — not fall back to the sibling match.
        //
        // Regression test for: consolidation failing with "BEEF structure is
        // invalid" because a tx's bump_index was being set to a bump that
        // contained its hash only as a sibling (used only for merkle
        // computation of some OTHER tx's proof). Go SDK reference:
        // `go-sdk/transaction/beef.go:tryToValidateBumpIndex` — strict only.
        let mut beef = Beef::new();

        // Build a bump that proves SOME OTHER tx (txid=true for it) and
        // happens to include `tx_id` as a sibling hash (txid=false).
        let tx_raw = make_raw_tx(None, 1234, None);
        let tx_id = BeefTx::from_raw_tx(tx_raw.clone(), None).txid();
        let other_txid = "d".repeat(64);

        let bump = MerklePath {
            block_height: 500,
            path: vec![vec![
                MerklePathLeaf {
                    offset: 0,
                    hash: Some(other_txid),
                    txid: true,
                    duplicate: false,
                },
                MerklePathLeaf {
                    offset: 1,
                    hash: Some(tx_id.clone()), // our tx appears here as SIBLING
                    txid: false,
                    duplicate: false,
                },
            ]],
        };
        beef.merge_bump(bump);

        // Now add our tx via merge_raw_tx (bump_index=None, forcing
        // try_to_validate_bump_index to run). Before the fix this would
        // fall back to the sibling match and set bump_index=Some(0).
        beef.merge_raw_tx(tx_raw, None);

        let tx = beef.find_txid(&tx_id).unwrap();
        assert_eq!(
            tx.bump_index(),
            None,
            "tx must not be assigned to a bump where it appears only as a sibling hash"
        );
    }

    #[test]
    fn test_update_bump_indices_ignores_siblings() {
        // Verify that update_bump_indices (called by merge_bump) does not
        // assign bump indices based on sibling hashes.
        let mut beef = Beef::new();

        let tx_raw = make_raw_tx(None, 1000, None);
        let tx_id = add_raw_tx(&mut beef, tx_raw, None);

        // Create a bump where tx_id is a SIBLING (txid=false), not a leaf
        let other_txid = "c".repeat(64);
        let bump = MerklePath {
            block_height: 100,
            path: vec![vec![
                MerklePathLeaf {
                    offset: 0,
                    hash: Some(other_txid),
                    txid: true,
                    duplicate: false,
                },
                MerklePathLeaf {
                    offset: 1,
                    hash: Some(tx_id.clone()),
                    txid: false, // Our tx appears as sibling only
                    duplicate: false,
                },
            ]],
        };

        beef.merge_bump(bump);

        // The tx should NOT have been assigned this bump
        let tx = beef.find_txid(&tx_id).unwrap();
        assert_eq!(
            tx.bump_index(),
            None,
            "Transaction must not be assigned a bump where it appears only as a sibling"
        );
    }
}
