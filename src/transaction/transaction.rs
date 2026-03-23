//! Transaction.
//!
//! Represents a complete Bitcoin transaction with inputs, outputs, and metadata.
//! Provides parsing, serialization, signing, and fee computation functionality.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

use serde_json::Value;

use super::beef::Beef;
use super::beef_tx::{BEEF_V1, BEEF_V2};
use super::input::TransactionInput;
use super::merkle_path::MerklePath;
use super::output::TransactionOutput;
use crate::primitives::{from_hex, sha256d, to_hex, Reader, Writer};
use crate::script::{LockingScript, SigningContext, UnlockingScript};
use crate::Result;

/// Represents a complete Bitcoin transaction.
///
/// This struct encapsulates all the details required for creating, signing,
/// and processing a Bitcoin transaction, including inputs, outputs, version,
/// and lock time.
///
/// # Example
///
/// ```rust,ignore
/// use bsv_rs::transaction::{Transaction, TransactionInput, TransactionOutput};
///
/// let mut tx = Transaction::new();
/// tx.add_input(TransactionInput::new("abc123...".to_string(), 0))?;
/// tx.add_output(TransactionOutput::new(100_000, locking_script))?;
/// tx.fee(None, ChangeDistribution::Equal).await?;
/// tx.sign().await?;
/// ```
#[derive(Debug, Clone)]
pub struct Transaction {
    /// Transaction version number.
    ///
    /// Version 1 is standard. Version 2 enables BIP 68/112/113 features.
    pub version: u32,

    /// Transaction inputs.
    pub inputs: Vec<TransactionInput>,

    /// Transaction outputs.
    pub outputs: Vec<TransactionOutput>,

    /// Lock time.
    ///
    /// If non-zero, specifies the earliest time or block height at which
    /// the transaction can be added to the blockchain.
    pub lock_time: u32,

    /// Metadata for attaching additional data to the transaction.
    ///
    /// This is not included in the serialized transaction.
    pub metadata: HashMap<String, Value>,

    /// Merkle path (BRC-74 BUMP) proving this transaction is in a block.
    ///
    /// When set, indicates this transaction has been mined and has SPV proof.
    /// Used by `to_beef()` to determine when to stop walking the ancestry chain.
    pub merkle_path: Option<MerklePath>,

    // Caches for serialization and hashing
    cached_hash: RefCell<Option<[u8; 32]>>,
    raw_bytes_cache: RefCell<Option<Vec<u8>>>,
    hex_cache: RefCell<Option<String>>,
}

/// Specifies how change should be distributed among change outputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeDistribution {
    /// Distribute change equally among all change outputs.
    Equal,
    /// Distribute change randomly using Benford's law distribution.
    Random,
}

/// Script offsets for efficient script retrieval from binary transaction data.
#[derive(Debug, Clone)]
pub struct ScriptOffsets {
    /// Offsets for input scripts.
    pub inputs: Vec<ScriptOffset>,
    /// Offsets for output scripts.
    pub outputs: Vec<ScriptOffset>,
}

/// Offset and length of a script within binary transaction data.
#[derive(Debug, Clone)]
pub struct ScriptOffset {
    /// Input/output index.
    pub index: usize,
    /// Byte offset within the transaction.
    pub offset: usize,
    /// Length of the script in bytes.
    pub length: usize,
}

impl Transaction {
    /// Creates a new empty transaction with default version 1.
    pub fn new() -> Self {
        Self {
            version: 1,
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0,
            metadata: HashMap::new(),
            merkle_path: None,
            cached_hash: RefCell::new(None),
            raw_bytes_cache: RefCell::new(None),
            hex_cache: RefCell::new(None),
        }
    }

    /// Creates a new transaction with the specified parameters.
    pub fn with_params(
        version: u32,
        inputs: Vec<TransactionInput>,
        outputs: Vec<TransactionOutput>,
        lock_time: u32,
    ) -> Self {
        Self {
            version,
            inputs,
            outputs,
            lock_time,
            metadata: HashMap::new(),
            merkle_path: None,
            cached_hash: RefCell::new(None),
            raw_bytes_cache: RefCell::new(None),
            hex_cache: RefCell::new(None),
        }
    }

    /// Parses a transaction from binary data.
    ///
    /// # Arguments
    ///
    /// * `bin` - The binary transaction data
    ///
    /// # Returns
    ///
    /// The parsed transaction.
    pub fn from_binary(bin: &[u8]) -> Result<Self> {
        let raw_bytes = bin.to_vec();
        let mut reader = Reader::new(bin);
        let tx = Self::from_reader(&mut reader)?;

        *tx.raw_bytes_cache.borrow_mut() = Some(raw_bytes);
        Ok(tx)
    }

    /// Parses a transaction from a hex string.
    ///
    /// # Arguments
    ///
    /// * `hex` - The hex-encoded transaction
    ///
    /// # Returns
    ///
    /// The parsed transaction.
    pub fn from_hex(hex: &str) -> Result<Self> {
        let bin = from_hex(hex)?;
        let raw_bytes = bin.clone();
        let mut reader = Reader::new(&bin);
        let tx = Self::from_reader(&mut reader)?;

        *tx.raw_bytes_cache.borrow_mut() = Some(raw_bytes);
        *tx.hex_cache.borrow_mut() = Some(hex.to_lowercase());
        Ok(tx)
    }

    /// Parses a transaction from Extended Format (BRC-30).
    ///
    /// The EF format includes source satoshis and locking scripts for each input,
    /// enabling SPV verification without needing the full source transactions.
    ///
    /// # Arguments
    ///
    /// * `ef` - The binary EF data
    ///
    /// # Returns
    ///
    /// The parsed transaction with source transaction data populated.
    pub fn from_ef(ef: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(ef);

        let version = reader.read_u32_le()?;

        // Check for EF marker: 6 bytes of 0x0000000000EF
        let marker = reader.read_bytes(6)?;
        if marker != [0x00, 0x00, 0x00, 0x00, 0x00, 0xEF] {
            return Err(crate::Error::TransactionError(
                "Invalid EF marker".to_string(),
            ));
        }

        // Parse inputs with source data
        let input_count = reader.read_var_int_num()?;
        let mut inputs = Vec::with_capacity(input_count);

        for _ in 0..input_count {
            // Read TXID (reversed in EF format)
            let txid_bytes = reader.read_bytes(32)?;
            let mut txid_reversed = [0u8; 32];
            for (i, byte) in txid_bytes.iter().enumerate() {
                txid_reversed[31 - i] = *byte;
            }
            let source_txid = to_hex(&txid_reversed);

            let source_output_index = reader.read_u32_le()?;

            // Read unlocking script
            let script_len = reader.read_var_int_num()?;
            let script_bytes = reader.read_bytes(script_len)?;
            let unlocking_script = UnlockingScript::from_binary(script_bytes)?;

            let sequence = reader.read_u32_le()?;

            // Read source satoshis
            let source_satoshis = reader.read_u64_le()?;

            // Read source locking script
            let locking_script_len = reader.read_var_int_num()?;
            let locking_script_bytes = reader.read_bytes(locking_script_len)?;
            let locking_script = LockingScript::from_binary(locking_script_bytes)?;

            // Create a minimal source transaction with just the output we need
            let mut source_tx = Transaction::new();
            source_tx.outputs =
                vec![TransactionOutput::default(); source_output_index as usize + 1];
            source_tx.outputs[source_output_index as usize] = TransactionOutput {
                satoshis: Some(source_satoshis),
                locking_script,
                change: false,
            };

            inputs.push(TransactionInput {
                source_transaction: Some(Box::new(source_tx)),
                source_txid: Some(source_txid),
                source_output_index,
                unlocking_script: Some(unlocking_script),
                unlocking_script_template: None,
                sequence,
            });
        }

        // Parse outputs
        let output_count = reader.read_var_int_num()?;
        let mut outputs = Vec::with_capacity(output_count);

        for _ in 0..output_count {
            let satoshis = reader.read_u64_le()?;
            let script_len = reader.read_var_int_num()?;
            let script_bytes = reader.read_bytes(script_len)?;
            let locking_script = LockingScript::from_binary(script_bytes)?;

            outputs.push(TransactionOutput {
                satoshis: Some(satoshis),
                locking_script,
                change: false,
            });
        }

        let lock_time = reader.read_u32_le()?;

        Ok(Self::with_params(version, inputs, outputs, lock_time))
    }

    /// Parses a transaction from a hex-encoded Extended Format string.
    ///
    /// # Arguments
    ///
    /// * `hex` - The hex-encoded EF data
    ///
    /// # Returns
    ///
    /// The parsed transaction.
    pub fn from_hex_ef(hex: &str) -> Result<Self> {
        let bin = from_hex(hex)?;
        Self::from_ef(&bin)
    }

    /// Parses a transaction from a Reader.
    pub(crate) fn from_reader_internal(reader: &mut Reader) -> Result<Self> {
        Self::from_reader(reader)
    }

    /// Parses a transaction from a Reader.
    fn from_reader(reader: &mut Reader) -> Result<Self> {
        let version = reader.read_u32_le()?;

        let input_count = reader.read_var_int_num()?;
        let mut inputs = Vec::with_capacity(input_count);

        for _ in 0..input_count {
            // Read TXID (stored reversed)
            let txid_bytes = reader.read_bytes(32)?;
            let mut txid_reversed = [0u8; 32];
            for (i, byte) in txid_bytes.iter().enumerate() {
                txid_reversed[31 - i] = *byte;
            }
            let source_txid = to_hex(&txid_reversed);

            let source_output_index = reader.read_u32_le()?;

            let script_len = reader.read_var_int_num()?;
            let script_bytes = reader.read_bytes(script_len)?;
            let unlocking_script = UnlockingScript::from_binary(script_bytes)?;

            let sequence = reader.read_u32_le()?;

            inputs.push(TransactionInput {
                source_transaction: None,
                source_txid: Some(source_txid),
                source_output_index,
                unlocking_script: Some(unlocking_script),
                unlocking_script_template: None,
                sequence,
            });
        }

        let output_count = reader.read_var_int_num()?;
        let mut outputs = Vec::with_capacity(output_count);

        for _ in 0..output_count {
            let satoshis = reader.read_u64_le()?;
            let script_len = reader.read_var_int_num()?;
            let script_bytes = reader.read_bytes(script_len)?;
            let locking_script = LockingScript::from_binary(script_bytes)?;

            outputs.push(TransactionOutput {
                satoshis: Some(satoshis),
                locking_script,
                change: false,
            });
        }

        let lock_time = reader.read_u32_le()?;

        Ok(Self::with_params(version, inputs, outputs, lock_time))
    }

    /// Parses script offsets from binary transaction data.
    ///
    /// This is useful for efficiently retrieving scripts from stored transaction data
    /// without parsing the entire transaction.
    ///
    /// # Arguments
    ///
    /// * `bin` - The binary transaction data
    ///
    /// # Returns
    ///
    /// The script offsets for inputs and outputs.
    pub fn parse_script_offsets(bin: &[u8]) -> Result<ScriptOffsets> {
        let mut reader = Reader::new(bin);
        let mut input_offsets = Vec::new();
        let mut output_offsets = Vec::new();

        // Skip version
        reader.read_u32_le()?;

        // Parse input offsets
        let input_count = reader.read_var_int_num()?;
        for i in 0..input_count {
            // Skip txid and vout (36 bytes)
            reader.read_bytes(36)?;

            let script_len = reader.read_var_int_num()?;
            let offset = reader.position();

            input_offsets.push(ScriptOffset {
                index: i,
                offset,
                length: script_len,
            });

            // Skip script and sequence
            reader.read_bytes(script_len)?;
            reader.read_u32_le()?;
        }

        // Parse output offsets
        let output_count = reader.read_var_int_num()?;
        for i in 0..output_count {
            // Skip satoshis
            reader.read_u64_le()?;

            let script_len = reader.read_var_int_num()?;
            let offset = reader.position();

            output_offsets.push(ScriptOffset {
                index: i,
                offset,
                length: script_len,
            });

            // Skip script
            reader.read_bytes(script_len)?;
        }

        Ok(ScriptOffsets {
            inputs: input_offsets,
            outputs: output_offsets,
        })
    }

    // ===================
    // BEEF Format Methods
    // ===================

    /// Parses a transaction from BEEF format.
    ///
    /// # Arguments
    ///
    /// * `beef` - The BEEF binary data
    /// * `txid` - Optional txid to extract. If None, returns the last transaction.
    ///
    /// # Returns
    ///
    /// The parsed transaction.
    pub fn from_beef(beef: &[u8], txid: Option<&str>) -> Result<Self> {
        let parsed = Beef::from_binary(beef)?;

        match txid {
            Some(id) => parsed
                .find_txid(id)
                .and_then(|btx| btx.tx().cloned())
                .ok_or_else(|| {
                    crate::Error::TransactionError(format!("Transaction {} not found in BEEF", id))
                }),
            None => parsed
                .txs
                .last()
                .and_then(|btx| btx.tx().cloned())
                .ok_or_else(|| {
                    crate::Error::TransactionError("No transactions in BEEF".to_string())
                }),
        }
    }

    /// Parses a transaction from Atomic BEEF format.
    ///
    /// The atomic txid in the BEEF header identifies the transaction to return.
    pub fn from_atomic_beef(beef: &[u8]) -> Result<Self> {
        let parsed = Beef::from_binary(beef)?;

        let txid = parsed.atomic_txid.as_ref().ok_or_else(|| {
            crate::Error::TransactionError("Not an Atomic BEEF format".to_string())
        })?;

        parsed.find_atomic_transaction(txid).ok_or_else(|| {
            crate::Error::TransactionError("Atomic transaction not found".to_string())
        })
    }

    /// Serializes this transaction to BEEF format.
    ///
    /// This method walks the `source_transaction` chain for each input,
    /// collecting all ancestor transactions and their merkle proofs until
    /// it reaches transactions that are proven (have a `merkle_path`).
    ///
    /// # Arguments
    ///
    /// * `allow_partial` - If true, skips inputs with missing source transactions.
    ///   If false, returns an error if any source transaction is missing.
    ///
    /// # Returns
    ///
    /// The BEEF binary data containing this transaction and all required ancestors.
    ///
    /// # Errors
    ///
    /// Returns an error if `allow_partial` is false and any input is missing
    /// its source transaction.
    pub fn to_beef(&self, allow_partial: bool) -> Result<Vec<u8>> {
        let mut beef = Beef::with_version(BEEF_V2);

        // Collect all ancestors in dependency order
        let mut seen_txids: HashSet<String> = HashSet::new();
        let mut ancestors: Vec<Transaction> = Vec::new();
        let mut bumps: Vec<MerklePath> = Vec::new();
        let mut bump_index_by_root: HashMap<String, usize> = HashMap::new();

        self.collect_ancestors(
            allow_partial,
            &mut seen_txids,
            &mut ancestors,
            &mut bumps,
            &mut bump_index_by_root,
        )?;

        // Add all collected merkle paths to the BEEF
        for bump in bumps {
            beef.merge_bump(bump);
        }

        // Add all ancestor transactions in dependency order (oldest first)
        for ancestor in ancestors {
            beef.merge_transaction(ancestor);
        }

        Ok(beef.to_binary())
    }

    /// Serializes this transaction and its ancestors to BEEF V1 format.
    ///
    /// BEEF V1 (BRC-62) is the format required by ARC and most broadcast services.
    /// This method is identical to `to_beef()` but produces V1 format output.
    ///
    /// # Arguments
    ///
    /// * `allow_partial` - If true, skips inputs with missing source transactions.
    ///   If false, returns an error if any source transaction is missing.
    ///
    /// # Returns
    ///
    /// The BEEF V1 binary data containing all ancestor transactions and merkle proofs.
    ///
    /// # Errors
    ///
    /// Returns an error if `allow_partial` is false and any input is missing
    /// its source transaction.
    pub fn to_beef_v1(&self, allow_partial: bool) -> Result<Vec<u8>> {
        let mut beef = Beef::with_version(BEEF_V1);

        // Collect all ancestors in dependency order
        let mut seen_txids: HashSet<String> = HashSet::new();
        let mut ancestors: Vec<Transaction> = Vec::new();
        let mut bumps: Vec<MerklePath> = Vec::new();
        let mut bump_index_by_root: HashMap<String, usize> = HashMap::new();

        self.collect_ancestors(
            allow_partial,
            &mut seen_txids,
            &mut ancestors,
            &mut bumps,
            &mut bump_index_by_root,
        )?;

        // Add all collected merkle paths to the BEEF
        for bump in bumps {
            beef.merge_bump(bump);
        }

        // Add all ancestor transactions in dependency order (oldest first)
        for ancestor in ancestors {
            beef.merge_transaction(ancestor);
        }

        Ok(beef.to_binary())
    }

    /// Serializes this transaction to Atomic BEEF format.
    ///
    /// The Atomic BEEF format (BRC-95) includes a 4-byte prefix `0x01010101`,
    /// followed by this transaction's TXID, and then the BEEF data containing
    /// only this transaction and its dependencies.
    ///
    /// # Arguments
    ///
    /// * `allow_partial` - If true, skips inputs with missing source transactions.
    ///   If false, returns an error if any source transaction is missing.
    ///
    /// # Returns
    ///
    /// The Atomic BEEF binary data.
    ///
    /// # Errors
    ///
    /// Returns an error if `allow_partial` is false and any input is missing
    /// its source transaction.
    pub fn to_atomic_beef(&self, allow_partial: bool) -> Result<Vec<u8>> {
        let mut beef = Beef::with_version(BEEF_V2);

        // Collect all ancestors in dependency order
        let mut seen_txids: HashSet<String> = HashSet::new();
        let mut ancestors: Vec<Transaction> = Vec::new();
        let mut bumps: Vec<MerklePath> = Vec::new();
        let mut bump_index_by_root: HashMap<String, usize> = HashMap::new();

        self.collect_ancestors(
            allow_partial,
            &mut seen_txids,
            &mut ancestors,
            &mut bumps,
            &mut bump_index_by_root,
        )?;

        // Add all collected merkle paths to the BEEF
        for bump in bumps {
            beef.merge_bump(bump);
        }

        // Add all ancestor transactions in dependency order (oldest first)
        for ancestor in ancestors {
            beef.merge_transaction(ancestor);
        }

        let txid = self.id();
        beef.to_binary_atomic(&txid)
    }

    /// Recursively collects ancestor transactions and their merkle proofs.
    ///
    /// This implements the same algorithm as the TypeScript and Go SDKs:
    /// - If this transaction has a merkle_path (is proven), add it and stop recursion
    /// - Otherwise, recursively collect ancestors from each input's source_transaction
    /// - Ancestors are returned in dependency order (oldest first)
    /// - Merkle proofs are deduplicated by block height and computed root
    ///
    /// # Arguments
    ///
    /// * `allow_partial` - If true, skip inputs with missing source transactions
    /// * `seen_txids` - Set of already-processed txids (for cycle detection)
    /// * `ancestors` - Output vector of ancestor transactions in dependency order
    /// * `bumps` - Output vector of deduplicated merkle paths
    /// * `bump_index_by_root` - Map from "height:root" to bump index for deduplication
    fn collect_ancestors(
        &self,
        allow_partial: bool,
        seen_txids: &mut HashSet<String>,
        ancestors: &mut Vec<Transaction>,
        bumps: &mut Vec<MerklePath>,
        bump_index_by_root: &mut HashMap<String, usize>,
    ) -> Result<()> {
        let txid = self.id();

        // Check for cycles - if we've already seen this transaction, skip it
        if seen_txids.contains(&txid) {
            return Ok(());
        }

        // If this transaction has a merkle proof, it's proven (mined)
        // Add the proof and transaction, then stop recursion
        if let Some(ref merkle_path) = self.merkle_path {
            // Deduplicate merkle proofs by block height and computed root
            let root = merkle_path.compute_root(Some(&txid)).unwrap_or_default();
            let key = format!("{}:{}", merkle_path.block_height, root);

            if let Some(&existing_idx) = bump_index_by_root.get(&key) {
                // Combine with existing bump at same height/root
                if bumps[existing_idx].combine(merkle_path).is_err() {
                    // If combine fails, just add as new
                    let new_idx = bumps.len();
                    bumps.push(merkle_path.clone());
                    bump_index_by_root.insert(key, new_idx);
                }
            } else {
                // Add as new bump
                let new_idx = bumps.len();
                bumps.push(merkle_path.clone());
                bump_index_by_root.insert(key, new_idx);
            }

            // Mark as seen and add to ancestors
            seen_txids.insert(txid);
            ancestors.push(self.clone());
            return Ok(());
        }

        // Transaction is not proven - recursively collect ancestors from inputs
        // Process inputs in reverse order (like TypeScript SDK) for correct dependency order
        for i in (0..self.inputs.len()).rev() {
            let input = &self.inputs[i];

            if let Some(ref source_tx) = input.source_transaction {
                // Recursively collect ancestors from this source transaction
                source_tx.collect_ancestors(
                    allow_partial,
                    seen_txids,
                    ancestors,
                    bumps,
                    bump_index_by_root,
                )?;
            } else if !allow_partial {
                // Missing source transaction and not allowing partial
                let source_txid = input.source_txid.as_deref().unwrap_or("unknown");
                return Err(crate::Error::TransactionError(format!(
                    "Missing source transaction for input {} (txid: {}). \
                     Set allow_partial=true to skip missing source transactions.",
                    i, source_txid
                )));
            }
            // If allow_partial and source_transaction is None, just skip this input
        }

        // After processing all ancestors, add this transaction
        seen_txids.insert(txid);
        ancestors.push(self.clone());

        Ok(())
    }

    /// Invalidates all serialization caches.
    fn invalidate_caches(&self) {
        *self.cached_hash.borrow_mut() = None;
        *self.raw_bytes_cache.borrow_mut() = None;
        *self.hex_cache.borrow_mut() = None;
    }

    /// Adds an input to the transaction.
    ///
    /// # Arguments
    ///
    /// * `input` - The input to add
    ///
    /// # Errors
    ///
    /// Returns an error if the input has neither a source TXID nor source transaction.
    pub fn add_input(&mut self, mut input: TransactionInput) -> Result<()> {
        if input.source_txid.is_none() && input.source_transaction.is_none() {
            return Err(crate::Error::TransactionError(
                "A reference to an input transaction is required. If the input transaction itself \
                 cannot be referenced, its TXID must still be provided."
                    .to_string(),
            ));
        }

        // Default sequence to final if not set
        if input.sequence == 0 {
            input.sequence = 0xFFFFFFFF;
        }

        self.invalidate_caches();
        self.inputs.push(input);
        Ok(())
    }

    /// Adds an output to the transaction.
    ///
    /// # Arguments
    ///
    /// * `output` - The output to add
    ///
    /// # Errors
    ///
    /// Returns an error if the output is missing required fields.
    pub fn add_output(&mut self, output: TransactionOutput) -> Result<()> {
        if !output.change && output.satoshis.is_none() {
            return Err(crate::Error::TransactionError(
                "Either satoshis must be defined or change must be set to true".to_string(),
            ));
        }

        self.invalidate_caches();
        self.outputs.push(output);
        Ok(())
    }

    /// Adds a P2PKH output to the transaction.
    ///
    /// # Arguments
    ///
    /// * `address` - The P2PKH address (Base58Check encoded)
    /// * `satoshis` - Optional amount; if None, creates a change output
    pub fn add_p2pkh_output(&mut self, address: &str, satoshis: Option<u64>) -> Result<()> {
        use crate::primitives::from_base58_check;
        use crate::script::Script;

        // Decode the address to get the pubkey hash
        let (version, pubkey_hash) = from_base58_check(address)?;

        // Verify it's a P2PKH address (version 0x00 for mainnet)
        if version.len() != 1 || (version[0] != 0x00 && version[0] != 0x6f) {
            return Err(crate::Error::TransactionError(format!(
                "Invalid P2PKH address version: {:?}",
                version
            )));
        }

        if pubkey_hash.len() != 20 {
            return Err(crate::Error::TransactionError(
                "Invalid pubkey hash length".to_string(),
            ));
        }

        // Build P2PKH locking script: OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG
        let mut script = Script::new();
        script
            .write_opcode(0x76) // OP_DUP
            .write_opcode(0xa9) // OP_HASH160
            .write_bin(&pubkey_hash)
            .write_opcode(0x88) // OP_EQUALVERIFY
            .write_opcode(0xac); // OP_CHECKSIG

        let locking_script = LockingScript::from_script(script);

        match satoshis {
            Some(sats) => self.add_output(TransactionOutput::new(sats, locking_script)),
            None => self.add_output(TransactionOutput::new_change(locking_script)),
        }
    }

    /// Adds an OP_FALSE OP_RETURN output with a single data payload.
    ///
    /// Creates a safe data carrier output (unspendable, prunable) with the given data.
    /// The output has 0 satoshis.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to embed in the OP_RETURN output
    pub fn add_op_return_output(&mut self, data: &[u8]) -> Result<()> {
        self.add_op_return_parts_output(&[data])
    }

    /// Adds an OP_FALSE OP_RETURN output with multiple data parts.
    ///
    /// Creates a safe data carrier output (unspendable, prunable) with multiple
    /// push-data segments. The output has 0 satoshis.
    ///
    /// # Arguments
    ///
    /// * `parts` - The data parts to embed in the OP_RETURN output
    pub fn add_op_return_parts_output(&mut self, parts: &[&[u8]]) -> Result<()> {
        use crate::script::Script;

        let mut script = Script::new();
        script
            .write_opcode(0x00) // OP_FALSE
            .write_opcode(0x6a); // OP_RETURN
        for part in parts {
            script.write_bin(part);
        }

        let locking_script = LockingScript::from_script(script);
        self.add_output(TransactionOutput::new(0, locking_script))
    }

    /// Adds a hash puzzle output to the transaction.
    ///
    /// Creates a locking script that requires both knowledge of a secret preimage
    /// and a valid P2PKH signature to spend:
    /// `OP_HASH160 <HASH160(secret)> OP_EQUALVERIFY OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG`
    ///
    /// # Arguments
    ///
    /// * `secret` - The secret string whose HASH160 becomes the puzzle
    /// * `public_key_hash` - Hex-encoded 20-byte public key hash
    /// * `satoshis` - The amount to lock in the output
    pub fn add_hash_puzzle_output(
        &mut self,
        secret: &str,
        public_key_hash: &str,
        satoshis: u64,
    ) -> Result<()> {
        use crate::primitives::{from_hex as decode_hex, hash160};
        use crate::script::Script;

        let pubkey_hash_bytes = decode_hex(public_key_hash)?;
        if pubkey_hash_bytes.len() != 20 {
            return Err(crate::Error::TransactionError(
                "Invalid pubkey hash length, expected 20 bytes".to_string(),
            ));
        }

        let secret_hash = hash160(secret.as_bytes());

        let mut script = Script::new();
        script
            .write_opcode(0xa9) // OP_HASH160
            .write_bin(&secret_hash)
            .write_opcode(0x88) // OP_EQUALVERIFY
            .write_opcode(0x76) // OP_DUP
            .write_opcode(0xa9) // OP_HASH160
            .write_bin(&pubkey_hash_bytes)
            .write_opcode(0x88) // OP_EQUALVERIFY
            .write_opcode(0xac); // OP_CHECKSIG

        let locking_script = LockingScript::from_script(script);
        self.add_output(TransactionOutput::new(satoshis, locking_script))
    }

    /// Adds an input from a source transaction and output index, with an unlocking script template.
    ///
    /// This is a convenience wrapper that creates a `TransactionInput` with a full
    /// source transaction reference and assigns the given unlocking script template,
    /// matching the Go SDK's `AddInputFromTx` method.
    ///
    /// # Arguments
    ///
    /// * `source_tx` - The source transaction containing the output being spent
    /// * `vout` - The index of the output being spent in the source transaction
    /// * `template` - The unlocking script template for signing this input
    ///
    /// # Errors
    ///
    /// Returns an error if the input cannot be added (e.g., missing source data).
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use bsv_rs::transaction::Transaction;
    /// use bsv_rs::script::templates::P2PKH;
    ///
    /// let source_tx = Transaction::from_hex("...")?;
    /// let mut tx = Transaction::new();
    /// tx.add_input_from_tx(source_tx, 0, P2PKH::new().unlock(&private_key, None, None, None)?)?;
    /// ```
    pub fn add_input_from_tx(
        &mut self,
        source_tx: Transaction,
        vout: u32,
        template: crate::script::ScriptTemplateUnlock,
    ) -> Result<()> {
        let mut input = TransactionInput::with_source_transaction(source_tx, vout);
        input.set_unlocking_script_template(template);
        self.add_input(input)
    }

    /// Adds an input from a previous TXID, output index, locking script, and satoshis,
    /// with an unlocking script template.
    ///
    /// This is a convenience wrapper that creates a `TransactionInput` with a minimal
    /// source transaction containing the specified locking script and satoshis at the
    /// correct output index. This allows signing to work without having the full source
    /// transaction available, matching the Go SDK's `AddInputFrom` method.
    ///
    /// # Arguments
    ///
    /// * `prev_txid` - The hex-encoded TXID of the previous transaction
    /// * `vout` - The index of the output being spent
    /// * `prev_locking_script` - The locking script of the output being spent
    /// * `satoshis` - The satoshi value of the output being spent
    /// * `template` - The unlocking script template for signing this input
    ///
    /// # Errors
    ///
    /// Returns an error if the TXID is empty or not valid hex encoding of 32 bytes.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use bsv_rs::transaction::Transaction;
    /// use bsv_rs::script::{LockingScript, templates::P2PKH};
    ///
    /// let mut tx = Transaction::new();
    /// let locking_script = LockingScript::from_hex("76a914...88ac")?;
    /// tx.add_input_from(
    ///     "abc123...",
    ///     0,
    ///     &locking_script,
    ///     100_000,
    ///     P2PKH::new().unlock(&private_key, None, None, None)?,
    /// )?;
    /// ```
    pub fn add_input_from(
        &mut self,
        prev_txid: &str,
        vout: u32,
        prev_locking_script: &LockingScript,
        satoshis: u64,
        template: crate::script::ScriptTemplateUnlock,
    ) -> Result<()> {
        // Validate the TXID
        if prev_txid.is_empty() {
            return Err(crate::Error::TransactionError(
                "Previous TXID must not be empty".to_string(),
            ));
        }

        let txid_bytes = from_hex(prev_txid)?;
        if txid_bytes.len() != 32 {
            return Err(crate::Error::TransactionError(format!(
                "Invalid TXID length: expected 32 bytes (64 hex chars), got {} bytes",
                txid_bytes.len()
            )));
        }

        // Build a minimal source transaction with the correct output at the given index
        let mut source_tx = Transaction::new();
        for _ in 0..vout {
            source_tx
                .outputs
                .push(TransactionOutput::new(0, LockingScript::new()));
        }
        source_tx.outputs.push(TransactionOutput::new(
            satoshis,
            prev_locking_script.clone(),
        ));

        let mut input = TransactionInput::new(prev_txid.to_string(), vout);
        input.source_transaction = Some(Box::new(source_tx));
        input.set_unlocking_script_template(template);
        self.add_input(input)
    }

    /// Adds inputs from a slice of UTXOs.
    ///
    /// For each UTXO, creates a `TransactionInput` with a minimal source transaction
    /// containing the UTXO's locking script and satoshis at the correct output index.
    /// The unlocking script template is **not** set; the caller must set templates on
    /// the inputs separately or provide them during signing.
    ///
    /// This matches the Go SDK's `AddInputsFromUTXOs` method.
    ///
    /// # Arguments
    ///
    /// * `utxos` - The UTXOs to add as inputs
    ///
    /// # Errors
    ///
    /// Returns an error if any UTXO has an empty or invalid TXID.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use bsv_rs::transaction::{Transaction, Utxo};
    /// use bsv_rs::script::LockingScript;
    ///
    /// let utxos = vec![
    ///     Utxo {
    ///         txid: "abc123...".to_string(),
    ///         vout: 0,
    ///         satoshis: 100_000,
    ///         locking_script: LockingScript::from_hex("76a914...88ac")?,
    ///     },
    /// ];
    /// let mut tx = Transaction::new();
    /// tx.add_inputs_from_utxos(&utxos)?;
    /// ```
    pub fn add_inputs_from_utxos(&mut self, utxos: &[super::input::Utxo]) -> Result<()> {
        for utxo in utxos {
            // Validate the TXID
            if utxo.txid.is_empty() {
                return Err(crate::Error::TransactionError(
                    "UTXO TXID must not be empty".to_string(),
                ));
            }

            let txid_bytes = from_hex(&utxo.txid)?;
            if txid_bytes.len() != 32 {
                return Err(crate::Error::TransactionError(format!(
                    "Invalid UTXO TXID length: expected 32 bytes (64 hex chars), got {} bytes",
                    txid_bytes.len()
                )));
            }

            // Build a minimal source transaction with the correct output at the given index
            let mut source_tx = Transaction::new();
            for _ in 0..utxo.vout {
                source_tx
                    .outputs
                    .push(TransactionOutput::new(0, LockingScript::new()));
            }
            source_tx.outputs.push(TransactionOutput::new(
                utxo.satoshis,
                utxo.locking_script.clone(),
            ));

            let mut input = TransactionInput::new(utxo.txid.clone(), utxo.vout);
            input.source_transaction = Some(Box::new(source_tx));
            self.add_input(input)?;
        }
        Ok(())
    }

    /// Updates the transaction metadata.
    ///
    /// # Arguments
    ///
    /// * `key` - The metadata key
    /// * `value` - The metadata value
    pub fn update_metadata(&mut self, key: &str, value: Value) {
        self.metadata.insert(key.to_string(), value);
    }

    /// Serializes the transaction to binary format.
    pub fn to_binary(&self) -> Vec<u8> {
        if let Some(ref bytes) = *self.raw_bytes_cache.borrow() {
            return bytes.clone();
        }

        let bytes = self.build_serialized_bytes();
        *self.raw_bytes_cache.borrow_mut() = Some(bytes.clone());
        bytes
    }

    /// Serializes the transaction to a hex string.
    pub fn to_hex(&self) -> String {
        if let Some(ref hex) = *self.hex_cache.borrow() {
            return hex.clone();
        }

        let bytes = self.to_binary();
        let hex = to_hex(&bytes);
        *self.hex_cache.borrow_mut() = Some(hex.clone());
        hex
    }

    /// Serializes the transaction to Extended Format (BRC-30).
    ///
    /// The EF format includes source satoshis and locking scripts for each input.
    ///
    /// # Errors
    ///
    /// Returns an error if any input is missing its source transaction.
    pub fn to_ef(&self) -> Result<Vec<u8>> {
        let mut writer = Writer::new();

        writer.write_u32_le(self.version);

        // Write EF marker
        writer.write_bytes(&[0x00, 0x00, 0x00, 0x00, 0x00, 0xEF]);

        // Write inputs with source data
        writer.write_var_int(self.inputs.len() as u64);
        for input in &self.inputs {
            // Get TXID bytes (reversed)
            let txid_bytes = input.get_source_txid_bytes()?;
            writer.write_bytes(&txid_bytes);

            writer.write_u32_le(input.source_output_index);

            // Write unlocking script
            let unlocking_script = input
                .unlocking_script
                .as_ref()
                .ok_or_else(|| {
                    crate::Error::TransactionError("unlockingScript is undefined".to_string())
                })?
                .to_binary();
            writer.write_var_int(unlocking_script.len() as u64);
            writer.write_bytes(&unlocking_script);

            writer.write_u32_le(input.sequence);

            // Get source satoshis and locking script
            let source_tx = input.source_transaction.as_ref().ok_or_else(|| {
                crate::Error::TransactionError(
                    "All inputs must have source transactions when serializing to EF format"
                        .to_string(),
                )
            })?;

            let source_output = source_tx
                .outputs
                .get(input.source_output_index as usize)
                .ok_or_else(|| {
                    crate::Error::TransactionError("Source output index out of bounds".to_string())
                })?;

            writer.write_u64_le(source_output.satoshis.unwrap_or(0));

            let locking_script = source_output.locking_script.to_binary();
            writer.write_var_int(locking_script.len() as u64);
            writer.write_bytes(&locking_script);
        }

        // Write outputs
        writer.write_var_int(self.outputs.len() as u64);
        for output in &self.outputs {
            writer.write_u64_le(output.satoshis.unwrap_or(0));

            let script = output.locking_script.to_binary();
            writer.write_var_int(script.len() as u64);
            writer.write_bytes(&script);
        }

        writer.write_u32_le(self.lock_time);

        Ok(writer.into_bytes())
    }

    /// Serializes the transaction to a hex-encoded Extended Format string.
    pub fn to_hex_ef(&self) -> Result<String> {
        Ok(to_hex(&self.to_ef()?))
    }

    /// Builds the serialized bytes for this transaction.
    fn build_serialized_bytes(&self) -> Vec<u8> {
        let mut writer = Writer::new();

        writer.write_u32_le(self.version);

        // Write inputs
        writer.write_var_int(self.inputs.len() as u64);
        for input in &self.inputs {
            // Write TXID (reversed)
            if let Ok(txid_bytes) = input.get_source_txid_bytes() {
                writer.write_bytes(&txid_bytes);
            } else if let Some(ref tx) = input.source_transaction {
                let hash = tx.hash();
                writer.write_bytes(&hash);
            } else {
                writer.write_bytes(&[0u8; 32]);
            }

            writer.write_u32_le(input.source_output_index);

            // Write unlocking script
            if let Some(ref script) = input.unlocking_script {
                let script_bytes = script.to_binary();
                writer.write_var_int(script_bytes.len() as u64);
                writer.write_bytes(&script_bytes);
            } else {
                writer.write_var_int(0);
            }

            writer.write_u32_le(input.sequence);
        }

        // Write outputs
        writer.write_var_int(self.outputs.len() as u64);
        for output in &self.outputs {
            writer.write_u64_le(output.satoshis.unwrap_or(0));

            let script = output.locking_script.to_binary();
            writer.write_var_int(script.len() as u64);
            writer.write_bytes(&script);
        }

        writer.write_u32_le(self.lock_time);

        writer.into_bytes()
    }

    /// Computes the transaction hash (double SHA-256).
    ///
    /// This is the internal byte order hash, not the display TXID.
    pub fn hash(&self) -> [u8; 32] {
        if let Some(hash) = *self.cached_hash.borrow() {
            return hash;
        }

        let bytes = self.to_binary();
        let hash = sha256d(&bytes);
        *self.cached_hash.borrow_mut() = Some(hash);
        hash
    }

    /// Returns the transaction ID (TXID).
    ///
    /// The TXID is the reversed hash displayed as a hex string.
    pub fn id(&self) -> String {
        let hash = self.hash();
        let mut reversed = hash;
        reversed.reverse();
        to_hex(&reversed)
    }

    /// Returns the hash as a hex string (not reversed).
    pub fn hash_hex(&self) -> String {
        to_hex(&self.hash())
    }

    /// Signs the transaction by hydrating unlocking scripts from templates.
    ///
    /// This method processes each input that has an `unlocking_script_template`
    /// and generates the unlocking script by calling the template's sign method.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Any output is missing a satoshi amount (except change outputs)
    /// - Change outputs haven't been computed (call `fee()` first)
    /// - Template signing fails
    pub async fn sign(&mut self) -> Result<()> {
        self.invalidate_caches();

        // Validate all outputs have amounts
        for output in &self.outputs {
            if output.satoshis.is_none() {
                if output.change {
                    return Err(crate::Error::TransactionError(
                        "There are still change outputs with uncomputed amounts. Use the fee() \
                         method to compute the change amounts and transaction fees prior to signing."
                            .to_string(),
                    ));
                } else {
                    return Err(crate::Error::TransactionError(
                        "One or more transaction outputs is missing an amount. Ensure all output \
                         amounts are provided before signing."
                            .to_string(),
                    ));
                }
            }
        }

        // Sign each input with a template
        let raw_tx = self.to_binary();

        for i in 0..self.inputs.len() {
            if self.inputs[i].unlocking_script_template.is_some() {
                // Get source data for signing context
                let source_satoshis = self.inputs[i].source_satoshis().ok_or_else(|| {
                    crate::Error::TransactionError(format!(
                        "Input {} is missing source satoshis for signing",
                        i
                    ))
                })?;

                // Clone the locking script to avoid borrow issues
                let locking_script = self.inputs[i]
                    .source_locking_script()
                    .ok_or_else(|| {
                        crate::Error::TransactionError(format!(
                            "Input {} is missing source locking script for signing",
                            i
                        ))
                    })?
                    .clone();

                // Take the template temporarily
                let template = self.inputs[i].unlocking_script_template.take().unwrap();

                let context =
                    SigningContext::new(&raw_tx, i, source_satoshis, locking_script.as_script());
                let unlocking = template.sign(&context)?;

                self.inputs[i].unlocking_script = Some(unlocking);
                self.inputs[i].unlocking_script_template = Some(template);
            }
        }

        // Invalidate caches after signing
        self.invalidate_caches();

        Ok(())
    }

    /// Computes fees and distributes change.
    ///
    /// # Arguments
    ///
    /// * `model` - Optional fee model. If None, uses a default 1 sat/byte rate.
    /// * `change_distribution` - How to distribute change among change outputs.
    ///
    /// # Errors
    ///
    /// Returns an error if source transactions are missing for inputs.
    pub async fn fee(
        &mut self,
        fee_sats: Option<u64>,
        change_distribution: ChangeDistribution,
    ) -> Result<()> {
        self.invalidate_caches();

        // Calculate fee based on transaction size if not provided
        let fee = match fee_sats {
            Some(f) => f,
            None => {
                // Estimate transaction size and use 1 sat/byte as default
                self.estimate_size() as u64
            }
        };

        // Calculate total input satoshis
        let mut total_in: u64 = 0;
        for input in &self.inputs {
            let sats = input.source_satoshis().ok_or_else(|| {
                crate::Error::TransactionError(
                    "Source transactions are required for all inputs during fee computation"
                        .to_string(),
                )
            })?;
            total_in += sats;
        }

        // Calculate total output satoshis (excluding change)
        let mut total_out: u64 = 0;
        for output in &self.outputs {
            if !output.change {
                total_out += output.satoshis.unwrap_or(0);
            }
        }

        // Calculate change
        let change = total_in.saturating_sub(fee).saturating_sub(total_out);

        if change == 0 {
            // Remove change outputs if no change
            self.outputs.retain(|o| !o.change);
            return Ok(());
        }

        // Distribute change
        self.distribute_change(change, change_distribution);

        Ok(())
    }

    /// Distributes change among change outputs.
    fn distribute_change(&mut self, change: u64, distribution: ChangeDistribution) {
        let change_outputs: Vec<usize> = self
            .outputs
            .iter()
            .enumerate()
            .filter(|(_, o)| o.change)
            .map(|(i, _)| i)
            .collect();

        if change_outputs.is_empty() {
            return;
        }

        match distribution {
            ChangeDistribution::Equal => {
                let per_output = change / change_outputs.len() as u64;
                let mut remaining = change % change_outputs.len() as u64;

                for &idx in &change_outputs {
                    let extra = if remaining > 0 {
                        remaining -= 1;
                        1
                    } else {
                        0
                    };
                    self.outputs[idx].satoshis = Some(per_output + extra);
                }
            }
            ChangeDistribution::Random => {
                // Use Benford's law distribution for privacy
                let mut distributed = 0u64;
                let count = change_outputs.len();

                for (i, &idx) in change_outputs.iter().enumerate() {
                    if i == count - 1 {
                        // Last output gets remaining
                        self.outputs[idx].satoshis = Some(change - distributed);
                    } else {
                        // Random portion using Benford-like distribution
                        let remaining = change - distributed;
                        let portion = self.benford_number(1, remaining);
                        self.outputs[idx].satoshis = Some(portion);
                        distributed += portion;
                    }
                }
            }
        }
    }

    /// Generates a random number following Benford's law distribution.
    fn benford_number(&self, min: u64, max: u64) -> u64 {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        let d: f64 = rng.gen_range(1..=9) as f64;
        let factor = (1.0 + 1.0 / d).log10() / 1_f64.log10();

        let range = (max - min) as f64;
        min + (range * factor) as u64
    }

    /// Returns the current fee based on inputs and outputs.
    ///
    /// # Errors
    ///
    /// Returns an error if source transactions are missing.
    pub fn get_fee(&self) -> Result<u64> {
        let mut total_in: u64 = 0;
        for input in &self.inputs {
            let sats = input.source_satoshis().ok_or_else(|| {
                crate::Error::TransactionError(
                    "Source transactions or sourceSatoshis are required for all inputs to calculate fee"
                        .to_string(),
                )
            })?;
            total_in += sats;
        }

        let mut total_out: u64 = 0;
        for output in &self.outputs {
            total_out += output.satoshis.unwrap_or(0);
        }

        Ok(total_in.saturating_sub(total_out))
    }

    /// Estimates the transaction size in bytes.
    pub fn estimate_size(&self) -> usize {
        let mut size = 8; // version (4) + locktime (4)

        // Input count varint
        size += varint_size(self.inputs.len() as u64);

        // Inputs
        for input in &self.inputs {
            size += 32; // TXID
            size += 4; // vout
            size += 4; // sequence

            // Unlocking script
            let script_len = input
                .unlocking_script
                .as_ref()
                .map(|s| s.to_binary().len())
                .or_else(|| {
                    input
                        .unlocking_script_template
                        .as_ref()
                        .map(|t| t.estimate_length())
                })
                .unwrap_or(0);

            size += varint_size(script_len as u64) + script_len;
        }

        // Output count varint
        size += varint_size(self.outputs.len() as u64);

        // Outputs
        for output in &self.outputs {
            size += 8; // satoshis
            let script_len = output.locking_script.to_binary().len();
            size += varint_size(script_len as u64) + script_len;
        }

        size
    }

    /// Returns the number of inputs.
    pub fn input_count(&self) -> usize {
        self.inputs.len()
    }

    /// Returns the number of outputs.
    pub fn output_count(&self) -> usize {
        self.outputs.len()
    }

    /// Returns true if this is a coinbase transaction.
    ///
    /// A coinbase transaction has exactly one input with a null TXID
    /// (all zeros) and output index of 0xFFFFFFFF.
    pub fn is_coinbase(&self) -> bool {
        if self.inputs.len() != 1 {
            return false;
        }
        let input = &self.inputs[0];
        if input.source_output_index != 0xFFFFFFFF {
            return false;
        }
        // Check if source TXID is all zeros
        if let Some(ref txid) = input.source_txid {
            txid.chars().all(|c| c == '0')
        } else {
            false
        }
    }

    /// Returns true if this transaction has any data-only outputs (OP_RETURN).
    ///
    /// Checks each output's locking script using `Script::is_data()`.
    pub fn has_data_outputs(&self) -> bool {
        self.outputs
            .iter()
            .any(|o| o.locking_script.as_script().is_data())
    }

    /// Returns the total satoshis of all inputs that have source transaction data.
    ///
    /// Returns an error if any input is missing its source transaction, since
    /// the satoshi value cannot be determined without it.
    pub fn total_input_satoshis(&self) -> Result<u64> {
        let mut total: u64 = 0;
        for (i, input) in self.inputs.iter().enumerate() {
            match input.source_satoshis() {
                Some(sats) => {
                    total = total.checked_add(sats).ok_or_else(|| {
                        crate::Error::TransactionError("Input satoshis overflow".to_string())
                    })?;
                }
                None => {
                    return Err(crate::Error::TransactionError(format!(
                        "Input {} is missing source transaction data",
                        i
                    )));
                }
            }
        }
        Ok(total)
    }

    /// Returns the total satoshis of all outputs.
    pub fn total_output_satoshis(&self) -> u64 {
        self.outputs.iter().filter_map(|o| o.satoshis).sum()
    }

    /// Verifies this transaction using SPV (Simplified Payment Verification).
    ///
    /// Performs a queue-based recursive verification of the transaction and its
    /// ancestry chain. For each transaction:
    ///
    /// 1. If the transaction has a merkle path, verifies it against the chain tracker
    /// 2. Optionally validates that the fee meets the fee model requirements
    /// 3. Validates all input scripts using the Spend interpreter
    /// 4. Enqueues unverified source transactions for recursive verification
    ///
    /// Matches the Go SDK's `spv.Verify()` and TS SDK's `Transaction.verify()`.
    ///
    /// # Arguments
    ///
    /// * `chain_tracker` - The chain tracker for verifying merkle roots
    /// * `fee_model` - Optional fee model for fee validation
    pub async fn verify(
        &self,
        chain_tracker: &dyn super::ChainTracker,
        fee_model: Option<&dyn super::FeeModel>,
    ) -> Result<bool> {
        use crate::primitives::bsv::sighash::{TxInput, TxOutput};
        use crate::script::{LockingScript, Spend, SpendParams, UnlockingScript};
        use std::collections::HashSet;

        let mut verified_txids: HashSet<String> = HashSet::new();
        let mut tx_queue: Vec<&Transaction> = vec![self];

        while let Some(tx) = tx_queue.pop() {
            let txid = tx.id();

            if verified_txids.contains(&txid) {
                continue;
            }

            // If the transaction has a merkle path, verify it
            if let Some(ref merkle_path) = tx.merkle_path {
                let root = merkle_path.compute_root(Some(&txid))?;
                let is_valid = chain_tracker
                    .is_valid_root_for_height(&root, merkle_path.block_height)
                    .await
                    .map_err(|e| {
                        crate::Error::TransactionError(format!("Chain tracker error: {}", e))
                    })?;

                if is_valid {
                    verified_txids.insert(txid);
                    continue;
                } else {
                    return Err(crate::Error::TransactionError(format!(
                        "Invalid merkle path for transaction {}",
                        txid
                    )));
                }
            }

            // Verify fee if fee model is provided
            if let Some(fm) = fee_model {
                let tx_fee = tx.get_fee()?;
                let required_fee = fm.compute_fee(tx)?;
                if tx_fee < required_fee {
                    return Err(crate::Error::TransactionError("Fee is too low".to_string()));
                }
            }

            // Verify each input's script
            for (vin, input) in tx.inputs.iter().enumerate() {
                let source_tx = input.source_transaction.as_ref().ok_or_else(|| {
                    crate::Error::TransactionError(format!(
                        "Input {} has no source transaction",
                        vin
                    ))
                })?;

                let source_output = source_tx
                    .outputs
                    .get(input.source_output_index as usize)
                    .ok_or_else(|| {
                        crate::Error::TransactionError(format!(
                            "Input {} source output index out of bounds",
                            vin
                        ))
                    })?;

                let source_satoshis = source_output.satoshis.unwrap_or(0);
                let locking_script = source_output.locking_script.clone();
                let unlocking_script = input.unlocking_script.as_ref().ok_or_else(|| {
                    crate::Error::TransactionError(format!(
                        "Input {} is missing unlocking script",
                        vin
                    ))
                })?;

                // Build other_inputs for sighash context
                let other_inputs: Vec<TxInput> = tx
                    .inputs
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| *i != vin)
                    .map(|(_, inp)| TxInput {
                        txid: inp.get_source_txid_bytes().unwrap_or([0u8; 32]),
                        output_index: inp.source_output_index,
                        script: inp
                            .unlocking_script
                            .as_ref()
                            .map(|s| s.to_binary())
                            .unwrap_or_default(),
                        sequence: inp.sequence,
                    })
                    .collect();

                let outputs: Vec<TxOutput> = tx
                    .outputs
                    .iter()
                    .map(|o| TxOutput {
                        satoshis: o.satoshis.unwrap_or(0),
                        script: o.locking_script.to_binary(),
                    })
                    .collect();

                let source_txid_bytes = input.get_source_txid_bytes()?;

                let mut spend = Spend::new(SpendParams {
                    source_txid: source_txid_bytes,
                    source_output_index: input.source_output_index,
                    source_satoshis,
                    locking_script: LockingScript::from_script(crate::script::Script::from_binary(
                        &locking_script.to_binary(),
                    )?),
                    transaction_version: tx.version as i32,
                    other_inputs,
                    outputs,
                    input_index: vin,
                    unlocking_script: UnlockingScript::from_script(
                        crate::script::Script::from_binary(&unlocking_script.to_binary())?,
                    ),
                    input_sequence: input.sequence,
                    lock_time: tx.lock_time,
                    memory_limit: None,
                });

                spend.validate().map_err(|e| {
                    crate::Error::TransactionError(format!(
                        "Script validation failed for input {}: {}",
                        vin, e.message
                    ))
                })?;

                // Enqueue unverified source transactions
                let source_txid = source_tx.id();
                if !verified_txids.contains(&source_txid) {
                    tx_queue.push(source_tx);
                }
            }

            verified_txids.insert(txid);
        }

        Ok(true)
    }
}

impl Default for Transaction {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialEq for Transaction {
    fn eq(&self, other: &Self) -> bool {
        self.to_binary() == other.to_binary()
    }
}

impl Eq for Transaction {}

/// Calculates the size of a varint.
fn varint_size(val: u64) -> usize {
    if val < 0xFD {
        1
    } else if val <= 0xFFFF {
        3
    } else if val <= 0xFFFFFFFF {
        5
    } else {
        9
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test transaction hex (simple P2PKH spend)
    const TEST_TX_HEX: &str = "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000";

    #[test]
    fn test_new_transaction() {
        let tx = Transaction::new();
        assert_eq!(tx.version, 1);
        assert_eq!(tx.lock_time, 0);
        assert!(tx.inputs.is_empty());
        assert!(tx.outputs.is_empty());
    }

    #[test]
    fn test_from_hex() {
        let tx = Transaction::from_hex(TEST_TX_HEX).unwrap();

        assert_eq!(tx.version, 1);
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 2);
        assert_eq!(tx.lock_time, 0);
    }

    #[test]
    fn test_to_hex_roundtrip() {
        let tx = Transaction::from_hex(TEST_TX_HEX).unwrap();
        let hex = tx.to_hex();
        assert_eq!(hex.to_lowercase(), TEST_TX_HEX.to_lowercase());
    }

    #[test]
    fn test_to_binary_roundtrip() {
        let original = Transaction::from_hex(TEST_TX_HEX).unwrap();
        let binary = original.to_binary();
        let parsed = Transaction::from_binary(&binary).unwrap();

        assert_eq!(original.to_hex(), parsed.to_hex());
    }

    #[test]
    fn test_hash() {
        let tx = Transaction::from_hex(TEST_TX_HEX).unwrap();
        let hash = tx.hash();

        // Verify it's a valid 32-byte hash
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_id() {
        let tx = Transaction::from_hex(TEST_TX_HEX).unwrap();
        let txid = tx.id();

        // TXID should be 64 hex characters
        assert_eq!(txid.len(), 64);

        // Hash and ID should be different (reversed)
        let hash_hex = tx.hash_hex();
        assert_ne!(txid, hash_hex);
    }

    #[test]
    fn test_add_input() {
        let mut tx = Transaction::new();

        // Should fail without TXID or source transaction
        let bad_input = TransactionInput::default();
        assert!(tx.add_input(bad_input).is_err());

        // Should succeed with TXID
        let good_input = TransactionInput::new("abc123".repeat(11), 0);
        assert!(tx.add_input(good_input).is_ok());
        assert_eq!(tx.inputs.len(), 1);
    }

    #[test]
    fn test_add_output() {
        let mut tx = Transaction::new();

        // Should fail without satoshis and not being change
        let bad_output = TransactionOutput {
            satoshis: None,
            locking_script: LockingScript::new(),
            change: false,
        };
        assert!(tx.add_output(bad_output).is_err());

        // Should succeed with satoshis
        let good_output = TransactionOutput::new(100_000, LockingScript::new());
        assert!(tx.add_output(good_output).is_ok());

        // Should succeed as change output
        let change_output = TransactionOutput::new_change(LockingScript::new());
        assert!(tx.add_output(change_output).is_ok());

        assert_eq!(tx.outputs.len(), 2);
    }

    #[test]
    fn test_parse_script_offsets() {
        let tx = Transaction::from_hex(TEST_TX_HEX).unwrap();
        let offsets = Transaction::parse_script_offsets(&tx.to_binary()).unwrap();

        assert_eq!(offsets.inputs.len(), 1);
        assert_eq!(offsets.outputs.len(), 2);

        // Verify the first input script offset
        assert_eq!(offsets.inputs[0].index, 0);
        assert!(offsets.inputs[0].length > 0);
    }

    #[test]
    fn test_estimate_size() {
        let tx = Transaction::from_hex(TEST_TX_HEX).unwrap();
        let estimated = tx.estimate_size();
        let actual = tx.to_binary().len();

        // Estimation should be close to actual
        assert!((estimated as i64 - actual as i64).abs() < 10);
    }

    #[test]
    fn test_equality() {
        let tx1 = Transaction::from_hex(TEST_TX_HEX).unwrap();
        let tx2 = Transaction::from_hex(TEST_TX_HEX).unwrap();

        assert_eq!(tx1, tx2);
    }

    #[test]
    fn test_varint_size() {
        assert_eq!(varint_size(0), 1);
        assert_eq!(varint_size(0xFC), 1);
        assert_eq!(varint_size(0xFD), 3);
        assert_eq!(varint_size(0xFFFF), 3);
        assert_eq!(varint_size(0x10000), 5);
    }

    #[test]
    fn test_ef_format_roundtrip() {
        // Create a transaction with source transaction data
        let mut tx = Transaction::new();

        // Create a source transaction
        let source_tx = Transaction::from_hex(TEST_TX_HEX).unwrap();

        // Create input with source transaction
        let mut input = TransactionInput::with_source_transaction(source_tx, 0);
        input.unlocking_script = Some(UnlockingScript::from_hex("00").unwrap());

        tx.inputs.push(input);

        // Add an output
        let output = TransactionOutput::new(
            50_000,
            LockingScript::from_hex("76a914000000000000000000000000000000000000000088ac").unwrap(),
        );
        tx.outputs.push(output);

        // Serialize to EF
        let ef_bytes = tx.to_ef().unwrap();

        // Parse from EF
        let parsed = Transaction::from_ef(&ef_bytes).unwrap();

        // Verify the parsed transaction
        assert_eq!(parsed.version, tx.version);
        assert_eq!(parsed.inputs.len(), tx.inputs.len());
        assert_eq!(parsed.outputs.len(), tx.outputs.len());
        assert_eq!(parsed.lock_time, tx.lock_time);

        // Verify input has source satoshis
        assert!(parsed.inputs[0].source_satoshis().is_some());
    }

    #[test]
    fn test_txid_is_reversed_hash() {
        let tx = Transaction::from_hex(TEST_TX_HEX).unwrap();

        // Get hash and TXID
        let hash = tx.hash();
        let txid = tx.id();

        // TXID should be the reversed hash as hex
        let mut reversed_hash = hash;
        reversed_hash.reverse();
        let expected_txid = to_hex(&reversed_hash);

        assert_eq!(txid, expected_txid);
    }

    #[test]
    fn test_metadata() {
        let mut tx = Transaction::new();
        tx.update_metadata("key", serde_json::json!("value"));

        assert_eq!(tx.metadata.get("key"), Some(&serde_json::json!("value")));
    }

    #[test]
    fn test_is_coinbase() {
        // Create a coinbase transaction
        let mut coinbase_tx = Transaction::new();
        coinbase_tx.inputs.push(TransactionInput {
            source_transaction: None,
            source_txid: Some(
                "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            ),
            source_output_index: 0xFFFFFFFF,
            unlocking_script: Some(UnlockingScript::from_hex("03a75e0b").unwrap()),
            unlocking_script_template: None,
            sequence: 0xFFFFFFFF,
        });
        coinbase_tx.outputs.push(TransactionOutput::new(
            5000000000,
            LockingScript::from_hex("76a914000000000000000000000000000000000000000088ac").unwrap(),
        ));
        assert!(coinbase_tx.is_coinbase());

        // Regular transaction is not coinbase
        let regular_tx = Transaction::from_hex(TEST_TX_HEX).unwrap();
        assert!(!regular_tx.is_coinbase());

        // Transaction with 2 inputs is not coinbase
        let mut two_input_tx = Transaction::new();
        two_input_tx.inputs.push(TransactionInput {
            source_transaction: None,
            source_txid: Some(
                "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            ),
            source_output_index: 0xFFFFFFFF,
            unlocking_script: None,
            unlocking_script_template: None,
            sequence: 0xFFFFFFFF,
        });
        two_input_tx.inputs.push(TransactionInput {
            source_transaction: None,
            source_txid: Some("abc123".repeat(11)),
            source_output_index: 0,
            unlocking_script: None,
            unlocking_script_template: None,
            sequence: 0xFFFFFFFF,
        });
        assert!(!two_input_tx.is_coinbase());
    }

    #[test]
    fn test_has_data_outputs() {
        // Transaction with no data outputs
        let mut tx = Transaction::new();
        tx.outputs.push(TransactionOutput::new(
            100_000,
            LockingScript::from_hex("76a914000000000000000000000000000000000000000088ac").unwrap(),
        ));
        assert!(!tx.has_data_outputs());

        // Transaction with an OP_RETURN output
        let mut tx_data = Transaction::new();
        tx_data.outputs.push(TransactionOutput::new(
            0,
            LockingScript::from_hex("6a0568656c6c6f").unwrap(), // OP_RETURN "hello"
        ));
        assert!(tx_data.has_data_outputs());

        // Transaction with both data and non-data outputs
        let mut tx_mixed = Transaction::new();
        tx_mixed.outputs.push(TransactionOutput::new(
            100_000,
            LockingScript::from_hex("76a914000000000000000000000000000000000000000088ac").unwrap(),
        ));
        tx_mixed.outputs.push(TransactionOutput::new(
            0,
            LockingScript::from_asm("OP_FALSE OP_RETURN").unwrap(),
        ));
        assert!(tx_mixed.has_data_outputs());

        // Empty outputs
        let tx_empty = Transaction::new();
        assert!(!tx_empty.has_data_outputs());
    }

    #[test]
    fn test_add_op_return_output() {
        let mut tx = Transaction::new();
        tx.add_op_return_output(b"hello world").unwrap();

        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.outputs[0].satoshis, Some(0));
        assert!(tx.outputs[0].locking_script.as_script().is_data());
        assert!(tx.outputs[0]
            .locking_script
            .as_script()
            .is_safe_data_carrier());

        // Verify the script structure: OP_FALSE OP_RETURN <data>
        let asm = tx.outputs[0].locking_script.to_asm();
        assert!(asm.starts_with("0 OP_RETURN"));
    }

    #[test]
    fn test_add_op_return_output_empty_data() {
        let mut tx = Transaction::new();
        tx.add_op_return_output(b"").unwrap();

        assert_eq!(tx.outputs.len(), 1);
        assert!(tx.outputs[0].locking_script.as_script().is_data());
    }

    #[test]
    fn test_add_op_return_parts_output() {
        let mut tx = Transaction::new();
        tx.add_op_return_parts_output(&[b"part1", b"part2", b"part3"])
            .unwrap();

        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.outputs[0].satoshis, Some(0));
        assert!(tx.outputs[0].locking_script.as_script().is_data());
        assert!(tx.outputs[0]
            .locking_script
            .as_script()
            .is_safe_data_carrier());

        // Verify all parts are present in the script
        let asm = tx.outputs[0].locking_script.to_asm();
        assert!(asm.starts_with("0 OP_RETURN"));
    }

    #[test]
    fn test_add_op_return_parts_single_part() {
        let mut tx = Transaction::new();
        tx.add_op_return_parts_output(&[b"single"]).unwrap();

        // Single part should produce same result as add_op_return_output
        let mut tx2 = Transaction::new();
        tx2.add_op_return_output(b"single").unwrap();

        assert_eq!(
            tx.outputs[0].locking_script.to_hex(),
            tx2.outputs[0].locking_script.to_hex()
        );
    }

    #[test]
    fn test_add_op_return_triggers_has_data_outputs() {
        let mut tx = Transaction::new();
        assert!(!tx.has_data_outputs());

        tx.add_op_return_output(b"test").unwrap();
        assert!(tx.has_data_outputs());
    }

    #[test]
    fn test_add_hash_puzzle_output() {
        let mut tx = Transaction::new();
        // 20-byte pubkey hash (hex)
        let pubkey_hash = "89abcdefabbaabbaabbaabbaabbaabbaabbaabba";
        tx.add_hash_puzzle_output("my secret", pubkey_hash, 50_000)
            .unwrap();

        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.outputs[0].satoshis, Some(50_000));

        // Verify the script structure:
        // OP_HASH160 <hash> OP_EQUALVERIFY OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG
        let asm = tx.outputs[0].locking_script.to_asm();
        assert!(asm.starts_with("OP_HASH160"));
        assert!(asm.contains("OP_EQUALVERIFY OP_DUP OP_HASH160"));
        assert!(asm.ends_with("OP_EQUALVERIFY OP_CHECKSIG"));
    }

    #[test]
    fn test_add_hash_puzzle_output_invalid_pubkey_hash() {
        let mut tx = Transaction::new();
        // Wrong length (not 20 bytes)
        let result = tx.add_hash_puzzle_output("secret", "abcd", 1000);
        assert!(result.is_err());
    }

    #[test]
    fn test_add_hash_puzzle_output_invalid_hex() {
        let mut tx = Transaction::new();
        let result = tx.add_hash_puzzle_output("secret", "not_hex!", 1000);
        assert!(result.is_err());
    }

    #[test]
    fn test_total_output_satoshis() {
        let mut tx = Transaction::new();
        assert_eq!(tx.total_output_satoshis(), 0);

        tx.outputs.push(TransactionOutput::new(
            100_000,
            LockingScript::from_hex("76a914000000000000000000000000000000000000000088ac").unwrap(),
        ));
        assert_eq!(tx.total_output_satoshis(), 100_000);

        tx.outputs.push(TransactionOutput::new(
            50_000,
            LockingScript::from_hex("76a914000000000000000000000000000000000000000088ac").unwrap(),
        ));
        assert_eq!(tx.total_output_satoshis(), 150_000);
    }

    #[test]
    fn test_total_output_satoshis_with_op_return() {
        let mut tx = Transaction::new();
        tx.add_op_return_output(b"data").unwrap();
        tx.outputs.push(TransactionOutput::new(
            100_000,
            LockingScript::from_hex("76a914000000000000000000000000000000000000000088ac").unwrap(),
        ));
        // OP_RETURN has 0 satoshis
        assert_eq!(tx.total_output_satoshis(), 100_000);
    }

    #[test]
    fn test_total_input_satoshis() {
        // Parse a known transaction that has source data
        let source_tx = Transaction::from_hex(TEST_TX_HEX).unwrap();
        let mut tx = Transaction::new();
        tx.add_input(TransactionInput::with_source_transaction(
            source_tx.clone(),
            0,
        ))
        .unwrap();

        let total = tx.total_input_satoshis().unwrap();
        assert_eq!(total, source_tx.outputs[0].satoshis.unwrap());
    }

    #[test]
    fn test_total_input_satoshis_missing_source() {
        let mut tx = Transaction::new();
        tx.add_input(TransactionInput::new(
            "0000000000000000000000000000000000000000000000000000000000000001".to_string(),
            0,
        ))
        .unwrap();

        // Should error because source transaction is not available
        assert!(tx.total_input_satoshis().is_err());
    }

    #[test]
    fn test_total_input_satoshis_empty() {
        let tx = Transaction::new();
        assert_eq!(tx.total_input_satoshis().unwrap(), 0);
    }

    #[test]
    fn test_add_op_return_large_data() {
        let mut tx = Transaction::new();
        let large_data = vec![0xAB; 10_000];
        tx.add_op_return_output(&large_data).unwrap();

        assert_eq!(tx.outputs.len(), 1);
        assert!(tx.outputs[0].locking_script.as_script().is_data());
    }

    #[test]
    fn test_add_op_return_parts_empty() {
        let mut tx = Transaction::new();
        let empty_parts: &[&[u8]] = &[];
        tx.add_op_return_parts_output(empty_parts).unwrap();

        assert_eq!(tx.outputs.len(), 1);
        assert!(tx.outputs[0].locking_script.as_script().is_data());
        // Should just be OP_FALSE OP_RETURN with no data
        let asm = tx.outputs[0].locking_script.to_asm();
        assert_eq!(asm, "0 OP_RETURN");
    }

    #[test]
    fn test_hash_puzzle_secret_deterministic() {
        // Same secret should produce the same hash puzzle
        let mut tx1 = Transaction::new();
        let mut tx2 = Transaction::new();
        let pubkey_hash = "89abcdefabbaabbaabbaabbaabbaabbaabbaabba";
        tx1.add_hash_puzzle_output("same_secret", pubkey_hash, 1000)
            .unwrap();
        tx2.add_hash_puzzle_output("same_secret", pubkey_hash, 1000)
            .unwrap();

        assert_eq!(
            tx1.outputs[0].locking_script.to_hex(),
            tx2.outputs[0].locking_script.to_hex()
        );
    }

    #[test]
    fn test_hash_puzzle_different_secrets() {
        let mut tx1 = Transaction::new();
        let mut tx2 = Transaction::new();
        let pubkey_hash = "89abcdefabbaabbaabbaabbaabbaabbaabbaabba";
        tx1.add_hash_puzzle_output("secret1", pubkey_hash, 1000)
            .unwrap();
        tx2.add_hash_puzzle_output("secret2", pubkey_hash, 1000)
            .unwrap();

        assert_ne!(
            tx1.outputs[0].locking_script.to_hex(),
            tx2.outputs[0].locking_script.to_hex()
        );
    }

    // =========================================================
    // Tests for add_input_from_tx, add_input_from, add_inputs_from_utxos
    // =========================================================

    /// Helper: create a dummy ScriptTemplateUnlock for testing.
    fn dummy_template() -> crate::script::ScriptTemplateUnlock {
        crate::script::ScriptTemplateUnlock::new(
            |_ctx| Ok(UnlockingScript::from_hex("00").unwrap()),
            || 1,
        )
    }

    #[test]
    fn test_add_input_from_tx() {
        let source_tx = Transaction::from_hex(TEST_TX_HEX).unwrap();
        let expected_txid = source_tx.id();
        let expected_satoshis = source_tx.outputs[0].satoshis.unwrap();

        let mut tx = Transaction::new();
        tx.add_input_from_tx(source_tx, 0, dummy_template())
            .unwrap();

        assert_eq!(tx.inputs.len(), 1);
        assert!(tx.inputs[0].has_source_transaction());
        assert_eq!(tx.inputs[0].get_source_txid().unwrap(), expected_txid);
        assert_eq!(tx.inputs[0].source_output_index, 0);
        assert_eq!(tx.inputs[0].source_satoshis().unwrap(), expected_satoshis);
    }

    #[test]
    fn test_add_input_from() {
        let prev_txid = "a477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458";
        let locking_script =
            LockingScript::from_hex("76a914000000000000000000000000000000000000000088ac").unwrap();
        let satoshis = 50_000u64;

        let mut tx = Transaction::new();
        tx.add_input_from(prev_txid, 0, &locking_script, satoshis, dummy_template())
            .unwrap();

        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.inputs[0].get_source_txid().unwrap(), prev_txid);
        assert_eq!(tx.inputs[0].source_output_index, 0);
        assert_eq!(tx.inputs[0].source_satoshis().unwrap(), satoshis);
        assert_eq!(
            tx.inputs[0].source_locking_script().unwrap().to_hex(),
            locking_script.to_hex()
        );
    }

    #[test]
    fn test_add_input_from_with_nonzero_vout() {
        let prev_txid = "a477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458";
        let locking_script =
            LockingScript::from_hex("76a914000000000000000000000000000000000000000088ac").unwrap();
        let satoshis = 75_000u64;

        let mut tx = Transaction::new();
        tx.add_input_from(prev_txid, 3, &locking_script, satoshis, dummy_template())
            .unwrap();

        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.inputs[0].source_output_index, 3);
        // The minimal source transaction should have padding outputs + the real one at index 3
        let source = tx.inputs[0].source_transaction.as_ref().unwrap();
        assert_eq!(source.outputs.len(), 4);
        assert_eq!(source.outputs[3].satoshis.unwrap(), satoshis);
        assert_eq!(
            source.outputs[3].locking_script.to_hex(),
            locking_script.to_hex()
        );
    }

    #[test]
    fn test_add_input_from_invalid_txid_empty() {
        let locking_script =
            LockingScript::from_hex("76a914000000000000000000000000000000000000000088ac").unwrap();

        let mut tx = Transaction::new();
        let result = tx.add_input_from("", 0, &locking_script, 1000, dummy_template());
        assert!(result.is_err());
    }

    #[test]
    fn test_add_input_from_invalid_txid_bad_hex() {
        let locking_script =
            LockingScript::from_hex("76a914000000000000000000000000000000000000000088ac").unwrap();

        let mut tx = Transaction::new();
        let result =
            tx.add_input_from("not_valid_hex!", 0, &locking_script, 1000, dummy_template());
        assert!(result.is_err());
    }

    #[test]
    fn test_add_input_from_invalid_txid_wrong_length() {
        let locking_script =
            LockingScript::from_hex("76a914000000000000000000000000000000000000000088ac").unwrap();

        let mut tx = Transaction::new();
        // Only 16 bytes (32 hex chars) instead of 32 bytes (64 hex chars)
        let result = tx.add_input_from(
            "a477af6b2667c29670467e4e0728b685",
            0,
            &locking_script,
            1000,
            dummy_template(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_add_inputs_from_utxos() {
        use crate::transaction::input::Utxo;

        let locking_script =
            LockingScript::from_hex("76a914000000000000000000000000000000000000000088ac").unwrap();

        let utxos = vec![
            Utxo {
                txid: "a477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458"
                    .to_string(),
                vout: 0,
                satoshis: 100_000,
                locking_script: locking_script.clone(),
            },
            Utxo {
                txid: "b577af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58459"
                    .to_string(),
                vout: 1,
                satoshis: 200_000,
                locking_script: locking_script.clone(),
            },
            Utxo {
                txid: "c677af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58460"
                    .to_string(),
                vout: 2,
                satoshis: 300_000,
                locking_script: locking_script.clone(),
            },
        ];

        let mut tx = Transaction::new();
        tx.add_inputs_from_utxos(&utxos).unwrap();

        assert_eq!(tx.inputs.len(), 3);

        // Verify each input matches its UTXO
        for (i, utxo) in utxos.iter().enumerate() {
            assert_eq!(tx.inputs[i].get_source_txid().unwrap(), utxo.txid);
            assert_eq!(tx.inputs[i].source_output_index, utxo.vout);
            assert_eq!(tx.inputs[i].source_satoshis().unwrap(), utxo.satoshis);
            assert_eq!(
                tx.inputs[i].source_locking_script().unwrap().to_hex(),
                utxo.locking_script.to_hex()
            );
        }

        // Template should NOT be set (add_inputs_from_utxos does not set it)
        for input in &tx.inputs {
            assert!(input.unlocking_script_template.is_none());
        }
    }

    #[test]
    fn test_add_inputs_from_utxos_empty() {
        let utxos: Vec<crate::transaction::input::Utxo> = vec![];
        let mut tx = Transaction::new();
        tx.add_inputs_from_utxos(&utxos).unwrap();

        assert_eq!(tx.inputs.len(), 0);
    }

    #[test]
    fn test_add_input_from_tx_preserves_template() {
        use crate::script::{Script, SigningContext};

        let source_tx = Transaction::from_hex(TEST_TX_HEX).unwrap();

        let mut tx = Transaction::new();
        tx.add_input_from_tx(source_tx, 0, dummy_template())
            .unwrap();

        // The template should be set on the input
        assert!(tx.inputs[0].unlocking_script_template.is_some());

        // Verify the template can produce an unlocking script
        let template = tx.inputs[0].unlocking_script_template.as_ref().unwrap();
        let dummy_tx = Transaction::new();
        let raw_tx = dummy_tx.to_binary();
        let locking_script = Script::new();
        let ctx = SigningContext::new(&raw_tx, 0, 0, &locking_script);
        let result = template.sign(&ctx);
        assert!(result.is_ok());
    }
}
