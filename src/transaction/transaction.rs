//! Transaction.
//!
//! Represents a complete Bitcoin transaction with inputs, outputs, and metadata.
//! Provides parsing, serialization, signing, and fee computation functionality.

use std::collections::{HashMap, HashSet};

use serde_json::Value;

use super::amount::{read_amount, unnamed_source_amounts, written_amount, AmountRule};
use super::beef::Beef;
use super::beef_tx::{BEEF_V1, BEEF_V2};
use super::input::TransactionInput;
use super::merkle_path::MerklePath;
use super::output::TransactionOutput;
use super::Txid;
use crate::primitives::{bounded_capacity, from_hex, sha256d, to_hex, var_int_len, Reader, Writer};
use crate::script::{LockingScript, SigningContext, UnlockingScript};
use crate::Result;

mod fields;
pub(in crate::transaction) use fields::{
    outpoint_txid, outpoint_txid_bytes, outpoint_txid_name, OutpointTxid,
};
pub use fields::{TransactionParts, TransactionPartsMut};

/// Number of placeholder outputs to fabricate for an EF source transaction whose
/// spent output index is `source_output_index`, or `None` if that many outputs
/// would exceed the fabrication budget (an implausibly large / adversarial vout
/// that no real transaction could have).
///
/// EF (BRC-30) carries only the ONE spent output per input, so `from_ef` builds a
/// stand-in source tx with the real output at position `source_output_index`.
/// That index is an attacker-controlled `u32` (up to `u32::MAX`); fabricating
/// billions of default outputs would OOM-abort the parser.
///
/// The count is computed and compared in **`u64`** so the `+ 1` cannot overflow
/// on any target. On `wasm32` `usize` is 32-bit, so the earlier
/// `source_output_index as usize + 1` wrapped `u32::MAX` to `0` — silently
/// passing the budget check and then indexing a zero-length vec (index-OOB panic
/// ⇒ `panic = abort`). Doing the arithmetic in `u64` and only narrowing *after*
/// the guard (where the value is known ≤ the small budget) closes that.
fn ef_source_placeholder_len(source_output_index: u32) -> Option<usize> {
    const MAX_FABRICATED_BYTES: usize = 16 * 1024 * 1024;
    let max_outputs = MAX_FABRICATED_BYTES / core::mem::size_of::<TransactionOutput>().max(1);
    let needed = source_output_index as u64 + 1; // u64: cannot overflow on 32-bit
    if needed > max_outputs as u64 {
        return None;
    }
    // `needed <= max_outputs` (a small, platform-independent budget), so the
    // narrowing to `usize` is exact on every target.
    Some(needed as usize)
}

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
/// tx.add_input(TransactionInput::new("abc123...".parse().unwrap(), 0))?;
/// tx.add_output(TransactionOutput::new(100_000, locking_script))?;
/// tx.fee(None, ChangeDistribution::Equal).await?;
/// tx.sign().await?;
/// ```
///
/// The four serialized fields are private (#843): read them through
/// [`version`](Self::version), [`inputs`](Self::inputs),
/// [`outputs`](Self::outputs) and [`lock_time`](Self::lock_time), write them
/// through [`set_version`](Self::set_version), [`set_lock_time`](Self::set_lock_time),
/// [`inputs_mut`](Self::inputs_mut), [`outputs_mut`](Self::outputs_mut) or
/// [`parts_mut`](Self::parts_mut), each of which clears the caches first, so
/// [`id`](Self::id), [`to_binary`](Self::to_binary) and [`to_hex`](Self::to_hex)
/// are always those of the current fields.
///
/// `Clone` and `Drop` walk the linked `source_transaction` ancestry with an
/// explicit stack, not by recursion (0.3.35, bsv-stack-lean #57): a chain of
/// unproven links a stranger's BEEF can carry is as deep as the BEEF is long,
/// and the derived glue spent several stack frames per link. `Debug` prints
/// each input's linked source as its txid, not its ancestry (0.3.35, P0-5c).
pub struct Transaction {
    // The four serialized fields and their three caches, in a struct whose
    // fields only the `sealed` module of `fields.rs` sees (#843, #869's
    // sixth fold): read through `version()`, `inputs()`, `outputs()`,
    // `lock_time()`, written through the doors there, every one of them
    // through `Fields::write`, which empties the caches before it lends.
    fields: fields::Fields,

    /// Metadata for attaching additional data to the transaction.
    ///
    /// This is not included in the serialized transaction.
    pub metadata: HashMap<String, Value>,

    /// Merkle path (BRC-74 BUMP) proving this transaction is in a block.
    ///
    /// When set, indicates this transaction has been mined and has SPV proof.
    /// Used by `to_beef()` to determine when to stop walking the ancestry chain.
    pub merkle_path: Option<MerklePath>,
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

/// The reference's words for bytes after a transaction
/// (`ts-stack@edf6e03` `Transaction.ts:462`, `:535`; #840).
const TRAILING_DATA: &str = "Serialized transaction contains trailing data";

/// The reference's words for bytes after an EF transaction (`Transaction.ts:419`).
const EF_TRAILING_DATA: &str = "Serialized EF transaction contains trailing data";

/// Refuses a reader that has not reached its end, in `words`.
fn refuse_trailing(reader: &Reader, words: &str) -> Result<()> {
    if reader.is_empty() {
        Ok(())
    } else {
        Err(crate::Error::TransactionError(words.to_string()))
    }
}

impl Transaction {
    /// Creates a new empty transaction with default version 1.
    pub fn new() -> Self {
        Self::with_params(1, Vec::new(), Vec::new(), 0)
    }

    /// Creates a new transaction with the specified parameters.
    pub fn with_params(
        version: u32,
        inputs: Vec<TransactionInput>,
        outputs: Vec<TransactionOutput>,
        lock_time: u32,
    ) -> Self {
        Self::from_parts(TransactionParts {
            version,
            inputs,
            outputs,
            lock_time,
            metadata: HashMap::new(),
            merkle_path: None,
        })
    }

    /// Parses a transaction from binary data: the bytes are exactly one
    /// transaction.
    ///
    /// A byte after the lock time is refused as
    /// `TransactionError("Serialized transaction contains trailing data")`,
    /// the reference's words (`ts-stack@edf6e03` `Transaction.ts:532-535`);
    /// until #840 such bytes were kept as the cached serialization and hashed
    /// into the txid. To read one transaction from the front of a longer
    /// buffer, use [`from_reader`](Self::from_reader). An output amount of
    /// 2^53 satoshis or more is refused as `TransactionError("Number can only
    /// safely store up to 53 bits")`, the reference's words (#844).
    ///
    /// ```
    /// use bsv_rs::transaction::Transaction;
    /// let tx = Transaction::new();
    /// let mut bytes = tx.to_binary();
    /// assert_eq!(Transaction::from_binary(&bytes)?.id(), tx.id());
    /// bytes.push(0);
    /// assert!(Transaction::from_binary(&bytes).is_err());
    /// # Ok::<(), bsv_rs::Error>(())
    /// ```
    pub fn from_binary(bin: &[u8]) -> Result<Self> {
        Self::read_exact(bin.to_vec(), None)
    }

    /// One transaction read from `bin`, a byte after it refused in `words`.
    fn from_whole(bin: &[u8], words: &str) -> Result<Self> {
        let mut reader = Reader::new(bin);
        let tx = Self::from_reader(&mut reader)?;
        refuse_trailing(&reader, words)?;
        Ok(tx)
    }

    /// The one-input door's reader (#874): exactly one transaction, as
    /// [`from_binary`](Self::from_binary) reads it, save that an output
    /// amount is any 64-bit value, as the node's consensus library reads it.
    /// Beside the transaction, `from_binary`'s refusal when the only one it
    /// makes is an amount of 2^53 or more; any other refusal is
    /// `from_binary`'s own error (its amount refusal when such an amount
    /// precedes it, as `from_binary` stops there).
    pub(crate) fn from_binary_as_node(bin: &[u8]) -> Result<(Self, Option<crate::Error>)> {
        let mut amounts = AmountRule::node();
        let mut reader = Reader::new(bin);
        let read = Self::read_one(&mut reader, &mut amounts)
            .and_then(|tx| refuse_trailing(&reader, TRAILING_DATA).map(|()| tx));
        let reference = amounts.reference_refusal();
        match read {
            Ok(tx) => Ok((tx, reference)),
            Err(error) => Err(reference.unwrap_or(error)),
        }
    }

    /// Parses a transaction from a hex string: the text is exactly one
    /// transaction, refused as [`from_binary`](Self::from_binary) refuses
    /// bytes after it (#840).
    pub fn from_hex(hex: &str) -> Result<Self> {
        Self::read_exact(from_hex(hex)?, Some(hex.to_lowercase()))
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
    /// The parsed transaction with source transaction data populated. A
    /// source or output amount of 2^53 satoshis or more is refused in the
    /// reference's words, as [`from_binary`](Self::from_binary) refuses one (#844).
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
        // Bound the pre-allocation by what the buffer can actually hold: a bogus
        // count varint must never trigger a capacity-overflow / OOM abort before
        // any input is read. Each EF input is >= 50 bytes (txid 32 + vout 4 +
        // script len 1 + sequence 4 + source satoshis 8 + source script len 1).
        let mut inputs = Vec::with_capacity(bounded_capacity(input_count, reader.remaining(), 50));

        for _ in 0..input_count {
            // Read TXID (reversed in EF format)
            let mut txid_wire = [0u8; 32];
            txid_wire.copy_from_slice(reader.read_bytes(32)?);
            let source_txid = Txid::from_wire_bytes(txid_wire);

            let source_output_index = reader.read_u32_le()?;

            // Read unlocking script
            let script_len = reader.read_var_int_num()?;
            let script_bytes = reader.read_bytes(script_len)?;
            let unlocking_script = UnlockingScript::from_binary(script_bytes)?;

            let sequence = reader.read_u32_le()?;

            // Read source satoshis
            let source_satoshis = read_amount(&mut reader)?;

            // Read source locking script
            let locking_script_len = reader.read_var_int_num()?;
            let locking_script_bytes = reader.read_bytes(locking_script_len)?;
            let locking_script = LockingScript::from_binary(locking_script_bytes)?;

            // Create a minimal source transaction with just the output we need.
            // The real output must live at `source_output_index`, so the
            // placeholder vec has to be that long — but `source_output_index` is
            // an attacker-controlled u32 (up to ~4.29e9). Fabricating billions of
            // default outputs would OOM-abort the parser, so reject indices whose
            // placeholder allocation would exceed a sane memory budget. The count
            // is computed in u64 (see `ef_source_placeholder_len`) so the `+ 1`
            // cannot overflow on 32-bit targets (wasm32).
            let needed = ef_source_placeholder_len(source_output_index).ok_or_else(|| {
                crate::Error::TransactionError(format!(
                    "EF source output index {} is implausibly large",
                    source_output_index
                ))
            })?;
            let mut outputs = vec![TransactionOutput::default(); needed];
            outputs[source_output_index as usize] = TransactionOutput {
                satoshis: Some(source_satoshis),
                locking_script,
                change: false,
            };
            let source_tx = Transaction::with_params(1, Vec::new(), outputs, 0);

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
        // Each output is >= 9 bytes (satoshis 8 + script len 1); bound the
        // pre-allocation so a bogus count cannot OOM-abort before any read.
        let mut outputs = Vec::with_capacity(bounded_capacity(output_count, reader.remaining(), 9));

        for _ in 0..output_count {
            let satoshis = read_amount(&mut reader)?;
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
        // The reference's words for a byte after the EF frame
        // (`Transaction.ts:419`, #840).
        refuse_trailing(&reader, EF_TRAILING_DATA)?;

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

    /// Reads one transaction from the front of a reader and leaves the
    /// reader after its lock time, the bytes after it unread: the
    /// reference's `fromReader` (`ts-stack@edf6e03` `Transaction.ts:466-468`).
    /// The door for a transaction at the front of a longer buffer, where
    /// [`from_binary`](Self::from_binary) refuses the bytes after it (#840).
    /// The transaction holds no copy of the reader's bytes: its serialization
    /// and txid are computed from its fields. An output amount of 2^53
    /// satoshis or more is refused in the reference's words, `Number can only
    /// safely store up to 53 bits` (`Transaction.ts:497`, #844), as every
    /// reader of a transaction refuses it.
    ///
    /// ```
    /// use bsv_rs::{primitives::Reader, transaction::Transaction};
    /// let tx = Transaction::new();
    /// let mut bytes = tx.to_binary();
    /// bytes.extend_from_slice(&[1, 2, 3, 4]);
    /// let mut reader = Reader::new(&bytes);
    /// let read = Transaction::from_reader(&mut reader)?;
    /// assert_eq!(read.id(), tx.id());
    /// assert_eq!(read.to_binary(), tx.to_binary());
    /// assert_eq!(reader.remaining(), 4);
    /// # Ok::<(), bsv_rs::Error>(())
    /// ```
    pub fn from_reader(reader: &mut Reader) -> Result<Self> {
        Self::read_one(reader, &mut AmountRule::Reference)
    }

    /// The one reader of a transaction (#874): `from_reader` under the
    /// reference's amount rule, the door's reader under the node's.
    pub(crate) fn read_one(reader: &mut Reader, amounts: &mut AmountRule) -> Result<Self> {
        let version = reader.read_u32_le()?;

        let input_count = reader.read_var_int_num()?;
        // Each input is >= 41 bytes (txid 32 + vout 4 + script len 1 +
        // sequence 4); bound the pre-allocation so a bogus count varint cannot
        // OOM-abort before any input is read.
        let mut inputs = Vec::with_capacity(bounded_capacity(input_count, reader.remaining(), 41));

        for _ in 0..input_count {
            // Read TXID (stored reversed)
            let mut txid_wire = [0u8; 32];
            txid_wire.copy_from_slice(reader.read_bytes(32)?);
            let source_txid = Txid::from_wire_bytes(txid_wire);

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
        // Each output is >= 9 bytes (satoshis 8 + script len 1); bound the
        // pre-allocation so a bogus count cannot OOM-abort before any read.
        let mut outputs = Vec::with_capacity(bounded_capacity(output_count, reader.remaining(), 9));

        for _ in 0..output_count {
            let satoshis = amounts.read(reader)?;
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
    /// The script offsets for inputs and outputs. The bytes are exactly one
    /// transaction: a missing lock time or a byte after it is refused, as the
    /// reference's `parseScriptOffsets` refuses them (#840).
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
            // Skip satoshis, unread as the reference's `br.read(8)` skips
            // them (`Transaction.ts:456`): no amount refused here (#844).
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

        // The lock time, then nothing: the reference's `parseScriptOffsets`
        // (`Transaction.ts:460-462`, #840).
        reader.read_u32_le()?;
        refuse_trailing(&reader, TRAILING_DATA)?;

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

        // Route through `find_atomic_transaction` so the returned transaction
        // carries its merkle path and linked input sources, matching the
        // TypeScript `Transaction.fromBEEF` (which resolves the target txid and
        // then calls `Beef.findAtomicTransaction` -> `addInputProof`). Cloning
        // the parsed transaction alone would drop the BUMP, because bumps live
        // in `Beef::bumps` and are referenced by `BeefTx::bump_index` rather
        // than being stored inside the transaction.
        // Target resolution order is the TS SDK's, verbatim
        // (`Transaction.fromAnyBeef`, ts-stack packages/sdk
        // src/transaction/Transaction.ts): `txid ?? beef.atomicTxid ??
        // lastTx.txid`. The middle preference matters: an Atomic BEEF names its
        // subject in the header, and wallet serializers do NOT all place the
        // subject last in wire order. Falling straight to `txs.last()` handed
        // back a PARENT for such beefs — the mis-pick behind the
        // zanaadu#284 stored-BEEF corruption and a wrong-subject hazard for any
        // caller validating "the" transaction of an atomic submit.
        let target = match txid {
            Some(id) => id.to_string(),
            None => match parsed.atomic_txid.clone() {
                Some(atomic) => atomic,
                None => parsed.txs.last().map(|btx| btx.txid()).ok_or_else(|| {
                    crate::Error::TransactionError("No transactions in BEEF".to_string())
                })?,
            },
        };
        parsed.find_atomic_transaction(&target).ok_or_else(|| {
            crate::Error::TransactionError(format!("Transaction {} not found in BEEF", target))
        })
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
    /// The entries are written in the order the walk collects them — each
    /// entry's sources above it, this transaction last (BRC-62's rule) —
    /// not the dependency order [`Beef::to_binary`](crate::transaction::Beef)
    /// sorts a BEEF a caller assembles by hand into. Since 0.8.8: until
    /// then the sort could place a proven ancestor after this transaction,
    /// so a reader taking the last entry ([`from_beef`](Self::from_beef)
    /// with no txid) read the ancestor, not this transaction.
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
        let mut beef = self.ancestry_beef(BEEF_V2, allow_partial)?;
        beef.to_binary()
    }

    /// Serializes this transaction and its ancestors to BEEF V1 format.
    ///
    /// BEEF V1 (BRC-62) has no TXID-only entries, for a reader that takes no V2 (BRC-96).
    /// This method is identical to `to_beef()` but produces V1 format output: the
    /// entries in the order the walk collects them, this transaction last (BRC-62's
    /// rule; see [`to_beef`](Self::to_beef)).
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
        let mut beef = self.ancestry_beef(BEEF_V1, allow_partial)?;
        beef.to_binary()
    }

    /// Serializes this transaction to Atomic BEEF format.
    ///
    /// The Atomic BEEF format (BRC-95) includes a 4-byte prefix `0x01010101`,
    /// followed by this transaction's TXID, and then the BEEF data containing
    /// only this transaction and its dependencies, this transaction last on the
    /// wire (BRC-62's rule; see [`to_beef`](Self::to_beef)): the closure is
    /// sorted as [`Beef::to_binary_atomic`] sorts it and this transaction is
    /// then moved last (since 0.8.8; until then a graph holding a proven
    /// entry beside a missing source left it ahead of the proven ones), while
    /// `Beef::to_binary_atomic` on a BEEF a caller assembles by hand keeps
    /// its documented dependency sort.
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
        let mut beef = self.ancestry_beef(BEEF_V2, allow_partial)?;
        let txid = self.id();
        beef.to_binary_atomic_subject_last(&txid)
    }

    /// The BEEF of this transaction and its ancestry under `version`'s word,
    /// the entries in the order [`collect_ancestors`](Self::collect_ancestors)
    /// builds — each entry's sources above it, this transaction last (BRC-62's
    /// rule) — held in that order for writing, without the Beef-level
    /// dependency sort: a BEEF these doors write ends with this transaction,
    /// as the reference's transaction door writes what it collects without a
    /// sort (`ts-stack@edf6e03` `Transaction.ts:1787-1839`), while its
    /// `Beef.toBinary` — and this crate's — still sorts a BEEF a caller
    /// assembles by hand. The atomic door sorts its closure as
    /// [`Beef::to_binary_atomic`] does and then moves this transaction last
    /// (0.8.8's fold), where `Beef::to_binary_atomic` on a BEEF a caller
    /// assembles by hand writes the sort alone. Until 0.8.8 the doors sorted, so a graph holding
    /// a proven entry beside a missing source wrote the subject before it.
    fn ancestry_beef(&self, version: u32, allow_partial: bool) -> Result<Beef> {
        let mut beef = Beef::with_version(version);

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

        // The ancestors in dependency order, each entry alone (#764's fold)
        for ancestor in ancestors {
            beef.push_transaction(ancestor.id(), ancestor, None);
        }

        beef.hold_order();
        Ok(beef)
    }

    /// Collects ancestor transactions and their merkle proofs.
    ///
    /// This implements the same algorithm as the TypeScript and Go SDKs:
    /// - If this transaction has a merkle_path (is proven), add it and stop descending
    /// - Otherwise, collect ancestors from each input's source_transaction first
    /// - Ancestors are returned in dependency order (oldest first)
    /// - Merkle proofs are deduplicated by block height and computed root
    ///
    /// The walk is depth first with an explicit stack, not recursive (0.3.35,
    /// bsv-stack-lean #57), in the recursive walk's order: inputs from the
    /// last to the first, a txid already collected skipped on entry, a
    /// transaction collected after its sources. Each collected transaction is
    /// a copy WITHOUT its ancestry (the BEEF needs its bytes, not its sources;
    /// an input with no `source_txid` gets its source's id), where the
    /// recursive walk cloned every ancestor's whole ancestry again, which made
    /// `to_beef` quadratic in a chain's depth. The reference walks with an
    /// explicit stack too (`@bsv/sdk` `Transaction.toBEEF`).
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
        /// An unproven transaction whose sources are being collected, and how
        /// many of its inputs (counted from the last) are left to visit.
        struct Frame<'a> {
            tx: &'a Transaction,
            txid: String,
            inputs_left: usize,
        }

        let mut stack: Vec<Frame> = Vec::new();
        let mut entering: Option<&Transaction> = Some(self);
        loop {
            if let Some(tx) = entering.take() {
                let txid = tx.id();
                if seen_txids.contains(&txid) {
                    // Already collected: skip it.
                } else if let Some(ref merkle_path) = tx.merkle_path {
                    // Proven (mined): add the proof and the transaction, and
                    // do not descend. Deduplicate merkle proofs by block
                    // height and computed root.
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

                    seen_txids.insert(txid);
                    ancestors.push(tx.clone_for_beef());
                } else {
                    // Not proven: collect its sources first, last input first
                    // (like the TypeScript SDK) for the dependency order.
                    stack.push(Frame {
                        tx,
                        txid,
                        inputs_left: tx.inputs().len(),
                    });
                }
            }

            let Some(top) = stack.last_mut() else {
                return Ok(());
            };
            if top.inputs_left == 0 {
                // After processing all ancestors, add this transaction
                let Some(frame) = stack.pop() else {
                    return Ok(());
                };
                seen_txids.insert(frame.txid);
                ancestors.push(frame.tx.clone_for_beef());
                continue;
            }
            top.inputs_left -= 1;
            let i = top.inputs_left;
            let input = &top.tx.inputs()[i];
            if let Some(source_tx) = input.source_transaction.as_deref() {
                entering = Some(source_tx);
            } else if !allow_partial {
                // Missing source transaction and not allowing partial
                let source_txid = input
                    .source_txid
                    .map_or_else(|| "unknown".to_string(), |txid| txid.to_string());
                return Err(crate::Error::TransactionError(format!(
                    "Missing source transaction for input {} (txid: {}). \
                     Set allow_partial=true to skip missing source transactions.",
                    i, source_txid
                )));
            }
            // If allow_partial and source_transaction is None, just skip this input
        }
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

        self.inputs_mut().push(input);
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

        self.outputs_mut().push(output);
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
        // 64 hex digits by the checks above; held as a `Txid`, so an
        // upper-case text names the same input (#845).
        let prev_txid = Txid::named(prev_txid, "sourceTXID")?;

        // Build a minimal source transaction with the correct output at the given index
        let mut outputs = vec![TransactionOutput::new(0, LockingScript::new()); vout as usize];
        outputs.push(TransactionOutput::new(
            satoshis,
            prev_locking_script.clone(),
        ));
        let source_tx = Transaction::with_params(1, Vec::new(), outputs, 0);

        let mut input = TransactionInput::new(prev_txid, vout);
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
            let mut outputs =
                vec![TransactionOutput::new(0, LockingScript::new()); utxo.vout as usize];
            outputs.push(TransactionOutput::new(
                utxo.satoshis,
                utxo.locking_script.clone(),
            ));
            let source_tx = Transaction::with_params(1, Vec::new(), outputs, 0);

            let mut input =
                TransactionInput::new(Txid::named(&utxo.txid, "sourceTXID")?, utxo.vout);
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
        self.serialized_bytes().to_vec()
    }

    /// Serializes the transaction to a hex string.
    pub fn to_hex(&self) -> String {
        self.serialized_hex().to_string()
    }

    /// Serializes the transaction to Extended Format (BRC-30).
    ///
    /// The EF format includes source satoshis and locking scripts for each input.
    ///
    /// # Errors
    ///
    /// Returns an error if any input is missing its source transaction, and,
    /// since #843d7, if a linked source output's amount or an output's amount
    /// is 2^53 satoshis or more: `TransactionError("The number is larger than
    /// 2 ^ 53 (unsafe)")`, the reference writer's words, at the amount in
    /// written order, as its `toEF` throws (`from_ef` refuses such bytes).
    /// For an input that names no txid (`TransactionInput::source_txid`
    /// `None`, as `with_source_transaction` and `add_input_from_tx` leave it)
    /// the same refusal for such an amount in ANY output of its source, or of
    /// a source reached through inputs naming no txid, ahead of that input's
    /// other checks: the reference writes such an outpoint from the source's
    /// `hash()`, its plain writer (`Transaction.ts:1137-1138`). This crate's
    /// `to_binary`, `hash` and `id` refuse nothing (the node's serializer).
    pub fn to_ef(&self) -> Result<Vec<u8>> {
        let mut writer = Writer::new();

        writer.write_u32_le(self.version());

        // Write EF marker
        writer.write_bytes(&[0x00, 0x00, 0x00, 0x00, 0x00, 0xEF]);

        // Write inputs with source data
        writer.write_var_int(self.inputs().len() as u64);
        for input in self.inputs() {
            // Get TXID bytes (reversed)
            let txid_bytes = input.get_source_txid_bytes()?;
            // An input naming no txid: the reference writes its source's
            // hash, which refuses an amount of 2^53 or more there (#843d7's fold).
            if input.source_txid.is_none() {
                if let Some(source) = input.source_transaction.as_deref() {
                    unnamed_source_amounts(source)?;
                }
            }
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
                .outputs()
                .get(input.source_output_index as usize)
                .ok_or_else(|| {
                    crate::Error::TransactionError("Source output index out of bounds".to_string())
                })?;

            writer.write_u64_le(written_amount(source_output.satoshis.unwrap_or(0))?);

            let locking_script = source_output.locking_script.to_binary();
            writer.write_var_int(locking_script.len() as u64);
            writer.write_bytes(&locking_script);
        }

        // Write outputs
        writer.write_var_int(self.outputs().len() as u64);
        for output in self.outputs() {
            writer.write_u64_le(written_amount(output.satoshis.unwrap_or(0))?);

            let script = output.locking_script.to_binary();
            writer.write_var_int(script.len() as u64);
            writer.write_bytes(&script);
        }

        writer.write_u32_le(self.lock_time());

        Ok(writer.into_bytes())
    }

    /// Serializes the transaction to a hex-encoded Extended Format string.
    ///
    /// # Errors
    ///
    /// What [`to_ef`](Self::to_ef) refuses, an amount of 2^53 or more among
    /// them (#843d7).
    pub fn to_hex_ef(&self) -> Result<String> {
        Ok(to_hex(&self.to_ef()?))
    }

    /// Computes the transaction hash (double SHA-256).
    ///
    /// This is the internal byte order hash, not the display TXID.
    pub fn hash(&self) -> [u8; 32] {
        self.serialized_hash()
    }

    /// Returns the transaction ID as a [`Txid`]: the double SHA-256 of the
    /// serialized fields, the value an input that spends this transaction
    /// holds as its `source_txid` (#845).
    pub fn txid(&self) -> Txid {
        Txid::from_wire_bytes(self.hash())
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
    /// - An input's `source_txid` (64 hex digits) is not the id of its linked
    ///   source, and that source has an input or a merkle path (#848, the
    ///   reference's refusal and words, `Transaction.ts:964-984`); no template
    ///   runs and no field moves
    /// - Template signing fails
    pub async fn sign(&mut self) -> Result<()> {
        // Validate all outputs have amounts
        for output in self.outputs() {
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

        // No complete source linked under another txid is signed (#848).
        super::source_link::refuse_at_sign(self.inputs())?;

        // Sign each input with a template
        let raw_tx = self.to_binary();

        for i in 0..self.inputs().len() {
            if self.inputs()[i].unlocking_script_template.is_some() {
                // Get source data for signing context
                let source_satoshis = self.inputs()[i].source_satoshis().ok_or_else(|| {
                    crate::Error::TransactionError(format!(
                        "Input {} is missing source satoshis for signing",
                        i
                    ))
                })?;

                // Clone the locking script to avoid borrow issues
                let locking_script = self.inputs()[i]
                    .source_locking_script()
                    .ok_or_else(|| {
                        crate::Error::TransactionError(format!(
                            "Input {} is missing source locking script for signing",
                            i
                        ))
                    })?
                    .clone();

                // Take the template temporarily
                let Some(template) = self.inputs_mut()[i].unlocking_script_template.take() else {
                    continue;
                };

                let context =
                    SigningContext::new(&raw_tx, i, source_satoshis, locking_script.as_script());
                let unlocking = template.sign(&context)?;

                let input = &mut self.inputs_mut()[i];
                input.unlocking_script = Some(unlocking);
                input.unlocking_script_template = Some(template);
            }
        }

        Ok(())
    }

    /// Computes fees and distributes change, as the reference's `fee` does
    /// (`ts-stack@edf6e03` `Transaction.ts:770-862`).
    ///
    /// # Arguments
    ///
    /// * `fee_sats` - The fee in satoshis. If `None`, one satoshi per byte of
    ///   [`Transaction::estimate_size`], where the reference's default is its
    ///   live fee policy (a stated difference, #871).
    /// * `change_distribution` - How to distribute change among change outputs.
    ///
    /// # Errors
    ///
    /// In the reference's order and words (#871): a fee past 21e14 satoshis;
    /// then for each input in turn, no source transaction, a source output
    /// that does not exist, a source output with no amount or one past 21e14,
    /// an input total past 21e14; then for each output that is not a change
    /// output, no amount or one past 21e14, an output total past 21e14; then
    /// inputs that cannot pay the outputs and the fee
    /// (`Transaction inputs are insufficient for the requested outputs and fee.`).
    /// The transaction is unchanged on `Err`.
    pub async fn fee(
        &mut self,
        fee_sats: Option<u64>,
        change_distribution: ChangeDistribution,
    ) -> Result<()> {
        let fee = super::amount::require_satoshi_amount(
            Some(fee_sats.unwrap_or_else(|| self.estimate_size() as u64)),
            "Computed transaction fee",
        )?;
        let change = self.calculate_change(fee)?;

        if change == 0 {
            // Remove change outputs if no change
            self.outputs_mut().retain(|o| !o.change);
            return Ok(());
        }

        // Distribute change
        self.distribute_change(change, change_distribution);

        Ok(())
    }

    /// The input total of every source output, each checked as an amount
    /// (`Input N source amount`), refused where an input has no source
    /// transaction (`missing_source`, the caller's words) or names a source
    /// output that does not exist (`Transaction.ts:836-848`, `:904-919`).
    fn source_total(&self, missing_source: &str) -> Result<u64> {
        let mut total: u64 = 0;
        for (index, input) in self.inputs().iter().enumerate() {
            let source = input
                .source_transaction
                .as_ref()
                .ok_or_else(|| crate::Error::TransactionError(missing_source.to_string()))?;
            let output = source
                .outputs()
                .get(input.source_output_index as usize)
                .ok_or_else(|| {
                    crate::Error::TransactionError(format!(
                        "Input {index} references a source output that does not exist."
                    ))
                })?;
            let amount = super::amount::require_satoshi_amount(
                output.satoshis,
                &format!("Input {index} source amount"),
            )?;
            total = super::amount::add_amount(total, amount, "Transaction input total")?;
        }
        Ok(total)
    }

    /// The reference's `#calculateChange` (`Transaction.ts:832-862`): the
    /// inputs less the outputs that are not change less `fee`, refused when
    /// the inputs cannot pay them (#871; saturated to 0 until then).
    fn calculate_change(&self, fee: u64) -> Result<u64> {
        let total_in = self.source_total(
            "Source transactions are required for all inputs during fee computation",
        )?;
        let mut total_out: u64 = 0;
        for (index, output) in self.outputs().iter().enumerate() {
            if !output.change {
                let amount = super::amount::require_satoshi_amount(
                    output.satoshis,
                    &format!("Output {index} amount"),
                )?;
                total_out =
                    super::amount::add_amount(total_out, amount, "Transaction output total")?;
            }
        }
        // Both at most 21e14: the sum fits.
        if total_out + fee > total_in {
            return Err(crate::Error::TransactionError(
                "Transaction inputs are insufficient for the requested outputs and fee."
                    .to_string(),
            ));
        }
        Ok(total_in - total_out - fee)
    }

    /// Distributes change among change outputs, as the reference's
    /// `#distributeChange` does (`ts-stack@edf6e03` `Transaction.ts:864-897`):
    /// equal, `floor(change / n)` to each and the remainder to the last; random,
    /// a Benford portion of what remains to each but the last, the rest to the
    /// last. An output may receive 0 satoshis, as there (#868).
    fn distribute_change(&mut self, change: u64, distribution: ChangeDistribution) {
        let change_outputs: Vec<usize> = (0..self.outputs().len())
            .filter(|&i| self.outputs()[i].change)
            .collect();
        let Some((&last, rest)) = change_outputs.split_last() else {
            return;
        };
        let per_output = change / change_outputs.len() as u64;
        let mut remaining = change;
        for &idx in rest {
            let portion = match distribution {
                ChangeDistribution::Equal => per_output,
                ChangeDistribution::Random => Self::benford_number(remaining),
            };
            self.outputs_mut()[idx].satoshis = Some(portion);
            remaining -= portion;
        }
        self.outputs_mut()[last].satoshis = Some(remaining);
    }

    /// The reference's `#benfordNumber(0, max)`: `floor(max * log10(1 + 1/d) / log10(10))`
    /// for a digit `d` of 1 to 9, never above `max` (the factor is at most log10(2)).
    /// The digit is drawn by `gen_range`, where the reference takes `Random(1)[0] % 9 + 1`.
    /// Until #868 it divided by `log10(1)`, zero.
    fn benford_number(max: u64) -> u64 {
        use rand::Rng;
        let d: f64 = rand::thread_rng().gen_range(1..=9) as f64;
        let factor = (1.0 + 1.0 / d).log10() / 10_f64.log10();
        (max as f64 * factor).floor() as u64
    }

    /// Returns the current fee based on inputs and outputs, as the
    /// reference's `getFee` (`Transaction.ts:899-933`).
    ///
    /// # Errors
    ///
    /// In the reference's order and words (#871): for each input, no source
    /// transaction, a source output that does not exist, a source amount
    /// absent or past 21e14, an input total past 21e14; then for each output,
    /// a change output's included, no amount or one past 21e14, an output
    /// total past 21e14. Where the outputs exceed the inputs the answer is 0,
    /// where the reference answers a negative number (stated: a `u64`, and
    /// `fee` refuses that transaction).
    pub fn get_fee(&self) -> Result<u64> {
        let total_in = self.source_total(
            "Source transactions or sourceSatoshis are required for all inputs to calculate fee",
        )?;
        let mut total_out: u64 = 0;
        for (index, output) in self.outputs().iter().enumerate() {
            let amount = super::amount::require_satoshi_amount(
                output.satoshis,
                &format!("Output {index} amount"),
            )?;
            total_out = super::amount::add_amount(total_out, amount, "Transaction output total")?;
        }
        Ok(total_in.saturating_sub(total_out))
    }

    /// Estimates the transaction size in bytes.
    pub fn estimate_size(&self) -> usize {
        let mut size = 8; // version (4) + locktime (4)

        // Input count varint
        size += var_int_len(self.inputs().len() as u64);

        // Inputs
        for input in self.inputs() {
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

            size += var_int_len(script_len as u64) + script_len;
        }

        // Output count varint
        size += var_int_len(self.outputs().len() as u64);

        // Outputs
        for output in self.outputs() {
            size += 8; // satoshis
            let script_len = output.locking_script.to_binary().len();
            size += var_int_len(script_len as u64) + script_len;
        }

        size
    }

    /// Returns the number of inputs.
    pub fn input_count(&self) -> usize {
        self.inputs().len()
    }

    /// Returns the number of outputs.
    pub fn output_count(&self) -> usize {
        self.outputs().len()
    }

    /// Returns true if this is a coinbase transaction.
    ///
    /// A coinbase transaction has exactly one input with a null TXID
    /// (all zeros) and output index of 0xFFFFFFFF.
    pub fn is_coinbase(&self) -> bool {
        if self.inputs().len() != 1 {
            return false;
        }
        let input = &self.inputs()[0];
        if input.source_output_index != 0xFFFFFFFF {
            return false;
        }
        // Check if source TXID is all zeros
        input.source_txid.is_some_and(|txid| txid.is_null())
    }

    /// Returns true if this transaction has any data-only outputs (OP_RETURN).
    ///
    /// Checks each output's locking script using `Script::is_data()`.
    pub fn has_data_outputs(&self) -> bool {
        self.outputs()
            .iter()
            .any(|o| o.locking_script.as_script().is_data())
    }

    /// Returns the total satoshis of all inputs that have source transaction data.
    ///
    /// Returns an error if any input is missing its source transaction, since
    /// the satoshi value cannot be determined without it.
    pub fn total_input_satoshis(&self) -> Result<u64> {
        let mut total: u64 = 0;
        for (i, input) in self.inputs().iter().enumerate() {
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
        // Saturating: a sum past `u64` panicked in a debug build (#868's class).
        self.outputs()
            .iter()
            .filter_map(|o| o.satoshis)
            .fold(0, u64::saturating_add)
    }

    /// Every transaction reachable from `self` through `source_transaction`
    /// links, keyed by txid.
    ///
    /// A txid reached more than once keeps ONE copy: any copy carrying a
    /// merkle path wins outright (a proven transaction needs no ancestry at
    /// all), otherwise the copy with the most linked sources wins, and only
    /// the winner is descended. That makes the gather independent of which
    /// object copy a particular input happens to hold (`Beef::add_input_proof`
    /// links each distinct parent once and hands later inputs a bare stub),
    /// and keeps the work linear even on a graph linked by an older,
    /// duplicating walk.
    pub(super) fn reachable_by_txid(&self) -> HashMap<String, &Transaction> {
        /// How much ancestry a copy carries: a proof beats every link count.
        fn linkage(tx: &Transaction) -> usize {
            if tx.merkle_path.is_some() {
                usize::MAX
            } else {
                tx.inputs()
                    .iter()
                    .filter(|input| input.source_transaction.is_some())
                    .count()
            }
        }

        let mut by_txid: HashMap<String, &Transaction> = HashMap::new();
        let mut stack: Vec<&Transaction> = vec![self];
        while let Some(tx) = stack.pop() {
            match by_txid.entry(tx.id()) {
                std::collections::hash_map::Entry::Occupied(mut slot) => {
                    if linkage(tx) <= linkage(slot.get()) {
                        continue; // a copy at least as complete is already in
                    }
                    slot.insert(tx);
                }
                std::collections::hash_map::Entry::Vacant(slot) => {
                    slot.insert(tx);
                }
            }
            if tx.merkle_path.is_some() {
                continue; // proven: its ancestry is not needed
            }
            for input in tx.inputs() {
                if let Some(source) = input.source_transaction.as_deref() {
                    stack.push(source);
                }
            }
        }
        by_txid
    }

    /// Verifies this transaction using SPV (Simplified Payment Verification).
    ///
    /// The walk is BY TXID, not by object graph: every transaction reachable
    /// through `source_transaction` links is gathered into a map keyed by txid
    /// (see the private `reachable_by_txid` walk) and each txid is then processed
    /// exactly once:
    ///
    /// 1. a transaction carrying a merkle path is checked against the chain
    ///    tracker and is not descended;
    /// 2. an unproven one has every output's amount read, its fee checked when
    ///    a fee model is given, every input's script executed with the source
    ///    looked up BY TXID in the map, and the reference's value rule applied
    ///    (its outputs may not spend more than its inputs);
    /// 3. the sources of an unproven transaction are queued by txid.
    ///
    /// Each input must link a source, and its `source_txid`, when 64 hex
    /// digits, must be that source's id (#848); the copy looked up is then
    /// one of the same id and bytes, so nothing depends on which copy of a
    /// parent an input holds: a BEEF that links each distinct parent once (the
    /// linear structure `Beef::add_input_proof` builds, where later inputs
    /// sourcing the same txid get a stub of the same id) verifies exactly like
    /// one that links every input in full. The earlier object-graph walk
    /// forced that second structure, which is exponential on a diamond chain
    /// (0.3.21).
    ///
    /// Refused in the reference's words (`ts-stack@edf6e03`
    /// `Transaction.ts:1336-1432`, `:1464-1474`), for every unproven
    /// transaction the walk reaches: an output amount absent or past 21e14,
    /// the output total past 21e14 (both before any input); an input that
    /// links no source (`... is missing an associated source transaction.
    /// ...`), whatever another input links; a source output that does not
    /// exist (in this crate's words, `Input N source output index out of
    /// bounds`); a source amount absent or past 21e14, the input total past
    /// 21e14; a linked source that is not the transaction the input names
    /// (`Verification failed because input N of transaction <txid> does not
    /// reference its supplied source transaction.`, a descriptor without
    /// inputs included, so a `from_ef` transaction is refused here).
    ///
    /// Matches the Go SDK's `spv.Verify()` and TS SDK's `Transaction.verify()`,
    /// whose inputs share one source object per txid by reference.
    ///
    /// A transaction the walk reaches with no input, or with an input and no
    /// output, is refused, proven or not: the error names it and the
    /// streaming reader's kind (`NoInputs`, `NoOutputs`), the node's two
    /// checks in their order (bsv-script-lean@87f0461
    /// `lean/BsvScript/TxRules.lean:85-86`). Until 0.4.3 a transaction with no
    /// inputs was a synthetic root, exempt from the value rule; the node
    /// mines no such transaction, so a root carries an input and, to be
    /// judged without its ancestry, a merkle path (bsv-stack-lean #59). The
    /// TS SDK refuses the same two for an unmined transaction, in the same
    /// order (`ts-stack@edf6e03` `Transaction.ts:1336-1342`); this walk asks
    /// it of a proven one too, as the streaming reader does.
    ///
    /// Scripts run in the default mode under `memory_limit`, the reference's third parameter
    /// (`ts-stack@edf6e03` `Transaction.ts:1685-1697`): `None` uncapped, its default
    /// (`Spend.ts:295-296`), `Some(n)` `n` bytes per stack (bsv-rs#331); `fee_model`, when
    /// given, is checked. An invalid script is `Err(TransactionError("Script validation failed
    /// for input N: …"))`; one stopped at the budget or by the allocator is
    /// `Err(ScriptEvaluationDeclined)`, a decline, never to be read as invalid (bsv-rs#38).
    /// Work is unbounded by default, as in the reference's `verify`, which has no
    /// work bound. [`Self::verify_with_work_budget`] and
    /// [`Self::verify_with_chain_params_and_work_budget`] add an optional local
    /// budget beside the memory budget, using [`crate::script::SpendParams::work_limit`]
    /// and [`super::StreamVerifier::set_work_limit`]'s one counter per input.
    /// Exceeding it is [`crate::script::NotJudgedCause::WorkBudgetExceeded`] on
    /// [`crate::Error::TransactionNotJudged`], never a script failure. A service door
    /// sets its own policy value; `None` keeps the reference's behavior.
    /// This counter cannot interrupt one arithmetic opcode; an elapsed-time
    /// bound must be external (#378).
    pub async fn verify(
        &self,
        chain_tracker: &dyn super::ChainTracker,
        fee_model: Option<&dyn super::FeeModel>,
        memory_limit: Option<usize>,
    ) -> Result<bool> {
        self.verify_with_work_budget(chain_tracker, fee_model, memory_limit, None)
            .await
    }
}

/// A transaction with no input, or with an input and no output, is no
/// transaction: the streaming reader's refusal (`beef_stream::no_transaction`)
/// for the whole-transaction path, naming the txid and the kind.
pub(super) fn refuse_no_transaction(tx: &Transaction, txid: &str) -> Result<()> {
    match super::beef_stream::no_transaction(tx.inputs().len(), tx.outputs().len()) {
        Some(reason) => Err(crate::Error::TransactionError(format!(
            "invalid transaction {}: {:?}",
            txid,
            reason.kind()
        ))),
        None => Ok(()),
    }
}

impl Drop for Transaction {
    /// Drops the linked ancestry one transaction at a time: every
    /// `source_transaction` is taken out before its owner is dropped, so no
    /// drop reaches below the one in hand.
    fn drop(&mut self) {
        let mut ancestry: Vec<Box<Transaction>> = self
            .inputs_mut()
            .iter_mut()
            .filter_map(|input| input.source_transaction.take())
            .collect();
        while let Some(mut tx) = ancestry.pop() {
            ancestry.extend(
                tx.inputs_mut()
                    .iter_mut()
                    .filter_map(|input| input.source_transaction.take()),
            );
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    // Test transaction hex (simple P2PKH spend)
    const TEST_TX_HEX: &str = "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000";

    // ── Panic-hardening: adversarial count varints must Err, never OOM-abort ──
    //
    // A bogus input/output count varint (e.g. 0xFE FF FF FF FF = u32::MAX) used
    // to reach `Vec::with_capacity(count)` *before* any element was read,
    // aborting the process with a capacity-overflow / OOM panic — a cheap DoS.
    // These parses must now return `Err`. (A panic here fails the test on
    // native; on wasm it would abort, so `bounded_capacity` is load-bearing.)

    #[test]
    fn test_from_binary_bogus_input_count_errs_not_panics() {
        // version(4) + input_count varint 0xFE u32::MAX, then nothing.
        let bin = [
            0x00, 0x00, 0x00, 0x00, // version = 0
            0xFE, 0xFF, 0xFF, 0xFF, 0xFF, // input_count = 0xFFFFFFFF
        ];
        assert!(Transaction::from_binary(&bin).is_err());
    }

    #[test]
    fn test_from_binary_bogus_output_count_errs_not_panics() {
        let bin = [
            0x00, 0x00, 0x00, 0x00, // version = 0
            0x00, // input_count = 0
            0xFE, 0xFF, 0xFF, 0xFF, 0xFF, // output_count = 0xFFFFFFFF
        ];
        assert!(Transaction::from_binary(&bin).is_err());
    }

    #[test]
    fn test_from_beef_bogus_input_count_errs_not_panics() {
        // BEEF V1 (0xEFBE0001, LE) + 0 bumps + 1 tx whose input_count is bogus.
        let beef = [
            0x01, 0x00, 0xBE, 0xEF, // BEEF_V1
            0x00, // bump_count = 0
            0x01, // tx_count = 1
            0x00, 0x00, 0x00, 0x00, // tx version = 0
            0xFE, 0xFF, 0xFF, 0xFF, 0xFF, // input_count = 0xFFFFFFFF
        ];
        assert!(Transaction::from_beef(&beef, None).is_err());
    }

    #[test]
    fn test_from_ef_bogus_source_output_index_errs_not_panics() {
        // A well-formed EF input whose source_output_index is u32::MAX would
        // fabricate ~4.29e9 placeholder outputs; that must be rejected, not
        // OOM-abort.
        let mut ef: Vec<u8> = Vec::new();
        ef.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // version
        ef.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0xEF]); // EF marker
        ef.push(0x01); // input_count = 1
        ef.extend_from_slice(&[0u8; 32]); // source txid
        ef.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]); // source_output_index = u32::MAX
        ef.push(0x00); // unlocking script len = 0
        ef.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // sequence
        ef.extend_from_slice(&[0u8; 8]); // source satoshis
        ef.push(0x00); // source locking script len = 0
        assert!(Transaction::from_ef(&ef).is_err());
    }

    /// PURE GUARD — the EF placeholder-length computation is overflow-safe on
    /// EVERY target word size. `ef_source_placeholder_len` computes `needed` in
    /// u64, so `u32::MAX + 1` cannot wrap to `0` (the 32-bit trap the native-only
    /// functional test above masks — on wasm32 `usize` is 32-bit). These
    /// assertions are correct on both widths and would FAIL on a 32-bit build if
    /// the guard regressed to `source_output_index as usize + 1`, which there
    /// returns `Some(0)` → a zero-length placeholder → an index-OOB abort.
    #[test]
    fn test_ef_source_placeholder_len_is_overflow_safe() {
        // The value a 32-bit `usize + 1` would wrap `u32::MAX` to — the bug.
        assert_eq!(u32::MAX.wrapping_add(1), 0);
        // Small, plausible vouts: accepted, sized to exactly index + 1.
        assert_eq!(ef_source_placeholder_len(0), Some(1));
        assert_eq!(ef_source_placeholder_len(4), Some(5));
        assert_eq!(ef_source_placeholder_len(1000), Some(1001));
        // Adversarial vouts: rejected outright, never wrapped to Some(0).
        assert_eq!(ef_source_placeholder_len(u32::MAX), None);
        assert_eq!(ef_source_placeholder_len(u32::MAX - 1), None);
    }

    #[test]
    fn test_new_transaction() {
        let tx = Transaction::new();
        assert_eq!(tx.version(), 1);
        assert_eq!(tx.lock_time(), 0);
        assert!(tx.inputs().is_empty());
        assert!(tx.outputs().is_empty());
    }

    #[test]
    fn test_from_hex() {
        let tx = Transaction::from_hex(TEST_TX_HEX).unwrap();

        assert_eq!(tx.version(), 1);
        assert_eq!(tx.inputs().len(), 1);
        assert_eq!(tx.outputs().len(), 2);
        assert_eq!(tx.lock_time(), 0);
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
        let good_input = TransactionInput::new("ab".repeat(32).parse().unwrap(), 0);
        assert!(tx.add_input(good_input).is_ok());
        assert_eq!(tx.inputs().len(), 1);
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

        assert_eq!(tx.outputs().len(), 2);
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
    fn test_var_int_len() {
        assert_eq!(var_int_len(0), 1);
        assert_eq!(var_int_len(0xFC), 1);
        assert_eq!(var_int_len(0xFD), 3);
        assert_eq!(var_int_len(0xFFFF), 3);
        assert_eq!(var_int_len(0x10000), 5);
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

        tx.inputs_mut().push(input);

        // Add an output
        let output = TransactionOutput::new(
            50_000,
            LockingScript::from_hex("76a914000000000000000000000000000000000000000088ac").unwrap(),
        );
        tx.outputs_mut().push(output);

        // Serialize to EF
        let ef_bytes = tx.to_ef().unwrap();

        // Parse from EF
        let parsed = Transaction::from_ef(&ef_bytes).unwrap();

        // Verify the parsed transaction
        assert_eq!(parsed.version(), tx.version());
        assert_eq!(parsed.inputs().len(), tx.inputs().len());
        assert_eq!(parsed.outputs().len(), tx.outputs().len());
        assert_eq!(parsed.lock_time(), tx.lock_time());

        // Verify input has source satoshis
        assert!(parsed.inputs()[0].source_satoshis().is_some());
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
        coinbase_tx.inputs_mut().push(TransactionInput {
            source_transaction: None,
            source_txid: Some(
                "0000000000000000000000000000000000000000000000000000000000000000"
                    .parse()
                    .unwrap(),
            ),
            source_output_index: 0xFFFFFFFF,
            unlocking_script: Some(UnlockingScript::from_hex("03a75e0b").unwrap()),
            unlocking_script_template: None,
            sequence: 0xFFFFFFFF,
        });
        coinbase_tx.outputs_mut().push(TransactionOutput::new(
            5000000000,
            LockingScript::from_hex("76a914000000000000000000000000000000000000000088ac").unwrap(),
        ));
        assert!(coinbase_tx.is_coinbase());

        // Regular transaction is not coinbase
        let regular_tx = Transaction::from_hex(TEST_TX_HEX).unwrap();
        assert!(!regular_tx.is_coinbase());

        // Transaction with 2 inputs is not coinbase
        let mut two_input_tx = Transaction::new();
        two_input_tx.inputs_mut().push(TransactionInput {
            source_transaction: None,
            source_txid: Some(
                "0000000000000000000000000000000000000000000000000000000000000000"
                    .parse()
                    .unwrap(),
            ),
            source_output_index: 0xFFFFFFFF,
            unlocking_script: None,
            unlocking_script_template: None,
            sequence: 0xFFFFFFFF,
        });
        two_input_tx.inputs_mut().push(TransactionInput {
            source_transaction: None,
            source_txid: Some("ab".repeat(32).parse().unwrap()),
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
        tx.outputs_mut().push(TransactionOutput::new(
            100_000,
            LockingScript::from_hex("76a914000000000000000000000000000000000000000088ac").unwrap(),
        ));
        assert!(!tx.has_data_outputs());

        // Transaction with an OP_RETURN output
        let mut tx_data = Transaction::new();
        tx_data.outputs_mut().push(TransactionOutput::new(
            0,
            LockingScript::from_hex("6a0568656c6c6f").unwrap(), // OP_RETURN "hello"
        ));
        assert!(tx_data.has_data_outputs());

        // Transaction with both data and non-data outputs
        let mut tx_mixed = Transaction::new();
        tx_mixed.outputs_mut().push(TransactionOutput::new(
            100_000,
            LockingScript::from_hex("76a914000000000000000000000000000000000000000088ac").unwrap(),
        ));
        tx_mixed.outputs_mut().push(TransactionOutput::new(
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

        assert_eq!(tx.outputs().len(), 1);
        assert_eq!(tx.outputs()[0].satoshis, Some(0));
        assert!(tx.outputs()[0].locking_script.as_script().is_data());
        assert!(tx.outputs()[0]
            .locking_script
            .as_script()
            .is_safe_data_carrier());

        // Verify the script structure: OP_FALSE OP_RETURN <data>
        let asm = tx.outputs()[0].locking_script.to_asm();
        assert!(asm.starts_with("OP_0 OP_RETURN"));
    }

    #[test]
    fn test_add_op_return_output_empty_data() {
        let mut tx = Transaction::new();
        tx.add_op_return_output(b"").unwrap();

        assert_eq!(tx.outputs().len(), 1);
        assert!(tx.outputs()[0].locking_script.as_script().is_data());
    }

    #[test]
    fn test_add_op_return_parts_output() {
        let mut tx = Transaction::new();
        tx.add_op_return_parts_output(&[b"part1", b"part2", b"part3"])
            .unwrap();

        assert_eq!(tx.outputs().len(), 1);
        assert_eq!(tx.outputs()[0].satoshis, Some(0));
        assert!(tx.outputs()[0].locking_script.as_script().is_data());
        assert!(tx.outputs()[0]
            .locking_script
            .as_script()
            .is_safe_data_carrier());

        // Verify all parts are present in the script
        let asm = tx.outputs()[0].locking_script.to_asm();
        assert!(asm.starts_with("OP_0 OP_RETURN"));
    }

    #[test]
    fn test_add_op_return_parts_single_part() {
        let mut tx = Transaction::new();
        tx.add_op_return_parts_output(&[b"single"]).unwrap();

        // Single part should produce same result as add_op_return_output
        let mut tx2 = Transaction::new();
        tx2.add_op_return_output(b"single").unwrap();

        assert_eq!(
            tx.outputs()[0].locking_script.to_hex(),
            tx2.outputs()[0].locking_script.to_hex()
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

        assert_eq!(tx.outputs().len(), 1);
        assert_eq!(tx.outputs()[0].satoshis, Some(50_000));

        // Verify the script structure:
        // OP_HASH160 <hash> OP_EQUALVERIFY OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG
        let asm = tx.outputs()[0].locking_script.to_asm();
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

        tx.outputs_mut().push(TransactionOutput::new(
            100_000,
            LockingScript::from_hex("76a914000000000000000000000000000000000000000088ac").unwrap(),
        ));
        assert_eq!(tx.total_output_satoshis(), 100_000);

        tx.outputs_mut().push(TransactionOutput::new(
            50_000,
            LockingScript::from_hex("76a914000000000000000000000000000000000000000088ac").unwrap(),
        ));
        assert_eq!(tx.total_output_satoshis(), 150_000);
    }

    #[test]
    fn test_total_output_satoshis_with_op_return() {
        let mut tx = Transaction::new();
        tx.add_op_return_output(b"data").unwrap();
        tx.outputs_mut().push(TransactionOutput::new(
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
        assert_eq!(total, source_tx.outputs()[0].satoshis.unwrap());
    }

    #[test]
    fn test_total_input_satoshis_missing_source() {
        let mut tx = Transaction::new();
        tx.add_input(TransactionInput::new(
            "0000000000000000000000000000000000000000000000000000000000000001"
                .parse()
                .unwrap(),
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

        assert_eq!(tx.outputs().len(), 1);
        assert!(tx.outputs()[0].locking_script.as_script().is_data());
    }

    #[test]
    fn test_add_op_return_parts_empty() {
        let mut tx = Transaction::new();
        let empty_parts: &[&[u8]] = &[];
        tx.add_op_return_parts_output(empty_parts).unwrap();

        assert_eq!(tx.outputs().len(), 1);
        assert!(tx.outputs()[0].locking_script.as_script().is_data());
        // Should just be OP_FALSE OP_RETURN with no data
        let asm = tx.outputs()[0].locking_script.to_asm();
        assert_eq!(asm, "OP_0 OP_RETURN");
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
            tx1.outputs()[0].locking_script.to_hex(),
            tx2.outputs()[0].locking_script.to_hex()
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
            tx1.outputs()[0].locking_script.to_hex(),
            tx2.outputs()[0].locking_script.to_hex()
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
        let expected_satoshis = source_tx.outputs()[0].satoshis.unwrap();

        let mut tx = Transaction::new();
        tx.add_input_from_tx(source_tx, 0, dummy_template())
            .unwrap();

        assert_eq!(tx.inputs().len(), 1);
        assert!(tx.inputs()[0].has_source_transaction());
        assert_eq!(tx.inputs()[0].get_source_txid().unwrap(), expected_txid);
        assert_eq!(tx.inputs()[0].source_output_index, 0);
        assert_eq!(tx.inputs()[0].source_satoshis().unwrap(), expected_satoshis);
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

        assert_eq!(tx.inputs().len(), 1);
        assert_eq!(tx.inputs()[0].get_source_txid().unwrap(), prev_txid);
        assert_eq!(tx.inputs()[0].source_output_index, 0);
        assert_eq!(tx.inputs()[0].source_satoshis().unwrap(), satoshis);
        assert_eq!(
            tx.inputs()[0].source_locking_script().unwrap().to_hex(),
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

        assert_eq!(tx.inputs().len(), 1);
        assert_eq!(tx.inputs()[0].source_output_index, 3);
        // The minimal source transaction should have padding outputs + the real one at index 3
        let source = tx.inputs()[0].source_transaction.as_ref().unwrap();
        assert_eq!(source.outputs().len(), 4);
        assert_eq!(source.outputs()[3].satoshis.unwrap(), satoshis);
        assert_eq!(
            source.outputs()[3].locking_script.to_hex(),
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

        assert_eq!(tx.inputs().len(), 3);

        // Verify each input matches its UTXO
        for (i, utxo) in utxos.iter().enumerate() {
            assert_eq!(tx.inputs()[i].get_source_txid().unwrap(), utxo.txid);
            assert_eq!(tx.inputs()[i].source_output_index, utxo.vout);
            assert_eq!(tx.inputs()[i].source_satoshis().unwrap(), utxo.satoshis);
            assert_eq!(
                tx.inputs()[i].source_locking_script().unwrap().to_hex(),
                utxo.locking_script.to_hex()
            );
        }

        // Template should NOT be set (add_inputs_from_utxos does not set it)
        for input in tx.inputs() {
            assert!(input.unlocking_script_template.is_none());
        }
    }

    #[test]
    fn test_add_inputs_from_utxos_empty() {
        let utxos: Vec<crate::transaction::input::Utxo> = vec![];
        let mut tx = Transaction::new();
        tx.add_inputs_from_utxos(&utxos).unwrap();

        assert_eq!(tx.inputs().len(), 0);
    }

    #[test]
    fn test_add_input_from_tx_preserves_template() {
        use crate::script::{Script, SigningContext};

        let source_tx = Transaction::from_hex(TEST_TX_HEX).unwrap();

        let mut tx = Transaction::new();
        tx.add_input_from_tx(source_tx, 0, dummy_template())
            .unwrap();

        // The template should be set on the input
        assert!(tx.inputs()[0].unlocking_script_template.is_some());

        // Verify the template can produce an unlocking script
        let template = tx.inputs()[0].unlocking_script_template.as_ref().unwrap();
        let dummy_tx = Transaction::new();
        let raw_tx = dummy_tx.to_binary();
        let locking_script = Script::new();
        let ctx = SigningContext::new(&raw_tx, 0, 0, &locking_script);
        let result = template.sign(&ctx);
        assert!(result.is_ok());
    }
}

#[cfg(test)]
mod from_beef_subject_tests {
    use super::Transaction;
    use crate::transaction::Beef;

    /// A real two-tx BEEF (parent + child spending it, with a BUMP) — the same
    /// fixture the overlay engine's tests use. Parsed here and re-serialized in
    /// controlled wire orders.
    const CHAIN_BEEF_HEX: &str = "0100beef01fe636d0c0007021400fe507c0c7aa754cef1f7889d5fd395cf1f785dd7de98eed895dbedfe4e5bc70d1502ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e010b00bc4ff395efd11719b277694cface5aa50d085a0bb81f613f70313acd28cf4557010400574b2d9142b8d28b61d88e3b2c3f44d858411356b49a28a4643b6d1a6a092a5201030051a05fc84d531b5d250c23f4f886f6812f9fe3f402d61607f977b4ecd2701c19010000fd781529d58fc2523cf396a7f25440b409857e7e221766c57214b1d38c7b481f01010062f542f45ea3660f86c013ced80534cb5fd4c19d66c56e7e8c5d4bf2d40acc5e010100b121e91836fd7cd5102b654e9f72f3cf6fdbfd0b161c53a9c54b12c841126331020100000001cd4e4cac3c7b56920d1e7655e7e260d31f29d9a388d04910f1bbd72304a79029010000006b483045022100e75279a205a547c445719420aa3138bf14743e3f42618e5f86a19bde14bb95f7022064777d34776b05d816daf1699493fcdf2ef5a5ab1ad710d9c97bfb5b8f7cef3641210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff013e660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac0000000001000100000001ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e000000006a47304402203a61a2e931612b4bda08d541cfb980885173b8dcf64a3471238ae7abcd368d6402204cbf24f04b9aa2256d8901f0ed97866603d2be8324c2bfb7a37bf8fc90edd5b441210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff013c660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac0000000000";

    /// Re-serialize the fixture chain so the SUBJECT IS NOT LAST in wire order
    /// (the shape real wallet serializers emit — the zanaadu#284 trigger).
    /// `to_writer` on purpose: `to_binary` re-sorts parents-first and hides it.
    fn wire_order_beef(subject_first: bool) -> (Vec<u8>, String, String) {
        let parsed =
            Beef::from_binary(&crate::primitives::encoding::from_hex(CHAIN_BEEF_HEX).unwrap())
                .unwrap();
        let parent = parsed.txs[0].tx().unwrap().clone();
        let child = parsed.txs[1].tx().unwrap().clone();
        let (parent_id, child_id) = (parent.id(), child.id());
        assert_ne!(parent_id, child_id);

        let mut beef = Beef::new();
        if subject_first {
            beef.merge_transaction(child);
            beef.merge_transaction(parent);
        } else {
            beef.merge_transaction(parent);
            beef.merge_transaction(child);
        }

        let mut w = crate::primitives::encoding::Writer::new();
        beef.to_writer(&mut w).expect("the BEEF is writable");
        (w.into_bytes(), child_id, parent_id)
    }

    fn as_atomic(bytes: &[u8], subject: &str) -> Vec<u8> {
        let mut w = crate::primitives::encoding::Writer::new();
        w.write_u32_le(crate::transaction::beef_tx::ATOMIC_BEEF);
        let mut le = crate::primitives::encoding::from_hex(subject).unwrap();
        le.reverse();
        w.write_bytes(&le);
        w.write_bytes(bytes);
        w.into_bytes()
    }

    /// TS parity (`Transaction.fromAnyBeef`, ts-stack packages/sdk): the target
    /// is `txid ?? atomicTxid ?? last`. With the subject FIRST in wire order,
    /// txs.last() is the PARENT — the old behavior returned it.
    #[test]
    fn none_prefers_the_atomic_subject_over_wire_order() {
        let (bytes, child_id, parent_id) = wire_order_beef(true);
        let tx = Transaction::from_beef(&as_atomic(&bytes, &child_id), None).unwrap();
        assert_eq!(tx.id(), child_id, "atomic subject must win over txs.last()");
        assert_ne!(tx.id(), parent_id);
    }

    /// A plain (non-atomic) BEEF has no subject header; the last-tx fallback is
    /// the documented TS behavior and keeps working unchanged.
    #[test]
    fn none_falls_back_to_last_tx_for_plain_beef() {
        let (bytes, child_id, _parent_id) = wire_order_beef(false);
        let tx = Transaction::from_beef(&bytes, None).unwrap();
        assert_eq!(tx.id(), child_id);
    }

    /// An explicit txid outranks both the atomic header and wire order.
    #[test]
    fn explicit_txid_outranks_everything() {
        let (bytes, child_id, parent_id) = wire_order_beef(true);
        let tx = Transaction::from_beef(&as_atomic(&bytes, &child_id), Some(&parent_id)).unwrap();
        assert_eq!(tx.id(), parent_id);
    }
}
