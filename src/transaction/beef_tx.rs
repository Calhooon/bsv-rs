//! BeefTx - Transaction wrapper for BEEF format.
//!
//! A `BeefTx` represents a single Bitcoin transaction associated with a BEEF validity proof set.
//! It can contain:
//! - A full transaction (parsed or raw bytes)
//! - Just a transaction ID (for "known" transactions)
//!
//! The BEEF format supports "known" transactions which are represented solely by their txid.
//! This allows parties with shared history to exchange smaller proofs.

use crate::primitives::{from_hex, sha256d, to_hex, Reader, Writer};
use crate::Result;

use super::transaction::Transaction;

/// BEEF V1 format marker - when written as little-endian u32, produces bytes: 01 00 BE EF
pub const BEEF_V1: u32 = 0xEFBE0001;

/// BEEF V2 format marker - when written as little-endian u32, produces bytes: 02 00 BE EF
pub const BEEF_V2: u32 = 0xEFBE0002;

/// Atomic BEEF format marker.
pub const ATOMIC_BEEF: u32 = 0x01010101;

/// Transaction data format in BEEF.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxDataFormat {
    /// Raw transaction without BUMP index.
    RawTx = 0,
    /// Raw transaction with BUMP index.
    RawTxAndBumpIndex = 1,
    /// Transaction ID only (BRC-96).
    TxidOnly = 2,
}

impl TxDataFormat {
    /// Converts a u8 to TxDataFormat.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::RawTx),
            1 => Some(Self::RawTxAndBumpIndex),
            2 => Some(Self::TxidOnly),
            _ => None,
        }
    }
}

/// A single Bitcoin transaction associated with a BEEF validity proof set.
///
/// Simple case is transaction data included directly, either as raw bytes or fully parsed data.
/// Supports "known" transactions which are represented by just their txid.
#[derive(Debug, Clone)]
pub struct BeefTx {
    /// Index into the BEEF's bumps array, if this transaction has a proof.
    bump_index: Option<usize>,
    /// Parsed transaction (lazily populated from raw_tx).
    tx: Option<Transaction>,
    /// Raw transaction bytes.
    raw_tx: Option<Vec<u8>>,
    /// Transaction ID (cached or for txid-only entries).
    txid: Option<String>,
    /// TXIDs of inputs (populated when transaction data is available and no proof).
    pub input_txids: Vec<String>,
    /// Whether this transaction is valid (has proof or chains to proofs).
    pub is_valid: Option<bool>,
    /// Set by [`tx_mut`](Self::tx_mut): `input_txids` waits for
    /// [`refresh`](Self::refresh) (bsv-rs#171).
    mutated: bool,
}

impl BeefTx {
    /// Creates a BeefTx from a parsed Transaction.
    pub fn from_tx(tx: Transaction, bump_index: Option<usize>) -> Self {
        let mut btx = Self {
            bump_index,
            tx: Some(tx),
            raw_tx: None,
            txid: None,
            input_txids: Vec::new(),
            is_valid: None,
            mutated: false,
        };
        btx.update_input_txids();
        btx
    }

    /// Creates a BeefTx from raw transaction bytes.
    pub fn from_raw_tx(raw_tx: Vec<u8>, bump_index: Option<usize>) -> Self {
        let mut btx = Self {
            bump_index,
            tx: None,
            raw_tx: Some(raw_tx),
            txid: None,
            input_txids: Vec::new(),
            is_valid: None,
            mutated: false,
        };
        btx.update_input_txids();
        btx
    }

    /// A raw transaction read from a BEEF: its bytes and their parse, both
    /// in hand, read once (the whole-BEEF reader's collect, bsv-rs#86).
    pub(crate) fn from_parts(tx: Transaction, raw_tx: Vec<u8>, bump_index: Option<usize>) -> Self {
        let mut btx = Self {
            bump_index,
            tx: Some(tx),
            raw_tx: Some(raw_tx),
            txid: None,
            input_txids: Vec::new(),
            is_valid: None,
            mutated: false,
        };
        btx.update_input_txids();
        btx
    }

    /// The entry with its txid in hand: the display hex of the hash the
    /// decoder computed as the bytes passed, so [`txid`](Self::txid) does not
    /// serialize and hash the transaction again on each call (bsv-rs#86).
    #[must_use]
    pub(crate) fn with_txid(mut self, txid: String) -> Self {
        self.txid = Some(txid);
        self
    }

    /// Creates a BeefTx from just a transaction ID.
    pub fn from_txid(txid: String) -> Self {
        Self {
            bump_index: None,
            tx: None,
            raw_tx: None,
            txid: Some(txid),
            input_txids: Vec::new(),
            is_valid: None,
            mutated: false,
        }
    }

    /// Returns the bump index if this transaction has a proof.
    pub fn bump_index(&self) -> Option<usize> {
        self.bump_index
    }

    /// Sets the bump index.
    pub fn set_bump_index(&mut self, index: Option<usize>) {
        self.bump_index = index;
        self.update_input_txids();
    }

    /// Returns true if this transaction has a proof (bump).
    pub fn has_proof(&self) -> bool {
        self.bump_index.is_some()
    }

    /// Returns true if this is a txid-only entry (no transaction data).
    pub fn is_txid_only(&self) -> bool {
        self.txid.is_some() && self.raw_tx.is_none() && self.tx.is_none()
    }

    /// Returns the transaction ID.
    ///
    /// Computes and caches the txid if not already known.
    #[allow(clippy::panic)] // #134: every constructor sets a transaction, raw bytes or a txid; a Result here is a breaking change
    pub fn txid(&self) -> String {
        if let Some(ref txid) = self.txid {
            return txid.clone();
        }

        if let Some(ref tx) = self.tx {
            // A hash cached inside the `tx_mut` borrow may be the pre-mutation
            // one (the caller read `id()` before editing a field): hash from the
            // fields until `refresh` clears the mark (bsv-rs#171, the review's fold).
            if self.mutated {
                tx.invalidate_caches();
            }
            return tx.id();
        }

        if let Some(ref raw_tx) = self.raw_tx {
            // Compute txid from raw transaction bytes
            let hash = sha256d(raw_tx);
            let mut reversed = hash;
            reversed.reverse();
            return to_hex(&reversed);
        }

        panic!("BeefTx has no transaction data or txid");
    }

    /// Returns a reference to the parsed transaction, parsing from raw bytes if needed.
    pub fn tx(&self) -> Option<&Transaction> {
        self.tx.as_ref()
    }

    /// Returns a mutable reference to the parsed transaction, parsing from
    /// raw bytes if needed.
    ///
    /// From this call the transaction is the entry's only reading (bsv-rs#171,
    /// as `@bsv/sdk` 3's `BeefTx.syncRawTxFromTransaction`): the bytes and the
    /// txid it was read with are dropped, so [`txid`](Self::txid) is the
    /// mutated transaction's hash and the writer emits its serialization; the
    /// BUMP index stays as it was, so a proven entry whose hash moves is
    /// refused `TxidNotInBump`. `input_txids` is refreshed by the BEEF's next
    /// whole-BEEF reader (`sort_txs`, `verify_structure`, `verify_valid`,
    /// `is_valid`, `to_binary`, `to_binary_atomic`, `trim_known_proven`,
    /// `to_log_string`), which also re-keys the BEEF's index by the new
    /// txid; until then a lookup by the new txid misses and one by the old
    /// txid finds nothing.
    pub fn tx_mut(&mut self) -> Option<&mut Transaction> {
        self.parse_raw();
        if let Some(ref tx) = self.tx {
            tx.invalidate_caches();
            self.raw_tx = None;
            self.txid = None;
            self.mutated = true;
        }
        self.tx.as_mut()
    }

    /// The parsed transaction, parsing from raw bytes if needed, for a
    /// reader: unlike [`tx_mut`](Self::tx_mut) the entry keeps its bytes.
    pub(crate) fn parsed(&mut self) -> Option<&Transaction> {
        self.parse_raw();
        self.tx.as_ref()
    }

    /// After [`tx_mut`](Self::tx_mut), reads `input_txids` from the mutated
    /// transaction again; true when it did.
    pub(crate) fn refresh(&mut self) -> bool {
        if !std::mem::take(&mut self.mutated) {
            return false;
        }
        if let Some(ref tx) = self.tx {
            // A field edit after `tx_mut` may have left the hash cached.
            tx.invalidate_caches();
        }
        self.update_input_txids();
        true
    }

    /// True when the entry's txid is `txid`, without a copy when it is held.
    pub(crate) fn has_txid(&self, txid: &str) -> bool {
        match self.txid {
            Some(ref held) => held == txid,
            None => self.txid() == txid,
        }
    }

    /// Parses the raw bytes into the transaction, when only the bytes are
    /// held and they parse.
    fn parse_raw(&mut self) {
        if self.tx.is_none() {
            if let Some(Ok(tx)) = self.raw_tx.as_deref().map(Transaction::from_binary) {
                self.tx = Some(tx);
            }
        }
    }

    /// Returns the raw transaction bytes.
    pub fn raw_tx(&self) -> Option<&[u8]> {
        if self.raw_tx.is_some() {
            return self.raw_tx.as_deref();
        }

        None
    }

    /// Returns raw transaction bytes, computing from parsed tx if needed.
    pub fn raw_tx_or_compute(&mut self) -> Option<Vec<u8>> {
        if let Some(ref raw_tx) = self.raw_tx {
            return Some(raw_tx.clone());
        }

        if let Some(ref tx) = self.tx {
            let bytes = tx.to_binary();
            self.raw_tx = Some(bytes.clone());
            return Some(bytes);
        }

        None
    }

    /// True for a raw transaction whose input count is 0. A txid-only entry
    /// has no bytes to read and is never this.
    ///
    /// Such bytes are no transaction: the node refuses one before any script
    /// runs, so no block holds it and nothing spends it. Since 0.4.1
    /// [`Beef::verify_valid`](super::beef::Beef::verify_valid) refuses a BEEF
    /// that carries one, with or without a BUMP index, as the streaming
    /// reader does (`Kind::NoInputs`).
    pub fn has_no_inputs(&self) -> bool {
        if let Some(ref tx) = self.tx {
            return tx.inputs.is_empty();
        }
        match self.raw_tx {
            // The input count is the varint after the four bytes of version.
            Some(ref raw_tx) => {
                let mut reader = Reader::new(raw_tx);
                reader.read_bytes(4).is_ok() && matches!(reader.read_var_int_num(), Ok(0))
            }
            None => false,
        }
    }

    /// True for a raw transaction with at least one input and an output
    /// count of 0. A txid-only entry has no bytes to read and is never this;
    /// raw bytes that do not parse are not this either (the parse refuses
    /// them first).
    ///
    /// The node refuses such bytes beside a transaction with no input, after
    /// it (bsv-script-lean@87f0461 `lean/BsvScript/TxRules.lean:86`,
    /// `checkTransactionCommon_voutEmpty`). Since 0.4.3
    /// [`Beef::verify_valid`](super::beef::Beef::verify_valid) refuses a BEEF
    /// that carries one, with or without a BUMP index, as the streaming
    /// reader does (`Kind::NoOutputs`).
    pub fn has_no_outputs(&self) -> bool {
        if self.has_no_inputs() {
            return false;
        }
        if let Some(ref tx) = self.tx {
            return tx.outputs.is_empty();
        }
        match self.raw_tx {
            Some(ref raw_tx) => {
                matches!(Transaction::from_binary(raw_tx), Ok(tx) if tx.outputs.is_empty())
            }
            None => false,
        }
    }

    /// Updates the input_txids list based on transaction data.
    fn update_input_txids(&mut self) {
        // Computed afresh: a second call (`set_bump_index`, or a reader that
        // set the parse after the bytes) names each txid once, not again.
        self.input_txids = Vec::new();
        if self.has_proof() {
            // If we have a proof, we don't need to track input txids
            return;
        }

        self.parse_raw();

        if let Some(ref tx) = self.tx {
            let mut seen = std::collections::HashSet::new();
            for input in &tx.inputs {
                // Use get_source_txid() which falls back to source_transaction
                // when source_txid is None (e.g., when input was created via
                // TransactionInput::with_source_transaction())
                if let Ok(txid) = input.get_source_txid() {
                    if !txid.is_empty() && seen.insert(txid.clone()) {
                        self.input_txids.push(txid);
                    }
                }
            }
        }
    }

    /// Writes this BeefTx to a Writer.
    pub fn to_writer(&self, writer: &mut Writer, version: u32) {
        if version == BEEF_V2 {
            if self.is_txid_only() {
                // TXID only format
                writer.write_u8(TxDataFormat::TxidOnly as u8);
                let txid_bytes = from_hex(&self.txid()).unwrap_or_default();
                let mut reversed = txid_bytes;
                reversed.reverse();
                writer.write_bytes(&reversed);
            } else if let Some(bump_idx) = self.bump_index {
                // Raw tx with bump index
                writer.write_u8(TxDataFormat::RawTxAndBumpIndex as u8);
                writer.write_var_int(bump_idx as u64);
                self.write_tx_data(writer);
            } else {
                // Raw tx without bump index
                writer.write_u8(TxDataFormat::RawTx as u8);
                self.write_tx_data(writer);
            }
        } else {
            // V1 format
            self.write_tx_data(writer);
            if let Some(bump_idx) = self.bump_index {
                writer.write_u8(1);
                writer.write_var_int(bump_idx as u64);
            } else {
                writer.write_u8(0);
            }
        }
    }

    /// Writes the transaction data (raw bytes or serialized).
    #[allow(clippy::panic)] // #134: called only for an entry with data; the writers it serves return no Result
    fn write_tx_data(&self, writer: &mut Writer) {
        if let Some(ref raw_tx) = self.raw_tx {
            writer.write_bytes(raw_tx);
        } else if let Some(ref tx) = self.tx {
            writer.write_bytes(&tx.to_binary());
        } else {
            panic!("BeefTx has no transaction data to write");
        }
    }

    /// Reads a BeefTx from a Reader.
    pub fn from_reader(reader: &mut Reader, version: u32) -> Result<Self> {
        if version == BEEF_V2 {
            let format = reader.read_u8()?;

            match TxDataFormat::from_u8(format) {
                Some(TxDataFormat::TxidOnly) => {
                    // Read txid (reversed)
                    let txid_slice = reader.read_bytes(32)?;
                    let mut txid_bytes = txid_slice.to_vec();
                    txid_bytes.reverse();
                    let txid = to_hex(&txid_bytes);
                    Ok(Self::from_txid(txid))
                }
                Some(TxDataFormat::RawTxAndBumpIndex) => {
                    let bump_index = reader.read_var_int_num()?;
                    let (tx, raw_tx) = read_tx(reader)?;
                    Ok(Self::from_parts(tx, raw_tx, Some(bump_index)))
                }
                Some(TxDataFormat::RawTx) | None => {
                    let (tx, raw_tx) = read_tx(reader)?;
                    Ok(Self::from_parts(tx, raw_tx, None))
                }
            }
        } else {
            // V1 format
            let (tx, raw_tx) = read_tx(reader)?;
            let has_bump = reader.read_u8()? != 0;
            let bump_index = if has_bump {
                Some(reader.read_var_int_num()?)
            } else {
                None
            };
            Ok(Self::from_parts(tx, raw_tx, bump_index))
        }
    }
}

/// A raw transaction at the reader: its parse and the bytes it took.
fn read_tx(reader: &mut Reader) -> Result<(Transaction, Vec<u8>)> {
    let tx_start = reader.position();
    let tx = Transaction::from_reader_internal(reader)?;
    Ok((tx, reader.consumed_since(tx_start).to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Simple P2PKH transaction hex
    const TEST_TX_HEX: &str = "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000";

    #[test]
    fn test_from_tx() {
        let tx = Transaction::from_hex(TEST_TX_HEX).unwrap();
        let beef_tx = BeefTx::from_tx(tx, None);
        assert!(!beef_tx.is_txid_only());
        assert!(!beef_tx.has_proof());
        assert_eq!(beef_tx.txid().len(), 64);
    }

    #[test]
    fn test_from_raw_tx() {
        let raw_tx = from_hex(TEST_TX_HEX).unwrap();
        let beef_tx = BeefTx::from_raw_tx(raw_tx, Some(0));
        assert!(!beef_tx.is_txid_only());
        assert!(beef_tx.has_proof());
        assert_eq!(beef_tx.bump_index(), Some(0));
    }

    #[test]
    fn test_from_txid() {
        let txid = "abc123".repeat(11)[..64].to_string();
        let beef_tx = BeefTx::from_txid(txid.clone());
        assert!(beef_tx.is_txid_only());
        assert!(!beef_tx.has_proof());
        assert_eq!(beef_tx.txid(), txid);
    }

    #[test]
    fn test_input_txids() {
        let tx = Transaction::from_hex(TEST_TX_HEX).unwrap();
        let beef_tx = BeefTx::from_tx(tx, None);
        // This transaction has one input, so should have one input txid
        assert_eq!(beef_tx.input_txids.len(), 1);
    }

    #[test]
    fn test_input_txids_cleared_with_proof() {
        let tx = Transaction::from_hex(TEST_TX_HEX).unwrap();
        let beef_tx = BeefTx::from_tx(tx, Some(0));
        // With a proof, input_txids should be empty
        assert!(beef_tx.input_txids.is_empty());
    }

    /// Through 0.8.3 the reader computed an unproven entry's input txids
    /// twice (`from_raw_tx`, then again once the parse was set) and kept
    /// both: `input_txids` named each parent twice, and
    /// `SortResult::missing_inputs` a missing parent twice. So did a second
    /// `set_bump_index`.
    #[test]
    fn a_read_entry_names_each_input_txid_once() {
        let raw = from_hex(TEST_TX_HEX).unwrap();
        let mut bytes = raw.clone();
        bytes.push(0); // V1: no BUMP index
        let mut entry = BeefTx::from_reader(&mut Reader::new(&bytes), super::BEEF_V1).unwrap();
        assert_eq!(entry.input_txids.len(), 1);
        entry.set_bump_index(None);
        entry.set_bump_index(None);
        assert_eq!(entry.input_txids.len(), 1);

        let mut v2 = vec![0u8];
        v2.extend_from_slice(&raw);
        let entry = BeefTx::from_reader(&mut Reader::new(&v2), BEEF_V2).unwrap();
        assert_eq!(entry.input_txids.len(), 1);
    }

    #[test]
    fn test_tx_data_format() {
        assert_eq!(TxDataFormat::from_u8(0), Some(TxDataFormat::RawTx));
        assert_eq!(
            TxDataFormat::from_u8(1),
            Some(TxDataFormat::RawTxAndBumpIndex)
        );
        assert_eq!(TxDataFormat::from_u8(2), Some(TxDataFormat::TxidOnly));
        assert_eq!(TxDataFormat::from_u8(3), None);
    }
}
