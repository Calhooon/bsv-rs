//! BeefTx - Transaction wrapper for BEEF format.
//!
//! A `BeefTx` represents a single Bitcoin transaction associated with a BEEF validity proof set.
//! It can contain:
//! - A full transaction (parsed or raw bytes)
//! - Just a transaction ID (for "known" transactions)
//!
//! The BEEF format supports "known" transactions which are represented solely by their txid.
//! This allows parties with shared history to exchange smaller proofs.

use crate::primitives::{sha256d, Reader};
use crate::Result;

use super::transaction::Transaction;
use super::txid::Txid;

// The writer and its check (#817), in the nightly's `beef*.rs` mutation selection.
#[path = "beef_tx_writer.rs"]
mod writer;

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
    /// Transaction ID (cached or for txid-only entries), a [`Txid`] since
    /// #843b: a text that is no txid cannot be held.
    txid: Option<Txid>,
    /// TXIDs of inputs (populated when transaction data is available and no
    /// proof); read through [`input_txids`](Self::input_txids), written by
    /// this file alone (#843b: a hand write of it moved the sort).
    input_txids: Vec<Txid>,
    /// Whether this transaction is valid (has proof or chains to proofs);
    /// read through [`is_valid`](Self::is_valid), set by the sort alone
    /// (`Beef.ts:1461` at `ts-stack@edf6e03`).
    is_valid: Option<bool>,
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
        };
        btx.update_input_txids();
        btx
    }

    /// Creates a BeefTx from raw transaction bytes.
    ///
    /// # Errors
    ///
    /// `Error::BeefError` for bytes that are not exactly one transaction
    /// (#817), with or without `bump_index`: cut short or malformed, in the
    /// words the reference's scan throws at the same read
    /// (`Serialized transaction exceeds available BEEF data`,
    /// `ReaderUint8Array read exceeds available data`, `non-canonical varInt`;
    /// `ts-stack@edf6e03` `BeefTx.ts:16-48`), or with bytes after the lock
    /// time, `Serialized transaction has N bytes after its lock time`. A raw
    /// entry has no length on the wire, so such bytes would misframe every
    /// element a writer wrote after them. The reference scans only where no
    /// index is given and reads a prefix (stated rows, the root `CLAUDE.md`);
    /// until #817 this kept the bytes and dropped the parse's failure.
    pub fn from_raw_tx(raw_tx: Vec<u8>, bump_index: Option<usize>) -> Result<Self> {
        super::beef_raw_frame::one_transaction(&raw_tx).map_err(crate::Error::BeefError)?;
        Ok(Self::from_framed_raw_tx(raw_tx, bump_index))
    }

    /// [`from_raw_tx`](Self::from_raw_tx) for bytes already framed as one
    /// transaction: `merge_beef`'s source entries, written and read back by
    /// its verdict before any is merged (#817).
    pub(crate) fn from_framed_raw_tx(raw_tx: Vec<u8>, bump_index: Option<usize>) -> Self {
        let mut btx = Self {
            bump_index,
            tx: None,
            raw_tx: Some(raw_tx),
            txid: None,
            input_txids: Vec::new(),
            is_valid: None,
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
        };
        btx.update_input_txids();
        btx
    }

    /// The entry with its txid in hand: the hash the decoder computed as
    /// the bytes passed, so [`txid`](Self::txid) does not serialize and hash
    /// the transaction again on each call (bsv-rs#86).
    #[must_use]
    pub(crate) fn with_txid(mut self, txid: Txid) -> Self {
        self.txid = Some(txid);
        self
    }

    /// The entry with the sort's word on it (`Beef::edit_tx` keeps it over
    /// an edit that moves nothing).
    #[must_use]
    pub(crate) fn with_valid(mut self, is_valid: Option<bool>) -> Self {
        self.is_valid = is_valid;
        self
    }

    /// Creates a BeefTx from just a transaction ID: a [`Txid`] since #843b
    /// (`BeefTx::from_txid(text.parse()?)`), where a text nothing checked was
    /// held until then and the writers refused it late.
    pub fn from_txid(txid: Txid) -> Self {
        Self {
            bump_index: None,
            tx: None,
            raw_tx: None,
            txid: Some(txid),
            input_txids: Vec::new(),
            is_valid: None,
        }
    }

    /// The txids this entry's inputs name, each once, in input order; none
    /// for an entry that names a BUMP or holds a txid alone. Read-only since
    /// #843b: the sort reads it, and a hand write of it moved the sort.
    pub fn input_txids(&self) -> &[Txid] {
        &self.input_txids
    }

    /// Whether the last sort found this entry valid (it has a proof);
    /// `None` before any sort. Read-only since #843b, set by
    /// [`Beef::sort_txs`](super::beef::Beef::sort_txs) alone.
    pub fn is_valid(&self) -> Option<bool> {
        self.is_valid
    }

    /// The sort's word on this entry.
    pub(crate) fn set_valid(&mut self, is_valid: Option<bool>) {
        self.is_valid = is_valid;
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

    /// Returns the transaction ID as a value (#843b; a `String` until
    /// then, which [`id`](Self::id) still gives): the one held, else the
    /// hash of the entry's transaction.
    #[allow(clippy::panic)] // #134: every constructor sets a transaction, raw bytes or a txid; a Result here is a breaking change
    pub fn txid(&self) -> Txid {
        if let Some(txid) = self.txid {
            return txid;
        }

        if let Some(ref tx) = self.tx {
            // A transaction's id is always its fields' hash (#843).
            return tx.txid();
        }

        if let Some(ref raw_tx) = self.raw_tx {
            // The double SHA-256 of the bytes is the txid in wire order.
            return Txid::from_wire_bytes(sha256d(raw_tx));
        }

        panic!("BeefTx has no transaction data or txid");
    }

    /// Returns the transaction ID as its display text, 64 lower-case hex
    /// digits: [`txid`](Self::txid)`.to_string()`, the pair
    /// [`Transaction`] has (`txid()` beside `id()`).
    pub fn id(&self) -> String {
        self.txid().to_string()
    }

    /// The parse this entry holds, if any: an entry held raw with a BUMP
    /// index is not parsed by the doors that build it, so this answers
    /// `None` for it until a door parses it (`trim_known_proven`, or an
    /// index set to none).
    pub fn tx(&self) -> Option<&Transaction> {
        self.tx.as_ref()
    }

    /// Stores `tx` as this entry's parse, every other member kept: for
    /// `Rows::swap_parse` alone, which has checked that `tx` is the
    /// transaction the entry holds (#843b; until then `BeefTx::tx_mut` lent
    /// the transaction and the entry waited for a refresh).
    pub(in crate::transaction) fn set_parse(&mut self, tx: Transaction) {
        self.tx = Some(tx);
    }

    /// The txid the entry holds, without hashing: the decoder's hash of the
    /// bytes it read (`collect.rs`), `merge_raw_tx`'s or `from_txid`'s.
    /// `None` for an entry built by the public `from_raw_tx` or `from_tx`
    /// (#621's fold: `merge_beef` hashes such an entry's bytes, never
    /// trusting `txid()`'s reading of its fields).
    pub(crate) fn held_txid(&self) -> Option<Txid> {
        self.txid
    }

    /// The bytes [`to_writer`](Self::to_writer) writes for the entry's
    /// transaction, as [`Beef::to_binary`](super::beef::Beef::to_binary)
    /// writes them: the held bytes, else the transaction's
    /// serialization; `None` for a txid-only entry. The snapshot form of an
    /// entry in `merge_beef` (#621's second fold).
    pub(crate) fn written_tx_bytes(&self) -> Option<std::borrow::Cow<'_, [u8]>> {
        if let Some(ref raw_tx) = self.raw_tx {
            return Some(std::borrow::Cow::Borrowed(raw_tx));
        }
        let tx = self.tx.as_ref()?;
        Some(std::borrow::Cow::Owned(tx.to_binary()))
    }

    /// A copy for the Atomic BEEF's closure naming `bump`: an entry held as
    /// bytes keeps this entry's input list, as the reference's copy of a
    /// `_rawTx` entry keeps `inputTxids` (`Beef.ts:464-465`); one held as a
    /// transaction alone has it read again with the new index, as
    /// `BeefTx.fromTx` reads it (`:466-467`; #798's fold).
    pub(in crate::transaction) fn atomic_copy(&self, bump: Option<usize>) -> Self {
        let mut copy = self.clone();
        copy.set_bump_index(bump);
        if self.held_raw() {
            copy.input_txids = self.input_txids.clone();
        }
        copy
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

    /// True when the entry holds bytes: the reference's
    /// `tx._rawTx != null`, the atomic copy's raw branch (`Beef.ts:464-465`).
    pub(crate) fn held_raw(&self) -> bool {
        self.raw_tx.is_some()
    }

    /// Returns the raw transaction bytes: the ones held, else the parsed
    /// transaction's serialization; `None` for an entry holding a txid
    /// alone. A read (`&self`) since #843b, keeping nothing: until then it
    /// took `&mut self` and kept the bytes it computed, which no door of a
    /// [`Beef`](super::beef::Beef) can lend an entry for any more.
    pub fn raw_tx_or_compute(&self) -> Option<Vec<u8>> {
        self.written_tx_bytes().map(std::borrow::Cow::into_owned)
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
            return tx.inputs().is_empty();
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
            return tx.outputs().is_empty();
        }
        match self.raw_tx {
            Some(ref raw_tx) => {
                matches!(Transaction::from_binary(raw_tx), Ok(tx) if tx.outputs().is_empty())
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
            self.input_txids = input_txids_of(tx);
        }
    }

    /// Reads a BeefTx from a Reader.
    pub fn from_reader(reader: &mut Reader, version: u32) -> Result<Self> {
        if version == BEEF_V2 {
            let format = reader.read_u8()?;

            match TxDataFormat::from_u8(format) {
                Some(TxDataFormat::TxidOnly) => {
                    // The 32 bytes on the wire are the txid in wire order.
                    let mut wire = [0u8; 32];
                    wire.copy_from_slice(reader.read_bytes(32)?);
                    Ok(Self::from_txid(Txid::from_wire_bytes(wire)))
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

/// The txids `tx`'s inputs name, each once, in input order.
fn input_txids_of(tx: &Transaction) -> Vec<Txid> {
    let mut seen = std::collections::HashSet::new();
    let mut txids = Vec::new();
    for input in tx.inputs() {
        // The txid the outpoint names: the input's own, else its linked
        // source's id (#869's third fold).
        if let Some(txid) = crate::transaction::transaction::outpoint_txid_name(input) {
            if seen.insert(txid) {
                txids.push(txid);
            }
        }
    }
    txids
}

/// A raw transaction at the reader: its parse and the bytes it took.
fn read_tx(reader: &mut Reader) -> Result<(Transaction, Vec<u8>)> {
    let tx_start = reader.position();
    let tx = Transaction::from_reader(reader)?;
    Ok((tx, reader.consumed_since(tx_start).to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::from_hex;

    // Simple P2PKH transaction hex
    const TEST_TX_HEX: &str = "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000";

    #[test]
    fn test_from_tx() {
        let tx = Transaction::from_hex(TEST_TX_HEX).unwrap();
        let beef_tx = BeefTx::from_tx(tx, None);
        assert!(!beef_tx.is_txid_only());
        assert!(!beef_tx.has_proof());
        assert_eq!(beef_tx.id().len(), 64);
    }

    #[test]
    fn test_from_raw_tx() {
        let raw_tx = from_hex(TEST_TX_HEX).unwrap();
        let beef_tx = BeefTx::from_raw_tx(raw_tx, Some(0)).expect("the bytes are one transaction");
        assert!(!beef_tx.is_txid_only());
        assert!(beef_tx.has_proof());
        assert_eq!(beef_tx.bump_index(), Some(0));
    }

    #[test]
    fn test_from_txid() {
        let txid = "abc123".repeat(11)[..64].to_string();
        let beef_tx = BeefTx::from_txid(txid.parse().unwrap());
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

    // #603: the surviving mutants of the widened oracle (run 41327640129),
    // each killed from the sibling's rule and vector or the reference's.

    /// The sibling's `corpus/chain/mempool/mempool.jsonl` row
    /// `regular-empty-inputs` (bsv-script-lean@387dab3), recorded
    /// `bad-txns-vin-empty` against the node: version 2, no input, one
    /// output.
    const REGULAR_EMPTY_INPUTS: &str = "0200000000018403000000000000015100000000";

    /// The same file's row `regular-empty-outputs`, recorded
    /// `bad-txns-vout-empty`: version 2, one input, no output.
    const REGULAR_EMPTY_OUTPUTS: &str = "020000000101010101010101010101010101010101010101010101010101010101010101010000000000ffffffff0000000000";

    /// `TEST_TX_HEX` is block 170's spend, the first transaction between two
    /// keys; its txid is a recorded chain fact.
    const TEST_TX_ID: &str = "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16";

    /// An entry of `hex`'s bytes as the BEEF reader holds them: raw bytes
    /// alone under a BUMP index (the proven entry is not parsed), and the
    /// bytes parsed without one.
    fn raw_and_parsed(hex: &str) -> [BeefTx; 2] {
        let raw = from_hex(hex).unwrap();
        let proven =
            BeefTx::from_raw_tx(raw.clone(), Some(0)).expect("the bytes are one transaction");
        assert!(
            proven.tx().is_none(),
            "a proven entry keeps its bytes alone"
        );
        let unproven = BeefTx::from_raw_tx(raw, None).expect("the bytes are one transaction");
        assert!(unproven.tx().is_some(), "an unproven entry is parsed");
        [proven, unproven]
    }

    /// bsv-script-lean@387dab3 `lean/BsvScript/TxRules.lean:88`
    /// (`checkTransactionCommon`: `if tx.inputs.isEmpty then throw .vinEmpty`,
    /// before the output check at `:89`; `checkTransactionCommon_vinEmpty`,
    /// `:220-224`), the vector `regular-empty-inputs` of `corpus/chain/mempool`
    /// recorded `bad-txns-vin-empty`: the entry has no input and is not the
    /// no-output case, read from its bytes and from its parse.
    #[test]
    fn vin_empty_is_has_no_inputs_txrules_chain_mempool_regular_empty_inputs() {
        for entry in raw_and_parsed(REGULAR_EMPTY_INPUTS) {
            assert!(entry.has_no_inputs(), "bad-txns-vin-empty");
            assert!(!entry.has_no_outputs(), "vin-empty is judged first");
        }
    }

    /// bsv-script-lean@387dab3 `lean/BsvScript/TxRules.lean:89`
    /// (`if tx.outputs.isEmpty then throw .voutEmpty`, behind the input
    /// check; `checkTransactionCommon_voutEmpty`, `:227-231`), the vector
    /// `regular-empty-outputs` of `corpus/chain/mempool` recorded
    /// `bad-txns-vout-empty`: one input, so not `has_no_inputs`, and no
    /// output, read from its bytes and from its parse.
    #[test]
    fn vout_empty_is_has_no_outputs_txrules_chain_mempool_regular_empty_outputs() {
        for entry in raw_and_parsed(REGULAR_EMPTY_OUTPUTS) {
            assert!(!entry.has_no_inputs(), "one input");
            assert!(entry.has_no_outputs(), "bad-txns-vout-empty");
        }
    }

    /// The same rule on a transaction it accepts at both checks
    /// (`TxRules.lean:88-89`): one input and two outputs, so neither; and a
    /// txid-only entry, which has no bytes for the rule to read.
    #[test]
    fn a_transaction_with_inputs_and_outputs_is_neither_txrules_check_transaction_common() {
        for entry in raw_and_parsed(TEST_TX_HEX) {
            assert!(!entry.has_no_inputs());
            assert!(!entry.has_no_outputs());
        }
        let known = BeefTx::from_txid(TEST_TX_ID.to_string().parse().unwrap());
        assert!(!known.has_no_inputs());
        assert!(!known.has_no_outputs());
    }

    /// `ts-stack@edf6e03` `BeefTx.ts:105-116`: an entry's txid is the held one
    /// or the hash of its transaction, whether the txid is held (a txid-only
    /// entry, a read entry) or not (an entry built from a transaction or
    /// bytes); `id()` is its display text (#843b: the comparison was
    /// `has_txid`, on text, until then).
    #[test]
    fn the_entry_txid_is_held_or_hashed_beef_tx_ts_105_116() {
        let tx = Transaction::from_hex(TEST_TX_HEX).unwrap();
        let named: Txid = TEST_TX_ID.parse().unwrap();
        let other: Txid = "00".repeat(32).parse().unwrap();
        let entries = [
            BeefTx::from_tx(tx, None),
            BeefTx::from_raw_tx(from_hex(TEST_TX_HEX).unwrap(), Some(0))
                .expect("the bytes are one transaction"),
            BeefTx::from_txid(named),
        ];
        for entry in entries {
            assert_eq!(entry.txid(), named);
            assert_eq!(entry.id(), TEST_TX_ID);
            assert_eq!(entry.txid(), TEST_TX_ID.to_uppercase(), "either case");
            assert!(entry.txid() != other);
        }
    }

    /// `ts-stack@edf6e03` `BeefTx.ts:144-151` (`getRawTxBytes`): the bytes
    /// held, else the parsed transaction's serialization; a txid-only
    /// entry has none. A read since #843b: the reference keeps the bytes it
    /// computes, and this crate kept them until then (`&mut self`); nothing
    /// is kept now, so an entry held as a transaction stays one (the atomic
    /// copy's branch, the root `CLAUDE.md`'s #798 row).
    #[test]
    fn raw_tx_or_compute_is_the_held_bytes_or_the_serialization_beef_tx_ts_144_151() {
        let raw = from_hex(TEST_TX_HEX).unwrap();
        let read =
            BeefTx::from_raw_tx(raw.clone(), Some(0)).expect("the bytes are one transaction");
        assert_eq!(read.raw_tx_or_compute(), Some(raw.clone()));

        let built = BeefTx::from_tx(Transaction::from_hex(TEST_TX_HEX).unwrap(), None);
        assert_eq!(built.raw_tx(), None);
        assert_eq!(built.raw_tx_or_compute(), Some(raw.clone()));
        assert_eq!(built.raw_tx(), None, "nothing kept");
        assert!(!built.held_raw());

        let known = BeefTx::from_txid(TEST_TX_ID.parse().unwrap());
        assert_eq!(known.raw_tx_or_compute(), None);
    }

    /// `ts-stack@edf6e03` `BeefTx.ts:218-233` (`updateInputTxids`, a `Set` of
    /// the inputs' source txids) and `:31-33` (the reader's scan, the same
    /// `Set`): two inputs spending two outputs of one parent name it once.
    /// The entry is the crate's writer's bytes, read as the BEEF reader reads
    /// an unproven entry.
    #[test]
    fn two_inputs_of_one_parent_name_it_once_beef_tx_ts_218_233() {
        use crate::script::{LockingScript, UnlockingScript};
        use crate::transaction::{TransactionInput, TransactionOutput};
        let parent = "e5".repeat(32);
        let mut tx = Transaction::new();
        for vout in 0..2 {
            let mut input = TransactionInput::new(parent.parse().unwrap(), vout);
            input.unlocking_script = Some(UnlockingScript::from_binary(&[]).unwrap());
            tx.inputs_mut().push(input);
        }
        tx.outputs_mut().push(TransactionOutput::new(
            1_000,
            LockingScript::from_binary(&[0x51]).unwrap(),
        ));
        let mut bytes = tx.to_binary();
        bytes.push(0); // V1: no BUMP index
        let entry = BeefTx::from_reader(&mut Reader::new(&bytes), BEEF_V1).unwrap();
        assert_eq!(entry.input_txids, vec![parent.clone()]);
        assert_eq!(BeefTx::from_tx(tx, None).input_txids, vec![parent]);
    }

    // #843b removed `a_transaction_mutated_through_tx_mut_is_the_entry_reading_
    // beef_tx_ts_160_177`: `BeefTx::tx_mut` and its `refresh` are gone, so no
    // entry is mutated in place. The reference's sync
    // (`syncRawTxFromTransaction`, `BeefTx.ts:160-177`) is `Beef::edit_tx`'s
    // eager repair, pinned by `tests/beef_edit_door_817.rs`; that `tx_mut`
    // does not compile is `beef/rows.rs`' `compile_fail` doc test.
}
