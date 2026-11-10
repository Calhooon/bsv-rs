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

use super::beef_stream::Kind;
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
    pub fn from_raw_tx(raw_tx: Vec<u8>, bump_index: Option<usize>) -> Self {
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

    /// Creates a BeefTx from just a transaction ID.
    pub fn from_txid(txid: String) -> Self {
        Self {
            bump_index: None,
            tx: None,
            raw_tx: None,
            txid: Some(txid),
            input_txids: Vec::new(),
            is_valid: None,
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

    /// Returns a mutable reference to the parsed transaction.
    pub fn tx_mut(&mut self) -> Option<&mut Transaction> {
        // Ensure we have a parsed transaction
        if self.tx.is_none() && self.raw_tx.is_some() {
            if let Some(ref raw_tx) = self.raw_tx {
                if let Ok(tx) = Transaction::from_binary(raw_tx) {
                    self.tx = Some(tx);
                }
            }
        }
        self.tx.as_mut()
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

    /// The one predicate of #852: `Err` with the kind of the entry's raw
    /// bytes when they are not exactly one transaction by the strict parse
    /// ([`Transaction::from_binary`]), else `Ok` with whether the entry's
    /// transaction has no output (`false` for a txid-only entry). One parse
    /// of raw bytes, none for a parsed transaction or a txid-only entry.
    ///
    /// Such an entry is held unparsed: `from_raw_tx` returns no `Result` on
    /// this line, so the bytes are refused at the verdict, never answered
    /// valid by [`Beef::sort_txs`](super::beef::Beef::sort_txs),
    /// [`Beef::verify_structure`](super::beef::Beef::verify_structure),
    /// `verify_valid` or `is_valid`; both doors read this and nothing else.
    /// The kind is the streaming reader's for the same bytes: `TrailingBytes`
    /// for a transaction with bytes after it, `BadVarint` where they end
    /// inside a varint or hold a non-canonical one, `Truncated` where they
    /// end inside a fixed field or a script.
    pub(crate) fn strict_read(&self) -> std::result::Result<bool, Kind> {
        match (&self.tx, &self.raw_tx) {
            (Some(tx), _) => Ok(tx.outputs.is_empty()),
            (None, Some(raw)) => match Transaction::from_binary(raw) {
                Ok(tx) => Ok(tx.outputs.is_empty()),
                Err(_) => Err(frame_kind(raw)),
            },
            (None, None) => Ok(false),
        }
    }

    /// The verdict doors' reading of the entry on
    /// [`strict_read`](Self::strict_read): which of `NoInputs`, the
    /// held kind and `NoOutputs` applies, in that order, and whether the
    /// entry is held. A held entry whose four bytes of version are followed
    /// by an input count of 0 is `NoInputs`, as 0.8.3 named it; one
    /// transaction is never held.
    pub(crate) fn structure_kind(&self) -> (Option<Kind>, bool) {
        let reading = self.strict_read();
        let kind = if self.has_no_inputs() {
            Some(Kind::NoInputs)
        } else {
            match reading {
                Err(held) => Some(held),
                Ok(no_outputs) => no_outputs.then_some(Kind::NoOutputs),
            }
        };
        (kind, reading.is_err())
    }

    /// Updates the input_txids list based on transaction data.
    fn update_input_txids(&mut self) {
        if self.has_proof() {
            // If we have a proof, we don't need to track input txids
            self.input_txids = Vec::new();
            return;
        }

        // Parse transaction if we have raw bytes but not parsed
        if self.tx.is_none() && self.raw_tx.is_some() {
            if let Some(ref raw_tx) = self.raw_tx {
                if let Ok(tx) = Transaction::from_binary(raw_tx) {
                    self.tx = Some(tx);
                }
            }
        }

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
                    let tx_start = reader.position();
                    let tx = Transaction::from_reader(reader)?;
                    let raw_tx = reader.consumed_since(tx_start).to_vec();
                    let mut btx = Self::from_raw_tx(raw_tx, Some(bump_index));
                    btx.tx = Some(tx);
                    btx.update_input_txids();
                    Ok(btx)
                }
                Some(TxDataFormat::RawTx) | None => {
                    let tx_start = reader.position();
                    let tx = Transaction::from_reader(reader)?;
                    let raw_tx = reader.consumed_since(tx_start).to_vec();
                    let mut btx = Self::from_raw_tx(raw_tx, None);
                    btx.tx = Some(tx);
                    btx.update_input_txids();
                    Ok(btx)
                }
            }
        } else {
            // V1 format
            let tx_start = reader.position();
            let tx = Transaction::from_reader(reader)?;
            let raw_tx = reader.consumed_since(tx_start).to_vec();
            let has_bump = reader.read_u8()? != 0;
            let bump_index = if has_bump {
                Some(reader.read_var_int_num()?)
            } else {
                None
            };
            let mut btx = Self::from_raw_tx(raw_tx, bump_index);
            btx.tx = Some(tx);
            btx.update_input_txids();
            Ok(btx)
        }
    }
}

/// Where bytes that do not parse as one transaction go wrong, field by field
/// as the streaming reader reads a transaction (`beef_stream`'s `finish`):
/// bytes that end inside a varint, or a varint wider than it needs, are
/// `BadVarint`; bytes that end inside a fixed field or a script are
/// `Truncated`; a whole transaction followed by more is `TrailingBytes`.
fn frame_kind(raw: &[u8]) -> Kind {
    fn fixed(r: &mut Reader, n: usize) -> std::result::Result<(), Kind> {
        r.read_bytes(n).map(|_| ()).map_err(|_| Kind::Truncated)
    }
    fn varint(r: &mut Reader) -> std::result::Result<u64, Kind> {
        r.read_var_int().map_err(|_| Kind::BadVarint)
    }
    fn run(r: &mut Reader, len: u64) -> std::result::Result<(), Kind> {
        usize::try_from(len).map_or(Err(Kind::Truncated), |n| fixed(r, n))
    }
    let mut r = Reader::new(raw);
    let walk = |r: &mut Reader| -> std::result::Result<(), Kind> {
        fixed(r, 4)?;
        for _ in 0..varint(r)? {
            fixed(r, 36)?;
            let len = varint(r)?;
            run(r, len)?;
            fixed(r, 4)?;
        }
        for _ in 0..varint(r)? {
            fixed(r, 8)?;
            let len = varint(r)?;
            run(r, len)?;
        }
        fixed(r, 4)
    };
    match walk(&mut r) {
        Err(kind) => kind,
        Ok(()) if !r.is_empty() => Kind::TrailingBytes,
        // The walk reads every field the strict parse reads; a parse that
        // failed where the walk did not ran out where the walk did not.
        Ok(()) => Kind::Truncated,
    }
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

    /// #840 on the stable line, #852's fold: raw bytes with a byte after the
    /// transaction are held unparsed (no `tx()`, no input txids), their txid
    /// the hash of the bytes given, and are refused at the verdict as
    /// `TrailingBytes`. The reference's `BeefTx` keeps such bytes at
    /// construction too, its inputs read from the prefix (`BeefTx.ts:52-54`,
    /// `:234-235`); only its lazy `tx` getter refuses them (`:118-121`).
    #[test]
    fn a_raw_entry_with_a_trailing_byte_is_held_unparsed_840() {
        let mut raw_tx = from_hex(TEST_TX_HEX).unwrap();
        raw_tx.push(0);
        let mut reversed = sha256d(&raw_tx);
        reversed.reverse();
        let mut beef_tx = BeefTx::from_raw_tx(raw_tx.clone(), None);
        assert!(beef_tx.tx().is_none());
        assert!(beef_tx.input_txids.is_empty());
        assert_eq!(beef_tx.txid(), to_hex(&reversed));
        assert_eq!(beef_tx.raw_tx(), Some(raw_tx.as_slice()));
        assert!(!beef_tx.has_no_outputs());
        assert_eq!(beef_tx.strict_read().err(), Some(Kind::TrailingBytes));
        assert_eq!(beef_tx.structure_kind(), (Some(Kind::TrailingBytes), true));
        assert!(beef_tx.tx_mut().is_none());
        let mut beef = super::super::beef::Beef::new();
        beef.merge_raw_tx(raw_tx, None);
        assert_eq!(beef.verify_structure(), Err(Kind::TrailingBytes));
    }

    /// The held kind is the streaming reader's for the same bytes (#852): at
    /// every cut of a transaction, and for it with bytes after it, the kind
    /// equals the one `verify_stream` gives a BEEF that holds those bytes as
    /// its last element.
    #[test]
    fn the_held_kind_is_the_stream_kind_at_every_cut_852() {
        use crate::transaction::beef_stream::{verify_stream_structure, Verdict};
        let tx = from_hex(TEST_TX_HEX).unwrap();
        let mut forty = from_hex("01000000fd0100").unwrap();
        forty.resize(40, 0);
        let shapes = (0..tx.len())
            .map(|n| tx[..n].to_vec())
            .chain([forty, [tx.clone(), vec![0]].concat()]);
        let mut seen = std::collections::HashSet::new();
        for raw in shapes {
            let held = BeefTx::from_raw_tx(raw.clone(), Some(0))
                .strict_read()
                .err();
            let kind = held.unwrap_or_else(|| panic!("{} bytes held as one", raw.len()));
            seen.insert(kind);
            // BEEF V2, no BUMP, one raw entry (format 0) holding the bytes.
            let mut frame = vec![0x02, 0x00, 0xbe, 0xef, 0, 1, 0];
            frame.extend_from_slice(&raw);
            let verdict =
                verify_stream_structure(&frame[..], std::collections::HashMap::new(), None)
                    .unwrap();
            let stream = match verdict {
                Verdict::Invalid { kind, .. } => kind,
                other => panic!("{} bytes: {other:?}", raw.len()),
            };
            if kind != Kind::TrailingBytes {
                assert_eq!(kind, stream, "{} bytes", raw.len());
            }
        }
        let want = [Kind::Truncated, Kind::BadVarint, Kind::TrailingBytes];
        assert_eq!(seen, want.into_iter().collect());
    }

    /// The predicate is the strict parse (#852): `strict_read` names a kind
    /// exactly when `Transaction::from_binary` refuses the same bytes, with
    /// and without a BUMP index, and the kind is the streaming reader's
    /// wherever the stream names `Truncated`, `BadVarint` or `TrailingBytes`
    /// for a BEEF holding those bytes as its one raw entry. Over every
    /// single-byte change, cut, one-byte extension, insertion and deletion of
    /// the transactions of `tests/transaction/vectors/tx_valid.rs`,
    /// `bigtx.rs`, `beef_cross_sdk.rs` and `tests/vectors/beef_held_entry_852.json`,
    /// and over 4,096 byte strings from a fixed seed.
    #[test]
    fn the_held_kind_is_exactly_the_strict_parse_refusal_852() {
        use crate::transaction::beef::Beef;
        use crate::transaction::beef_stream::{verify_stream_structure, Verdict};
        let sources = [
            include_str!("../../tests/transaction/vectors/tx_valid.rs"),
            include_str!("../../tests/transaction/vectors/bigtx.rs"),
            include_str!("../../tests/transaction/vectors/beef_cross_sdk.rs"),
            include_str!("../../tests/vectors/beef_held_entry_852.json"),
        ];
        let mut txs: Vec<Vec<u8>> = Vec::new();
        for hex in sources.iter().flat_map(|s| s.split('"').skip(1).step_by(2)) {
            if let Ok(tx) = Transaction::from_hex(hex) {
                txs.push(tx.to_binary());
            } else if let Ok(beef) = Beef::from_hex(hex) {
                txs.extend(
                    beef.txs
                        .iter()
                        .filter_map(|t| t.raw_tx().map(<[u8]>::to_vec)),
                );
            }
        }
        let mut seen = std::collections::HashSet::new();
        txs.retain(|t| seen.insert(t.clone()));
        assert!(txs.len() >= 10, "{} transactions", txs.len());
        let mut compared = std::collections::HashMap::new();
        let mut count = 0usize;
        let mut trailing = 0usize;
        let mut check = |raw: &[u8]| {
            count += 1;
            let refused = Transaction::from_binary(raw).is_err();
            let entry = BeefTx::from_raw_tx(raw.to_vec(), None);
            let kind = entry.strict_read().err();
            assert_eq!(kind.is_some(), refused, "{}", to_hex(raw));
            assert_eq!(entry.structure_kind().1, refused, "{}", to_hex(raw));
            let proven = BeefTx::from_raw_tx(raw.to_vec(), Some(0))
                .strict_read()
                .err();
            assert_eq!(proven, kind, "{}", to_hex(raw));
            let mut frame = vec![0x02, 0x00, 0xbe, 0xef, 0, 1, 0];
            frame.extend_from_slice(raw);
            let headers = std::collections::HashMap::new();
            if let Verdict::Invalid { kind: stream, .. } =
                verify_stream_structure(&frame[..], headers, None).unwrap()
            {
                if matches!(
                    stream,
                    Kind::Truncated | Kind::BadVarint | Kind::TrailingBytes
                ) {
                    assert_eq!(kind, Some(stream), "{}", to_hex(raw));
                    *compared.entry(stream).or_insert(0usize) += 1;
                }
            }
        };
        for tx in &txs {
            for i in 0..tx.len() {
                for v in (0..=255u8).filter(|&v| v != tx[i]) {
                    let mut m = tx.clone();
                    m[i] = v;
                    check(&m);
                }
                let mut m = tx.clone();
                m.remove(i);
                check(&m);
                check(&tx[..i]);
            }
            for v in 0..=255u8 {
                let raw = [&tx[..], &[v]].concat();
                check(&raw);
                // Proven by a BUMP of the prefix, the stream reaches the byte.
                let prefix = Transaction::from_binary(tx).unwrap().id();
                let bump = crate::transaction::MerklePath::from_coinbase_txid(&prefix, 1);
                let mut tracker = crate::transaction::MockChainTracker::new(1);
                tracker.add_root(1, bump.compute_root(None).unwrap());
                let mut beef = Beef::new();
                beef.merge_bump(bump);
                beef.merge_raw_tx(raw.clone(), Some(0));
                let held = BeefTx::from_raw_tx(raw, Some(0)).strict_read().err();
                let bytes = beef.to_binary();
                match verify_stream_structure(&bytes[..], &tracker, None).unwrap() {
                    Verdict::Invalid { kind, .. } => assert_eq!(held, Some(kind)),
                    other => panic!("{other:?}"),
                }
                trailing += 1;
            }
            for i in 0..=tx.len() {
                for v in [0x00, 0x01, 0xfc, 0xfd, 0xfe, 0xff] {
                    let mut m = tx.clone();
                    m.insert(i, v);
                    check(&m);
                }
            }
        }
        let mut state = 0x852u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for n in 0..4096u64 {
            let mut m = if n % 2 == 0 {
                Vec::new()
            } else {
                txs[(next() % txs.len() as u64) as usize].clone()
            };
            if n % 2 == 0 {
                m.extend((0..next() % 80).map(|_| next() as u8));
            } else {
                for _ in 0..1 + next() % 4 {
                    let i = (next() % (m.len() as u64 + 1)) as usize;
                    match next() % 3 {
                        0 if i < m.len() => m[i] = next() as u8,
                        1 => m.insert(i, next() as u8),
                        _ => m.truncate(i),
                    }
                }
            }
            check(&m);
        }
        *compared.entry(Kind::TrailingBytes).or_insert(0) += trailing;
        assert_eq!(compared.len(), 3, "{compared:?}");
        assert!(count > 600_000, "{count} inputs");
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
