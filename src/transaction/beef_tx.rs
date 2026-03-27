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
                    let tx = Transaction::from_reader_internal(reader)?;
                    let raw_tx = reader.consumed_since(tx_start).to_vec();
                    let mut btx = Self::from_raw_tx(raw_tx, Some(bump_index));
                    btx.tx = Some(tx);
                    btx.update_input_txids();
                    Ok(btx)
                }
                Some(TxDataFormat::RawTx) | None => {
                    let tx_start = reader.position();
                    let tx = Transaction::from_reader_internal(reader)?;
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
            let tx = Transaction::from_reader_internal(reader)?;
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
