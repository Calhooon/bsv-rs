//! `BeefTx`'s writer and its check (#817): `to_writer` refuses, before any
//! byte, an entry its layout cannot carry faithfully; `Beef`'s writers run
//! the same checks over every entry (`beef_writable.rs`).

use super::{BeefTx, TxDataFormat, BEEF_V2};
use crate::primitives::{from_hex, Writer};
use crate::Result;

/// The reference writer's refusal of a txid-only entry outside V2
/// (`ts-stack@edf6e03` `BeefTx.ts:253-258`, #817).
pub(crate) const RAW_TX_EXPECTED: &str = "a valid serialized Transaction is expected";

impl BeefTx {
    /// Writes this BeefTx to a Writer, in `version`'s layout: BRC-96's
    /// (`TxDataFormat` byte) under [`BEEF_V2`], BRC-62's under any other word,
    /// as the reference's `toWriter` writes it (`ts-stack@edf6e03`
    /// `BeefTx.ts:240-285`).
    ///
    /// # Errors
    ///
    /// `Error::BeefError` for an entry the layout cannot carry faithfully
    /// (#817), judged before any byte, so `writer` is untouched on `Err`: a
    /// txid-only entry under a word other than V2 (`a valid serialized
    /// Transaction is expected`, the reference's words, `BeefTx.ts:253-258`),
    /// a txid-only txid with a non-hex character (`Invalid hex string`, the
    /// reference's) or of other than 64 hex digits (`Invalid txid-only entry
    /// txid: expected 64 hex digits, got N`), a raw entry held without its
    /// parse whose bytes are not one transaction
    /// ([`from_raw_tx`](Self::from_raw_tx)'s words). Until #817 a txid-only entry
    /// under a word other than V2 panicked, and a txid of other than 64 hex
    /// digits was written as the bytes it decoded to, or none.
    pub fn to_writer(&self, writer: &mut Writer, version: u32) -> Result<()> {
        self.writable(version)?;
        self.write_unchecked(writer, version, false);
        Ok(())
    }

    /// The refusals of [`to_writer`](Self::to_writer), in the order the
    /// reference meets them, read-only: [`reference_refusal`](Self::reference_refusal),
    /// then [`own_refusal`](Self::own_refusal).
    pub(crate) fn writable(&self, version: u32) -> Result<()> {
        self.reference_refusal(version)?;
        self.own_refusal()
    }

    /// What the reference's writer throws for this entry (#817): a txid-only
    /// entry under a word other than V2, `a valid serialized Transaction is
    /// expected` (`BeefTx.ts:253-258`: its BRC-62 layout has no form for a
    /// txid); one under V2 whose txid has a character that is not a hex
    /// digit, `Invalid hex string` (`toArray(txid, 'hex')`, `hex.ts:6-17`).
    /// A txid-only entry whose txid is empty is refused ahead of every BUMP by
    /// `Beef`'s check (`empty_txid`).
    pub(crate) fn reference_refusal(&self, version: u32) -> Result<()> {
        if !self.is_txid_only() {
            return Ok(());
        }
        if version != BEEF_V2 {
            return Err(crate::Error::BeefError(RAW_TX_EXPECTED.to_string()));
        }
        if !super::super::merkle_path_walk::is_reference_hex(&self.txid()) {
            return Err(crate::Error::BeefError(
                super::super::merkle_path_walk::INVALID_HEX.to_string(),
            ));
        }
        Ok(())
    }

    /// What this crate refuses where the reference writes bytes no reader
    /// reads back as written (#817, stated rows): a txid-only entry's txid of
    /// other than 64 hex digits (the reference writes its bytes at their
    /// length, or pads an odd length with a leading zero, a txid of another
    /// text: `Invalid txid-only entry txid: expected 64 hex digits, got N`);
    /// a raw entry held without its parse whose bytes are not exactly one
    /// transaction (`from_raw_tx`'s words; its constructor scans them too).
    pub(crate) fn own_refusal(&self) -> Result<()> {
        if self.is_txid_only() {
            let digits = self.txid().len();
            if digits != 64 {
                return Err(crate::Error::BeefError(format!(
                    "Invalid txid-only entry txid: expected 64 hex digits, got {digits}"
                )));
            }
        } else if self.tx.is_none() {
            if let Some(ref raw_tx) = self.raw_tx {
                super::super::beef_raw_frame::one_transaction(raw_tx)
                    .map_err(crate::Error::BeefError)?;
            }
        }
        Ok(())
    }

    /// A txid-only entry whose txid is the empty text: the reference's
    /// `txid` getter throws `Internal` for it (`BeefTx.ts:105-116`), reached
    /// by `#ensureSerializableState` ahead of the BUMPs (`Beef.ts:334-340`,
    /// `:368`), so `Beef`'s check refuses it there, in `own_refusal`'s words.
    pub(crate) fn empty_txid(&self) -> bool {
        self.is_txid_only() && self.txid.as_deref() == Some("")
    }

    /// The bytes of an entry [`writable`](Self::writable) accepted under
    /// `version`, as 0.9.0-beta wrote them; for `to_writer` and `Beef`'s
    /// writers, each after the check. `as_merged` writes a parsed
    /// transaction's bytes as `merge_beef` merges them
    /// ([`written_tx_bytes`](Self::written_tx_bytes)), for its verdict. An entry with nothing to write (a
    /// txid-only one, which the check refuses outside V2) writes no
    /// transaction bytes: the check is the guard, no panic is left (#817).
    pub(crate) fn write_unchecked(&self, writer: &mut Writer, version: u32, as_merged: bool) {
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
                self.write_tx_data(writer, as_merged);
            } else {
                // Raw tx without bump index
                writer.write_u8(TxDataFormat::RawTx as u8);
                self.write_tx_data(writer, as_merged);
            }
        } else {
            // V1 format
            self.write_tx_data(writer, as_merged);
            if let Some(bump_idx) = self.bump_index {
                writer.write_u8(1);
                writer.write_var_int(bump_idx as u64);
            } else {
                writer.write_u8(0);
            }
        }
    }

    /// Writes the transaction data (raw bytes or serialized); nothing for a
    /// txid-only entry, which the writers' check keeps from here (#817).
    fn write_tx_data(&self, writer: &mut Writer, as_merged: bool) {
        if as_merged {
            if let Some(bytes) = self.written_tx_bytes() {
                writer.write_bytes(&bytes);
            }
        } else if let Some(ref raw_tx) = self.raw_tx {
            writer.write_bytes(raw_tx);
        } else if let Some(ref tx) = self.tx {
            writer.write_bytes(&tx.to_binary());
        }
    }
}
