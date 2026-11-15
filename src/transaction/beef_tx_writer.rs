//! `BeefTx`'s writer and its check (#817): `to_writer` refuses, before any
//! byte, an entry its layout cannot carry faithfully; `Beef`'s writers run
//! the same checks over every entry (`beef_writable.rs`).

use super::{BeefTx, TxDataFormat, BEEF_V2};
use crate::primitives::Writer;
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
    /// an entry whose written bytes
    /// are not one transaction, held raw or parsed with a cache holding a
    /// transaction and more (#621's fold; [`from_raw_tx`](Self::from_raw_tx)'s
    /// words). Until #817 a txid-only entry
    /// under a word other than V2 panicked. A txid-only entry's txid is a
    /// [`Txid`](crate::transaction::Txid) since #843b, so the three refusals
    /// of a text that is no txid (empty, a non-hex character, another
    /// length) have no state left to refuse and are gone.
    pub fn to_writer(&self, writer: &mut Writer, version: u32) -> Result<()> {
        self.writable(version)?;
        self.write_unchecked(writer, version);
        Ok(())
    }

    /// The refusals of [`to_writer`](Self::to_writer), in the order the
    /// reference meets them, read-only: [`reference_refusal`](Self::reference_refusal),
    /// then [`own_refusal`](Self::own_refusal).
    pub(crate) fn writable(&self, version: u32) -> Result<()> {
        self.amount_refusal()?;
        self.reference_refusal(version)?;
        self.own_refusal()
    }

    /// An entry holding a transaction (parsed, edited, or built by hand and
    /// pushed) with an output amount of 2^53 or more, refused in the
    /// reference's writer's words, `The number is larger than 2 ^ 53
    /// (unsafe)` (#844's fold; `BigNumber.ts:462`, recorded), as its writer
    /// throws serializing the entry's `Transaction` before any other check
    /// (`Beef.ts:360-373`, `BeefTx.ts:255-262`). Every output is read, the
    /// first, a middle and the last alike. A transaction a reader built holds
    /// no such amount (the readers refuse it in theirs, #844), so the state
    /// is a field-built one; an entry held as bytes alone is the raw-entry
    /// scan's, in the reader's words (`own_refusal`), and no door builds
    /// such bytes.
    pub(crate) fn amount_refusal(&self) -> Result<()> {
        if let Some(ref tx) = self.tx {
            for output in tx.outputs() {
                if super::super::amount::safe_amount(output.satoshis.unwrap_or(0)).is_err() {
                    return Err(crate::Error::BeefError(
                        super::super::amount::UNSAFE_WRITE.to_string(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// What the reference's writer throws for this entry (#817): a txid-only
    /// entry under a word other than V2, `a valid serialized Transaction is
    /// expected` (`BeefTx.ts:253-258`: its BRC-62 layout has no form for a
    /// txid). Its throw for a txid with a character that is not a hex digit
    /// (`toArray(txid, 'hex')`, `hex.ts:6-17`) has no state here since
    /// #843b: the txid is a `Txid`.
    pub(crate) fn reference_refusal(&self, version: u32) -> Result<()> {
        if self.is_txid_only() && version != BEEF_V2 {
            return Err(crate::Error::BeefError(RAW_TX_EXPECTED.to_string()));
        }
        Ok(())
    }

    /// What this crate refuses where the reference writes bytes no reader
    /// reads back as written (#817, stated rows):
    /// an entry with data whose written bytes are not exactly one
    /// transaction (`from_raw_tx`'s words; its constructor scans them too).
    /// A txid-only entry's txid of other than 64 hex digits, refused here
    /// until #843b, cannot be held since (a `Txid`).
    /// The bytes judged are the ones [`written_tx_bytes`](Self::written_tx_bytes)
    /// gives, held with a parse or without (#621's fold): the held bytes,
    /// else the transaction's cached serialization (since #840 one
    /// transaction from every door that sets it; until then
    /// `Transaction::from_binary` and `from_hex` set it to the whole buffer
    /// they read a prefix of, the check holding without that fix), else
    /// the fields the bytes are written from: a serialization built from
    /// them is one transaction by construction save an output amount of
    /// 2^53 or more, which the reader refuses since #844 and
    /// [`amount_refusal`](Self::amount_refusal) refuses ahead of every check,
    /// in the reference's writer's words (`fuzz_beef_parser` found the
    /// state on its seeds, a hand-built transaction merged by
    /// `merge_transaction`, which the round trip refused and the pre-pass
    /// passed to the merge; refused here in the scan's words until #844's
    /// fold). Until the
    /// fold a parsed entry was not scanned, so one holding a transaction
    /// followed by more bytes was written as a frame the reader refuses and
    /// merged by `merge_beef`. Linear, no allocation.
    pub(crate) fn own_refusal(&self) -> Result<()> {
        if let Some(ref raw_tx) = self.raw_tx {
            super::super::beef_raw_frame::one_transaction(raw_tx)
                .map_err(crate::Error::BeefError)?;
        } else if let Some(ref tx) = self.tx {
            let cached = tx.with_cached_bytes(|bytes| {
                bytes.map(super::super::beef_raw_frame::one_transaction)
            });
            // Written from the fields: one transaction by construction save
            // an amount of 2^53 or more, which `amount_refusal` refuses ahead
            // of this check, in the reference's writer's words (#844's fold).
            if let Some(scanned) = cached {
                scanned.map_err(crate::Error::BeefError)?;
            }
        }
        Ok(())
    }

    /// The bytes of an entry [`writable`](Self::writable) accepted under
    /// `version`, as 0.9.0-beta wrote them; for `to_writer` and `Beef`'s
    /// writers, each after the check. The transaction's bytes are
    /// [`written_tx_bytes`](Self::written_tx_bytes), the ones the check
    /// judged and `merge_beef` merges (#621's fold). An entry with nothing to write
    /// (a txid-only one, which the check refuses outside V2) writes no
    /// transaction bytes: the check is the guard, no panic is left (#817).
    pub(crate) fn write_unchecked(&self, writer: &mut Writer, version: u32) {
        if version == BEEF_V2 {
            if self.is_txid_only() {
                // TXID only format: the txid's 32 bytes in wire order.
                writer.write_u8(TxDataFormat::TxidOnly as u8);
                writer.write_bytes(self.txid().as_wire_bytes());
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

    /// Writes the transaction data (`written_tx_bytes`); nothing for a
    /// txid-only entry, which the writers' check keeps from here (#817).
    fn write_tx_data(&self, writer: &mut Writer) {
        if let Some(bytes) = self.written_tx_bytes() {
            writer.write_bytes(&bytes);
        }
    }
}
