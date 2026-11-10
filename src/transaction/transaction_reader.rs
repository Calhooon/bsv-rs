//! `Transaction`'s reader door (#840): the reference's `fromReader`, one
//! transaction from the front of a reader, and the words the whole readers
//! (`from_binary`, `from_hex`, `from_ef`, `from_hex_ef`,
//! `parse_script_offsets`, in `transaction.rs`) refuse bytes after it in.
//! A child file of `transaction.rs` on the stable line, whose line ceiling
//! the fix would otherwise raise.

use super::input::TransactionInput;
use super::output::TransactionOutput;
use super::transaction::Transaction;
use crate::primitives::{bounded_capacity, to_hex, Reader};
use crate::script::{LockingScript, UnlockingScript};
use crate::Result;

/// The reference's words for bytes after a transaction
/// (`ts-stack@edf6e03` `Transaction.ts:462`, `:535`; #840).
pub(super) const TRAILING_DATA: &str = "Serialized transaction contains trailing data";

/// The reference's words for bytes after an EF transaction (`Transaction.ts:419`).
pub(super) const EF_TRAILING_DATA: &str = "Serialized EF transaction contains trailing data";

/// Refuses a reader that has not reached its end, in `words`.
pub(super) fn refuse_trailing(reader: &Reader, words: &str) -> Result<()> {
    if reader.is_empty() {
        Ok(())
    } else {
        Err(crate::Error::TransactionError(words.to_string()))
    }
}

impl Transaction {
    /// Reads one transaction from the front of a reader and leaves the
    /// reader after its lock time, the bytes after it unread: the
    /// reference's `fromReader` (`ts-stack@edf6e03` `Transaction.ts:466-468`).
    /// The door for a transaction at the front of a longer buffer, where
    /// [`from_binary`](Self::from_binary) refuses the bytes after it (#840).
    /// The transaction holds no copy of the reader's bytes: its serialization
    /// and txid are computed from its fields. One cell reads what `fromReader`
    /// refuses: an output amount of 2^53 satoshis or more is read as its `u64`,
    /// where the reference throws `Number can only safely store up to 53 bits`
    /// (`Transaction.ts:497`; a stated row, closed by #844).
    ///
    /// # Errors
    ///
    /// A field the bytes end inside, or a script that does not parse.
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
        let version = reader.read_u32_le()?;

        let input_count = reader.read_var_int_num()?;
        // Each input is >= 41 bytes (txid 32 + vout 4 + script len 1 +
        // sequence 4); bound the pre-allocation so a bogus count varint cannot
        // OOM-abort before any input is read.
        let mut inputs = Vec::with_capacity(bounded_capacity(input_count, reader.remaining(), 41));

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
        // Each output is >= 9 bytes (satoshis 8 + script len 1); bound the
        // pre-allocation so a bogus count cannot OOM-abort before any read.
        let mut outputs = Vec::with_capacity(bounded_capacity(output_count, reader.remaining(), 9));

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
}
