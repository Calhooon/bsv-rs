//! The one reader of the Extended Format (BRC-30): [`Transaction::from_ef`],
//! [`Transaction::from_hex_ef`] and their bounded twins
//! [`Transaction::from_ef_bounded`], [`Transaction::from_hex_ef_bounded`]
//! all read through [`Transaction::read_ef`]. The source transaction an
//! input is given is built in [`source_for`] alone, under the caller's
//! budget when one is given (`tests/arch_ef_one_reader.rs` pins both).

use super::{
    ef_source_placeholder_len, from_hex, read_amount, refuse_trailing, to_hex, Transaction,
    EF_TRAILING_DATA,
};
use crate::primitives::{bounded_capacity, Reader};
use crate::script::{LockingScript, UnlockingScript};
use crate::transaction::{TransactionInput, TransactionOutput};
use crate::Result;

/// The source outputs a bounded read may still give its inputs, or `None`
/// for the unbounded doors.
type SourceBudget = Option<(u64, usize)>;

impl Transaction {
    /// Parses a transaction from Extended Format (BRC-30), as
    /// [`from_ef`](Self::from_ef) does, refusing one whose inputs'
    /// source transactions would hold more than `max_source_outputs`
    /// outputs between them.
    ///
    /// An input spending output `n` of its source is given a source
    /// transaction of `n + 1` outputs by [`from_ef`](Self::from_ef), the
    /// spent one at `n`; this door counts them over every input and refuses
    /// the bytes before it builds the source that would pass the figure.
    /// Under the figure, the answer is exactly [`from_ef`](Self::from_ef)'s.
    ///
    /// # Errors
    ///
    /// `TransactionError` when the inputs' source outputs together pass
    /// `max_source_outputs`; otherwise every error of [`from_ef`](Self::from_ef).
    ///
    /// ```
    /// use bsv_rs::transaction::{Transaction, TransactionInput, TransactionOutput};
    /// use bsv_rs::script::{LockingScript, UnlockingScript};
    /// let mut source = Transaction::new();
    /// for _ in 0..3 {
    ///     source.add_output(TransactionOutput::new(1_000, LockingScript::new()))?;
    /// }
    /// let mut input = TransactionInput::with_source_transaction(source, 2);
    /// input.unlocking_script = Some(UnlockingScript::new());
    /// let mut tx = Transaction::new();
    /// tx.add_input(input)?;
    /// tx.add_output(TransactionOutput::new(900, LockingScript::new()))?;
    /// let ef = tx.to_ef()?;
    /// // The input spends output 2: its source holds 3 outputs.
    /// assert_eq!(Transaction::from_ef_bounded(&ef, 3)?.id(), tx.id());
    /// assert!(Transaction::from_ef_bounded(&ef, 2).is_err());
    /// # Ok::<(), bsv_rs::Error>(())
    /// ```
    pub fn from_ef_bounded(ef: &[u8], max_source_outputs: usize) -> Result<Self> {
        Self::read_ef(ef, Some((max_source_outputs as u64, max_source_outputs)))
    }

    /// Parses a hex-encoded Extended Format transaction as
    /// [`from_hex_ef`](Self::from_hex_ef) does, under the same figure as
    /// [`from_ef_bounded`](Self::from_ef_bounded).
    ///
    /// # Errors
    ///
    /// `InvalidHex` for text that is not hex; otherwise every error of
    /// [`from_ef_bounded`](Self::from_ef_bounded).
    pub fn from_hex_ef_bounded(hex: &str, max_source_outputs: usize) -> Result<Self> {
        Self::from_ef_bounded(&from_hex(hex)?, max_source_outputs)
    }

    /// The one EF reader: `budget` is `None` for the unbounded doors.
    pub(super) fn read_ef(ef: &[u8], mut budget: SourceBudget) -> Result<Self> {
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
            inputs.push(read_ef_input(&mut reader, &mut budget)?);
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
}

/// One EF input, its source transaction built by [`source_for`].
fn read_ef_input(reader: &mut Reader, budget: &mut SourceBudget) -> Result<TransactionInput> {
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
    let source_satoshis = read_amount(reader)?;

    // Read source locking script
    let locking_script_len = reader.read_var_int_num()?;
    let locking_script_bytes = reader.read_bytes(locking_script_len)?;
    let locking_script = LockingScript::from_binary(locking_script_bytes)?;

    let spent = TransactionOutput {
        satoshis: Some(source_satoshis),
        locking_script,
        change: false,
    };
    let source_tx = source_for(source_output_index, spent, budget)?;

    Ok(TransactionInput {
        source_transaction: Some(Box::new(source_tx)),
        source_txid: Some(source_txid),
        source_output_index,
        unlocking_script: Some(unlocking_script),
        unlocking_script_template: None,
        sequence,
    })
}

/// The source transaction of an EF input spending output
/// `source_output_index`: `spent` at that index, a default output before it.
/// The count is refused past the per-input figure of
/// `ef_source_placeholder_len`, then past what is left of `budget`, before
/// any output is built.
fn source_for(
    source_output_index: u32,
    spent: TransactionOutput,
    budget: &mut SourceBudget,
) -> Result<Transaction> {
    // The real output must live at `source_output_index`, so the source
    // has that many outputs before it; the count is computed in u64 (see
    // `ef_source_placeholder_len`) so the `+ 1` cannot overflow on 32-bit
    // targets (wasm32).
    let needed = ef_source_placeholder_len(source_output_index).ok_or_else(|| {
        crate::Error::TransactionError(format!(
            "EF source output index {} is implausibly large",
            source_output_index
        ))
    })?;
    if let Some((left, max)) = budget.as_mut() {
        // `needed` is at most the per-input figure, so the u64 cannot wrap.
        if needed as u64 > *left {
            return Err(crate::Error::TransactionError(format!(
                "EF inputs' source outputs exceed the bound of {}",
                max
            )));
        }
        *left -= needed as u64;
    }
    let mut outputs = vec![TransactionOutput::default(); needed];
    outputs[source_output_index as usize] = spent;
    Ok(Transaction::with_params(1, Vec::new(), outputs, 0))
}
