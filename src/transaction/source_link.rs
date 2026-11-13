//! An input's `source_txid` against its linked source's id (#848): the one
//! judgment `Transaction::sign` and `Transaction::verify` share, beside the
//! outpoint rule it reads (`transaction/fields.rs`, `outpoint_txid`).

use super::transaction::{outpoint_txid, outpoint_txid_bytes, OutpointTxid};
use super::{Transaction, TransactionInput};
use crate::{Error, Result};

/// The linked source of an input whose `source_txid` names another
/// transaction: the input is in the [`OutpointTxid::Named`] arm (its text 64
/// hex digits, of either case, so the serializer writes the text) and links a
/// source whose id is not that text. `None` for every other input: one that
/// links nothing, one whose text is its source's id, and one whose text does
/// not parse (the serializer then writes the source's hash, so nothing
/// disagrees). The reference's
/// `requireTXID(input.sourceTXID) !== input.sourceTransaction.id('hex')`
/// (`ts-stack@edf6e03` `Transaction.ts:974-979`, `:1423-1428`); the source's
/// hash is its cached one, so a source is hashed once however often it is
/// asked.
pub(super) fn source_named_otherwise(input: &TransactionInput) -> Option<&Transaction> {
    let source = input.source_transaction.as_deref()?;
    match outpoint_txid(input) {
        OutpointTxid::Named(_) if outpoint_txid_bytes(input) != source.hash() => Some(source),
        _ => None,
    }
}

/// `sign`'s pass over every input, template or not, before any template runs:
/// a complete or anchored source (one with an input or a merkle path) linked
/// under another txid is refused, as the reference refuses it
/// (`Transaction.ts:970-984`): the signature would commit to the named
/// outpoint with the linked source's amount and script. A source with neither
/// is an EF descriptor, which carries only claimed outpoint data (`from_ef`,
/// `add_input_from`, `add_inputs_from_utxos`): exempt.
pub(super) fn refuse_at_sign(inputs: &[TransactionInput]) -> Result<()> {
    for (index, input) in inputs.iter().enumerate() {
        if let Some(source) = source_named_otherwise(input) {
            if !source.inputs().is_empty() || source.merkle_path.is_some() {
                return Err(Error::TransactionError(format!(
                    "Input {index} sourceTXID does not reference its supplied source transaction."
                )));
            }
        }
    }
    Ok(())
}
