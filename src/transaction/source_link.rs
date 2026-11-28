//! An input's `source_txid` against its linked source's id (#848): the one
//! judgment `Transaction::sign` and `Transaction::verify` share.
//!
//! An input carries a named outpoint (`source_txid`) and may also link a copy
//! of the source (`source_transaction`). The serializer writes the named
//! outpoint; `sign` signs over it with the linked source's amount and script,
//! and `verify` resolves the source by the named txid. When the two disagree
//! the input does not spend the coin it links. The reference refuses the
//! disagreement at both doors (`ts-stack@edf6e03`
//! `packages/sdk/src/transaction/Transaction.ts`: sign `:964-984`, verify
//! `:1423-1432`).

use super::{Transaction, TransactionInput};
use crate::{Error, Result};

/// Whether `text` is 64 hex digits, i.e. the serializer writes an input's
/// outpoint from the text rather than from its linked source's hash.
fn names_32_bytes(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The linked source of an input whose `source_txid` names another
/// transaction: the input links a source, its `source_txid` is 64 hex digits
/// (of either case, so the serializer writes the text), and that text is not
/// the linked source's id. `None` for every other input: one that links
/// nothing, one whose text is its source's id (any case), and one whose text
/// is not 64 hex digits (the serializer then writes the source's hash, so
/// nothing disagrees). The reference's
/// `requireTXID(input.sourceTXID) !== input.sourceTransaction.id('hex')`
/// (`ts-stack@edf6e03` `Transaction.ts:974-979`, `:1423-1428`); the source's
/// id is its cached hash, so a source is hashed once however often it is
/// asked.
pub(super) fn source_named_otherwise(input: &TransactionInput) -> Option<&Transaction> {
    let source = input.source_transaction.as_deref()?;
    let named = input.source_txid.as_deref()?;
    if names_32_bytes(named) && !named.eq_ignore_ascii_case(&source.id()) {
        Some(source)
    } else {
        None
    }
}

/// `sign`'s pass over every input, template or not, before any template runs:
/// a complete or anchored source (one with an input or a merkle path) linked
/// under another txid is refused, as the reference refuses it
/// (`Transaction.ts:970-984`): the signature would commit to the named
/// outpoint with the linked source's amount and script. A source with
/// neither is an EF descriptor, which carries only claimed outpoint data
/// (`from_ef`, `add_input_from`, `add_inputs_from_utxos`): exempt.
///
/// The comparison is case-insensitive (`source_named_otherwise`), so an input
/// naming its own source's id in upper case reads as a match and is not
/// refused here — it signs — where `verify` resolves it through its lower-case
/// by-txid map, misses, and refuses it (`has no source transaction`). The two
/// doors answer an upper-case own-id differently, as on 0.8.13; the 0.9 line's
/// lowering of verify's lookup is not ported (the root `CLAUDE.md` row).
pub(super) fn refuse_at_sign(inputs: &[TransactionInput]) -> Result<()> {
    for (index, input) in inputs.iter().enumerate() {
        if let Some(source) = source_named_otherwise(input) {
            if !source.inputs.is_empty() || source.merkle_path.is_some() {
                return Err(Error::TransactionError(format!(
                    "Input {index} sourceTXID does not reference its supplied source transaction."
                )));
            }
        }
    }
    Ok(())
}
