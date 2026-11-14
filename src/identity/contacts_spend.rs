//! The checks the reference's contacts manager makes around a spend of its
//! token (#904; `ts-stack@edf6e03` `ContactsManager.ts:661-745`): the
//! wallet's transactions read as Atomic BEEF, the one input bound to the
//! token's outpoint, the signed transaction held to the signable one, the
//! requested output present once.
use crate::transaction::Transaction;
use crate::{Error, Result};

fn refused(words: impl Into<String>) -> Error {
    Error::IdentityError(words.into())
}

/// `MAX_CONTACT_BEEF_BYTES` (`ContactsManager.ts:34`).
pub(super) const MAX_BEEF: usize = 16 * 1024 * 1024;

/// `bytes(value, field, 1, MAX_CONTACT_BEEF_BYTES)` (`:200-216`).
pub(super) fn bounded_beef<'a>(value: &'a [u8], field: &str) -> Result<&'a [u8]> {
    if value.is_empty() || value.len() > MAX_BEEF {
        return Err(refused(format!("{field} must contain 1-{MAX_BEEF} bytes")));
    }
    Ok(value)
}

/// `#parseAtomicTransaction` (`:661-664`): the bytes bounded, then read as
/// Atomic BEEF (this crate's reader's words where it refuses).
pub(super) fn parse_atomic(value: &[u8], field: &str) -> Result<Transaction> {
    Transaction::from_atomic_beef(bounded_beef(value, field)?)
}

/// `#inputOutpoint` (`:666-687`): an input's outpoint as `<txid>.<index>`,
/// its txid the one it names or the one of the source it carries, the two
/// equal when both are present, 64 lower-case hex digits.
pub(super) fn input_outpoint(tx: &Transaction, index: usize) -> Result<String> {
    let input = tx
        .inputs()
        .get(index)
        .ok_or_else(|| refused("Contact transaction input is malformed"))?;
    let embedded = input.source_transaction.as_ref().map(|t| t.txid());
    if let (Some(named), Some(embedded)) = (&input.source_txid, &embedded) {
        if named != embedded {
            return Err(refused("Contact transaction input source mismatch"));
        }
    }
    let txid = input
        .source_txid
        .or(embedded)
        .ok_or_else(|| refused("Contact transaction input has no canonical source ID"))?;
    Ok(format!("{txid}.{}", input.source_output_index))
}

/// `#findBoundInput` (`:689-697`): the index of the one input spending
/// `outpoint`.
pub(super) fn find_bound_input(tx: &Transaction, outpoint: &str) -> Result<usize> {
    let mut matches = Vec::new();
    for index in 0..tx.inputs().len() {
        if input_outpoint(tx, index)? == outpoint {
            matches.push(index);
        }
    }
    match matches.as_slice() {
        [index] => Ok(*index),
        _ => Err(refused(
            "Contact transaction does not spend the exact contact outpoint once",
        )),
    }
}

/// `#assertTransactionTemplate` (`:699-727`): the signed transaction keeps
/// the signable one's version, lock time, inputs (outpoint and sequence)
/// and outputs (satoshis and script).
pub(super) fn assert_template(signable: &Transaction, signed: &Transaction) -> Result<()> {
    if signable.version() != signed.version()
        || signable.lock_time() != signed.lock_time()
        || signable.inputs().len() != signed.inputs().len()
        || signable.outputs().len() != signed.outputs().len()
    {
        return Err(refused(
            "Signed contact transaction substituted the authorized transaction template",
        ));
    }
    for index in 0..signable.inputs().len() {
        if input_outpoint(signable, index)? != input_outpoint(signed, index)?
            || signable.inputs()[index].sequence != signed.inputs()[index].sequence
        {
            return Err(refused(
                "Signed contact transaction substituted an authorized input",
            ));
        }
    }
    for (expected, actual) in signable.outputs().iter().zip(signed.outputs()) {
        if expected.satoshis != actual.satoshis
            || expected.locking_script.to_binary() != actual.locking_script.to_binary()
        {
            return Err(refused(
                "Signed contact transaction substituted an authorized output",
            ));
        }
    }
    Ok(())
}

/// `#requireContactOutput` (`:729-736`): exactly one output of one satoshi
/// locked by `lock`.
pub(super) fn require_contact_output(tx: &Transaction, lock: &[u8]) -> Result<()> {
    let matches = tx
        .outputs()
        .iter()
        .filter(|output| output.satoshis == Some(1) && output.locking_script.to_binary() == lock)
        .count();
    if matches != 1 {
        return Err(refused(
            "Contact transaction does not contain the exact requested output",
        ));
    }
    Ok(())
}

/// The words of the update's and the removal's checks after signAction
/// (`:839-850`, `:1006-1015`).
pub(super) struct SpendWords {
    pub unsigned: &'static str,
    pub no_tx: &'static str,
    pub signed_field: &'static str,
    pub moved: &'static str,
    pub substituted: &'static str,
    pub signable_field: &'static str,
}

pub(super) const UPDATE: SpendWords = SpendWords {
    unsigned: "Unable to update contact",
    no_tx: "Failed to update contact output",
    signed_field: "signed contact transaction",
    moved: "Signed contact transaction moved the authorized input",
    substituted: "Signed contact transaction omitted or substituted the authorized signature",
    signable_field: "contact signable transaction",
};

pub(super) const DELETE: SpendWords = SpendWords {
    unsigned: "Unable to delete contact",
    no_tx: "Failed to delete contact output",
    signed_field: "signed contact deletion transaction",
    moved: "Signed contact deletion moved the authorized input",
    substituted: "Signed contact deletion omitted or substituted the authorized signature",
    signable_field: "contact deletion transaction",
};

/// The checks of the signed transaction (`:841-851`, `:1008-1015`).
pub(super) fn check_signed(
    signable: &Transaction,
    signed: &[u8],
    input_index: usize,
    outpoint: &str,
    unlocking_script: &[u8],
    lock: Option<&[u8]>,
    words: &SpendWords,
) -> Result<()> {
    let signed = parse_atomic(signed, words.signed_field)?;
    assert_template(signable, &signed)?;
    if find_bound_input(&signed, outpoint)? != input_index {
        return Err(refused(words.moved));
    }
    let script = signed.inputs()[input_index].unlocking_script.as_ref();
    if script.map(|s| s.to_binary()).as_deref() != Some(unlocking_script) {
        return Err(refused(words.substituted));
    }
    if let Some(lock) = lock {
        require_contact_output(&signed, lock)?;
    }
    Ok(())
}
