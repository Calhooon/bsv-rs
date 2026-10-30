//! Locate the completed token as LocalKVStore.ts:538-546 does (#478).
use crate::script::LockingScript;
use crate::transaction::Transaction;
use crate::{Error, Result};

pub(super) fn token_outpoint(
    tx: &Transaction,
    lock: &LockingScript,
    amount: u64,
) -> Result<String> {
    let mut indexes = tx.outputs.iter().enumerate().filter_map(|(index, output)| {
        (output.satoshis == Some(amount) && output.locking_script == *lock).then_some(index)
    });
    match (indexes.next(), indexes.next()) {
        (Some(index), None) => Ok(format!("{}.{index}", tx.id())),
        _ => Err(Error::KvStoreLocalError(
            "Final transaction does not contain one unique KVStore token".into(),
        )),
    }
}

#[cfg(test)]
#[path = "local_outpoint_tests.rs"]
mod tests;
