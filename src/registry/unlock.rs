//! The definition token's spend on revoke and update, as the reference
//! unlocks it (#548; `ts-stack@edf6e03` `RegistryClient.ts:540-548`,
//! `:630-639`): `PushDrop.unlock(protocol, '1', 'anyone', 'all', false,
//! satoshis, lockingScript)` (`PushDrop.ts:217-262`), the record's satoshis
//! and locking script under SIGHASH_ALL | FORKID, signed by the wallet's
//! `createSignature` for counterparty `anyone`.

use crate::primitives::bsv::sighash::{
    parse_transaction, SighashParams, SIGHASH_ALL, SIGHASH_FORKID,
};
use crate::primitives::from_hex;
use crate::registry::types::RegistryRecord;
use crate::registry::REGISTRANT_KEY_ID;
use crate::transaction::Transaction;
use crate::wallet::interface::WalletInterface;
use crate::wallet::{Counterparty, Protocol, SecurityLevel, SignActionSpend};
use crate::{Error, Result};
use std::collections::HashMap;

/// The signAction spends for `record`'s token in the wallet's signable
/// transaction (`signable`, atomic BEEF): the token's input found by its
/// outpoint, keyed by its index there, its unlocking script the reference's.
pub(super) async fn token_spends<W: WalletInterface + ?Sized>(
    wallet: &W,
    signable: &[u8],
    record: &RegistryRecord,
    originator: Option<&str>,
) -> Result<HashMap<u32, SignActionSpend>> {
    let tx = Transaction::from_atomic_beef(signable)?;
    let txid = record.txid().to_ascii_lowercase();
    let index = tx
        .inputs
        .iter()
        .position(|input| {
            let source = input
                .source_txid
                .clone()
                .or_else(|| input.source_transaction.as_ref().map(|tx| tx.id()));
            input.source_output_index == record.output_index()
                && source.is_some_and(|source| source.eq_ignore_ascii_case(&txid))
        })
        .ok_or_else(|| {
            Error::RegistryError("Signable transaction does not spend the registry token".into())
        })?;
    let locking_script = from_hex(&record.token.locking_script)
        .map_err(|e| Error::RegistryError(format!("Invalid lockingScript: {}", e)))?;
    let parsed = parse_transaction(&tx.to_binary())?;
    let (_, name) = record.get_definition_type().wallet_protocol();
    let unlocking_script = crate::wallet::pushdrop::sign(
        wallet,
        &SighashParams {
            version: parsed.version,
            inputs: &parsed.inputs,
            outputs: &parsed.outputs,
            locktime: parsed.locktime,
            input_index: index,
            subscript: &locking_script,
            satoshis: record.token.satoshis,
            scope: SIGHASH_ALL | SIGHASH_FORKID,
        },
        Protocol::new(SecurityLevel::App, name),
        REGISTRANT_KEY_ID.into(),
        Counterparty::Anyone,
        originator,
    )
    .await?;
    let index = u32::try_from(index)
        .map_err(|_| Error::RegistryError("Signable transaction input is malformed".into()))?;
    Ok(HashMap::from([(
        index,
        SignActionSpend {
            unlocking_script,
            sequence_number: None,
        },
    )]))
}
