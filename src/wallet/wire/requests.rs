//! The processor's readers of a request's parameters, one per call, where a
//! call's frame needs more than the handler's few lines.

use super::encoding::WireReader;
use crate::primitives::PublicKey;
use crate::wallet::interface::{RevealCounterpartyKeyLinkageArgs, RevealSpecificKeyLinkageArgs};
use crate::Error;

/// Reads revealCounterpartyKeyLinkage's parameters.
pub(super) fn read_reveal_counterparty_key_linkage_args(
    reader: &mut WireReader<'_>,
) -> Result<RevealCounterpartyKeyLinkageArgs, Error> {
    let counterparty = PublicKey::from_bytes(reader.read_bytes(33)?)?;
    let verifier = PublicKey::from_bytes(reader.read_bytes(33)?)?;
    Ok(RevealCounterpartyKeyLinkageArgs {
        counterparty,
        verifier,
        privileged: None,
        privileged_reason: None,
    })
}

/// Reads revealSpecificKeyLinkage's parameters.
pub(super) fn read_reveal_specific_key_linkage_args(
    reader: &mut WireReader<'_>,
) -> Result<RevealSpecificKeyLinkageArgs, Error> {
    let counterparty = reader
        .read_counterparty()?
        .ok_or_else(|| Error::WalletError("counterparty is required".to_string()))?;
    let verifier = PublicKey::from_bytes(reader.read_bytes(33)?)?;
    let protocol_id = reader.read_protocol_id()?;
    let key_id = reader.read_string()?;
    Ok(RevealSpecificKeyLinkageArgs {
        counterparty,
        verifier,
        protocol_id,
        key_id,
        privileged: None,
        privileged_reason: None,
    })
}
