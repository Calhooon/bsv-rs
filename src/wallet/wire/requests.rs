//! The processor's readers of a request's parameters, one per call, where a
//! call's frame needs more than the handler's few lines.

use super::encoding::WireReader;
use crate::primitives::PublicKey;
use crate::wallet::interface::{RevealCounterpartyKeyLinkageArgs, RevealSpecificKeyLinkageArgs};
use crate::Error;

/// Reads the privileged flag and reason as the reference's
/// `#decodePrivilegedParams` does (`ts-stack@edf6e03`
/// `WalletWireProcessor.ts:2465-2476`): the flag an `i8` (-1 absent, 0, 1),
/// then the reason's length an `i8` (-1 absent, 0 to 127) and its UTF-8 bytes.
fn read_privileged_params(
    reader: &mut WireReader<'_>,
) -> Result<(Option<bool>, Option<String>), Error> {
    let privileged = reader.read_optional_bool()?;
    let privileged_reason =
        match reader.read_i8()? {
            -1 => None,
            length if length < 0 => {
                return Err(Error::WalletError(format!(
                    "invalid privilegedReason length: expected -1 or 0 to 127, got {length}"
                )))
            }
            length => {
                let bytes = reader.read_bytes(length.unsigned_abs().into())?;
                Some(String::from_utf8(bytes.to_vec()).map_err(|e| {
                    Error::WalletError(format!("invalid privilegedReason UTF-8: {e}"))
                })?)
            }
        };
    Ok((privileged, privileged_reason))
}

/// Reads revealCounterpartyKeyLinkage's parameters in the reference's order
/// (`WalletWireProcessor.ts:1739-1747`, `WalletWireTransceiver.ts:809-811`;
/// BRC-100 `wallet/0100.md:2016-2019` at `ed1b015`, `:2039-2042` at `5119a9b`):
/// the privileged flag and reason, then the counterparty and the verifier,
/// 33 bytes each (#191).
pub(super) fn read_reveal_counterparty_key_linkage_args(
    reader: &mut WireReader<'_>,
) -> Result<RevealCounterpartyKeyLinkageArgs, Error> {
    let (privileged, privileged_reason) = read_privileged_params(reader)?;
    let counterparty = PublicKey::from_bytes(reader.read_bytes(33)?)?;
    let verifier = PublicKey::from_bytes(reader.read_bytes(33)?)?;
    Ok(RevealCounterpartyKeyLinkageArgs {
        counterparty,
        verifier,
        privileged,
        privileged_reason,
    })
}

/// Reads revealSpecificKeyLinkage's parameters in the reference's order
/// (`#decodeKeyRelatedParams` then the verifier, `WalletWireProcessor.ts:1790-1797`
/// and `:2564-2583`; `WalletWireTransceiver.ts:874-883`; BRC-100
/// `wallet/0100.md:2045-2055` at `ed1b015`): the protocol, the key ID, the
/// counterparty, the privileged flag and reason, then the verifier (#191).
pub(super) fn read_reveal_specific_key_linkage_args(
    reader: &mut WireReader<'_>,
) -> Result<RevealSpecificKeyLinkageArgs, Error> {
    let protocol_id = reader.read_protocol_id()?;
    let key_id = reader.read_string()?;
    let counterparty = reader
        .read_counterparty()?
        .ok_or_else(|| Error::WalletError("counterparty is required".to_string()))?;
    let (privileged, privileged_reason) = read_privileged_params(reader)?;
    let verifier = PublicKey::from_bytes(reader.read_bytes(33)?)?;
    Ok(RevealSpecificKeyLinkageArgs {
        counterparty,
        verifier,
        protocol_id,
        key_id,
        privileged,
        privileged_reason,
    })
}
