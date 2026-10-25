//! The processor's readers of a request's parameters, one per call, where a
//! call's frame needs more than the handler's few lines.

use super::encoding::WireReader;
use crate::primitives::PublicKey;
use crate::wallet::interface::{RevealCounterpartyKeyLinkageArgs, RevealSpecificKeyLinkageArgs};
use crate::wallet::{CreateSignatureArgs, VerifyHmacArgs, VerifySignatureArgs};
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

/// The bytes behind a varint length, the length read as the reference's
/// `readVarIntNumStrict(false)` reads it.
fn read_length_prefixed(reader: &mut WireReader<'_>) -> Result<Vec<u8>, Error> {
    let length = reader.read_var_int_num_strict()?;
    Ok(reader.read_bytes(length)?.to_vec())
}

/// Reads 32 raw bytes (the reference's `paramsReader.read(32)`).
fn read_32(reader: &mut WireReader<'_>) -> Result<[u8; 32], Error> {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(reader.read_bytes(32)?);
    Ok(bytes)
}

/// The data, or the 32-byte hash, a signature call carries.
type DataOrHash = (Option<Vec<u8>>, Option<[u8; 32]>);

/// The signature calls' data-type flag (bsv-rs#199): `1` then the data behind
/// its length, `2` then the 32 bytes of the hash, any other value refused in
/// the reference's words (`WalletWireProcessor.ts:1533-1543` createSignature,
/// `:1576-1586` verifySignature; BRC-100 `wallet/0100.md:2168-2170`,
/// `:2194-2196` at `ed1b015`).
fn read_data_or_hash(reader: &mut WireReader<'_>, call: &str) -> Result<DataOrHash, Error> {
    match reader.read_u8()? {
        1 => Ok((Some(read_length_prefixed(reader)?), None)),
        2 => Ok((None, Some(read_32(reader)?))),
        flag => Err(Error::WalletError(format!(
            "Invalid {call} data type flag: expected 1 or 2, received {flag}"
        ))),
    }
}

/// Reads verifyHmac's parameters in the reference's order
/// (`WalletWireProcessor.ts:1502-1509`, `WalletWireTransceiver.ts:1048-1050`;
/// BRC-100 `wallet/0100.md:2149-2151` at `ed1b015`): the protocol, the key ID,
/// the counterparty, then the 32 raw bytes of the HMAC, then the data behind
/// its length (#199). The privileged pair and seekPermission are not read:
/// `VerifyHmacArgs` has no field for them (#193).
pub(super) fn read_verify_hmac_args(reader: &mut WireReader<'_>) -> Result<VerifyHmacArgs, Error> {
    let protocol_id = reader.read_protocol_id()?;
    let key_id = reader.read_string()?;
    let counterparty = reader.read_counterparty()?;
    let hmac = read_32(reader)?;
    let data = read_length_prefixed(reader)?;
    Ok(VerifyHmacArgs {
        data,
        hmac,
        protocol_id,
        key_id,
        counterparty,
    })
}

/// Reads createSignature's parameters in the reference's order
/// (`WalletWireProcessor.ts:1530-1543`): the protocol, the key ID, the
/// counterparty, then the data-type flag and the data or the hash (#199).
/// The privileged pair and seekPermission are not read (#193).
pub(super) fn read_create_signature_args(
    reader: &mut WireReader<'_>,
) -> Result<CreateSignatureArgs, Error> {
    let protocol_id = reader.read_protocol_id()?;
    let key_id = reader.read_string()?;
    let counterparty = reader.read_counterparty()?;
    let (data, hash_to_directly_sign) = read_data_or_hash(reader, "createSignature")?;
    Ok(CreateSignatureArgs {
        data,
        hash_to_directly_sign,
        protocol_id,
        key_id,
        counterparty,
    })
}

/// Reads verifySignature's parameters in the reference's order
/// (`WalletWireProcessor.ts:1566-1586`; BRC-100 `wallet/0100.md:2192-2196`
/// at `ed1b015`): the protocol, the key ID, the counterparty, forSelf, the
/// signature behind its length, then the data-type flag and the data or the
/// hash (#199). The privileged pair and seekPermission are not read (#193).
pub(super) fn read_verify_signature_args(
    reader: &mut WireReader<'_>,
) -> Result<VerifySignatureArgs, Error> {
    let protocol_id = reader.read_protocol_id()?;
    let key_id = reader.read_string()?;
    let counterparty = reader.read_counterparty()?;
    let for_self = reader.read_optional_bool()?;
    let signature = read_length_prefixed(reader)?;
    let (data, hash_to_directly_verify) = read_data_or_hash(reader, "verifySignature")?;
    Ok(VerifySignatureArgs {
        data,
        hash_to_directly_verify,
        signature,
        protocol_id,
        key_id,
        counterparty,
        for_self,
    })
}
