//! The processor's readers of a request's parameters, one per call, where a
//! call's frame needs more than the handler's few lines.

use super::encoding::WireReader;
use crate::wallet::types::{Counterparty, Protocol};
use crate::wallet::{
    CreateHmacArgs, CreateSignatureArgs, DecryptArgs, EncryptArgs, GetPublicKeyArgs,
    VerifyHmacArgs, VerifySignatureArgs,
};
use crate::Error;

/// Refuses a request with bytes after its last field, in the reference's
/// words (`#assertRequestConsumed`, `WalletWireProcessor.ts:2433-2437` at
/// `ts-stack@edf6e03`, called by every call before the wallet is; #193).
pub(super) fn assert_request_consumed(reader: &WireReader<'_>, call: &str) -> Result<(), Error> {
    if reader.is_empty() {
        Ok(())
    } else {
        Err(Error::WalletError(format!(
            "Wallet Wire {call} request contains trailing data"
        )))
    }
}

/// The key-related parameters (`#decodeKeyRelatedParams`,
/// `WalletWireProcessor.ts:2564-2583`): the protocol, the key ID, the
/// counterparty, then the privileged flag and reason.
struct KeyRelated {
    protocol_id: Protocol,
    key_id: String,
    counterparty: Option<Counterparty>,
    privileged: Option<bool>,
    privileged_reason: Option<String>,
}

/// An args value from its own fields, its key-related parameters and its
/// seekPermission, read in that order by the caller.
macro_rules! from_key_related {
    ($ty:ident { $($field:ident),* }, $key:expr, $seek:expr) => {{
        let key: KeyRelated = $key;
        $ty {
            $($field,)*
            protocol_id: key.protocol_id,
            key_id: key.key_id,
            counterparty: key.counterparty,
            privileged: key.privileged,
            privileged_reason: key.privileged_reason,
            seek_permission: $seek,
        }
    }};
}

fn read_key_related_params(reader: &mut WireReader<'_>) -> Result<KeyRelated, Error> {
    let protocol_id = reader.read_protocol_id()?;
    let key_id = reader.read_string()?;
    let counterparty = reader.read_counterparty()?;
    let (privileged, privileged_reason) = read_privileged_params(reader)?;
    Ok(KeyRelated {
        protocol_id,
        key_id,
        counterparty,
        privileged,
        privileged_reason,
    })
}

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

/// revealCounterpartyKeyLinkage's request as the reference reads it: the two
/// keys 33 raw bytes each, judged by `validation::reveal_counterparty_args`.
pub(super) struct RevealCounterpartyRequest {
    pub(super) counterparty: [u8; 33],
    pub(super) verifier: [u8; 33],
    pub(super) privileged: Option<bool>,
    pub(super) privileged_reason: Option<String>,
}

/// revealSpecificKeyLinkage's request as the reference reads it: the
/// counterparty as the key-related parameters carry it (absent when its flag
/// is 0) and the verifier 33 raw bytes, judged by
/// `validation::reveal_specific_args`.
pub(super) struct RevealSpecificRequest {
    pub(super) counterparty: Option<Counterparty>,
    pub(super) verifier: [u8; 33],
    pub(super) protocol_id: Protocol,
    pub(super) key_id: String,
    pub(super) privileged: Option<bool>,
    pub(super) privileged_reason: Option<String>,
}

/// Reads revealCounterpartyKeyLinkage's parameters in the reference's order
/// (`WalletWireProcessor.ts:1739-1747`, `WalletWireTransceiver.ts:809-811`;
/// BRC-100 `wallet/0100.md:2016-2019` at `ed1b015`, `:2039-2042` at `5119a9b`):
/// the privileged flag and reason, then the counterparty and the verifier,
/// 33 raw bytes each (#191), a non-point refused by validation (#226).
pub(super) fn read_reveal_counterparty_key_linkage_args(
    reader: &mut WireReader<'_>,
) -> Result<RevealCounterpartyRequest, Error> {
    let (privileged, privileged_reason) = read_privileged_params(reader)?;
    let counterparty = read_33(reader)?;
    let verifier = read_33(reader)?;
    Ok(RevealCounterpartyRequest {
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
/// counterparty, the privileged flag and reason, then the verifier (#191);
/// an absent counterparty and a verifier that is no point are refused by
/// validation (#226).
pub(super) fn read_reveal_specific_key_linkage_args(
    reader: &mut WireReader<'_>,
) -> Result<RevealSpecificRequest, Error> {
    let key = read_key_related_params(reader)?;
    let verifier = read_33(reader)?;
    Ok(RevealSpecificRequest {
        counterparty: key.counterparty,
        verifier,
        protocol_id: key.protocol_id,
        key_id: key.key_id,
        privileged: key.privileged,
        privileged_reason: key.privileged_reason,
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

/// Reads 33 raw bytes (the reference's `paramsReader.read(33)`).
fn read_33(reader: &mut WireReader<'_>) -> Result<[u8; 33], Error> {
    let mut bytes = [0u8; 33];
    bytes.copy_from_slice(reader.read_bytes(33)?);
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

/// Reads getPublicKey's parameters in the reference's order
/// (`WalletWireProcessor.ts:1386-1403`, `WalletWireTransceiver.ts:756-779`;
/// BRC-100 `wallet/0100.md` getPublicKey): the identityKey flag (0 or 1);
/// for the identity key the privileged flag and reason, otherwise the
/// key-related parameters and forSelf; then seekPermission (#193).
pub(super) fn read_get_public_key_args(
    reader: &mut WireReader<'_>,
) -> Result<GetPublicKeyArgs, Error> {
    let identity_key = reader.read_boolean_flag("identityKey")?;
    let mut args = GetPublicKeyArgs {
        identity_key,
        ..GetPublicKeyArgs::default()
    };
    if identity_key {
        (args.privileged, args.privileged_reason) = read_privileged_params(reader)?;
    } else {
        let key = read_key_related_params(reader)?;
        args.protocol_id = Some(key.protocol_id);
        args.key_id = Some(key.key_id);
        args.counterparty = key.counterparty;
        args.privileged = key.privileged;
        args.privileged_reason = key.privileged_reason;
        args.for_self = reader.read_optional_bool()?;
    }
    args.seek_permission = reader.read_optional_bool()?;
    Ok(args)
}

/// Reads encrypt's, decrypt's or createHmac's parameters in the reference's
/// order (`WalletWireProcessor.ts:1421-1430`, `:1448-1457`, `:1475-1484`):
/// the key-related parameters, the bytes behind their length, then
/// seekPermission (#193).
fn read_key_bytes_args(
    reader: &mut WireReader<'_>,
) -> Result<(KeyRelated, Vec<u8>, Option<bool>), Error> {
    let key = read_key_related_params(reader)?;
    let bytes = read_length_prefixed(reader)?;
    Ok((key, bytes, reader.read_optional_bool()?))
}

/// encrypt's parameters ([`read_key_bytes_args`]).
pub(super) fn read_encrypt_args(reader: &mut WireReader<'_>) -> Result<EncryptArgs, Error> {
    let (key, plaintext, seek) = read_key_bytes_args(reader)?;
    Ok(from_key_related!(EncryptArgs { plaintext }, key, seek))
}

/// decrypt's parameters ([`read_key_bytes_args`]).
pub(super) fn read_decrypt_args(reader: &mut WireReader<'_>) -> Result<DecryptArgs, Error> {
    let (key, ciphertext, seek) = read_key_bytes_args(reader)?;
    Ok(from_key_related!(DecryptArgs { ciphertext }, key, seek))
}

/// createHmac's parameters ([`read_key_bytes_args`]).
pub(super) fn read_create_hmac_args(reader: &mut WireReader<'_>) -> Result<CreateHmacArgs, Error> {
    let (key, data, seek) = read_key_bytes_args(reader)?;
    Ok(from_key_related!(CreateHmacArgs { data }, key, seek))
}

/// Reads verifyHmac's parameters in the reference's order
/// (`WalletWireProcessor.ts:1500-1512`, `WalletWireTransceiver.ts:1038-1052`;
/// BRC-100 `wallet/0100.md:2149-2151` at `ed1b015`): the key-related
/// parameters, the 32 raw bytes of the HMAC, the data behind its length
/// (#199), then seekPermission (#193).
pub(super) fn read_verify_hmac_args(reader: &mut WireReader<'_>) -> Result<VerifyHmacArgs, Error> {
    let key = read_key_related_params(reader)?;
    let hmac = read_32(reader)?;
    let data = read_length_prefixed(reader)?;
    let seek = reader.read_optional_bool()?;
    Ok(from_key_related!(VerifyHmacArgs { data, hmac }, key, seek))
}

/// Reads createSignature's parameters in the reference's order
/// (`WalletWireProcessor.ts:1528-1546`): the key-related parameters, the
/// data-type flag and the data or the hash (#199), then seekPermission (#193).
pub(super) fn read_create_signature_args(
    reader: &mut WireReader<'_>,
) -> Result<CreateSignatureArgs, Error> {
    let key = read_key_related_params(reader)?;
    let (data, hash_to_directly_sign) = read_data_or_hash(reader, "createSignature")?;
    let seek = reader.read_optional_bool()?;
    Ok(from_key_related!(
        CreateSignatureArgs {
            data,
            hash_to_directly_sign
        },
        key,
        seek
    ))
}

/// Reads verifySignature's parameters in the reference's order
/// (`WalletWireProcessor.ts:1564-1589`; BRC-100 `wallet/0100.md:2192-2196`
/// at `ed1b015`): the key-related parameters, forSelf, the signature behind
/// its length, the data-type flag and the data or the hash (#199), then
/// seekPermission (#193).
pub(super) fn read_verify_signature_args(
    reader: &mut WireReader<'_>,
) -> Result<VerifySignatureArgs, Error> {
    let key = read_key_related_params(reader)?;
    let for_self = reader.read_optional_bool()?;
    let signature = read_length_prefixed(reader)?;
    let (data, hash_to_directly_verify) = read_data_or_hash(reader, "verifySignature")?;
    let seek = reader.read_optional_bool()?;
    Ok(from_key_related!(
        VerifySignatureArgs {
            data,
            hash_to_directly_verify,
            signature,
            for_self
        },
        key,
        seek
    ))
}
