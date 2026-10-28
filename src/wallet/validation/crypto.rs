//! The typed portion of ProtoWallet's argument validators (#415).
//!
//! `ts-stack@edf6e03`, `validationHelpers.ts:146-230,1752-1804`.
//! Order matters: encryption arguments, data/hash, signature, then forSelf.
//! Rust's types already enforce records, byte elements, security levels,
//! counterparties, booleans and the 32-byte hashes/HMACs. The wire processor
//! shares these checks; its decoder additionally enforces those types.

use super::originator::invalid_parameter;
use crate::error::Result;
use crate::wallet::{
    CreateHmacArgs, CreateSignatureArgs, Protocol, VerifyHmacArgs, VerifySignatureArgs,
};

const MAX_WALLET_WIRE_FRAME_BYTES: usize = 256 * 1024 * 1024;
const MAX_SIGNATURE_BYTES: usize = 72;
const GROUP_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// `validateStringLength`: UTF-8 bytes, without trimming or normalization.
pub(crate) fn string_length(value: &str, name: &str, min: usize, max: usize) -> Result<()> {
    if value.len() < min {
        return Err(invalid_parameter(name, &format!("at least {min} length.")));
    }
    if value.len() > max {
        return Err(invalid_parameter(
            name,
            &format!("no more than {max} length."),
        ));
    }
    Ok(())
}

/// `validateByteArray` on typed bytes: only its inclusive size bound remains.
pub(crate) fn byte_array(length: usize, name: &str) -> Result<()> {
    if length > MAX_WALLET_WIRE_FRAME_BYTES {
        return Err(invalid_parameter(
            name,
            &format!("at most {MAX_WALLET_WIRE_FRAME_BYTES} bytes"),
        ));
    }
    Ok(())
}

/// `validateProtocol`: SecurityLevel already represents exactly 0, 1 and 2.
pub(crate) fn protocol(protocol: &Protocol) -> Result<()> {
    string_length(&protocol.protocol_name, "protocolID[1]", 5, 400)
}

/// `validatePrivilege`: validate a present reason even without privilege.
pub(crate) fn privilege(privileged: Option<bool>, reason: Option<&str>) -> Result<()> {
    if let Some(reason) = reason {
        string_length(reason, "privilegedReason", 5, 50)?;
    }
    if privileged == Some(true) && reason.is_none() {
        return Err(invalid_parameter(
            "privilegedReason",
            "a value when 'privileged' is true",
        ));
    }
    Ok(())
}

/// `validateEncryptionArgs`: protocol, key ID, counterparty, privilege.
pub(crate) fn encryption(
    protocol_id: &Protocol,
    key_id: &str,
    privileged: Option<bool>,
    reason: Option<&str>,
) -> Result<()> {
    protocol(protocol_id)?;
    string_length(key_id, "keyID", 1, 800)?;
    privilege(privileged, reason)
}

/// `validateCreateHmacArgs`, before derivation or hashing.
pub(crate) fn create_hmac_args(args: &CreateHmacArgs) -> Result<()> {
    encryption(
        &args.protocol_id,
        &args.key_id,
        args.privileged,
        args.privileged_reason.as_deref(),
    )?;
    byte_array(args.data.len(), "data")
}

/// `validateVerifyHmacArgs`: the HMAC's exact length is carried by its type.
pub(crate) fn verify_hmac_args(args: &VerifyHmacArgs) -> Result<()> {
    encryption(
        &args.protocol_id,
        &args.key_id,
        args.privileged,
        args.privileged_reason.as_deref(),
    )?;
    byte_array(args.data.len(), "data")
}

/// `validateExclusiveDataAndHash`: presence, then the chosen bytes.
fn exclusive_data_and_hash(data: Option<&[u8]>, has_hash: bool, hash_field: &str) -> Result<()> {
    if data.is_some() == has_hash {
        return Err(invalid_parameter(
            &format!("data, {hash_field}"),
            "exactly one value",
        ));
    }
    if let Some(data) = data {
        byte_array(data.len(), "data")?;
    }
    Ok(())
}

/// `validateCreateSignatureArgs`, before derivation or hashing.
pub(crate) fn create_signature_args(args: &CreateSignatureArgs) -> Result<()> {
    encryption(
        &args.protocol_id,
        &args.key_id,
        args.privileged,
        args.privileged_reason.as_deref(),
    )?;
    exclusive_data_and_hash(
        args.data.as_deref(),
        args.hash_to_directly_sign.is_some(),
        "hashToDirectlySign",
    )
}

/// `validateVerifySignatureArgs`, before any DER parsing. The final forSelf
/// boolean check is guaranteed by `Option<bool>`.
pub(crate) fn verify_signature_args(args: &VerifySignatureArgs) -> Result<()> {
    encryption(
        &args.protocol_id,
        &args.key_id,
        args.privileged,
        args.privileged_reason.as_deref(),
    )?;
    exclusive_data_and_hash(
        args.data.as_deref(),
        args.hash_to_directly_verify.is_some(),
        "hashToDirectlyVerify",
    )?;
    if args.signature.len() > MAX_SIGNATURE_BYTES {
        return Err(invalid_parameter("signature", "at most 72 bytes"));
    }
    if !is_canonical_der_signature(&args.signature) {
        return Err(invalid_parameter(
            "signature",
            "a canonical DER-encoded ECDSA signature",
        ));
    }
    Ok(())
}

/// `isCanonicalDERSignature` (`Secp256k1Validation.ts:33-53`): strict,
/// minimally encoded DER with each scalar in 1..n, without requiring low-S.
pub(crate) fn is_canonical_der_signature(bytes: &[u8]) -> bool {
    if bytes.len() < 8 || bytes.len() > MAX_SIGNATURE_BYTES || bytes[0] != 0x30 {
        return false;
    }
    if usize::from(bytes[1]) != bytes.len() - 2 {
        return false;
    }
    let mut offset = 2;
    for _ in 0..2 {
        if bytes.get(offset) != Some(&0x02) {
            return false;
        }
        let Some(&length) = bytes.get(offset + 1) else {
            return false;
        };
        let length = usize::from(length);
        offset += 2;
        if !(1..=33).contains(&length) || offset + length > bytes.len() {
            return false;
        }
        let scalar = &bytes[offset..offset + length];
        if scalar[0] & 0x80 != 0 || (length > 1 && scalar[0] == 0 && scalar[1] & 0x80 == 0) {
            return false;
        }
        if !scalar_in_range(scalar) {
            return false;
        }
        offset += length;
    }
    offset == bytes.len()
}

fn scalar_in_range(scalar: &[u8]) -> bool {
    let Some(leading) = scalar.iter().position(|&b| b != 0) else {
        return false;
    };
    let digits = &scalar[leading..];
    if digits.len() > 32 {
        return false;
    }
    let mut padded = [0u8; 32];
    padded[32 - digits.len()..].copy_from_slice(digits);
    padded < GROUP_ORDER
}
