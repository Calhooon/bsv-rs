//! The reference's ECIES byte bounds, before reading or hashing (#333, #463).
//!
//! `ts-stack@edf6e03` `packages/sdk/src/compat/ECIES.ts:12,551,589-594,673,704-709`
//! uses these figures through `CompatValidation.ts:1-15`. Rust byte slices
//! already guarantee dense bytes; only their length needs checking here.

use crate::error::{Error, Result};

const MAX_COMPAT_BYTE_PAYLOAD: usize = 16 * 1024 * 1024;
const MAX_ECIES_ENVELOPE_BYTES: usize = MAX_COMPAT_BYTE_PAYLOAD + 160;

fn bounded(
    data: &[u8],
    minimum: usize,
    maximum: usize,
    label: &str,
    refusal: fn(String) -> Error,
) -> Result<()> {
    if data.len() < minimum || data.len() > maximum {
        return Err(refusal(format!(
            "{label} must be a bounded dense byte array"
        )));
    }
    Ok(())
}

pub(super) fn electrum_envelope(data: &[u8]) -> Result<()> {
    bounded(
        data,
        4 + 16 + 32,
        MAX_ECIES_ENVELOPE_BYTES,
        "Electrum ECIES envelope",
        Error::EciesDecryptionFailed,
    )
}

pub(super) fn bitcore_envelope(data: &[u8]) -> Result<()> {
    bounded(
        data,
        33 + 16 + 16 + 32,
        MAX_ECIES_ENVELOPE_BYTES,
        "Bitcore ECIES envelope",
        Error::EciesDecryptionFailed,
    )
}

pub(super) fn electrum_plaintext(data: &[u8]) -> Result<()> {
    bounded(
        data,
        0,
        MAX_COMPAT_BYTE_PAYLOAD,
        "Electrum ECIES plaintext",
        Error::EciesInvalidPlaintext,
    )
}

pub(super) fn bitcore_plaintext(data: &[u8]) -> Result<()> {
    bounded(
        data,
        0,
        MAX_COMPAT_BYTE_PAYLOAD,
        "Bitcore ECIES plaintext",
        Error::EciesInvalidPlaintext,
    )
}
