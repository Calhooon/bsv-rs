//! Local parser catches: reference words only for failures the reference also has.
use super::lookup::refused;
use crate::primitives::PublicKey;
use crate::script::templates::pushdrop_position::{canonical_refusal, key_text_refusal};
use crate::script::{templates::PushDrop, LockingScript};
use crate::{Error, Result};

pub(super) fn parse_public_key(key: &str) -> Result<PublicKey> {
    PublicKey::from_hex(key).map_err(|error| match error {
        Error::InvalidHex(_) | Error::InvalidPublicKey(_) => {
            key_text_refusal(key).map_or_else(|| refused(error.to_string()), refused)
        }
        other => other,
    })
}

// The reference's local decode is lock-before alone (PushDropValidation.ts:59,
// PushDrop.ts:74-75; #499). The general decoder reads a first chunk that is not
// a 33- or 65-byte push as lock-after; here that token meets the first-chunk read.
pub(super) fn decode_pushdrop(script: &LockingScript) -> Result<PushDrop> {
    let lock_before = script
        .chunks()
        .first()
        .and_then(|chunk| chunk.data.as_ref())
        .is_some_and(|key| matches!(key.len(), 33 | 65));
    if !lock_before {
        let error = Error::ScriptParseError("Expected a lock-before PushDrop".into());
        return Err(decode_error(error, script));
    }
    PushDrop::decode(script).map_err(|error| decode_error(error, script))
}

fn decode_error(error: Error, script: &LockingScript) -> Error {
    if !matches!(
        error,
        Error::InvalidPublicKey(_) | Error::ScriptParseError(_)
    ) {
        return error;
    }
    // PushDrop.ts:73-77, then PushDropValidation.ts:59-74 with its two fields.
    canonical_refusal(script, &[2]).map_or_else(|| refused(error.to_string()), refused)
}
