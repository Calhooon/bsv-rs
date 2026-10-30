//! Local parser catches: reference words only for failures the reference also has.
use super::lookup::refused;
use crate::primitives::{from_hex, BigNumber, PublicKey};
use crate::script::{op, templates::PushDrop, LockingScript};
use crate::{Error, Result};

// Point.fromDER at ts-stack@edf6e03 Point.ts:303-325. None means the reference
// accepts the point, so keep the native words. Normalization here only selects
// a diagnostic: it does not change which keys this crate accepts.
fn point_message(bytes: &[u8]) -> Option<&'static str> {
    match (bytes.len(), bytes.first().copied(), bytes.last().copied()) {
        (65, Some(prefix @ (6 | 7)), Some(last)) if (prefix & 1) != (last & 1) => {
            return Some("Point string value is wrong length");
        }
        (33, Some(2 | 3), _) | (65, Some(4 | 6 | 7), _) => {}
        _ => return Some("Unknown point format"),
    }
    let mut canonical = bytes.to_vec();
    if canonical.len() == 65 {
        canonical[0] = 4;
    }
    // The reference checks hybrid parity before field arithmetic; both its
    // Point constructor/validate and fromX evaluate coordinates modulo p.
    let prime = BigNumber::secp256k1_prime();
    for coordinate in canonical[1..].as_chunks_mut::<32>().0 {
        let reduced = BigNumber::from_bytes_be(coordinate)
            .modulo(&prime)
            .to_bytes_be(32);
        coordinate.copy_from_slice(&reduced);
    }
    PublicKey::from_bytes(&canonical)
        .is_err()
        .then_some("Invalid point")
}

pub(super) fn parse_public_key(key: &str) -> Result<PublicKey> {
    PublicKey::from_hex(key).map_err(|error| match error {
        Error::InvalidHex(_) if !key.bytes().all(|byte| byte.is_ascii_hexdigit()) => {
            refused("Invalid hex string")
        }
        Error::InvalidHex(_) | Error::InvalidPublicKey(_) => {
            if !matches!(key.len().div_ceil(2), 33 | 65) {
                return refused("Unknown point format");
            }
            // Bound the diagnostic's allocation, then pad as hex.ts:28-30 does.
            let bytes = if key.len().is_multiple_of(2) {
                from_hex(key)
            } else {
                from_hex(&format!("0{key}"))
            };
            bytes
                .ok()
                .as_deref()
                .and_then(point_message)
                .map_or_else(|| refused(error.to_string()), refused)
        }
        other => other,
    })
}

pub(super) fn decode_pushdrop(script: &LockingScript) -> Result<PushDrop> {
    PushDrop::decode(script).map_err(|error| decode_error(error, script))
}

fn decode_error(error: Error, script: &LockingScript) -> Error {
    if !matches!(
        error,
        Error::InvalidPublicKey(_) | Error::ScriptParseError(_)
    ) {
        return error;
    }
    // The reference's LocalKVStore uses lock-before (PushDrop.ts:73-77).
    // Rust also decodes lock-after; a success reaches decode_token's later
    // field/envelope checks unchanged (the stated #489 parity difference).
    let chunks = script.chunks();
    let Some(first) = chunks.first() else {
        return refused("Cannot read properties of undefined (reading 'data')");
    };
    let Some(key) = &first.data else {
        return refused("script.chunks[0].data must have value");
    };
    if PublicKey::from_bytes(key).is_err() {
        return point_message(key).map_or_else(|| refused(error.to_string()), refused);
    }
    // A valid key can still fail the general decoder's length/CHECKSIG tests.
    // Reference PushDrop.ts:96-115 reads fields until the *next* chunk is DROP;
    // PushDropValidation.ts:59-74 then checks field count before the envelope.
    let mut fields = 0;
    for index in 2..chunks.len() {
        fields += 1;
        if chunks
            .get(index + 1)
            .is_some_and(|chunk| matches!(chunk.op, op::OP_DROP | op::OP_2DROP))
        {
            break;
        }
    }
    refused(if fields != 2 {
        "Unexpected PushDrop token field count"
    } else {
        "PushDrop token must use the canonical PushDrop envelope"
    })
}
