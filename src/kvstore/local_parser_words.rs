//! Local parser catches: the reference's Error.message, without changing primitives.
use super::lookup::refused;
use crate::primitives::PublicKey;
use crate::script::{op, templates::PushDrop, LockingScript};
use crate::{Error, Result};

// Point.fromDER at ts-stack@edf6e03 Point.ts:303-325. Inspect the failed
// encoding's shape, never a native diagnostic's words.
fn point_message(length: usize, prefix: Option<u8>, last: Option<u8>) -> &'static str {
    match (length, prefix, last) {
        (65, Some(prefix @ (6 | 7)), Some(last)) if (prefix & 1) != (last & 1) => {
            "Point string value is wrong length"
        }
        (33, Some(2 | 3), _) | (65, Some(4 | 6 | 7), _) => "Invalid point",
        _ => "Unknown point format",
    }
}

pub(super) fn parse_public_key(key: &str) -> Result<PublicKey> {
    PublicKey::from_hex(key).map_err(|error| match error {
        Error::InvalidHex(_) if !key.bytes().all(|byte| byte.is_ascii_hexdigit()) => {
            refused("Invalid hex string")
        }
        Error::InvalidHex(_) | Error::InvalidPublicKey(_) => {
            // The reference pads an odd hex string before classifying its point.
            let prefix_chars = if key.len().is_multiple_of(2) { 2 } else { 1 };
            let prefix = key
                .get(..prefix_chars)
                .and_then(|text| u8::from_str_radix(text, 16).ok());
            let last = key
                .get(key.len().saturating_sub(2)..)
                .and_then(|text| u8::from_str_radix(text, 16).ok());
            refused(point_message(key.len().div_ceil(2), prefix, last))
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
    // LocalKVStore always uses lock-before. PushDrop.decode :73-77 reads this
    // key before inspecting fields; Rust's general decoder also tries lock-after.
    let chunks = script.chunks();
    let Some(first) = chunks.first() else {
        return refused("Cannot read properties of undefined (reading 'data')");
    };
    let Some(key) = &first.data else {
        return refused("script.chunks[0].data must have value");
    };
    if PublicKey::from_bytes(key).is_err() {
        return refused(point_message(
            key.len(),
            key.first().copied(),
            key.last().copied(),
        ));
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
