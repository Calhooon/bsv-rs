//! PushDrop's decode at the reference's default lock position (#537), and
//! the reference's words where that read refuses a token.

use super::PushDrop;
use crate::primitives::{BigNumber, PublicKey};
use crate::script::{op, LockingScript};
use crate::{Error, Result};

impl PushDrop {
    /// `PushDrop.decode(script)` at its default position, `'before'`
    /// (`ts-stack@edf6e03` `PushDrop.ts:63-78`), as every call site of the
    /// identity, contacts, registry, kvstore, overlay and storage clients'
    /// counterparts passes it: the key is the first chunk and the other
    /// position is never tried, so a lock-after token is refused at the key
    /// read. [`PushDrop::decode`] still reads both positions.
    pub(crate) fn decode_before(script: &LockingScript) -> Result<Self> {
        let chunks = script.chunks();
        if chunks.len() < 2 {
            return Err(Error::ScriptParseError(
                "Script too short for PushDrop".into(),
            ));
        }
        if chunks[0].data.is_none() {
            return Err(Error::ScriptParseError(
                "script.chunks[0].data must have value".into(),
            ));
        }
        Self::decode_lock_before(&chunks)
    }
}

/// `Point.fromDER`'s words (`ts-stack@edf6e03` `Point.ts:303-325`) for key
/// bytes it refuses; `None` where the reference accepts the point, so the
/// caller keeps its native words. Normalization here only selects a
/// diagnostic: it does not change which keys this crate accepts.
pub(crate) fn point_message(bytes: &[u8]) -> Option<&'static str> {
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

/// The words `decodeCanonicalPushDrop` (`PushDropValidation.ts:54-79`) with
/// `counts` as its field counts throws for a script this crate's lock-before
/// read refuses: the first chunk's read, then the key's parse
/// (`PushDrop.ts:73-77`), then the count of the fields it reads (until the
/// *next* chunk is a DROP, `:96-115`) and the envelope. `None` where the
/// reference accepts a key this crate refuses.
pub(crate) fn canonical_refusal(script: &LockingScript, counts: &[usize]) -> Option<&'static str> {
    let chunks = script.chunks();
    let Some(first) = chunks.first() else {
        return Some("Cannot read properties of undefined (reading 'data')");
    };
    let Some(key) = &first.data else {
        return Some("script.chunks[0].data must have value");
    };
    if PublicKey::from_bytes(key).is_err() {
        return point_message(key);
    }
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
    Some(if counts.contains(&fields) {
        "PushDrop token must use the canonical PushDrop envelope"
    } else {
        "Unexpected PushDrop token field count"
    })
}

/// [`canonical_refusal`] for a token written lock-after (one the general
/// decoder reads at that position), `None` for any other script.
pub(crate) fn lock_after_refusal(script: &LockingScript, counts: &[usize]) -> Option<&'static str> {
    PushDrop::decode_lock_after(&script.chunks()).ok()?;
    canonical_refusal(script, counts)
}
