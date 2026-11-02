//! `PushDrop::decode`'s reading of a key alone and of a key whose second
//! chunk is not `OP_CHECKSIG` (#618), the two shapes the lock-before read
//! refuses: the reference's `PushDrop.decode` at its default position
//! (`ts-stack@edf6e03` `PushDrop.ts:63-121`); and the field loop every path
//! of `decode` reads with (`:96-115`, #618's fold). The canonical path
//! (`PushDrop::decode_before`, the identity and contacts envelope checks)
//! still refuses both, as each site's reference counterpart does.

use super::{LockPosition, PushDrop};
use crate::primitives::PublicKey;
use crate::script::op::{OP_0, OP_1NEGATE, OP_2DROP, OP_DROP};
use crate::script::ScriptChunk;
use crate::Result;

impl PushDrop {
    /// The key the first chunk (`PushDrop.ts:73-77`), the second chunk
    /// never read, the fields from the third: each chunk pushed, then the
    /// read ends where the *next* chunk is a DROP (`:96-115`).
    pub(super) fn decode_reference_before(chunks: &[ScriptChunk]) -> Result<Self> {
        let key = chunks
            .first()
            .and_then(|chunk| chunk.data.as_deref())
            .unwrap_or_default();
        let locking_public_key = PublicKey::from_bytes(key)?;
        Ok(Self {
            locking_public_key,
            fields: reference_fields(chunks, 2),
            lock_position: LockPosition::Before,
        })
    }
}

/// The fields from `start` as `PushDrop.ts:96-115` reads them, on every path
/// of `decode` (#618 and its fold): each chunk is a field, a DROP or 2DROP
/// among them, and the read ends where the *next* chunk is a DROP or 2DROP,
/// else at the script's end (lock-after, the key and `OP_CHECKSIG` too).
pub(super) fn reference_fields(chunks: &[ScriptChunk], start: usize) -> Vec<Vec<u8>> {
    let mut fields = Vec::new();
    for (index, chunk) in chunks.iter().enumerate().skip(start) {
        fields.push(reference_field(chunk));
        if chunks
            .get(index + 1)
            .is_some_and(|next| matches!(next.op, OP_DROP | OP_2DROP))
        {
            break;
        }
    }
    fields
}

/// A chunk's field (`PushDrop.ts:99-109`): its data, or for an empty one the
/// number its opcode pushes (`OP_0`, `0x50`-`0x60` less `0x50`,
/// `OP_1NEGATE`), else empty: `OP_RESERVED` is `00`, a DROP's own chunk and
/// an empty `OP_PUSHDATA1` are empty.
fn reference_field(chunk: &ScriptChunk) -> Vec<u8> {
    let data = chunk.data.clone().unwrap_or_default();
    if !data.is_empty() {
        return data;
    }
    match chunk.op {
        op @ 0x50..=0x60 => vec![op - 0x50],
        OP_0 => vec![0],
        OP_1NEGATE => vec![0x81],
        _ => Vec::new(),
    }
}
