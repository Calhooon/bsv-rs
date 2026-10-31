//! PushDrop's decode at the reference's default lock position (#537).

use super::PushDrop;
use crate::script::LockingScript;
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
