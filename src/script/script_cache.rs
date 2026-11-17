//! The owner of a [`Script`](super::Script)'s chunks and of the two
//! serializations derived from them (#843d1, the IDENTITY law of #843 for
//! scripts, `docs/design/843-identity-and-framing.md`, sections 2 and 8).
//!
//! [`Cache`]'s three fields are private to this module, so no other code can
//! name one: a cache is filled only through `&self` (`get_or_init`, here), and
//! the one way to a `&mut` of the chunks is [`Cache::write`], which parses,
//! then empties both serializations, then lends. The compiler holds that much
//! (E0616, E0451). That a cache is FILLED with the right value is the claim of
//! `tests/script_cache_agreement_843d1.rs` and of `fuzz_script_parser`'s
//! invariant, not the compiler's.
//!
//! The reference holds the same three things (`ts-stack@edf6e03`
//! `Script.ts:54-57`: `#_chunks`, `#rawBytesCache`, `#hexCache`), parses its
//! bytes once (`:206-215`) and drops its caches at every writer (`:492-496`).
//! Its getter lends a mutable array (`:195-198`) and finds an in-place edit at
//! its next serialization (`:507-536`); here the lent slice is shared and an
//! edit goes through `write`.

use std::sync::OnceLock;

use super::{serialize_chunks, Script};
use crate::primitives::to_hex;
use crate::script::ScriptChunk;

/// The chunks and their two serializations. Built only from chunks or from
/// bytes, so one of `chunks` and `raw` is always set; no macro, no derive and
/// no attribute but doc comments inside, so nothing expands into it.
pub(super) struct Cache {
    chunks: OnceLock<Vec<ScriptChunk>>,
    raw: OnceLock<Vec<u8>>,
    hex: OnceLock<String>,
}

impl Cache {
    /// A script held as its chunks; its bytes and hex filled when asked.
    pub(super) fn from_chunks(chunks: Vec<ScriptChunk>) -> Self {
        Self {
            chunks: OnceLock::from(chunks),
            raw: OnceLock::new(),
            hex: OnceLock::new(),
        }
    }

    /// A script held as the bytes given (and their hex, when the caller read
    /// them from hex); its chunks parsed when asked. The bytes are answered as
    /// given until an edit, as the reference's `#getSerializedBytes` answers
    /// them while unparsed (`Script.ts:529`).
    pub(super) fn from_bytes(raw: Vec<u8>, hex: Option<String>) -> Self {
        let hex_cache = OnceLock::new();
        if let Some(text) = hex {
            let _ = hex_cache.set(text);
        }
        Self {
            chunks: OnceLock::new(),
            raw: OnceLock::from(raw),
            hex: hex_cache,
        }
    }

    /// The chunks, parsed from the bytes once.
    pub(super) fn chunks(&self) -> &[ScriptChunk] {
        self.chunks.get_or_init(|| {
            Script::parse_chunks(self.raw.get().map_or(&[][..], Vec::as_slice), true)
        })
    }

    /// The bytes: as given, else the serialization of the chunks.
    pub(super) fn bytes(&self) -> &[u8] {
        self.raw.get_or_init(|| serialize_chunks(self.chunks()))
    }

    /// The hex of [`Cache::bytes`].
    pub(super) fn hex(&self) -> &str {
        self.hex.get_or_init(|| to_hex(self.bytes()))
    }

    /// The one exclusive door: parses the chunks (so a script held as bytes
    /// keeps them: `write_opcode`'s regression test), then empties both
    /// serializations, then lends the chunks to `edit`. The chunks stay in
    /// place during the edit, so a panic in `edit` leaves a script whose
    /// serializations are recomputed from what it holds.
    pub(super) fn write<R>(&mut self, edit: impl FnOnce(&mut Vec<ScriptChunk>) -> R) -> R {
        let _ = self.chunks();
        self.raw.take();
        self.hex.take();
        match self.chunks.get_mut() {
            Some(chunks) => edit(chunks),
            // `chunks()` above set it and nothing took it since; a scratch
            // list keeps this arm total without a panic.
            None => edit(&mut Vec::new()),
        }
    }
}

impl Clone for Cache {
    fn clone(&self) -> Self {
        Self {
            chunks: self.chunks.clone(),
            raw: self.raw.clone(),
            hex: self.hex.clone(),
        }
    }
}

impl std::fmt::Debug for Cache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cache")
            .field("chunks", &self.chunks.get())
            .field("bytes", &self.raw.get())
            .field("hex", &self.hex.get())
            .finish()
    }
}
