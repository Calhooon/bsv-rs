//! Internal utilities shared across crate modules.
//!
//! Nothing in this module is part of the public API; it exists purely to
//! provide cfg-gated helpers (wasm32-safe time; `debug_redact`, the header and
//! URL `Debug` helpers; `non_exhaustive_enum!`, an enum's `#[non_exhaustive]`
//! pinned by a doc test written from its definition, #819) that several feature
//! gates need without forcing them to depend on each other.

#[cfg(feature = "transaction")]
pub(crate) mod debug_redact;
/// `non_exhaustive_enum!`: an enum's `#[non_exhaustive]` pinned by a doc test
/// written from the definition itself (#819's fold); `assert_no_drop!`, a
/// pinned struct's `Drop` and its pin's path held by the compiler.
///
/// A hand-written `compile_fail` match that names every variant judges the
/// attribute only while it does name every variant: stable rustdoc checks no
/// error number, so once a variant is added and the block is not extended the
/// block fails to compile for the missing arm, with the attribute or without
/// it, and reads `ok` (`Kind` and `Reason` of the BEEF stream stood so from
/// #167 until the fold). The macro's block names the definition's variants by
/// construction, one arm each and no wildcard, so the only thing left for it
/// to fail on is the attribute; its compiling twin, the same arms and a
/// wildcard, fails where the block is broken in another way.
///
/// The file holds no inner attribute (#819's third fold): its own doc tests
/// `include!` it whole, so the macros are held by what they write and what
/// they refuse to compile, not by their text. The doc suite's lines for every
/// pinned type and for those doc tests are read by
/// `tests/arch_non_exhaustive_pins_819.rs` from the log of CI's doc step.
pub(crate) mod non_exhaustive;
pub(crate) mod time;
