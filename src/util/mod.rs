//! Internal utilities shared across crate modules.
//!
//! Nothing in this module is part of the public API; it exists purely to
//! provide cfg-gated helpers (wasm32-safe time; `debug_redact`, the header and
//! URL `Debug` helpers) that several feature
//! gates need without forcing them to depend on each other.

#[cfg(feature = "transaction")]
pub(crate) mod debug_redact;
pub(crate) mod time;
