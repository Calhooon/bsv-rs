//! Internal utilities shared across crate modules.
//!
//! Nothing in this module is part of the public API; it exists purely to
//! provide cfg-gated helpers (e.g. wasm32-safe time) that several feature
//! gates need without forcing them to depend on each other.

pub(crate) mod time;
