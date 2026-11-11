//! The crate.
pub mod error;
pub(crate) mod util;
#[cfg(feature = "primitives")]
pub mod primitives;
#[cfg(feature = "transaction")]
pub mod transaction;
