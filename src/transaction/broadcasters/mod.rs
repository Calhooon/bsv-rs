//! Transaction broadcaster implementations.
//!
//! This module provides concrete implementations of the [`Broadcaster`](super::Broadcaster) trait
//! for broadcasting transactions to the BSV network.
//!
//! # Available Broadcasters
//!
//! - [`ArcBroadcaster`] - Broadcasts via the ARC (TAAL's broadcast service)
//! - [`WhatsOnChainBroadcaster`] - Broadcasts via the WhatsOnChain API
//!
//! # Feature Requirements
//!
//! These implementations require the `http` feature to be enabled:
//!
//! ```toml
//! [dependencies]
//! bsv-rs = { version = "0.3", features = ["transaction", "http"] }
//! ```

// The one rule of the id a success answers; ARC's verdict (built without
// `http` for its tests) and WhatsOnChain (`http` only) ask it.
#[cfg_attr(not(feature = "http"), allow(dead_code))]
mod acknowledged;
mod arc;
mod teranode;
mod whatsonchain;

pub use arc::{ArcBroadcaster, ArcConfig};
pub use teranode::{TeranodeBroadcaster, TeranodeConfig};
pub use whatsonchain::{WhatsOnChainBroadcaster, WocBroadcastConfig, WocBroadcastNetwork};
