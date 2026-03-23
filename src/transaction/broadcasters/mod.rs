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

mod arc;
mod teranode;
mod whatsonchain;

pub use arc::{ArcBroadcaster, ArcConfig};
pub use teranode::{TeranodeBroadcaster, TeranodeConfig};
pub use whatsonchain::{WhatsOnChainBroadcaster, WocBroadcastConfig, WocBroadcastNetwork};
