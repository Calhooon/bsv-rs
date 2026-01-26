//! Transaction broadcaster implementations.
//!
//! This module provides concrete implementations of the [`Broadcaster`] trait
//! for broadcasting transactions to the BSV network.
//!
//! # Available Broadcasters
//!
//! - [`ArcBroadcaster`] - Broadcasts via the ARC (TAAL's broadcast service)
//!
//! # Feature Requirements
//!
//! These implementations require the `http` feature to be enabled:
//!
//! ```toml
//! [dependencies]
//! bsv-sdk = { version = "0.2", features = ["transaction", "http"] }
//! ```

mod arc;

pub use arc::{ArcBroadcaster, ArcConfig};
