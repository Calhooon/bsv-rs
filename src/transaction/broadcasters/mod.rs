//! Transaction broadcaster implementations.
//!
//! This module provides concrete implementations of the [`Broadcaster`](super::Broadcaster) trait
//! for broadcasting transactions to the BSV network.
//!
//! # Available Broadcasters
//!
//! - [`TeranodeBroadcaster`] - Broadcasts Extended Format bytes to a Teranode `POST /v1/tx`
//! - [`WhatsOnChainBroadcaster`] - Broadcasts via the WhatsOnChain API
//! - [`ArcBroadcaster`] - ARC (TAAL's broadcast service): deprecated since 0.9.0,
//!   ARC is deprecated and ARCade is the standard (bsv-rs#350); never a default
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

// The one transport-fault classifier of every HTTP transport (#87): here
// because a network client lives in a transport home and `transaction` is
// the lowest feature gate the four homes share.
#[cfg(feature = "http")]
pub(crate) mod transport_fault;

#[allow(deprecated)] // re-exported for the callers who name them; deprecated at the definition
pub use arc::{ArcBroadcaster, ArcConfig};
pub use teranode::{TeranodeBroadcaster, TeranodeConfig};
pub use whatsonchain::{WhatsOnChainBroadcaster, WocBroadcastConfig, WocBroadcastNetwork};
