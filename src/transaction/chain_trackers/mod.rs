//! Chain tracker implementations.
//!
//! This module provides concrete implementations of the [`ChainTracker`] trait
//! for verifying merkle roots against the blockchain.
//!
//! # Available Trackers
//!
//! - [`WhatsOnChainTracker`] - Verifies via WhatsOnChain API
//!
//! # Feature Requirements
//!
//! These implementations require the `http` feature to be enabled:
//!
//! ```toml
//! [dependencies]
//! bsv-sdk = { version = "0.2", features = ["transaction", "http"] }
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use bsv_sdk::transaction::{ChainTracker, WhatsOnChainTracker};
//!
//! #[tokio::main]
//! async fn main() {
//!     let tracker = WhatsOnChainTracker::mainnet();
//!
//!     let height = tracker.current_height().await.unwrap();
//!     println!("Current height: {}", height);
//! }
//! ```

mod whatsonchain;

pub use whatsonchain::{WhatsOnChainTracker, WocNetwork};
