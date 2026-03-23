//! Chain tracker implementations.
//!
//! This module provides concrete implementations of the [`ChainTracker`](super::ChainTracker) trait
//! for verifying merkle roots against the blockchain.
//!
//! # Available Trackers
//!
//! - [`WhatsOnChainTracker`] - Verifies via WhatsOnChain API
//! - [`BlockHeadersServiceTracker`] - Verifies via Block Headers Service API
//!
//! # Feature Requirements
//!
//! These implementations require the `http` feature to be enabled:
//!
//! ```toml
//! [dependencies]
//! bsv-rs = { version = "0.3", features = ["transaction", "http"] }
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use bsv_rs::transaction::{ChainTracker, WhatsOnChainTracker};
//!
//! #[tokio::main]
//! async fn main() {
//!     let tracker = WhatsOnChainTracker::mainnet();
//!
//!     let height = tracker.current_height().await.unwrap();
//!     println!("Current height: {}", height);
//! }
//! ```

mod block_headers_service;
mod whatsonchain;

pub use block_headers_service::{
    BlockHeadersServiceConfig, BlockHeadersServiceTracker, DEFAULT_HEADERS_URL,
};
pub use whatsonchain::{WhatsOnChainTracker, WocNetwork};
