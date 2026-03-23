//! Wallet communication substrates.
//!
//! This module provides transport substrates for wallet communication.
//! Substrates implement the [`crate::wallet::wire::WalletWire`] trait and handle the actual
//! network communication.
//!
//! # Available Substrates
//!
//! | Substrate | Protocol | Default Port | Description |
//! |-----------|----------|--------------|-------------|
//! | `HttpWalletWire` | Binary | 3301 | Wire protocol over HTTP |
//! | `HttpWalletJson` | JSON | 3321 | JSON API over HTTP |
//!
//! # Platform-Specific Substrates (Not Included)
//!
//! The following substrates from the TypeScript SDK are NOT included in Rust:
//!
//! - **XDM**: Requires browser `window.parent.postMessage()` API
//! - **ReactNativeWebView**: Requires React Native bridge
//! - **WindowCWI**: Requires browser extension injection
//!
//! These substrates require a JavaScript runtime and are not applicable to
//! native Rust code. The Go SDK also excludes these for the same reason.
//!
//! # Example
//!
//! ```rust,ignore
//! use bsv_rs::wallet::substrates::HttpWalletWire;
//! use bsv_rs::wallet::wire::WalletWireTransceiver;
//!
//! // Create HTTP wire substrate
//! let wire = HttpWalletWire::new(Some("myapp.example.com".into()), None);
//!
//! // Wrap with transceiver for wallet operations
//! let wallet = WalletWireTransceiver::new(wire);
//!
//! // Use wallet methods
//! let version = wallet.get_version("myapp.example.com").await?;
//! ```

#[cfg(feature = "http")]
mod http_json;
#[cfg(feature = "http")]
mod http_wire;

#[cfg(feature = "http")]
pub use http_json::HttpWalletJson;
#[cfg(feature = "http")]
pub use http_wire::HttpWalletWire;

/// Default port for HTTP Wire protocol.
pub const DEFAULT_WIRE_PORT: u16 = 3301;

/// Default port for HTTP JSON protocol.
pub const DEFAULT_JSON_PORT: u16 = 3321;

/// Default base URL for HTTP Wire protocol.
pub const DEFAULT_WIRE_URL: &str = "http://localhost:3301";

/// Default base URL for HTTP JSON protocol.
pub const DEFAULT_JSON_URL: &str = "http://localhost:3321";

/// Secure local JSON API URL.
pub const SECURE_JSON_URL: &str = "https://localhost:2121";
