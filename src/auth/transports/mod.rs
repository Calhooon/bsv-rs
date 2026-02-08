//! Transport implementations for auth messages.
//!
//! This module provides transport layer implementations for sending
//! and receiving authentication messages.
//!
//! ## Available Transports
//!
//! - [`SimplifiedFetchTransport`] - HTTP-based transport (requires `http` feature)
//! - `WebSocketTransport` - WebSocket-based transport (requires `websocket` feature)
//! - [`MockTransport`] - Mock transport for testing
//!
//! ## Custom Transports
//!
//! Implement the [`Transport`] trait to create custom transports:
//!
//! ```rust,ignore
//! use bsv_sdk::auth::transports::Transport;
//!
//! struct MyTransport;
//!
//! #[async_trait]
//! impl Transport for MyTransport {
//!     async fn send(&self, message: &AuthMessage) -> Result<()> {
//!         // Send the message
//!         Ok(())
//!     }
//!
//!     fn set_callback(&self, callback: Box<TransportCallback>) {
//!         // Store the callback
//!     }
//!
//!     fn clear_callback(&self) {
//!         // Clear the callback
//!     }
//! }
//! ```

pub mod http;

#[cfg(feature = "websocket")]
pub mod websocket_transport;

pub use http::{
    headers, HttpRequest, HttpResponse, MockTransport, SimplifiedFetchTransport, Transport,
    TransportCallback,
};

#[cfg(feature = "websocket")]
pub use websocket_transport::{WebSocketTransport, WebSocketTransportOptions};
