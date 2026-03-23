//! WalletWire binary protocol for efficient wallet communication.
//!
//! This module implements the WalletWire protocol, which provides efficient binary
//! serialization for wallet operations. The protocol is designed to be binary-compatible
//! with the TypeScript and Go BSV SDK implementations.
//!
//! # Architecture
//!
//! The protocol uses a client-server model:
//!
//! - **[`WalletWireTransceiver`]** (client): Serializes method calls into binary messages
//!   and deserializes responses. Implements the wallet interface trait.
//!
//! - **[`WalletWire`]** (transport): Abstract trait for binary message transmission.
//!   Can be implemented over HTTP, WebSocket, IPC, etc.
//!
//! - **[`WalletWireProcessor`]** (server): Deserializes incoming messages and dispatches
//!   to the appropriate wallet method. Returns serialized responses.
//!
//! # Wire Format
//!
//! ## Request Frame
//!
//! ```text
//! ┌─────────┬──────────────┬────────────┬────────────────┐
//! │ Call    │ Originator   │ Originator │ Serialized     │
//! │ Code    │ Length       │ String     │ Parameters     │
//! │ (1 byte)│ (1 byte)     │ (N bytes)  │ (variable)     │
//! └─────────┴──────────────┴────────────┴────────────────┘
//! ```
//!
//! ## Response Frame
//!
//! ```text
//! ┌─────────┬────────────────────────────────────────────┐
//! │ Error   │ Result Data (if success) or Error Message  │
//! │ (1 byte)│ (variable length)                          │
//! └─────────┴────────────────────────────────────────────┘
//! ```
//!
//! # Serialization Rules
//!
//! | Type | Encoding |
//! |------|----------|
//! | Strings | VarInt length + UTF-8 bytes |
//! | Optional values | -1 (signed VarInt) for null/undefined |
//! | Booleans | Int8 (1 = true, 0 = false, -1 = undefined) |
//! | Binary data | VarInt length + raw bytes |
//! | Outpoints | 32-byte TXID + VarInt index |
//! | Public keys | 33 bytes (compressed) |
//! | Counterparty | 0 = undefined, 11 = 'self', 12 = 'anyone', else 33-byte pubkey |
//!
//! # Example
//!
//! ```rust,ignore
//! use bsv_rs::wallet::wire::{WalletWire, WalletWireTransceiver};
//!
//! // Implement transport
//! struct HttpWire { /* ... */ }
//!
//! impl WalletWire for HttpWire {
//!     async fn transmit_to_wallet(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
//!         // Send message over HTTP and return response
//!     }
//! }
//!
//! // Create transceiver
//! let wire = HttpWire::new("https://wallet.example.com");
//! let wallet = WalletWireTransceiver::new(wire);
//!
//! // Use wallet methods
//! let result = wallet.get_public_key(args, "originator").await?;
//! ```

mod calls;
mod encoding;
mod processor;
mod transceiver;

pub use calls::WalletCall;
pub use encoding::{WireReader, WireWriter};
pub use processor::WalletWireProcessor;
pub use transceiver::WalletWireTransceiver;

use crate::Error;

/// Transport abstraction for wallet wire protocol.
///
/// Implementations of this trait handle the actual transmission of binary
/// messages to and from the wallet. This could be HTTP, WebSocket, IPC,
/// or any other transport mechanism.
///
/// # Example
///
/// ```rust,ignore
/// use bsv_rs::wallet::wire::WalletWire;
///
/// struct WebSocketWire {
///     url: String,
/// }
///
/// #[async_trait::async_trait]
/// impl WalletWire for WebSocketWire {
///     async fn transmit_to_wallet(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
///         // Send over WebSocket and receive response
///     }
/// }
/// ```
#[async_trait::async_trait]
pub trait WalletWire: Send + Sync {
    /// Transmits a binary message to the wallet and receives a response.
    ///
    /// # Arguments
    ///
    /// * `message` - The binary message to send
    ///
    /// # Returns
    ///
    /// The binary response from the wallet
    async fn transmit_to_wallet(&self, message: &[u8]) -> Result<Vec<u8>, Error>;
}

/// Counterparty wire encoding constants.
pub mod counterparty_codes {
    /// Counterparty is undefined/null.
    pub const UNDEFINED: u8 = 0;
    /// Counterparty is "self".
    pub const SELF: u8 = 11;
    /// Counterparty is "anyone".
    pub const ANYONE: u8 = 12;
}

/// Action status wire encoding.
pub mod status_codes {
    /// Status code for "completed".
    pub const COMPLETED: i8 = 1;
    /// Status code for "unprocessed".
    pub const UNPROCESSED: i8 = 2;
    /// Status code for "sending".
    pub const SENDING: i8 = 3;
    /// Status code for "unproven".
    pub const UNPROVEN: i8 = 4;
    /// Status code for "unsigned".
    pub const UNSIGNED: i8 = 5;
    /// Status code for "nosend".
    pub const NOSEND: i8 = 6;
    /// Status code for "nonfinal".
    pub const NONFINAL: i8 = 7;
    /// Status code for "failed".
    pub const FAILED: i8 = 8;
    /// Status code for unknown/undefined.
    pub const UNKNOWN: i8 = -1;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counterparty_codes() {
        assert_eq!(counterparty_codes::UNDEFINED, 0);
        assert_eq!(counterparty_codes::SELF, 11);
        assert_eq!(counterparty_codes::ANYONE, 12);
    }

    #[test]
    fn test_status_codes() {
        assert_eq!(status_codes::COMPLETED, 1);
        assert_eq!(status_codes::FAILED, 8);
        assert_eq!(status_codes::UNKNOWN, -1);
    }
}
