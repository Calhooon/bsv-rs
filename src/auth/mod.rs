//! # Auth Module
//!
//! Peer-to-peer authentication using BRC-31 (Authrite) protocol.
//!
//! ## Overview
//!
//! This module provides mutual authentication between peers using
//! cryptographic handshakes and optional certificate exchange.
//!
//! ## Components
//!
//! - [`Peer`] - Main authentication handler
//! - [`SessionManager`] - Concurrent session management
//! - [`certificates`] - BRC-52/53 certificate handling
//! - [`transports`] - Transport layer implementations
//!
//! ## Authentication Flow
//!
//! 1. **Initial Handshake**: Peers exchange nonces and establish session
//! 2. **Certificate Exchange** (optional): Peers exchange identity certificates
//! 3. **General Messages**: Authenticated message exchange
//!
//! ## Example
//!
//! ```rust,ignore
//! use bsv_sdk::auth::{Peer, PeerOptions, SimplifiedFetchTransport};
//! use bsv_sdk::wallet::ProtoWallet;
//! use bsv_sdk::primitives::PrivateKey;
//!
//! // Create wallet and transport
//! let wallet = ProtoWallet::new(Some(PrivateKey::random()));
//! let transport = SimplifiedFetchTransport::new("https://example.com");
//!
//! // Create peer
//! let peer = Peer::new(PeerOptions {
//!     wallet,
//!     transport,
//!     certificates_to_request: None,
//!     session_manager: None,
//!     auto_persist_last_session: false,
//!     originator: Some("myapp.com".into()),
//! });
//!
//! // Send authenticated message
//! peer.to_peer(b"Hello!", Some(&recipient_key), None).await?;
//!
//! // Listen for incoming messages
//! let callback_id = peer.listen_for_general_messages(|sender, payload| {
//!     Box::pin(async move {
//!         println!("Received from {}: {:?}", sender.to_hex(), payload);
//!         Ok(())
//!     })
//! }).await;
//! ```
//!
//! ## BRC Standards
//!
//! This module implements:
//! - **BRC-31**: Authrite peer-to-peer authentication
//! - **BRC-52**: Certificate issuance and structure
//! - **BRC-53**: Certificate verification with selective disclosure
//! - **BRC-104**: HTTP headers for authenticated requests

pub mod certificates;
pub mod peer;
pub mod session_manager;
pub mod transports;
pub mod types;
pub mod utils;

// Re-exports
pub use certificates::{Certificate, MasterCertificate, VerifiableCertificate};
pub use peer::{Peer, PeerOptions};
pub use session_manager::SessionManager;
pub use transports::{MockTransport, SimplifiedFetchTransport, Transport};
pub use types::{
    current_time_ms, AuthMessage, MessageType, PeerSession, RequestedCertificateSet, AUTH_PROTOCOL_ID,
    AUTH_VERSION,
};
pub use utils::{create_nonce, validate_certificates, verify_nonce};
