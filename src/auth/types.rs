//! Core types for BRC-31 authentication protocol.
//!
//! This module defines the fundamental types used in peer-to-peer authentication:
//! - `MessageType` - Authentication message types
//! - `AuthMessage` - Full authentication message structure
//! - `PeerSession` - Session state between peers
//! - `RequestedCertificateSet` - Certificate request specification

use crate::primitives::PublicKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Protocol version for BRC-31 authentication.
pub const AUTH_VERSION: &str = "0.1";

/// Protocol ID used for signing auth messages.
/// This is used with security level 2 for BRC-42 key derivation.
pub const AUTH_PROTOCOL_ID: &str = "auth message signature";

/// Message types in the BRC-31 authentication protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum MessageType {
    /// Initial authentication request from initiator.
    InitialRequest,
    /// Response to initial request with session nonce.
    InitialResponse,
    /// Request for certificates from peer.
    CertificateRequest,
    /// Response with certificates.
    CertificateResponse,
    /// General authenticated message.
    General,
}

impl MessageType {
    /// Returns the string representation of the message type.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InitialRequest => "initialRequest",
            Self::InitialResponse => "initialResponse",
            Self::CertificateRequest => "certificateRequest",
            Self::CertificateResponse => "certificateResponse",
            Self::General => "general",
        }
    }

    /// Parses a message type from its string representation.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "initialRequest" => Some(Self::InitialRequest),
            "initialResponse" => Some(Self::InitialResponse),
            "certificateRequest" => Some(Self::CertificateRequest),
            "certificateResponse" => Some(Self::CertificateResponse),
            "general" => Some(Self::General),
            _ => None,
        }
    }

    /// Returns true if this is an initial handshake message type.
    pub fn is_handshake(&self) -> bool {
        matches!(self, Self::InitialRequest | Self::InitialResponse)
    }

    /// Returns true if this is a certificate-related message type.
    pub fn is_certificate(&self) -> bool {
        matches!(self, Self::CertificateRequest | Self::CertificateResponse)
    }
}

impl std::fmt::Display for MessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Authentication message structure (BRC-31).
///
/// This structure represents all message types in the authentication protocol.
/// Different fields are used depending on the message type.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthMessage {
    /// Protocol version (e.g., "0.1").
    pub version: String,

    /// Type of message.
    pub message_type: MessageType,

    /// Sender's identity key (33-byte compressed public key).
    pub identity_key: PublicKey,

    /// Sender's nonce for this message (base64, 32 bytes: 16 random + 16 HMAC).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,

    /// Session nonce from initial handshake (for InitialResponse).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_nonce: Option<String>,

    /// Recipient's nonce from previous message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub your_nonce: Option<String>,

    /// Attached certificates (for CertificateResponse).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificates: Option<Vec<crate::auth::certificates::VerifiableCertificate>>,

    /// Requested certificate specifications (for InitialRequest, CertificateRequest).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_certificates: Option<RequestedCertificateSet>,

    /// Message payload (for General messages).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<Vec<u8>>,

    /// DER-encoded signature over message contents.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<Vec<u8>>,
}

impl AuthMessage {
    /// Creates a new message with required fields.
    pub fn new(message_type: MessageType, identity_key: PublicKey) -> Self {
        Self {
            version: AUTH_VERSION.to_string(),
            message_type,
            identity_key,
            nonce: None,
            initial_nonce: None,
            your_nonce: None,
            certificates: None,
            requested_certificates: None,
            payload: None,
            signature: None,
        }
    }

    /// Returns the bytes to sign for this message.
    ///
    /// The signing data varies by message type:
    /// - InitialResponse: yourNonce || initialNonce (initiator's nonce || responder's session nonce, decoded from base64)
    /// - General/CertificateRequest/CertificateResponse: payload or serialized requested_certificates
    pub fn signing_data(&self) -> Vec<u8> {
        match self.message_type {
            MessageType::InitialResponse => {
                // For InitialResponse, sign: yourNonce (initiator's nonce) || initialNonce (responder's session nonce)
                // This matches Go/TS SDKs: initiator_nonce_bytes || responder_nonce_bytes
                let mut data = Vec::new();
                if let Some(ref your_nonce) = self.your_nonce {
                    if let Ok(decoded) = crate::primitives::from_base64(your_nonce) {
                        data.extend_from_slice(&decoded);
                    }
                }
                if let Some(ref initial_nonce) = self.initial_nonce {
                    if let Ok(decoded) = crate::primitives::from_base64(initial_nonce) {
                        data.extend_from_slice(&decoded);
                    }
                }
                data
            }
            MessageType::General => {
                // For General messages, sign the payload
                self.payload.clone().unwrap_or_default()
            }
            MessageType::CertificateRequest => {
                // For CertificateRequest, sign the serialized requested_certificates
                if let Some(ref req) = self.requested_certificates {
                    serde_json::to_vec(req).unwrap_or_default()
                } else {
                    Vec::new()
                }
            }
            MessageType::CertificateResponse => {
                // For CertificateResponse, sign serialized certificates
                if let Some(ref certs) = self.certificates {
                    serde_json::to_vec(certs).unwrap_or_default()
                } else {
                    Vec::new()
                }
            }
            MessageType::InitialRequest => {
                // Initial request is not signed (starts handshake)
                Vec::new()
            }
        }
    }

    /// Returns the key ID to use for signing/verification.
    ///
    /// Format: "{nonce} {peer_nonce}" for most messages.
    pub fn get_key_id(&self, peer_session_nonce: Option<&str>) -> String {
        let nonce = self.nonce.as_deref().unwrap_or("");
        let peer_nonce = peer_session_nonce.unwrap_or("");

        match self.message_type {
            MessageType::InitialResponse => {
                // For InitialResponse: "{yourNonce} {initialNonce}" = "{initiator_nonce} {responder_nonce}"
                // Matches Go: keyID(message.InitialNonce, session.SessionNonce) on responder
                //             keyID(session.SessionNonce, message.InitialNonce) on initiator
                let your = self.your_nonce.as_deref().unwrap_or("");
                let initial = self.initial_nonce.as_deref().unwrap_or("");
                format!("{} {}", your, initial)
            }
            _ => {
                // For other messages: "{nonce} {peer_session_nonce}"
                format!("{} {}", nonce, peer_nonce)
            }
        }
    }

    /// Validates the message structure.
    pub fn validate(&self) -> crate::Result<()> {
        // Check version
        if self.version != AUTH_VERSION {
            return Err(crate::Error::AuthError(format!(
                "Invalid auth version: expected {}, got {}",
                AUTH_VERSION, self.version
            )));
        }

        // Validate based on message type
        match self.message_type {
            MessageType::InitialRequest => {
                // InitialRequest must have an initial_nonce (session nonce)
                if self.initial_nonce.is_none() {
                    return Err(crate::Error::AuthError(
                        "InitialRequest must have an initial_nonce".into(),
                    ));
                }
            }
            MessageType::InitialResponse => {
                // InitialResponse must have nonce, initial_nonce, your_nonce, and signature
                if self.nonce.is_none() {
                    return Err(crate::Error::AuthError(
                        "InitialResponse must have a nonce".into(),
                    ));
                }
                if self.initial_nonce.is_none() {
                    return Err(crate::Error::AuthError(
                        "InitialResponse must have initial_nonce".into(),
                    ));
                }
                if self.your_nonce.is_none() {
                    return Err(crate::Error::AuthError(
                        "InitialResponse must have your_nonce".into(),
                    ));
                }
                if self.signature.is_none() {
                    return Err(crate::Error::AuthError(
                        "InitialResponse must have signature".into(),
                    ));
                }
            }
            MessageType::CertificateRequest => {
                // CertificateRequest must have requested_certificates
                if self.requested_certificates.is_none() {
                    return Err(crate::Error::AuthError(
                        "CertificateRequest must have requested_certificates".into(),
                    ));
                }
            }
            MessageType::CertificateResponse => {
                // CertificateResponse must have certificates
                if self.certificates.is_none() {
                    return Err(crate::Error::AuthError(
                        "CertificateResponse must have certificates".into(),
                    ));
                }
            }
            MessageType::General => {
                // General messages should have nonce, your_nonce, and signature
                if self.signature.is_none() {
                    return Err(crate::Error::AuthError(
                        "General message must have signature".into(),
                    ));
                }
            }
        }

        Ok(())
    }
}

/// Peer session state.
///
/// Tracks the authentication state between two peers, including
/// nonces, identity keys, and certificate validation status.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerSession {
    /// Whether the session has completed mutual authentication.
    pub is_authenticated: bool,

    /// This session's unique nonce (session identifier).
    pub session_nonce: Option<String>,

    /// Peer's nonce from their last message.
    pub peer_nonce: Option<String>,

    /// Peer's identity public key.
    pub peer_identity_key: Option<PublicKey>,

    /// Last update timestamp (milliseconds since epoch).
    pub last_update: u64,

    /// Whether certificates are required for this session.
    pub certificates_required: bool,

    /// Whether certificates have been validated.
    pub certificates_validated: bool,
}

impl PeerSession {
    /// Creates a new empty session.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new session with the given session nonce.
    pub fn with_nonce(session_nonce: String) -> Self {
        Self {
            session_nonce: Some(session_nonce),
            last_update: current_time_ms(),
            ..Default::default()
        }
    }

    /// Updates the last update timestamp to now.
    pub fn touch(&mut self) {
        self.last_update = current_time_ms();
    }

    /// Returns true if this session is ready for general messages.
    pub fn is_ready(&self) -> bool {
        self.is_authenticated && (!self.certificates_required || self.certificates_validated)
    }
}

/// Certificate request specification.
///
/// Specifies which certificates are required from a peer, including
/// trusted certifiers and the certificate types with fields to reveal.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestedCertificateSet {
    /// List of trusted certifier public keys (hex encoded).
    #[serde(default)]
    pub certifiers: Vec<String>,

    /// Map of certificate type ID (base64) -> list of field names to reveal.
    #[serde(default)]
    pub types: HashMap<String, Vec<String>>,
}

impl RequestedCertificateSet {
    /// Creates a new empty certificate request set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns true if no certificates are requested.
    pub fn is_empty(&self) -> bool {
        self.certifiers.is_empty() && self.types.is_empty()
    }

    /// Adds a trusted certifier by public key hex.
    pub fn add_certifier(&mut self, certifier_hex: impl Into<String>) {
        self.certifiers.push(certifier_hex.into());
    }

    /// Adds a certificate type with fields to reveal.
    pub fn add_type(&mut self, type_id: impl Into<String>, fields: Vec<String>) {
        self.types.insert(type_id.into(), fields);
    }

    /// Checks if a certifier is trusted.
    pub fn is_certifier_trusted(&self, certifier_hex: &str) -> bool {
        self.certifiers.is_empty() || self.certifiers.contains(&certifier_hex.to_string())
    }

    /// Checks if a certificate type is requested.
    pub fn is_type_requested(&self, type_id: &str) -> bool {
        self.types.is_empty() || self.types.contains_key(type_id)
    }

    /// Gets the fields to reveal for a certificate type.
    pub fn get_fields_for_type(&self, type_id: &str) -> Option<&Vec<String>> {
        self.types.get(type_id)
    }
}

/// Returns current time in milliseconds since Unix epoch.
pub fn current_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::PrivateKey;

    #[test]
    fn test_message_type_conversion() {
        assert_eq!(MessageType::InitialRequest.as_str(), "initialRequest");
        assert_eq!(
            MessageType::from_str("initialRequest"),
            Some(MessageType::InitialRequest)
        );
        assert_eq!(MessageType::from_str("invalid"), None);
    }

    #[test]
    fn test_auth_message_creation() {
        let key = PrivateKey::random().public_key();
        let msg = AuthMessage::new(MessageType::InitialRequest, key.clone());

        assert_eq!(msg.version, AUTH_VERSION);
        assert_eq!(msg.message_type, MessageType::InitialRequest);
        assert_eq!(msg.identity_key, key);
        assert!(msg.nonce.is_none());
    }

    #[test]
    fn test_peer_session() {
        let mut session = PeerSession::with_nonce("test-nonce".to_string());
        assert_eq!(session.session_nonce.as_deref(), Some("test-nonce"));
        assert!(!session.is_authenticated);
        assert!(!session.is_ready());

        session.is_authenticated = true;
        assert!(session.is_ready());

        session.certificates_required = true;
        assert!(!session.is_ready());

        session.certificates_validated = true;
        assert!(session.is_ready());
    }

    #[test]
    fn test_requested_certificate_set() {
        let mut req = RequestedCertificateSet::new();
        assert!(req.is_empty());

        req.add_certifier("02abc123");
        req.add_type("type1", vec!["name".to_string(), "email".to_string()]);

        assert!(!req.is_empty());
        assert!(req.is_certifier_trusted("02abc123"));
        assert!(!req.is_certifier_trusted("02def456"));
        assert!(req.is_type_requested("type1"));
        assert!(!req.is_type_requested("type2"));
    }
}
