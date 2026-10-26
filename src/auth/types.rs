//! Core types for BRC-31 authentication protocol.
//!
//! This module defines the fundamental types used in peer-to-peer authentication:
//! - `MessageType` - Authentication message types
//! - `AuthMessage` - Full authentication message structure
//! - `PeerSession` - Session state between peers
//! - `RequestedCertificateSet` - Certificate request specification

use crate::primitives::PublicKey;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::value::RawValue;
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
///
/// A certificateRequest's signature covers the UTF-8 bytes of its
/// `requestedCertificates` JSON text and a certificateResponse's those of
/// its `certificates` text, the text as transmitted (#280): the reference
/// signs `JSON.stringify` of what it sends and verifies `JSON.stringify` of
/// what it parsed (`ts-stack@edf6e03` `Peer.ts:453`, `:1068`, `:1140`,
/// `:1203`), which is the received text when that text is compact JSON.
/// [`certificates_text`](Self::certificates_text) and
/// [`requested_certificates_text`](Self::requested_certificates_text) carry
/// those texts: a parsed message keeps them as received, a message built
/// with [`set_certificates`](Self::set_certificates) or
/// [`set_requested_certificates`](Self::set_requested_certificates) the
/// compact text it will send. The serializer writes a text as it stands
/// and [`signing_data`](Self::signing_data) signs it, while it still reads
/// back to the member's value; a member changed since is serialized afresh.
/// Its serde is JSON's: the texts are `serde_json` raw values.
#[derive(Debug, Clone)]
pub struct AuthMessage {
    /// Protocol version (e.g., "0.1").
    pub version: String,

    /// Type of message.
    pub message_type: MessageType,

    /// Sender's identity key (33-byte compressed public key).
    pub identity_key: PublicKey,

    /// Sender's nonce for this message (base64, 32 bytes: 16 random + 16 HMAC).
    pub nonce: Option<String>,

    /// Session nonce from initial handshake (for InitialResponse).
    pub initial_nonce: Option<String>,

    /// Recipient's nonce from previous message.
    pub your_nonce: Option<String>,

    /// Attached certificates (for CertificateResponse).
    pub certificates: Option<Vec<crate::auth::certificates::VerifiableCertificate>>,

    /// Requested certificate specifications (for InitialRequest, CertificateRequest).
    pub requested_certificates: Option<RequestedCertificateSet>,

    /// Message payload (for General messages).
    pub payload: Option<Vec<u8>>,

    /// DER-encoded signature over message contents.
    pub signature: Option<Vec<u8>>,

    /// The `certificates` member's JSON text: as received, or as this
    /// crate sends it. The certificateResponse signature covers its bytes.
    pub certificates_text: Option<Box<RawValue>>,

    /// The `requestedCertificates` member's JSON text: as received, or as
    /// this crate sends it. The certificateRequest signature covers its
    /// bytes.
    pub requested_certificates_text: Option<Box<RawValue>>,
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
            certificates_text: None,
            requested_certificates_text: None,
        }
    }

    /// Sets the certificates and the compact JSON text this message sends
    /// and signs for them.
    pub fn set_certificates(
        &mut self,
        certificates: Vec<crate::auth::certificates::VerifiableCertificate>,
    ) {
        self.certificates_text = serde_json::value::to_raw_value(&certificates).ok();
        self.certificates = Some(certificates);
    }

    /// Sets the requested certificate set and the compact JSON text this
    /// message sends and signs for it.
    pub fn set_requested_certificates(&mut self, requested: RequestedCertificateSet) {
        self.requested_certificates_text = serde_json::value::to_raw_value(&requested).ok();
        self.requested_certificates = Some(requested);
    }

    /// The `certificates` text this message sends and signs: the carried
    /// text while it reads back to `certificates`, `None` otherwise.
    fn current_certificates_text(&self) -> Option<&RawValue> {
        current_text(
            self.certificates_text.as_deref(),
            self.certificates.as_ref(),
        )
    }

    /// The `requestedCertificates` text this message sends and signs: the
    /// carried text while it reads back to `requested_certificates`, `None`
    /// otherwise.
    fn current_requested_certificates_text(&self) -> Option<&RawValue> {
        current_text(
            self.requested_certificates_text.as_deref(),
            self.requested_certificates.as_ref(),
        )
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
                // InitialResponse must have at least one of nonce/initial_nonce (the
                // responder's session nonce), plus your_nonce and signature.
                // The Go SDK sends both nonce and initial_nonce; the TS SDK only sends
                // initialNonce (no nonce field). Accept either for cross-SDK compat.
                if self.nonce.is_none() && self.initial_nonce.is_none() {
                    return Err(crate::Error::AuthError(
                        "InitialResponse must have nonce or initial_nonce".into(),
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

/// The carried text when it still reads back to `value`: parsed as `T`, it
/// serializes to the same JSON value as `value` does.
fn current_text<'a, T>(text: Option<&'a RawValue>, value: Option<&T>) -> Option<&'a RawValue>
where
    T: Serialize + serde::de::DeserializeOwned,
{
    let (text, value) = (text?, value?);
    let carried: T = serde_json::from_str(text.get()).ok()?;
    let carried = serde_json::to_value(&carried).ok()?;
    (serde_json::to_value(value).ok()? == carried).then_some(text)
}

/// A signed member on the wire: its carried text as it stands, or its value.
#[derive(Serialize)]
#[serde(untagged)]
enum WireMember<'a, T: Serialize> {
    Text(&'a RawValue),
    Value(&'a T),
}

impl<'a, T: Serialize> WireMember<'a, T> {
    fn new(text: Option<&'a RawValue>, value: Option<&'a T>) -> Option<Self> {
        match (text, value) {
            (Some(text), Some(_)) => Some(Self::Text(text)),
            (None, Some(value)) => Some(Self::Value(value)),
            _ => None,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthMessageOut<'a> {
    version: &'a str,
    message_type: MessageType,
    identity_key: &'a PublicKey,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<&'a String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    initial_nonce: Option<&'a String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    your_nonce: Option<&'a String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    certificates: Option<WireMember<'a, Vec<crate::auth::certificates::VerifiableCertificate>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    requested_certificates: Option<WireMember<'a, RequestedCertificateSet>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<&'a Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<&'a Vec<u8>>,
}

impl Serialize for AuthMessage {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        AuthMessageOut {
            version: &self.version,
            message_type: self.message_type,
            identity_key: &self.identity_key,
            nonce: self.nonce.as_ref(),
            initial_nonce: self.initial_nonce.as_ref(),
            your_nonce: self.your_nonce.as_ref(),
            certificates: WireMember::new(
                self.current_certificates_text(),
                self.certificates.as_ref(),
            ),
            requested_certificates: WireMember::new(
                self.current_requested_certificates_text(),
                self.requested_certificates.as_ref(),
            ),
            payload: self.payload.as_ref(),
            signature: self.signature.as_ref(),
        }
        .serialize(serializer)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthMessageIn {
    version: String,
    message_type: MessageType,
    identity_key: PublicKey,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    initial_nonce: Option<String>,
    #[serde(default)]
    your_nonce: Option<String>,
    #[serde(default)]
    certificates: Option<Box<RawValue>>,
    #[serde(default)]
    requested_certificates: Option<Box<RawValue>>,
    #[serde(default)]
    payload: Option<Vec<u8>>,
    #[serde(default)]
    signature: Option<Vec<u8>>,
}

impl<'de> Deserialize<'de> for AuthMessage {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let wire = AuthMessageIn::deserialize(deserializer)?;
        let certificates = match &wire.certificates {
            Some(text) => Some(
                serde_json::from_str(text.get())
                    .map_err(|e| serde::de::Error::custom(format_args!("certificates: {e}")))?,
            ),
            None => None,
        };
        let requested_certificates = match &wire.requested_certificates {
            Some(text) => Some(serde_json::from_str(text.get()).map_err(|e| {
                serde::de::Error::custom(format_args!("requestedCertificates: {e}"))
            })?),
            None => None,
        };
        Ok(Self {
            version: wire.version,
            message_type: wire.message_type,
            identity_key: wire.identity_key,
            nonce: wire.nonce,
            initial_nonce: wire.initial_nonce,
            your_nonce: wire.your_nonce,
            certificates,
            requested_certificates,
            payload: wire.payload,
            signature: wire.signature,
            certificates_text: wire.certificates,
            requested_certificates_text: wire.requested_certificates,
        })
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
///
/// On `wasm32-unknown-unknown` (e.g. Cloudflare Workers) this uses
/// `js_sys::Date::now()` because `std::time::SystemTime::now()` is
/// unimplemented and panics there. On all other targets the behavior is
/// unchanged. See `crate::util::time` for the cfg-gated implementation.
pub fn current_time_ms() -> u64 {
    crate::util::time::current_time_ms()
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
