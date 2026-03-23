//! Overlay admin token template for SHIP/SLAP advertisements.
//!
//! This module provides functionality for creating and decoding overlay
//! advertisement tokens that are used to announce SHIP topics and SLAP
//! services on the overlay network.

use crate::overlay::types::Protocol;
use crate::primitives::PublicKey;
use crate::script::templates::PushDrop;
use crate::script::LockingScript;
use crate::{Error, Result};

/// Decoded admin token data.
///
/// Contains the parsed fields from an overlay advertisement token.
#[derive(Debug, Clone)]
pub struct OverlayAdminTokenData {
    /// Protocol (SHIP or SLAP).
    pub protocol: Protocol,
    /// Identity key of the service operator.
    pub identity_key: PublicKey,
    /// Domain where the service is hosted.
    pub domain: String,
    /// Topic (for SHIP) or service name (for SLAP).
    pub topic_or_service: String,
}

impl OverlayAdminTokenData {
    /// Get the identity key as a hex string.
    pub fn identity_key_hex(&self) -> String {
        crate::primitives::to_hex(&self.identity_key.to_compressed())
    }
}

/// Decodes a SHIP or SLAP advertisement from a locking script.
///
/// Advertisement tokens use PushDrop format with 4 fields:
/// 1. Protocol ("SHIP" or "SLAP")
/// 2. Identity key (33-byte compressed public key)
/// 3. Domain (UTF-8 string)
/// 4. Topic or service name (UTF-8 string)
///
/// # Arguments
///
/// * `script` - The locking script to decode
///
/// # Returns
///
/// The decoded token data, or an error if the script is not a valid
/// advertisement token.
///
/// # Example
///
/// ```rust,ignore
/// use bsv_rs::overlay::overlay_admin_token_template::decode_overlay_admin_token;
/// use bsv_rs::script::LockingScript;
///
/// let script = LockingScript::from_hex("...")?;
/// let token = decode_overlay_admin_token(&script)?;
/// println!("Protocol: {}", token.protocol);
/// println!("Domain: {}", token.domain);
/// ```
pub fn decode_overlay_admin_token(script: &LockingScript) -> Result<OverlayAdminTokenData> {
    // Try to decode as PushDrop
    let pushdrop = PushDrop::decode(script)
        .map_err(|_| Error::OverlayError("Script is not a valid PushDrop format".into()))?;

    let fields = &pushdrop.fields;

    // Must have at least 4 fields
    if fields.len() < 4 {
        return Err(Error::OverlayError(format!(
            "Invalid SHIP/SLAP advertisement: expected at least 4 fields, got {}",
            fields.len()
        )));
    }

    // Parse protocol (first field)
    let protocol_str = std::str::from_utf8(&fields[0])
        .map_err(|_| Error::OverlayError("Protocol field is not valid UTF-8".into()))?;

    let protocol = Protocol::parse(protocol_str)
        .ok_or_else(|| Error::OverlayError(format!("Invalid protocol type: {}", protocol_str)))?;

    // Parse identity key (second field, 33 bytes compressed pubkey)
    let identity_key = PublicKey::from_bytes(&fields[1])
        .map_err(|e| Error::OverlayError(format!("Invalid identity key: {}", e)))?;

    // Parse domain (third field)
    let domain = std::str::from_utf8(&fields[2])
        .map_err(|_| Error::OverlayError("Domain field is not valid UTF-8".into()))?
        .to_string();

    // Parse topic or service (fourth field)
    let topic_or_service = std::str::from_utf8(&fields[3])
        .map_err(|_| Error::OverlayError("Topic/service field is not valid UTF-8".into()))?
        .to_string();

    Ok(OverlayAdminTokenData {
        protocol,
        identity_key,
        domain,
        topic_or_service,
    })
}

/// Create an overlay admin token locking script.
///
/// This creates a PushDrop locking script that advertises a SHIP topic
/// or SLAP service.
///
/// # Arguments
///
/// * `protocol` - SHIP or SLAP
/// * `identity_key` - The public key of the service operator
/// * `domain` - The domain where the service is hosted
/// * `topic_or_service` - The topic name (for SHIP) or service name (for SLAP)
///
/// # Returns
///
/// A locking script containing the advertisement token.
///
/// # Example
///
/// ```rust,ignore
/// use bsv_rs::overlay::{create_overlay_admin_token, Protocol};
/// use bsv_rs::primitives::PrivateKey;
///
/// let private_key = PrivateKey::random();
/// let public_key = private_key.public_key();
///
/// let script = create_overlay_admin_token(
///     Protocol::Ship,
///     &public_key,
///     "https://example.com",
///     "tm_mytopic",
/// );
/// ```
pub fn create_overlay_admin_token(
    protocol: Protocol,
    identity_key: &PublicKey,
    domain: &str,
    topic_or_service: &str,
) -> LockingScript {
    // Build PushDrop fields
    let fields = vec![
        protocol.as_str().as_bytes().to_vec(),
        identity_key.to_compressed().to_vec(),
        domain.as_bytes().to_vec(),
        topic_or_service.as_bytes().to_vec(),
    ];

    // Create PushDrop locking script
    // The identity key is also used as the locking key
    let pushdrop = PushDrop::new(identity_key.clone(), fields);
    pushdrop.lock()
}

/// Check if a locking script is a valid overlay admin token.
///
/// Returns `true` if the script can be decoded as an overlay advertisement.
pub fn is_overlay_admin_token(script: &LockingScript) -> bool {
    decode_overlay_admin_token(script).is_ok()
}

/// Check if a locking script is a SHIP advertisement.
pub fn is_ship_token(script: &LockingScript) -> bool {
    decode_overlay_admin_token(script)
        .map(|t| t.protocol == Protocol::Ship)
        .unwrap_or(false)
}

/// Check if a locking script is a SLAP advertisement.
pub fn is_slap_token(script: &LockingScript) -> bool {
    decode_overlay_admin_token(script)
        .map(|t| t.protocol == Protocol::Slap)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::PrivateKey;

    #[test]
    fn test_create_and_decode_ship_token() {
        let private_key = PrivateKey::random();
        let public_key = private_key.public_key();

        let script = create_overlay_admin_token(
            Protocol::Ship,
            &public_key,
            "https://example.com",
            "tm_test_topic",
        );

        let decoded = decode_overlay_admin_token(&script).unwrap();

        assert_eq!(decoded.protocol, Protocol::Ship);
        assert_eq!(
            decoded.identity_key.to_compressed(),
            public_key.to_compressed()
        );
        assert_eq!(decoded.domain, "https://example.com");
        assert_eq!(decoded.topic_or_service, "tm_test_topic");
    }

    #[test]
    fn test_create_and_decode_slap_token() {
        let private_key = PrivateKey::random();
        let public_key = private_key.public_key();

        let script = create_overlay_admin_token(
            Protocol::Slap,
            &public_key,
            "https://service.example.com",
            "ls_myservice",
        );

        let decoded = decode_overlay_admin_token(&script).unwrap();

        assert_eq!(decoded.protocol, Protocol::Slap);
        assert_eq!(decoded.domain, "https://service.example.com");
        assert_eq!(decoded.topic_or_service, "ls_myservice");
    }

    #[test]
    fn test_is_ship_token() {
        let private_key = PrivateKey::random();
        let public_key = private_key.public_key();

        let ship_script = create_overlay_admin_token(
            Protocol::Ship,
            &public_key,
            "https://example.com",
            "tm_test",
        );

        let slap_script = create_overlay_admin_token(
            Protocol::Slap,
            &public_key,
            "https://example.com",
            "ls_test",
        );

        assert!(is_ship_token(&ship_script));
        assert!(!is_ship_token(&slap_script));
    }

    #[test]
    fn test_is_slap_token() {
        let private_key = PrivateKey::random();
        let public_key = private_key.public_key();

        let slap_script = create_overlay_admin_token(
            Protocol::Slap,
            &public_key,
            "https://example.com",
            "ls_test",
        );

        let ship_script = create_overlay_admin_token(
            Protocol::Ship,
            &public_key,
            "https://example.com",
            "tm_test",
        );

        assert!(is_slap_token(&slap_script));
        assert!(!is_slap_token(&ship_script));
    }

    #[test]
    fn test_is_overlay_admin_token() {
        let private_key = PrivateKey::random();
        let public_key = private_key.public_key();

        let admin_script = create_overlay_admin_token(
            Protocol::Ship,
            &public_key,
            "https://example.com",
            "tm_test",
        );

        // A regular P2PKH script is not an admin token
        let regular_script =
            LockingScript::from_asm("OP_DUP OP_HASH160 0x14 OP_EQUALVERIFY OP_CHECKSIG");

        assert!(is_overlay_admin_token(&admin_script));
        assert!(regular_script.is_err() || !is_overlay_admin_token(&regular_script.unwrap()));
    }

    #[test]
    fn test_identity_key_hex() {
        let private_key = PrivateKey::random();
        let public_key = private_key.public_key();

        let script = create_overlay_admin_token(
            Protocol::Ship,
            &public_key,
            "https://example.com",
            "tm_test",
        );

        let decoded = decode_overlay_admin_token(&script).unwrap();
        let hex = decoded.identity_key_hex();

        // Should be 66 hex characters (33 bytes * 2)
        assert_eq!(hex.len(), 66);
    }

    #[test]
    fn test_decode_invalid_script() {
        // Empty script
        let script = LockingScript::new();
        assert!(decode_overlay_admin_token(&script).is_err());
    }

    #[test]
    fn test_decode_insufficient_fields() {
        // Create a PushDrop with only 2 fields (need 4)
        let private_key = PrivateKey::random();
        let public_key = private_key.public_key();

        let fields = vec![b"SHIP".to_vec(), b"domain".to_vec()];
        let pushdrop = PushDrop::new(public_key, fields);
        let script = pushdrop.lock();

        let result = decode_overlay_admin_token(&script);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_invalid_protocol() {
        let private_key = PrivateKey::random();
        let public_key = private_key.public_key();

        // Create with invalid protocol
        let fields = vec![
            b"INVALID".to_vec(),
            public_key.to_compressed().to_vec(),
            b"domain".to_vec(),
            b"topic".to_vec(),
        ];
        let pushdrop = PushDrop::new(public_key, fields);
        let script = pushdrop.lock();

        let result = decode_overlay_admin_token(&script);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid protocol"));
    }
}
