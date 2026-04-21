//! Overlay admin token template for SHIP/SLAP advertisements.
//!
//! This module provides functionality for creating and decoding overlay
//! advertisement tokens that are used to announce SHIP topics and SLAP
//! services on the overlay network.

use crate::overlay::types::Protocol;
use crate::primitives::hash::sha256;
use crate::primitives::{PrivateKey, PublicKey};
use crate::script::templates::PushDrop;
use crate::script::LockingScript;
use crate::wallet::{Counterparty, KeyDeriver, Protocol as WalletProtocol, SecurityLevel};
use crate::{Error, Result};

/// BRC-43 protocol names for SHIP/SLAP key derivation.
///
/// These are the exact strings used by `@bsv/overlay-discovery-services`'s
/// `WalletAdvertiser.ts` as the `protocol[1]` component of
/// `wallet.getPublicKey({protocolID: [2, NAME], ...})` and matching
/// `wallet.createSignature(...)` calls. They are NOT the on-chain field-0
/// string (which is `"SHIP"` / `"SLAP"`); they are the key-derivation
/// namespace. The two happen to differ, and both matter — the on-chain
/// field-0 is what topic-manager validators read, the BRC-43 name is what
/// drives the BRC-42 child-key derivation used for the locking key and
/// signature.
const SHIP_BRC43_PROTOCOL_NAME: &str = "service host interconnect";
const SLAP_BRC43_PROTOCOL_NAME: &str = "service lookup availability";
const OVERLAY_ADMIN_KEY_ID: &str = "1";

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
/// Accepts EITHER layout:
///
/// - **Current spec (5 fields, signed)** — what
///   [`create_signed_overlay_admin_token`] emits and what
///   `@bsv/overlay-discovery-services` tm_ship/tm_slap validators admit:
///
///   1. Protocol ("SHIP" or "SLAP")
///   2. Identity key (33-byte compressed public key)
///   3. Domain (UTF-8 string)
///   4. Topic or service name (UTF-8 string)
///   5. Signature (DER-encoded ECDSA, not parsed here)
///
/// - **Legacy 4-field unsigned** — what the deprecated
///   [`create_overlay_admin_token`] emits. Decoded for backward
///   compatibility with any older on-chain tokens; however, such
///   tokens will NOT be admitted by current validators and are
///   effectively decorative.
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
#[deprecated(
    since = "0.3.7",
    note = "Produces a 4-field unsigned PushDrop with identity-key locking, which \
            is rejected by current SHIP/SLAP validators (`@bsv/overlay-discovery-services` \
            requires 5 fields with a BRC-42-derived locking key and trailing \
            signature — see tm_ship.ts). Use `create_signed_overlay_admin_token` \
            instead; it requires a `PrivateKey` (not just a `PublicKey`) because \
            it has to SIGN the advert. Byte-equivalent to `@bsv/sdk 1.10.1`'s \
            `pushdrop.lock(fields, [2, protocol_name], '1', 'anyone', true, true, \
            'before')` path — verified via byte-exact fixtures in \
            `overlay_admin_token_template_parity.rs`."
)]
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

/// Create a TS-parity signed overlay admin token for SHIP/SLAP
/// advertisements.
///
/// This is the **current** spec function — produces bytes byte-exact to
/// `@bsv/sdk 1.10.1`'s `pushdrop.lock(fields, [2, protocol_name], '1',
/// 'anyone', forSelf=true, includeSignature=true, lockPosition='before')`,
/// which is what `@bsv/overlay-discovery-services/src/WalletAdvertiser.ts`
/// calls and what `nanostore.babbage.systems` / `overlay-us-1.bsvb.tech`
/// validators admit under `tm_ship` / `tm_slap`.
///
/// # PushDrop layout
///
/// Emits a 5-field PushDrop:
///
/// ```text
/// <locking_pubkey:33>   OP_CHECKSIG
/// <"SHIP"|"SLAP">       // field[0] — 4 UTF-8 bytes
/// <identity_key:33>     // field[1] — root pubkey compressed
/// <domain>              // field[2] — UTF-8
/// <topic_or_service>    // field[3] — UTF-8
/// <signature_der>       // field[4] — ECDSA DER over sha256(concat(fields[0..4]))
/// OP_2DROP OP_2DROP OP_DROP
/// ```
///
/// # Key derivation (BRC-42)
///
/// Both the **locking pubkey** and the **signing key** are BRC-42 children
/// of `root_key` for:
///
/// - `protocolID = (SecurityLevel::Counterparty, "service host interconnect")`
///   for SHIP, or `"service lookup availability"` for SLAP
/// - `keyID = "1"`
/// - `counterparty = Anyone`
/// - `forSelf = true` (locking pubkey side)
///
/// The signature is produced by the same child private key over
/// `sha256(concat(fields[0..4]))`. Deterministic-k (RFC 6979) means the
/// same inputs produce byte-identical bytes every run.
///
/// # Go SDK note
///
/// `github.com/bsv-blockchain/go-sdk/overlay/admin-token` uses
/// `counterparty=Self, forSelf=false` which produces a DIFFERENT signature
/// (though the same locking pubkey by BRC-42 symmetry). These Go-shaped
/// tokens are NOT what bsvb's TS validators admit. This function matches
/// TS; cross-SDK parity has been logged as a Go-side follow-up.
///
/// # Example
///
/// ```rust,ignore
/// use bsv_rs::overlay::{create_signed_overlay_admin_token, Protocol};
/// use bsv_rs::primitives::PrivateKey;
///
/// let root = PrivateKey::random();
/// let script = create_signed_overlay_admin_token(
///     &root,
///     Protocol::Ship,
///     "https://my-overlay.example.com",
///     "tm_mytopic",
/// );
/// ```
pub fn create_signed_overlay_admin_token(
    root_key: &PrivateKey,
    protocol: Protocol,
    domain: &str,
    topic_or_service: &str,
) -> LockingScript {
    let brc43_name = match protocol {
        Protocol::Ship => SHIP_BRC43_PROTOCOL_NAME,
        Protocol::Slap => SLAP_BRC43_PROTOCOL_NAME,
    };
    let wallet_protocol = WalletProtocol::new(SecurityLevel::Counterparty, brc43_name);
    let deriver = KeyDeriver::new(Some(root_key.clone()));

    // Locking pubkey: BRC-42 derive(counterparty=Anyone, forSelf=true). By
    // BRC-42 symmetry this is the same point the TS wallet returns from
    // `getPublicKey({counterparty: 'anyone', forSelf: true})`.
    let locking_pubkey = deriver
        .derive_public_key(
            &wallet_protocol,
            OVERLAY_ADMIN_KEY_ID,
            &Counterparty::Anyone,
            true,
        )
        .expect("BRC-42 derive_public_key is infallible for well-formed inputs");
    let signing_priv = deriver
        .derive_private_key(
            &wallet_protocol,
            OVERLAY_ADMIN_KEY_ID,
            &Counterparty::Anyone,
        )
        .expect("BRC-42 derive_private_key is infallible for well-formed inputs");

    let identity_pubkey = root_key.public_key();
    let data_fields: Vec<Vec<u8>> = vec![
        protocol.as_str().as_bytes().to_vec(),
        identity_pubkey.to_compressed().to_vec(),
        domain.as_bytes().to_vec(),
        topic_or_service.as_bytes().to_vec(),
    ];

    // Signature preimage: concat(fields[0..4]) — matches
    // `pushdrop.lock`'s `fields.reduce((a, e) => [...a, ...e], [])`.
    let sign_data: Vec<u8> = data_fields.iter().flat_map(|f| f.iter().copied()).collect();
    let sig_der = signing_priv
        .sign(&sha256(&sign_data))
        .expect("ECDSA sign is infallible with a valid private key + 32-byte digest")
        .to_der();

    let mut all_fields = data_fields;
    all_fields.push(sig_der);

    let pushdrop = PushDrop::new(locking_pubkey, all_fields);
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
    #[allow(deprecated)]
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

    /// The new TS-parity function round-trips through the decoder for
    /// both protocols. Byte-exact match against the TS @bsv/sdk 1.10.1
    /// output is verified in a separate test-file (parity goldens) that
    /// pulls fixtures from the downstream workspace — this test just
    /// locks in the round-trip semantics.
    #[test]
    fn test_create_signed_and_decode_ship_token() {
        let root = PrivateKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        let identity_key = root.public_key();

        let script = create_signed_overlay_admin_token(
            &root,
            Protocol::Ship,
            "https://example.com",
            "tm_test_topic",
        );

        let decoded = decode_overlay_admin_token(&script).unwrap();
        assert_eq!(decoded.protocol, Protocol::Ship);
        assert_eq!(
            decoded.identity_key.to_compressed(),
            identity_key.to_compressed()
        );
        assert_eq!(decoded.domain, "https://example.com");
        assert_eq!(decoded.topic_or_service, "tm_test_topic");
        assert!(is_ship_token(&script));
        assert!(!is_slap_token(&script));
    }

    #[test]
    fn test_create_signed_and_decode_slap_token() {
        let root = PrivateKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();

        let script = create_signed_overlay_admin_token(
            &root,
            Protocol::Slap,
            "https://overlay.example.com",
            "ls_myservice",
        );

        let decoded = decode_overlay_admin_token(&script).unwrap();
        assert_eq!(decoded.protocol, Protocol::Slap);
        assert_eq!(decoded.domain, "https://overlay.example.com");
        assert_eq!(decoded.topic_or_service, "ls_myservice");
        assert!(is_slap_token(&script));
    }

    /// Signing is deterministic (RFC 6979) — same inputs → same bytes.
    /// This is load-bearing for our cross-SDK byte-parity assertions.
    #[test]
    fn test_create_signed_overlay_admin_token_is_deterministic() {
        let root = PrivateKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        let a = create_signed_overlay_admin_token(
            &root,
            Protocol::Ship,
            "https://overlay.example.com",
            "tm_uhrp",
        );
        let b = create_signed_overlay_admin_token(
            &root,
            Protocol::Ship,
            "https://overlay.example.com",
            "tm_uhrp",
        );
        assert_eq!(a.to_hex(), b.to_hex());
    }

    /// The NEW signed variant produces DIFFERENT bytes than the
    /// DEPRECATED unsigned variant for the same inputs. Catches any
    /// accidental regression if someone re-routes create_signed to
    /// the old code path.
    #[test]
    #[allow(deprecated)]
    fn test_signed_and_unsigned_tokens_produce_different_bytes() {
        let root = PrivateKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        let signed = create_signed_overlay_admin_token(
            &root,
            Protocol::Ship,
            "https://overlay.example.com",
            "tm_uhrp",
        );
        let unsigned = create_overlay_admin_token(
            Protocol::Ship,
            &root.public_key(),
            "https://overlay.example.com",
            "tm_uhrp",
        );
        assert_ne!(
            signed.to_hex(),
            unsigned.to_hex(),
            "signed (5-field) and unsigned (4-field) variants must produce different bytes"
        );
    }

    #[test]
    #[allow(deprecated)]
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
    #[allow(deprecated)]
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
    #[allow(deprecated)]
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
    #[allow(deprecated)]
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
    #[allow(deprecated)]
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
