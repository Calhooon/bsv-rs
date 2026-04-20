//! Cryptographic nonce creation and verification.
//!
//! Nonces are used in the authentication protocol to prevent replay attacks
//! and establish session identity.
//!
//! ## Nonce Format
//!
//! A nonce is 48 bytes encoded as base64 (64 chars):
//! - First 16 bytes: Random data
//! - Last 32 bytes: Full HMAC-SHA256 of the random data
//!
//! Matches the TypeScript SDK's `createNonce` and go-sdk's `CreateNonce` so
//! nonces are wire-compatible across all three SDKs.
//!
//! ### Legacy format (pre-v0.3.6)
//!
//! Older bsv-rs releases emitted a 32-byte nonce (16 random + 16 truncated
//! HMAC). `verify_nonce` still accepts these so in-flight sessions and
//! derivation prefixes created by older peers keep working through a single
//! release cycle. The dual-accept path will be removed in v0.3.7.

use crate::primitives::{from_base64, to_base64};
use crate::wallet::{Counterparty, CreateHmacArgs, Protocol, SecurityLevel, WalletInterface};
use crate::{Error, Result};
use rand::RngCore;

/// Protocol for nonce HMAC computation.
pub const NONCE_PROTOCOL: &str = "server hmac";

/// Size of the random portion of the nonce.
const NONCE_RANDOM_SIZE: usize = 16;

/// Size of the HMAC portion in the canonical (post-v0.3.6) format.
const NONCE_HMAC_SIZE: usize = 32;

/// Total size of a canonical nonce (random + full HMAC).
const NONCE_TOTAL_SIZE: usize = NONCE_RANDOM_SIZE + NONCE_HMAC_SIZE;

/// Legacy nonce size from bsv-rs ≤ 0.3.5 (16 random + 16 truncated HMAC).
/// `verify_nonce` accepts both formats for one release cycle.
const NONCE_LEGACY_SIZE: usize = NONCE_RANDOM_SIZE + NONCE_RANDOM_SIZE;

/// Creates a cryptographic nonce.
///
/// The nonce format is: base64(random_16_bytes || hmac_16_bytes) = 32 bytes total.
///
/// The HMAC is computed using BRC-42 key derivation with the `"server hmac"` protocol,
/// making the nonce verifiable by the wallet.
///
/// # Arguments
/// * `wallet` - Wallet for HMAC computation
/// * `counterparty` - Optional counterparty for HMAC (None = self)
/// * `originator` - Application originator
///
/// # Returns
/// Base64-encoded nonce string
pub async fn create_nonce<W: WalletInterface>(
    wallet: &W,
    counterparty: Option<&crate::primitives::PublicKey>,
    originator: &str,
) -> Result<String> {
    // Generate 16 random bytes
    let mut random_bytes = [0u8; NONCE_RANDOM_SIZE];
    rand::thread_rng().fill_bytes(&mut random_bytes);

    // Compute HMAC of the random bytes
    let protocol = Protocol::new(SecurityLevel::App, NONCE_PROTOCOL);

    // Use the UTF-8 bytes of the random data as key_id
    let key_id = to_base64(&random_bytes);

    let hmac_result = wallet
        .create_hmac(
            CreateHmacArgs {
                data: random_bytes.to_vec(),
                protocol_id: protocol,
                key_id,
                counterparty: counterparty.map(|pk| Counterparty::Other(pk.clone())),
            },
            originator,
        )
        .await?;

    // Combine random bytes and the full 32-byte HMAC. Matches TS/Go SDK.
    let mut nonce = Vec::with_capacity(NONCE_TOTAL_SIZE);
    nonce.extend_from_slice(&random_bytes);
    nonce.extend_from_slice(&hmac_result.hmac);

    Ok(to_base64(&nonce))
}

/// Verifies a nonce.
///
/// Checks that the HMAC portion of the nonce matches the expected value
/// computed from the random portion.
///
/// # Arguments
/// * `nonce` - Base64-encoded nonce to verify
/// * `wallet` - Wallet for HMAC verification
/// * `counterparty` - Optional counterparty for HMAC (None = self)
/// * `originator` - Application originator
///
/// # Returns
/// `true` if the nonce is valid, `false` otherwise
pub async fn verify_nonce<W: WalletInterface>(
    nonce: &str,
    wallet: &W,
    counterparty: Option<&crate::primitives::PublicKey>,
    originator: &str,
) -> Result<bool> {
    // Decode nonce
    let nonce_bytes = from_base64(nonce)?;

    // Accept canonical (48-byte) and legacy (32-byte) formats. Legacy support
    // keeps in-flight sessions and derivation prefixes working across the
    // v0.3.6 upgrade window and will be removed in v0.3.7.
    let (random_bytes, hmac_bytes) = match nonce_bytes.len() {
        NONCE_TOTAL_SIZE => (
            &nonce_bytes[..NONCE_RANDOM_SIZE],
            &nonce_bytes[NONCE_RANDOM_SIZE..NONCE_TOTAL_SIZE],
        ),
        NONCE_LEGACY_SIZE => (
            &nonce_bytes[..NONCE_RANDOM_SIZE],
            &nonce_bytes[NONCE_RANDOM_SIZE..NONCE_LEGACY_SIZE],
        ),
        n => {
            return Err(Error::InvalidNonce(format!(
                "Nonce size invalid: expected {} or {} bytes, got {}",
                NONCE_TOTAL_SIZE, NONCE_LEGACY_SIZE, n
            )))
        }
    };

    let protocol = Protocol::new(SecurityLevel::App, NONCE_PROTOCOL);
    let key_id = to_base64(random_bytes);

    // Recompute the HMAC. Compare as many bytes as the stored portion has —
    // canonical nonces carry all 32 HMAC bytes; legacy nonces only kept the
    // first 16.
    let hmac_result = wallet
        .create_hmac(
            CreateHmacArgs {
                data: random_bytes.to_vec(),
                protocol_id: protocol,
                key_id,
                counterparty: counterparty.map(|pk| Counterparty::Other(pk.clone())),
            },
            originator,
        )
        .await?;

    let stored_len = hmac_bytes.len();
    Ok(hmac_result.hmac[..stored_len] == *hmac_bytes)
}

/// Validates that a nonce has the correct format.
///
/// This is a quick check without cryptographic verification.
pub fn validate_nonce_format(nonce: &str) -> Result<()> {
    let bytes = from_base64(nonce)?;

    // Accept canonical 48-byte or legacy 32-byte formats; anything shorter is
    // definitely malformed. Size bigger than canonical is allowed (forward-
    // compatible with any future extension).
    if bytes.len() < NONCE_LEGACY_SIZE {
        return Err(Error::InvalidNonce(format!(
            "Nonce too short: expected at least {} bytes, got {}",
            NONCE_LEGACY_SIZE,
            bytes.len()
        )));
    }

    Ok(())
}

/// Extracts the random portion of a nonce.
///
/// Useful for using the nonce as an identifier.
pub fn get_nonce_random(nonce: &str) -> Result<Vec<u8>> {
    let bytes = from_base64(nonce)?;

    if bytes.len() < NONCE_RANDOM_SIZE {
        return Err(Error::InvalidNonce(format!(
            "Nonce too short: expected at least {} bytes, got {}",
            NONCE_RANDOM_SIZE,
            bytes.len()
        )));
    }

    Ok(bytes[..NONCE_RANDOM_SIZE].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_nonce_format_canonical() {
        let canonical = to_base64(&[0u8; 48]);
        assert!(validate_nonce_format(&canonical).is_ok());
    }

    #[test]
    fn test_validate_nonce_format_legacy_still_ok() {
        // Legacy 32-byte format stays valid through v0.3.6 for migration.
        let legacy = to_base64(&[0u8; 32]);
        assert!(validate_nonce_format(&legacy).is_ok());
    }

    #[test]
    fn test_validate_nonce_format_too_short() {
        let short = to_base64(&[0u8; 16]);
        assert!(validate_nonce_format(&short).is_err());
        assert!(validate_nonce_format("not-valid-base64!!!").is_err());
    }

    #[test]
    fn test_get_nonce_random() {
        let mut full_nonce = [0u8; 48];
        full_nonce[..16].copy_from_slice(&[1u8; 16]);
        full_nonce[16..].copy_from_slice(&[2u8; 32]);
        let nonce_str = to_base64(&full_nonce);
        let random = get_nonce_random(&nonce_str).unwrap();
        assert_eq!(random.len(), 16);
        assert_eq!(random, vec![1u8; 16]);
    }

    // Cross-SDK roundtrip: canonical 48-byte nonce created by bsv-rs verifies
    // back through bsv-rs. Matches TS `createNonce` / go-sdk `CreateNonce`
    // wire format (16 random || 32 HMAC).
    use crate::primitives::PrivateKey;
    use crate::wallet::ProtoWallet;

    #[tokio::test]
    async fn test_create_verify_roundtrip_canonical_48_bytes() {
        let wallet = ProtoWallet::new(Some(
            PrivateKey::from_hex(
                "0000000000000000000000000000000000000000000000000000000000000001",
            )
            .unwrap(),
        ));
        let nonce = create_nonce(&wallet, None, "test.app").await.unwrap();
        let decoded = from_base64(&nonce).unwrap();
        assert_eq!(
            decoded.len(),
            NONCE_TOTAL_SIZE,
            "canonical nonce must be 48 bytes"
        );
        assert!(verify_nonce(&nonce, &wallet, None, "test.app")
            .await
            .unwrap());
    }

    // Upgrade-window coverage: nonces produced by bsv-rs ≤ 0.3.5 (16 random ||
    // first 16 bytes of HMAC, 32 bytes total) must still verify against the
    // v0.3.6 verify_nonce path, so a mid-flight session doesn't break when a
    // peer upgrades. Dual-accept is planned to be removed in v0.3.7.
    #[tokio::test]
    async fn test_verify_legacy_32_byte_nonce_still_passes() {
        let wallet = ProtoWallet::new(Some(
            PrivateKey::from_hex(
                "0000000000000000000000000000000000000000000000000000000000000002",
            )
            .unwrap(),
        ));
        let mut random = [0u8; NONCE_RANDOM_SIZE];
        rand::thread_rng().fill_bytes(&mut random);
        let hmac = wallet
            .create_hmac(CreateHmacArgs {
                data: random.to_vec(),
                protocol_id: Protocol::new(SecurityLevel::App, NONCE_PROTOCOL),
                key_id: to_base64(&random),
                counterparty: None,
            })
            .unwrap();
        let mut legacy = Vec::with_capacity(NONCE_LEGACY_SIZE);
        legacy.extend_from_slice(&random);
        legacy.extend_from_slice(&hmac.hmac[..NONCE_RANDOM_SIZE]);
        let nonce = to_base64(&legacy);
        assert_eq!(from_base64(&nonce).unwrap().len(), NONCE_LEGACY_SIZE);
        assert!(verify_nonce(&nonce, &wallet, None, "test.app")
            .await
            .unwrap());
    }
}
