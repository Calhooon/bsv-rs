//! Cryptographic nonce creation and verification.
//!
//! Nonces are used in the authentication protocol to prevent replay attacks
//! and establish session identity.
//!
//! ## Nonce Format
//!
//! A nonce is 32 bytes encoded as base64:
//! - First 16 bytes: Random data
//! - Last 16 bytes: HMAC of the random data
//!
//! The HMAC is computed using BRC-42 key derivation, making the nonce
//! verifiable by the counterparty.

use crate::primitives::{from_base64, to_base64};
use crate::wallet::{
    Counterparty, CreateHmacArgs, Protocol, SecurityLevel, VerifyHmacArgs, WalletInterface,
};
use crate::{Error, Result};
use rand::RngCore;

/// Protocol for nonce HMAC computation.
pub const NONCE_PROTOCOL: &str = "server hmac";

/// Size of the random portion of the nonce.
const NONCE_RANDOM_SIZE: usize = 16;

/// Total size of the nonce (random + HMAC).
const NONCE_TOTAL_SIZE: usize = 32;

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

    // Combine random bytes and HMAC (take first 16 bytes of HMAC)
    let mut nonce = Vec::with_capacity(NONCE_TOTAL_SIZE);
    nonce.extend_from_slice(&random_bytes);

    // HMAC result is 32 bytes, we take first 16
    nonce.extend_from_slice(&hmac_result.hmac[..NONCE_RANDOM_SIZE]);

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

    if nonce_bytes.len() < NONCE_TOTAL_SIZE {
        return Err(Error::InvalidNonce(format!(
            "Nonce too short: expected {} bytes, got {}",
            NONCE_TOTAL_SIZE,
            nonce_bytes.len()
        )));
    }

    // Split into random and HMAC portions
    let random_bytes = &nonce_bytes[..NONCE_RANDOM_SIZE];
    let hmac_bytes = &nonce_bytes[NONCE_RANDOM_SIZE..NONCE_TOTAL_SIZE];

    let protocol = Protocol::new(SecurityLevel::App, NONCE_PROTOCOL);
    let key_id = to_base64(random_bytes);

    // Convert hmac_bytes to fixed-size array
    let mut hmac_array = [0u8; 32];
    hmac_array[..NONCE_RANDOM_SIZE].copy_from_slice(hmac_bytes);

    // Verify HMAC
    let verify_result = wallet
        .verify_hmac(
            VerifyHmacArgs {
                data: random_bytes.to_vec(),
                hmac: hmac_array,
                protocol_id: protocol,
                key_id,
                counterparty: counterparty.map(|pk| Counterparty::Other(pk.clone())),
            },
            originator,
        )
        .await?;

    Ok(verify_result.valid)
}

/// Validates that a nonce has the correct format.
///
/// This is a quick check without cryptographic verification.
pub fn validate_nonce_format(nonce: &str) -> Result<()> {
    let bytes = from_base64(nonce)?;

    if bytes.len() < NONCE_TOTAL_SIZE {
        return Err(Error::InvalidNonce(format!(
            "Nonce too short: expected at least {} bytes, got {}",
            NONCE_TOTAL_SIZE,
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
    fn test_validate_nonce_format() {
        // Valid nonce (32 bytes base64 encoded)
        let valid_nonce = to_base64(&[0u8; 32]);
        assert!(validate_nonce_format(&valid_nonce).is_ok());

        // Too short
        let short_nonce = to_base64(&[0u8; 16]);
        assert!(validate_nonce_format(&short_nonce).is_err());

        // Invalid base64
        assert!(validate_nonce_format("not-valid-base64!!!").is_err());
    }

    #[test]
    fn test_get_nonce_random() {
        let mut full_nonce = [0u8; 32];
        full_nonce[..16].copy_from_slice(&[1u8; 16]); // Random portion
        full_nonce[16..].copy_from_slice(&[2u8; 16]); // HMAC portion

        let nonce_str = to_base64(&full_nonce);
        let random = get_nonce_random(&nonce_str).unwrap();

        assert_eq!(random.len(), 16);
        assert_eq!(random, vec![1u8; 16]);
    }
}
