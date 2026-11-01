//! A certificate's subject or certifier text read as the reference's
//! `Certificate.toBinary` reads it (`ts-stack@edf6e03`
//! `packages/sdk/src/auth/certificates/Certificate.ts:240-254`; bsv-rs#585).

use crate::primitives::PublicKey;
use crate::{Error, Result};

/// `toBinary`'s reading of the `subject` or `certifier` text
/// (`Certificate.ts:240-254`), which `Certificate.verify` runs first
/// (`:425-427`): the text taken as given, never trimmed, must match
/// `/^(02|03)[0-9a-fA-F]{64}$/` (either case), else `Invalid certificate
/// <field>: expected compressed public key hex`; then the 33 bytes are read
/// as a key (`assertCompressedPublicKey`, `:136-143`), else `Invalid
/// certificate <field>: expected a compressed secp256k1 public key`.
///
/// Not one of the #579 helpers' rules: `wallet::validate_public_key` trims
/// and `auth::assert_auth_identity_key` refuses upper-case hex, which
/// `toBinary` reads; `wallet::validate_result_public_key` reads the same
/// texts in other words. An x at or above the field prime, which
/// `PublicKey.fromDER` reduces there (`Point.ts:365-367`) while `toBinary`
/// writes the bytes as given, stays #183's refusal here (`from_bytes`).
///
/// `field` is `subject` or `certifier`, as the reference names it.
pub(crate) fn read_to_binary_key(text: &str, field: &str) -> Result<PublicKey> {
    let bytes = text.as_bytes();
    let form = bytes.len() == 66
        && matches!(&bytes[..2], b"02" | b"03")
        && bytes[2..].iter().all(u8::is_ascii_hexdigit);
    if !form {
        return Err(Error::CertificateValidationError(format!(
            "Invalid certificate {field}: expected compressed public key hex"
        )));
    }
    hex::decode(text)
        .ok()
        .and_then(|key| PublicKey::from_bytes(&key).ok())
        .ok_or_else(|| {
            Error::CertificateValidationError(format!(
                "Invalid certificate {field}: expected a compressed secp256k1 public key"
            ))
        })
}
