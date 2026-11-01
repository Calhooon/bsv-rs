//! The reference's authentication identity key validator, public since #579.

use crate::primitives::PublicKey;
use crate::{Error, Result};

/// The reference's `assertAuthIdentityKey` (`ts-stack@edf6e03`
/// `packages/sdk/src/auth/AuthMessageValidation.ts:81-90`), public since #579:
/// the rule the reference applies to a received message's `identityKey`
/// (`:344`, the HTTP transport's `x-bsv-auth-identity-key` header folded into
/// that message, `SimplifiedFetchTransport.ts:346`) and to a requested set's
/// certifiers (`:124`).
///
/// Not the wallet's rule ([`validate_public_key`](crate::wallet::validate_public_key),
/// `validationHelpers.ts:185-191`) at another site: the text is taken as
/// given, never trimmed, and must be `02` or `03` and 64 lowercase hex
/// digits, where the wallet's trims and reads either case; then the key read
/// as `PublicKey.fromString` reads it must write the same text back, which
/// refuses an x off the curve or at or above the field prime. Returns the
/// parsed key, equal to [`PublicKey::from_hex`] of the same text.
///
/// # Errors
///
/// [`Error::AuthError`] in the reference's two sentences:
/// `Authentication identityKey must be a canonical compressed public key.`
/// for the text's form, and
/// `Authentication identityKey must be a valid compressed public key.` for
/// the point.
///
/// ```
/// use bsv_rs::auth::assert_auth_identity_key;
///
/// let g = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
/// assert_eq!(assert_auth_identity_key(g).unwrap().to_hex(), g);
/// assert!(assert_auth_identity_key(&g.to_uppercase()).is_err());
/// ```
pub fn assert_auth_identity_key(value: &str) -> Result<PublicKey> {
    let bytes = value.as_bytes();
    let form = bytes.len() == 66
        && (value.starts_with("02") || value.starts_with("03"))
        && bytes[2..]
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b));
    if !form {
        return Err(Error::AuthError(
            "Authentication identityKey must be a canonical compressed public key.".into(),
        ));
    }
    match PublicKey::from_hex(value) {
        Ok(key) if key.to_hex() == value => Ok(key),
        _ => Err(Error::AuthError(
            "Authentication identityKey must be a valid compressed public key.".into(),
        )),
    }
}
