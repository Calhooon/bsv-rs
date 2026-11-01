//! A certificate's subject or certifier text read as the reference's
//! `Certificate.toBinary` reads it (`ts-stack@edf6e03`
//! `packages/sdk/src/auth/certificates/Certificate.ts:240-254`; bsv-rs#585,
//! the public helper bsv-rs#610).

use crate::primitives::ec::public_key_forms::from_reference_der;
#[cfg(feature = "identity")]
use crate::primitives::PublicKey;
use crate::{Error, Result};

/// The 33 key bytes `Certificate.toBinary` writes for a certificate's
/// `subject` or `certifier` text (`ts-stack@edf6e03`
/// `packages/sdk/src/auth/certificates/Certificate.ts:240-254`), or the error
/// it throws, in its words.
///
/// The text is taken as given, never trimmed, and must match
/// `/^(02|03)[0-9a-fA-F]{64}$/` (either case), else
/// `Invalid certificate <field>: expected compressed public key hex`; the
/// decoded bytes must then be a key to `PublicKey.fromDER`
/// (`assertCompressedPublicKey`, `:136-143`), else
/// `Invalid certificate <field>: expected a compressed secp256k1 public key`.
/// Both refusals are [`Error::CertificateValidationError`]. The bytes
/// returned are the text's hex decoded, as `toBinary` writes them: an x at or
/// above the field prime that `fromDER` reduces to a point (`Point.ts:365-367`)
/// is written unreduced there and returned unreduced here, so a caller that
/// needs a [`crate::PublicKey`] reads these bytes with
/// [`crate::PublicKey::from_bytes`], which refuses that x (#183).
///
/// `field` is `subject` or `certifier`, as the reference names it in its
/// words; any other name is written into the words as given.
///
/// ```
/// use bsv_rs::auth::certificates::certificate_key_bytes;
///
/// let text = "0362D14DAB4150BF497402FDC45A215E10DCB01C354959B10CFE31C7E9D87FF33D";
/// let bytes = certificate_key_bytes(text, "subject").unwrap();
/// assert_eq!(hex::encode(bytes), text.to_lowercase());
///
/// let refused = certificate_key_bytes(&format!(" {text}"), "certifier").unwrap_err();
/// assert_eq!(
///     refused.to_string(),
///     "certificate validation failed: Invalid certificate certifier: expected compressed public key hex"
/// );
/// ```
pub fn certificate_key_bytes(text: &str, field: &str) -> Result<[u8; 33]> {
    let bytes = text.as_bytes();
    let form = bytes.len() == 66
        && matches!(&bytes[..2], b"02" | b"03")
        && bytes[2..].iter().all(u8::is_ascii_hexdigit);
    if !form {
        return Err(Error::CertificateValidationError(format!(
            "Invalid certificate {field}: expected compressed public key hex"
        )));
    }
    let mut key = [0u8; 33];
    hex::decode_to_slice(text, &mut key)
        .ok()
        .filter(|()| from_reference_der(&key).is_ok())
        .map(|()| key)
        .ok_or_else(|| not_a_point(field))
}

fn not_a_point(field: &str) -> Error {
    Error::CertificateValidationError(format!(
        "Invalid certificate {field}: expected a compressed secp256k1 public key"
    ))
}

/// `toBinary`'s reading of the `subject` or `certifier` text as a key
/// ([`certificate_key_bytes`]), which `Certificate.verify` runs first
/// (`:425-427`): the bytes read by `PublicKey::from_bytes`, so an x at or
/// above the field prime, which `toBinary` writes unreduced, stays #183's
/// refusal here, in `assertCompressedPublicKey`'s words.
///
/// Not one of the #579 helpers' rules: `wallet::validate_public_key` trims
/// and `auth::assert_auth_identity_key` refuses upper-case hex, which
/// `toBinary` reads; `wallet::validate_result_public_key` reads the same
/// texts in other words.
#[cfg(feature = "identity")]
pub(crate) fn read_to_binary_key(text: &str, field: &str) -> Result<PublicKey> {
    let key = certificate_key_bytes(text, field)?;
    PublicKey::from_bytes(&key).map_err(|_| not_a_point(field))
}
