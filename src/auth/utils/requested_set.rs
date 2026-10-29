//! The reference's requested certificate set validator, which `Peer` calls
//! on its own policy and on a received message (#294).

use crate::auth::types::{AuthMessage, RequestedCertificateSet};
use crate::primitives::PublicKey;
use crate::{Error, Result};

/// The reference's limits on a requested certificate set
/// (`ts-stack@edf6e03` `packages/sdk/src/auth/AuthMessageValidation.ts:11-14`).
const MAX_REQUESTED_CERTIFIERS: usize = 100;
const MAX_REQUESTED_CERTIFICATE_TYPES: usize = 100;
const MAX_REQUESTED_CERTIFICATE_FIELDS: usize = 100;
const MAX_REQUESTED_CERTIFICATE_FIELD_BYTES: usize = 50;

/// A record key that can alter or impersonate a JavaScript object's
/// structure (`SafeRecord.ts:2-4`).
fn is_unsafe_record_key(key: &str) -> bool {
    matches!(key, "__proto__" | "constructor" | "prototype")
}

/// Refuses a requested certificate set the reference's `Peer` refuses, in
/// its words: `assertRequestedCertificateSet` (`ts-stack@edf6e03`
/// `packages/sdk/src/auth/AuthMessageValidation.ts:107-162`), which the
/// reference calls on its own policy before it signs or sends it
/// (`Peer.ts:158`, `:332`, `:434`) and on a received message's
/// `requestedCertificates` before any handler (`:346`, `:367`, through
/// `snapshotAuthMessage` at `Peer.ts:767`). [`Peer`](crate::auth::Peer)
/// calls it at the same sites (#294).
///
/// An empty set is valid: it is the reference's default policy
/// (`Peer.ts:154-157`). Each certifier is a lowercase compressed public key
/// in its canonical hex, the certifiers unique; each type ID canonical
/// base64 of exactly 32 bytes (`base64ToBytes`, `WalletByteEncoding.ts:39`),
/// so an integer-like key (`"42"`, which a JavaScript object moves first) is
/// never signed by either side; each type's field names unique, non-empty,
/// at most 50 UTF-8 bytes. Unlike [`validate_requested_certificate_set`](super::validate_requested_certificate_set),
/// whose words and empty-set refusal are this crate's own.
///
/// # Errors
///
/// [`Error::AuthError`] carrying the reference's message.
pub fn assert_requested_certificate_set(requested: &RequestedCertificateSet) -> Result<()> {
    let refuse = |words: &str| Err(Error::AuthError(words.to_string()));

    if requested.certifiers.len() > MAX_REQUESTED_CERTIFIERS {
        return refuse("requestedCertificates.certifiers exceeds its limit.");
    }
    let mut certifiers = std::collections::HashSet::new();
    for certifier in &requested.certifiers {
        assert_auth_identity_key(certifier)?;
        if !certifiers.insert(certifier.as_str()) {
            return refuse("requestedCertificates.certifiers must be unique.");
        }
    }

    if requested.types.len() > MAX_REQUESTED_CERTIFICATE_TYPES {
        return refuse("requestedCertificates.types exceeds its limit.");
    }
    for (type_id, fields) in &requested.types {
        // The bounded-data walk refuses an unsafe key before the set's own
        // check (`:110`, `:241-244`) can
        if is_unsafe_record_key(type_id) {
            return refuse("Authentication messages contain an unsafe property key.");
        }
        assert_canonical_base64(type_id, "certificate type", 32)?;
        if fields.len() > MAX_REQUESTED_CERTIFICATE_FIELDS {
            return refuse("Requested certificate fields exceed their limit.");
        }
        let mut unique = std::collections::HashSet::new();
        for field in fields {
            if field.is_empty()
                || field.len() > MAX_REQUESTED_CERTIFICATE_FIELD_BYTES
                || is_unsafe_record_key(field)
                || !unique.insert(field.as_str())
            {
                return refuse("Requested certificate field names must be unique safe strings.");
            }
        }
    }
    Ok(())
}

/// `assertAuthIdentityKey` (`AuthMessageValidation.ts:81-91`): `02` or `03`
/// and 64 lowercase hex digits, a point on the curve.
fn assert_auth_identity_key(value: &str) -> Result<()> {
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
        Ok(key) if key.to_hex() == value => Ok(()),
        _ => Err(Error::AuthError(
            "Authentication identityKey must be a valid compressed public key.".into(),
        )),
    }
}

/// `assertCanonicalBase64` (`AuthMessageValidation.ts:64-79`): at most 128
/// characters of canonical base64 (padded, no whitespace, zero trailing
/// bits: the text this crate's encoder writes back for the bytes), decoding
/// to `decoded_bytes`.
pub(super) fn assert_canonical_base64(value: &str, name: &str, decoded_bytes: usize) -> Result<()> {
    let decoded = canonical_base64(value, name)?;
    if decoded.len() != decoded_bytes {
        return Err(Error::AuthError(format!(
            "{name} must encode exactly {decoded_bytes} bytes."
        )));
    }
    Ok(())
}

/// The text half of `assertCanonicalBase64` (`AuthMessageValidation.ts:69-75`),
/// its bytes, or the refusal in its words.
pub(crate) fn canonical_base64(value: &str, name: &str) -> Result<Vec<u8>> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    match STANDARD.decode(value) {
        Ok(decoded) if value.len() <= 128 && STANDARD.encode(&decoded) == value => Ok(decoded),
        _ => Err(Error::AuthError(format!(
            "{name} must be canonical base64."
        ))),
    }
}

/// A received message's `requestedCertificates`, refused before any handler
/// as the reference's `snapshotAuthMessage` refuses it (`ts-stack@edf6e03`
/// `packages/sdk/src/auth/AuthMessageValidation.ts:345-347` on any message;
/// called at `Peer.ts:767`). A missing set on a certificateRequest is
/// refused after its nonces in `check_received_message` (`:367`).
pub(crate) fn check_received_requested_certificates(message: &AuthMessage) -> Result<()> {
    match message.requested_certificates {
        Some(ref requested) => assert_requested_certificate_set(requested),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::PrivateKey;

    // The reference's words for each rule of `assertRequestedCertificateSet`
    // (`ts-stack@edf6e03` `AuthMessageValidation.ts:107-162`, #294)
    fn refused(set: &RequestedCertificateSet) -> String {
        match assert_requested_certificate_set(set) {
            Err(Error::AuthError(words)) => words,
            other => panic!("expected an AuthError, got {other:?}"),
        }
    }

    fn one_type(type_id: &str, fields: &[&str]) -> RequestedCertificateSet {
        let mut set = RequestedCertificateSet::new();
        set.add_type(
            type_id.to_string(),
            fields.iter().map(|f| f.to_string()).collect(),
        );
        set
    }

    #[test]
    fn the_peers_validator_accepts_the_references_default_and_a_full_set_294() {
        assert_requested_certificate_set(&RequestedCertificateSet::new()).unwrap();
        let mut set = one_type(&crate::primitives::to_base64(&[9u8; 32]), &[]);
        set.add_certifier(PrivateKey::random().public_key().to_hex());
        set.add_certifier(PrivateKey::random().public_key().to_hex());
        assert_requested_certificate_set(&set).unwrap();
        let fifty = "é".repeat(25);
        assert_requested_certificate_set(&one_type(
            &crate::primitives::to_base64(&[9u8; 32]),
            &[&fifty, "name"],
        ))
        .unwrap();
    }

    #[test]
    fn the_peers_validator_refuses_a_certifier_in_the_references_words_294() {
        let key = PrivateKey::random().public_key().to_hex();
        for bad in [
            key.to_uppercase(),
            format!("04{}", &key[2..]),
            key[..64].to_string(),
            format!("{key}00"),
        ] {
            let mut set = RequestedCertificateSet::new();
            set.add_certifier(bad.clone());
            assert_eq!(
                refused(&set),
                "Authentication identityKey must be a canonical compressed public key.",
                "{bad}"
            );
        }
        // The form, but x = 5 is on no point of secp256k1
        let mut set = RequestedCertificateSet::new();
        set.add_certifier(format!("02{:064x}", 5));
        assert_eq!(
            refused(&set),
            "Authentication identityKey must be a valid compressed public key."
        );
        let mut set = RequestedCertificateSet::new();
        set.add_certifier(key.clone());
        set.certifiers.push(key);
        assert_eq!(
            refused(&set),
            "requestedCertificates.certifiers must be unique."
        );
        let mut set = RequestedCertificateSet::new();
        set.certifiers = (0..101)
            .map(|_| PrivateKey::random().public_key().to_hex())
            .collect();
        assert_eq!(
            refused(&set),
            "requestedCertificates.certifiers exceeds its limit."
        );
    }

    #[test]
    fn the_peers_validator_refuses_a_type_id_in_the_references_words_294() {
        let canonical = "certificate type must be canonical base64.";
        let length = "certificate type must encode exactly 32 bytes.";
        let b64 = |n: usize| crate::primitives::to_base64(&vec![1u8; n]);
        for (type_id, words) in [
            (b64(31), length),
            (b64(33), length),
            (String::new(), length),
            ("42".to_string(), canonical),
            ("not base64!".to_string(), canonical),
            (b64(32).trim_end_matches('=').to_string(), canonical),
            (format!(" {}", b64(32)), canonical),
            // The URL-safe alphabet
            (
                crate::primitives::to_base64(&[0xfb; 32]).replace(['+', '/'], "-"),
                canonical,
            ),
            // Nonzero bits under the padding: `base64ToBytes` refuses them
            (
                "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQF=".to_string(),
                canonical,
            ),
            ("A".repeat(132), canonical),
        ] {
            assert_eq!(
                refused(&one_type(&type_id, &["name"])),
                words,
                "{type_id:?}"
            );
        }
        for unsafe_key in ["__proto__", "constructor", "prototype"] {
            assert_eq!(
                refused(&one_type(unsafe_key, &["name"])),
                "Authentication messages contain an unsafe property key."
            );
        }
        let mut set = RequestedCertificateSet::new();
        for n in 0..101u8 {
            set.add_type(crate::primitives::to_base64(&[n; 32]), vec![]);
        }
        assert_eq!(
            refused(&set),
            "requestedCertificates.types exceeds its limit."
        );
    }

    #[test]
    fn the_peers_validator_refuses_a_field_name_in_the_references_words_294() {
        let type_id = crate::primitives::to_base64(&[3u8; 32]);
        let words = "Requested certificate field names must be unique safe strings.";
        let fifty_one = "é".repeat(25) + "a";
        for fields in [
            vec![""],
            vec![fifty_one.as_str()],
            vec!["__proto__"],
            vec!["constructor"],
            vec!["name", "name"],
        ] {
            assert_eq!(refused(&one_type(&type_id, &fields)), words, "{fields:?}");
        }
        let many: Vec<String> = (0..101).map(|n| format!("f{n}")).collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        assert_eq!(
            refused(&one_type(&type_id, &many)),
            "Requested certificate fields exceed their limit."
        );
    }
}
