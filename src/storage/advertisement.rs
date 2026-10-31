//! `decodeAndVerifyUHRPAdvertisement` (`ts-stack@edf6e03`
//! `UHRPAdvertisementValidation.ts:37-115`; #544): the canonical lock-before
//! envelope of six fields, the host's canonical identity key, the 32-byte
//! hash, a credential-free HTTPS location, the expiry time and file size as
//! positive canonical CompactSize integers, the signature canonical DER of 8
//! to 80 bytes, the locking key the host's linked to `anyone`, the host's
//! signature over the five data fields; refused otherwise in the
//! reference's words, as `Error::OverlayError`.

use crate::primitives::{PublicKey, Reader};
use crate::script::templates::pushdrop_position::{canonical_refusal, point_message};
use crate::script::templates::PushDrop;
use crate::script::LockingScript;
use crate::wallet::{
    Counterparty, KeyDeriver, ProtoWallet, Protocol, SecurityLevel, VerifySignatureArgs,
};
use crate::{Error, Result};

/// `MAX_UHRP_ADVERTISEMENT_URL_BYTES` (`:11`) and the payload bound (`:41-43`).
const MAX_URL_BYTES: usize = 2048;
const MAX_PAYLOAD_BYTES: usize = MAX_URL_BYTES + 256;

fn refused(words: impl Into<String>) -> Error {
    Error::OverlayError(words.into())
}

/// An advertisement `decode_and_verify` authenticated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Advertisement {
    pub hash: Vec<u8>,
    pub hosted_file_location: String,
    pub expiry_time: u64,
}

/// `decodeCanonicalPushDrop(script, { fieldCount: 6, ... })` (`:40-44`).
fn canonical(script: &LockingScript) -> Result<PushDrop> {
    let token = PushDrop::decode_before(script)
        .map_err(|error| canonical_refusal(script, &[6]).map_or(error, refused))?;
    if token.fields.len() != 6 {
        return Err(refused("Unexpected PushDrop token field count"));
    }
    let mut payload = 0;
    for field in &token.fields {
        if field.len() > MAX_URL_BYTES {
            return Err(refused("PushDrop token contains an oversized field"));
        }
        payload += field.len();
        if payload > MAX_PAYLOAD_BYTES {
            return Err(refused("PushDrop token payload is too large"));
        }
    }
    if token.lock().to_binary() != script.to_binary() {
        return Err(refused(
            "PushDrop token must use the canonical PushDrop envelope",
        ));
    }
    Ok(token)
}

/// The host's identity key (`:46-53`).
fn host_key(field: &[u8]) -> Result<PublicKey> {
    if field.len() != 33 || !matches!(field[0], 2 | 3) {
        return Err(refused("UHRP advertisement host identity key is invalid"));
    }
    let key = PublicKey::from_reference_der(field)
        .map_err(|_| refused(point_message(field).unwrap_or("Invalid point")))?;
    if key.to_compressed().as_slice() != field {
        return Err(refused(
            "UHRP advertisement host identity key is not canonical",
        ));
    }
    Ok(key)
}

/// The hosted file's location (`:55-76`), as the WHATWG URL reads it.
fn location(field: &[u8]) -> Result<String> {
    let invalid = || refused("UHRP advertisement URL is invalid");
    if field.is_empty() || field.len() > MAX_URL_BYTES {
        return Err(invalid());
    }
    let text = std::str::from_utf8(field)
        .map_err(|_| refused("The encoded data was not valid for encoding utf-8"))?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    if text.chars().any(char::is_control) {
        return Err(refused(
            "UHRP advertisement URL contains control characters",
        ));
    }
    let url = url::Url::parse(text).map_err(|_| invalid())?;
    if url.scheme() != "https"
        || url.host_str().is_none_or(str::is_empty)
        || !url.username().is_empty()
        || url.password().is_some_and(|p| !p.is_empty())
        || url.fragment().is_some_and(|f| !f.is_empty())
    {
        return Err(refused(
            "UHRP advertisement must use a credential-free HTTPS URL",
        ));
    }
    Ok(text.to_string())
}

/// `readPositiveCompactSize` (`:23-30`): one canonical CompactSize, the
/// whole field, a positive safe integer.
fn positive_compact_size(field: &[u8], name: &str) -> Result<u64> {
    let mut reader = Reader::new(field);
    match reader.read_var_int() {
        Ok(value @ 1..=0x1f_ffff_ffff_ffff) if reader.is_empty() => Ok(value),
        _ => Err(refused(format!("UHRP advertisement {name} is invalid"))),
    }
}

/// `decodeAndVerifyUHRPAdvertisement` (`:37-115`).
pub(crate) fn decode_and_verify(script: &LockingScript) -> Result<Advertisement> {
    let token = canonical(script)?;
    let fields = &token.fields;
    let host = host_key(&fields[0])?;
    if fields[1].len() != 32 {
        return Err(refused("UHRP advertisement hash is invalid"));
    }
    let hosted_file_location = location(&fields[2])?;
    let expiry_time = positive_compact_size(&fields[3], "expiry time")?;
    positive_compact_size(&fields[4], "file size")?;
    if fields[5].len() < 8 || fields[5].len() > 80 {
        return Err(refused("UHRP advertisement signature is invalid"));
    }
    let canonical_der = crate::wallet::wire::reference_der(&fields[5]).map_err(refused)?;
    if canonical_der != fields[5] {
        return Err(refused("UHRP advertisement signature is not canonical"));
    }
    let protocol = Protocol::new(SecurityLevel::Counterparty, "uhrp advertisement");
    let counterparty = Counterparty::Other(host);
    let expected = KeyDeriver::new(None).derive_public_key(&protocol, "1", &counterparty, false)?;
    if expected != token.locking_public_key {
        return Err(refused(
            "UHRP advertisement locking key is not linked to its host",
        ));
    }
    let verified = ProtoWallet::anyone()
        .verify_signature(VerifySignatureArgs {
            data: Some(fields[..5].concat()),
            signature: fields[5].clone(),
            protocol_id: protocol,
            key_id: "1".into(),
            counterparty: Some(counterparty),
            ..Default::default()
        })
        .map_err(|error| match error {
            Error::WalletError(words) | Error::WalletRefusal { message: words, .. } => {
                refused(words)
            }
            other => other,
        })?;
    if !verified.valid {
        return Err(refused("UHRP advertisement signature is invalid"));
    }
    Ok(Advertisement {
        hash: fields[1].clone(),
        hosted_file_location,
        expiry_time,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    /// The reader's verdicts and words on the storage cases of
    /// `tests/vectors/token_envelope_544.json`, each the reference's
    /// `decodeAndVerifyUHRPAdvertisement` at `ts-stack@edf6e03` under
    /// Node v22.18.0.
    #[test]
    fn the_reader_gives_the_reference_verdict_in_its_words_544() {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/vectors/token_envelope_544.json"))
                .unwrap();
        let cases = v["storage"]["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 8);
        for case in cases {
            let script = LockingScript::from_hex(case["locking_script"].as_str().unwrap()).unwrap();
            let read = decode_and_verify(&script);
            match case["words"].as_str() {
                None => assert!(read.is_ok(), "{}: {read:?}", case["name"]),
                Some(words) => assert_eq!(read.unwrap_err(), refused(words), "{}", case["name"]),
            }
        }
    }
}
