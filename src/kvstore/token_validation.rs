//! `decodeAndVerifyKVStoreToken` (`ts-stack@edf6e03`
//! `kvStoreTokenValidation.ts:85-119`), the reference interpreter's reader
//! (`kvStoreInterpreter.ts:37`; #544): the canonical lock-before envelope of
//! five or six fields (`decodeCanonicalPushDrop`, `PushDropValidation.ts:54-79`),
//! the protocol ID canonical JSON, the key, the value, the 33-byte
//! controller and the optional tags in their bounds, the locking key the
//! controller's linked to `anyone`, the controller's signature over the data
//! fields; refused otherwise in the reference's words, as
//! `Error::KvStoreError`.

use super::interpreter::validate_tags;
use crate::primitives::{to_hex, PublicKey};
use crate::script::templates::pushdrop_position::canonical_refusal;
use crate::script::templates::PushDrop;
use crate::script::LockingScript;
use crate::wallet::{Counterparty, KeyDeriver, ProtoWallet, Protocol, VerifySignatureArgs};
use crate::{Error, Result};

/// `MAX_VALUE_BYTES` (`kvStoreTokenValidation.ts:11`) and the payload bound
/// the reader passes (`:89-91`).
const MAX_VALUE_BYTES: usize = 1024 * 1024;
const MAX_PAYLOAD_BYTES: usize = MAX_VALUE_BYTES + 64 * 1024;

fn refused(words: impl Into<String>) -> Error {
    Error::KvStoreError(words.into())
}

/// A token `decode_and_verify` authenticated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthenticatedToken {
    pub protocol_id_text: String,
    pub key: String,
    pub value: String,
    pub controller: String,
    pub tags: Option<Vec<String>>,
}

/// `toUTF8Strict`: a fatal `TextDecoder`, which drops one leading BOM.
fn strict_utf8(field: &[u8]) -> Result<String> {
    let text = std::str::from_utf8(field)
        .map_err(|_| refused("The encoded data was not valid for encoding utf-8"))?;
    Ok(text.strip_prefix('\u{feff}').unwrap_or(text).to_string())
}

/// `decodeCanonicalPushDrop(script, { fieldCount: [5, 6], ... })`.
fn canonical(script: &LockingScript) -> Result<PushDrop> {
    let token = PushDrop::decode_before(script)
        .map_err(|error| canonical_refusal(script, &[5, 6]).map_or(error, refused))?;
    if !matches!(token.fields.len(), 5 | 6) {
        return Err(refused("Unexpected PushDrop token field count"));
    }
    let mut payload = 0;
    for field in &token.fields {
        if field.len() > MAX_VALUE_BYTES {
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

/// `validateKVStoreProtocol` and the canonical-text check
/// (`kvStoreTokenValidation.ts:28-40`, `:95-98`).
fn protocol(text: &str) -> Result<Protocol> {
    let parsed: serde_json::Value =
        serde_json::from_str(text).map_err(|e| refused(e.to_string()))?;
    let pair = parsed
        .as_array()
        .filter(|pair| pair.len() == 2)
        .ok_or_else(|| refused("KVStore protocol ID must contain exactly two fields"))?;
    let (Some(level @ 0..=2), Some(name)) = (pair[0].as_u64(), pair[1].as_str()) else {
        return Err(refused("KVStore protocol ID is invalid"));
    };
    if !(5..=400).contains(&name.len()) {
        return Err(refused("KVStore protocol name is invalid"));
    }
    if serde_json::to_string(&(level, name)).ok().as_deref() != Some(text) {
        return Err(refused("KVStore protocol ID must use canonical JSON"));
    }
    Protocol::from_tuple((level as u8, name))
        .ok_or_else(|| refused("KVStore protocol ID is invalid"))
}

/// `decodeAndVerifyKVStoreToken` (`kvStoreTokenValidation.ts:85-119`).
pub(crate) fn decode_and_verify(script: &LockingScript) -> Result<AuthenticatedToken> {
    let token = canonical(script)?;
    let (data, signature) = token.fields.split_at(token.fields.len() - 1);
    let protocol_id_text = strict_utf8(&data[0])?;
    let protocol = protocol(&protocol_id_text)?;
    let key = strict_utf8(&data[1])?;
    if !(1..=800).contains(&key.len()) {
        return Err(refused("KVStore key has an invalid length"));
    }
    let value = strict_utf8(&data[2])?;
    if !(1..=MAX_VALUE_BYTES).contains(&value.len()) {
        return Err(refused("KVStore value has an invalid length"));
    }
    if data[3].len() != 33 {
        return Err(refused("KVStore controller is invalid"));
    }
    let controller_key = PublicKey::from_bytes(&data[3])?;
    let tags = match data.get(4) {
        Some(field) => {
            let parsed: serde_json::Value =
                serde_json::from_str(&strict_utf8(field)?).map_err(|e| refused(e.to_string()))?;
            Some(validate_tags(&parsed)?)
        }
        None => None,
    };
    let counterparty = Counterparty::Other(controller_key);
    let expected =
        KeyDeriver::new(None).derive_public_key(&protocol, &key, &counterparty, false)?;
    if expected != token.locking_public_key {
        return Err(refused(
            "KVStore token locking key is not linked to its controller",
        ));
    }
    let verified = ProtoWallet::anyone()
        .verify_signature(VerifySignatureArgs {
            data: Some(data.concat()),
            signature: signature[0].clone(),
            protocol_id: protocol,
            key_id: key.clone(),
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
        return Err(refused("KVStore token signature is invalid"));
    }
    Ok(AuthenticatedToken {
        protocol_id_text,
        key,
        value,
        controller: to_hex(&data[3]),
        tags,
    })
}

#[cfg(test)]
#[path = "token_validation_tests.rs"]
mod tests;
