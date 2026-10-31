//! The registry's definition token as the reference writes and reads it
//! (#543; `ts-stack@edf6e03` `registryTokenValidation.ts:13-64`,
//! `RegistryClient.ts:308-342`, `PushDrop.ts:146-202`): the data fields (6
//! for a basket or a protocol, 7 for a certificate, the operator's identity
//! key last), then the operator's signature over them, locked with the
//! operator's key linked to `anyone`.

use crate::primitives::PublicKey;
use crate::registry::types::DefinitionType;
use crate::registry::REGISTRANT_KEY_ID;
use crate::script::templates::pushdrop_key_bytes::wallet_key_lock;
use crate::script::templates::pushdrop_position::{
    canonical_refusal, key_text_refusal, point_message,
};
use crate::script::templates::PushDrop;
use crate::script::LockingScript;
use crate::wallet::interface::WalletInterface;
use crate::wallet::validation::crypto::public_key_hex;
use crate::wallet::{
    Counterparty, CreateSignatureArgs, GetPublicKeyArgs, KeyDeriver, ProtoWallet, Protocol,
    SecurityLevel, VerifySignatureArgs,
};
use crate::{Error, Result};

/// `MAX_REGISTRY_FIELD_BYTES` and `MAX_REGISTRY_TOKEN_BYTES`
/// (`registryTokenValidation.ts:10-11`).
const MAX_FIELD_BYTES: usize = 16 * 1024;
const MAX_TOKEN_BYTES: usize = 64 * 1024;

/// The definition type's data fields and wallet protocol (`tokenShape`,
/// `registryTokenValidation.ts:13-17`).
fn shape(definition_type: DefinitionType) -> (usize, Protocol) {
    let (_, name) = definition_type.wallet_protocol();
    let data_fields = match definition_type {
        DefinitionType::Certificate => 7,
        DefinitionType::Basket | DefinitionType::Protocol => 6,
    };
    (data_fields, Protocol::new(SecurityLevel::App, name))
}

fn refused(words: impl Into<String>) -> Error {
    Error::RegistryError(words.into())
}

/// `decodeAndVerifyRegistryToken` (`registryTokenValidation.ts:57-64`): the
/// token's data fields as text, the operator's identity key last, once the
/// token is the canonical lock-before envelope of the type's field count
/// plus a signature, its key the operator's linked to `anyone`, and its
/// signature the operator's over the data fields; refused otherwise as
/// `Error::RegistryError` in the reference's words. The operator's text is
/// read as a key as `PublicKey.fromString` reads it (`PublicKey::from_hex`,
/// the reference's lenient forms since #498) for the linkage, then judged as
/// the counterparty of the reference's `verifySignature`
/// (`validationHelpers.ts:185-196`, `:522-534`): 66 hex characters (either
/// case, as the reference lowercases them), a compressed key, a valid point.
pub fn decode_and_verify_registry_token(
    definition_type: DefinitionType,
    locking_script: &LockingScript,
) -> Result<Vec<String>> {
    let (data_fields, protocol) = shape(definition_type);
    let count = data_fields + 1;
    let token = PushDrop::decode_before(locking_script)
        .map_err(|error| canonical_refusal(locking_script, &[count]).map_or(error, refused))?;
    // `Point.fromDER`'s read of the locking key (`PushDropValidation.ts:59`, `PushDrop.ts:74-75`):
    // k256 reads a `05` prefix as a compact point the reference refuses.
    let lock_key = locking_script.chunks().first().and_then(|c| c.data.clone());
    if let Some(words) = lock_key.as_deref().and_then(point_message) {
        return Err(refused(words));
    }
    if token.fields.len() != count {
        return Err(refused("Unexpected PushDrop token field count"));
    }
    let mut payload = 0;
    for field in &token.fields {
        if field.len() > MAX_FIELD_BYTES {
            return Err(refused("PushDrop token contains an oversized field"));
        }
        payload += field.len();
        if payload > MAX_TOKEN_BYTES {
            return Err(refused("PushDrop token payload is too large"));
        }
    }
    if token.lock().to_binary() != locking_script.to_binary() {
        return Err(refused(
            "PushDrop token must use the canonical PushDrop envelope",
        ));
    }
    let (data, signature) = token.fields.split_at(data_fields);
    // `toUTF8Strict`: a fatal `TextDecoder`, which drops one leading BOM.
    let decoded = data
        .iter()
        .map(|field| match std::str::from_utf8(field) {
            Ok(text) => Ok(text.strip_prefix('\u{feff}').unwrap_or(text).to_string()),
            Err(_) => Err(refused("The encoded data was not valid for encoding utf-8")),
        })
        .collect::<Result<Vec<_>>>()?;
    // `PublicKey.fromString(registryOperator)` (`registryTokenValidation.ts:36`):
    // its words first, as k256 reads a `05` prefix as a compact point the
    // reference refuses.
    let operator_text = &decoded[data_fields - 1];
    if let Some(words) = key_text_refusal(operator_text) {
        return Err(refused(words));
    }
    let operator = PublicKey::from_hex(operator_text)?;
    let counterparty = Counterparty::Other(operator);
    let expected = KeyDeriver::new(None).derive_public_key(
        &protocol,
        REGISTRANT_KEY_ID,
        &counterparty,
        false,
    )?;
    if expected != token.locking_public_key {
        return Err(refused(
            "Registry token locking key is not linked to its operator",
        ));
    }
    // `validateVerifySignatureArgs`' counterparty (`ProtoWallet.ts:359`,
    // `validationHelpers.ts:1797`, `:228`), judged before the signature.
    public_key_hex(operator_text, "counterparty").map_err(|error| match error {
        Error::WalletRefusal { message, .. } => refused(message),
        other => other,
    })?;
    ProtoWallet::anyone()
        .verify_signature(VerifySignatureArgs {
            data: Some(data.concat()),
            signature: signature[0].clone(),
            protocol_id: protocol,
            key_id: REGISTRANT_KEY_ID.into(),
            counterparty: Some(counterparty),
            ..Default::default()
        })
        // `validateVerifySignatureArgs`' words for a non-DER signature
        // (`ProtoWallet.ts:359`, `validationHelpers.ts:1801`) and the verdict's.
        .map_err(|error| match error {
            Error::WalletError(words) | Error::WalletRefusal { message: words, .. } => {
                refused(words)
            }
            other => other,
        })?;
    Ok(decoded)
}

/// The definition's data fields as `decode_and_verify_registry_token`
/// reads them, as bytes for `from_pushdrop_fields`.
pub(crate) fn data_fields(
    definition_type: DefinitionType,
    locking_script: &LockingScript,
) -> Result<Vec<Vec<u8>>> {
    Ok(
        decode_and_verify_registry_token(definition_type, locking_script)?
            .into_iter()
            .map(String::into_bytes)
            .collect(),
    )
}

/// `PushDrop.lock(fields, protocol, '1', 'anyone', true)`
/// (`RegistryClient.ts:320`, `:622-628`): the wallet's key for `anyone`
/// (`forSelf`), then its signature over the fields' bytes for `anyone`,
/// appended as the last field.
pub(crate) async fn lock_definition<W: WalletInterface>(
    wallet: &W,
    definition_type: DefinitionType,
    mut fields: Vec<Vec<u8>>,
    originator: Option<&str>,
) -> Result<LockingScript> {
    let (_, protocol) = shape(definition_type);
    let key = wallet
        .get_public_key(
            GetPublicKeyArgs {
                protocol_id: Some(protocol.clone()),
                key_id: Some(REGISTRANT_KEY_ID.into()),
                counterparty: Some(Counterparty::Anyone),
                for_self: Some(true),
                ..Default::default()
            },
            originator,
        )
        .await?;
    let signed = wallet
        .create_signature(
            CreateSignatureArgs {
                data: Some(fields.concat()),
                protocol_id: protocol,
                key_id: REGISTRANT_KEY_ID.into(),
                counterparty: Some(Counterparty::Anyone),
                ..Default::default()
            },
            originator,
        )
        .await?;
    fields.push(signed.signature);
    wallet_key_lock(&key.public_key, fields)
}
