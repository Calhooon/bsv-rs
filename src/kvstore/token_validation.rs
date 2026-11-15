//! The authentication the interpreter asks of a KVStore token before it
//! returns an entry (the stable line's port of #544's interpreter site): the
//! controller (field 3, a 33-byte key) signed the bytes of the data fields
//! (every field before the last, the signature) as its writer signs them,
//! and the token is locked with the key that controller's writer locks it
//! with. Two writers' tokens are read:
//!
//! - this crate's `GlobalKVStore::set` (every release from 0.2.0): the
//!   protocol ID as its raw text, signed under `[1, <protocol ID>]` with the
//!   key ID `kvstore-token` for `anyone`, locked with the controller's key;
//! - the canonical form, as 0.9.0's writer writes it:
//!   the protocol ID as JSON `[level, name]`, signed under that protocol with
//!   the entry's key as key ID for `anyone`, locked with the controller's key
//!   for `anyone`.
//!
//! A token that neither authenticates is no entry. Nothing else is judged
//! here: the field layout and the entry the interpreter builds are
//! unchanged.

use crate::primitives::PublicKey;
use crate::script::templates::PushDrop;
use crate::wallet::{
    Counterparty, KeyDeriver, ProtoWallet, Protocol, SecurityLevel, VerifySignatureArgs,
};

/// The key ID this crate's writer signs with (`GlobalKVStore::set`).
const CRATE_KEY_ID: &str = "kvstore-token";

/// Whether the controller a decoded token names signed it and its writer
/// locked it, in either writer's form.
pub(crate) fn authenticated(token: &PushDrop) -> bool {
    let Some((signature, data)) = token.fields.split_last() else {
        return false;
    };
    let (Some(protocol), Some(key), Some(controller)) = (data.first(), data.get(1), data.get(3))
    else {
        return false;
    };
    if controller.len() != 33 {
        return false;
    }
    let (Ok(protocol), Ok(key), Ok(controller)) = (
        std::str::from_utf8(protocol),
        std::str::from_utf8(key),
        PublicKey::from_bytes(controller),
    ) else {
        return false;
    };
    let signed = data.concat();
    crate_form(token, protocol, &controller, &signed, signature)
        || canonical_form(token, protocol, key, &controller, &signed, signature)
}

/// This crate's writer: locked with the controller's key, signed under the
/// raw protocol text at security level 1 with the key ID `kvstore-token`.
fn crate_form(
    token: &PushDrop,
    protocol: &str,
    controller: &PublicKey,
    signed: &[u8],
    signature: &[u8],
) -> bool {
    token.locking_public_key == *controller
        && verified(
            Protocol::new(SecurityLevel::App, protocol),
            CRATE_KEY_ID,
            controller,
            signed,
            signature,
        )
}

/// The canonical form: the protocol as JSON `[level, name]`, the entry's
/// key as key ID, locked with the controller's key for `anyone`.
fn canonical_form(
    token: &PushDrop,
    protocol: &str,
    key: &str,
    controller: &PublicKey,
    signed: &[u8],
    signature: &[u8],
) -> bool {
    let Some(protocol) = serde_json::from_str::<(u8, String)>(protocol)
        .ok()
        .and_then(|(level, name)| Protocol::from_tuple((level, &name)))
    else {
        return false;
    };
    let counterparty = Counterparty::Other(controller.clone());
    let linked = KeyDeriver::new(None).derive_public_key(&protocol, key, &counterparty, false);
    linked.is_ok_and(|linked| linked == token.locking_public_key)
        && verified(protocol, key, controller, signed, signature)
}

/// The controller's signature over `signed`, checked by `anyone`.
fn verified(
    protocol: Protocol,
    key_id: &str,
    controller: &PublicKey,
    signed: &[u8],
    signature: &[u8],
) -> bool {
    ProtoWallet::anyone()
        .verify_signature(VerifySignatureArgs {
            data: Some(signed.to_vec()),
            hash_to_directly_verify: None,
            signature: signature.to_vec(),
            protocol_id: protocol,
            key_id: key_id.to_string(),
            counterparty: Some(Counterparty::Other(controller.clone())),
            for_self: Some(false),
        })
        .is_ok_and(|result| result.valid)
}
