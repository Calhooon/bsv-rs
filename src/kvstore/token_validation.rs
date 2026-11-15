//! The authentication the interpreter asks of a `KVStore` token before it
//! returns an entry: the controller (field 3, a 33-byte key) signed the
//! bytes of the data fields (every field before the last, the signature)
//! under the one derivation every judging door uses (`token_derivation`:
//! the protocol ID as canonical JSON `[level, name]`, the entry's key as key
//! ID, locked with the controller's key linked to `anyone`). A token in any
//! other form is no entry, this crate's earlier writer's form among them
//! (the raw protocol text and the key ID `kvstore-token`: its signature does
//! not bind the key). Nothing else is judged here: the field layout and the
//! entry the interpreter builds are unchanged.

use crate::primitives::PublicKey;
use crate::script::templates::PushDrop;
use crate::wallet::{Counterparty, ProtoWallet, VerifySignatureArgs};

/// Whether the controller a decoded token names signed it under the
/// key-bound derivation and its lock is that derivation's.
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
    let Ok(controller) = PublicKey::from_bytes(controller) else {
        return false;
    };
    let Some((protocol, key_id)) = super::token_derivation::derivation(
        protocol,
        key,
        &controller,
        &token.locking_public_key,
        None,
    ) else {
        return false;
    };
    ProtoWallet::anyone()
        .verify_signature(VerifySignatureArgs {
            data: Some(data.concat()),
            hash_to_directly_verify: None,
            signature: signature.clone(),
            protocol_id: protocol,
            key_id,
            counterparty: Some(Counterparty::Other(controller)),
            for_self: Some(false),
        })
        .is_ok_and(|result| result.valid)
}
