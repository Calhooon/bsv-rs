//! The verdict of the deprecated `KVStoreInterpreter::verify_signature_legacy`.
//!
//! `true` only when the PushDrop carries a token of five or six fields whose
//! controller field is `controller`'s compressed key and whose last field is
//! `controller`'s signature over the others (a field read as `OP_0`'s single
//! zero byte signed as that byte or as an empty field). The signature is
//! judged under the derivation the token's protocol field names, one of the
//! two this crate's writers have used: the `[level, name]` namespace with the
//! key as the key ID and the locking key derived from the controller, or a
//! plain protocol name with the key ID `kvstore-token`. The tags' bounds are
//! the readers' rule and are not judged here, so a token its controller
//! signed answers `true` whatever its tags.

use crate::primitives::PublicKey;
use crate::script::templates::PushDrop;
use crate::wallet::{
    Counterparty, KeyDeriverApi, ProtoWallet, Protocol, SecurityLevel, VerifySignatureArgs,
};

/// Whether `pushdrop` carries a token whose controller field is `controller`
/// and whose last field is `controller`'s signature over the others.
pub(super) fn signed_by(pushdrop: &PushDrop, controller: &PublicKey, wallet: &ProtoWallet) -> bool {
    let fields = &pushdrop.fields;
    if !matches!(fields.len(), 5 | 6) {
        return false;
    }
    let Some((signature, signed)) = fields.split_last() else {
        return false;
    };
    if signature.is_empty() || signed[3].as_slice() != controller.to_compressed().as_slice() {
        return false;
    }
    let Some((protocol_id, key_id)) = derivation(pushdrop, controller, wallet) else {
        return false;
    };
    // `OP_0` is the push of an empty field and of a single zero byte alike,
    // and reads back as the zero byte: either is a faithful reading of it.
    let zeros: Vec<usize> = (0..signed.len())
        .filter(|&at| signed[at].as_slice() == [0])
        .collect();
    (0..1u32 << zeros.len()).any(|emptied| {
        let data: Vec<u8> = signed
            .iter()
            .enumerate()
            .filter(|(at, _)| {
                let bit = zeros.iter().position(|zero| zero == at);
                bit.is_none_or(|bit| emptied & (1 << bit) == 0)
            })
            .flat_map(|(_, field)| field.iter().copied())
            .collect();
        wallet
            .verify_signature(VerifySignatureArgs {
                data: Some(data),
                hash_to_directly_verify: None,
                signature: signature.clone(),
                protocol_id: protocol_id.clone(),
                key_id: key_id.clone(),
                counterparty: Some(Counterparty::Other(controller.clone())),
                for_self: Some(false),
            })
            .is_ok_and(|result| result.valid)
    })
}

/// The protocol and key ID the token was signed under, `None` for a protocol
/// field neither writer produces or a namespace token whose locking key is
/// not the one derived from its controller.
fn derivation(
    pushdrop: &PushDrop,
    controller: &PublicKey,
    wallet: &ProtoWallet,
) -> Option<(Protocol, String)> {
    let text = std::str::from_utf8(&pushdrop.fields[0]).ok()?;
    let Ok((level, name)) = serde_json::from_str::<(u8, String)>(text) else {
        return Some((
            Protocol::new(SecurityLevel::App, text),
            "kvstore-token".to_owned(),
        ));
    };
    if serde_json::to_string(&(level, &name)).ok()? != text {
        return None;
    }
    let protocol = Protocol::from_tuple((level, &name))?;
    let key_id = String::from_utf8(pushdrop.fields[1].clone()).ok()?;
    let linked = wallet.key_deriver().derive_public_key(
        &protocol,
        &key_id,
        &Counterparty::Other(controller.clone()),
        false,
    );
    linked
        .is_ok_and(|key| key == pushdrop.locking_public_key)
        .then_some((protocol, key_id))
}
