//! The authentication the SLAP and SHIP discoveries ask of an advertisement
//! before they admit its host (the stable line's port of #544's discovery
//! sites): the advertisement is the protocol the discovery asks for, its
//! five fields are the four data fields and a DER signature over them by the
//! identity key's linked key (BRC-42 for `anyone`, the protocol's BRC-43
//! name at security level 2, key ID `1`), and it is locked with that linked
//! key, as `create_signed_overlay_admin_token` writes it. The fields are read
//! by `decode_overlay_admin_token`, which is unchanged: a decode does not
//! establish the author.

use super::overlay_admin_token_template::{decode_overlay_admin_token, OverlayAdminTokenData};
use crate::overlay::types::Protocol;
use crate::primitives::hash::sha256;
use crate::primitives::Signature;
use crate::script::templates::PushDrop;
use crate::script::LockingScript;
use crate::wallet::{Counterparty, KeyDeriver, Protocol as WalletProtocol, SecurityLevel};
use crate::{Error, Result};

fn refused(words: &str) -> Error {
    Error::OverlayError(words.to_string())
}

/// The advertisement's fields, when its identity's linked key signed it and
/// locks it and it is the `expected` protocol.
pub(crate) fn decode_and_verify(
    script: &LockingScript,
    expected: Protocol,
) -> Result<OverlayAdminTokenData> {
    let data = decode_overlay_admin_token(script)?;
    if data.protocol != expected {
        return Err(refused("Discovery advertisement protocol mismatch"));
    }
    let token = PushDrop::decode(script)?;
    let [fields @ .., signature] = token.fields.as_slice() else {
        return Err(refused("Discovery advertisement is not signed"));
    };
    if fields.len() != 4 {
        return Err(refused("Discovery advertisement is not signed"));
    }
    let name = match data.protocol {
        Protocol::Ship => "service host interconnect",
        Protocol::Slap => "service lookup availability",
    };
    let linked = KeyDeriver::new(None).derive_public_key(
        &WalletProtocol::new(SecurityLevel::Counterparty, name),
        "1",
        &Counterparty::Other(data.identity_key.clone()),
        false,
    )?;
    let signed = sha256(&fields.concat());
    if !Signature::from_der(signature).is_ok_and(|signature| linked.verify(&signed, &signature)) {
        return Err(refused("Signature is not valid"));
    }
    if linked != token.locking_public_key {
        return Err(refused(
            "Discovery advertisement locking key is not linked to its identity",
        ));
    }
    Ok(data)
}
