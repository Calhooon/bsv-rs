//! The one derivation a `GlobalKVStore` token's signature is judged under,
//! for every door that judges one (`verify_signature`, the deprecated
//! `verify_signature_legacy`, the store's reads and its history walk): the
//! protocol field as canonical JSON `[level, name]`, the key field as the
//! key ID, the locking key the controller's key linked to `anyone` under
//! that protocol and key (BRC-35, as `@bsv/sdk` writes and reads it). A
//! token in any other form authenticates nowhere: among them the form this
//! crate's `GlobalKVStore::set` wrote before (the protocol as raw text, the
//! constant key ID `kvstore-token`, locked with the controller's own key),
//! whose signature does not bind the key.

use crate::primitives::PublicKey;
use crate::wallet::{Counterparty, KeyDeriver, Protocol, SecurityLevel};

/// The protocol and key ID a token's signature is checked under, `None`
/// unless the protocol field is canonical JSON `[level, name]` and the
/// locking key is the controller's linked to `anyone` under that protocol
/// and the key. With `asked`, the protocol field must also name the protocol
/// asked (see [`names`]).
pub(crate) fn derivation(
    protocol_field: &[u8],
    key_field: &[u8],
    controller: &PublicKey,
    locking_key: &PublicKey,
    asked: Option<&str>,
) -> Option<(Protocol, String)> {
    let protocol = namespace(protocol_field)?;
    if asked.is_some_and(|asked| !names(&protocol, asked)) {
        return None;
    }
    let key_id = String::from_utf8(key_field.to_vec()).ok()?;
    let counterparty = Counterparty::Other(controller.clone());
    KeyDeriver::new(None)
        .derive_public_key(&protocol, &key_id, &counterparty, false)
        .is_ok_and(|linked| linked == *locking_key)
        .then_some((protocol, key_id))
}

/// The protocol a canonical `[level, name]` field names.
fn namespace(field: &[u8]) -> Option<Protocol> {
    let (level, name) = serde_json::from_slice::<(u8, String)>(field).ok()?;
    if serde_json::to_vec(&(level, &name)).ok()? != field {
        return None;
    }
    Protocol::from_tuple((level, &name))
}

/// Whether `protocol` is the protocol `asked` names: `asked` is a canonical
/// `[level, name]` or a plain name at level 1 (the store's configuration),
/// and the names compare as the derivation reads them (trimmed, lowercase).
fn names(protocol: &Protocol, asked: &str) -> bool {
    let asked =
        namespace(asked.as_bytes()).unwrap_or_else(|| Protocol::new(SecurityLevel::App, asked));
    let read = |name: &str| name.trim().to_lowercase();
    asked.security_level == protocol.security_level
        && read(&asked.protocol_name) == read(&protocol.protocol_name)
}
