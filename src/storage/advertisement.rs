//! The authentication `StorageDownloader::resolve` asks of a UHRP
//! advertisement before it names its host (the stable line's port of #544's
//! storage site): six fields, the first the host's 33-byte identity key and
//! the second the hash of the file asked for, the sixth a signature over the
//! five data fields by the host's linked key (BRC-42 for `anyone`, the
//! protocol `uhrp advertisement` at security level 2, key ID `1`), and the
//! token locked with that key. The location and the expiry are read by the
//! downloader as before.

use crate::primitives::PublicKey;
use crate::script::templates::PushDrop;
use crate::wallet::{
    Counterparty, KeyDeriver, ProtoWallet, Protocol, SecurityLevel, VerifySignatureArgs,
};

/// Whether the advertisement's host signed it and locks it, and it is for
/// the file whose hash is `requested`.
pub(crate) fn authenticated(token: &PushDrop, requested: &[u8; 32]) -> bool {
    let [host, hash, _, _, _, signature] = token.fields.as_slice() else {
        return false;
    };
    if host.len() != 33 || hash.as_slice() != requested.as_slice() {
        return false;
    }
    let Ok(host) = PublicKey::from_bytes(host) else {
        return false;
    };
    let protocol = Protocol::new(SecurityLevel::Counterparty, "uhrp advertisement");
    let counterparty = Counterparty::Other(host);
    let linked = KeyDeriver::new(None).derive_public_key(&protocol, "1", &counterparty, false);
    if !linked.is_ok_and(|linked| linked == token.locking_public_key) {
        return false;
    }
    ProtoWallet::anyone()
        .verify_signature(VerifySignatureArgs {
            data: Some(token.fields[..5].concat()),
            hash_to_directly_verify: None,
            signature: signature.clone(),
            protocol_id: protocol,
            key_id: "1".to_string(),
            counterparty: Some(counterparty),
            for_self: Some(false),
        })
        .is_ok_and(|result| result.valid)
}
