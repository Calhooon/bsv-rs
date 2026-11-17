//! The `identity` module's doors (`send_rule`'s header has the rule).

use super::{send, Values};
use crate::identity::{ContactsManager, IdentityClient};
use crate::wallet::WalletInterface;

// src/identity/client.rs
fn identity<V: Values, W: WalletInterface + Clone>(v: &V) {
    let identity = v.any::<&IdentityClient<W>>();
    send(identity.get_identity_key());
    send(identity.publicly_reveal_attributes(v.any(), v.any()));
    send(identity.publicly_reveal_attributes_simple(v.any(), v.any()));
    send(identity.revoke_certificate_revelation(v.any()));
    send(identity.resolve_by_identity_key(v.any(), v.any()));
    send(identity.resolve_by_attributes(v.any(), v.any()));
    send(identity.discover_certificates(v.any()));
    send(identity.discover_certificates_by_type(v.any(), v.any()));
    send(identity.query(v.any()));
    send(identity.get_contacts(v.any()));
    send(identity.get_contact(v.any()));
    send(identity.save_contact(v.any(), v.any()));
    send(identity.remove_contact(v.any()));
}

// src/identity/contacts.rs
fn contacts<V: Values, W: WalletInterface>(v: &V) {
    let contacts = v.any::<&ContactsManager<W>>();
    send(contacts.add_contact(v.any()));
    send(contacts.get_contact(v.any()));
    send(contacts.update_contact(v.any(), v.any()));
}

// src/identity/contacts_actions.rs
fn contacts_actions<V: Values, W: WalletInterface>(v: &V) {
    let removing = v.any::<&ContactsManager<W>>();
    send(removing.remove_contact(v.any()));
}

// src/identity/contacts_cache.rs
fn contacts_cache<V: Values, W: WalletInterface>(v: &V) {
    let cache = v.any::<&ContactsManager<W>>();
    send(cache.list_contacts());
    send(cache.list_contacts_with_refresh(v.any()));
    send(cache.search_contacts(v.any()));
    send(cache.get_contacts_by_tag(v.any()));
    send(cache.clear_cache());
    send(cache.is_cache_initialized());
    send(cache.cached_count());
}
