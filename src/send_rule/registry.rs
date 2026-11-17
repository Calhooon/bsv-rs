//! The `registry` module's doors (`send_rule`'s header has the rule).

use super::{send, Values};
use crate::registry::RegistryClient;
use crate::wallet::WalletInterface;

// src/registry/client.rs
fn registry<V: Values, W: WalletInterface>(v: &V) {
    let registry = v.any::<&RegistryClient<W>>();
    send(registry.register_definition(v.any()));
    send(registry.resolve_basket(v.any()));
    send(registry.resolve_protocol(v.any()));
    send(registry.resolve_certificate(v.any()));
    send(registry.list_own_registry_entries(v.any()));
    send(registry.revoke_own_registry_entry(v.any()));
    send(registry.update_definition(v.any(), v.any()));
}
