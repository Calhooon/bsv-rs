//! The `kvstore` module's doors (`send_rule`'s header has the rule).

use super::{send, Values};
use crate::kvstore::{GlobalKVStore, LocalKVStore};
use crate::wallet::WalletInterface;

// src/kvstore/global.rs
fn global<V: Values, W: WalletInterface>(v: &V) {
    let global = v.any::<&GlobalKVStore<W>>();
    send(global.get(v.any(), v.any()));
    send(global.set(v.any(), v.any(), v.any()));
    send(global.remove(v.any(), v.any()));
    send(global.query(v.any()));
    send(global.get_by_controller(v.any()));
    send(global.batch_get(v.any()));
    send(global.batch_set(v.any()));
    send(global.batch_remove(v.any()));
    send(global.get_by_tags(v.any(), v.any()));
}

// src/kvstore/local.rs
fn local<V: Values, W: WalletInterface + std::fmt::Debug>(v: &V) {
    let local = v.any::<&LocalKVStore<W>>();
    send(local.get(v.any(), v.any()));
    send(local.get_entry(v.any(), v.any()));
    send(local.set(v.any(), v.any(), v.any()));
    send(local.remove(v.any(), v.any()));
    send(local.keys());
    send(local.list(v.any()));
    send(local.has(v.any()));
    send(local.count());
    send(local.batch_get(v.any()));
    send(local.batch_set(v.any()));
    send(local.batch_remove(v.any()));
    send(local.clear());
}
