//! The `overlay` module's doors (`send_rule`'s header has the rule).

use super::{send, Values};
use crate::overlay::{
    with_double_spend_retry, Historian, LookupResolver, OverlayBroadcastFacilitator,
    OverlayLookupFacilitator, RankChangeReceiver, TopicBroadcaster,
};
use crate::Result;
use core::future::Ready;

// src/overlay/facilitators.rs
fn lookup_facilitator<V: Values, L: OverlayLookupFacilitator + ?Sized>(v: &V) {
    let lookup = v.any::<&L>();
    send(lookup.lookup(v.any(), v.any(), v.any()));
    send(lookup.lookup_ordered(v.any(), v.any(), v.any(), v.any()));
    send(lookup.lookup_bounded(v.any(), v.any(), v.any(), v.any(), v.any()));
}

// src/overlay/facilitators.rs
fn broadcast_facilitator<V: Values, S: OverlayBroadcastFacilitator + ?Sized>(v: &V) {
    let submit = v.any::<&S>();
    send(submit.send(v.any(), v.any()));
}

// src/overlay/lookup_resolver.rs
fn resolver<V: Values>(v: &V) {
    let resolver = v.any::<&LookupResolver>();
    send(resolver.prune_tx_memo_cache());
    send(resolver.tx_memo_cache_size());
}

// src/overlay/lookup_resolver/discovery.rs
fn resolver_discovery<V: Values>(v: &V) {
    let discovering = v.any::<&LookupResolver>();
    send(discovering.find_competent_hosts(v.any()));
}

// src/overlay/lookup_resolver/query.rs
fn resolver_query<V: Values>(v: &V) {
    let asking = v.any::<&LookupResolver>();
    send(asking.query(v.any(), v.any()));
}

// src/overlay/topic_broadcaster.rs
fn topic_broadcaster<V: Values>(v: &V) {
    let topics = v.any::<&TopicBroadcaster>();
    send(topics.broadcast_tx(v.any()));
    send(topics.find_interested_hosts());
}

// src/overlay/historian.rs
fn historian<V: Values, T: Clone + Send + Sync + 'static, C: Send + Sync + 'static>(v: &V) {
    let historian = v.any::<&Historian<T, C>>();
    send(historian.build_history(v.any(), v.any()));
}

// src/overlay/rank_change_receiver.rs
fn rank_changes<V: Values>(v: &V) {
    let events = v.any::<&mut RankChangeReceiver>();
    send(events.recv());
}

// src/overlay/retry.rs
fn retry<V: Values>(v: &V) {
    // The caller's operation: the door's future is `Send` when it is.
    let operation = v.any::<fn() -> Ready<Result<u8>>>();
    send(with_double_spend_retry(v.any(), operation));
}
