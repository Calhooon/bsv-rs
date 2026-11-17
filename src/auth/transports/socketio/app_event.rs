//! The queue `install_app_event_listener` hands back (#843d23).

use crate::primitives::PublicKey;
use serde_json::Value;

/// One application-level event decoded from a post-BRC-103-handshake
/// [`MessageType::General`](crate::auth::MessageType::General) payload.
///
/// The payload shape is the canonical `{eventName, data}` JSON envelope
/// used by `@bsv/authsocket-client`'s `encodeEventPayload`, byte-identical
/// between the TS canonical and this Rust client.
///
/// A record this crate produces, so it is `#[non_exhaustive]` (#843): read
/// the fields, end a pattern over it in `..`, and build one (a test's) with
/// [`AppEvent::new`].
///
/// ```compile_fail,E0639
/// fn rebuilt(value: bsv_rs::auth::AppEvent) -> bsv_rs::auth::AppEvent {
///     bsv_rs::auth::AppEvent { ..value }
/// }
/// ```
///
/// ```
/// fn kept(value: bsv_rs::auth::AppEvent) -> bsv_rs::auth::AppEvent {
///     value
/// }
/// ```
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct AppEvent {
    /// The signing identity from the inbound General's `identity_key`
    /// field, typically the server's identity key, but typed as
    /// [`PublicKey`] so the same shape generalizes to peer-to-peer events.
    pub sender: PublicKey,
    /// The `eventName` field from the payload JSON. Empty string when the
    /// payload was missing the field (still surfaced so callers can
    /// observe malformed traffic instead of silently dropping it).
    pub event_name: String,
    /// The `data` field from the payload JSON. Type varies by event;
    /// left as [`Value`] so callers parse the per-event shape themselves.
    pub data: Value,
}

crate::util::non_exhaustive::assert_no_drop!(AppEvent, bsv_rs::auth::AppEvent);

impl AppEvent {
    /// The event `event_name` carrying `data`, signed by `sender`.
    #[must_use]
    pub fn new(sender: PublicKey, event_name: impl Into<String>, data: Value) -> Self {
        Self {
            sender,
            event_name: event_name.into(),
            data,
        }
    }
}

/// The queue [`install_app_event_listener`](super::install_app_event_listener) hands back: this crate's type
/// (#843d23), so no public signature names another crate's channel and a
/// `futures` major is never this crate's break.
///
/// Events arrive in the order the listener received them. [`recv`] waits for
/// the next; it answers `None` once the listener is gone (the [`Peer`] and its
/// callbacks dropped, or the callback removed with
/// `Peer::stop_listening_for_general_messages`) and the queue is empty.
/// [`try_recv`] answers at once. `Debug` prints no event.
///
/// [`recv`]: AppEventReceiver::recv
/// [`try_recv`]: AppEventReceiver::try_recv
/// [`Peer`]: crate::auth::Peer
pub struct AppEventReceiver {
    /// `None` once the channel has answered its end: it is not polled again.
    inner: Option<futures::channel::mpsc::UnboundedReceiver<AppEvent>>,
}

impl AppEventReceiver {
    pub(super) fn new(inner: futures::channel::mpsc::UnboundedReceiver<AppEvent>) -> Self {
        Self { inner: Some(inner) }
    }

    /// The next event, waiting for it; `None` once the listener is gone and
    /// every queued event has been taken, and `None` again on every call
    /// after that.
    pub async fn recv(&mut self) -> Option<AppEvent> {
        let event = futures::StreamExt::next(self.inner.as_mut()?).await;
        self.ended_unless(event)
    }

    /// The next queued event without waiting; `None` when the queue is empty
    /// now (the listener may still send more) or the listener is gone.
    pub fn try_recv(&mut self) -> Option<AppEvent> {
        // One poll of the stream's `next`, which every `futures` 0.3 has: the
        // channel's own `try_recv` exists from futures-channel 0.3.32 alone,
        // and the manifest asks `futures = "0.3"` (#843d23's fold). An item
        // ready is `Some(Some(_))`, a closed queue `Some(None)`, an empty open
        // one `None`: the two fold into `None`, as `try_recv().ok()` folded
        // them. The poll leaves a no-op waker in the channel, which the next
        // `recv` replaces with its own before it reads the queue again.
        let polled =
            futures::FutureExt::now_or_never(futures::StreamExt::next(self.inner.as_mut()?))?;
        self.ended_unless(polled)
    }

    /// Drops the channel when it has answered its end, so no call polls it
    /// after that: futures-channel 0.3.11 to 0.3.13 panic on such a poll
    /// (`Receiver::next_message called after None`), later ones answer `None`.
    fn ended_unless(&mut self, event: Option<AppEvent>) -> Option<AppEvent> {
        if event.is_none() {
            self.inner = None;
        }
        event
    }
}

impl std::fmt::Debug for AppEventReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppEventReceiver").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::{AppEvent, AppEventReceiver};
    use crate::primitives::PrivateKey;
    use futures::channel::mpsc::{unbounded, UnboundedSender};
    use serde_json::json;

    fn event(name: &str) -> AppEvent {
        let mut scalar = [0u8; 32];
        scalar[31] = 7;
        AppEvent {
            sender: PrivateKey::from_bytes(&scalar)
                .expect("the scalar 7 is a private key")
                .public_key(),
            event_name: name.to_string(),
            data: json!({ "n": name }),
        }
    }

    fn queue() -> (UnboundedSender<AppEvent>, AppEventReceiver) {
        let (tx, rx) = unbounded::<AppEvent>();
        (tx, AppEventReceiver::new(rx))
    }

    #[test]
    fn try_recv_answers_an_item_that_is_ready_in_the_order_sent_843d23() {
        let (tx, mut rx) = queue();
        tx.unbounded_send(event("a")).expect("the queue is open");
        tx.unbounded_send(event("b")).expect("the queue is open");
        assert_eq!(rx.try_recv(), Some(event("a")));
        assert_eq!(rx.try_recv(), Some(event("b")));
        assert_eq!(rx.try_recv(), None);
    }

    #[test]
    fn try_recv_answers_none_on_an_empty_open_queue_and_the_queue_stays_open_843d23() {
        let (tx, mut rx) = queue();
        assert_eq!(rx.try_recv(), None);
        assert_eq!(rx.try_recv(), None);
        // The queue was not closed by the empty answers: a later event is
        // read, by `try_recv` and by `recv`.
        tx.unbounded_send(event("late")).expect("still open");
        assert_eq!(rx.try_recv(), Some(event("late")));
        tx.unbounded_send(event("later")).expect("still open");
        assert_eq!(futures::executor::block_on(rx.recv()), Some(event("later")));
    }

    #[test]
    fn try_recv_answers_none_on_a_closed_queue_after_its_queued_items_843d23() {
        let (tx, mut rx) = queue();
        tx.unbounded_send(event("last")).expect("the queue is open");
        drop(tx);
        // Closed with an item queued: the item, then `None`, and `None` again.
        assert_eq!(rx.try_recv(), Some(event("last")));
        assert_eq!(rx.try_recv(), None);
        assert_eq!(rx.try_recv(), None);
        assert_eq!(futures::executor::block_on(rx.recv()), None);
        assert_eq!(futures::executor::block_on(rx.recv()), None);
        assert_eq!(rx.try_recv(), None);

        // The end read by `recv`, then asked again both ways.
        let (tx, mut rx) = queue();
        drop(tx);
        assert_eq!(futures::executor::block_on(rx.recv()), None);
        assert_eq!(rx.try_recv(), None);
        assert_eq!(futures::executor::block_on(rx.recv()), None);
    }

    #[test]
    fn a_recv_after_an_empty_try_recv_is_woken_by_the_next_event_843d23() {
        use std::future::Future;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::task::{Context, Poll, Wake, Waker};

        struct Counted(AtomicUsize);
        impl Wake for Counted {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        // `try_recv` polls with a no-op waker; the `recv` after it must
        // register its own, or the next event would wake nobody.
        let (tx, mut rx) = queue();
        assert_eq!(rx.try_recv(), None);
        let counted = Arc::new(Counted(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&counted));
        let mut cx = Context::from_waker(&waker);
        let mut recv = Box::pin(rx.recv());
        assert_eq!(recv.as_mut().poll(&mut cx), Poll::Pending);
        assert_eq!(counted.0.load(Ordering::SeqCst), 0);
        tx.unbounded_send(event("woken"))
            .expect("the queue is open");
        assert_eq!(counted.0.load(Ordering::SeqCst), 1);
        assert_eq!(
            recv.as_mut().poll(&mut cx),
            Poll::Ready(Some(event("woken")))
        );
    }
}
