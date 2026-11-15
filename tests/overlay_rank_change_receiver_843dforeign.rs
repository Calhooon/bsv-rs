//! `HostReputationTracker::subscribe` hands back this crate's receiver
//! (#843dforeign, the captain's ruling of 2026-11-12 on #843's foreign types):
//! it returned a `tokio::sync::broadcast::Receiver<RankChangeEvent>` until
//! then, so a `tokio` major was this crate's break; it returns
//! `RankChangeReceiver`, read with `recv` and `try_recv`, in the shape of
//! #843d23's `AppEventReceiver`. The rank events are this crate's addition:
//! the reference's tracker has `reset`, `recordSuccess`, `recordFailure`,
//! `rankHosts`, `snapshot` and `flush` and no subscription (`ts-stack@edf6e03`
//! `overlay-tools/HostReputationTracker.ts:87,98,103,126,166,198,205`), and
//! go-sdk has no tracker. No wire byte moves.
//!
//! The lag: the tracker keeps its newest 64 events. Until #843dforeign a
//! receiver further behind got `Err(RecvError::Lagged(n))` once and then the
//! oldest event kept; now `recv` and `try_recv` read that event and `missed()`
//! counts the `n`: the same events in the same order, the lag a count.
//!
//! A tracker of each test's own (never the process-wide one); `recv` under
//! `futures::executor::block_on`, no tokio runtime; no network, no port.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(feature = "overlay")]

use bsv_rs::overlay::{HostReputationTracker, RankChangeEvent, RankChangeReceiver};
use futures::executor::block_on;

/// The tracker's kept events (`DEFAULT_BROADCAST_CHANNEL_CAPACITY`).
const KEPT: usize = 64;

fn host(n: usize) -> String {
    format!("https://host-{n}.rank.invalid")
}

/// One rank change per host: a first success moves a new host's score.
fn change(tracker: &HostReputationTracker, n: usize) {
    tracker.record_success(&host(n), 100);
}

fn hosts(events: &[RankChangeEvent]) -> Vec<String> {
    events.iter().map(|event| event.host.clone()).collect()
}

#[test]
fn n_rank_changes_are_read_in_order_843dforeign() {
    let tracker = HostReputationTracker::new();
    // The door's type, by name
    let mut rx: RankChangeReceiver = tracker.subscribe();
    assert!(rx.try_recv().is_none(), "nothing sent yet");
    for n in 0..KEPT {
        change(&tracker, n);
    }
    let mut read = Vec::new();
    for _ in 0..KEPT {
        read.push(block_on(rx.recv()).expect("an event for each change"));
    }
    assert_eq!(hosts(&read), (0..KEPT).map(host).collect::<Vec<_>>());
    for event in &read {
        assert!(
            event.old_rank > event.new_rank,
            "a success improves the rank"
        );
        assert!(event.reason.contains("success"), "{}", event.reason);
    }
    assert!(rx.try_recv().is_none(), "the queue is empty");
    assert_eq!(rx.missed(), 0, "a receiver that kept up missed nothing");

    // The queue is still open: a later change is read by `try_recv`
    change(&tracker, KEPT);
    assert_eq!(rx.try_recv().map(|event| event.host), Some(host(KEPT)));
    assert!(rx.try_recv().is_none());
}

#[test]
fn a_lagging_reader_reads_on_and_counts_what_it_missed_843dforeign() {
    for (k, by_try) in [
        (1usize, false),
        (7, false),
        (64, false),
        (200, false),
        (7, true),
    ] {
        let tracker = HostReputationTracker::new();
        let mut rx = tracker.subscribe();
        for n in 0..KEPT + k {
            change(&tracker, n);
        }
        assert_eq!(rx.missed(), 0, "nothing is counted before a read");
        let mut read = Vec::new();
        for _ in 0..KEPT {
            let event = if by_try {
                rx.try_recv()
            } else {
                block_on(rx.recv())
            };
            read.push(event.expect("the newest 64 are kept"));
        }
        // The newest 64, in order: the k oldest passed over, and counted
        assert_eq!(
            hosts(&read),
            (k..KEPT + k).map(host).collect::<Vec<_>>(),
            "k = {k}"
        );
        assert_eq!(rx.missed(), k as u64, "k = {k}");
        assert!(rx.try_recv().is_none(), "k = {k}");
        assert_eq!(rx.missed(), k as u64, "an empty read counts nothing");

        // A second lag adds to the count
        for n in 0..KEPT + 3 {
            change(&tracker, 1000 + n);
        }
        assert_eq!(
            block_on(rx.recv()).map(|event| event.host),
            Some(host(1003))
        );
        assert_eq!(rx.missed(), k as u64 + 3, "k = {k}");
    }

    // A reader exactly 64 behind missed nothing
    let tracker = HostReputationTracker::new();
    let mut rx = tracker.subscribe();
    for n in 0..KEPT {
        change(&tracker, n);
    }
    assert_eq!(rx.try_recv().map(|event| event.host), Some(host(0)));
    assert_eq!(rx.missed(), 0);
}

#[test]
fn two_receivers_each_read_every_event_843dforeign() {
    let tracker = HostReputationTracker::new();
    let mut first = tracker.subscribe();
    change(&tracker, 0);
    // A receiver reads what was sent after its own `subscribe`
    let mut second = tracker.subscribe();
    change(&tracker, 1);
    tracker.record_failure(&host(1), Some("connection refused"));

    let mut of_first = Vec::new();
    while let Some(event) = first.try_recv() {
        of_first.push(event);
    }
    let mut of_second = Vec::new();
    while let Some(event) = second.try_recv() {
        of_second.push(event);
    }
    assert_eq!(hosts(&of_first), vec![host(0), host(1), host(1)]);
    assert_eq!(hosts(&of_second), vec![host(1), host(1)]);
    let (a, b) = (&of_first[2], &of_second[1]);
    assert!(a.reason.contains("connection refused"), "{}", a.reason);
    assert_eq!(a.reason, b.reason);
    assert_eq!(a.old_rank.to_bits(), b.old_rank.to_bits());
    assert_eq!(a.new_rank.to_bits(), b.new_rank.to_bits());
    assert!(a.new_rank > a.old_rank, "a failure worsens the rank");

    // Dropping one receiver leaves the other reading
    drop(first);
    change(&tracker, 2);
    assert_eq!(
        block_on(second.recv()).map(|event| event.host),
        Some(host(2))
    );
}

#[test]
fn a_receiver_answers_none_once_the_tracker_is_dropped_843dforeign() {
    let tracker = HostReputationTracker::new();
    let mut rx = tracker.subscribe();
    change(&tracker, 0);
    change(&tracker, 1);
    drop(tracker);
    // The queued events, then the end, and the end again both ways
    assert_eq!(block_on(rx.recv()).map(|event| event.host), Some(host(0)));
    assert_eq!(rx.try_recv().map(|event| event.host), Some(host(1)));
    assert!(block_on(rx.recv()).is_none());
    assert!(block_on(rx.recv()).is_none());
    assert!(rx.try_recv().is_none());
    assert_eq!(rx.missed(), 0);

    // Dropped with nothing queued; and dropped behind a lag, which is still
    // counted on the way to the end
    let tracker = HostReputationTracker::new();
    let mut rx = tracker.subscribe();
    drop(tracker);
    assert!(rx.try_recv().is_none());
    assert!(block_on(rx.recv()).is_none());

    let tracker = HostReputationTracker::new();
    let mut rx = tracker.subscribe();
    for n in 0..KEPT + 5 {
        change(&tracker, n);
    }
    drop(tracker);
    let mut read = Vec::new();
    while let Some(event) = block_on(rx.recv()) {
        read.push(event);
    }
    assert_eq!(hosts(&read), (5..KEPT + 5).map(host).collect::<Vec<_>>());
    assert_eq!(rx.missed(), 5);
}

#[test]
fn a_waiting_recv_is_woken_by_the_next_change_843dforeign() {
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

    let tracker = HostReputationTracker::new();
    let mut rx = tracker.subscribe();
    assert!(rx.try_recv().is_none());
    let counted = Arc::new(Counted(AtomicUsize::new(0)));
    let waker = Waker::from(Arc::clone(&counted));
    let mut cx = Context::from_waker(&waker);
    let mut recv = Box::pin(rx.recv());
    assert!(recv.as_mut().poll(&mut cx).is_pending());
    assert_eq!(counted.0.load(Ordering::SeqCst), 0);
    change(&tracker, 0);
    assert!(
        counted.0.load(Ordering::SeqCst) >= 1,
        "the change woke the reader"
    );
    match recv.as_mut().poll(&mut cx) {
        Poll::Ready(Some(event)) => assert_eq!(event.host, host(0)),
        other => panic!(
            "the woken reader read {:?}",
            other.map(|e| e.map(|e| e.host))
        ),
    }
}

fn is_send<T: Send>(_: &T) {}

#[test]
fn the_receiver_and_its_recv_are_send_and_its_debug_prints_no_event_843dforeign() {
    let tracker = HostReputationTracker::new();
    let mut rx = tracker.subscribe();
    is_send(&rx);
    {
        let receiving = rx.recv();
        is_send(&receiving);
    }
    tracker.record_failure(&host(41), Some("a-reason-843dforeign"));
    for n in 0..KEPT + 2 {
        change(&tracker, n);
    }
    // Queued events, and after a counted lag: the count, no host, no reason
    let before = format!("{rx:?} {rx:#?}");
    assert!(rx.try_recv().is_some());
    let after = format!("{rx:?} {rx:#?}");
    assert_eq!(format!("{rx:?}"), "RankChangeReceiver { missed: 3, .. }");
    for text in [&before, &after] {
        for secret in ["rank.invalid", "host-", "a-reason-843dforeign", "success"] {
            assert!(!text.contains(secret), "`{text}` prints `{secret}`");
        }
    }
    // The receiver moves to another thread and reads there
    let reader = std::thread::spawn(move || block_on(rx.recv()).map(|event| event.host));
    assert_eq!(reader.join().unwrap(), Some(host(3)));
}
