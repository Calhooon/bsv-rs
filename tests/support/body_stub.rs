//! A raw stub for what wiremock cannot answer, shared by three
//! `transport_fault_*` files: it reads each whole request, answers `200`
//! with `Content-Length: 200` and sends twelve bytes of the body. Then it
//! either closes (the body cut after the request was written, the reviewer's
//! probe on #87) or holds the connection open and silent (the body that
//! never ends, Calhooon/bsv-rs#98; `ResponseTemplate::set_delay` delays the
//! whole answer, head included: this is the other stall, after the head).
//!
//! The stub counts the requests it read whole, so a test also holds that a
//! call made one request and no second (#98). On the cut the count is read
//! as it stands ([`BodyStub::requests`]): the stub counts before it answers,
//! and the call's error is the answer's, so the count is ahead of the call's
//! return. On the stall the call's return is its own timer's, which a slow
//! host can fire before the stub has read the request off its socket, so the
//! count is read by [`BodyStub::settled`], an answer the stub writes only
//! after every earlier connection's read has ended (the fold of #98).

use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;

/// What [`BodyStub::settled`] writes where a door writes its request: no
/// request, so the stub does not count it.
const SETTLE: &[u8] = b"SETTLE\r\n\r\n";

/// The stalled cell's attempts: a call whose request never left the client
/// inside the door's timeout (a host stalled for the whole of it) stalled on
/// no body, and is made again.
const ATTEMPTS: usize = 3;

/// The timeout a test configures at its door.
pub const DOOR_TIMEOUT: Duration = Duration::from_millis(500);

/// The margin a call must end inside: forty times the door's timeout, so a
/// loaded host does not fail a door that is bounded, and a door that is not
/// bounded fails here and does not hang the suite.
pub const BOUND: Duration = Duration::from_secs(20);

/// The stub's address and its count of requests read whole.
pub struct BodyStub {
    pub url: String,
    addr: SocketAddr,
    requests: Arc<AtomicUsize>,
}

impl BodyStub {
    /// A stub that closes after its twelve bytes of body.
    pub async fn cut() -> Self {
        Self::start(false).await
    }

    /// A stub that sends its twelve bytes of body and nothing more, the
    /// connection held open.
    pub async fn stalled() -> Self {
        Self::start(true).await
    }

    /// Bind `127.0.0.1` on a port of the kernel's choosing and serve until
    /// the test's runtime ends.
    async fn start(stall: bool) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{addr}");
        let requests = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&requests);
        // One flag a connection, in the order accepted: whether its read has
        // ended (a whole request, or the far side's close).
        let read_ended = Arc::new(watch::channel(Vec::<bool>::new()).0);
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let counted = Arc::clone(&counted);
                let read_ended = Arc::clone(&read_ended);
                let mut ordinal = 0;
                read_ended.send_modify(|ended| {
                    ordinal = ended.len();
                    ended.push(false);
                });
                tokio::spawn(async move {
                    let request = read_request(&mut stream).await;
                    let settle = request.as_deref().is_some_and(|r| r.starts_with(SETTLE));
                    if request.is_some() && !settle {
                        counted.fetch_add(1, Ordering::SeqCst);
                    }
                    read_ended.send_modify(|ended| ended[ordinal] = true);
                    if request.is_none() {
                        return;
                    }
                    if settle {
                        // The count, once every connection accepted before
                        // this one has been read to its request or its close.
                        let mut ended = read_ended.subscribe();
                        let earlier = |ended: &Vec<bool>| ended[..ordinal].iter().all(|e| *e);
                        if ended.wait_for(earlier).await.is_ok() {
                            let count = counted.load(Ordering::SeqCst).to_string();
                            let _ = stream.write_all(count.as_bytes()).await;
                        }
                        let _ = stream.shutdown().await;
                        return;
                    }
                    let head = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                                 Content-Length: 200\r\n\r\n0123456789ab";
                    if stream.write_all(head).await.is_err() || stream.flush().await.is_err() {
                        return;
                    }
                    if !stall {
                        let _ = stream.shutdown().await;
                        return;
                    }
                    // The body never ends: the connection stays open, unread
                    // and unwritten, until the far side gives up.
                    let mut rest = [0u8; 64];
                    while matches!(stream.read(&mut rest).await, Ok(n) if n > 0) {}
                });
            }
        });
        Self {
            url,
            addr,
            requests,
        }
    }

    /// The requests read whole so far: the count of a call the stub answered
    /// (the cut), which it counted before it answered.
    pub fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }

    /// The requests read whole, once the stub has read every connection made
    /// before this question to its request or to its close: no sleep, the
    /// stub's own answer. Every door that called is dropped before this is
    /// asked (a connection a live client holds idle has neither a request nor
    /// a close, and the question would end at [`BOUND`]).
    pub async fn settled(&self) -> usize {
        let asked = async {
            let mut stream = tokio::net::TcpStream::connect(self.addr).await.unwrap();
            stream.write_all(SETTLE).await.unwrap();
            let mut count = String::new();
            stream.read_to_string(&mut count).await.unwrap();
            count.parse::<usize>().unwrap()
        };
        let Ok(count) = tokio::time::timeout(BOUND, asked).await else {
            panic!("the stub's connections did not settle within {BOUND:?}");
        };
        count
    }

    /// One call against the stalled body, held by itself: `call` builds its
    /// door, asks and drops the door; its answer comes no earlier than the
    /// door's timeout and inside [`BOUND`] ([`bounded`]), and the stub read
    /// exactly one request of it, counted after the stub's reads ended. A
    /// call none of whose request reached the stub is made again.
    pub async fn stalled_once<F, Fut>(&self, what: &str, mut call: F) -> Fut::Output
    where
        F: FnMut() -> Fut,
        Fut: Future,
    {
        for _ in 0..ATTEMPTS {
            let before = self.settled().await;
            let answer = bounded(what, call()).await;
            match self.settled().await - before {
                0 => continue,
                1 => return answer,
                n => panic!("{what}: {n} requests for one call"),
            }
        }
        panic!("{what}: no request reached the stub in {ATTEMPTS} calls");
    }
}

/// One connection's request, read whole; `None` when the far side closed or
/// failed before it was whole.
async fn read_request(stream: &mut tokio::net::TcpStream) -> Option<Vec<u8>> {
    let mut request = Vec::new();
    let mut buf = [0u8; 4096];
    while !request_read(&request) {
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => request.extend_from_slice(&buf[..n]),
        }
    }
    Some(request)
}

/// Whether `request` holds its head and the body its `Content-Length` names.
fn request_read(request: &[u8]) -> bool {
    let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") else {
        return false;
    };
    let head = String::from_utf8_lossy(&request[..end]).to_ascii_lowercase();
    let length = head
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    request.len() >= end + 4 + length
}

/// `call`'s answer, which must come no earlier than the door's timeout (the
/// stall was waited out, not refused at once) and inside [`BOUND`].
pub async fn bounded<F: Future>(what: &str, call: F) -> F::Output {
    let started = Instant::now();
    let Ok(answer) = tokio::time::timeout(BOUND, call).await else {
        panic!("{what}: no answer within {BOUND:?} of a body that never ends");
    };
    let waited = started.elapsed();
    assert!(
        waited >= DOOR_TIMEOUT - Duration::from_millis(100),
        "{what}: answered after {waited:?}, before the door's timeout"
    );
    answer
}
