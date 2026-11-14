//! The servers and the scripted facilitator of the #775 and #785 tests
//! (`tests/lookup_limits_775.rs`, `tests/lookup_limits_configured_775.rs`).
//! Every listener binds `127.0.0.1:0`, an ephemeral port; no default URL or
//! port is asked.
#![allow(dead_code)]

use bsv_rs::overlay::{
    get_overlay_host_reputation_tracker, LookupAnswer, LookupQuestion, OutputListItem,
    OverlayLookupFacilitator,
};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// The URLs asked, in order.
pub type Asked = Arc<Mutex<Vec<String>>>;

/// A facilitator answering by URL from its script and recording each URL; a
/// URL outside the script is refused in words of its own. It overrides
/// `lookup` alone, so the resolver's own check is what bounds its answers.
pub struct Scripted {
    pub asked: Asked,
    pub script: HashMap<String, bsv_rs::Result<LookupAnswer>>,
}

impl Scripted {
    pub fn new(script: Vec<(&str, bsv_rs::Result<LookupAnswer>)>) -> (Arc<Self>, Asked) {
        let asked = Asked::default();
        let scripted = Arc::new(Self {
            asked: asked.clone(),
            script: script
                .into_iter()
                .map(|(url, answer)| (url.to_string(), answer))
                .collect(),
        });
        (scripted, asked)
    }
}

#[async_trait::async_trait(?Send)]
impl OverlayLookupFacilitator for Scripted {
    async fn lookup(
        &self,
        url: &str,
        _question: &LookupQuestion,
        _timeout_ms: Option<u64>,
    ) -> bsv_rs::Result<LookupAnswer> {
        self.asked.lock().unwrap().push(url.to_string());
        self.script
            .get(url)
            .cloned()
            .unwrap_or_else(|| Err(bsv_rs::Error::OverlayError(format!("unscripted: {url}"))))
    }
}

/// An output list of `count` outputs, each a BEEF of `beef_bytes` bytes (no
/// BEEF: the bounds are judged before any is parsed).
pub fn output_list(count: usize, beef_bytes: usize) -> LookupAnswer {
    LookupAnswer::OutputList {
        outputs: (0..count)
            .map(|index| OutputListItem {
                beef: vec![7; beef_bytes],
                output_index: index as u32,
                context: None,
                txid: None,
            })
            .collect(),
    }
}

/// The host's recorded `(failures, successes)`, `None` when the tracker has
/// never recorded anything for it.
pub fn record(host: &str) -> Option<(u64, u64)> {
    get_overlay_host_reputation_tracker()
        .snapshot(host)
        .map(|entry| (entry.total_failures, entry.total_successes))
}

/// A BEEF for the binary answers, built by this crate's writer: one
/// transaction (an `OP_TRUE` output) proven by a block of its own, its txid
/// and the length of its Atomic BEEF, the bytes `atomic_outputs` hands each
/// outpoint naming it (`LookupResolver.ts:905-936`, #735's fold).
pub struct BinaryBeef {
    pub bytes: Vec<u8>,
    pub txid: String,
    pub atomic_len: usize,
}

/// [`BinaryBeef`], built once per call.
pub fn binary_beef() -> BinaryBeef {
    binary_beef_spending(&"11".repeat(32))
}

/// [`BinaryBeef`] of a transaction spending `source:0`: another source,
/// another transaction, so two hosts' answers are not one output to the
/// resolver's dedup.
pub fn binary_beef_spending(source: &str) -> BinaryBeef {
    use bsv_rs::script::{LockingScript, UnlockingScript};
    use bsv_rs::transaction::{
        Beef, MerklePath, MerklePathLeaf, Transaction, TransactionInput, TransactionOutput,
    };
    let mut input = TransactionInput::new(source.parse().unwrap(), 0);
    input.set_unlocking_script(UnlockingScript::from_hex("").unwrap());
    let mut tx = Transaction::new();
    tx.add_input(input).unwrap();
    tx.add_output(TransactionOutput::new(
        1,
        LockingScript::from_hex("51").unwrap(),
    ))
    .unwrap();
    let txid = tx.id();
    let path = MerklePath::new(900, vec![vec![MerklePathLeaf::new_txid(0, txid.clone())]]).unwrap();
    let mut beef = Beef::new();
    let index = beef.merge_bump(path);
    beef.merge_raw_tx(tx.to_binary(), Some(index))
        .expect("the bytes are one transaction");
    let atomic_len = beef.to_binary_atomic(&txid).unwrap().len();
    BinaryBeef {
        bytes: beef.to_binary().expect("the BEEF is writable"),
        txid,
        atomic_len,
    }
}

/// One outpoint of a binary lookup body (`LookupResolver.ts:885-893`): the
/// 32 bytes whose hex is `txid`, the index and the context length as
/// varints, then the context.
pub fn binary_outpoint(
    body: &mut bsv_rs::primitives::Writer,
    txid: &str,
    index: u64,
    context: &[u8],
) {
    body.write_bytes(&bsv_rs::primitives::from_hex(txid).unwrap());
    body.write_var_int(index);
    body.write_var_int(context.len() as u64);
    body.write_bytes(context);
}

/// The binary lookup body: a varint count, `count` outpoints of `beef`'s
/// transaction (the index the outpoint's position, no context), then the
/// BEEF.
pub fn binary_body(count: usize, beef: &BinaryBeef) -> Vec<u8> {
    let mut body = bsv_rs::primitives::Writer::new();
    body.write_var_int(count as u64);
    for index in 0..count {
        binary_outpoint(&mut body, &beef.txid, index as u64, &[]);
    }
    body.write_bytes(&beef.bytes);
    body.into_bytes()
}

/// An HTTP server on an ephemeral port, a thread per connection, that reads
/// each request, writes `head` and then each of `pieces` (flushing between
/// them), and holds the connection until the client closes it or two
/// seconds pass. The answer is the bytes given and nothing else: a
/// `Content-Length` the body never honours, or chunks without end. (Not
/// `wiremock`: its server's drop waits on the test's own current-thread
/// runtime after a large answer.) Returns the host's base URL and the count
/// of pieces the clients let it write.
pub fn raw_host(head: String, pieces: Vec<Vec<u8>>) -> (String, Arc<Mutex<usize>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let written = Arc::new(Mutex::new(0usize));
    let count = written.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else {
                return;
            };
            let (head, pieces, count) = (head.clone(), pieces.clone(), count.clone());
            std::thread::spawn(move || serve(stream, &head, pieces, &count));
        }
    });
    (format!("http://127.0.0.1:{port}"), written)
}

/// A host answering every request with `body` whole, its length declared.
pub fn host_answering(content_type: &str, body: Vec<u8>) -> String {
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    raw_host(head, vec![body]).0
}

fn serve(mut stream: TcpStream, head: &str, pieces: Vec<Vec<u8>>, count: &Mutex<usize>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    // The request: its head, then the body its Content-Length declares.
    let mut request = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        let Ok(read) = stream.read(&mut buffer) else {
            return;
        };
        if read == 0 {
            return;
        }
        request.extend_from_slice(&buffer[..read]);
        let text = String::from_utf8_lossy(&request).to_ascii_lowercase();
        if let Some(end) = text.find("\r\n\r\n") {
            let length = text
                .split("content-length:")
                .nth(1)
                .and_then(|rest| rest.lines().next())
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if request.len() >= end + 4 + length {
                break;
            }
        }
    }
    if stream.write_all(head.as_bytes()).is_err() {
        return;
    }
    let paced = pieces.len() > 1;
    for piece in pieces {
        if stream
            .write_all(&piece)
            .and_then(|()| stream.flush())
            .is_err()
        {
            return;
        }
        *count.lock().unwrap() += 1;
        if paced {
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    // Hold the connection: the client's refusal is its own, not an EOF.
    let _ = stream.read(&mut buffer);
}
