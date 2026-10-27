#![no_main]
//! Each call's response decoding in the HTTP JSON substrate
//! (`HttpWalletJson`): the status, the busy word, the error body, the
//! `Retry-After` reading and the JSON result, on arbitrary bytes. The answer
//! comes from a loopback listener in this process (hermetic: no route leaves
//! the host), so the substrate's whole decoding runs as it runs against a
//! wallet, through `reqwest`.
//!
//! The input: byte 0 picks the call (the 26 the wire also carries, then the
//! two key-linkage reveals), byte 1 the status, byte 2's low bit a
//! `Retry-After` header whose value is the body's bytes up to the leading
//! newline; the rest is the body. The assertion is that each call returns.
use bsv_rs::wallet::substrates::HttpWalletJson;
use libfuzzer_sys::fuzz_target;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::Duration;

mod support;

const STATUSES: [u16; 12] = [200, 200, 201, 204, 400, 401, 404, 429, 500, 502, 503, 504];

/// The response the listener writes next, whole (status line to body).
static ANSWER: Mutex<Vec<u8>> = Mutex::new(Vec::new());

struct Harness {
    runtime: tokio::runtime::Runtime,
    wallet: HttpWalletJson,
}

fn serve(stream: TcpStream) {
    let mut reader = BufReader::new(stream.try_clone().expect("a clone of the stream"));
    let mut writer = stream;
    loop {
        let mut length = 0usize;
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
            if line == "\r\n" {
                break;
            }
            let lower = line.to_ascii_lowercase();
            if let Some(value) = lower.strip_prefix("content-length:") {
                length = value.trim().parse().unwrap_or(0);
            }
        }
        let mut body = vec![0u8; length];
        if reader.read_exact(&mut body).is_err() {
            return;
        }
        let answer = ANSWER.lock().expect("the answer's lock").clone();
        if writer.write_all(&answer).is_err() {
            return;
        }
    }
}

fn harness() -> &'static Harness {
    static HARNESS: OnceLock<Harness> = OnceLock::new();
    HARNESS.get_or_init(|| {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        let port = listener.local_addr().expect("the port").port();
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                thread::spawn(move || serve(stream));
            }
        });
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("a client");
        let wallet =
            HttpWalletJson::with_client(client, None, Some(format!("http://127.0.0.1:{port}")));
        Harness { runtime, wallet }
    })
}

/// A header value the framing carries: visible ASCII and spaces only.
fn header_value(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| {
            if (0x20..0x7f).contains(&b) {
                b as char
            } else {
                '?'
            }
        })
        .collect()
}

fuzz_target!(|data: &[u8]| {
    let [call, status, flags, rest @ ..] = data else {
        return;
    };
    let status = STATUSES[*status as usize % STATUSES.len()];
    let (retry_after, body) = if flags & 1 == 1 {
        match rest.iter().position(|&b| b == b'\n') {
            Some(at) => (Some(header_value(&rest[..at])), &rest[at + 1..]),
            None => (Some(header_value(rest)), &[][..]),
        }
    } else {
        (None, rest)
    };

    let mut answer = format!(
        "HTTP/1.1 {status} Fuzz\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
        body.len()
    )
    .into_bytes();
    if let Some(value) = retry_after {
        answer.extend_from_slice(format!("Retry-After: {value}\r\n").as_bytes());
    }
    answer.extend_from_slice(b"\r\n");
    answer.extend_from_slice(body);
    *ANSWER.lock().expect("the answer's lock") = answer;

    let harness = harness();
    let wallet = &harness.wallet;
    harness.runtime.block_on(async {
        match call % (support::SHARED_CALLS + 2) {
            26 => drop(
                wallet
                    .reveal_counterparty_key_linkage(
                        support::reveal_counterparty(),
                        Some("fuzz.example"),
                    )
                    .await,
            ),
            27 => drop(
                wallet
                    .reveal_specific_key_linkage(support::reveal_specific(), Some("fuzz.example"))
                    .await,
            ),
            index => support::call_shared!(wallet, index, Some("fuzz.example")),
        }
    });
});
