//! #603: `HttpWalletJson`'s response bound (`src/wallet/substrates/result_values/boundary.rs`'s
//! `response_bytes`) at the reference's edges, against
//! `tests/vectors/http_json_boundary_603.json` (`ts-stack@edf6e03` under Node
//! v22.18.0, `tests/support/http_json_boundary_603.mjs`, the reference's
//! `HTTPWalletJSON` on an injected fetch). The reference's reader
//! (`packages/sdk/src/wallet/substrates/HTTPWalletJSON.ts`):
//!
//! ```text
//! :59  const MAX_WALLET_JSON_RESPONSE_BYTES = 256 * 1024 * 1024
//! :65  if (!/^\d+$/.test(declaredLength)) {
//! :66    throw new Error('HTTPWalletJSON response has an invalid Content-Length')
//! :69  if (!Number.isSafeInteger(length) || length > MAX_WALLET_JSON_RESPONSE_BYTES) {
//! :70    throw new Error('HTTPWalletJSON response exceeds the maximum permitted size')
//! :83  totalLength += value.byteLength
//! :84  if (totalLength > MAX_WALLET_JSON_RESPONSE_BYTES) {
//! :86    throw new Error('HTTPWalletJSON response exceeds the maximum permitted size')
//! ```
//!
//! Each answer is written by hand on a `127.0.0.1:0` listener of the test's own
//! (wiremock writes its own `Content-Length`); no default URL or port. A large
//! body is the vector's recipe (`prefix`, then `padByte` to `length`), sent
//! from one reused 1 MiB buffer.
//!
//! Run with: `cargo test --features "wallet,http" --test wallet_http_json_boundary_603`
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(all(feature = "wallet", feature = "http"))]

use bsv_rs::wallet::substrates::HttpWalletJson;
use bsv_rs::Error;
use serde_json::Value;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const VECTOR: &str = include_str!("vectors/http_json_boundary_603.json");

/// The recorded case `name` and the reference's answer: `Ok(height)` or the
/// error words.
fn recorded(name: &str) -> (Value, Result<u64, String>) {
    let vector: Value = serde_json::from_str(VECTOR).unwrap();
    assert_eq!(vector["source"], "ts-stack@edf6e03");
    let case = vector["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("no recorded case {name}"))
        .clone();
    let reference = &case["reference"];
    let answer = match reference["error"].as_str() {
        Some(words) => Err(words.to_owned()),
        None => {
            assert_eq!(reference["accepted"], true, "{name}");
            Ok(reference["height"].as_u64().unwrap())
        }
    };
    (case, answer)
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

/// A listener answering one request with the recipe's body: declared with its
/// `declared` Content-Length text, or chunked when it has none.
async fn serve(body: &Value) -> String {
    let prefix = body["prefix"].as_str().unwrap().as_bytes().to_vec();
    let pad = u8::try_from(body["padByte"].as_u64().unwrap()).unwrap();
    let length = usize::try_from(body["length"].as_u64().unwrap()).unwrap();
    let chunk = usize::try_from(body["chunkBytes"].as_u64().unwrap()).unwrap();
    let declared = body["declared"].as_str().map(str::to_owned);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buf = [0u8; 4096];
        while !request_read(&request) {
            let n = stream.read(&mut buf).await.unwrap();
            if n == 0 {
                return;
            }
            request.extend_from_slice(&buf[..n]);
        }
        let mut head = String::from("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n");
        match &declared {
            Some(text) => head.push_str(&format!("Content-Length: {text}\r\n")),
            None => head.push_str("Transfer-Encoding: chunked\r\n"),
        }
        head.push_str("Connection: close\r\n\r\n");
        if stream.write_all(head.as_bytes()).await.is_err() {
            return;
        }
        let mut padding = vec![pad; chunk];
        padding[..prefix.len()].copy_from_slice(&prefix);
        let mut sent = 0;
        while sent < length {
            let size = chunk.min(length - sent);
            let piece = &padding[..size];
            let written = if declared.is_some() {
                stream.write_all(piece).await
            } else {
                let mut frame = format!("{size:x}\r\n").into_bytes();
                frame.extend_from_slice(piece);
                frame.extend_from_slice(b"\r\n");
                stream.write_all(&frame).await
            };
            // The client refusing mid-body closes the connection: done.
            if written.is_err() {
                return;
            }
            if sent == 0 {
                padding[..prefix.len()].fill(pad);
            }
            sent += size;
        }
        if declared.is_none() {
            let _ = stream.write_all(b"0\r\n\r\n").await;
        }
        let _ = stream.shutdown().await;
    });
    format!("http://{addr}")
}

/// `getHeight` against the recorded case's answer, with its time logged.
async fn assert_recorded(name: &str) {
    let (case, reference) = recorded(name);
    let started = Instant::now();
    let url = serve(&case["body"]).await;
    let wallet = HttpWalletJson::new(Some("fixtures.invalid".into()), Some(url)).unwrap();
    let answer = wallet.get_height(None).await.map_err(|e| match e {
        Error::WalletError(words) => words,
        other => panic!("{name}: not a WalletError: {other:?}"),
    });
    eprintln!("{name}: {:?}, {} ms", answer, started.elapsed().as_millis());
    assert_eq!(answer, reference, "{name}");
}

/// `HTTPWalletJSON.ts:65-66`: a Content-Length that is not `^\d+$` is refused
/// as invalid; hyper's HTTP/1 reader passes a list of equal values (`12, 12`)
/// through to the headers, so the grammar, not the size, refuses it
/// (`boundary.rs:137:39`).
#[tokio::test]
async fn a_content_length_list_is_refused_as_invalid_603() {
    assert_eq!(
        recorded("content_length_list").1,
        Err("HTTPWalletJSON response has an invalid Content-Length".into())
    );
    assert_recorded("content_length_list").await;
}

/// `HTTPWalletJSON.ts:69` and `:84`: a body of exactly 268,435,456 bytes is
/// read, declared (`boundary.rs:141:53`, `151:24`) and chunked (`151:24`).
#[tokio::test]
async fn a_body_of_exactly_the_cap_is_read_603() {
    assert_eq!(recorded("exact_cap_declared").1, Ok(1));
    assert_recorded("exact_cap_declared").await;
}

/// The chunked twin of the exact-cap body (no Content-Length).
#[tokio::test]
async fn a_chunked_body_of_exactly_the_cap_is_read_603() {
    assert_eq!(recorded("exact_cap_chunked").1, Ok(1));
    assert_recorded("exact_cap_chunked").await;
}

/// `HTTPWalletJSON.ts:83-86`: one byte past the cap, chunked, is refused in
/// `HTTPWalletJSON response exceeds the maximum permitted size`
/// (`boundary.rs:151:24`, `151:36`).
#[tokio::test]
async fn a_chunked_body_one_past_the_cap_is_refused_603() {
    assert_eq!(
        recorded("one_past_cap_chunked").1,
        Err("HTTPWalletJSON response exceeds the maximum permitted size".into())
    );
    assert_recorded("one_past_cap_chunked").await;
}
