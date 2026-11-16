//! Regression (bsv-rs #843): the auth HTTP transport's wire readers must
//! consume the whole payload or refuse. A request/response followed by a
//! trailing byte was silently read as the prefix and the extra bytes ignored;
//! it is now refused, as the reference SDK refuses the same
//! (`SimplifiedFetchTransport.ts` / `AuthFetch.ts StrictResponseReader`).
//!
//! Each `..._refuses_a_trailing_byte_843` is RED on the pre-fix door (the extra
//! byte was accepted) and GREEN after; the `..._reads_an_exact_payload_843`
//! guards that an honest, exact payload still decodes (refused 0).
#![cfg(feature = "auth")]
#![allow(clippy::unwrap_used)]

use bsv_rs::auth::transports::{HttpRequest, HttpResponse};

fn a_request() -> HttpRequest {
    HttpRequest {
        request_id: [7u8; 32],
        method: "POST".to_string(),
        path: "/api/v1/users".to_string(),
        search: "?q=1".to_string(),
        headers: vec![("content-type".to_string(), "application/json".to_string())],
        body: b"{\"name\":\"Alice\"}".to_vec(),
    }
}

fn a_response() -> HttpResponse {
    HttpResponse {
        request_id: [9u8; 32],
        status: 200,
        headers: vec![("x-bsv-data".to_string(), "abc".to_string())],
        body: b"OK".to_vec(),
    }
}

#[test]
fn an_http_request_reads_an_exact_payload_843() {
    let payload = a_request().to_payload();
    let decoded = HttpRequest::from_payload(&payload).unwrap();
    assert_eq!(decoded.method, "POST");
    assert_eq!(decoded.url_postfix(), "/api/v1/users?q=1");
    assert_eq!(decoded.body, b"{\"name\":\"Alice\"}");
}

/// Drives both one trailing byte AND many: a refusal that fires only for a
/// single extra byte (a `len - cursor == 1` weakening) is caught by the many
/// case (bsv-rs #843 fold).
#[test]
fn an_http_request_refuses_a_trailing_byte_843() {
    let base = a_request().to_payload();
    for n in [1usize, 2, 17, 64] {
        let mut payload = base.clone();
        payload.resize(payload.len() + n, 0xAB);
        assert!(
            HttpRequest::from_payload(&payload).is_err(),
            "a request payload with {n} trailing byte(s) must be refused"
        );
    }
}

#[test]
fn an_http_response_reads_an_exact_payload_843() {
    let payload = a_response().to_payload();
    let decoded = HttpResponse::from_payload(&payload).unwrap();
    assert_eq!(decoded.status, 200);
    assert_eq!(decoded.body, b"OK");
}

/// Drives both one trailing byte AND many (bsv-rs #843 fold).
#[test]
fn an_http_response_refuses_a_trailing_byte_843() {
    let base = a_response().to_payload();
    for n in [1usize, 2, 17, 64] {
        let mut payload = base.clone();
        payload.resize(payload.len() + n, 0xAB);
        assert!(
            HttpResponse::from_payload(&payload).is_err(),
            "a response payload with {n} trailing byte(s) must be refused"
        );
    }
}

/// An empty-body response (the `-1` body convention) is the last field; a
/// trailing byte after it is still refused — one AND many.
#[test]
fn an_http_response_with_empty_body_refuses_a_trailing_byte_843() {
    let empty = HttpResponse {
        request_id: [0u8; 32],
        status: 204,
        headers: vec![],
        body: vec![],
    };
    let payload = empty.to_payload();
    assert!(HttpResponse::from_payload(&payload).is_ok());
    for n in [1usize, 2, 17, 64] {
        let mut longer = payload.clone();
        longer.resize(longer.len() + n, 0xAB);
        assert!(
            HttpResponse::from_payload(&longer).is_err(),
            "empty-body response + {n} trailing byte(s) must be refused"
        );
    }
}

/// The inner length-prefixed body must itself consume the bytes it claims: a
/// body-length prefix that over-claims (claims more bytes than remain) once let
/// the lenient short-body branch swallow a suffix and slip the trailing-bytes
/// check. The response reader now refuses it, as the request reader and the
/// reference's `StrictResponseReader` (`readExact`) do (bsv-rs #843 fold). The
/// payload is built by this crate's own `to_payload`, then its single-byte
/// body-length prefix is raised; a trailing suffix is appended so the attack
/// is exactly "an over-claim swallowing a suffix". RED on the pre-fold lenient
/// reader (it returned `Ok` with an empty body), GREEN after.
#[test]
fn an_http_response_refuses_an_over_claimed_body_843() {
    // body "OK" (2 bytes) => a single-byte body-length prefix at index len-3.
    let payload = a_response().to_payload();
    let n = payload.len();
    let body_len_idx = n - 3;
    assert_eq!(
        payload[body_len_idx], 2,
        "fixture assumption: body is 2 bytes with a single-byte length prefix"
    );
    // Control: the exact payload still decodes.
    assert!(HttpResponse::from_payload(&payload).is_ok());

    // Over-claim the body length and append a short suffix: the exact shape the
    // lenient branch used to swallow. 200 is still a single-byte var-int (< 0xFD).
    let mut over = payload.clone();
    over[body_len_idx] = 200; // claim 200 body bytes; only a handful remain
    over.resize(over.len() + 5, 0xCD); // the suffix an over-claim would swallow
    assert!(
        HttpResponse::from_payload(&over).is_err(),
        "an over-claimed body-length prefix must be refused, not swallow the suffix"
    );

    // Over-claim with NO suffix at all (the body is simply shorter than claimed):
    // still refused (the reference's StrictResponseReader throws truncated).
    let mut short = payload.clone();
    short[body_len_idx] = 9; // claim 9, only 2 present
    assert!(
        HttpResponse::from_payload(&short).is_err(),
        "a body shorter than its length prefix must be refused"
    );
}
