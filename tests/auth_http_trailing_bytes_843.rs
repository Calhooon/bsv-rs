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

#[test]
fn an_http_request_refuses_a_trailing_byte_843() {
    let mut payload = a_request().to_payload();
    payload.push(0xAB); // one byte past the request
    assert!(
        HttpRequest::from_payload(&payload).is_err(),
        "a request payload with a trailing byte must be refused"
    );
}

#[test]
fn an_http_response_reads_an_exact_payload_843() {
    let payload = a_response().to_payload();
    let decoded = HttpResponse::from_payload(&payload).unwrap();
    assert_eq!(decoded.status, 200);
    assert_eq!(decoded.body, b"OK");
}

#[test]
fn an_http_response_refuses_a_trailing_byte_843() {
    let mut payload = a_response().to_payload();
    payload.push(0xAB); // one byte past the response
    assert!(
        HttpResponse::from_payload(&payload).is_err(),
        "a response payload with a trailing byte must be refused"
    );
}

/// An empty-body response (the `-1` body convention) is the last field; a
/// trailing byte after it is still refused.
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
    let mut longer = payload.clone();
    longer.push(0xAB);
    assert!(HttpResponse::from_payload(&longer).is_err());
}
