//! The auth readers refuse a length the bytes remaining cannot hold, with no
//! sum that can wrap (Calhooon/bsv-rs#108, found by `fuzz_auth_messages`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(feature = "auth")]

use bsv_rs::auth::certificates::Certificate;
use bsv_rs::auth::transports::{HttpRequest, HttpResponse};
use bsv_rs::primitives::{from_base64, PrivateKey};
use bsv_rs::Error;

/// The 189-byte crash input of #108, as the issue gives it: a field length
/// near `usize::MAX` wrapped `pos + n` past `read_bytes`'s check.
const ISSUE_108_INPUT: &str = "ezQ0NDQ0NDQ0NDQ0NDQ0NDQidmZiZTHEMzciXSwGAABhdHVyZSI6SzQ4LDYseyJ2ZQICMiwDAAEAAAAAAAIyAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIsAgICAgICOGZhNmM4M2M1MzdlOWE0NGMzYzVi////////////////////////////////////////////////////////////////////////////////////";

/// A certificate with no fields and no signature, by this crate's writer;
/// its last byte is the field count.
fn certificate_head() -> Vec<u8> {
    let subject = PrivateKey::from_bytes(&[1u8; 32]).unwrap().public_key();
    let certifier = PrivateKey::from_bytes(&[2u8; 32]).unwrap().public_key();
    let bytes = Certificate::new([3u8; 32], [4u8; 32], subject, certifier).to_binary(false);
    assert_eq!(bytes.last(), Some(&0), "the field count closes the head");
    bytes
}

#[test]
fn a_certificate_length_that_wraps_the_bounds_check_is_refused() {
    let data = from_base64(ISSUE_108_INPUT).unwrap();
    assert_eq!(data.len(), 189);
    let result = std::panic::catch_unwind(|| Certificate::from_binary(&data));
    let result = result.expect("Certificate::from_binary panicked on the #108 input");
    // Two typed refusals meet on these bytes: the revocation outpoint's index
    // varint reads above u32::MAX, refused first since #120 landed (#121,
    // `CertificateValidationError`), and behind it the field length that
    // wrapped the bounds check (#108, `ReaderUnderflow`). Either is the
    // finding's pin: a refusal, never a panic. The constructed inputs below
    // carry a valid index and pin the length check alone.
    assert!(
        matches!(
            result,
            Err(Error::ReaderUnderflow { .. }) | Err(Error::CertificateValidationError(_))
        ),
        "{result:?}"
    );
}

#[test]
fn a_certificate_field_length_of_usize_max_minus_k_is_refused() {
    for k in [0u64, 1, 7, 64] {
        let mut data = certificate_head();
        data.pop();
        data.push(1); // one field
        data.push(0xff); // its name length: an 8-byte varint
        data.extend_from_slice(&(usize::MAX as u64 - k).to_le_bytes());
        data.extend_from_slice(b"name");
        let result = std::panic::catch_unwind(|| Certificate::from_binary(&data));
        let result = result.unwrap_or_else(|_| panic!("panicked at usize::MAX - {k}"));
        assert!(
            matches!(result, Err(Error::ReaderUnderflow { .. })),
            "usize::MAX - {k}: {result:?}"
        );
    }
}

#[test]
fn a_certificate_value_length_of_usize_max_is_refused() {
    let mut data = certificate_head();
    data.pop();
    data.extend_from_slice(&[1, 1, b'a', 0xff]); // one field "a", then its value length
    data.extend_from_slice(&u64::MAX.to_le_bytes());
    let result = std::panic::catch_unwind(|| Certificate::from_binary(&data)).unwrap();
    assert!(
        matches!(result, Err(Error::ReaderUnderflow { .. })),
        "{result:?}"
    );
}

/// A request payload up to the method length, which the caller appends.
fn request_head() -> Vec<u8> {
    vec![0u8; 32]
}

/// The lengths a 32-bit target (wasm32) wrapped or truncated: near `u32::MAX`
/// (`cursor + len` wrapped), and past it (`as usize` truncated it to `5`).
fn wrapping_lengths() -> Vec<Vec<u8>> {
    let mut near = vec![0xfe];
    near.extend_from_slice(&(u32::MAX - 8).to_le_bytes());
    let mut past = vec![0xff];
    past.extend_from_slice(&((1u64 << 32) + 5).to_le_bytes());
    vec![near, past]
}

#[test]
fn an_http_request_length_that_wraps_a_32_bit_bounds_check_is_refused() {
    // The method, the path, the search and the body, each in turn.
    for position in 0..4 {
        for len in wrapping_lengths() {
            let mut payload = request_head();
            payload.resize(payload.len() + position.min(3), 0); // empty method, path, search
            if position == 3 {
                payload.push(0); // no headers
            }
            payload.extend_from_slice(&len);
            payload.extend_from_slice(b"GET /path ?q=1 body");
            let result = std::panic::catch_unwind(|| HttpRequest::from_payload(&payload))
                .unwrap_or_else(|_| panic!("panicked at position {position}"));
            assert!(
                matches!(result, Err(Error::AuthError(ref m)) if m.contains("too short")),
                "position {position}: {result:?}"
            );
        }
    }
}

#[test]
fn an_http_header_length_that_wraps_a_32_bit_bounds_check_is_refused() {
    for value in [false, true] {
        for len in wrapping_lengths() {
            // The request: empty method, path, search; one header.
            let mut request = request_head();
            request.extend_from_slice(&[0, 0, 0, 1]);
            // The response: status 200, one header.
            let mut response = request_head();
            response.extend_from_slice(&[0xfd, 200, 0, 1]);
            for payload in [&mut request, &mut response] {
                if value {
                    payload.extend_from_slice(&[1, b'k']);
                }
                payload.extend_from_slice(&len);
                payload.extend_from_slice(b"header bytes");
            }
            let req = std::panic::catch_unwind(|| HttpRequest::from_payload(&request)).unwrap();
            let res = std::panic::catch_unwind(|| HttpResponse::from_payload(&response)).unwrap();
            for result in [req.map(|_| ()), res.map(|_| ())] {
                assert!(
                    matches!(result, Err(Error::AuthError(ref m)) if m.contains("too short")),
                    "value {value}: {result:?}"
                );
            }
        }
    }
}

#[test]
fn an_http_response_body_length_that_wraps_a_32_bit_bounds_check_reads_as_empty() {
    // A response body that overruns the payload reads as empty, as before.
    for len in wrapping_lengths() {
        let mut payload = request_head();
        payload.extend_from_slice(&[0xfd, 200, 0, 0]); // status 200, no headers
        payload.extend_from_slice(&len);
        payload.extend_from_slice(b"body");
        let response = std::panic::catch_unwind(|| HttpResponse::from_payload(&payload))
            .unwrap()
            .unwrap();
        assert_eq!(response.status, 200);
        assert!(response.body.is_empty());
    }
}

#[test]
fn a_valid_certificate_and_http_payloads_still_parse() {
    let subject = PrivateKey::from_bytes(&[1u8; 32]).unwrap().public_key();
    let certifier = PrivateKey::from_bytes(&[2u8; 32]).unwrap().public_key();
    let mut cert = Certificate::new([3u8; 32], [4u8; 32], subject, certifier);
    cert.set_field("name", "value");
    let bytes = cert.to_binary(false);
    assert_eq!(
        Certificate::from_binary(&bytes).unwrap().to_binary(false),
        bytes
    );

    let request = HttpRequest {
        request_id: [9u8; 32],
        method: "POST".into(),
        path: "/p".into(),
        search: "?q=1".into(),
        headers: vec![("k".into(), "v".into())],
        body: b"body".to_vec(),
    };
    let parsed = HttpRequest::from_payload(&request.to_payload()).unwrap();
    assert_eq!(parsed.to_payload(), request.to_payload());
    let response = HttpResponse {
        request_id: [9u8; 32],
        status: 201,
        headers: vec![("k".into(), "v".into())],
        body: b"body".to_vec(),
    };
    let parsed = HttpResponse::from_payload(&response.to_payload()).unwrap();
    assert_eq!(parsed.to_payload(), response.to_payload());
}
