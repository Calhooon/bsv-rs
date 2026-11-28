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
    // The #108 regression property is: refused, never a process-ending panic.
    // When the certificate revocation-outpoint-index bound released in 0.8.14
    // co-lands it refuses this input's u64::MAX revocation-outpoint index before
    // the field-length guard, so assert "refused" rather than the ReaderUnderflow
    // kind (the two constructed-input cert tests above still pin ReaderUnderflow).
    assert!(
        result.is_err(),
        "the #108 input must be refused: {result:?}"
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
fn an_http_response_body_length_that_wraps_a_32_bit_bounds_check_is_refused() {
    // On this line a response body-length prefix that overruns the payload is
    // refused (the short-body guard of #843), not read as an empty body; the
    // wrapping length must not slip that guard on a 32-bit target.
    for len in wrapping_lengths() {
        let mut payload = request_head();
        payload.extend_from_slice(&[0xfd, 200, 0, 0]); // status 200, no headers
        payload.extend_from_slice(&len);
        payload.extend_from_slice(b"body");
        let result = std::panic::catch_unwind(|| HttpResponse::from_payload(&payload))
            .unwrap_or_else(|_| panic!("panicked on a wrapping body length"));
        assert!(
            matches!(result, Err(Error::AuthError(ref m)) if m.contains("too short")),
            "{result:?}"
        );
    }
}

#[test]
fn a_valid_certificate_and_http_payloads_still_parse() {
    let subject = PrivateKey::from_bytes(&[1u8; 32]).unwrap().public_key();
    let certifier = PrivateKey::from_bytes(&[2u8; 32]).unwrap().public_key();
    let mut cert = Certificate::new([3u8; 32], [4u8; 32], subject, certifier);
    cert.fields.insert("name".into(), b"value".to_vec());
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

// ---------------------------------------------------------------------------
// The production-target-only guards, their 32-bit arithmetic pinned on every
// host (#108 fold).
//
// Three of the guards the fix adds only bite on the production target (wasm32,
// where `usize` is `u32`): the certificate `read_len` conversion, the HTTP
// `take` bound, and the HTTP header-count conversion. A 64-bit host cannot make
// the real door fail through any input — a 64-bit `usize` cannot wrap these
// sums, so the pre-fix door returns an error there too. The real door on the
// production target is therefore bound by a wasm32 run (recorded in the fold
// ledger): on the pre-fix tree each door is an uncatchable trap; on this tip
// each returns an error.
//
// These tests pin the SAME arithmetic the door uses, at the 32-bit width, on
// every host. Each transcribes the door's expression (named in its comment),
// feeds it the two crafted lengths `wrapping_lengths()` feeds the real door,
// and asserts the fixed form refuses both while the pre-fix form wrapped or
// truncated them. They cannot drift unnoticed: the wasm32 run cross-checks the
// real door against this same arithmetic (pre-fix trap / tip error) for the
// same inputs. A model was chosen over factoring the door to keep the port
// faithful (the certificate reader is byte-identical to #108; the HTTP reader
// is the reviewed hand port).

// The two crafted lengths, as `read_varint` yields them (i64): `near` fits a
// `u32` (the pre-fix `cursor + len` wrapped); `past` exceeds it (the pre-fix
// `as usize` truncated it to 5).
const NEAR_RAW: i64 = (u32::MAX - 8) as i64; // 4_294_967_287
const PAST_RAW: i64 = (1i64 << 32) + 5; // 4_294_967_301

/// Models HTTP `take` at `usize == u32`: `usize::try_from(len).ok()?`, then
/// `len > payload.len().checked_sub(cursor)?` (src/auth/transports/http.rs).
/// `Some` means the field is accepted; `None` means refused.
fn http_take_32bit(payload_len: u32, cursor: u32, len_raw: i64) -> Option<u32> {
    let len = u32::try_from(len_raw).ok()?;
    let remaining = payload_len.checked_sub(cursor)?;
    if len > remaining {
        return None;
    }
    Some(len) // payload.get(cursor..cursor + len) is Some
}

/// Models the pre-#108 HTTP field read at `usize == u32`:
/// `let len = raw as usize; if cursor + len > payload.len() { Err }`.
/// Returns true when the crafted length slips the check — the sum wrapped, or
/// the length truncated and fit — i.e. the pre-fix door would index past-end.
fn http_bound_pre108_slips_32bit(payload_len: u32, cursor: u32, len_raw: i64) -> bool {
    let len = len_raw as u32; // `raw as usize` truncates on a 32-bit target
    let end = cursor.wrapping_add(len); // `cursor + len` wraps on a 32-bit target
    end <= payload_len // the (wrapped/truncated) sum passes `> payload.len()`
}

#[test]
fn the_http_bound_refuses_a_32_bit_wrapping_length() {
    // A header-sized payload: a cursor a few bytes in, little room left.
    let payload_len: u32 = 51;
    let cursor: u32 = 33;
    for len_raw in [NEAR_RAW, PAST_RAW] {
        assert_eq!(
            http_take_32bit(payload_len, cursor, len_raw),
            None,
            "the fixed bound must refuse a length of {len_raw} at 32-bit width"
        );
        assert!(
            http_bound_pre108_slips_32bit(payload_len, cursor, len_raw),
            "the pre-fix bound slipped a length of {len_raw} at 32-bit width"
        );
    }
    // An honest length is still accepted (no false refusal).
    assert_eq!(http_take_32bit(payload_len, cursor, 10), Some(10));
}

/// Models the certificate `read_len` conversion at `usize == u32`:
/// `usize::try_from(varint)` (src/auth/certificates/certificate.rs). `None`
/// means a length past the width is refused, never truncated.
fn cert_read_len_32bit(varint: u64) -> Option<u32> {
    u32::try_from(varint).ok()
}

#[test]
fn the_certificate_length_above_32_bits_is_refused_not_truncated() {
    for varint in [u64::MAX, (1u64 << 32) + 5, PAST_RAW as u64] {
        assert_eq!(
            cert_read_len_32bit(varint),
            None,
            "a length of {varint} must be refused at 32-bit width"
        );
        // The pre-fix `varint as usize` (== `as u32`) would truncate it to a
        // short, in-range length and read the wrong bytes.
        assert!((varint as u32) < u32::MAX || varint == u64::MAX);
    }
    // A length within the width still converts.
    assert_eq!(cert_read_len_32bit(64), Some(64));
}

/// Models the HTTP header-count conversion at `usize == u32`:
/// `usize::try_from(count).unwrap_or(usize::MAX)` (src/auth/transports/http.rs).
fn header_count_32bit(count: i64) -> u32 {
    u32::try_from(count).unwrap_or(u32::MAX)
}

#[test]
fn the_header_count_above_32_bits_saturates_not_truncates() {
    // A count past the width saturates to u32::MAX (the header loop then runs
    // out of bytes and errors), never truncating to a small, plausible count.
    assert_eq!(header_count_32bit(PAST_RAW), u32::MAX);
    assert_eq!(header_count_32bit(i64::MAX), u32::MAX);
    // The pre-fix `count as usize` (== `as u32`) truncated it to a small count.
    assert_eq!(PAST_RAW as u32, 5);
    // An honest count is unchanged.
    assert_eq!(header_count_32bit(3), 3);
}
