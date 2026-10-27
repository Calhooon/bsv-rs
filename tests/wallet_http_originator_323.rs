//! The HTTP wallet substrates' originator, headers, redirect refusal and base
//! URL, as the reference's (bsv-rs#323; `ts-stack@edf6e03`
//! `packages/sdk/src/wallet/substrates/HTTPWalletJSON.ts:280-314`,
//! `HTTPWalletWire.ts:17-20`, `:43-66`, `utils/toOriginHeader.ts`,
//! `validationHelpers.ts:996-1037`): the originator validated at construction
//! (a hostname, its port dropped), the JSON call refused with none configured,
//! the JSON substrate sending the constructor's originator as `Origin` and
//! `Originator` in the origin form and the wire the frame's raw as `Origin`,
//! refusing a frame whose originator is not the configured one; no redirect
//! followed; the base URL an exact origin, cleartext only to a loopback host;
//! a JSON body or a wire frame over 256 MiB refused unsent.
//!
//! Run with: `cargo test --features "wallet,http" --test wallet_http_originator_323`
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(all(feature = "wallet", feature = "http"))]

use bsv_rs::wallet::substrates::{HttpWalletJson, HttpWalletWire};
use bsv_rs::wallet::wire::{WalletCall, WalletWire};
use bsv_rs::wallet::CreateActionArgs;
use bsv_rs::{Error, WalletRefusalClass};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORIGINATOR_REQUIRED: &str = "HTTPWalletJSON: originator is required when using the HTTP \
    substrate in Node.js. Pass an originator (e.g. \"example.com\") to the constructor.";
const NOT_CANONICAL: &str =
    "The originator parameter must be a canonical DNS hostname with an optional port";
/// The reference's `MAX_WALLET_JSON_REQUEST_BYTES` (`HTTPWalletJSON.ts:60`).
const MAX_WALLET_JSON_REQUEST_BYTES: usize = 256 * 1024 * 1024;
/// The reference's `MAX_WALLET_WIRE_FRAME_BYTES` (`WalletWire.ts:9`).
const MAX_WALLET_WIRE_FRAME_BYTES: usize = 256 * 1024 * 1024;
const MISMATCH: &str = "Wallet Wire frame originator does not match the configured originator";

fn refusal(message: &str) -> Error {
    Error::WalletRefusal {
        class: WalletRefusalClass::InvalidParameter,
        message: message.to_string(),
    }
}

fn wallet_error(words: &str) -> Error {
    Error::WalletError(words.to_string())
}

fn json(originator: Option<&str>, base_url: &str) -> Result<HttpWalletJson, Error> {
    HttpWalletJson::new(originator.map(str::to_string), Some(base_url.to_string()))
}

fn wire(originator: Option<&str>, base_url: &str) -> Result<HttpWalletWire, Error> {
    HttpWalletWire::new(originator.map(str::to_string), Some(base_url.to_string()))
}

/// A getVersion frame carrying `originator`, its payload empty.
fn get_version_frame(originator: &str) -> Vec<u8> {
    let mut frame = vec![WalletCall::GetVersion as u8, originator.len() as u8];
    frame.extend_from_slice(originator.as_bytes());
    frame
}

/// A server answering getVersion, both substrates' way, and refusing to be
/// asked anything else.
async fn version_server() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/getVersion"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "version": "wallet-1.0.0" })),
        )
        .mount(&server)
        .await;
    server
}

/// The value of `name` on every request `server` received.
async fn header_values(server: &MockServer, name: &str) -> Vec<Option<String>> {
    let requests = server.received_requests().await.unwrap();
    requests
        .iter()
        .map(|r| r.headers.get(name).map(|v| v.to_str().unwrap().to_string()))
        .collect()
}

#[tokio::test]
async fn a_json_call_with_no_originator_configured_is_refused_in_the_references_words() {
    let server = version_server().await;
    let client = json(None, &server.uri()).unwrap();
    assert_eq!(
        client.get_version("example.com").await,
        Err(wallet_error(ORIGINATOR_REQUIRED))
    );
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn the_json_substrate_sends_both_headers_in_the_origin_form_with_the_port_dropped() {
    for (configured, origin) in [
        ("example.com", "http://example.com"),
        ("Example.COM:8080", "http://example.com"),
        (" app.example.com ", "http://app.example.com"),
    ] {
        let server = version_server().await;
        let client = json(Some(configured), &server.uri()).unwrap();
        assert_eq!(
            client.originator(),
            Some(origin.trim_start_matches("http://"))
        );
        // The call's originator is not the one sent: the constructor's is
        let version = client.get_version("other.example").await.unwrap();
        assert_eq!(version, "wallet-1.0.0");
        assert_eq!(
            header_values(&server, "origin").await,
            [Some(origin.into())]
        );
        assert_eq!(
            header_values(&server, "originator").await,
            [Some(origin.into())]
        );
    }
}

#[tokio::test]
async fn an_originator_that_is_not_a_hostname_is_refused_at_construction_by_both_substrates() {
    // The reference's `validateOriginator` reads the scheme's colon as a port
    // separator, so a scheme-prefixed originator never reaches
    // `toOriginHeader`'s trimming branch through a constructor
    for originator in [
        "https://example.com/app?x=1",
        "http://example.com",
        "example.com:65536",
        "bad_host.example",
        "a:1:2",
    ] {
        let expected = Err(refusal(NOT_CANONICAL));
        assert_eq!(
            json(Some(originator), "http://localhost:3321").map(|_| ()),
            expected
        );
        assert_eq!(
            wire(Some(originator), "http://localhost:3301").map(|_| ()),
            expected
        );
    }
    let empty = Err(refusal(
        "The originator parameter must be at least 1 length.",
    ));
    assert_eq!(json(Some(" "), "http://localhost:3321").map(|_| ()), empty);
    assert_eq!(wire(Some(" "), "http://localhost:3301").map(|_| ()), empty);
}

#[tokio::test]
async fn the_wire_sends_the_frames_originator_raw_as_origin() {
    for (configured, frame, origin) in [
        (Some("example.com"), "example.com", "example.com"),
        (Some("example.com"), "Example.com:8080", "example.com"),
        (None, "app.example.com:3000", "app.example.com"),
        (None, "", ""),
    ] {
        let server = version_server().await;
        let wire = wire(configured, &server.uri()).unwrap();
        wire.transmit_to_wallet(&get_version_frame(frame))
            .await
            .unwrap();
        assert_eq!(
            header_values(&server, "origin").await,
            [Some(origin.into())]
        );
        assert_eq!(header_values(&server, "originator").await, [None]);
    }
}

#[tokio::test]
async fn the_wire_refuses_a_frame_whose_originator_is_not_the_configured_one() {
    let server = version_server().await;
    let wire = wire(Some("example.com"), &server.uri()).unwrap();
    for frame in ["other.example", ""] {
        assert_eq!(
            wire.transmit_to_wallet(&get_version_frame(frame)).await,
            Err(wallet_error(MISMATCH)),
            "{frame:?}"
        );
    }
    assert_eq!(
        wire.transmit_to_wallet(&get_version_frame("bad_host"))
            .await,
        Err(refusal(NOT_CANONICAL))
    );
    let mut long = vec![WalletCall::GetVersion as u8, 251];
    long.extend_from_slice(&[b'a'; 251]);
    assert_eq!(
        wire.transmit_to_wallet(&long).await,
        Err(wallet_error(
            "Invalid originator length: expected at most 250 bytes, received 251"
        ))
    );
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn a_redirect_is_answered_and_not_followed_by_either_substrate() {
    let elsewhere = version_server().await;
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/getVersion"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("Location", format!("{}/getVersion", elsewhere.uri())),
        )
        .expect(2)
        .mount(&server)
        .await;
    let refused = wallet_error("HTTP 302 Found for getVersion: a redirect is refused");

    let client = json(Some("example.com"), &server.uri()).unwrap();
    assert_eq!(
        client.get_version("example.com").await,
        Err(refused.clone())
    );
    let wire = wire(Some("example.com"), &server.uri()).unwrap();
    let answer = wire
        .transmit_to_wallet(&get_version_frame("example.com"))
        .await;
    assert_eq!(answer, Err(refused));

    assert!(elsewhere.received_requests().await.unwrap().is_empty());
}

#[test]
fn a_base_url_that_is_not_an_exact_origin_or_is_cleartext_to_another_host_is_refused() {
    let bare = "Wallet HTTP baseUrl must be an HTTP(S) origin without credentials, path, query, \
        or fragment.";
    let cleartext = "Wallet HTTP baseUrl may use cleartext HTTP only for a loopback host.";
    for (base_url, words) in [
        ("https://wallet.example.com/api", bare),
        ("http://localhost:3321/wallet", bare),
        ("https://wallet.example.com/?key=1", bare),
        ("https://user:pass@wallet.example.com", bare),
        ("https://wallet.example.com/#f", bare),
        ("http://wallet.example.com", cleartext),
        ("http://192.168.1.10:3321", cleartext),
        ("http://localhost.example.com", cleartext),
        (
            "wallet.example.com",
            "Wallet HTTP baseUrl must be an exact HTTP(S) origin.",
        ),
        (
            " http://localhost:3321",
            "Wallet HTTP baseUrl must be an exact HTTP(S) origin.",
        ),
    ] {
        let expected = Err(wallet_error(words));
        assert_eq!(
            json(Some("example.com"), base_url).map(|_| ()),
            expected,
            "{base_url}"
        );
        assert_eq!(
            wire(Some("example.com"), base_url).map(|_| ()),
            expected,
            "{base_url}"
        );
    }
}

#[test]
fn a_loopback_or_https_base_url_is_accepted_as_its_origin() {
    for (base_url, origin) in [
        ("http://localhost:3321", "http://localhost:3321"),
        ("http://localhost:3321/", "http://localhost:3321"),
        (
            "http://wallet.localhost:3321",
            "http://wallet.localhost:3321",
        ),
        ("http://127.0.0.1:3301", "http://127.0.0.1:3301"),
        ("http://[::1]:3301", "http://[::1]:3301"),
        (
            "https://wallet.example.com:443",
            "https://wallet.example.com",
        ),
        (
            "https://wallet.example.com:8443",
            "https://wallet.example.com:8443",
        ),
    ] {
        assert_eq!(
            json(Some("example.com"), base_url).unwrap().base_url(),
            origin
        );
        assert_eq!(
            wire(Some("example.com"), base_url).unwrap().base_url(),
            origin
        );
    }
    let json_default = HttpWalletJson::new(Some("example.com".into()), None).unwrap();
    assert_eq!(json_default.base_url(), "http://localhost:3321");
    let wire_default = HttpWalletWire::new(None, None).unwrap();
    assert_eq!(wire_default.base_url(), "http://localhost:3301");
}

#[tokio::test]
async fn a_json_request_over_256_mib_is_refused_unsent() {
    let server = version_server().await;
    let client = json(Some("example.com"), &server.uri()).unwrap();
    // The body one byte past 256 MiB: the description fills what the rest
    // of the request leaves (a string, written by the byte; numbers are slow
    // to write in a debug build)
    let mut args = CreateActionArgs {
        description: String::new(),
        input_beef: None,
        inputs: None,
        outputs: None,
        lock_time: None,
        version: None,
        labels: None,
        options: None,
    };
    let rest = serde_json::to_vec(&args).unwrap().len();
    args.description = "a".repeat(MAX_WALLET_JSON_REQUEST_BYTES + 1 - rest);
    assert_eq!(
        client.create_action(args, "example.com").await.map(|_| ()),
        Err(wallet_error(
            "HTTPWalletJSON request exceeds the maximum permitted size"
        ))
    );
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn a_wire_frame_over_256_mib_is_refused_unsent_on_its_length() {
    let server = version_server().await;
    let wire = wire(Some("example.com"), &server.uri()).unwrap();
    // One byte past the reference's `MAX_WALLET_WIRE_FRAME_BYTES`
    // (`WalletWire.ts:9`), zeroed: the bound is read from the length, before
    // the call code, the originator or a body is read or built
    let frame = vec![0u8; MAX_WALLET_WIRE_FRAME_BYTES + 1];
    assert_eq!(
        wire.transmit_to_wallet(&frame).await,
        Err(wallet_error(
            "HTTPWalletWire request exceeds the maximum permitted size"
        ))
    );
    assert!(server.received_requests().await.unwrap().is_empty());
}
