//! A server that signs its responses, as the reference's middleware does, is
//! accepted by a client `Peer` on `start` over `SimplifiedFetchTransport`
//! (#353): the initial response signed over the two nonces
//! (`ts-stack@edf6e03` `packages/sdk/src/auth/Peer.ts:886-930`) and a general
//! response signed over the payload the reference client builds from it (its
//! request ID, status, `x-bsv-*` headers and body,
//! `transports/SimplifiedFetchTransport.ts:289-323`) under
//! `<nonce> <clientSessionNonce>` (`Peer.ts:1293-1301`). The server is a
//! wiremock host whose answers this crate's writer (`HttpResponse::to_payload`)
//! and signer (`ProtoWallet::create_signature`) build; the same server signing
//! with another key, or not signing, is refused.
//!
//! Run with: `cargo test --features "auth,http" --test auth_peer_http_signing_server_353`
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(all(feature = "auth", feature = "http"))]

use bsv_rs::auth::transports::{headers, HttpRequest, HttpResponse};
use bsv_rs::auth::{
    create_nonce, AuthMessage, MessageType, Peer, PeerOptions, SimplifiedFetchTransport,
    AUTH_PROTOCOL_ID,
};
use bsv_rs::primitives::{from_base64, to_base64, to_hex, PrivateKey};
use bsv_rs::wallet::{Counterparty, CreateSignatureArgs, ProtoWallet, Protocol, SecurityLevel};
use bsv_rs::Error;
use std::sync::{Arc, Mutex};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

fn scalar(n: u8) -> PrivateKey {
    PrivateKey::from_hex(&format!("{n:064x}")).unwrap()
}

fn client_key() -> PrivateKey {
    scalar(41)
}

fn server_key() -> PrivateKey {
    scalar(42)
}

fn mallory_key() -> PrivateKey {
    scalar(43)
}

/// `signer`'s BRC-103 signature to the client over `data` under `key_id`
fn sign(signer: &PrivateKey, key_id: &str, data: &[u8]) -> Vec<u8> {
    ProtoWallet::new(Some(signer.clone()))
        .create_signature(CreateSignatureArgs {
            data: Some(data.to_vec()),
            protocol_id: Protocol::new(SecurityLevel::Counterparty, AUTH_PROTOCOL_ID),
            key_id: key_id.to_string(),
            counterparty: Some(Counterparty::Other(client_key().public_key())),
            ..Default::default()
        })
        .unwrap()
        .signature
}

fn header(request: &Request, name: &str) -> String {
    request
        .headers
        .get(name)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string()
}

/// How the server's general response is signed
#[derive(Clone, Copy)]
enum Signing {
    Server,
    Mallory,
    None,
}

/// The server (scalar 42): its initial response signed over the client's
/// nonce and its own, and its answer to `POST /hello` a 200 carrying a signed
/// `x-bsv-greeting` header and the body `hi`, signed as `signing` says. The
/// client's session nonce is kept from the handshake for the general
/// response's `yourNonce` and key ID.
async fn server(signing: Signing) -> MockServer {
    let mock = MockServer::start().await;
    let server_nonce = create_nonce(&ProtoWallet::new(Some(server_key())), None, Some("test"))
        .await
        .unwrap();
    let client_nonce = Arc::new(Mutex::new(String::new()));

    let kept = client_nonce.clone();
    let responder_nonce = server_nonce.clone();
    Mock::given(method("POST"))
        .and(path("/.well-known/auth"))
        .respond_with(move |request: &Request| {
            let initial: AuthMessage = serde_json::from_slice(&request.body).unwrap();
            assert_eq!(initial.message_type, MessageType::InitialRequest);
            let their_nonce = initial.initial_nonce.unwrap();
            *kept.lock().unwrap() = their_nonce.clone();
            let mut data = from_base64(&their_nonce).unwrap();
            data.extend(from_base64(&responder_nonce).unwrap());
            let mut response =
                AuthMessage::new(MessageType::InitialResponse, server_key().public_key());
            response.initial_nonce = Some(responder_nonce.clone());
            response.your_nonce = Some(their_nonce.clone());
            response.signature = Some(sign(
                &server_key(),
                &format!("{their_nonce} {responder_nonce}"),
                &data,
            ));
            ResponseTemplate::new(200).set_body_string(serde_json::to_string(&response).unwrap())
        })
        .mount(&mock)
        .await;

    Mock::given(method("POST"))
        .and(path("/hello"))
        .respond_with(move |request: &Request| {
            // The client's general message names the server's nonce
            assert_eq!(header(request, headers::YOUR_NONCE), server_nonce);
            let request_id = header(request, headers::REQUEST_ID);
            let their_nonce = client_nonce.lock().unwrap().clone();
            let nonce = to_base64(&[9u8; 32]);
            let payload = HttpResponse {
                request_id: from_base64(&request_id).unwrap().try_into().unwrap(),
                status: 200,
                headers: vec![("x-bsv-greeting".into(), "hello".into())],
                body: b"hi".to_vec(),
            }
            .to_payload();
            let key_id = format!("{nonce} {their_nonce}");
            let mut answer = ResponseTemplate::new(200)
                .insert_header("x-bsv-greeting", "hello")
                .set_body_string("hi");
            let signer = match signing {
                Signing::Server => server_key(),
                Signing::Mallory => mallory_key(),
                Signing::None => return answer,
            };
            answer = answer
                .insert_header(headers::VERSION, "0.1")
                .insert_header(headers::IDENTITY_KEY, server_key().public_key().to_hex())
                .insert_header(headers::NONCE, nonce.as_str())
                .insert_header(headers::YOUR_NONCE, their_nonce.as_str())
                .insert_header(headers::REQUEST_ID, request_id.as_str())
                .insert_header(
                    headers::SIGNATURE,
                    to_hex(&sign(&signer, &key_id, &payload)),
                );
            answer
        })
        .mount(&mock)
        .await;
    mock
}

/// A client (scalar 41) on `start` over `SimplifiedFetchTransport` to `mock`,
/// its listener recording each payload
async fn client(
    mock: &MockServer,
) -> (
    Peer<ProtoWallet, SimplifiedFetchTransport>,
    Arc<Mutex<Vec<Vec<u8>>>>,
) {
    let peer = Peer::new(PeerOptions {
        wallet: ProtoWallet::new(Some(client_key())),
        transport: SimplifiedFetchTransport::new(&mock.uri()),
        certificates_to_request: None,
        session_manager: None,
        auto_persist_last_session: false,
        originator: Some("test".into()),
    });
    peer.start();
    let received = Arc::new(Mutex::new(Vec::new()));
    let log = received.clone();
    peer.listen_for_general_messages(move |_, payload| {
        log.lock().unwrap().push(payload);
        Box::pin(async { Ok(()) })
    })
    .await;
    (peer, received)
}

fn hello() -> Vec<u8> {
    HttpRequest {
        request_id: [7; 32],
        method: "POST".into(),
        path: "/hello".into(),
        search: String::new(),
        headers: vec![("content-type".into(), "text/plain".into())],
        body: b"hello".to_vec(),
    }
    .to_payload()
}

async fn say_hello(peer: &Peer<ProtoWallet, SimplifiedFetchTransport>) -> bsv_rs::Result<()> {
    let server = server_key().public_key().to_hex();
    peer.to_peer(&hello(), Some(&server), Some(5000)).await
}

#[tokio::test]
async fn a_signing_server_is_accepted_by_a_client_on_start_353() {
    let mock = server(Signing::Server).await;
    let (peer, received) = client(&mock).await;

    say_hello(&peer).await.unwrap();

    let received = received.lock().unwrap().clone();
    assert_eq!(received.len(), 1);
    let response = HttpResponse::from_payload(&received[0]).unwrap();
    assert_eq!(response.request_id, [7; 32]);
    assert_eq!(response.status, 200);
    assert_eq!(
        response.headers,
        vec![("x-bsv-greeting".to_string(), "hello".to_string())]
    );
    assert_eq!(response.body, b"hi");
    let sessions = peer.session_manager().read().await;
    let session = sessions.iter().next().unwrap();
    assert!(session.is_authenticated);
    assert_eq!(session.peer_identity_key, Some(server_key().public_key()));
}

#[tokio::test]
async fn a_server_response_signed_by_another_key_is_refused_353() {
    let mock = server(Signing::Mallory).await;
    let (peer, received) = client(&mock).await;

    // A `ProtoWallet`'s verify refuses a miss in its own words before the
    // Peer's, as the reference's `ProtoWallet.verifySignature` throws
    assert_eq!(
        say_hello(&peer).await.unwrap_err(),
        Error::WalletError("Signature is not valid".into())
    );
    assert!(received.lock().unwrap().is_empty());
}

/// An unsigned response is refused by the transport before it becomes a
/// message, in the reference's words (`Received HTTP 200 OK from <url>
/// without valid BSV authentication (missing headers: ...)`,
/// `SimplifiedFetchTransport.ts:220-232`, `:464-494`; bsv-rs#354), where
/// until #354 the transport gave it the client's own key and the Peer
/// refused its absent `yourNonce` naming that key.
#[tokio::test]
async fn an_unsigned_server_response_is_refused_353() {
    let mock = server(Signing::None).await;
    let (peer, received) = client(&mock).await;

    assert_eq!(
        say_hello(&peer).await.unwrap_err(),
        Error::AuthError(format!(
            "Received HTTP 200 OK from {}/hello without valid BSV authentication \
             (missing headers: x-bsv-auth-version, x-bsv-auth-identity-key, \
             x-bsv-auth-signature) - body preview: hi",
            mock.uri()
        ))
    );
    assert!(received.lock().unwrap().is_empty());
}
