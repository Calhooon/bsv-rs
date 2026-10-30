#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test assertions.

mod wallet;
use async_trait::async_trait;
use bsv_rs::auth::clients::{AuthFetch, AuthFetchOptions, Response};
use bsv_rs::auth::transports::TransportCallback;
use bsv_rs::auth::{AuthMessage, MessageType, SimplifiedFetchTransport, Transport};
use bsv_rs::primitives::{from_base64, to_base64, PrivateKey};
use bsv_rs::wallet::{Counterparty, CreateSignatureArgs, ProtoWallet, Protocol, SecurityLevel};
use bsv_rs::{Error, Result};
use serde_json::Value;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
pub use wallet::TestWallet;
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

pub fn vector() -> Value {
    serde_json::from_str(include_str!("../../vectors/auth_fetch_423.json")).unwrap()
}
pub fn row(name: &str) -> Value {
    vector()["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == name)
        .unwrap()
        .clone()
}
pub fn key(number: u8) -> PrivateKey {
    PrivateKey::from_hex(&format!("{number:064x}")).unwrap()
}
fn sign(data: Vec<u8>, key_id: String) -> Vec<u8> {
    ProtoWallet::new(Some(key(42)))
        .create_signature(CreateSignatureArgs {
            data: Some(data),
            key_id,
            protocol_id: Protocol::new(SecurityLevel::Counterparty, "auth message signature"),
            counterparty: Some(Counterparty::Other(key(41).public_key())),
            ..Default::default()
        })
        .unwrap()
        .signature
}
pub fn words<T>(result: Result<T>) -> String {
    match result.err().expect("refusal") {
        Error::AuthError(text) | Error::WalletError(text) => text,
        e => e.to_string(),
    }
}
pub fn options(row: &Value) -> AuthFetchOptions {
    let value = &row["options"];
    AuthFetchOptions {
        method: value["method"].as_str().map(str::to_owned),
        headers: value["headers"]
            .as_object()
            .map(|h| {
                h.iter()
                    .map(|(k, v)| (k.clone(), v.as_str().unwrap().into()))
                    .collect()
            })
            .unwrap_or_default(),
        body: value["body"]
            .as_array()
            .map(|b| b.iter().map(|n| n.as_u64().unwrap() as u8).collect()),
        retry_counter: value["retryCounter"].as_u64().map(|n| n as u32),
        labels: value["labels"]
            .as_array()
            .map(|a| a.iter().map(|s| s.as_str().unwrap().into()).collect())
            .unwrap_or_default(),
        ..Default::default()
    }
}

pub struct RecordingTransport {
    inner: SimplifiedFetchTransport,
    sent: Arc<Mutex<Vec<AuthMessage>>>,
    handler: bool,
}

#[async_trait]
impl Transport for RecordingTransport {
    async fn send(&self, message: &AuthMessage) -> Result<()> {
        self.sent.lock().unwrap().push(message.clone());
        self.inner.send(message).await
    }
    fn set_callback(&self, callback: Box<TransportCallback>) {
        let handler = self.handler;
        self.inner.set_callback(Box::new(move |mut message| {
            // Separate #416 handler harness: replace the field the HTTP fold
            // loses, only after the ordinary-intake test has pinned its refusal.
            if handler && message.message_type == MessageType::CertificateRequest {
                message.initial_nonce = Some(to_base64(&[11; 48]));
            }
            callback(message)
        }));
    }
    fn clear_callback(&self) {
        self.inner.clear_callback();
    }
}

pub struct Environment {
    pub mock: MockServer,
    pub client: AuthFetch<TestWallet, RecordingTransport>,
    pub row: Value,
    pub sent: Arc<Mutex<Vec<AuthMessage>>>,
    pub actions: Arc<Mutex<Vec<Value>>>,
    pub payment_keys: Arc<Mutex<Vec<String>>>,
}

impl Environment {
    pub async fn new(name: &str) -> Self {
        Self::with_response_body(name, None).await
    }
    pub async fn with_response_body(name: &str, body: Option<Vec<u8>>) -> Self {
        Self::with_response(name, body, None).await
    }
    pub async fn with_response_status(name: &str, status: u16) -> Self {
        Self::with_response(name, None, Some(status)).await
    }
    async fn with_response(name: &str, body: Option<Vec<u8>>, status: Option<u16>) -> Self {
        let row = row(name);
        let mock = MockServer::start().await;
        let state = Arc::new(ServerState {
            row: row.clone(),
            nonce: Mutex::new(String::new()),
            general: AtomicUsize::new(0),
            body,
            status,
        });
        Mock::given(wiremock::matchers::any())
            .respond_with(move |request: &Request| state.respond(request))
            .mount(&mock)
            .await;
        let sent = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&sent);
        let wallet = TestWallet::new(row.clone());
        let actions = Arc::clone(&wallet.actions);
        let payment_keys = Arc::clone(&wallet.payment_keys);
        let policy = (name == "receive_certificates")
            .then(|| serde_json::from_value(vector()["policy"].clone()).unwrap());
        let handler = name == "certificate_handler";
        let client = AuthFetch::with_transport_factory(wallet, policy, None, move |origin| {
            RecordingTransport {
                inner: SimplifiedFetchTransport::new(origin),
                sent: Arc::clone(&log),
                handler,
            }
        })
        .with_response_timeout_ms(2000);
        Self {
            mock,
            client,
            row,
            sent,
            actions,
            payment_keys,
        }
    }
    pub fn url(&self) -> String {
        format!("{}/resource?q=1", self.mock.uri())
    }
    pub async fn fetch(&self) -> Result<Response> {
        self.client.fetch(&self.url(), options(&self.row)).await
    }
    pub fn assert_response(&self, response: &Response) {
        let expected = &self.row["result"];
        assert_eq!(response.status, expected["status"].as_u64().unwrap() as u16);
        assert_eq!(
            serde_json::to_value(&response.headers).unwrap(),
            expected["headers"]
        );
        assert_eq!(hex::encode(&response.body), expected["body_hex"]);
    }
    pub fn assert_frames(&self) {
        let sent = self.sent.lock().unwrap();
        let expected: Vec<_> = self.row["messages"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|m| m["messageType"] == "general")
            .collect();
        let actual: Vec<_> = sent
            .iter()
            .filter(|m| m.message_type == MessageType::General)
            .collect();
        assert_eq!(actual.len(), expected.len());
        for (actual, expected) in actual.iter().zip(expected) {
            let mut actual = actual.payload.clone().unwrap();
            let expected: Vec<u8> = expected["payload"]
                .as_array()
                .unwrap()
                .iter()
                .map(|n| n.as_u64().unwrap() as u8)
                .collect();
            // Only entropy is normalized: request ID and the payment's nonce.
            actual[..32].copy_from_slice(&expected[..32]);
            normalize_payment_nonce(&mut actual, &expected);
            assert_eq!(actual, expected, "the complete serialized HTTP request");
        }
    }
}

fn normalize_payment_nonce(actual: &mut [u8], expected: &[u8]) {
    let a = bsv_rs::auth::transports::HttpRequest::from_payload(actual).unwrap();
    let e = bsv_rs::auth::transports::HttpRequest::from_payload(expected).unwrap();
    let header = |r: bsv_rs::auth::transports::HttpRequest| {
        r.headers
            .into_iter()
            .find(|(k, _)| k == "x-bsv-payment")
            .map(|(_, v)| serde_json::from_str::<Value>(&v).unwrap())
    };
    if let (Some(a), Some(e)) = (header(a), header(e)) {
        let a = a["derivationSuffix"].as_str().unwrap().as_bytes();
        let e = e["derivationSuffix"].as_str().unwrap().as_bytes();
        let offset = actual.windows(a.len()).position(|b| b == a).unwrap();
        actual[offset..offset + a.len()].copy_from_slice(e);
    }
}

struct ServerState {
    row: Value,
    nonce: Mutex<String>,
    general: AtomicUsize,
    body: Option<Vec<u8>>,
    status: Option<u16>,
}
impl ServerState {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        if request.url.path() == "/.well-known/auth" {
            return self.handshake(request);
        }
        let name = self.row["name"].as_str().unwrap();
        if name == "timeout" {
            return ResponseTemplate::new(200).set_delay(std::time::Duration::from_secs(10));
        }
        let index = self.general.fetch_add(1, Ordering::SeqCst);
        if name == "payment_network" && index > 0 {
            let fault = self.row["responses"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["fault_status"].is_number())
                .unwrap();
            return ResponseTemplate::new(fault["fault_status"].as_u64().unwrap() as u16)
                .set_body_bytes(hex::decode(fault["body_hex"].as_str().unwrap()).unwrap());
        }
        let frames: Vec<_> = self.row["responses"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["status"].is_number())
            .collect();
        let frame = frames[index.min(frames.len() - 1)];
        let mut headers = frame["headers"].as_object().unwrap().clone();
        let request_id = if name == "mismatch" {
            headers["x-bsv-auth-request-id"]
                .as_str()
                .unwrap()
                .to_owned()
        } else {
            request.headers["x-bsv-auth-request-id"]
                .to_str()
                .unwrap()
                .into()
        };
        headers.insert("x-bsv-auth-request-id".into(), request_id.clone().into());
        let ours = self.nonce.lock().unwrap().clone();
        headers.insert("x-bsv-auth-your-nonce".into(), ours.clone().into());
        let mut payload = hex::decode(frame["frame_hex"].as_str().unwrap()).unwrap();
        payload[..32].copy_from_slice(&from_base64(&request_id).unwrap());
        let body = self
            .body
            .clone()
            .unwrap_or_else(|| hex::decode(frame["body_hex"].as_str().unwrap()).unwrap());
        if self.body.is_some() || self.status.is_some() {
            let mut response =
                bsv_rs::auth::transports::HttpResponse::from_payload(&payload).unwrap();
            response.body = body.clone();
            response.status = self.status.unwrap_or(response.status);
            payload = response.to_payload();
        }
        if headers.contains_key("x-bsv-auth-requested-certificates") {
            payload = headers["x-bsv-auth-requested-certificates"]
                .as_str()
                .unwrap()
                .as_bytes()
                .to_vec();
        }
        let key_id = format!("{} {ours}", headers["x-bsv-auth-nonce"].as_str().unwrap());
        headers.insert(
            "x-bsv-auth-signature".into(),
            hex::encode(sign(payload, key_id)).into(),
        );
        let mut response = ResponseTemplate::new(
            self.status
                .unwrap_or(frame["status"].as_u64().unwrap() as u16),
        )
        .set_body_bytes(body);
        for (name, value) in headers {
            response = response.insert_header(name.as_str(), value.as_str().unwrap());
        }
        response
    }

    fn handshake(&self, request: &Request) -> ResponseTemplate {
        let message: AuthMessage = serde_json::from_slice(&request.body).unwrap();
        let field = match message.message_type {
            MessageType::InitialRequest => "handshake",
            MessageType::CertificateRequest => "certificate_response",
            MessageType::CertificateResponse => "certificate_ack",
            _ => panic!("unexpected message"),
        };
        let template = self.row["responses"]
            .as_array()
            .unwrap()
            .iter()
            .find_map(|r| r.get(field))
            .unwrap();
        let mut response: AuthMessage = serde_json::from_value(template.clone()).unwrap();
        if message.message_type == MessageType::InitialRequest {
            *self.nonce.lock().unwrap() = message.initial_nonce.unwrap();
        }
        let ours = self.nonce.lock().unwrap().clone();
        response.your_nonce = Some(ours.clone());
        let (data, key_id) = if field == "handshake" {
            let theirs = response.initial_nonce.as_ref().unwrap();
            let mut data = from_base64(&ours).unwrap();
            data.extend(from_base64(theirs).unwrap());
            (data, format!("{ours} {theirs}"))
        } else {
            (
                response.signing_data(),
                format!("{} {ours}", response.nonce.as_ref().unwrap()),
            )
        };
        response.signature = Some(sign(data, key_id));
        ResponseTemplate::new(200).set_body_string(serde_json::to_string(&response).unwrap())
    }
}
