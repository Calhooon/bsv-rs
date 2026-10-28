//! revealCounterpartyKeyLinkage (9) and revealSpecificKeyLinkage (10) on the
//! wallet wire, against the reference's transceiver and processor (#406;
//! `ts-stack@edf6e03` `WalletWireTransceiver.ts:790-924`,
//! `WalletWireProcessor.ts:1734-1849`, recorded by
//! `tests/support/wire_linkage_calls_406.mjs` under Node v22.18.0): this
//! crate's transceiver writes each recorded request frame byte for byte and
//! reads each recorded response to the reference's result; its processor
//! reads each request to the args the reference's wallet saw and writes each
//! response byte for byte; the transport a `WalletClient` uses over the wire
//! (`HttpWalletWire`, here on an in-process wiremock) carries both calls;
//! the transceiver refuses the answers the reference's refuses. Until #406
//! the transceiver had neither method, so a client over the wire could not
//! make either call.
#![cfg(all(feature = "wallet", feature = "http"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[allow(dead_code)]
#[path = "support/fixtures/mod.rs"]
mod fixtures;

use bsv_rs::primitives::PrivateKey;
use bsv_rs::wallet::interface::{RevealCounterpartyKeyLinkageArgs, RevealSpecificKeyLinkageArgs};
use bsv_rs::wallet::substrates::HttpWalletWire;
use bsv_rs::wallet::wire::{WalletWire, WalletWireProcessor, WalletWireTransceiver};
use bsv_rs::wallet::{
    Counterparty, ProtoWallet, RevealCounterpartyKeyLinkageResult, RevealSpecificKeyLinkageResult,
};
use bsv_rs::{Error, WalletRefusalClass};
use fixtures::wallet::Stub;
use fixtures::wallet_json::FixtureJson;
use serde_json::Value;
use std::sync::{Arc, Mutex};
use wiremock::matchers::{body_bytes, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn vector() -> Value {
    serde_json::from_str(include_str!("vectors/wallet_wire/linkage_calls_406.json")).unwrap()
}

fn bytes(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().unwrap()).unwrap()
}

fn text(value: &Value) -> &str {
    value.as_str().unwrap()
}

/// Captures the request frame and answers with a fixed response frame.
struct Canned {
    response: Vec<u8>,
    request: Arc<Mutex<Option<Vec<u8>>>>,
}

#[async_trait::async_trait]
impl WalletWire for Canned {
    async fn transmit_to_wallet(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        *self.request.lock().unwrap() = Some(message.to_vec());
        Ok(self.response.clone())
    }
}

/// Makes the case's call through `client` and answers the result as the
/// reference's JSON.
async fn call<T: WalletWire>(
    client: &WalletWireTransceiver<T>,
    case: &Value,
    originator: Option<&str>,
) -> Result<Value, Error> {
    let args = case["args"].clone();
    match text(&case["call"]) {
        "revealCounterpartyKeyLinkage" => client
            .reveal_counterparty_key_linkage(
                RevealCounterpartyKeyLinkageArgs::from_fixture(args),
                originator,
            )
            .await
            .map(|result| result.fixture()),
        "revealSpecificKeyLinkage" => client
            .reveal_specific_key_linkage(
                RevealSpecificKeyLinkageArgs::from_fixture(args),
                originator,
            )
            .await
            .map(|result| result.fixture()),
        other => panic!("no linkage call {other}"),
    }
}

#[tokio::test]
async fn the_transceiver_writes_the_references_linkage_requests_and_reads_its_answers_406() {
    let vector = vector();
    let originator = text(&vector["originator"]);
    let cases = vector["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 6, "three cases per call");
    for case in cases {
        let name = text(&case["name"]);
        let request = Arc::default();
        let client = WalletWireTransceiver::new(Canned {
            response: bytes(&case["response_hex"]),
            request: Arc::clone(&request),
        });
        let result = call(&client, case, Some(originator))
            .await
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let sent = request.lock().unwrap().take().unwrap();
        assert_eq!(hex::encode(sent), text(&case["request_hex"]), "{name}");
        assert_eq!(result, case["result"], "{name}");
    }
}

#[tokio::test]
async fn the_processor_reads_the_references_linkage_requests_and_writes_its_answers_406() {
    let vector = vector();
    for case in vector["cases"].as_array().unwrap() {
        let name = text(&case["name"]);
        let stub = Stub::new(case["result"].clone());
        let observed = stub.observed.clone();
        let response = WalletWireProcessor::new(stub)
            .process_message(&bytes(&case["request_hex"]))
            .await
            .unwrap();
        assert_eq!(hex::encode(response), text(&case["response_hex"]), "{name}");
        let seen = observed.lock().unwrap().take().unwrap();
        let reference = &case["wallet_observed"];
        assert_eq!(seen["originator"], reference["originator"], "{name}");
        // The reference's wallet sees an absent privileged pair as absent
        // keys, the recording as `null`; the stub writes `null` too
        assert_eq!(seen["args"], reference["args"], "{name}");
    }
}

#[tokio::test]
async fn a_wallet_client_over_the_wire_sends_both_linkage_calls_406() {
    // `WalletClient`'s wire arm is a `WalletWireTransceiver<HttpWalletWire>`;
    // its default URL is a live wallet's port, so the same type is pointed at
    // an in-process server answering the reference's frames.
    let vector = vector();
    let originator = text(&vector["originator"]);
    for case in vector["cases"].as_array().unwrap() {
        let name = text(&case["name"]);
        let request = bytes(&case["request_hex"]);
        // The HTTP body is the frame after the call code and the originator
        let payload = request[2 + originator.len()..].to_vec();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(format!("/{}", text(&case["call"]))))
            .and(body_bytes(payload))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes(&case["response_hex"])))
            .expect(1)
            .mount(&server)
            .await;
        let wire = HttpWalletWire::new(Some(originator.into()), Some(server.uri())).unwrap();
        let client = WalletWireTransceiver::new(wire);
        let result = call(&client, case, Some(originator))
            .await
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(result, case["result"], "{name}");
    }
}

/// The one refusal made here in other words than the reference's: a key that
/// is no compressed point is refused by its check, where the reference's
/// `PublicKey.fromDER` throws its own parser's words.
const WORDS_DIFFER: [(&str, &str); 1] = [(
    "counterparty-prover-not-a-point",
    "Invalid revealCounterpartyKeyLinkage prover: expected a compressed secp256k1 public key",
)];

#[tokio::test]
async fn the_transceiver_refuses_the_linkage_answers_the_reference_refuses_406() {
    let vector = vector();
    let originator = text(&vector["originator"]);
    let refusals = vector["refusals"].as_array().unwrap();
    assert_eq!(refusals.len(), 8);
    for refusal in refusals {
        let name = text(&refusal["name"]);
        let case = vector["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["name"] == refusal["base"])
            .unwrap();
        let client = WalletWireTransceiver::new(Canned {
            response: bytes(&refusal["response_hex"]),
            request: Arc::default(),
        });
        let error = call(&client, case, Some(originator)).await.unwrap_err();
        let words = WORDS_DIFFER
            .iter()
            .find(|(differs, _)| *differs == name)
            .map_or_else(|| text(&refusal["thrown"]["message"]), |(_, words)| words);
        assert_eq!(error, Error::WalletError(words.to_string()), "{name}");
    }
}

#[tokio::test]
async fn the_transceiver_refuses_a_linkage_argument_before_sending_it_406() {
    let request = Arc::new(Mutex::new(None));
    let client = WalletWireTransceiver::new(Canned {
        response: vec![0],
        request: Arc::clone(&request),
    });
    let key = |n: u8| PrivateKey::from_bytes(&[n; 32]).unwrap().public_key();
    let error = client
        .reveal_counterparty_key_linkage(
            RevealCounterpartyKeyLinkageArgs {
                counterparty: key(3),
                verifier: key(5),
                privileged: Some(true),
                privileged_reason: Some("four".into()),
            },
            None,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(
            &error,
            Error::WalletRefusal { class: WalletRefusalClass::InvalidParameter, message }
                if message.starts_with("The privilegedReason parameter must be")
        ),
        "{error:?}"
    );
    assert!(request.lock().unwrap().is_none(), "nothing sent");
}

/// The two calls through the transceiver to the processor over a
/// `ProtoWallet`, the result the wallet's own.
#[tokio::test]
async fn a_proto_wallet_answers_both_linkage_calls_across_the_wire_406() {
    struct Loopback(WalletWireProcessor<ProtoWallet>);
    #[async_trait::async_trait]
    impl WalletWire for Loopback {
        async fn transmit_to_wallet(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
            self.0.process_message(message).await
        }
    }
    let prover = ProtoWallet::new(Some(PrivateKey::from_bytes(&[7; 32]).unwrap()));
    let identity = prover.identity_key();
    let client = WalletWireTransceiver::new(Loopback(WalletWireProcessor::new(prover)));
    let counterparty = PrivateKey::from_bytes(&[3; 32]).unwrap().public_key();
    let verifier = PrivateKey::from_bytes(&[5; 32]).unwrap().public_key();

    let RevealCounterpartyKeyLinkageResult { linkage, .. } = client
        .reveal_counterparty_key_linkage(
            RevealCounterpartyKeyLinkageArgs {
                counterparty: counterparty.clone(),
                verifier: verifier.clone(),
                privileged: None,
                privileged_reason: None,
            },
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        (&linkage.prover, &linkage.verifier, &linkage.counterparty),
        (&identity, &verifier, &counterparty)
    );

    let RevealSpecificKeyLinkageResult {
        linkage, key_id, ..
    } = client
        .reveal_specific_key_linkage(
            RevealSpecificKeyLinkageArgs {
                counterparty: Counterparty::Other(counterparty.clone()),
                verifier: verifier.clone(),
                protocol_id: bsv_rs::wallet::Protocol::new(
                    bsv_rs::wallet::SecurityLevel::App,
                    "fixture linkage",
                ),
                key_id: "key-1".into(),
                privileged: None,
                privileged_reason: None,
            },
            None,
        )
        .await
        .unwrap();
    assert_eq!((&linkage.prover, key_id.as_str()), (&identity, "key-1"));
}

/// Go's two linkage vectors (`go-sdk` `wallet/substrates/testdata/`, the
/// frames without an originator): the transceiver writes each args vector's
/// wire for its json and reads each result vector's wire to its json.
#[tokio::test]
async fn the_transceiver_writes_and_reads_gos_linkage_vectors_406() {
    let load = |name: &str| -> Value {
        let file = format!(
            "{}/tests/vectors/wallet_wire/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap()
    };
    for method in ["revealCounterpartyKeyLinkage", "revealSpecificKeyLinkage"] {
        let args = load(&format!("{method}-simple-args.json"));
        let result = load(&format!("{method}-simple-result.json"));
        let request = Arc::default();
        let client = WalletWireTransceiver::new(Canned {
            response: bytes(&result["wire"]),
            request: Arc::clone(&request),
        });
        let case = serde_json::json!({"call": method, "args": args["json"]});
        let read = call(&client, &case, None).await.unwrap();
        let sent = request.lock().unwrap().take().unwrap();
        assert_eq!(hex::encode(sent), text(&args["wire"]), "{method}");
        assert_eq!(read, result["json"], "{method}");
    }
}
