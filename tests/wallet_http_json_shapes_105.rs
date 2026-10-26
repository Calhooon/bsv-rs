//! The HTTP JSON substrate's certificate and key-linkage shapes are BRC-100's
//! and the reference's (Calhooon/bsv-rs#105): the certificate's type field is
//! `type` (BRC-100 at `5119a9b` `wallet/0100.md:1247`, `:1265`, `:1300`,
//! `:1332`, `:1365`; `ts-stack@edf6e03` `Wallet.interfaces.ts:837`, `:852`,
//! `:937`), not `certificateType`; the two linkage results are flat with the
//! linkage and its proof as byte arrays, and the specific one names the
//! protocol `protocolID` (a `[level, name]` pair) and the key `keyID`
//! (`0100.md:1011-1018`, `:1043-1052`; `Wallet.interfaces.ts:719-744`).
//!
//! The witnesses are `tests/vectors/wallet_http_json_shapes_105.json`,
//! recorded by `tests/support/http_json_shapes_105.mjs` against the
//! reference's `HTTPWalletJSON` at `ts-stack@edf6e03` under Node v22.18.0:
//! the body the reference sends for each case's args, what it returns for
//! the case's result, and what it makes of the bodies this crate writes.
//!
//! Run with: `cargo test --features "wallet,http" --test wallet_http_json_shapes_105`
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(all(feature = "wallet", feature = "http"))]

use bsv_rs::primitives::PublicKey;
use bsv_rs::wallet::substrates::HttpWalletJson;
use bsv_rs::wallet::{
    AcquireCertificateArgs, Counterparty, ListCertificatesArgs, Protocol, ProveCertificateArgs,
    RelinquishCertificateArgs, RevealCounterpartyKeyLinkageResult, RevealSpecificKeyLinkageResult,
    WalletCertificate, WalletRevealCounterpartyArgs, WalletRevealSpecificArgs,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORIGINATOR: &str = "fixtures.invalid";

fn vector() -> Value {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/wallet_http_json_shapes_105.json"
    ))
    .unwrap();
    serde_json::from_str(&text).unwrap()
}

fn json(text: &Value) -> Value {
    serde_json::from_str(text.as_str().unwrap()).unwrap()
}

fn key(value: &Value) -> PublicKey {
    PublicKey::from_hex(value.as_str().unwrap()).unwrap()
}

/// The args a case names, parsed by this crate's args type: the reference's
/// body read as a server built on this crate reads it.
fn parsed<T: DeserializeOwned>(case: &Value) -> T {
    serde_json::from_str(case["reference_request_body"].as_str().unwrap())
        .unwrap_or_else(|e| panic!("{}: the reference's request: {e}", case["name"]))
}

fn written<T: Serialize>(result: Result<T>) -> std::result::Result<String, String> {
    result
        .map(|r| serde_json::to_string(&r).unwrap())
        .map_err(|e| e.to_string())
}

type Result<T> = std::result::Result<T, bsv_rs::Error>;

/// Sends the case's call through `HttpWalletJson` to a server answering with
/// the case's result: the body this crate sent, and its result written back
/// to JSON (the body a server built on these types answers with).
async fn exchange(case: &Value) -> (String, std::result::Result<String, String>) {
    let call = case["call"].as_str().unwrap();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/{call}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(&case["result"]))
        .mount(&server)
        .await;
    let wallet = HttpWalletJson::new(None, Some(server.uri()));
    let args = &case["args"];
    let result = match call {
        "acquireCertificate" => written(
            wallet
                .acquire_certificate(parsed::<AcquireCertificateArgs>(case), ORIGINATOR)
                .await,
        ),
        "listCertificates" => written(
            wallet
                .list_certificates(parsed::<ListCertificatesArgs>(case), ORIGINATOR)
                .await,
        ),
        "proveCertificate" => written(
            wallet
                .prove_certificate(parsed::<ProveCertificateArgs>(case), ORIGINATOR)
                .await,
        ),
        "relinquishCertificate" => written(
            wallet
                .relinquish_certificate(parsed::<RelinquishCertificateArgs>(case), ORIGINATOR)
                .await,
        ),
        "revealCounterpartyKeyLinkage" => written(
            wallet
                .reveal_counterparty_key_linkage(
                    WalletRevealCounterpartyArgs {
                        counterparty: key(&args["counterparty"]),
                        verifier: key(&args["verifier"]),
                        privileged: None,
                        privileged_reason: None,
                    },
                    ORIGINATOR,
                )
                .await,
        ),
        "revealSpecificKeyLinkage" => written(
            wallet
                .reveal_specific_key_linkage(
                    WalletRevealSpecificArgs {
                        counterparty: Counterparty::Other(key(&args["counterparty"])),
                        verifier: key(&args["verifier"]),
                        protocol_id: Protocol::from_tuple((
                            args["protocolID"][0].as_u64().unwrap() as u8,
                            args["protocolID"][1].as_str().unwrap(),
                        ))
                        .unwrap(),
                        key_id: args["keyID"].as_str().unwrap().to_string(),
                        privileged: None,
                        privileged_reason: None,
                    },
                    ORIGINATOR,
                )
                .await,
        ),
        other => panic!("no call {other}"),
    };
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1, "{}", case["name"]);
    (String::from_utf8(requests[0].body.clone()).unwrap(), result)
}

/// The request this crate sends with the protocol and key named as the
/// reference names them: `protocolId` and `keyId` are #105's item 7
/// (`docs/FIXTURES.md` F5), the eight key-related calls' request names, not
/// this lane's.
fn with_item_7_names(mut request: Value) -> Value {
    let map = request.as_object_mut().unwrap();
    for (ours, theirs) in [("protocolId", "protocolID"), ("keyId", "keyID")] {
        if let Some(value) = map.remove(ours) {
            map.insert(theirs.to_string(), value);
        }
    }
    request
}

#[tokio::test]
async fn the_certificate_and_linkage_bodies_are_the_references() {
    for case in vector()["cases"].as_array().unwrap() {
        let name = &case["name"];
        let (sent, result) = exchange(case).await;
        assert_eq!(
            Some(sent.as_str()),
            case["crate_request_body"].as_str(),
            "{name}: the request body this crate sends"
        );
        assert_eq!(
            with_item_7_names(serde_json::from_str(&sent).unwrap()),
            json(&case["reference_request_body"]),
            "{name}: the request the reference sends for the same args"
        );
        let result = result.unwrap_or_else(|e| panic!("{name}: the reference's result: {e}"));
        assert_eq!(
            Some(result.as_str()),
            case["crate_result_body"].as_str(),
            "{name}: the result body this crate writes"
        );
        assert_eq!(
            serde_json::from_str::<Value>(&result).unwrap(),
            case["result"],
            "{name}: the reference's result read and written back"
        );
    }
}

#[test]
fn the_references_substrate_reads_this_crates_bodies() {
    for case in vector()["cases"].as_array().unwrap() {
        let name = &case["name"];
        assert_eq!(
            case["reference_reads_crate_result"], case["reference_result"],
            "{name}: the reference's client served this crate's result"
        );
        assert!(case.get("reference_refuses_crate_result").is_none());
        let resent = &case["reference_resends_crate_request"];
        if case["call"] == "revealSpecificKeyLinkage" {
            // #105's item 7: the request's `protocolId` and `keyId`
            assert_eq!(
                resent,
                "The protocolID parameter must be a [securityLevel, protocolName] tuple"
            );
        } else {
            assert_eq!(
                json(resent),
                json(&case["reference_request_body"]),
                "{name}: this crate's request taken as the reference's args and sent again"
            );
        }
    }
}

fn go_vector(file: &str) -> Value {
    let text = std::fs::read_to_string(format!(
        "{}/tests/vectors/wallet_wire/{file}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    serde_json::from_str::<Value>(&text).unwrap()["json"].clone()
}

fn reads_and_writes_back<T: Serialize + DeserializeOwned>(file: &str) {
    let json = go_vector(file);
    let value: T = serde_json::from_value(json.clone()).unwrap_or_else(|e| panic!("{file}: {e}"));
    assert_eq!(serde_json::to_value(&value).unwrap(), json, "{file}");
}

#[test]
fn the_go_vectors_certificate_args_read_as_this_crates_types() {
    reads_and_writes_back::<RelinquishCertificateArgs>("relinquishCertificate-simple-args.json");
    reads_and_writes_back::<WalletCertificate>("acquireCertificate-simple-result.json");
    // The two args vectors carry a `privileged: false` and a reason this
    // crate's args keep as given
    reads_and_writes_back::<AcquireCertificateArgs>("acquireCertificate-issuance-args.json");
    reads_and_writes_back::<ProveCertificateArgs>("proveCertificate-simple-args.json");
}

#[test]
fn the_go_vectors_linkage_results_read_flat_with_byte_arrays() {
    reads_and_writes_back::<RevealCounterpartyKeyLinkageResult>(
        "revealCounterpartyKeyLinkage-simple-result.json",
    );
    reads_and_writes_back::<RevealSpecificKeyLinkageResult>(
        "revealSpecificKeyLinkage-simple-result.json",
    );
    let specific: RevealSpecificKeyLinkageResult =
        serde_json::from_value(go_vector("revealSpecificKeyLinkage-simple-result.json")).unwrap();
    assert_eq!(specific.protocol.to_tuple(), (2, "tests"));
    assert_eq!(specific.key_id, "test-key-id");
    assert_eq!(specific.linkage.encrypted_linkage, [1, 2, 3, 4]);
    assert_eq!(specific.linkage.encrypted_linkage_proof, [5, 6, 7, 8]);
}

#[test]
fn a_linkage_result_in_hex_or_at_level_3_is_refused() {
    let mut hex = go_vector("revealCounterpartyKeyLinkage-simple-result.json");
    hex["encryptedLinkage"] = serde_json::json!("01020304");
    assert!(serde_json::from_value::<RevealCounterpartyKeyLinkageResult>(hex).is_err());
    let mut specific = go_vector("revealSpecificKeyLinkage-simple-result.json");
    specific["protocolID"] = serde_json::json!([3, "tests"]);
    assert!(serde_json::from_value::<RevealSpecificKeyLinkageResult>(specific).is_err());
}
