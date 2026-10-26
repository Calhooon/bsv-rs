//! The HTTP JSON substrate's shapes are BRC-100's and the reference's
//! (Calhooon/bsv-rs#105). The certificate's type field is
//! `type` (BRC-100 at `5119a9b` `wallet/0100.md:1247`, `:1265`, `:1300`,
//! `:1332`, `:1365`; `ts-stack@edf6e03` `Wallet.interfaces.ts:837`, `:852`,
//! `:937`), not `certificateType`; the two linkage results are flat with the
//! linkage and its proof as byte arrays, and the specific one names the
//! protocol `protocolID` (a `[level, name]` pair) and the key `keyID`
//! (`0100.md:1011-1018`, `:1043-1052`; `Wallet.interfaces.ts:719-744`).
//! A list or discovery entry carries the certificate's fields flat
//! (`0100.md:1299-1307`, `:1393-1411`, `:1436-1454`; `Wallet.interfaces.ts:877-903`)
//! and `keyringRevealer` is `'certifier'` or the key's hex (`0100.md:1255`;
//! `Wallet.interfaces.ts:233`). The action calls carry their transactions as
//! arrays of byte numbers (`inputBEEF`, `tx`, `signableTransaction.tx`), their
//! txids as hex, `returnTXIDOnly` and the signable reference as base64
//! (`0100.md:674-720`, `:744-763`, `:876-877`; `Wallet.interfaces.ts:340-445`,
//! `:601-602`); the eight key-related requests name `protocolID` and `keyID`,
//! the direct hashes arrays of byte numbers (`0100.md:1037-1038`,
//! `:1182-1184`, `:1213-1216`; `Wallet.interfaces.ts:665-667`, `:798`, `:813`).
//! The action cases' transactions are this crate's writer's
//! (`the_action_witnesses_are_this_crates_bytes`).
//!
//! The witnesses are `tests/vectors/wallet_http_json_shapes_105.json`,
//! recorded by `tests/support/http_json_shapes_105.mjs` against the
//! reference's `HTTPWalletJSON` at `ts-stack@edf6e03` under Node v22.18.0:
//! the body the reference sends for each case's args, what it returns for
//! the case's result, and what it makes of the bodies this crate writes.
//!
//! Run with: `cargo test --features "wallet,http" --test wallet_http_json_shapes_105`.
//! `BSV_SHAPES_105_RECORD=<dir>` writes this crate's transactions and bodies
//! to `<dir>/<test>.json` as `[case, JSON pointer, value]` patches instead of
//! comparing them; the script applies them to the vector (`--patch`), so the
//! vector has one writer and keeps its order.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(all(feature = "wallet", feature = "http"))]

#[allow(dead_code)]
#[path = "support/fixtures/wallet_json.rs"]
mod wallet_json;

use bsv_rs::primitives::PublicKey;
use bsv_rs::script::{LockingScript, UnlockingScript};
use bsv_rs::transaction::{Beef, MerklePath, Transaction, TransactionInput, TransactionOutput};
use bsv_rs::wallet::substrates::HttpWalletJson;
use bsv_rs::wallet::*;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;
use wallet_json::FixtureJson;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORIGINATOR: &str = "fixtures.invalid";

const VECTOR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/wallet_http_json_shapes_105.json"
);

fn vector() -> Value {
    serde_json::from_str(&std::fs::read_to_string(VECTOR).unwrap()).unwrap()
}

fn recording() -> Option<String> {
    std::env::var("BSV_SHAPES_105_RECORD").ok()
}

fn record(test: &str, patches: Vec<Value>) {
    let dir = recording().unwrap();
    let text = serde_json::to_string(&patches).unwrap();
    std::fs::write(format!("{dir}/{test}.json"), text).unwrap();
}

/// The action cases' transactions, written by this crate: a parent of one
/// 1,000-satoshi `OP_1` output, proven alone in a block at height 800,000
/// (the reference's internalizeAction asks for a complete atomic BEEF), and
/// its child spending it to one 900-satoshi `OP_1` output, unsigned (an empty
/// unlocking script) and signed (`OP_1`).
/// `inputBEEF` is the parent's BEEF; `signable` and `signed` the child's
/// atomic BEEF with the parent.
fn witness_bytes() -> Vec<(&'static str, Vec<u8>)> {
    let op_1 = || LockingScript::from_binary(&[0x51]).unwrap();
    let mut parent = Transaction::new();
    let mut funding = TransactionInput::new("44".repeat(32), 0);
    funding.unlocking_script = Some(UnlockingScript::from_binary(&[0x51]).unwrap());
    parent.add_input(funding).unwrap();
    parent
        .add_output(TransactionOutput::new(1000, op_1()))
        .unwrap();
    let proof = MerklePath::from_coinbase_txid(&parent.id(), 800_000);
    let with_parent = || {
        let mut beef = Beef::new();
        beef.merge_bump(proof.clone());
        beef.merge_transaction(parent.clone());
        beef
    };
    let child = |unlocking: &[u8]| {
        let mut child = Transaction::new();
        let mut input = TransactionInput::with_source_transaction(parent.clone(), 0);
        input.unlocking_script = Some(UnlockingScript::from_binary(unlocking).unwrap());
        child.add_input(input).unwrap();
        child
            .add_output(TransactionOutput::new(900, op_1()))
            .unwrap();
        let mut beef = with_parent();
        beef.merge_transaction(child.clone());
        beef.to_binary_atomic(&child.id()).unwrap()
    };
    vec![
        ("inputBEEF", with_parent().to_binary()),
        ("signable", child(&[])),
        ("signed", child(&[0x51])),
    ]
}

/// Where each action case carries a witness transaction, as a JSON pointer
/// into the case and the witness's name.
const WITNESS_PLACES: &[(&str, &str, &str)] = &[
    ("createAction-signable", "/args/inputBEEF", "inputBEEF"),
    (
        "createAction-signable",
        "/result/signableTransaction/tx",
        "signable",
    ),
    ("createAction-completed", "/args/inputBEEF", "inputBEEF"),
    ("createAction-completed", "/result/tx", "signed"),
    ("signAction", "/result/tx", "signed"),
    ("internalizeAction", "/args/tx", "signed"),
];

fn txid_of(atomic: &[u8]) -> String {
    Transaction::from_atomic_beef(atomic).unwrap().id()
}

#[test]
fn the_action_witnesses_are_this_crates_bytes() {
    let vector = vector();
    let witnesses = witness_bytes();
    let bytes = |name: &str| &witnesses.iter().find(|(n, _)| *n == name).unwrap().1;
    let mut patches = Vec::new();
    for (case_name, pointer, witness) in WITNESS_PLACES {
        let case = vector["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == *case_name)
            .unwrap_or_else(|| panic!("no case {case_name}"));
        let expected = serde_json::json!(bytes(witness));
        if recording().is_some() {
            patches.push(serde_json::json!([case_name, pointer, expected]));
        } else {
            assert_eq!(
                case.pointer(pointer),
                Some(&expected),
                "{case_name} {pointer}"
            );
        }
    }
    // The results' txid is the signed child's
    let signed = txid_of(bytes("signed"));
    for case in vector["cases"].as_array().unwrap() {
        if let Some(txid) = case["result"]["txid"].as_str() {
            assert_eq!(txid, signed, "{}", case["name"]);
        }
    }
    if recording().is_some() {
        record("witnesses", patches);
    }
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

/// A key-related result written by the fixtures' adapter.
fn written_fixture<T: FixtureJson>(result: Result<T>) -> std::result::Result<String, String> {
    result
        .map(|r| serde_json::to_string(&r.fixture()).unwrap())
        .map_err(|e| e.to_string())
}

type Result<T> = std::result::Result<T, bsv_rs::Error>;

/// Sends the case's call through `HttpWalletJson` to a server answering with
/// the case's result: the body this crate sent, and its result written back
/// to JSON (the body a server built on these types answers with).
async fn exchange(case: &Value) -> (String, std::result::Result<String, String>) {
    let args = &case["args"];
    let call = case["call"].as_str().unwrap();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/{call}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(&case["result"]))
        .mount(&server)
        .await;
    let wallet = HttpWalletJson::new(None, Some(server.uri()));
    // A key-related call's args and result as the fixtures' adapters read
    // and write them in the reference's names
    macro_rules! key_call {
        ($method:ident, $args:ty) => {
            written_fixture(
                wallet
                    .$method(<$args>::from_fixture(args.clone()), ORIGINATOR)
                    .await,
            )
        };
    }
    let result = match call {
        "createAction" => written(
            wallet
                .create_action(parsed::<CreateActionArgs>(case), ORIGINATOR)
                .await,
        ),
        "signAction" => written(
            wallet
                .sign_action(parsed::<SignActionArgs>(case), ORIGINATOR)
                .await,
        ),
        "internalizeAction" => written(
            wallet
                .internalize_action(parsed::<InternalizeActionArgs>(case), ORIGINATOR)
                .await,
        ),
        "discoverByIdentityKey" => written(
            wallet
                .discover_by_identity_key(parsed::<DiscoverByIdentityKeyArgs>(case), ORIGINATOR)
                .await,
        ),
        "getPublicKey" => key_call!(get_public_key, GetPublicKeyArgs),
        "encrypt" => key_call!(encrypt, EncryptArgs),
        "decrypt" => key_call!(decrypt, DecryptArgs),
        "createHmac" => key_call!(create_hmac, CreateHmacArgs),
        "verifyHmac" => key_call!(verify_hmac, VerifyHmacArgs),
        "createSignature" => key_call!(create_signature, CreateSignatureArgs),
        "verifySignature" => key_call!(verify_signature, VerifySignatureArgs),
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

#[tokio::test]
async fn the_bodies_are_the_references() {
    let mut vector = vector();
    let mut patches = Vec::new();
    for case in vector["cases"].as_array_mut().unwrap() {
        let name = case["name"].clone();
        let (sent, result) = exchange(case).await;
        let result = result.unwrap_or_else(|e| panic!("{name}: the reference's result: {e}"));
        if recording().is_some() {
            patches.push(serde_json::json!([name, "/crate_request_body", sent]));
            patches.push(serde_json::json!([name, "/crate_result_body", result]));
            case["crate_request_body"] = Value::String(sent.clone());
            case["crate_result_body"] = Value::String(result.clone());
        }
        assert_eq!(
            Some(sent.as_str()),
            case["crate_request_body"].as_str(),
            "{name}: the request body this crate sends"
        );
        assert_eq!(
            serde_json::from_str::<Value>(&sent).unwrap(),
            json(&case["reference_request_body"]),
            "{name}: the request the reference sends for the same args"
        );
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
    if recording().is_some() {
        record("bodies", patches);
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
        assert_eq!(
            json(&case["reference_resends_crate_request"]),
            json(&case["reference_request_body"]),
            "{name}: this crate's request taken as the reference's args and sent again"
        );
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

#[test]
fn the_go_vectors_action_and_entry_json_read_as_this_crates_types() {
    // internalizeAction's `tx` an array of byte numbers; a public-key
    // `keyringRevealer`; the list and discovery entries flat
    reads_and_writes_back::<InternalizeActionArgs>("internalizeAction-simple-args.json");
    reads_and_writes_back::<AcquireCertificateArgs>("acquireCertificate-simple-args.json");
    reads_and_writes_back::<ListCertificatesResult>("listCertificates-simple-result.json");
    reads_and_writes_back::<ListCertificatesResult>("listCertificates-full-result.json");
    reads_and_writes_back::<DiscoverCertificatesResult>("discoverByIdentityKey-simple-result.json");
    reads_and_writes_back::<DiscoverCertificatesResult>("discoverByAttributes-simple-result.json");
    reads_and_writes_back::<CreateActionArgs>("createAction-1-out-args.json");
    reads_and_writes_back::<SignActionArgs>("signAction-simple-args.json");
    let args: AcquireCertificateArgs =
        serde_json::from_value(go_vector("acquireCertificate-simple-args.json")).unwrap();
    assert!(matches!(
        args.keyring_revealer,
        Some(KeyringRevealer::PublicKey(key)) if key.to_hex().starts_with("025ad43a")
    ));
}

#[test]
fn a_keyring_revealer_is_certifier_or_a_key() {
    let read = |v: Value| serde_json::from_value::<KeyringRevealer>(v);
    assert!(matches!(
        read("certifier".into()),
        Ok(KeyringRevealer::Certifier)
    ));
    assert_eq!(
        serde_json::to_value(KeyringRevealer::Certifier).unwrap(),
        "certifier"
    );
    // The externally tagged form this crate wrote until #105, and a string
    // that is no key, are refused
    let key = "025ad43a22ac38d0bc1f8bacaabb323b5d634703b7a774c4268f6a09e4ddf79097";
    assert!(read(serde_json::json!({ "publicKey": key })).is_err());
    assert!(read("anyone".into()).is_err());
    let revealer = read(key.into()).unwrap();
    assert_eq!(serde_json::to_value(&revealer).unwrap(), key);
}
