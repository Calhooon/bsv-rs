//! #1002: the wallet wire's flag bytes and optional scalars against the
//! reference's recorded frames (`vectors/wallet_wire/flags_1002.json`,
//! `support/wire_flags_1002.mjs`: the unmodified `WalletWireTransceiver` and
//! `WalletWireProcessor` of `ts-stack@edf6e03` under Node v22.18.0, two runs
//! byte-identical).
//!
//! The instance: listActions' `labelQueryMode` is -1 absent, 1 `any`, 2 `all`
//! (`WalletWireTransceiver.ts:357-360`, `WalletWireProcessor.ts:830-841`),
//! where this crate wrote and read 0 and 1. The class: every request frame of
//! the recording written by this crate's transceiver, every result frame read
//! by it, every flag byte outside its range refused in the reference's words,
//! and the public mode helpers of `WireReader`/`WireWriter` set beside the
//! recorded byte.
#![cfg(feature = "wallet")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::primitives::{PrivateKey, PublicKey};
use bsv_rs::wallet::interface::{RevealCounterpartyKeyLinkageArgs, RevealSpecificKeyLinkageArgs};
use bsv_rs::wallet::wire::{
    WalletWire, WalletWireProcessor, WalletWireTransceiver, WireReader, WireWriter,
};
use bsv_rs::wallet::{
    AcquireCertificateArgs, ActionStatus, Counterparty, CreateActionArgs, CreateHmacArgs,
    CreateSignatureArgs, DecryptArgs, DiscoverByAttributesArgs, DiscoverByIdentityKeyArgs,
    EncryptArgs, GetPublicKeyArgs, InternalizeActionArgs, ListActionsArgs, ListActionsResult,
    ListCertificatesArgs, ListOutputsArgs, ListOutputsResult, OutputInclude, ProtoWallet, Protocol,
    ProveCertificateArgs, QueryMode, SecurityLevel, SignActionArgs, VerifyHmacArgs,
    VerifySignatureArgs,
};
use bsv_rs::Error;
use serde_json::{json, Value};
use std::sync::Mutex;

fn vector() -> Value {
    let vector: Value =
        serde_json::from_str(include_str!("vectors/wallet_wire/flags_1002.json")).unwrap();
    assert_eq!(vector["reference"], "ts-stack@edf6e03 (unmodified)");
    assert_eq!(vector["node"], "v22.18.0");
    vector
}

fn rows(group: &str, count: usize) -> Vec<Value> {
    let rows = vector()[group].as_array().unwrap().clone();
    assert_eq!(rows.len(), count, "{group}");
    rows
}

fn unhex(row: &Value, member: &str) -> Vec<u8> {
    hex::decode(row[member].as_str().unwrap()).unwrap()
}

fn text(value: &Value) -> &str {
    value.as_str().unwrap()
}

/// A transport that keeps the request frame and answers nothing.
#[derive(Default)]
struct Capture(Mutex<Option<Vec<u8>>>);

#[async_trait::async_trait]
impl WalletWire for &Capture {
    async fn transmit_to_wallet(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        *self.0.lock().unwrap() = Some(message.to_vec());
        Err(Error::WalletError("captured".into()))
    }
}

/// A transport that answers one recorded response.
struct Serve(Vec<u8>);

#[async_trait::async_trait]
impl WalletWire for Serve {
    async fn transmit_to_wallet(&self, _: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.0.clone())
    }
}

fn protocol(args: &Value) -> Protocol {
    let level = SecurityLevel::from_u8(args["protocolID"][0].as_u64().unwrap() as u8).unwrap();
    Protocol::new(level, text(&args["protocolID"][1]))
}

fn counterparty(args: &Value) -> Option<Counterparty> {
    match args["counterparty"].as_str() {
        None => None,
        Some("self") => Some(Counterparty::Self_),
        Some("anyone") => Some(Counterparty::Anyone),
        Some(key) => Some(Counterparty::Other(PublicKey::from_hex(key).unwrap())),
    }
}

fn bytes(value: &Value) -> Vec<u8> {
    serde_json::from_value(value.clone()).unwrap()
}

fn array32(value: &Value) -> [u8; 32] {
    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes(value));
    array
}

/// Calls this crate's transceiver with the row's call and args. The three
/// key calls' args carry no serde form and are built from the JSON here.
async fn call<W: WalletWire>(
    client: &WalletWireTransceiver<W>,
    name: &str,
    args: &Value,
) -> Result<Value, Error> {
    fn typed<T: serde::de::DeserializeOwned>(args: &Value) -> T {
        serde_json::from_value(args.clone()).unwrap_or_else(|error| panic!("{args}: {error}"))
    }
    fn json<T: serde::Serialize>(value: T) -> Value {
        serde_json::to_value(value).unwrap()
    }
    Ok(match name {
        "listActions" => json(
            client
                .list_actions(typed::<ListActionsArgs>(args), None)
                .await?,
        ),
        "listOutputs" => json(
            client
                .list_outputs(typed::<ListOutputsArgs>(args), None)
                .await?,
        ),
        "createAction" => json(
            client
                .create_action(typed::<CreateActionArgs>(args), None)
                .await?,
        ),
        "signAction" => json(
            client
                .sign_action(typed::<SignActionArgs>(args), None)
                .await?,
        ),
        "internalizeAction" => json(
            client
                .internalize_action(typed::<InternalizeActionArgs>(args), None)
                .await?,
        ),
        "acquireCertificate" => json(
            client
                .acquire_certificate(typed::<AcquireCertificateArgs>(args), None)
                .await?,
        ),
        "listCertificates" => json(
            client
                .list_certificates(typed::<ListCertificatesArgs>(args), None)
                .await?,
        ),
        "discoverByIdentityKey" => json(
            client
                .discover_by_identity_key(typed::<DiscoverByIdentityKeyArgs>(args), None)
                .await?,
        ),
        "discoverByAttributes" => json(
            client
                .discover_by_attributes(typed::<DiscoverByAttributesArgs>(args), None)
                .await?,
        ),
        "getPublicKey" => {
            let keyed = args.get("protocolID").is_some();
            let result = client
                .get_public_key(
                    GetPublicKeyArgs {
                        identity_key: args["identityKey"].as_bool().unwrap_or(false),
                        protocol_id: keyed.then(|| protocol(args)),
                        key_id: args["keyID"].as_str().map(str::to_string),
                        counterparty: counterparty(args),
                        for_self: args["forSelf"].as_bool(),
                        privileged: args["privileged"].as_bool(),
                        privileged_reason: args["privilegedReason"].as_str().map(str::to_string),
                        seek_permission: args["seekPermission"].as_bool(),
                    },
                    None,
                )
                .await?;
            json!({ "publicKey": result.public_key })
        }
        "createSignature" => {
            let hash = args.get("hashToDirectlySign").map(array32);
            let result = client
                .create_signature(
                    CreateSignatureArgs {
                        data: args.get("data").map(bytes),
                        hash_to_directly_sign: hash,
                        protocol_id: protocol(args),
                        key_id: text(&args["keyID"]).to_string(),
                        counterparty: counterparty(args),
                        ..Default::default()
                    },
                    None,
                )
                .await?;
            json!({ "signature": result.signature })
        }
        "encrypt" => {
            let result = client
                .encrypt(
                    EncryptArgs {
                        plaintext: bytes(&args["plaintext"]),
                        protocol_id: protocol(args),
                        key_id: text(&args["keyID"]).to_string(),
                        counterparty: counterparty(args),
                        seek_permission: args["seekPermission"].as_bool(),
                        ..Default::default()
                    },
                    None,
                )
                .await?;
            json!({ "ciphertext": result.ciphertext })
        }
        "decrypt" => {
            let args = DecryptArgs {
                ciphertext: bytes(&args["ciphertext"]),
                protocol_id: protocol(args),
                key_id: text(&args["keyID"]).to_string(),
                seek_permission: args["seekPermission"].as_bool(),
                ..Default::default()
            };
            json!({ "plaintext": client.decrypt(args, None).await?.plaintext })
        }
        "createHmac" => {
            let args = CreateHmacArgs {
                data: bytes(&args["data"]),
                protocol_id: protocol(args),
                key_id: text(&args["keyID"]).to_string(),
                ..Default::default()
            };
            json!({ "hmac": client.create_hmac(args, None).await?.hmac })
        }
        "verifyHmac" => {
            let args = VerifyHmacArgs {
                data: bytes(&args["data"]),
                hmac: array32(&args["hmac"]),
                protocol_id: protocol(args),
                key_id: text(&args["keyID"]).to_string(),
                seek_permission: args["seekPermission"].as_bool(),
                ..Default::default()
            };
            json!({ "valid": client.verify_hmac(args, None).await?.valid })
        }
        "verifySignature" => {
            let args = VerifySignatureArgs {
                data: args.get("data").map(bytes),
                hash_to_directly_verify: args.get("hashToDirectlyVerify").map(array32),
                signature: bytes(&args["signature"]),
                protocol_id: protocol(args),
                key_id: text(&args["keyID"]).to_string(),
                for_self: args["forSelf"].as_bool(),
                seek_permission: args["seekPermission"].as_bool(),
                ..Default::default()
            };
            json!({ "valid": client.verify_signature(args, None).await?.valid })
        }
        "revealCounterpartyKeyLinkage" => {
            let args = RevealCounterpartyKeyLinkageArgs {
                counterparty: PublicKey::from_hex(text(&args["counterparty"])).unwrap(),
                verifier: PublicKey::from_hex(text(&args["verifier"])).unwrap(),
                privileged: args["privileged"].as_bool(),
                privileged_reason: args["privilegedReason"].as_str().map(str::to_string),
            };
            client.reveal_counterparty_key_linkage(args, None).await?;
            json!({})
        }
        "revealSpecificKeyLinkage" => {
            let args = RevealSpecificKeyLinkageArgs {
                counterparty: counterparty(args).unwrap(),
                verifier: PublicKey::from_hex(text(&args["verifier"])).unwrap(),
                protocol_id: protocol(args),
                key_id: text(&args["keyID"]).to_string(),
                privileged: args["privileged"].as_bool(),
                privileged_reason: args["privilegedReason"].as_str().map(str::to_string),
            };
            client.reveal_specific_key_linkage(args, None).await?;
            json!({})
        }
        "proveCertificate" => json(
            client
                .prove_certificate(typed::<ProveCertificateArgs>(args), None)
                .await?,
        ),
        "isAuthenticated" => json!({ "authenticated": client.is_authenticated(None).await? }),
        "getNetwork" => {
            json!({ "network": client.get_network(None).await?.as_str() })
        }
        other => panic!("unrecorded call {other}"),
    })
}

/// The request frame this crate's transceiver writes for the row.
async fn written(row: &Value) -> Vec<u8> {
    let capture = Capture::default();
    let client = WalletWireTransceiver::new(&capture);
    let outcome = call(&client, text(&row["call"]), &row["args"]).await;
    let frame = capture.0.lock().unwrap().take();
    frame.unwrap_or_else(|| panic!("{}: nothing was sent: {outcome:?}", row["name"]))
}

/// This crate's transceiver's reading of the row's recorded response.
async fn read(row: &Value) -> Result<Value, Error> {
    let client = WalletWireTransceiver::new(Serve(unhex(row, "response_hex")));
    call(&client, text(&row["call"]), &row["args"]).await
}

fn words(error: &Error) -> String {
    match error {
        Error::WalletError(words) => words.clone(),
        other => panic!("not a wallet error: {other:?}"),
    }
}

/// An error frame's code and words.
fn refusal(frame: &[u8]) -> (u8, String) {
    let mut reader = WireReader::new(frame);
    let code = reader.read_u8().unwrap();
    assert_ne!(code, 0, "a success frame");
    (code, reader.read_string().unwrap())
}

fn group<'a>(rows: &'a [Value], name: &str) -> Vec<&'a Value> {
    let found: Vec<_> = rows.iter().filter(|row| row["group"] == name).collect();
    assert!(!found.is_empty(), "{name}");
    found
}

fn flag(rows: &[Value], group_name: &str, state: &str) -> u8 {
    let row = group(rows, group_name)
        .into_iter()
        .find(|row| row["state"] == state)
        .unwrap_or_else(|| panic!("{group_name}: {state}"));
    hex::decode(text(&row["byte_hex"])).unwrap()[0]
}

const REQUEST_ROWS: usize = 61;
const LABEL_QUERY_MODE: &str = "listActions labelQueryMode";

// ---------------------------------------------------------------------------
// The instance
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_actions_writes_label_query_mode_as_the_reference_does_1002() {
    let requests = rows("request_rows", REQUEST_ROWS);
    let states = group(&requests, LABEL_QUERY_MODE);
    assert_eq!(states.len(), 3);
    for row in states {
        assert_eq!(
            hex::encode(written(row).await),
            text(&row["request_hex"]),
            "{}",
            row["name"]
        );
    }
    let flags = rows("request_flag_rows", 29);
    assert_eq!(flag(&flags, LABEL_QUERY_MODE, "absent"), 0xff);
    assert_eq!(flag(&flags, LABEL_QUERY_MODE, "any"), 1);
    assert_eq!(flag(&flags, LABEL_QUERY_MODE, "all"), 2);
}

/// What an honest caller saw before #1002: the bytes this crate wrote, read
/// by the reference's processor. `any` was refused and `all` was read as
/// `any`; no frame this crate writes now is one of those two.
#[tokio::test]
async fn the_frames_written_before_1002_are_refused_or_misread_by_the_reference_1002() {
    let base = rows("crate_base_rows", 3);
    let requests = rows("request_rows", REQUEST_ROWS);
    for row in &base {
        let state = text(&row["state"]);
        let now = group(&requests, LABEL_QUERY_MODE)
            .into_iter()
            .find(|request| request["state"] == state)
            .unwrap();
        let frame = hex::encode(written(now).await);
        match state {
            "absent" => {
                assert_eq!(frame, text(&row["request_hex"]));
                assert!(row["observed"].get("labelQueryMode").is_none());
            }
            "any" => {
                assert_ne!(frame, text(&row["request_hex"]));
                assert!(
                    row["observed"].is_null(),
                    "the reference's wallet was not called"
                );
                assert_eq!(
                    refusal(&unhex(row, "response_hex")),
                    (
                        1,
                        "Invalid labelQueryMode flag: expected -1, 1, or 2, received 0".to_string()
                    )
                );
            }
            "all" => {
                assert_ne!(frame, text(&row["request_hex"]));
                assert_eq!(row["observed"]["labelQueryMode"], "any");
            }
            other => panic!("unrecorded state {other}"),
        }
    }
}

/// The reader of the byte in this crate: `WireReader::read_optional_query_mode`
/// (the processor's listActions is a stub, so no handler reads it).
#[test]
fn the_label_query_mode_reader_reads_the_byte_as_the_reference_processor_does_1002() {
    let requests = rows("request_rows", REQUEST_ROWS);
    let flags = rows("request_flag_rows", 29);
    for row in group(&requests, LABEL_QUERY_MODE) {
        let byte = flag(&flags, LABEL_QUERY_MODE, text(&row["state"]));
        let expected = match row["observed"]
            .get("labelQueryMode")
            .and_then(Value::as_str)
        {
            None => None,
            Some("any") => Some(QueryMode::Any),
            Some("all") => Some(QueryMode::All),
            Some(other) => panic!("unrecorded mode {other}"),
        };
        assert_eq!(
            WireReader::new(&[byte]).read_optional_query_mode().unwrap(),
            expected,
            "{}",
            row["name"]
        );
    }
    let refused = rows("processor_refusal_rows", PROCESSOR_REFUSALS);
    let mut seen = 0;
    for row in refused
        .iter()
        .filter(|row| text(&row["name"]).starts_with(LABEL_QUERY_MODE))
    {
        let request = unhex(row, "request_hex");
        let offset = flags
            .iter()
            .find(|flag| flag["group"] == LABEL_QUERY_MODE)
            .unwrap()["offset"]
            .as_u64()
            .unwrap() as usize;
        let error = WireReader::new(&request[offset..=offset])
            .read_optional_query_mode()
            .unwrap_err();
        assert_eq!(
            (1, words(&error)),
            refusal(&unhex(row, "response_hex")),
            "{}",
            row["name"]
        );
        seen += 1;
    }
    assert_eq!(seen, 3);
}

// ---------------------------------------------------------------------------
// The class: requests
// ---------------------------------------------------------------------------

/// Every recorded request frame, each a flag or an optional scalar in one of
/// its states, is the frame this crate's transceiver writes for the same args.
#[tokio::test]
async fn every_recorded_request_frame_is_the_frame_this_crate_writes_1002() {
    for row in rows("request_rows", REQUEST_ROWS) {
        assert_eq!(
            hex::encode(written(&row).await),
            text(&row["request_hex"]),
            "{}",
            row["name"]
        );
        assert!(
            !row["observed"].is_null(),
            "{}: the reference read it",
            row["name"]
        );
    }
}

const PROCESSOR_REFUSALS: usize = 26;

/// A request flag outside its range, served to this crate's processor: the
/// reference's error frame byte for byte, for every call this processor
/// reads. The twelve calls it answers as needing a full wallet read no flag.
#[tokio::test]
async fn the_processor_refuses_a_request_flag_outside_its_range_in_the_reference_frame_1002() {
    let processor = WalletWireProcessor::new(ProtoWallet::new(Some(
        PrivateKey::from_hex(&"07".repeat(32)).unwrap(),
    )));
    let mut read_here = Vec::new();
    for row in rows("processor_refusal_rows", PROCESSOR_REFUSALS) {
        assert_eq!(row["wallet_called"], false, "{}", row["name"]);
        let call = text(&row["call"]);
        let response = processor
            .process_message(&unhex(&row, "request_hex"))
            .await
            .unwrap();
        if matches!(
            call,
            "getPublicKey" | "createSignature" | "encrypt" | "verifySignature"
        ) {
            assert_eq!(
                hex::encode(&response),
                text(&row["response_hex"]),
                "{}: {:?} for {:?}",
                row["name"],
                refusal(&response),
                refusal(&unhex(&row, "response_hex"))
            );
            read_here.push(text(&row["name"]).to_string());
        } else {
            let (code, words) = refusal(&response);
            assert_eq!(
                (code, words),
                (1, format!("{call} requires a full wallet implementation")),
                "{}",
                row["name"]
            );
        }
    }
    assert_eq!(
        read_here,
        [
            "getPublicKey forSelf = 2",
            "getPublicKey privileged = 2",
            "getPublicKey identityKey = 2",
            "getPublicKey identityKey = 255",
            "getPublicKey privilegedReason length = -2",
            "createSignature data type = 3",
            "getPublicKey seekPermission = 2",
            "encrypt seekPermission = 2",
            "verifySignature forSelf = 2",
        ]
    );
}

// ---------------------------------------------------------------------------
// The class: results
// ---------------------------------------------------------------------------

const RESPONSE_ROWS: usize = 33;

fn without_nulls(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .filter(|(_, member)| !member.is_null())
                .map(|(name, member)| (name.clone(), without_nulls(member)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(without_nulls).collect()),
        other => other.clone(),
    }
}

/// Every recorded result frame is read by this crate's transceiver to the
/// value the reference's transceiver read: the status, the booleans, the
/// presence flags, an absent list apart from an empty one.
#[tokio::test]
async fn every_recorded_result_frame_reads_to_the_reference_value_1002() {
    for row in rows("response_rows", RESPONSE_ROWS) {
        assert!(row["message"].is_null(), "{}", row["name"]);
        let actual = read(&row)
            .await
            .unwrap_or_else(|error| panic!("{}: {error}", row["name"]));
        let actual = without_nulls(&actual);
        let recorded = &row["value"];
        match text(&row["call"]) {
            "listActions" | "listOutputs" | "isAuthenticated" | "getNetwork" => {
                assert_eq!(&actual, recorded, "{}", row["name"]);
            }
            "createAction" | "signAction" => {
                for member in ["txid", "tx", "signableTransaction"] {
                    assert_eq!(
                        actual.get(member),
                        recorded.get(member),
                        "{}: {member}",
                        row["name"]
                    );
                }
            }
            "listCertificates" => {
                // The reference's reader answers an empty keyring for flag 0;
                // this crate's type says `None` there.
                let certificate = &actual["certificates"][0];
                let reference = &recorded["certificates"][0];
                let keyring = certificate.get("keyring").cloned().unwrap_or(json!({}));
                assert_eq!(keyring, reference["keyring"], "{}", row["name"]);
                assert_eq!(
                    certificate.get("verifier"),
                    reference.get("verifier"),
                    "{}",
                    row["name"]
                );
            }
            other => panic!("unrecorded call {other}"),
        }
    }
}

const TRANSCEIVER_REFUSALS: usize = 28;

async fn refused_as_recorded(prefixes: &[&str], count: usize) {
    let refusals = rows("transceiver_refusal_rows", TRANSCEIVER_REFUSALS);
    let chosen: Vec<_> = refusals
        .iter()
        .filter(|row| {
            prefixes
                .iter()
                .any(|prefix| text(&row["name"]).starts_with(prefix))
        })
        .collect();
    assert_eq!(chosen.len(), count, "{prefixes:?}");
    for row in chosen {
        assert!(row["value"].is_null(), "{}", row["name"]);
        match read(row).await {
            Ok(value) => panic!("{}: read as {value}", row["name"]),
            Err(error) => assert_eq!(words(&error), text(&row["message"]), "{}", row["name"]),
        }
    }
}

#[tokio::test]
async fn a_presence_flag_of_an_action_result_other_than_0_or_1_is_refused_1002() {
    refused_as_recorded(&["createAction ", "signAction "], 10).await;
}

#[tokio::test]
async fn a_listed_action_status_outside_1_to_8_is_refused_1002() {
    refused_as_recorded(&["listActions status"], 3).await;
}

#[tokio::test]
async fn a_listed_action_boolean_other_than_0_or_1_is_refused_1002() {
    refused_as_recorded(
        &["listActions isOutgoing", "listActions output spendable"],
        4,
    )
    .await;
}

#[tokio::test]
async fn an_authentication_verdict_is_exactly_one_byte_0_or_1_1002() {
    refused_as_recorded(&["isAuthenticated"], 4).await;
}

#[tokio::test]
async fn a_network_answer_is_exactly_one_byte_0_or_1_1002() {
    refused_as_recorded(&["getNetwork"], 4).await;
}

/// An agreement pin: the keyring flag was read as the reference reads it
/// before #1002 (#183).
#[tokio::test]
async fn a_keyring_flag_other_than_0_or_1_is_refused_1002() {
    refused_as_recorded(&["listCertificates keyring present"], 2).await;
}

/// The verifier is absent (length 0) or 33 bytes: another length refused in
/// the reference's words (its capital until #1002 lower case here).
#[tokio::test]
async fn a_verifier_length_other_than_0_or_33_is_refused_1002() {
    refused_as_recorded(&["listCertificates verifier length"], 1).await;
}

// ---------------------------------------------------------------------------
// The class: the public writers of a result
// ---------------------------------------------------------------------------

/// The result frame this crate's public writers build for the answer the
/// reference's wallet gave (`00`, the total, then each entry).
fn result_frame(row: &Value) -> Vec<u8> {
    let mut writer = WireWriter::new();
    writer.write_u8(0);
    match text(&row["call"]) {
        "listActions" => {
            let result: ListActionsResult =
                serde_json::from_value(row["answered"].clone()).unwrap();
            writer.write_var_int(result.total_actions.into());
            for action in &result.actions {
                writer.write_wallet_action(action);
            }
        }
        "listOutputs" => {
            let result: ListOutputsResult =
                serde_json::from_value(row["answered"].clone()).unwrap();
            writer
                .write_var_int(result.total_outputs.into())
                .write_optional_bytes(result.beef.as_deref());
            for output in &result.outputs {
                writer.write_wallet_output(output);
            }
        }
        other => panic!("no public writer for {other}"),
    }
    writer.into_bytes()
}

/// The three rows whose answer this crate's types or optional writers cannot
/// carry as the reference's processor writes it, each stated in the lane
/// record's table: an action output's `tags` and `basket` are not optional
/// here (an absent `tags` is written as a count of 0), and a present empty
/// script or instruction is written as absent.
const WRITTEN_OTHERWISE: [&str; 3] = [
    "listActions_output_optionals_absent",
    "listActions_output_empty_strings",
    "listOutputs_empty_strings",
];

#[test]
fn the_public_result_writers_write_the_reference_processor_frames_1002() {
    let mut stated = Vec::new();
    let mut compared = 0;
    for row in rows("response_rows", RESPONSE_ROWS) {
        if !matches!(text(&row["call"]), "listActions" | "listOutputs") {
            continue;
        }
        let name = text(&row["name"]);
        let frame = hex::encode(result_frame(&row));
        if WRITTEN_OTHERWISE.contains(&name) {
            assert_ne!(
                frame,
                text(&row["response_hex"]),
                "{name}: no longer a difference"
            );
            stated.push(name.to_string());
        } else {
            assert_eq!(frame, text(&row["response_hex"]), "{name}");
        }
        compared += 1;
    }
    assert_eq!(compared, 23);
    assert_eq!(stated, WRITTEN_OTHERWISE);
}

/// The stated rows, byte by byte: what this crate writes where the
/// reference's processor writes the absence marker or a zero length.
#[test]
fn an_absent_tag_list_and_an_empty_script_are_written_otherwise_stated_1002() {
    let responses = rows("response_rows", RESPONSE_ROWS);
    let recorded = |name: &str| {
        let row = responses.iter().find(|row| row["name"] == name).unwrap();
        (
            hex::encode(result_frame(row)),
            text(&row["response_hex"]).to_string(),
        )
    };
    let absent = "ff".repeat(9);
    // tags absent: the reference `ff` x 9, this crate a count of 0
    let (here, there) = recorded("listActions_output_optionals_absent");
    assert!(
        there.ends_with(&format!("05666c616773{absent}{absent}")),
        "{there}"
    );
    assert!(here.ends_with(&format!("05666c61677300{absent}")), "{here}");
    // an empty locking script and empty instructions: the reference a length
    // of 0 each, this crate the absence marker
    let (here, there) = recorded("listActions_output_empty_strings");
    assert!(
        there.ends_with("fde80300010a666c6167207465737473000000"),
        "{there}"
    );
    assert!(
        here.ends_with(&format!(
            "fde803{absent}010a666c61672074657374730000{absent}"
        )),
        "{here}"
    );
    let (here, there) = recorded("listOutputs_empty_strings");
    assert!(
        there.ends_with(&format!("00fde8030000{absent}{absent}")),
        "{there}"
    );
    assert!(
        here.ends_with(&format!("00fde803{absent}{absent}{absent}{absent}")),
        "{here}"
    );
}

// ---------------------------------------------------------------------------
// The class: the public mode helpers, each beside the recorded byte
// ---------------------------------------------------------------------------

fn written_byte(write: impl FnOnce(&mut WireWriter)) -> u8 {
    let mut writer = WireWriter::new();
    write(&mut writer);
    assert_eq!(writer.len(), 1);
    writer.as_bytes()[0]
}

/// `write_optional_query_mode` and `read_optional_query_mode` are listActions'
/// `labelQueryMode` (the cell beside `test_optional_query_mode_roundtrip`).
#[test]
fn the_optional_query_mode_helpers_are_the_recorded_label_query_mode_bytes_1002() {
    let flags = rows("request_flag_rows", 29);
    for (state, mode) in [
        ("absent", None),
        ("any", Some(QueryMode::Any)),
        ("all", Some(QueryMode::All)),
    ] {
        let recorded = flag(&flags, LABEL_QUERY_MODE, state);
        assert_eq!(
            written_byte(|writer| {
                writer.write_optional_query_mode(mode);
            }),
            recorded,
            "{state}"
        );
        assert_eq!(
            WireReader::new(&[recorded])
                .read_optional_query_mode()
                .unwrap(),
            mode,
            "{state}"
        );
    }
    // listOutputs' tagQueryMode is the other assignment: the helper is not its writer
    assert_eq!(flag(&flags, "listOutputs tagQueryMode", "all"), 1);
    assert_eq!(flag(&flags, "listOutputs tagQueryMode", "any"), 2);
}

/// `write_optional_bool` and `read_optional_bool` are the reference's
/// optional boolean in each of its three states, at each recorded site (the
/// cell beside `test_optional_bool`).
#[test]
fn the_optional_bool_helpers_are_the_recorded_optional_boolean_bytes_1002() {
    let flags = rows("request_flag_rows", 29);
    let mut sites = 0;
    for site in [
        "listActions includeLabels",
        "listActions seekPermission",
        "listOutputs includeTags",
        "createAction signAndProcess",
        "getPublicKey forSelf",
        "getPublicKey privileged",
    ] {
        for (state, value) in [
            ("absent", None),
            ("false", Some(false)),
            ("true", Some(true)),
        ] {
            let recorded = flag(&flags, site, state);
            assert_eq!(
                written_byte(|writer| {
                    writer.write_optional_bool(value);
                }),
                recorded,
                "{site}: {state}"
            );
            assert_eq!(
                WireReader::new(&[recorded]).read_optional_bool().unwrap(),
                value,
                "{site}: {state}"
            );
        }
        sites += 1;
    }
    assert_eq!(sites, 6);
}

/// `write_action_status` and `read_action_status` are the recorded status
/// byte for each of the eight statuses; their `None`, -1, is no method's
/// byte: the reference's reader refuses it, and so does listActions' here.
#[test]
fn the_action_status_helpers_are_the_recorded_status_bytes_1002() {
    let flags = rows("response_flag_rows", 16);
    for (state, status) in [
        ("completed", ActionStatus::Completed),
        ("unprocessed", ActionStatus::Unprocessed),
        ("sending", ActionStatus::Sending),
        ("unproven", ActionStatus::Unproven),
        ("unsigned", ActionStatus::Unsigned),
        ("nosend", ActionStatus::NoSend),
        ("nonfinal", ActionStatus::NonFinal),
        ("failed", ActionStatus::Failed),
    ] {
        let recorded = flag(&flags, "listActions status", state);
        assert_eq!(
            written_byte(|writer| {
                writer.write_action_status(Some(status));
            }),
            recorded,
            "{state}"
        );
        assert_eq!(
            WireReader::new(&[recorded]).read_action_status().unwrap(),
            Some(status),
            "{state}"
        );
    }
    assert_eq!(
        written_byte(|writer| {
            writer.write_action_status(None);
        }),
        0xff
    );
    assert_eq!(WireReader::new(&[0xff]).read_action_status().unwrap(), None);
    let refusals = rows("transceiver_refusal_rows", TRANSCEIVER_REFUSALS);
    let unknown = refusals
        .iter()
        .find(|row| row["name"] == "listActions status = 255")
        .unwrap();
    assert_eq!(unknown["message"], "Unknown status code: -1");
    for code in [0u8, 9] {
        let error = WireReader::new(&[code]).read_action_status().unwrap_err();
        assert_eq!(words(&error), format!("Unknown status code: {code}"));
    }
}

/// Three helpers no method uses, whose bytes are no method's: the captain's
/// question (the lane record). Their bytes today, beside the recorded bytes
/// of the two fields their names suggest; the reference's processor refuses
/// the 0 each writes.
#[test]
fn the_unused_mode_helpers_write_no_methods_bytes_stated_1002() {
    let flags = rows("request_flag_rows", 29);
    let byte = |write: fn(&mut WireWriter)| written_byte(write);
    // write_query_mode: 0 any, 1 all
    let query = (
        byte(|writer| {
            writer.write_query_mode(QueryMode::Any);
        }),
        byte(|writer| {
            writer.write_query_mode(QueryMode::All);
        }),
    );
    assert_eq!(query, (0, 1));
    let label = (
        flag(&flags, LABEL_QUERY_MODE, "any"),
        flag(&flags, LABEL_QUERY_MODE, "all"),
    );
    let tag = (
        flag(&flags, "listOutputs tagQueryMode", "any"),
        flag(&flags, "listOutputs tagQueryMode", "all"),
    );
    assert_eq!((label, tag), ((1, 2), (2, 1)));
    assert!(query != label && query != tag);
    // write_output_include and its optional form: 0 locking scripts, 1 entire transactions
    let include = (
        byte(|writer| {
            writer.write_output_include(OutputInclude::LockingScripts);
        }),
        byte(|writer| {
            writer.write_output_include(OutputInclude::EntireTransactions);
        }),
    );
    let optional = (
        byte(|writer| {
            writer.write_optional_output_include(Some(OutputInclude::LockingScripts));
        }),
        byte(|writer| {
            writer.write_optional_output_include(Some(OutputInclude::EntireTransactions));
        }),
    );
    assert_eq!((include, optional), ((0, 1), (0, 1)));
    let recorded = (
        flag(&flags, "listOutputs include", "locking scripts"),
        flag(&flags, "listOutputs include", "entire transactions"),
    );
    assert_eq!(recorded, (1, 2));
    assert_eq!(
        byte(|writer| {
            writer.write_optional_output_include(None);
        }),
        flag(&flags, "listOutputs include", "absent")
    );
    // the readers are their writers' twins
    assert_eq!(
        WireReader::new(&[0]).read_query_mode().unwrap(),
        QueryMode::Any
    );
    assert_eq!(
        WireReader::new(&[1]).read_output_include().unwrap(),
        OutputInclude::EntireTransactions
    );
    assert_eq!(
        WireReader::new(&[0])
            .read_optional_output_include()
            .unwrap(),
        Some(OutputInclude::LockingScripts)
    );
    // the reference's processor refuses the 0 each helper writes
    let refused = rows("processor_refusal_rows", PROCESSOR_REFUSALS);
    for (name, words) in [
        (
            "listActions labelQueryMode = 0",
            "Invalid labelQueryMode flag: expected -1, 1, or 2, received 0",
        ),
        (
            "listOutputs tagQueryMode = 0",
            "Invalid tagQueryMode flag: expected -1, 1, or 2, received 0",
        ),
        (
            "listOutputs include = 0",
            "Invalid include flag: expected -1, 1, or 2, received 0",
        ),
    ] {
        let row = refused.iter().find(|row| row["name"] == name).unwrap();
        assert_eq!(refusal(&unhex(row, "response_hex")), (1, words.to_string()));
    }
}
