use super::cases::{self, Case};
use super::wallet::{calls, invoke, outcome, Stub, WireWallet};
use super::wallet_json::FixtureJson;
use super::Suite;
use bsv_rs::primitives::{from_base64, from_hex, PublicKey};
use bsv_rs::wallet::interface::{RevealCounterpartyKeyLinkageArgs, RevealSpecificKeyLinkageArgs};
use bsv_rs::wallet::wire::{
    WalletCall, WalletWire, WalletWireProcessor, WalletWireTransceiver, WireReader, WireWriter,
};
use bsv_rs::wallet::*;
use bsv_rs::Error;
use serde_json::{json, Value};
use std::sync::Mutex;

struct RecordingWire {
    processor: WalletWireProcessor<Stub>,
    reply: Option<Vec<u8>>,
    tape: Mutex<Option<Exchange>>,
}

#[derive(Clone)]
struct Exchange {
    request: Vec<u8>,
    response: Vec<u8>,
    processor_response: Vec<u8>,
}

#[async_trait::async_trait]
impl WalletWire for RecordingWire {
    async fn transmit_to_wallet(&self, message: &[u8]) -> bsv_rs::Result<Vec<u8>> {
        let processor_reply = self.processor.process_message(message).await?;
        let reply = self.reply.as_ref().unwrap_or(&processor_reply).clone();
        *self.tape.lock().unwrap() = Some(Exchange {
            request: message.to_vec(),
            response: reply.clone(),
            processor_response: processor_reply,
        });
        Ok(reply)
    }
}

struct ReplyWire(Vec<u8>);

#[async_trait::async_trait]
impl WalletWire for ReplyWire {
    async fn transmit_to_wallet(&self, _: &[u8]) -> bsv_rs::Result<Vec<u8>> {
        Ok(self.0.clone())
    }
}

// The transceiver exposes no linkage methods. As in wire_method_roundtrip_tests,
// use the public low-level codec for these two processor-supported calls, in the
// reference's order (`WalletWireTransceiver.ts:809-811`, `:874-883` at
// ts-stack@edf6e03; #191). It is not a new production client API.
fn linkage_request(call: WalletCall, originator: Option<&str>) -> WireWriter {
    let originator = originator.unwrap_or_default();
    let mut w = WireWriter::new();
    w.write_u8(call.as_u8())
        .write_u8(originator.len() as u8)
        .write_bytes(originator.as_bytes());
    w
}

// The reference's `#encodePrivilegedParams` (`WalletWireTransceiver.ts:1448-1462`).
fn privileged_params(w: &mut WireWriter, privileged: Option<bool>, reason: Option<&str>) {
    w.write_optional_bool(privileged);
    match reason {
        Some(reason) => w
            .write_i8(reason.len() as i8)
            .write_bytes(reason.as_bytes()),
        None => w.write_i8(-1),
    };
}

async fn linkage_response<T: WalletWire>(
    client: &WalletWireTransceiver<T>,
    w: WireWriter,
) -> bsv_rs::Result<Vec<u8>> {
    let bytes = client.wire().transmit_to_wallet(w.as_bytes()).await?;
    if bytes.first() == Some(&0) {
        return Ok(bytes[1..].to_vec());
    }
    // Use the production common error decoder, also for malformed envelopes.
    let decoder = WalletWireTransceiver::new(ReplyWire(bytes));
    Err(decoder.get_version(None).await.unwrap_err())
}

// The three keys open both results, in the reference's order
// (`WalletWireTransceiver.ts:818-836`, `:890-908` at ts-stack@edf6e03; #194).
fn read_linkage_keys(r: &mut WireReader<'_>) -> bsv_rs::Result<[PublicKey; 3]> {
    Ok([
        PublicKey::from_bytes(r.read_bytes(33)?)?,
        PublicKey::from_bytes(r.read_bytes(33)?)?,
        PublicKey::from_bytes(r.read_bytes(33)?)?,
    ])
}

fn read_linkage(r: &mut WireReader<'_>, keys: [PublicKey; 3]) -> bsv_rs::Result<KeyLinkageResult> {
    let [prover, verifier, counterparty] = keys;
    let len = r.read_var_int()? as usize;
    let encrypted_linkage = r.read_bytes(len)?.to_vec();
    let len = r.read_var_int()? as usize;
    let encrypted_linkage_proof = r.read_bytes(len)?.to_vec();
    Ok(KeyLinkageResult {
        encrypted_linkage,
        encrypted_linkage_proof,
        prover,
        verifier,
        counterparty,
    })
}

pub async fn counterparty<T: WalletWire>(
    client: &WalletWireTransceiver<T>,
    args: RevealCounterpartyKeyLinkageArgs,
    originator: Option<&str>,
) -> bsv_rs::Result<RevealCounterpartyKeyLinkageResult> {
    let mut w = linkage_request(WalletCall::RevealCounterpartyKeyLinkage, originator);
    privileged_params(&mut w, args.privileged, args.privileged_reason.as_deref());
    w.write_bytes(&args.counterparty.to_compressed())
        .write_bytes(&args.verifier.to_compressed());
    let bytes = linkage_response(client, w).await?;
    let mut r = WireReader::new(&bytes);
    let keys = read_linkage_keys(&mut r)?;
    let revelation_time = r.read_string()?;
    Ok(RevealCounterpartyKeyLinkageResult {
        linkage: read_linkage(&mut r, keys)?,
        revelation_time,
    })
}

pub async fn specific<T: WalletWire>(
    client: &WalletWireTransceiver<T>,
    args: RevealSpecificKeyLinkageArgs,
    originator: Option<&str>,
) -> bsv_rs::Result<RevealSpecificKeyLinkageResult> {
    let mut w = linkage_request(WalletCall::RevealSpecificKeyLinkage, originator);
    w.write_protocol_id(&args.protocol_id)
        .write_string(&args.key_id)
        .write_counterparty(Some(&args.counterparty));
    privileged_params(&mut w, args.privileged, args.privileged_reason.as_deref());
    w.write_bytes(&args.verifier.to_compressed());
    let bytes = linkage_response(client, w).await?;
    let mut r = WireReader::new(&bytes);
    let keys = read_linkage_keys(&mut r)?;
    let protocol = r.read_protocol_id()?;
    let key_id = r.read_string()?;
    Ok(RevealSpecificKeyLinkageResult {
        linkage: read_linkage(&mut r, keys)?,
        protocol,
        key_id,
        proof_type: r.read_u8()?,
    })
}

// These 12 processor handlers currently return "requires a full wallet
// implementation" even for a WalletInterface implementation (abortAction
// calls its wallet since bsv-rs#206). Keep that answer
// in processor_response_hex. Exercise their client decoders with WireWriter's
// public type encoders, without altering or hiding the processor's response.
fn type_writer_reply(call: WalletCall, value: &Value) -> Option<Vec<u8>> {
    use WalletCall::*;
    let mut w = WireWriter::new();
    w.write_u8(0);
    match call {
        CreateAction => {
            let r = CreateActionResult::from_fixture(value.clone());
            optional_tx(&mut w, r.txid, r.tx.as_deref());
            match r.no_send_change {
                None => {
                    w.write_var_int(u64::MAX);
                }
                Some(outpoints) => {
                    w.write_var_int(outpoints.len() as u64);
                    for outpoint in outpoints {
                        w.write_outpoint(&outpoint);
                    }
                }
            }
            w.write_send_with_result_array(r.send_with_results.as_deref());
            if let Some(tx) = r.signable_transaction {
                w.write_i8(1)
                    .write_var_int(tx.tx.len() as u64)
                    .write_bytes(&tx.tx)
                    .write_var_int(tx.reference.len() as u64)
                    .write_bytes(&tx.reference);
            } else {
                w.write_i8(0);
            }
        }
        SignAction => {
            let r = SignActionResult::from_fixture(value.clone());
            optional_tx(&mut w, r.txid, r.tx.as_deref());
            w.write_send_with_result_array(r.send_with_results.as_deref());
        }
        InternalizeAction | RelinquishOutput | RelinquishCertificate => {}
        ListActions => {
            let r = ListActionsResult::from_fixture(value.clone());
            w.write_var_int(r.total_actions.into());
            for action in r.actions {
                w.write_wallet_action(&action);
            }
        }
        ListOutputs => {
            let r = ListOutputsResult::from_fixture(value.clone());
            w.write_var_int(r.total_outputs.into())
                .write_optional_bytes(r.beef.as_deref());
            for output in r.outputs {
                w.write_wallet_output(&output);
            }
        }
        AcquireCertificate => {
            w.write_wallet_certificate(&WalletCertificate::from_fixture(value.clone()))
                .unwrap();
        }
        ListCertificates => {
            let r = ListCertificatesResult::from_fixture(value.clone());
            w.write_var_int(r.total_certificates.into());
            for entry in r.certificates {
                let mut certificate = WireWriter::new();
                certificate
                    .write_wallet_certificate(&entry.certificate)
                    .unwrap();
                w.write_var_int(certificate.len() as u64)
                    .write_bytes(certificate.as_bytes());
                if let Some(keyring) = entry.keyring {
                    w.write_i8(1);
                    keyring_bytes(&mut w, &keyring);
                } else {
                    w.write_i8(0);
                }
                // The verifier's 33 bytes behind their length, or 0
                // (`WalletWireTransceiver.ts:1533-1542` at `ts-stack@edf6e03`).
                let verifier = entry.verifier.map(|v| from_hex(&v).unwrap());
                let verifier = verifier.unwrap_or_default();
                w.write_var_int(verifier.len() as u64)
                    .write_bytes(&verifier);
            }
        }
        ProveCertificate => {
            let r = ProveCertificateResult::from_fixture(value.clone());
            keyring_bytes(&mut w, &r.keyring_for_verifier);
        }
        DiscoverByIdentityKey | DiscoverByAttributes => {
            let r = DiscoverCertificatesResult::from_fixture(value.clone());
            w.write_var_int(r.total_certificates.into());
            for entry in r.certificates {
                w.write_identity_certificate(&entry).unwrap();
            }
        }
        _ => return None,
    }
    Some(w.into_bytes())
}

fn optional_tx(w: &mut WireWriter, txid: Option<TxId>, tx: Option<&[u8]>) {
    if let Some(txid) = txid {
        w.write_i8(1).write_bytes(&txid);
    } else {
        w.write_i8(0);
    }
    if let Some(tx) = tx {
        w.write_i8(1).write_var_int(tx.len() as u64).write_bytes(tx);
    } else {
        w.write_i8(0);
    }
}

/// The keyring in the map's order, as the reference's processor writes it
/// (`#recordEntries`, `WalletWireProcessor.ts:2075`; #385).
fn keyring_bytes(w: &mut WireWriter, map: &indexmap::IndexMap<String, String>) {
    w.write_var_int(map.len() as u64);
    for (key, value) in map {
        let bytes = from_base64(value).unwrap();
        w.write_string(key)
            .write_var_int(bytes.len() as u64)
            .write_bytes(&bytes);
    }
}

async fn run_case(call: WalletCall, case: Case) -> Value {
    let stub = Stub::new(case.result.clone());
    let observed = stub.observed.clone();
    let writer_reply = type_writer_reply(call, &case.result);
    let encoder = if writer_reply.is_some() {
        "WireWriter"
    } else {
        "WalletWireProcessor"
    };
    let wire = RecordingWire {
        processor: WalletWireProcessor::new(stub),
        reply: writer_reply,
        tape: Mutex::default(),
    };
    let client = WireWallet(WalletWireTransceiver::new(wire));
    let result = outcome(invoke(&client, call, case.input.clone()).await);
    let Exchange {
        request,
        response,
        processor_response,
    } = client
        .0
        .wire()
        .tape
        .lock()
        .unwrap()
        .clone()
        .unwrap_or_else(|| panic!("{} {} did not reach the wire: {result}", call, case.name));
    json!({"name": case.name, "seed": cases::SEED, "input": {"args": case.input, "result": case.result},
        "expected": {"request_hex": hex::encode(request), "response_hex": hex::encode(response),
            "response_encoder": encoder, "client_result": result,
            "processor_response_hex": hex::encode(processor_response), "processor_observed": *observed.lock().unwrap()},
        "error_frames": "wire/error_frames.json"})
}

fn frame(code: u8, message: &str, stack: Option<&[u8]>) -> Vec<u8> {
    let mut w = WireWriter::new();
    w.write_u8(code).write_string(message);
    match stack {
        Some(stack) => {
            w.write_var_int(stack.len() as u64).write_bytes(stack);
        }
        None => {
            w.write_var_int(u64::MAX);
        }
    }
    w.into_bytes()
}

async fn error_frames() -> Vec<Value> {
    let mut inputs = Vec::new();
    for code in 1..=u8::MAX {
        inputs.push((
            format!("status_{code}"),
            json!({"code": code, "message": "fixture refusal", "stack": ""}),
            frame(code, "fixture refusal", Some(&[])),
        ));
    }
    inputs.push((
        "stack_bytes".into(),
        json!({"code": 1, "message": "refusé", "stack": "66697874757265"}),
        frame(1, "refusé", Some(b"fixture")),
    ));
    inputs.push((
        "nil_stack".into(),
        json!({"code": 1, "message": "fixture refusal", "stack": null}),
        frame(1, "fixture refusal", None),
    ));
    for (name, bytes) in [
        ("empty", vec![]),
        ("missing_message", vec![1]),
        ("missing_stack_length", vec![1, 0]),
        ("invalid_utf8", vec![1, 1, 255, 0]),
        ("truncated_message", vec![1, 3, b'a']),
        ("noncanonical_length", vec![1, 253, 1, 0, b'a', 0]),
        ("truncated_stack", vec![1, 0, 3, 1]),
    ] {
        inputs.push((
            name.into(),
            json!({"malformed_hex": hex::encode(&bytes)}),
            bytes,
        ));
    }
    // Pin the frames the production processor emits, with its own error writer:
    // every one unknownError (1) since bsv-rs#202, and each a wallet error, so
    // the reference's `Wallet operation failed` (`#invokeWallet`, `:2417`).
    for (name, error) in [
        (
            "processor_generic",
            Error::WalletError("fixture refusal".into()),
        ),
        (
            "processor_parameter",
            Error::WalletError("invalid parameter: fixture".into()),
        ),
        (
            "processor_funds",
            Error::WalletError("insufficient funds: fixture".into()),
        ),
    ] {
        let mut stub = Stub::new(json!({}));
        stub.error = Some(error.clone());
        let processor = WalletWireProcessor::new(stub);
        let mut request = WireWriter::new();
        request.write_u8(WalletCall::GetHeight.as_u8()).write_u8(0);
        let bytes = processor.process_message(request.as_bytes()).await.unwrap();
        inputs.push((
            name.into(),
            json!({"processor_error": format!("{error:?}")}),
            bytes,
        ));
    }
    let mut entries = Vec::new();
    for (name, input, bytes) in inputs {
        let mut expected = None;
        let mut by_call = serde_json::Map::new();
        for call in calls() {
            let client = WireWallet(WalletWireTransceiver::new(ReplyWire(bytes.clone())));
            let result = outcome(invoke(&client, call, cases::cases(call).remove(0).input).await);
            match expected {
                Some(ref expected) if &result != expected => {
                    // abortAction reads code 8 (`abortRefused`) as
                    // `aborted: false` (`WalletWireTransceiver.ts:337`, bsv-rs#206);
                    // every other call reads every frame alike
                    assert_eq!(
                        (call, name.as_str()),
                        (WalletCall::AbortAction, "status_8"),
                        "{call} error frame {name}"
                    );
                    by_call.insert(call.method_name().into(), result);
                }
                Some(_) => {}
                None => expected = Some(result),
            }
        }
        let mut entry = json!({"name": name, "input": input, "expected": {"response_hex": hex::encode(bytes), "client_result": expected}});
        if !by_call.is_empty() {
            entry["expected"]["client_result_by_call"] = Value::Object(by_call);
        }
        entries.push(entry);
    }
    entries
}

pub async fn record(suite: &mut Suite) {
    for call in calls() {
        let mut entries = Vec::new();
        for case in cases::cases(call) {
            entries.push(run_case(call, case).await);
        }
        assert_eq!(entries.len(), 2, "{call}: case count");
        suite.add(
            &format!("wire/{}.json", call.method_name()),
            &[(
                "wallet/0100.md",
                &format!(
                    "ABI Specification / Method Calls Specification / {}. {}",
                    call.as_u8(),
                    call.method_name()
                ),
            )],
            entries,
        );
    }
    suite.add(
        "wire/error_frames.json",
        &[("wallet/0100.md", "ABI Specification / Error Handling")],
        error_frames().await,
    );
}
