//! Writes the seed corpora of the fuzz targets under `fuzz/corpus/<target>/`
//! from the tree's own vectors (`tests/vectors/`, `tests/transaction/vectors/`,
//! the wallet-wire message files), each seed in its target's input shape and
//! built by this crate's own writers, so a seed cannot drift from the wire.
//!
//! `cargo run --release --manifest-path fuzz/corpus-gen/Cargo.toml -- [--rest <dir>]`
//!
//! The script target's seeds are the sibling harness's seed rows
//! (`$BSV_SCRIPT_SEED`, default `~/bsv/bsv-script-lean/corpus/seed/seed.jsonl`):
//! one row per family goes to the checked-in corpus, every other row to
//! `<dir>/fuzz_script_spend/` when `--rest` names one. Without the file the
//! target's other seeds are still written and the skip is printed.
//!
//! The BEEF targets' seeds are the Lean's rows (`tests/vectors/beef_of_any_size/`)
//! and, for each refusal the Lean names (`BeefOfAnySize.lean`, `Reason`; this
//! crate's `beef_stream::Kind`), the leading mutation of a row that the
//! streaming reader refuses with it; the census of the kinds reached is
//! printed, a kind no seed reaches named.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "../../../tests/transaction/vectors/beef_cross_sdk.rs"]
mod beef_cross_sdk;
#[path = "../../../tests/transaction/vectors/bigtx.rs"]
mod bigtx;
#[path = "../../../tests/transaction/vectors/bump_invalid.rs"]
mod bump_invalid;
#[path = "../../../tests/transaction/vectors/bump_valid.rs"]
mod bump_valid;
#[path = "../../../tests/transaction/vectors/tx_valid.rs"]
mod tx_valid;

use bsv_rs::auth::transports::socketio::codec::{EngineIoPacket, SocketIoPacket};
use bsv_rs::auth::transports::{HttpRequest, HttpResponse};
use bsv_rs::auth::{AuthMessage, Certificate, MessageType, RequestedCertificateSet};
use bsv_rs::compat::bip32::{ExtendedKey, Network};
use bsv_rs::compat::bip39::{Language, Mnemonic};
use bsv_rs::compat::{bsm, ecies};
use bsv_rs::messages;
use bsv_rs::primitives::bsv::shamir::split_private_key_with;
use bsv_rs::primitives::bsv::sighash::parse_transaction;
use bsv_rs::primitives::{from_hex, to_base64, PrivateKey};
use bsv_rs::transaction::{verify_stream, verify_stream_structure, Beef, Headers, Kind, Verdict};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");

/// The response decoders' call order (`fuzz_targets/support/mod.rs`,
/// `call_shared!`), by the wallet-wire vectors' call names; the two reveals
/// are the HTTP target's 26 and 27.
const CALLS: [&str; 28] = [
    "createAction",
    "signAction",
    "abortAction",
    "listActions",
    "internalizeAction",
    "listOutputs",
    "relinquishOutput",
    "getPublicKey",
    "encrypt",
    "decrypt",
    "createHmac",
    "verifyHmac",
    "createSignature",
    "verifySignature",
    "acquireCertificate",
    "listCertificates",
    "proveCertificate",
    "relinquishCertificate",
    "discoverByIdentityKey",
    "discoverByAttributes",
    "isAuthenticated",
    "waitForAuthentication",
    "getHeight",
    "getHeaderForHeight",
    "getNetwork",
    "getVersion",
    "revealCounterpartyKeyLinkage",
    "revealSpecificKeyLinkage",
];

struct Corpus {
    dir: PathBuf,
    seen: BTreeSet<[u8; 32]>,
    bytes: usize,
}

impl Corpus {
    fn new(base: &Path, target: &str) -> Self {
        // Its own seeds are rewritten by name; an entry merged from a
        // night's artifact (docs/NIGHTLY.md) stays.
        let dir = base.join(target);
        fs::create_dir_all(&dir).unwrap();
        Corpus {
            dir,
            seen: BTreeSet::new(),
            bytes: 0,
        }
    }

    /// Writes one seed named `<name>`; a seed with the bytes of an earlier
    /// one is not written again.
    fn add(&mut self, name: &str, data: &[u8]) {
        let digest: [u8; 32] = Sha256::digest(data).into();
        if !self.seen.insert(digest) {
            return;
        }
        let name: String = name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        fs::write(self.dir.join(name), data).unwrap();
        self.bytes += data.len();
    }

    fn report(&self, target: &str) {
        println!("{target}: {} seeds, {} bytes", self.seen.len(), self.bytes);
    }
}

fn read(path: &str) -> String {
    fs::read_to_string(Path::new(ROOT).join(path)).unwrap()
}

fn vector_files() -> Vec<(String, Value)> {
    let mut out = Vec::new();
    let dir = Path::new(ROOT).join("tests/vectors/wallet_wire");
    let mut names: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.ends_with(".json"))
        .collect();
    names.sort();
    for name in names {
        let value: Value =
            serde_json::from_str(&fs::read_to_string(dir.join(&name)).unwrap()).unwrap();
        out.push((name.trim_end_matches(".json").to_string(), value));
    }
    out
}

fn call_index(name: &str) -> Option<u8> {
    let call = name.split('-').next()?;
    CALLS.iter().position(|c| *c == call).map(|i| i as u8)
}

struct EveryRoot;

impl Headers for EveryRoot {
    fn carries(&self, _height: u64, _root: &[u8; 32]) -> bool {
        true
    }
}

/// The refusal the streaming reader gives the bytes, under headers that
/// carry every root, else under none (the door a root not carried opens).
fn kind_of(data: &[u8]) -> Option<Kind> {
    if let Ok(Verdict::Invalid { kind, .. }) = verify_stream_structure(data, EveryRoot, None) {
        return Some(kind);
    }
    let none: std::collections::HashMap<u64, [u8; 32]> = std::collections::HashMap::new();
    if let Ok(Verdict::Invalid { kind, .. }) = verify_stream_structure(data, &none, None) {
        return Some(kind);
    }
    match verify_stream(data, EveryRoot, None) {
        Ok(Verdict::Invalid { kind, .. }) => Some(kind),
        _ => None,
    }
}

/// The two doors a byte mutation does not reach: an input spent twice in one
/// transaction, a null outpoint in one that is not a coinbase. Each is a Lean
/// row's raw transaction with one input more, written by `Beef::to_binary`.
fn written_doors(rows: &[(String, Vec<u8>)]) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for (name, data) in rows {
        let Ok(parsed) = Beef::from_binary(data) else {
            continue;
        };
        for (i, entry) in parsed.txs.iter().enumerate() {
            let Some(tx) = entry.tx() else {
                continue;
            };
            let [spent, ..] = &tx.inputs[..] else {
                continue;
            };
            let mut twice = tx.clone();
            twice.inputs.push(spent.clone());
            let mut null = tx.clone();
            let mut input = spent.clone();
            input.source_txid = Some("00".repeat(32));
            input.source_output_index = 0xffff_ffff;
            null.inputs.push(input);
            // A field set by hand leaves the serialization cache standing.
            twice.invalidate_caches();
            null.invalidate_caches();
            // The transaction's bytes, as `Transaction::to_binary` writes
            // them, replaced in the row where they stand.
            let original = tx.to_binary();
            let Some(at) = data.windows(original.len()).position(|w| w == original) else {
                continue;
            };
            for (door, changed) in [("DuplicateInput", twice), ("NullOutpoint", null)] {
                let mut bytes = data[..at].to_vec();
                bytes.extend_from_slice(&changed.to_binary());
                bytes.extend_from_slice(&data[at + original.len()..]);
                out.push((format!("door-{door}-{name}-{i}"), bytes));
            }
        }
    }
    out
}

fn lean_rows() -> Vec<(String, Vec<u8>)> {
    let dir = Path::new(ROOT).join("tests/vectors/beef_of_any_size");
    let mut rows: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "bin"))
        .map(|p| {
            let name = p.file_stem().unwrap().to_string_lossy().to_string();
            (name, fs::read(&p).unwrap())
        })
        .collect();
    rows.sort();
    rows
}

fn beef_corpora(base: &Path) {
    let mut beef = Corpus::new(base, "fuzz_beef_parser");
    let mut bump = Corpus::new(base, "fuzz_merkle_path");
    let rows = lean_rows();
    let mut doors: BTreeMap<String, String> = BTreeMap::new();

    for (name, data) in &rows {
        beef.add(&format!("lean-{name}"), data);
        if let Some(kind) = kind_of(data) {
            doors
                .entry(format!("{kind:?}"))
                .or_insert(format!("lean-{name}"));
        }
        if let Ok(parsed) = Beef::from_binary(data) {
            for (i, path) in parsed.bumps.iter().enumerate() {
                bump.add(&format!("lean-{name}-bump{i}"), &path.to_binary());
            }
        }
    }
    for (name, hex) in [
        ("brc62", beef_cross_sdk::BRC62_HEX),
        ("beef-set", beef_cross_sdk::BEEF_SET_HEX),
    ] {
        beef.add(&format!("cross-sdk-{name}"), &from_hex(hex).unwrap());
    }
    let atomic: Value =
        serde_json::from_str(&read("tests/transaction/vectors/atomic-beef.json")).unwrap();
    for v in atomic["vectors"].as_array().unwrap() {
        if let Some(hex) = v["input"]["beef_hex"].as_str() {
            beef.add(
                &format!("atomic-{}", v["id"].as_str().unwrap()),
                &from_hex(hex).unwrap(),
            );
        }
    }

    // A door no row reaches: the leading mutation of a row (truncated, a
    // byte replaced, a byte inserted) the reader refuses with it.
    let mutate = |data: &[u8], at: usize, how: u8| -> Vec<u8> {
        let mut m = data.to_vec();
        match how {
            0 => m.truncate(at),
            1..=5 => m[at] = [0x00, 0xff, 0xfd, 0xfe, data[at].wrapping_add(1)][how as usize - 1],
            _ => m.insert(at, 0xfd),
        }
        m
    };
    for (name, data) in rows.iter().filter(|(_, d)| d.len() <= 8 << 10) {
        for at in 0..data.len() {
            for how in 0..7u8 {
                let m = mutate(data, at, how);
                if let Some(kind) = kind_of(&m) {
                    let key = format!("{kind:?}");
                    if let std::collections::btree_map::Entry::Vacant(slot) = doors.entry(key) {
                        let seed = format!("door-{}-{name}-{at}-{how}", slot.key());
                        beef.add(&seed, &m);
                        slot.insert(seed);
                    }
                }
            }
        }
    }

    for (seed, m) in written_doors(&rows) {
        if let Some(kind) = kind_of(&m) {
            if let std::collections::btree_map::Entry::Vacant(slot) =
                doors.entry(format!("{kind:?}"))
            {
                beef.add(&seed, &m);
                slot.insert(seed);
            }
        }
    }

    for hex in bump_valid::BUMP_VALID_VECTORS {
        bump.add(
            &format!("bump-valid-{}", &hex[..16]),
            &from_hex(hex).unwrap(),
        );
    }
    for (i, v) in bump_invalid::BUMP_INVALID_VECTORS.iter().enumerate() {
        bump.add(&format!("bump-invalid-{i}"), &from_hex(v.bump).unwrap());
    }
    bump.add("brc74", &from_hex(beef_cross_sdk::BRC74_HEX).unwrap());
    bump.add(
        "single-tx",
        &from_hex(beef_cross_sdk::SINGLE_TX_BUMP_HEX).unwrap(),
    );

    beef.report("fuzz_beef_parser");
    bump.report("fuzz_merkle_path");
    let all = [
        "BadVersion",
        "BadVarint",
        "Truncated",
        "BadFlag",
        "TreeHeightOver64",
        "TreeHeightZero",
        "OffsetOutsideTree",
        "NoTxidAtLevelZero",
        "MissingSibling",
        "MismatchedNode",
        "DuplicateOffset",
        "RootNotCarried",
        "BumpIndexNamesNoBump",
        "TxidNotInBump",
        "InputNamesNoElement",
        "StubNotProven",
        "TrailingBytes",
        "SubjectMissing",
        "UnrelatedTransaction",
        "NoInputs",
        "NoOutputs",
        "UnprovenCoinbase",
        "NullOutpoint",
        "DuplicateInput",
        "ValueOutOfRange",
    ];
    for kind in all {
        match doors.get(kind) {
            Some(seed) => println!("  door {kind}: {seed}"),
            None => println!("  door {kind}: NO SEED REACHES IT"),
        }
    }
}

fn wallet_corpora(base: &Path) {
    let mut wire = Corpus::new(base, "fuzz_wire_decoders");
    let mut http = Corpus::new(base, "fuzz_http_json_responses");
    for (name, value) in vector_files() {
        let bytes = hex::decode(value["wire"].as_str().unwrap()).unwrap();
        if name.contains("-args") {
            let mut seed = vec![0u8];
            seed.extend_from_slice(&bytes);
            wire.add(&format!("request-{name}"), &seed);
        } else if let Some(call) = call_index(&name) {
            if call < 26 {
                let mut seed = vec![1u8, call];
                seed.extend_from_slice(&bytes);
                wire.add(&format!("result-{name}"), &seed);
            }
            let mut seed = vec![call, 0, 0];
            seed.extend_from_slice(value["json"].to_string().as_bytes());
            http.add(&format!("ok-{name}"), &seed);
        }
    }
    // An error frame: the code, the message, an empty stack.
    for call in 0..26u8 {
        let mut seed = vec![1u8, call, 6, 4];
        seed.extend_from_slice(b"busy");
        seed.push(0);
        wire.add(&format!("result-error-{}", CALLS[call as usize]), &seed);
    }
    // The failure answers: the busy word (status 503, a Retry-After), the
    // wallet's error body (400), a bare gateway status (502).
    for call in 0..28u8 {
        let busy = br#"1
{"code":"STORE_BUSY","message":"the store is busy"}"#;
        let mut seed = vec![call, 10, 1];
        seed.extend_from_slice(busy);
        http.add(&format!("busy-{}", CALLS[call as usize]), &seed);
        let mut seed = vec![call, 4, 0];
        seed.extend_from_slice(br#"{"code":5,"description":"invalid parameter"}"#);
        http.add(&format!("error-{}", CALLS[call as usize]), &seed);
        http.add(&format!("gateway-{}", CALLS[call as usize]), &[call, 9, 0]);
    }
    wire.report("fuzz_wire_decoders");
    http.report("fuzz_http_json_responses");
}

fn key_corpora(base: &Path) {
    let mut bip32 = Corpus::new(base, "fuzz_bip32");
    for (i, seed) in [vec![0u8; 16], (0u8..64).collect::<Vec<_>>(), vec![0xff; 32]]
        .iter()
        .enumerate()
    {
        for network in [Network::Mainnet, Network::Testnet] {
            let master = ExtendedKey::new_master(seed, network).unwrap();
            bip32.add(
                &format!("master-{i}-{network:?}"),
                master.to_string().as_bytes(),
            );
            bip32.add(
                &format!("public-{i}-{network:?}"),
                master.neuter().unwrap().to_string().as_bytes(),
            );
            let child = master.derive_path("m/0'/1/2'/2/1000000000").unwrap();
            bip32.add(
                &format!("child-{i}-{network:?}"),
                child.to_string().as_bytes(),
            );
        }
        bip32.add(&format!("seed-{i}"), seed);
    }
    for path in [
        "m",
        "m/0",
        "m/0'/1/2'/2/1000000000",
        "m/44'/236'/0'/0/0",
        "m/2147483647'",
    ] {
        bip32.add(&format!("path-{path}"), path.as_bytes());
    }
    bip32.report("fuzz_bip32");

    let mut ecies_corpus = Corpus::new(base, "fuzz_ecies");
    let to = PrivateKey::from_bytes(&[1; 32]).unwrap();
    let from = PrivateKey::from_bytes(&[2; 32]).unwrap();
    for message in [&b""[..], b"Hello!", &[0x42; 31], &[0x42; 64]] {
        let n = message.len();
        let sealed = ecies::electrum_encrypt(message, &to.public_key(), &from, false).unwrap();
        ecies_corpus.add(&format!("electrum-{n}"), &sealed);
        let sealed = ecies::electrum_encrypt(message, &to.public_key(), &from, true).unwrap();
        ecies_corpus.add(&format!("electrum-nokey-{n}"), &sealed);
        let sealed = ecies::bitcore_encrypt(message, &to.public_key(), &from, None).unwrap();
        ecies_corpus.add(&format!("bitcore-{n}"), &sealed);
        let sealed = ecies::encrypt_single_base64(message, &to).unwrap();
        ecies_corpus.add(&format!("single-base64-{n}"), sealed.as_bytes());
        let sealed = ecies::encrypt_shared_base64(message, &to.public_key(), &from).unwrap();
        ecies_corpus.add(&format!("shared-base64-{n}"), sealed.as_bytes());
        ecies_corpus.add(&format!("plain-{n}"), message);
    }
    ecies_corpus.report("fuzz_ecies");
}

fn auth_corpus(base: &Path) {
    let mut auth = Corpus::new(base, "fuzz_auth_messages");
    let key = PrivateKey::from_bytes(&[3; 32]).unwrap();
    let certs: Value = serde_json::from_str(&read("tests/vectors/auth_certificate.json")).unwrap();
    let mut certificates = Vec::new();
    for (i, v) in certs.as_array().unwrap().iter().enumerate() {
        let mut v = v.clone();
        v.as_object_mut().unwrap().remove("description");
        if let Ok(cert) = serde_json::from_value::<Certificate>(v.clone()) {
            auth.add(&format!("certificate-{i}-binary"), &cert.to_binary(true));
            auth.add(
                &format!("certificate-{i}-json"),
                serde_json::to_string(&cert).unwrap().as_bytes(),
            );
            certificates.push(cert);
        }
    }
    let mut requested = RequestedCertificateSet::new();
    requested.add_certifier(key.public_key().to_hex());
    requested.add_type(
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
        vec!["name".into()],
    );
    auth.add(
        "requested-set",
        serde_json::to_string(&requested).unwrap().as_bytes(),
    );
    for (i, message_type) in [
        MessageType::InitialRequest,
        MessageType::InitialResponse,
        MessageType::CertificateRequest,
        MessageType::CertificateResponse,
        MessageType::General,
    ]
    .into_iter()
    .enumerate()
    {
        let mut message = AuthMessage::new(message_type, key.public_key());
        message.nonce = Some("q83vEjRWeJCrze8SNFZ4kKvN7xI0VniQq83vEjRWeJA=".into());
        message.initial_nonce = message.nonce.clone();
        message.your_nonce = message.nonce.clone();
        message.requested_certificates = Some(requested.clone());
        message.payload = Some(b"payload".to_vec());
        message.signature = Some(vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]);
        let text = serde_json::to_string(&message).unwrap();
        auth.add(&format!("message-{i}"), text.as_bytes());
        let event = SocketIoPacket::Event {
            nsp: "/".into(),
            ack_id: None,
            data: vec![json!("authMessage"), serde_json::from_str(&text).unwrap()],
        };
        auth.add(&format!("socketio-event-{i}"), event.encode().as_bytes());
        auth.add(
            &format!("engineio-message-{i}"),
            EngineIoPacket::Message(event.encode()).encode().as_bytes(),
        );
    }
    let request = HttpRequest {
        request_id: [9; 32],
        method: "POST".into(),
        path: "/api/thing".into(),
        search: "?a=1".into(),
        headers: vec![("content-type".into(), "application/json".into())],
        body: b"{}".to_vec(),
    };
    auth.add("http-request", &request.to_payload());
    let response = HttpResponse {
        request_id: [9; 32],
        status: 200,
        headers: vec![("x-bsv-thing".into(), "1".into())],
        body: b"ok".to_vec(),
    };
    auth.add("http-response", &response.to_payload());
    auth.add(
        "headers",
        b"x-bsv-auth-nonce: q83vEjRWeJCrze8SNFZ4kKvN7xI0VniQq83vEjRWeJA=\nx-bsv-auth-signature: MAYCAQECAQE=\n",
    );
    auth.add("engineio-open", br#"0{"sid":"abc","upgrades":[],"pingInterval":25000,"pingTimeout":20000,"maxPayload":1000000}"#);
    auth.add("socketio-connect", b"0/custom,{\"token\":\"x\"}");
    auth.add("socketio-ack", b"312[\"ok\"]");
    auth.report("fuzz_auth_messages");
}

fn script_corpus(base: &Path, rest: Option<&Path>) {
    let mut spend = Corpus::new(base, "fuzz_script_spend");
    let mut rest_corpus = rest.map(|dir| Corpus::new(dir, "fuzz_script_spend"));
    let shape = |mode: u8, unlocking: &[u8], locking: &[u8]| -> Vec<u8> {
        let mut seed = vec![mode];
        seed.extend_from_slice(&(unlocking.len() as u16).to_le_bytes());
        seed.extend_from_slice(unlocking);
        seed.extend_from_slice(locking);
        seed
    };
    for file in [
        "tests/vectors/script_valid.json",
        "tests/vectors/spend_valid.json",
    ] {
        let rows: Value = serde_json::from_str(&read(file)).unwrap();
        for (i, row) in rows.as_array().unwrap().iter().enumerate() {
            let (Some(sig), Some(pubkey)) =
                (row["scriptSig"].as_str(), row["scriptPubKey"].as_str())
            else {
                continue;
            };
            let (Ok(sig), Ok(pubkey)) = (from_hex(sig), from_hex(pubkey)) else {
                continue;
            };
            let stem = Path::new(file)
                .file_stem()
                .unwrap()
                .to_string_lossy()
                .to_string();
            spend.add(&format!("{stem}-{i}"), &shape(6, &sig, &pubkey));
        }
    }

    let default = format!(
        "{}/bsv/bsv-script-lean/corpus/seed/seed.jsonl",
        std::env::var("HOME").unwrap_or_default()
    );
    let path = std::env::var("BSV_SCRIPT_SEED").unwrap_or(default);
    match fs::read_to_string(&path) {
        Err(e) => println!("fuzz_script_spend: SKIPPED the sibling's seed rows ({path}: {e})"),
        Ok(text) => {
            let mut families = BTreeSet::new();
            let mut converted = 0usize;
            for line in text.lines() {
                let row: Value = serde_json::from_str(line).unwrap();
                let Ok(tx) = from_hex(row["tx"].as_str().unwrap()) else {
                    continue;
                };
                let Ok(raw) = parse_transaction(&tx) else {
                    continue;
                };
                let [input, ..] = &raw.inputs[..] else {
                    continue;
                };
                let Ok(locking) = from_hex(row["prevouts"][0]["script"].as_str().unwrap_or(""))
                else {
                    continue;
                };
                let params = &row["params"];
                let mode = u8::from(params["consensus"] != json!(true))
                    | if params["era"] == json!("post-chronicle") {
                        2
                    } else {
                        0
                    }
                    | if params["tx_version"].as_i64().unwrap_or(1) >= 2 {
                        4
                    } else {
                        0
                    };
                let seed = shape(mode, &input.script, &locking);
                let id = row["id"].as_str().unwrap();
                converted += 1;
                if families.insert(row["family"].as_str().unwrap().to_string()) {
                    spend.add(&format!("lean-{id}"), &seed);
                } else if let Some(c) = rest_corpus.as_mut() {
                    c.add(&format!("lean-{id}"), &seed);
                }
            }
            println!(
                "fuzz_script_spend: {converted} sibling rows converted, {} families checked in",
                families.len()
            );
        }
    }
    spend.report("fuzz_script_spend");
    if let Some(c) = rest_corpus {
        c.report("fuzz_script_spend (rest)");
    }
}

/// The serde-shaped wallet arguments: which of the shared vectors' `json`
/// (the Go SDK's) this crate's types read.
fn args_census() {
    fn check<T: serde::de::DeserializeOwned>(name: &str) {
        let path = format!("tests/vectors/wallet_wire/{name}");
        let value: Value = serde_json::from_str(&read(&path)).unwrap();
        match serde_json::from_value::<T>(value["json"].clone()) {
            Ok(_) => println!("  args {name}: reads"),
            Err(e) => println!("  args {name}: REFUSED ({e})"),
        }
    }
    use bsv_rs::wallet::*;
    check::<CreateActionArgs>("createAction-1-out-args.json");
    check::<SignActionArgs>("signAction-simple-args.json");
    check::<AbortActionArgs>("abortAction-simple-args.json");
    check::<ListActionsArgs>("listActions-simple-args.json");
    check::<InternalizeActionArgs>("internalizeAction-simple-args.json");
    check::<ListOutputsArgs>("listOutputs-simple-args.json");
    check::<RelinquishOutputArgs>("relinquishOutput-simple-args.json");
    check::<AcquireCertificateArgs>("acquireCertificate-simple-args.json");
    check::<AcquireCertificateArgs>("acquireCertificate-issuance-args.json");
    check::<ListCertificatesArgs>("listCertificates-simple-args.json");
    check::<ProveCertificateArgs>("proveCertificate-simple-args.json");
    check::<RelinquishCertificateArgs>("relinquishCertificate-simple-args.json");
    check::<DiscoverByIdentityKeyArgs>("discoverByIdentityKey-simple-args.json");
    check::<DiscoverByAttributesArgs>("discoverByAttributes-simple-args.json");
    check::<GetHeaderArgs>("getHeaderForHeight-simple-args.json");
}

fn main() {
    if std::env::args().any(|a| a == "--args-census") {
        args_census();
        return;
    }
    let args: Vec<String> = std::env::args().collect();
    let rest = args
        .iter()
        .position(|a| a == "--rest")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from);
    let base = Path::new(ROOT).join("fuzz/corpus");
    beef_corpora(&base);
    wallet_corpora(&base);
    key_corpora(&base);
    auth_corpus(&base);
    script_corpus(&base, rest.as_deref());
    parser_corpora(&base);
    reader_corpora(&base);
}

/// The six targets that predate this corpus: the parsers' inputs as the
/// vectors carry them.
fn parser_corpora(base: &Path) {
    let mut tx = Corpus::new(base, "fuzz_transaction_parser");
    for (i, hex) in tx_valid::TX_VALID_VECTORS.iter().enumerate() {
        tx.add(&format!("tx-valid-{i}"), &from_hex(hex).unwrap());
    }
    tx.add("tx-simple", &from_hex(tx_valid::TX_SIMPLE).unwrap());
    tx.add("multi-io", &from_hex(bigtx::MULTI_IO_TX_HEX).unwrap());
    tx.add("large", &from_hex(bigtx::LARGE_TX_HEX).unwrap());
    tx.report("fuzz_transaction_parser");

    let mut script = Corpus::new(base, "fuzz_script_parser");
    let rows: Value = serde_json::from_str(&read("tests/vectors/script_valid.json")).unwrap();
    for (i, row) in rows.as_array().unwrap().iter().enumerate().step_by(4) {
        if let Some(Ok(bytes)) = row["scriptPubKey"].as_str().map(from_hex) {
            script.add(&format!("script-valid-{i}"), &bytes);
        }
    }
    script.report("fuzz_script_parser");

    let mut wire = Corpus::new(base, "fuzz_wire_protocol");
    for (name, value) in vector_files() {
        let bytes = hex::decode(value["wire"].as_str().unwrap()).unwrap();
        if name.contains("-args") && bytes.len() > 2 {
            let params = &bytes[2 + bytes[1] as usize..];
            wire.add(&format!("params-{name}"), params);
        }
    }
    wire.report("fuzz_wire_protocol");

    let mut base58 = Corpus::new(base, "fuzz_base58");
    let key = PrivateKey::from_bytes(&[5; 32]).unwrap();
    base58.add("wif", key.to_wif().as_bytes());
    base58.add("address", key.public_key().to_address().as_bytes());
    base58.add("hex", b"00ff10ab");
    base58.add("base64", b"SGVsbG8h");
    base58.report("fuzz_base58");

    let mut chain = Corpus::new(base, "fuzz_chain_primitives");
    // The genesis header, by its fields.
    let genesis = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c";
    chain.add("genesis-header", &from_hex(genesis).unwrap());
    chain.add("genesis-header-hex", genesis.as_bytes());
    chain.add("bits", &0x1d00ffffu32.to_le_bytes());
    chain.add("varint", &[0xfd, 0x00, 0x01]);
    chain.report("fuzz_chain_primitives");
}

/// The five readers of #140: the signed and encrypted messages (BRC-77,
/// BRC-78), the BSM envelope, BIP-39 and the Shamir backup. The targets'
/// fixed keys are the bytes 6, 7, 8 (sender, recipient, another) and 9 (the
/// BSM key), repeated to 32. The message writers and the share split take
/// their key id, IV and coefficients through the `_with` forms (#180), each a
/// fixed byte repeated to 32 (the key id 1, the IV 2, the coefficients 3 on),
/// so a rerun writes the same bytes.
fn reader_corpora(base: &Path) {
    let key = |b: u8| PrivateKey::from_bytes(&[b; 32]).unwrap();
    let (sender, recipient, other) = (key(6), key(7), key(8));

    let mut signed = Corpus::new(base, "fuzz_messages_signed");
    // The message `fuzz_messages_signed` verifies against.
    let message = b"fuzz_messages_signed";
    for (name, verifier) in [
        ("recipient", Some(recipient.public_key())),
        ("anyone", None),
        ("other", Some(other.public_key())),
    ] {
        let sig = messages::sign_with(message, &sender, verifier.as_ref(), [1; 32]).unwrap();
        signed.add(&format!("signed-{name}"), &sig);
        signed.add(&format!("signed-{name}-header"), &sig[..sig.len().min(102)]);
    }
    signed.report("fuzz_messages_signed");

    let mut encrypted = Corpus::new(base, "fuzz_messages_encrypted");
    for plaintext in [&b""[..], b"Secret", &[0x42; 64]] {
        let n = plaintext.len();
        let sealed = messages::encrypt_with(
            plaintext,
            &sender,
            &recipient.public_key(),
            [1; 32],
            [2; 32],
        )
        .unwrap();
        encrypted.add(&format!("encrypted-{n}"), &sealed);
        let sealed =
            messages::encrypt_with(plaintext, &sender, &other.public_key(), [1; 32], [2; 32])
                .unwrap();
        encrypted.add(&format!("encrypted-other-{n}"), &sealed);
        encrypted.add(&format!("plain-{n}"), plaintext);
    }
    encrypted.report("fuzz_messages_encrypted");

    let mut envelope = Corpus::new(base, "fuzz_bsm");
    let bsm_key = key(9);
    // Named by position: "hello world" and "Hello, BSV!" are both 11 bytes.
    for (k, message) in [&b"hello world"[..], b"", b"Hello, BSV!", &[b'a'; 300]]
        .iter()
        .enumerate()
    {
        for compressed in [true, false] {
            let sig = bsm::sign_message_with_compression(&bsm_key, message, compressed).unwrap();
            let mut seed = sig.clone();
            seed.extend_from_slice(message);
            envelope.add(&format!("compact-{compressed}-{k}"), &seed);
            let mut text = to_base64(&sig).into_bytes();
            text.push(b'\n');
            text.extend_from_slice(message);
            envelope.add(&format!("base64-{compressed}-{k}"), &text);
        }
    }
    let der = bsm_key.sign(&bsm::magic_hash(b"")).unwrap().to_der();
    envelope.add("der-empty", &der);
    // The TypeScript SDK's signature over "hello world" (`src/compat/bsm.rs`,
    // `test_cross_sdk_bsm_known_vector`), as an envelope.
    envelope.add(
        "ts-sdk-hello-world",
        b"H4T8Asr0WkC6wYfBESR6pCAfECtdsPM4fwiSQ2qndFi8dVtv/mrOFaySx9xQE7j24ugoJ4iGnsRwAC8QwaoHOXk=\nhello world",
    );
    envelope.report("fuzz_bsm");

    // The BIP-39 vectors (TREZOR's, and the Go SDK's bad sentences) as
    // `tests/compat_bip39_tests.rs` carries them, each entropy also as a
    // phrase of every language.
    let mut bip39 = Corpus::new(base, "fuzz_bip39");
    let languages = [
        Language::ChineseSimplified,
        Language::ChineseTraditional,
        Language::Czech,
        Language::English,
        Language::French,
        Language::Italian,
        Language::Japanese,
        Language::Korean,
        Language::Spanish,
    ];
    let text = read("tests/compat_bip39_tests.rs");
    let quoted = |line: &str| line.split('"').nth(1).map(str::to_string);
    let mut in_bad = false;
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.starts_with("fn bad_mnemonic_sentences") {
            in_bad = true;
        } else if in_bad && line == "}" {
            in_bad = false;
        }
        if let Some(entropy) = line.strip_prefix("entropy: ").and_then(quoted) {
            let Ok(bytes) = from_hex(&entropy) else {
                continue;
            };
            bip39.add(&format!("entropy-{i}"), &bytes);
            for language in languages {
                if let Ok(m) = Mnemonic::from_entropy_with_language(&bytes, language) {
                    bip39.add(&format!("phrase-{language:?}-{i}"), m.phrase().as_bytes());
                }
            }
        } else if let Some(phrase) = line.strip_prefix("mnemonic: ").and_then(quoted) {
            bip39.add(&format!("mnemonic-{i}"), phrase.as_bytes());
            let shouted = format!("  {}  ", phrase.to_uppercase().replace(' ', "\t "));
            bip39.add(&format!("mnemonic-spelled-{i}"), shouted.as_bytes());
        } else if in_bad && line.starts_with('"') {
            if let Some(phrase) = quoted(line) {
                bip39.add(&format!("bad-{i}"), phrase.as_bytes());
            }
        }
    }
    bip39.report("fuzz_bip39");

    // Shamir backups as `split_private_key` and `to_backup_format` write
    // them (`tests/integration_tests.rs`' 3-of-5 and its subsets), one share
    // per line, the coefficients the bytes 3, 4, ... repeated to 32.
    let mut shamir = Corpus::new(base, "fuzz_shamir_backup");
    for (b, threshold, total) in [(5u8, 3usize, 5usize), (10, 2, 3), (11, 5, 8)] {
        let coefficients: Vec<[u8; 32]> = (3..).take(threshold - 1).map(|c| [c; 32]).collect();
        let lines = split_private_key_with(&key(b), threshold, total, &coefficients)
            .unwrap()
            .to_backup_format();
        shamir.add(
            &format!("split-{threshold}-of-{total}"),
            lines.join("\n").as_bytes(),
        );
        let subset = lines[..threshold].join("\n");
        shamir.add(&format!("subset-{threshold}-of-{total}"), subset.as_bytes());
        let fewer = lines[..threshold - 1].join("\n");
        shamir.add(&format!("fewer-{threshold}-of-{total}"), fewer.as_bytes());
        let mut mixed = lines[..threshold].to_vec();
        mixed[0] = mixed[0].replace(&format!(".{threshold}."), &format!(".{}.", threshold + 1));
        shamir.add(
            &format!("mismatch-{threshold}-of-{total}"),
            mixed.join("\n").as_bytes(),
        );
    }
    shamir.add("zero-point", b"1.1.2.abcd\n2.3J.2.abcd");
    shamir.report("fuzz_shamir_backup");
}
