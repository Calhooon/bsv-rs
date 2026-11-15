//! `StorageDownloader::resolve` names a host only from an advertisement its
//! host signed and its host's linked key locks, for the file asked for (the
//! stable line's port of #544's storage site). On advertisements this file
//! builds (the host's signed one; unsigned, junk-signed, signed by another
//! key, locked with another key, for another file, changed after signing,
//! its host named by a 65-byte key) and on the storage cases of
//! `tests/vectors/token_envelope_544.json`
//! (`tests/support/token_envelope_544.mjs`): its signed advertisement names
//! its host, and its unsigned, wrongly locked, wrongly signed, other-file and
//! expired ones name none. Hermetic: an in-process resolver on an
//! `.invalid` host.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(feature = "storage")]

use async_trait::async_trait;
use bsv_rs::overlay::{
    LookupAnswer, LookupQuestion, LookupResolver, LookupResolverConfig, OutputListItem,
    OverlayLookupFacilitator,
};
use bsv_rs::primitives::{PrivateKey, PublicKey};
use bsv_rs::script::templates::PushDrop;
use bsv_rs::script::LockingScript;
use bsv_rs::storage::{
    get_hash_from_url, get_url_for_file, StorageDownloader, StorageDownloaderConfig,
};
use bsv_rs::transaction::{Transaction, TransactionInput, TransactionOutput};
use bsv_rs::wallet::{
    Counterparty, CreateSignatureArgs, KeyDeriver, ProtoWallet, Protocol, SecurityLevel,
};
use std::collections::HashMap;
use std::sync::Arc;

const LOCATION: &str = "https://host.invalid/file";

/// A lookup host that answers `ls_uhrp` with one advertisement.
struct Answering(OutputListItem);

#[async_trait(?Send)]
impl OverlayLookupFacilitator for Answering {
    async fn lookup(
        &self,
        _url: &str,
        _question: &LookupQuestion,
        _timeout_ms: Option<u64>,
    ) -> bsv_rs::Result<LookupAnswer> {
        Ok(LookupAnswer::OutputList {
            outputs: vec![self.0.clone()],
        })
    }
}

/// The hosts `resolve` names for `url` when the lookup answers `script`.
async fn hosts(url: &str, script: &LockingScript) -> Vec<String> {
    let mut tx = Transaction::new();
    tx.add_input(TransactionInput::new("11".repeat(32), 0))
        .unwrap();
    tx.add_output(TransactionOutput::new(1, script.clone()))
        .unwrap();
    let item = OutputListItem {
        beef: tx.to_beef(true).unwrap(),
        output_index: 0,
        context: None,
    };
    let resolver = LookupResolver::new(LookupResolverConfig {
        facilitator: Some(Arc::new(Answering(item))),
        host_overrides: Some(HashMap::from([(
            "ls_uhrp".to_string(),
            vec!["https://lookup.invalid".to_string()],
        )])),
        ..Default::default()
    });
    StorageDownloader::new(StorageDownloaderConfig {
        resolver: Some(Arc::new(resolver)),
        ..Default::default()
    })
    .resolve(url)
    .await
    .unwrap()
}

fn protocol() -> Protocol {
    Protocol::new(SecurityLevel::Counterparty, "uhrp advertisement")
}

/// The five data fields of `host`'s advertisement for the file of `url`.
fn data(host: &PublicKey, url: &str) -> Vec<Vec<u8>> {
    vec![
        host.to_compressed().to_vec(),
        get_hash_from_url(url).unwrap().to_vec(),
        LOCATION.as_bytes().to_vec(),
        vec![0xfe, 0xff, 0xff, 0xff, 0x7f], // expiry, far ahead
        vec![0x10],                         // file size
    ]
}

fn sign(signer: &PrivateKey, fields: &[Vec<u8>]) -> Vec<u8> {
    ProtoWallet::new(Some(signer.clone()))
        .create_signature(CreateSignatureArgs {
            data: Some(fields.concat()),
            hash_to_directly_sign: None,
            protocol_id: protocol(),
            key_id: "1".to_string(),
            counterparty: Some(Counterparty::Anyone),
        })
        .unwrap()
        .signature
}

/// The host's linked key for `anyone`: the key that locks its advertisement.
fn linked(host: &PrivateKey) -> PublicKey {
    KeyDeriver::new(Some(host.clone()))
        .derive_public_key(&protocol(), "1", &Counterparty::Anyone, true)
        .unwrap()
}

fn advertisement(fields: &[Vec<u8>], signature: Vec<u8>, lock: PublicKey) -> LockingScript {
    let mut fields = fields.to_vec();
    fields.push(signature);
    PushDrop::new(lock, fields).lock()
}

#[tokio::test(flavor = "current_thread")]
async fn a_host_is_named_only_from_an_advertisement_its_host_signed_for_the_file_544() {
    let url = get_url_for_file(b"the file asked for").unwrap();
    let other = get_url_for_file(b"another file").unwrap();
    let host = PrivateKey::random();
    let stranger = PrivateKey::random();
    let fields = data(&host.public_key(), &url);
    let signature = sign(&host, &fields);
    let honest = advertisement(&fields, signature.clone(), linked(&host));
    assert_eq!(hosts(&url, &honest).await, vec![LOCATION.to_string()]);

    let mut changed = fields.clone();
    changed[2] = b"https://other.invalid/file".to_vec();
    let for_other = data(&host.public_key(), &other);
    let unsigned = PushDrop::new(
        linked(&host),
        vec![
            b"uhrp".to_vec(),
            stranger.public_key().to_compressed().to_vec(),
            LOCATION.as_bytes().to_vec(),
            vec![0xfe, 0xff, 0xff, 0xff, 0x7f],
            vec![0x10],
        ],
    )
    .lock();
    let refused = [
        ("unsigned", unsigned),
        (
            "a junk signature",
            advertisement(&fields, vec![0x30, 0x01, 0x02], linked(&host)),
        ),
        (
            "signed by another key",
            advertisement(&fields, sign(&stranger, &fields), linked(&host)),
        ),
        (
            "signed by another key, locked with it",
            advertisement(&fields, sign(&stranger, &fields), linked(&stranger)),
        ),
        (
            "signed, locked with another key",
            advertisement(&fields, signature.clone(), linked(&stranger)),
        ),
        (
            "signed, locked with the host's identity key",
            advertisement(&fields, signature.clone(), host.public_key()),
        ),
        (
            "a field changed after signing",
            advertisement(&changed, signature, linked(&host)),
        ),
        (
            "signed, for another file",
            advertisement(&for_other, sign(&host, &for_other), linked(&host)),
        ),
    ];
    for (case, script) in &refused {
        assert_eq!(hosts(&url, script).await, Vec::<String>::new(), "{case}");
    }
}

/// An advertisement whose host field holds the host's key uncompressed (65
/// bytes) names no host, though the host signed it and its linked key locks
/// it: the host is read as a 33-byte key alone.
#[tokio::test(flavor = "current_thread")]
async fn a_host_field_of_65_bytes_names_no_host_544() {
    let url = get_url_for_file(b"the file asked for").unwrap();
    let host = PrivateKey::random();
    let mut fields = data(&host.public_key(), &url);
    fields[0] = host.public_key().to_uncompressed().to_vec();
    let script = advertisement(&fields, sign(&host, &fields), linked(&host));
    assert_eq!(hosts(&url, &script).await, Vec::<String>::new());
}

/// The storage cases of the vector this port judges: the authentication's
/// and the binding's. `http_location` and `noncanonical_envelope` are a
/// location's form and an envelope's form, not an advertisement's author:
/// the stable line reads them as it did, and they are outside this file.
#[tokio::test(flavor = "current_thread")]
async fn the_vectors_signed_advertisement_names_its_host_and_its_unauthenticated_ones_none_544() {
    let v: serde_json::Value =
        serde_json::from_str(include_str!("vectors/token_envelope_544.json")).unwrap();
    let url = v["storage"]["uhrp_url"].as_str().unwrap();
    let judged = [
        "reference",
        "other_file",
        "expired",
        "unsigned",
        "wrong_lock_key",
        "bad_signature",
    ];
    let mut seen = 0;
    for case in v["storage"]["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        if !judged.contains(&name) {
            continue;
        }
        seen += 1;
        let script = LockingScript::from_hex(case["locking_script"].as_str().unwrap()).unwrap();
        let expected: Vec<String> = serde_json::from_value(case["hosts"].clone()).unwrap();
        assert_eq!(hosts(url, &script).await, expected, "{name}");
    }
    assert_eq!(seen, judged.len());
}
