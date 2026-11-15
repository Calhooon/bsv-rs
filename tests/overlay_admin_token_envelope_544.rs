//! The SLAP and SHIP discoveries admit a host only from an advertisement its
//! identity's linked key signed and locks (the stable line's port of #544's
//! discovery sites): `LookupResolver::find_competent_hosts` and
//! `TopicBroadcaster::find_interested_hosts` over a tracker's answer of one
//! advertisement, honest (`create_signed_overlay_admin_token`) and not
//! (the deprecated unsigned writer's, a junk signature, a signature by
//! another key, a signed one locked with another key, a field changed after
//! signing, one of six fields).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![allow(deprecated)] // the deprecated unsigned writer is one of the advertisements refused
#![cfg(feature = "overlay")]

use async_trait::async_trait;
use bsv_rs::overlay::{
    create_overlay_admin_token, create_signed_overlay_admin_token, LookupAnswer, LookupQuestion,
    LookupResolver, LookupResolverConfig, NetworkPreset, OutputListItem, OverlayLookupFacilitator,
    Protocol, TopicBroadcaster, TopicBroadcasterConfig,
};
use bsv_rs::primitives::{sha256, PrivateKey, PublicKey};
use bsv_rs::script::templates::PushDrop;
use bsv_rs::script::LockingScript;
use bsv_rs::transaction::{Transaction, TransactionInput, TransactionOutput};
use bsv_rs::wallet::{Counterparty, KeyDeriver, Protocol as WalletProtocol, SecurityLevel};
use std::collections::HashMap;
use std::sync::Arc;

const HOST: &str = "https://advertised.invalid";

/// A tracker that answers the discovery's question with one advertisement.
struct Tracker {
    service: &'static str,
    item: OutputListItem,
}

#[async_trait(?Send)]
impl OverlayLookupFacilitator for Tracker {
    async fn lookup(
        &self,
        _url: &str,
        question: &LookupQuestion,
        _timeout_ms: Option<u64>,
    ) -> bsv_rs::Result<LookupAnswer> {
        let outputs = if question.service == self.service {
            vec![self.item.clone()]
        } else {
            Vec::new()
        };
        Ok(LookupAnswer::OutputList { outputs })
    }
}

fn answer_of(script: &LockingScript) -> OutputListItem {
    let mut tx = Transaction::new();
    tx.add_input(TransactionInput::new("11".repeat(32), 0))
        .unwrap();
    tx.add_output(TransactionOutput::new(1, script.clone()))
        .unwrap();
    OutputListItem {
        beef: tx.to_beef(true).unwrap(),
        output_index: 0,
        context: None,
    }
}

fn resolver(service: &'static str, tracker: &str, script: &LockingScript) -> LookupResolver {
    LookupResolver::new(LookupResolverConfig {
        facilitator: Some(Arc::new(Tracker {
            service,
            item: answer_of(script),
        })),
        slap_trackers: Some(vec![tracker.to_string()]),
        // SHIP discovery asks `ls_ship` of the hosts the resolver names
        host_overrides: Some(HashMap::from([(
            "ls_ship".to_string(),
            vec![tracker.to_string()],
        )])),
        ..Default::default()
    })
}

/// The hosts SLAP discovery admits for `ls_kvstore` from the advertisement.
async fn slap_hosts(tracker: &str, script: &LockingScript) -> Vec<String> {
    resolver("ls_slap", tracker, script)
        .find_competent_hosts("ls_kvstore")
        .await
        .unwrap()
}

/// The hosts SHIP discovery admits for `tm_kvstore` from the advertisement.
async fn ship_hosts(tracker: &str, script: &LockingScript) -> Vec<String> {
    let lookup = resolver("ls_ship", tracker, script);
    let broadcaster = TopicBroadcaster::new(
        vec!["tm_kvstore".to_string()],
        TopicBroadcasterConfig {
            network_preset: NetworkPreset::Mainnet,
            resolver: Some(Arc::new(lookup)),
            ..Default::default()
        },
    )
    .unwrap();
    let mut hosts: Vec<String> = broadcaster
        .find_interested_hosts()
        .await
        .unwrap()
        .into_keys()
        .collect();
    hosts.sort();
    hosts
}

fn name_of(protocol: Protocol) -> (&'static str, &'static str) {
    match protocol {
        Protocol::Ship => ("service host interconnect", "tm_kvstore"),
        Protocol::Slap => ("service lookup availability", "ls_kvstore"),
    }
}

/// The identity's linked key for the protocol: the key that signs and locks.
fn linked(identity: &PrivateKey, protocol: Protocol) -> (PrivateKey, PublicKey) {
    let (name, _) = name_of(protocol);
    let protocol = WalletProtocol::new(SecurityLevel::Counterparty, name);
    let deriver = KeyDeriver::new(Some(identity.clone()));
    (
        deriver
            .derive_private_key(&protocol, "1", &Counterparty::Anyone)
            .unwrap(),
        deriver
            .derive_public_key(&protocol, "1", &Counterparty::Anyone, true)
            .unwrap(),
    )
}

fn data(protocol: Protocol, identity: &PublicKey) -> Vec<Vec<u8>> {
    let (_, topic) = name_of(protocol);
    vec![
        protocol.as_str().as_bytes().to_vec(),
        identity.to_compressed().to_vec(),
        HOST.as_bytes().to_vec(),
        topic.as_bytes().to_vec(),
    ]
}

fn advertisement(fields: &[Vec<u8>], signature: Vec<u8>, lock: PublicKey) -> LockingScript {
    let mut fields = fields.to_vec();
    fields.push(signature);
    PushDrop::new(lock, fields).lock()
}

/// Every advertisement of `identity`'s for the protocol that is not its own
/// signed one, with the honest one first.
fn advertisements(protocol: Protocol) -> (LockingScript, Vec<(&'static str, LockingScript)>) {
    let identity = PrivateKey::random();
    let stranger = PrivateKey::random();
    let (_, topic) = name_of(protocol);
    let honest = create_signed_overlay_admin_token(&identity, protocol, HOST, topic);
    let fields = data(protocol, &identity.public_key());
    let (signer, lock) = linked(&identity, protocol);
    let (stranger_signer, stranger_lock) = linked(&stranger, protocol);
    let signature = signer.sign(&sha256(&fields.concat())).unwrap().to_der();
    let by_stranger = stranger_signer
        .sign(&sha256(&fields.concat()))
        .unwrap()
        .to_der();
    let mut changed = fields.clone();
    changed[2] = b"https://other.invalid".to_vec();
    let refused = vec![
        (
            "the deprecated unsigned writer's",
            create_overlay_admin_token(protocol, &identity.public_key(), HOST, topic),
        ),
        (
            "a junk signature",
            advertisement(&fields, vec![0x30, 0x01, 0x02], lock.clone()),
        ),
        (
            "signed by another key",
            advertisement(&fields, by_stranger.clone(), lock.clone()),
        ),
        (
            "signed by another key, locked with it",
            advertisement(&fields, by_stranger, stranger_lock.clone()),
        ),
        (
            "signed, locked with another key",
            advertisement(&fields, signature.clone(), stranger_lock),
        ),
        (
            "signed, locked with the identity key",
            advertisement(&fields, signature.clone(), identity.public_key()),
        ),
        (
            "a field changed after signing",
            advertisement(&changed, signature, lock),
        ),
    ];
    (honest, refused)
}

#[tokio::test(flavor = "current_thread")]
async fn slap_discovery_admits_a_host_only_from_an_advertisement_its_identity_signed_544() {
    let (honest, refused) = advertisements(Protocol::Slap);
    let tracker = "https://slap-tracker-544.invalid";
    assert_eq!(slap_hosts(tracker, &honest).await, vec![HOST.to_string()]);
    for (case, script) in &refused {
        assert_eq!(
            slap_hosts(tracker, script).await,
            Vec::<String>::new(),
            "{case}"
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn ship_discovery_admits_a_host_only_from_an_advertisement_its_identity_signed_544() {
    let (honest, refused) = advertisements(Protocol::Ship);
    let tracker = "https://ship-tracker-544.invalid";
    assert_eq!(ship_hosts(tracker, &honest).await, vec![HOST.to_string()]);
    for (case, script) in &refused {
        assert_eq!(
            ship_hosts(tracker, script).await,
            Vec::<String>::new(),
            "{case}"
        );
    }
}

/// An advertisement of five data fields, signed over all five by the
/// identity's linked key and locked with it, admits no host in either
/// discovery: an advertisement is four data fields and their signature.
#[tokio::test(flavor = "current_thread")]
async fn an_advertisement_of_six_fields_admits_no_host_544() {
    for (protocol, tracker) in [
        (Protocol::Slap, "https://six-fields-544-a.invalid"),
        (Protocol::Ship, "https://six-fields-544-b.invalid"),
    ] {
        let identity = PrivateKey::random();
        let mut fields = data(protocol, &identity.public_key());
        fields.push(b"a fifth data field".to_vec());
        let (signer, lock) = linked(&identity, protocol);
        let signature = signer.sign(&sha256(&fields.concat())).unwrap().to_der();
        let script = advertisement(&fields, signature, lock);
        let found = match protocol {
            Protocol::Slap => slap_hosts(tracker, &script).await,
            Protocol::Ship => ship_hosts(tracker, &script).await,
        };
        assert_eq!(found, Vec::<String>::new());
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_discovery_admits_no_host_from_the_other_protocols_advertisement_544() {
    let (ship, _) = advertisements(Protocol::Ship);
    let (slap, _) = advertisements(Protocol::Slap);
    assert!(slap_hosts("https://cross-544-a.invalid", &ship)
        .await
        .is_empty());
    assert!(ship_hosts("https://cross-544-b.invalid", &slap)
        .await
        .is_empty());
}

/// The overlay cases of `tests/vectors/token_envelope_544.json`
/// (`tests/support/token_envelope_544.mjs`) this port judges: the canonical
/// writer's SHIP and SLAP advertisements admit their host; the legacy
/// unsigned one, and those signed by another key or locked with another key,
/// admit none. The other cases are an advertisement's form (its protocol
/// text, its URI, its name, its key's encoding, its signature's length, its
/// envelope), not its author: the stable line reads them as it did, and they
/// are outside this file.
#[tokio::test(flavor = "current_thread")]
async fn the_vectors_signed_advertisements_admit_their_host_and_the_unauthenticated_none_544() {
    let v: serde_json::Value =
        serde_json::from_str(include_str!("vectors/token_envelope_544.json")).unwrap();
    let judged = [
        ("reference_ship", true),
        ("reference_slap", true),
        ("legacy_unsigned", false),
        ("wrong_signer", false),
        ("wrong_lock_key", false),
        ("slap_wrong_signer", false),
        ("slap_wrong_lock_key", false),
    ];
    let mut seen = 0;
    for case in v["overlay"]["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let Some((_, admitted)) = judged.iter().find(|(judged, _)| *judged == name) else {
            continue;
        };
        seen += 1;
        let script = LockingScript::from_hex(case["locking_script"].as_str().unwrap()).unwrap();
        let token = PushDrop::decode(&script).unwrap();
        let protocol = String::from_utf8(token.fields[0].clone()).unwrap();
        let domain = String::from_utf8(token.fields[2].clone()).unwrap();
        let name_field = String::from_utf8(token.fields[3].clone()).unwrap();
        let tracker = format!("https://vector-{name}-544.invalid");
        let found = match protocol.as_str() {
            "SLAP" => resolver("ls_slap", &tracker, &script)
                .find_competent_hosts(&name_field)
                .await
                .unwrap(),
            _ => {
                let broadcaster = TopicBroadcaster::new(
                    vec![name_field.clone()],
                    TopicBroadcasterConfig {
                        network_preset: NetworkPreset::Mainnet,
                        resolver: Some(Arc::new(resolver("ls_ship", &tracker, &script))),
                        ..Default::default()
                    },
                )
                .unwrap();
                broadcaster
                    .find_interested_hosts()
                    .await
                    .unwrap()
                    .into_keys()
                    .collect()
            }
        };
        let expected = if *admitted { vec![domain] } else { Vec::new() };
        assert_eq!(found, expected, "{name}");
    }
    assert_eq!(seen, judged.len());
}
