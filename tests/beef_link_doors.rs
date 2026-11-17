//! The #749 fold2 ruling 1: the overlay "output-only" doors link nothing.
//!
//! Five doors parse a stranger's BEEF answer and read ONLY one output's own
//! locking script — the lookup resolver's SLAP parse, the kvstore query, the
//! storage downloader, topic discovery and the registry definition parsers.
//! None of them uses the input ancestry, so each now parses with
//! [`Transaction::from_beef_subject`] (no linking) rather than
//! [`Transaction::from_beef`] (which links and applies the #749 byte bound).
//!
//! On this line the overlay resolver harness (host resolution, the #775/#796
//! byte budget and txid-hint dedup) differs from the stable line's, so these
//! are PARSER-BOUNDARY pins: each builds a BEEF whose shared-parent ancestry the
//! linking door refuses (`BeefResourceLimit`) but whose subject output carries
//! the door's own token, and asserts the linking door refuses while the subject
//! door surfaces the token through that door's own decoder. A door that kept
//! `from_beef` would refuse the answer before its output is ever read, so the
//! parser choice is the whole of the #749 behaviour here. The full behavioural
//! door tests, end to end through a mock facilitator, run on the main line.
#![cfg(feature = "full")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use tokio::sync::RwLock;

use bsv_rs::overlay::{
    create_signed_overlay_admin_token, decode_overlay_admin_token, LookupAnswer, LookupQuestion,
    LookupResolver, LookupResolverConfig, NetworkPreset, OutputListItem, OverlayLookupFacilitator,
    Protocol, RequireAck, TopicBroadcaster, TopicBroadcasterConfig,
};
use bsv_rs::primitives::{PrivateKey, PublicKey};
use bsv_rs::script::templates::PushDrop;
use bsv_rs::script::{LockingScript, UnlockingScript};
use bsv_rs::transaction::{Beef, MerklePath, Transaction, TransactionInput, TransactionOutput};
use bsv_rs::{Error, Result};

const FAN: usize = 120;
const OUTPUT_BYTES: usize = 2 * 1024;

/// Builds a BEEF whose subject carries `token` at output 0 and spends a shared
/// parent of `FAN` large outputs through `FAN` inputs — so linking it
/// re-materializes ~29 MiB, past the 16 MiB default. Only the former links the
/// ancestry; the subject door reads the token untouched.
fn hostile_answer_with_token(token: LockingScript) -> Vec<u8> {
    let filler = LockingScript::from_binary(&vec![0u8; OUTPUT_BYTES]).unwrap();
    let mut parent = Transaction::new();
    let mut funding = TransactionInput::new("11".repeat(32), 0);
    funding.unlocking_script = Some(UnlockingScript::new());
    parent.inputs_mut().push(funding);
    for _ in 0..FAN {
        parent
            .outputs_mut()
            .push(TransactionOutput::new(1_000, filler.clone()));
    }
    let parent_txid = parent.id();

    let mut beef = Beef::new();
    let bump = beef.merge_bump(MerklePath::from_coinbase_txid(&parent_txid, 800_000));
    beef.merge_raw_tx(parent.to_binary(), Some(bump)).unwrap();

    let mut subject = Transaction::new();
    for vout in 0..FAN {
        let mut spend = TransactionInput::new(parent_txid.clone(), vout as u32);
        spend.unlocking_script = Some(UnlockingScript::new());
        subject.inputs_mut().push(spend);
    }
    // Exactly 1 satoshi: this line's overlay doors admit an advertisement output
    // only at 1 sat (#786), so the token must sit there for the behavioural
    // guards to read it (the boundary pins read the script regardless of value).
    subject.outputs_mut().push(TransactionOutput::new(1, token));
    beef.merge_raw_tx(subject.to_binary(), None).unwrap();
    beef.to_binary().unwrap()
}

/// Asserts the fixture is one the LINKING door refuses but the subject door
/// reads, and returns the subject's output-0 locking script.
fn refused_by_link_surfaced_by_subject(beef: &[u8]) -> LockingScript {
    assert!(
        matches!(
            Transaction::from_beef(beef, None),
            Err(Error::BeefResourceLimit(_))
        ),
        "the linking door must refuse the fixture, so a door that keeps linking would drop it"
    );
    let subject = Transaction::from_beef_subject(beef, None)
        .expect("the subject door parses the same answer without linking");
    subject.outputs()[0].locking_script.clone()
}

fn a_pubkey() -> PublicKey {
    bsv_rs::wallet::ProtoWallet::new(None).identity_key()
}

fn var_int(value: u64) -> Vec<u8> {
    if value < 0xFD {
        vec![value as u8]
    } else if value <= 0xFFFF {
        let mut v = vec![0xFD];
        v.extend_from_slice(&(value as u16).to_le_bytes());
        v
    } else if value <= 0xFFFF_FFFF {
        let mut v = vec![0xFE];
        v.extend_from_slice(&(value as u32).to_le_bytes());
        v
    } else {
        let mut v = vec![0xFF];
        v.extend_from_slice(&value.to_le_bytes());
        v
    }
}

#[test]
fn the_resolver_slap_door_links_nothing_on_a_hostile_answer() {
    let root = PrivateKey::random();
    let token = create_signed_overlay_admin_token(
        &root,
        Protocol::Slap,
        "https://host-749.example",
        "ls_749",
    );
    let script = refused_by_link_surfaced_by_subject(&hostile_answer_with_token(token.clone()));
    // The exact SLAP advertisement the resolver's parse reads survives at the
    // subject output of an answer the linking door refuses.
    assert_eq!(script, token);
    if let Ok(decoded) = decode_overlay_admin_token(&script) {
        assert_eq!(decoded.protocol, Protocol::Slap);
    }
}

#[test]
fn the_topic_discovery_door_links_nothing_on_a_hostile_answer() {
    let root = PrivateKey::random();
    let token = create_signed_overlay_admin_token(
        &root,
        Protocol::Ship,
        "https://host-749.example",
        "tm_749",
    );
    let script = refused_by_link_surfaced_by_subject(&hostile_answer_with_token(token.clone()));
    // The exact SHIP advertisement topic discovery reads survives at the subject
    // output of an answer the linking door refuses.
    assert_eq!(script, token);
    if let Ok(decoded) = decode_overlay_admin_token(&script) {
        assert_eq!(decoded.protocol, Protocol::Ship);
    }
}

#[test]
fn the_kvstore_door_links_nothing_on_a_hostile_answer() {
    let controller = a_pubkey();
    let token = kvstore_token("kvstore", "k", "v", &controller);
    let script = refused_by_link_surfaced_by_subject(&hostile_answer_with_token(token));
    let entry = bsv_rs::kvstore::KVStoreInterpreter::extract_fields(&script)
        .expect("the kvstore token survives at the subject output");
    assert_eq!(entry.key, b"k");
    assert_eq!(entry.value, b"v");
}

fn kvstore_token(
    protocol_id: &str,
    key: &str,
    value: &str,
    controller: &PublicKey,
) -> LockingScript {
    let fields = vec![
        protocol_id.as_bytes().to_vec(),
        key.as_bytes().to_vec(),
        value.as_bytes().to_vec(),
        controller.to_compressed().to_vec(),
        vec![0u8; 64],
    ];
    PushDrop::new(controller.clone(), fields).lock()
}

#[test]
fn the_storage_downloader_door_links_nothing_on_a_hostile_answer() {
    let controller = a_pubkey();
    let future = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 86_400;
    let fields = vec![
        b"uhrp".to_vec(),
        controller.to_compressed().to_vec(),
        b"https://host-749.example".to_vec(),
        var_int(future),
    ];
    let token = PushDrop::new(controller, fields).lock();
    let script = refused_by_link_surfaced_by_subject(&hostile_answer_with_token(token));
    let pd = PushDrop::decode(&script).expect("the UHRP advertisement survives at the subject");
    assert!(pd.fields.len() >= 4, "the UHRP token keeps its fields");
    assert_eq!(pd.fields[2], b"https://host-749.example");
}

#[test]
fn the_registry_door_links_nothing_on_a_hostile_answer() {
    let controller = a_pubkey();
    let basket = bsv_rs::registry::BasketDefinitionData::new("basket749", "Basket 749")
        .with_icon_url("https://icon-749.example")
        .with_description("the 749 fold2 basket")
        .with_documentation_url("https://docs-749.example");
    let operator = "02".to_string() + &"ab".repeat(32);
    let fields = basket.to_pushdrop_fields(&operator);
    let token = PushDrop::new(controller, fields).lock();
    let script = refused_by_link_surfaced_by_subject(&hostile_answer_with_token(token));
    let pd = PushDrop::decode(&script).expect("the basket definition survives at the subject");
    assert_eq!(pd.fields.len(), 6, "the basket token keeps its six fields");
    let back = bsv_rs::registry::BasketDefinitionData::from_pushdrop_fields(&pd.fields)
        .expect("the basket definition reads back from the subject output");
    assert_eq!(back.basket_id, "basket749");
}

// ============================================================================
// BEHAVIOURAL guards (fold3 ruling 1): beside the parser-boundary pins above, a
// test that drives the REAL door end to end through a mock facilitator — RED if
// the production door reverts to `from_beef` (the hostile answer is then refused
// before its output is read, so the host never surfaces). The mock facilitator +
// host-override harness is the crate's own hermetic injection point (as
// `overlay_mock_tests.rs`).
//
// SCOPE on this line (fold4 ruling 3): all FIVE doors now carry a behavioural
// guard, beside the parser-boundary pins. The resolver and topic-discovery doors
// read a SLAP/SHIP admin token (`create_signed_overlay_admin_token`, a public
// writer). The kvstore, storage and registry doors verify a signature the
// stable line's doors do not — but a token each ACCEPTS is reachable: the crate
// signs a valid kvstore token itself (the wallet signer, counterparty Anyone —
// the beta door's `verify_signature` chain is identical to the stable line's),
// and the shared #544 conformance vector (`tests/vectors/token_envelope_544.json`,
// the same tokens `registry_envelope_544.rs` and
// `storage_advertisement_envelope_544.rs` drive those doors with) supplies an
// accepted registry basket definition and an accepted UHRP advertisement. The
// fold3 premise that "a hand-built token is refused, so no behavioural guard is
// possible" was false for all three; each is driven end to end below, RED on a
// revert to `from_beef`. The parser-boundary pins stay beside them.
// ============================================================================

/// A mock lookup facilitator returning canned answers keyed by URL.
struct MockLookupFacilitator {
    responses: RwLock<HashMap<String, LookupAnswer>>,
    call_count: AtomicU32,
}

impl MockLookupFacilitator {
    fn new() -> Self {
        Self {
            responses: RwLock::new(HashMap::new()),
            call_count: AtomicU32::new(0),
        }
    }

    async fn add_response(&self, url: &str, answer: LookupAnswer) {
        self.responses.write().await.insert(url.to_string(), answer);
    }
}

#[async_trait(?Send)]
impl OverlayLookupFacilitator for MockLookupFacilitator {
    async fn lookup(
        &self,
        url: &str,
        _question: &LookupQuestion,
        _timeout_ms: Option<u64>,
    ) -> Result<LookupAnswer> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        let responses = self.responses.read().await;
        match responses.get(url) {
            Some(answer) => Ok(answer.clone()),
            None => Ok(LookupAnswer::empty_output_list()),
        }
    }
}

/// Confirms the fixture is one the LINKING door refuses but the subject door
/// reads — so any door that keeps linking drops the answer.
fn assert_fixture_discriminates(beef: &[u8]) {
    assert!(
        matches!(
            Transaction::from_beef(beef, None),
            Err(Error::BeefResourceLimit(_))
        ),
        "the fixture must trip the link bound so a linking door would drop it"
    );
    assert!(
        Transaction::from_beef_subject(beef, None).is_ok(),
        "the subject door parses the same answer without linking"
    );
}

fn mock_resolver(
    preset: NetworkPreset,
    service: &str,
    mock: Arc<MockLookupFacilitator>,
) -> LookupResolver {
    let mut host_overrides = HashMap::new();
    host_overrides.insert(
        service.to_string(),
        vec!["http://mock-749-host:8080".to_string()],
    );
    LookupResolver::new(
        LookupResolverConfig::default()
            .with_network_preset(preset)
            .with_facilitator(Some(mock as Arc<dyn OverlayLookupFacilitator>))
            .with_slap_trackers(Some(vec![]))
            .with_host_overrides(Some(host_overrides)),
    )
}

fn output_list_of(beef: Vec<u8>) -> LookupAnswer {
    LookupAnswer::OutputList {
        outputs: vec![OutputListItem {
            beef,
            output_index: 0,
            context: None,
            txid: None,
        }],
    }
}

#[tokio::test]
async fn the_resolver_slap_door_links_nothing_behaviourally() {
    let root = PrivateKey::random();
    let service = "ls_resolverfold";
    let token = create_signed_overlay_admin_token(
        &root,
        Protocol::Slap,
        "https://host-749.example",
        service,
    );
    let beef = hostile_answer_with_token(token);
    assert_fixture_discriminates(&beef);

    let mock = Arc::new(MockLookupFacilitator::new());
    mock.add_response("http://slap-749-tracker:8080", output_list_of(beef))
        .await;
    let resolver = LookupResolver::new(
        LookupResolverConfig::default()
            .with_network_preset(NetworkPreset::Mainnet)
            .with_facilitator(Some(mock as Arc<dyn OverlayLookupFacilitator>))
            .with_slap_trackers(Some(vec!["http://slap-749-tracker:8080".to_string()])),
    );

    let hosts = resolver.find_competent_hosts(service).await.unwrap();
    assert!(
        hosts.contains(&"https://host-749.example".to_string()),
        "the resolver surfaced the SLAP host from an answer a linking door drops: {hosts:?}"
    );
}

#[tokio::test]
async fn the_topic_discovery_door_links_nothing_behaviourally() {
    let root = PrivateKey::random();
    let topic = "tm_topicfold";
    let token =
        create_signed_overlay_admin_token(&root, Protocol::Ship, "https://host-749.example", topic);
    let beef = hostile_answer_with_token(token);
    assert_fixture_discriminates(&beef);

    let mock = Arc::new(MockLookupFacilitator::new());
    mock.add_response("http://mock-749-host:8080", output_list_of(beef))
        .await;
    let resolver = Arc::new(mock_resolver(NetworkPreset::Mainnet, "ls_ship", mock));
    let broadcaster = TopicBroadcaster::new(
        vec![topic.to_string()],
        TopicBroadcasterConfig::default()
            .with_network_preset(NetworkPreset::Mainnet)
            .with_facilitator(None)
            .with_resolver(Some(resolver))
            .with_require_ack_from_all_hosts(RequireAck::None)
            .with_require_ack_from_any_host(RequireAck::None)
            .with_require_ack_from_specific_hosts(HashMap::new()),
    )
    .unwrap();

    let hosts = broadcaster.find_interested_hosts().await.unwrap();
    assert!(
        hosts.contains_key("https://host-749.example"),
        "topic discovery surfaced the SHIP host from an answer a linking door drops: {hosts:?}"
    );
}

// ============================================================================
// The three #543/#544 doors driven end to end (fold4 ruling 3)
// ============================================================================

/// The #544 conformance vector's locking script for `section`'s case `index`
/// — the ACCEPTED tokens `registry_envelope_544.rs` /
/// `storage_advertisement_envelope_544.rs` drive those same doors with.
fn vector_value() -> serde_json::Value {
    serde_json::from_str(include_str!("vectors/token_envelope_544.json")).unwrap()
}

fn vector_script(v: &serde_json::Value, section: &str, index: usize) -> LockingScript {
    let hex = v[section]["cases"][index]["locking_script"]
        .as_str()
        .unwrap();
    LockingScript::from_hex(hex).unwrap()
}

#[tokio::test]
async fn the_kvstore_query_door_links_nothing_behaviourally() {
    // Drive the REAL kvstore query door (`GlobalKVStore::get` -> `query_overlay`)
    // end to end. The hostile answer carries a VALIDLY SIGNED kvstore token (the
    // crate's own wallet signer, counterparty Anyone — this door's
    // `KVStoreInterpreter::verify_signature` chain is identical to the stable
    // line's) at its subject output; the door reads it via `from_beef_subject`
    // and the entry surfaces. Reverting `global.rs`'s `query_overlay` to
    // `from_beef` drops the whole answer (the amplifying ancestry is refused
    // before the output is read) -> RED.
    use bsv_rs::wallet::{
        Counterparty, CreateSignatureArgs, KeyDeriver, ProtoWallet, Protocol, SecurityLevel,
    };

    // The token this line's door accepts, built exactly as the crate's own
    // `tests/kvstore_global_tests.rs::create_signed_token` does: the protocol
    // field is JSON `[1,"kvstore"]`, the signing key_id is the key, the lock key
    // is the controller's key derived for the protocol/key/Anyone (what the
    // door's `verify_signature` checks it is linked to), and the signature over
    // the four data fields is appended last.
    let controller = PrivateKey::random();
    let controller_pub = controller.public_key();
    let protocol_id = "kvstore";
    let (key, value) = ("k", "v");
    let protocol = Protocol::new(SecurityLevel::App, protocol_id);
    let mut fields = vec![
        serde_json::to_vec(&(1, protocol_id)).unwrap(),
        key.as_bytes().to_vec(),
        value.as_bytes().to_vec(),
        controller_pub.to_compressed().to_vec(),
    ];
    let sig = ProtoWallet::new(Some(controller.clone()))
        .create_signature(CreateSignatureArgs {
            data: Some(fields.concat()),
            protocol_id: protocol.clone(),
            key_id: key.into(),
            counterparty: Some(Counterparty::Anyone),
            ..Default::default()
        })
        .unwrap()
        .signature;
    fields.push(sig);
    let lock = KeyDeriver::new(Some(controller.clone()))
        .derive_public_key(&protocol, key, &Counterparty::Anyone, true)
        .unwrap();
    let token = PushDrop::new(lock, fields).lock();

    let beef = hostile_answer_with_token(token);
    assert_fixture_discriminates(&beef);

    let service = "ls_kvstore749";
    let mock = Arc::new(MockLookupFacilitator::new());
    mock.add_response("http://mock-749-host:8080", output_list_of(beef))
        .await;
    let resolver = mock_resolver(NetworkPreset::Local, service, mock);
    let config = bsv_rs::kvstore::KVStoreConfig::new()
        .with_service_name(service)
        .with_protocol_id(protocol_id);
    let store = bsv_rs::kvstore::GlobalKVStore::with_resolver(
        ProtoWallet::new(None),
        config,
        NetworkPreset::Local,
        resolver,
    );

    let entry =
        store.get(key, None).await.unwrap().expect(
            "the kvstore door surfaced the signed entry from an answer a linking door drops",
        );
    assert_eq!(entry.key, "k");
    assert_eq!(entry.value, "v");
}

#[tokio::test]
async fn the_registry_door_links_nothing_behaviourally() {
    // Drive the REAL registry basket door (`RegistryClient::resolve_basket` ->
    // `parse_basket_from_output` -> `token::data_fields`, the #543 operator-
    // signature validator) end to end with the #544 vector's ACCEPTED basket
    // definition (case 0, outcome "resolved"). Revert to `from_beef` -> the
    // hostile ancestry is refused before the output is read -> RED.
    let v = vector_value();
    let token = vector_script(&v, "registry", 0);
    let beef = hostile_answer_with_token(token);
    assert_fixture_discriminates(&beef);

    let mock = Arc::new(MockLookupFacilitator::new());
    mock.add_response("http://mock-749-host:8080", output_list_of(beef))
        .await;
    let resolver = Arc::new(mock_resolver(NetworkPreset::Local, "ls_basketmap", mock));
    let client = bsv_rs::registry::RegistryClient::new(
        bsv_rs::wallet::ProtoWallet::new(None),
        bsv_rs::registry::RegistryClientConfig::new().with_resolver(resolver),
    );

    let found = client
        .resolve_basket(bsv_rs::registry::BasketQuery::default())
        .await
        .unwrap();
    assert!(
        !found.is_empty(),
        "the registry door surfaced the signed basket definition from an answer a linking door \
         drops: {found:?}"
    );
}

#[tokio::test]
async fn the_storage_downloader_door_links_nothing_behaviourally() {
    // Drive the REAL storage downloader door (`StorageDownloader::resolve` ->
    // `advertisement::decode_and_verify`, the #544 host-signature + hash + expiry
    // validator) end to end with the #544 vector's ACCEPTED advertisement (case
    // 0) and the vector's own uhrp_url, so the hash binds and the expiry holds.
    // Revert to `from_beef` -> RED.
    let v = vector_value();
    let uhrp_url = v["storage"]["uhrp_url"].as_str().unwrap().to_string();
    let token = vector_script(&v, "storage", 0);
    let beef = hostile_answer_with_token(token);
    assert_fixture_discriminates(&beef);

    let mock = Arc::new(MockLookupFacilitator::new());
    mock.add_response("http://mock-749-host:8080", output_list_of(beef))
        .await;
    let resolver = Arc::new(mock_resolver(NetworkPreset::Local, "ls_uhrp", mock));
    let downloader = bsv_rs::storage::StorageDownloader::new(
        bsv_rs::storage::StorageDownloaderConfig::default()
            .with_network_preset(NetworkPreset::Local)
            .with_resolver(Some(resolver))
            .with_timeout_ms(Some(5_000)),
    );

    let hosts = downloader.resolve(&uhrp_url).await.unwrap();
    assert!(
        !hosts.is_empty(),
        "the storage door surfaced the UHRP host from an answer a linking door drops: {hosts:?}"
    );
}
