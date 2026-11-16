//! The #749 fold2 ruling 1: the overlay "output-only" doors link nothing.
//!
//! Five doors parse a stranger's BEEF answer and read ONLY one output's own
//! locking script — the lookup resolver's SLAP parse, the kvstore query, the
//! storage downloader, topic discovery and the registry definition parsers.
//! None of them uses the input ancestry, so each now parses with
//! [`Transaction::from_beef_subject`] (no linking) rather than
//! [`Transaction::from_beef`] (which links and applies the #749 byte bound).
//!
//! The consequence these tests pin: an honest answer whose ancestry WOULD trip
//! the 16 MiB default link bound is no longer dropped by these doors, because
//! they never link it — and an attacker cannot force the re-materialization at
//! these doors at all. Each test feeds the door a BEEF whose shared-parent
//! ancestry the linking door refuses (`BeefResourceLimit`) but whose subject
//! output carries a valid token, and asserts the door still surfaces it. A
//! revert to `from_beef` turns the test red: the refused link would drop the
//! answer before the output is ever read.
//!
//! CARRY NOTE (main-line release stack): two doors are reshaped on the stack the
//! coming release is cut from. The storage downloader now authenticates a signed
//! advertisement (#544), so its test uses a signed token of the same strength;
//! the registry resolves read no operator-signed definition at all (the
//! `parse_*_from_output` door is gone), so its test pins that the resolve links
//! nothing on the stack's shape. Both still fail if the door links again. See
//! each test's own note.
#![cfg(feature = "full")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::RwLock;

use bsv_rs::overlay::{
    create_signed_overlay_admin_token, LookupAnswer, LookupQuestion, LookupResolver,
    LookupResolverConfig, NetworkPreset, OutputListItem, OverlayLookupFacilitator, Protocol,
    RequireAck, TopicBroadcaster, TopicBroadcasterConfig,
};
use bsv_rs::primitives::{PrivateKey, PublicKey};
use bsv_rs::script::templates::PushDrop;
use bsv_rs::script::{LockingScript, UnlockingScript};
use bsv_rs::transaction::{Beef, MerklePath, Transaction, TransactionInput, TransactionOutput};
use bsv_rs::{Error, Result};

// A shared parent wide and large enough that linking it through every spending
// input re-materializes far past the 16 MiB default — so a linking door refuses
// the answer, while a subject-only door reads its output untouched.
const FAN: usize = 120;
const OUTPUT_BYTES: usize = 2 * 1024;

/// A mock lookup facilitator returning canned answers keyed by URL (copied from
/// `tests/overlay_mock_tests.rs`, the established hermetic injection point).
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

/// Builds a BEEF whose subject carries `token` at output 0 and spends a shared
/// parent of `FAN` large outputs through `FAN` inputs — so linking it
/// re-materializes `(FAN - 1)` copies of the whole parent, ~29 MiB, past the
/// 16 MiB default. The subject (the last entry) is what both `from_beef` and
/// `from_beef_subject` resolve to; only the former links the ancestry.
fn hostile_answer_with_token(token: LockingScript) -> Vec<u8> {
    let filler = LockingScript::from_binary(&vec![0u8; OUTPUT_BYTES]).unwrap();
    let mut parent = Transaction::new();
    let mut funding = TransactionInput::new("11".repeat(32), 0);
    funding.unlocking_script = Some(UnlockingScript::new());
    parent.inputs.push(funding);
    for _ in 0..FAN {
        parent
            .outputs
            .push(TransactionOutput::new(1_000, filler.clone()));
    }
    let parent_txid = parent.id();

    let mut beef = Beef::new();
    let bump = beef.merge_bump(MerklePath::from_coinbase_txid(&parent_txid, 800_000));
    beef.merge_raw_tx(parent.to_binary(), Some(bump));

    let mut subject = Transaction::new();
    for vout in 0..FAN {
        let mut spend = TransactionInput::new(parent_txid.clone(), vout as u32);
        spend.unlocking_script = Some(UnlockingScript::new());
        subject.inputs.push(spend);
    }
    subject.outputs.push(TransactionOutput::new(1_000, token));
    beef.merge_raw_tx(subject.to_binary(), None);
    beef.to_binary()
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
    LookupResolver::new(LookupResolverConfig {
        network_preset: preset,
        facilitator: Some(mock as Arc<dyn OverlayLookupFacilitator>),
        slap_trackers: Some(vec![]),
        host_overrides: Some(host_overrides),
        ..Default::default()
    })
}

fn output_list_of(beef: Vec<u8>) -> LookupAnswer {
    LookupAnswer::OutputList {
        outputs: vec![OutputListItem {
            beef,
            output_index: 0,
            context: None,
        }],
    }
}

// ============================================================================
// Door: the lookup resolver's SLAP parse (the re-read's explicit pin site)
// ============================================================================

#[tokio::test]
async fn the_resolver_slap_door_links_nothing_on_a_hostile_answer() {
    let root = PrivateKey::random();
    let service = "ls_749fold2";
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
    let resolver = LookupResolver::new(LookupResolverConfig {
        network_preset: NetworkPreset::Mainnet,
        facilitator: Some(mock as Arc<dyn OverlayLookupFacilitator>),
        slap_trackers: Some(vec!["http://slap-749-tracker:8080".to_string()]),
        ..Default::default()
    });

    let hosts = resolver.find_competent_hosts(service).await.unwrap();
    assert!(
        hosts.contains(&"https://host-749.example".to_string()),
        "the resolver surfaced the SLAP host from an answer a linking door would drop: {hosts:?}"
    );
}

// ============================================================================
// Door: kvstore query (reads only one output's locking script)
// ============================================================================

#[test]
fn the_kvstore_door_links_nothing_on_a_hostile_answer() {
    // The kvstore query door reads only `tx.outputs[i].locking_script` and now
    // parses via `from_beef_subject`. This pins the door at its parser boundary:
    // the token the door reads survives at the subject output of an answer the
    // linking door refuses. (On the standalone fix line a behavioural guard
    // drives the real door end to end, but this release's kvstore door validates
    // a full #544 signed envelope no hand-built token satisfies, so the carry
    // keeps the boundary pin here — fold3 ruling 1.)
    let controller = bsv_rs::wallet::ProtoWallet::new(None).identity_key();
    let token = kvstore_token("kvstore", "k", "v", &controller);
    let beef = hostile_answer_with_token(token);
    assert_fixture_discriminates(&beef);

    let subject = Transaction::from_beef_subject(&beef, None).unwrap();
    let script = &subject.outputs[0].locking_script;
    let entry = bsv_rs::kvstore::KVStoreInterpreter::extract_fields(script)
        .expect("the kvstore token survives at the subject output of the refused answer");
    assert_eq!(entry.key, b"k");
    assert_eq!(entry.value, b"v");
}

/// An unsigned kvstore PushDrop token (a signature placeholder) — enough for the
/// interpreter's field extraction, which is where the door reads.
fn kvstore_token(
    protocol_id: &str,
    key: &str,
    value: &str,
    controller: &bsv_rs::primitives::PublicKey,
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

// ============================================================================
// Door: the storage downloader (UHRP advertisement)
// ============================================================================

// CARRY RECONCILIATION (main-line stack): the release stack's commit f8493b29
// (#544's storage site) added `advertisement::authenticated` — the downloader
// names a host only from an advertisement its host SIGNED (BRC-42, the protocol
// "uhrp advertisement") and whose linked key LOCKS it, for the file asked. The
// original behavioural test's hand-built UNSIGNED token no longer passes that
// admission, so it is replaced by one of the same strength on the stack's shape:
// a properly signed advertisement (the stack's own
// `storage_advertisement_envelope_544` signing recipe) wrapped in the same
// hostile BEEF. The storage door itself is unchanged — it still reads the output
// via `from_beef_subject` — so this still turns RED if the door reverts to
// `from_beef`: the refused link drops the whole answer before the signed output
// is read.
#[tokio::test]
async fn the_storage_downloader_door_links_nothing_on_a_signed_hostile_answer() {
    let host = PrivateKey::random();
    let uhrp_url = bsv_rs::storage::get_url_for_file(b"the 749 signed fixture file").unwrap();
    let fields = uhrp_ad_data(&host.public_key(), &uhrp_url);
    let signature = uhrp_sign(&host, &fields);
    let token = uhrp_advertisement(&fields, signature, uhrp_linked(&host));
    let beef = hostile_answer_with_token(token);
    assert_fixture_discriminates(&beef);

    let mock = Arc::new(MockLookupFacilitator::new());
    mock.add_response("http://mock-749-host:8080", output_list_of(beef))
        .await;
    let resolver = Arc::new(mock_resolver(NetworkPreset::Local, "ls_uhrp", mock));
    let downloader =
        bsv_rs::storage::StorageDownloader::new(bsv_rs::storage::StorageDownloaderConfig {
            network_preset: NetworkPreset::Local,
            resolver: Some(resolver),
            timeout_ms: Some(5_000),
        });

    let hosts = downloader.resolve(&uhrp_url).await.unwrap();
    assert!(
        hosts.iter().any(|h| h == UHRP_LOCATION),
        "the downloader surfaced the signed UHRP host from an answer a linking door would drop: {hosts:?}"
    );
}

/// The host URL the signed advertisement names (one the resolver accepts).
const UHRP_LOCATION: &str = "https://host-749-signed.example";

/// The BRC-42 protocol the UHRP advertisement is signed and locked under.
fn uhrp_protocol() -> bsv_rs::wallet::Protocol {
    bsv_rs::wallet::Protocol::new(
        bsv_rs::wallet::SecurityLevel::Counterparty,
        "uhrp advertisement",
    )
}

/// The five data fields of `host`'s advertisement for the file of `url`.
fn uhrp_ad_data(host: &PublicKey, url: &str) -> Vec<Vec<u8>> {
    vec![
        host.to_compressed().to_vec(),
        bsv_rs::storage::get_hash_from_url(url).unwrap().to_vec(),
        UHRP_LOCATION.as_bytes().to_vec(),
        vec![0xfe, 0xff, 0xff, 0xff, 0x7f], // expiry, far ahead
        vec![0x10],                         // file size
    ]
}

/// The host's signature over the five data fields (BRC-42 for `anyone`).
fn uhrp_sign(signer: &PrivateKey, fields: &[Vec<u8>]) -> Vec<u8> {
    bsv_rs::wallet::ProtoWallet::new(Some(signer.clone()))
        .create_signature(bsv_rs::wallet::CreateSignatureArgs {
            data: Some(fields.concat()),
            hash_to_directly_sign: None,
            protocol_id: uhrp_protocol(),
            key_id: "1".to_string(),
            counterparty: Some(bsv_rs::wallet::Counterparty::Anyone),
        })
        .unwrap()
        .signature
}

/// The host's linked key for `anyone`: the key that locks its advertisement.
fn uhrp_linked(host: &PrivateKey) -> PublicKey {
    bsv_rs::wallet::KeyDeriver::new(Some(host.clone()))
        .derive_public_key(
            &uhrp_protocol(),
            "1",
            &bsv_rs::wallet::Counterparty::Anyone,
            true,
        )
        .unwrap()
}

/// The signed advertisement token (six fields; the signature last), locked.
fn uhrp_advertisement(fields: &[Vec<u8>], signature: Vec<u8>, lock: PublicKey) -> LockingScript {
    let mut fields = fields.to_vec();
    fields.push(signature);
    PushDrop::new(lock, fields).lock()
}

// ============================================================================
// Door: topic discovery (SHIP advertisement)
// ============================================================================

#[tokio::test]
async fn the_topic_discovery_door_links_nothing_on_a_hostile_answer() {
    let root = PrivateKey::random();
    let topic = "tm_749fold2";
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
        TopicBroadcasterConfig {
            network_preset: NetworkPreset::Mainnet,
            facilitator: None,
            resolver: Some(resolver),
            require_ack_from_all_hosts: RequireAck::None,
            require_ack_from_any_host: RequireAck::None,
            require_ack_from_specific_hosts: HashMap::new(),
        },
    )
    .unwrap();

    let hosts = broadcaster.find_interested_hosts().await.unwrap();
    assert!(
        hosts.contains_key("https://host-749.example"),
        "topic discovery surfaced the SHIP host from an answer a linking door would drop: {hosts:?}"
    );
}

// ============================================================================
// Door: registry basket definition
// ============================================================================

// CARRY RECONCILIATION (main-line stack): the release stack's commit f49ac4dc
// refactored the registry resolves into `authenticated<T>`, which on the 0.8
// line reads NO operator-signed definition and returns none WITHOUT parsing any
// overlay output — the `parse_*_from_output` doors #749 protected no longer
// exist here. The door that could re-materialize ancestry is gone entirely, a
// stronger outcome than linking nothing, so the original behavioural test (which
// surfaced a basket definition) cannot exist on this shape. It is replaced by a
// pin of the same strength on the stack's shape: given an answer whose output
// BEEF a LINKING door refuses, `resolve_basket` completes Ok and empty — it
// never materializes the untrusted ancestry and never surfaces the link bound
// error. RED if a linking parse of the untrusted output is ever restored: a
// propagated resource error fails the `expect`, a returned definition fails the
// `is_empty`. The parser-boundary assertion pins the subject-only door for any
// future restoration.
#[tokio::test]
async fn the_registry_resolve_links_nothing_on_the_stack_shape() {
    let controller = bsv_rs::wallet::ProtoWallet::new(None).identity_key();
    let basket = bsv_rs::registry::BasketDefinitionData::new("basket749", "Basket 749")
        .with_icon_url("https://icon-749.example")
        .with_description("the 749 fold2 basket")
        .with_documentation_url("https://docs-749.example");
    let operator = "02".to_string() + &"ab".repeat(32); // 33-byte hex operator id
    let fields = basket.to_pushdrop_fields(&operator);
    let token = PushDrop::new(controller, fields).lock();
    let beef = hostile_answer_with_token(token);
    assert_fixture_discriminates(&beef);

    // The subject-only door recovers the basket token at the subject output of
    // the answer the linking door refuses — the parser a restored registry door
    // must use (ruling 1), pinned for any future restoration on this line.
    let subject = Transaction::from_beef_subject(&beef, None).unwrap();
    PushDrop::decode(&subject.outputs[0].locking_script)
        .expect("the basket token survives at the subject output of the refused answer");

    let mock = Arc::new(MockLookupFacilitator::new());
    mock.add_response("http://mock-749-host:8080", output_list_of(beef))
        .await;
    let resolver = Arc::new(mock_resolver(NetworkPreset::Local, "ls_basketmap", mock));
    let client = bsv_rs::registry::RegistryClient::new(
        bsv_rs::wallet::ProtoWallet::new(None),
        bsv_rs::registry::RegistryClientConfig::new().with_resolver(resolver),
    );

    let found = client
        .resolve_basket(bsv_rs::registry::BasketQuery {
            basket_id: Some("basket749".to_string()),
            registry_operators: None,
            name: None,
        })
        .await
        .expect(
            "the registry resolve reads no untrusted overlay ancestry; \
             it must not surface the link bound error",
        );
    assert!(
        found.is_empty(),
        "the 0.8-line registry door reads no operator-signed definition and links nothing: {found:?}"
    );
}
