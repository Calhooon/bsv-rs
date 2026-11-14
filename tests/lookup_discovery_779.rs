//! #779: the SLAP discovery's four tests ask a scripted tracker and assert
//! exactly (`CLAUDE.md` rule 4). Until #779 they were unit tests in
//! `src/overlay/lookup_resolver.rs` that built `LookupResolver::default()`
//! (under `http`, the four Mainnet trackers of `NetworkPreset::slap_trackers`)
//! or the `Local` preset (`http://localhost:8080`) and accepted `Ok` or
//! `Err`, "depends on network availability". Here every tracker is an
//! `.invalid` name or a URL the scripted facilitator records and never dials,
//! so each test reads the same with and without `http`. Each test names its
//! own trackers and hosts, as the reputation tracker is one global keyed by
//! URL.
#![cfg(feature = "overlay")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/pushdrop_lock_position_537.rs"]
mod lock_position;

use bsv_rs::overlay::{
    create_signed_overlay_admin_token, LookupAnswer, LookupQuestion, LookupResolver,
    LookupResolverConfig, NetworkPreset, OverlayLookupFacilitator, Protocol,
    MAX_TRACKER_WAIT_TIME_MS,
};
use bsv_rs::primitives::PrivateKey;
use bsv_rs::Error;
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// The URL, the question's service and its query of each question asked.
type Asked = Arc<Mutex<Vec<(String, String, serde_json::Value)>>>;

/// The wait each question was asked with, in the order asked (#787).
type Waits = Arc<Mutex<Vec<Option<u64>>>>;

/// A facilitator answering by URL from its script, recording each question
/// and its wait; a URL outside the script is refused in words of its own.
struct Scripted {
    asked: Asked,
    waits: Waits,
    script: HashMap<String, bsv_rs::Result<LookupAnswer>>,
}

#[async_trait::async_trait(?Send)]
impl OverlayLookupFacilitator for Scripted {
    async fn lookup(
        &self,
        url: &str,
        question: &LookupQuestion,
        timeout_ms: Option<u64>,
    ) -> bsv_rs::Result<LookupAnswer> {
        self.waits.lock().unwrap().push(timeout_ms);
        self.asked.lock().unwrap().push((
            url.to_string(),
            question.service.clone(),
            question.query.clone(),
        ));
        self.script
            .get(url)
            .cloned()
            .unwrap_or_else(|| Err(Error::OverlayError(format!("unscripted: {url}"))))
    }
}

fn resolver(
    config: LookupResolverConfig,
    script: Vec<(&str, bsv_rs::Result<LookupAnswer>)>,
) -> (LookupResolver, Asked) {
    let (resolver, asked, _waits) = resolver_with_waits(config, script);
    (resolver, asked)
}

/// `resolver`, handing the test the record of the waits too (#787).
fn resolver_with_waits(
    config: LookupResolverConfig,
    script: Vec<(&str, bsv_rs::Result<LookupAnswer>)>,
) -> (LookupResolver, Asked, Waits) {
    let asked = Asked::default();
    let waits = Waits::default();
    let resolver = LookupResolver::new(LookupResolverConfig {
        facilitator: Some(Arc::new(Scripted {
            asked: asked.clone(),
            waits: waits.clone(),
            script: script
                .into_iter()
                .map(|(url, answer)| (url.to_string(), answer))
                .collect(),
        })),
        ..config
    });
    (resolver, asked, waits)
}

fn trackers(urls: &[&str]) -> LookupResolverConfig {
    LookupResolverConfig {
        slap_trackers: Some(urls.iter().map(|url| url.to_string()).collect()),
        ..Default::default()
    }
}

/// A tracker's answer naming each host for `service`, SLAP advertisements
/// signed by this crate's writer.
fn advertising(service: &str, hosts: &[&str]) -> bsv_rs::Result<LookupAnswer> {
    let outputs = hosts
        .iter()
        .map(|host| {
            lock_position::output_of(create_signed_overlay_admin_token(
                &PrivateKey::random(),
                Protocol::Slap,
                host,
                service,
            ))
        })
        .collect();
    Ok(LookupAnswer::OutputList { outputs })
}

fn slap(url: &str, service: &str) -> (String, String, serde_json::Value) {
    (
        url.to_string(),
        "ls_slap".to_string(),
        json!({ "service": service }),
    )
}

#[tokio::test]
async fn find_competent_hosts_answers_the_hosts_a_scripted_tracker_names() {
    const NAMING: &str = "https://naming.discovery-779.invalid";
    const REFUSING: &str = "https://refusing.discovery-779.invalid";
    let (resolver, asked) = resolver(
        trackers(&[NAMING, REFUSING]),
        vec![
            (
                NAMING,
                advertising(
                    "ls_test_service",
                    &[
                        "https://one.discovery-779.invalid",
                        "https://two.discovery-779.invalid",
                    ],
                ),
            ),
            (
                REFUSING,
                Err(Error::OverlayError("scripted refusal".into())),
            ),
        ],
    );

    // The tracker's answer order (#785; a `HashSet`'s until then, sorted here).
    let hosts = resolver
        .find_competent_hosts("ls_test_service")
        .await
        .unwrap();
    assert_eq!(
        hosts,
        [
            "https://one.discovery-779.invalid",
            "https://two.discovery-779.invalid"
        ]
    );
    // Each tracker asked once with the service; a refusing tracker is
    // accounted, not the discovery's refusal.
    assert_eq!(
        *asked.lock().unwrap(),
        [
            slap(NAMING, "ls_test_service"),
            slap(REFUSING, "ls_test_service")
        ]
    );
}

#[tokio::test]
async fn find_competent_hosts_sends_an_empty_service_as_given() {
    const TRACKER: &str = "https://empty.discovery-779.invalid";
    let (resolver, asked) = resolver(
        trackers(&[TRACKER]),
        vec![(
            TRACKER,
            advertising("ls_test_service", &["https://other.discovery-779.invalid"]),
        )],
    );

    // An advertisement for another service is not an answer for "".
    let hosts = resolver.find_competent_hosts("").await.unwrap();
    assert_eq!(hosts, Vec::<String>::new());
    assert_eq!(*asked.lock().unwrap(), [slap(TRACKER, "")]);
}

#[tokio::test]
async fn find_competent_hosts_on_the_local_preset_asks_its_tracker() {
    // The preset's tracker, recorded by the scripted facilitator and never
    // dialled: nothing listens, nothing connects.
    const LOCAL: &str = "http://localhost:8080";
    assert_eq!(NetworkPreset::Local.slap_trackers(), [LOCAL]);
    let (resolver, asked) = resolver(
        LookupResolverConfig {
            network_preset: NetworkPreset::Local,
            ..Default::default()
        },
        vec![(
            LOCAL,
            advertising("ls_test", &["https://found.discovery-779.invalid"]),
        )],
    );

    let hosts = resolver.find_competent_hosts("ls_test").await.unwrap();
    // The Local shortcut is `query`'s, not the discovery's. The advertised
    // host is `https://`: the admin token's URI check refuses `http://`.
    assert_eq!(hosts, ["https://found.discovery-779.invalid"]);
    assert_eq!(*asked.lock().unwrap(), [slap(LOCAL, "ls_test")]);
}

#[tokio::test]
async fn find_competent_hosts_does_not_apply_a_host_override() {
    const TRACKER: &str = "https://override.discovery-779.invalid";
    const SERVICE: &str = "ls_override_test";
    let (resolver, asked) = resolver(
        LookupResolverConfig {
            host_overrides: Some(HashMap::from([(
                SERVICE.to_string(),
                vec!["https://override.host".to_string()],
            )])),
            ..trackers(&[TRACKER])
        },
        vec![
            (TRACKER, advertising(SERVICE, &["https://discovered.host"])),
            (
                "https://override.host",
                Ok(LookupAnswer::OutputList { outputs: vec![] }),
            ),
        ],
    );

    let hosts = resolver.find_competent_hosts(SERVICE).await.unwrap();
    assert_eq!(hosts, ["https://discovered.host"]);
    assert_eq!(*asked.lock().unwrap(), [slap(TRACKER, SERVICE)]);

    // The contrast: `query` (through the internal `get_competent_hosts`)
    // asks the override and no tracker.
    asked.lock().unwrap().clear();
    let answer = resolver
        .query(&LookupQuestion::new(SERVICE, json!({})), None)
        .await
        .unwrap();
    assert!(
        matches!(&answer, LookupAnswer::OutputList { outputs } if outputs.is_empty()),
        "{answer:?}"
    );
    assert_eq!(
        *asked.lock().unwrap(),
        [(
            "https://override.host".to_string(),
            SERVICE.to_string(),
            json!({})
        )]
    );
}

/// #787: discovery on the default config asks the four Mainnet trackers of
/// the reference (`ts-stack@edf6e03` `LookupResolver.ts:216-223`, the
/// `mainnet` preset at `:1333-1335`), each once with `ls_slap` and the
/// reference's tracker wait, `MAX_TRACKER_WAIT_TIME = 5000` (`:248`, passed at
/// `:1975-1977`; go-sdk@2ca481c waits 30 s, `resolver.go:18`, not followed).
/// The URLs and the wait are literals, not `NetworkPreset::slap_trackers()`,
/// so a change to the default list or the wait is seen. The four URLs are
/// strings in the script: recorded, never dialled.
#[tokio::test]
async fn discovery_on_the_default_config_asks_the_four_mainnet_trackers_with_the_reference_wait_787(
) {
    const US: &str = "https://overlay-us-1.bsvb.tech";
    const EU: &str = "https://overlay-eu-1.bsvb.tech";
    const AP: &str = "https://overlay-ap-1.bsvb.tech";
    const BAPP: &str = "https://users.bapp.dev";
    // A name of its own; letters and underscores only, as the admin token's
    // canonical name pattern asks (`OverlayAdminTokenTemplate.ts:31-34`).
    const SERVICE: &str = "ls_default_config_discovery";
    const FOUND: &str = "https://found.discovery-787.invalid";

    // The default config, not a hand-built list.
    let config = LookupResolverConfig::default();
    assert_eq!(config.network_preset, NetworkPreset::Mainnet);
    assert!(config.slap_trackers.is_none());

    let empty = || Ok(LookupAnswer::OutputList { outputs: vec![] });
    let (resolver, asked, waits) = resolver_with_waits(
        config,
        vec![
            (US, advertising(SERVICE, &[FOUND])),
            (EU, empty()),
            (AP, empty()),
            (BAPP, empty()),
        ],
    );

    let hosts = resolver.find_competent_hosts(SERVICE).await.unwrap();
    assert_eq!(hosts, [FOUND]);
    // The order is the list's: the global reputation tracker is keyed by URL
    // and no other test in this binary names a Mainnet URL, so the four have
    // no history and rank tied, the tie broken by their original order
    // (`src/overlay/host_reputation_tracker.rs`, `rank_hosts_at`), and the
    // questions are polled in rank order.
    assert_eq!(
        *asked.lock().unwrap(),
        [
            slap(US, SERVICE),
            slap(EU, SERVICE),
            slap(AP, SERVICE),
            slap(BAPP, SERVICE)
        ]
    );
    assert_eq!(*waits.lock().unwrap(), [Some(5000); 4]);
    assert_eq!(MAX_TRACKER_WAIT_TIME_MS, 5000);
}

/// A SLAP advertisement of `host` for `service` carrying `satoshis`, its
/// own transaction (`seed` its source index) proven by a block of its own.
fn advertisement_at(
    host: &str,
    service: &str,
    satoshis: u64,
    seed: u32,
) -> bsv_rs::overlay::OutputListItem {
    use bsv_rs::transaction::{
        Beef, MerklePath, MerklePathLeaf, Transaction, TransactionInput, TransactionOutput,
    };
    let script =
        create_signed_overlay_admin_token(&PrivateKey::random(), Protocol::Slap, host, service);
    let mut tx = Transaction::new();
    tx.add_input(TransactionInput::new(
        "22".repeat(32).parse().unwrap(),
        seed,
    ))
    .unwrap();
    tx.add_output(TransactionOutput::new(satoshis, script))
        .unwrap();
    let mut beef = Beef::new();
    let index = beef.merge_bump(
        MerklePath::new(900, vec![vec![MerklePathLeaf::new_txid(0, tx.id())]]).unwrap(),
    );
    beef.merge_raw_tx(tx.to_binary(), Some(index)).unwrap();
    bsv_rs::overlay::OutputListItem {
        beef: beef.to_binary().unwrap(),
        output_index: 0,
        context: None,
        txid: None,
    }
}

/// #815, the pin the cold re-read of PR #801 asked for: a tracker's share
/// is counted over the hosts it admitted, as the reference's candidates
/// are admitted before `LookupDiscovery` counts them (`ts-stack@edf6e03`
/// `LookupDiscovery.ts:62-78`, the admission at `LookupResolver.ts:2194-2216`;
/// here `src/overlay/lookup_resolver/discovery.rs`, the `filter_map` before
/// `earliest_distinct`'s cut). A tracker whose share is 2 answers three
/// advertisements of 2 satoshis (each refused, #786) and then one of 1:
/// the admitted host is discovered. With the share taken ahead of the
/// admission (the mutant `.take(share)` before the `filter_map`) the two
/// refused outputs fill it and nothing is discovered.
#[tokio::test]
async fn a_trackers_share_is_counted_after_admission_815() {
    const TRACKER: &str = "https://share.discovery-815.invalid";
    const SERVICE: &str = "ls_share_admission";
    let mut outputs: Vec<_> = (0..3)
        .map(|seed| {
            advertisement_at(
                &format!("https://refused-{seed}.discovery-815.invalid"),
                SERVICE,
                2,
                seed,
            )
        })
        .collect();
    outputs.push(advertisement_at(
        "https://admitted.discovery-815.invalid",
        SERVICE,
        1,
        9,
    ));
    let mut limits = bsv_rs::overlay::LookupLimits::default();
    limits.max_hosts_per_tracker = 2;
    let (resolver, asked) = resolver(
        LookupResolverConfig {
            limits,
            ..trackers(&[TRACKER])
        },
        vec![(TRACKER, Ok(LookupAnswer::OutputList { outputs }))],
    );
    let hosts = resolver.find_competent_hosts(SERVICE).await.unwrap();
    assert_eq!(hosts, ["https://admitted.discovery-815.invalid"]);
    assert_eq!(*asked.lock().unwrap(), [slap(TRACKER, SERVICE)]);
}
