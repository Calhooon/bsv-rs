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
};
use bsv_rs::primitives::PrivateKey;
use bsv_rs::Error;
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// The URL, the question's service and its query of each question asked.
type Asked = Arc<Mutex<Vec<(String, String, serde_json::Value)>>>;

/// A facilitator answering by URL from its script, recording each question;
/// a URL outside the script is refused in words of its own.
struct Scripted {
    asked: Asked,
    script: HashMap<String, bsv_rs::Result<LookupAnswer>>,
}

#[async_trait::async_trait(?Send)]
impl OverlayLookupFacilitator for Scripted {
    async fn lookup(
        &self,
        url: &str,
        question: &LookupQuestion,
        _timeout_ms: Option<u64>,
    ) -> bsv_rs::Result<LookupAnswer> {
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
    let asked = Asked::default();
    let resolver = LookupResolver::new(LookupResolverConfig {
        facilitator: Some(Arc::new(Scripted {
            asked: asked.clone(),
            script: script
                .into_iter()
                .map(|(url, answer)| (url.to_string(), answer))
                .collect(),
        })),
        ..config
    });
    (resolver, asked)
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

    let mut hosts = resolver
        .find_competent_hosts("ls_test_service")
        .await
        .unwrap();
    // The discovery gathers into a set: the hosts are pinned, not their order.
    hosts.sort();
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
