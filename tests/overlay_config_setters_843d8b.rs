//! The two overlay configs are built from `default()` and a `with_<field>`
//! setter per field (#843d8b): each setter takes its field's own type and
//! sets that field alone, the three migration lines of the CHANGELOG build
//! what assignment on a `default()` builds, and the sixteen defaults are
//! the values they were. No network: nothing here asks a host.
//! Compile-RED on the base, where no setter exists (E0599 alone).
#![cfg(feature = "overlay")]
#![allow(clippy::unwrap_used)] // Test assertions.

use bsv_rs::overlay::{
    HttpsOverlayBroadcastFacilitator, HttpsOverlayLookupFacilitator, LookupLimits, LookupResolver,
    LookupResolverConfig, NetworkPreset, OverlayBroadcastFacilitator, OverlayLookupFacilitator,
    RequireAck, TopicBroadcasterConfig,
};
use std::collections::HashMap;
use std::sync::Arc;

/// The address an `Arc` holds, whatever it points at.
fn address<T: ?Sized>(held: &Option<Arc<T>>) -> Option<*const ()> {
    held.as_ref().map(|arc| Arc::as_ptr(arc).cast::<()>())
}

/// The ten fields of a lookup config, each as a text that tells two values
/// apart, in the struct's order.
fn lookup_fields(config: &LookupResolverConfig) -> [String; 10] {
    [
        format!("{:?}", config.network_preset),
        format!("{:?}", address(&config.facilitator)),
        format!("{:?}", config.slap_trackers),
        format!("{:?}", config.host_overrides),
        format!("{:?}", config.additional_hosts),
        format!("{:?}", config.hosts_cache_ttl_ms),
        format!("{:?}", config.hosts_cache_max_entries),
        format!("{:?}", config.tx_memo_ttl_ms),
        format!("{:?}", config.tx_memo_max_entries),
        format!("{:?}", config.limits),
    ]
}

/// The six fields of a broadcaster config, the same way.
fn broadcaster_fields(config: &TopicBroadcasterConfig) -> [String; 6] {
    [
        format!("{:?}", config.network_preset),
        format!("{:?}", address(&config.facilitator)),
        format!("{:?}", address(&config.resolver)),
        format!("{:?}", config.require_ack_from_all_hosts),
        format!("{:?}", config.require_ack_from_any_host),
        format!("{:?}", config.require_ack_from_specific_hosts),
    ]
}

/// `set` differs from `base` at `index` alone, where it reads `expected`.
fn sets_alone<const N: usize>(base: &[String; N], set: &[String; N], index: usize, expected: &str) {
    for (at, (was, is)) in base.iter().zip(set).enumerate() {
        if at == index {
            assert_eq!(is, expected, "field {index} was not set");
            assert_ne!(is, was, "field {index}: the value set is the default's");
        } else {
            assert_eq!(is, was, "the setter of field {index} moved field {at}");
        }
    }
}

fn hosts(service: &str, host: &str) -> HashMap<String, Vec<String>> {
    HashMap::from([(service.to_string(), vec![host.to_string()])])
}

fn limits() -> LookupLimits {
    let mut limits = LookupLimits::default();
    limits.max_hosts = 3;
    limits
}

#[test]
fn each_setter_of_the_two_overlay_configs_sets_its_field_alone_843d8b() {
    let base = lookup_fields(&LookupResolverConfig::default());
    let facilitator: Arc<dyn OverlayLookupFacilitator> =
        Arc::new(HttpsOverlayLookupFacilitator::new(false));
    let default = LookupResolverConfig::default;
    let cases: [(LookupResolverConfig, String); 10] = [
        (
            default().with_network_preset(NetworkPreset::Testnet),
            "Testnet".to_string(),
        ),
        (
            default().with_facilitator(Some(facilitator.clone())),
            format!("{:?}", address(&Some(facilitator.clone()))),
        ),
        (
            default().with_slap_trackers(Some(vec!["https://tracker.example".to_string()])),
            r#"Some(["https://tracker.example"])"#.to_string(),
        ),
        (
            default().with_host_overrides(Some(hosts("ls_a", "https://a.example"))),
            r#"Some({"ls_a": ["https://a.example"]})"#.to_string(),
        ),
        (
            default().with_additional_hosts(Some(hosts("ls_b", "https://b.example"))),
            r#"Some({"ls_b": ["https://b.example"]})"#.to_string(),
        ),
        (default().with_hosts_cache_ttl_ms(7), "7".to_string()),
        (default().with_hosts_cache_max_entries(8), "8".to_string()),
        (default().with_tx_memo_ttl_ms(9), "9".to_string()),
        (default().with_tx_memo_max_entries(10), "10".to_string()),
        (default().with_limits(limits()), format!("{:?}", limits())),
    ];
    for (index, (config, expected)) in cases.iter().enumerate() {
        sets_alone(&base, &lookup_fields(config), index, expected);
    }

    let base = broadcaster_fields(&TopicBroadcasterConfig::default());
    let facilitator: Arc<dyn OverlayBroadcastFacilitator> =
        Arc::new(HttpsOverlayBroadcastFacilitator::new(false));
    let resolver = Arc::new(LookupResolver::new(
        LookupResolverConfig::default().with_network_preset(NetworkPreset::Local),
    ));
    let default = TopicBroadcasterConfig::default;
    let cases: [(TopicBroadcasterConfig, String); 6] = [
        (
            default().with_network_preset(NetworkPreset::Local),
            "Local".to_string(),
        ),
        (
            default().with_facilitator(Some(facilitator.clone())),
            format!("{:?}", address(&Some(facilitator.clone()))),
        ),
        (
            default().with_resolver(Some(resolver.clone())),
            format!("{:?}", address(&Some(resolver.clone()))),
        ),
        (
            default().with_require_ack_from_all_hosts(RequireAck::Any),
            "Any".to_string(),
        ),
        (
            default().with_require_ack_from_any_host(RequireAck::Some(vec!["tm_a".to_string()])),
            r#"Some(["tm_a"])"#.to_string(),
        ),
        (
            default().with_require_ack_from_specific_hosts(HashMap::from([(
                "https://h.example".to_string(),
                RequireAck::All,
            )])),
            r#"{"https://h.example": All}"#.to_string(),
        ),
    ];
    for (index, (config, expected)) in cases.iter().enumerate() {
        sets_alone(&base, &broadcaster_fields(config), index, expected);
    }
}

/// The CHANGELOG's three migration lines, their "after" forms, against the
/// same values assigned to the public fields of a `default()`.
#[test]
fn the_migration_lines_build_what_assignment_builds_843d8b() {
    let facilitator: Arc<dyn OverlayLookupFacilitator> =
        Arc::new(HttpsOverlayLookupFacilitator::new(false));
    let overrides = hosts("ls_example", "https://overlay.example");

    // (a) `LookupResolverConfig { facilitator: Some(facilitator),
    //      host_overrides: Some(overrides), ..Default::default() }`
    let built = LookupResolverConfig::default()
        .with_facilitator(Some(facilitator.clone()))
        .with_host_overrides(Some(overrides.clone()));
    let mut assigned = LookupResolverConfig::default();
    assigned.facilitator = Some(facilitator.clone());
    assigned.host_overrides = Some(overrides.clone());
    assert_eq!(lookup_fields(&built), lookup_fields(&assigned));

    // (b) `LookupResolverConfig { limits, ..base }`
    let base = built.clone();
    let built = base.clone().with_limits(limits());
    let mut assigned = base;
    assigned.limits = limits();
    assert_eq!(lookup_fields(&built), lookup_fields(&assigned));
    assert_eq!(built.limits.max_hosts, 3);
    assert!(built.facilitator.is_some() && built.host_overrides.is_some());

    // (c) a full literal: `TopicBroadcasterConfig { network_preset, facilitator,
    //      resolver, require_ack_from_all_hosts, require_ack_from_any_host,
    //      require_ack_from_specific_hosts }`, every field named.
    let network_preset = NetworkPreset::Local;
    let facilitator: Option<Arc<dyn OverlayBroadcastFacilitator>> =
        Some(Arc::new(HttpsOverlayBroadcastFacilitator::new(true)));
    let resolver = Some(Arc::new(LookupResolver::new(built)));
    let specific = HashMap::from([("http://localhost:8080".to_string(), RequireAck::Any)]);
    let built = TopicBroadcasterConfig::default()
        .with_network_preset(network_preset)
        .with_facilitator(facilitator.clone())
        .with_resolver(resolver.clone())
        .with_require_ack_from_all_hosts(RequireAck::None)
        .with_require_ack_from_any_host(RequireAck::Any)
        .with_require_ack_from_specific_hosts(specific.clone());
    let mut assigned = TopicBroadcasterConfig::default();
    assigned.network_preset = network_preset;
    assigned.facilitator = facilitator;
    assigned.resolver = resolver;
    assigned.require_ack_from_all_hosts = RequireAck::None;
    assigned.require_ack_from_any_host = RequireAck::Any;
    assigned.require_ack_from_specific_hosts = specific;
    assert_eq!(broadcaster_fields(&built), broadcaster_fields(&assigned));
}

/// The sixteen defaults, as literals: no setter and no attribute moved one.
#[test]
fn the_two_defaults_are_unchanged_by_value_843d8b() {
    let lookup = LookupResolverConfig::default();
    assert_eq!(lookup.network_preset, NetworkPreset::Mainnet);
    assert!(lookup.facilitator.is_none());
    assert!(lookup.slap_trackers.is_none());
    assert!(lookup.host_overrides.is_none());
    assert!(lookup.additional_hosts.is_none());
    assert_eq!(lookup.hosts_cache_ttl_ms, 300_000);
    assert_eq!(lookup.hosts_cache_max_entries, 128);
    assert_eq!(lookup.tx_memo_ttl_ms, 600_000);
    assert_eq!(lookup.tx_memo_max_entries, 4096);
    assert_eq!(lookup.limits.max_hosts, 256);
    assert_eq!(lookup.limits.max_hosts_per_tracker, 64);
    assert_eq!(lookup.limits.max_response_bytes, 33_554_432);
    assert_eq!(lookup.limits.max_total_bytes, 67_108_864);
    assert_eq!(lookup.limits.max_outputs, 4096);

    let broadcaster = TopicBroadcasterConfig::default();
    assert_eq!(broadcaster.network_preset, NetworkPreset::Mainnet);
    assert!(broadcaster.facilitator.is_none());
    assert!(broadcaster.resolver.is_none());
    assert!(matches!(
        broadcaster.require_ack_from_all_hosts,
        RequireAck::None
    ));
    assert!(matches!(
        broadcaster.require_ack_from_any_host,
        RequireAck::All
    ));
    assert!(broadcaster.require_ack_from_specific_hosts.is_empty());
}
