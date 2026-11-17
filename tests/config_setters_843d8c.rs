//! Twelve of the eighteen configuration structs #843d8c attributes gained
//! setters there (forty, and `TeranodeConfig::new`): each setter takes its
//! field's own type and sets that field alone, `TeranodeConfig::new` carries
//! no key and 30,000 ms, `HistorianConfig<T, C>: Default` asks nothing of `T`
//! or `C`, and every `Default` of the eighteen holds the values it held
//! before the attribute. No network: nothing here asks a host.
//! Compile-RED on the base, where no new setter exists.
#![cfg(feature = "full")]
#![allow(clippy::unwrap_used)] // Test assertions.

use bsv_rs::identity::{ContactsManagerConfig, IdentityClientConfig};
use bsv_rs::kvstore::{KVStoreConfig, KVStoreGetOptions, KVStoreRemoveOptions, KVStoreSetOptions};
use bsv_rs::overlay::{HistorianConfig, LookupResolver, NetworkPreset, ReputationConfig};
use bsv_rs::registry::RegistryClientConfig;
use bsv_rs::storage::{StorageDownloaderConfig, StorageUploaderConfig};
use bsv_rs::totp::{Algorithm, TotpOptions, TotpValidateOptions};
use bsv_rs::transaction::{
    BlockHeadersServiceConfig, LivePolicyConfig, TeranodeConfig, WocBroadcastConfig,
    WocBroadcastNetwork,
};
use bsv_rs::wallet::CacheConfig;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// The address an `Arc` holds.
fn address<T>(held: &Option<Arc<T>>) -> Option<*const T> {
    held.as_ref().map(Arc::as_ptr)
}

/// One setter of `C` and the text its field reads after it.
type Setter<'a, C> = (Box<dyn Fn(C) -> C>, &'a str);

/// Each setter of one struct against its base: after `set`, exactly the
/// field at the setter's position reads otherwise, and reads `want`.
fn each_sets_its_field_alone<C>(
    name: &str,
    base: &dyn Fn() -> C,
    fields: &dyn Fn(&C) -> Vec<String>,
    setters: Vec<Setter<'_, C>>,
) -> usize {
    let before = fields(&base());
    assert_eq!(
        before.len(),
        setters.len(),
        "{name}: a setter for each field read"
    );
    for (at, (set, want)) in setters.iter().enumerate() {
        let after = fields(&set(base()));
        for (field, (old, new)) in before.iter().zip(&after).enumerate() {
            if field == at {
                assert_ne!(old, new, "{name}: setter {at} moved nothing");
                assert_eq!(new, want, "{name}: setter {at}");
            } else {
                assert_eq!(old, new, "{name}: setter {at} moved field {field}");
            }
        }
    }
    setters.len()
}

/// The fields of a Teranode config after its URL (the URL is `new`'s).
fn teranode(config: &TeranodeConfig) -> Vec<String> {
    vec![
        format!("{:?}", config.api_key),
        format!("{:?}", config.timeout_ms),
    ]
}

#[test]
fn every_new_setter_sets_its_field_and_no_other_843d8c() {
    let mut setters = 0;
    setters += each_sets_its_field_alone::<ReputationConfig>(
        "ReputationConfig",
        &ReputationConfig::default,
        &|c| {
            vec![
                format!("{:?}", c.latency_smoothing),
                format!("{:?}", c.grace_failures),
                format!("{:?}", c.backoff_base_ms),
                format!("{:?}", c.backoff_max_ms),
                format!("{:?}", c.default_latency_ms),
                format!("{:?}", c.failure_penalty_ms),
                format!("{:?}", c.success_bonus_ms),
            ]
        },
        vec![
            (Box::new(|c| c.with_latency_smoothing(0.5)), "0.5"),
            (Box::new(|c| c.with_grace_failures(7)), "7"),
            (Box::new(|c| c.with_backoff_base_ms(11)), "11"),
            (Box::new(|c| c.with_backoff_max_ms(13)), "13"),
            (Box::new(|c| c.with_default_latency_ms(17.5)), "17.5"),
            (Box::new(|c| c.with_failure_penalty_ms(19.5)), "19.5"),
            (Box::new(|c| c.with_success_bonus_ms(23.5)), "23.5"),
        ],
    );
    let resolver = Arc::new(LookupResolver::default());
    let held = format!("{:?}", Some(Arc::as_ptr(&resolver)));
    setters += each_sets_its_field_alone::<StorageDownloaderConfig>(
        "StorageDownloaderConfig",
        &StorageDownloaderConfig::default,
        &|c| {
            vec![
                format!("{:?}", c.network_preset),
                format!("{:?}", address(&c.resolver)),
                format!("{:?}", c.timeout_ms),
            ]
        },
        vec![
            (
                Box::new(|c| c.with_network_preset(NetworkPreset::Local)),
                "Local",
            ),
            (
                Box::new(move |c| c.with_resolver(Some(resolver.clone()))),
                &held,
            ),
            (Box::new(|c| c.with_timeout_ms(None)), "None"),
        ],
    );
    setters += each_sets_its_field_alone::<CacheConfig>(
        "CacheConfig",
        &CacheConfig::default,
        &|c| vec![format!("{:?}", c.max_size)],
        vec![(Box::new(|c| c.with_max_size(3)), "3")],
    );
    setters += each_sets_its_field_alone::<TotpOptions>(
        "TotpOptions",
        &TotpOptions::default,
        &|c| {
            vec![
                format!("{:?}", c.digits),
                format!("{:?}", c.algorithm),
                format!("{:?}", c.period),
                format!("{:?}", c.timestamp),
            ]
        },
        vec![
            (Box::new(|c| c.with_digits(8)), "8"),
            (Box::new(|c| c.with_algorithm(Algorithm::Sha512)), "Sha512"),
            (Box::new(|c| c.with_period(60)), "60"),
            (Box::new(|c| c.with_timestamp(Some(59))), "Some(59)"),
        ],
    );
    let eight = format!("{:?}", TotpOptions::default().with_digits(8));
    setters += each_sets_its_field_alone::<TotpValidateOptions>(
        "TotpValidateOptions",
        &TotpValidateOptions::default,
        &|c| vec![format!("{:?}", c.options), format!("{:?}", c.skew)],
        vec![
            (
                Box::new(|c| c.with_options(TotpOptions::default().with_digits(8))),
                &eight,
            ),
            (Box::new(|c| c.with_skew(2)), "2"),
        ],
    );
    let cache = HashMap::from([("k".to_string(), vec![5u8])]);
    let cached = format!("{:?}", Some(&cache));
    setters += each_sets_its_field_alone::<HistorianConfig<u8, u8>>(
        "HistorianConfig",
        &HistorianConfig::default,
        &|c| {
            vec![
                format!("{:?}", c.debug),
                format!("{:?}", c.history_cache),
                format!("{:?}", c.interpreter_version),
                format!("{:?}", c.ctx_key_fn.as_ref().map(|key| key(Some(&9)))),
            ]
        },
        vec![
            (Box::new(|c| c.with_debug(true)), "true"),
            (
                Box::new(move |c| c.with_history_cache(Some(cache.clone()))),
                &cached,
            ),
            (
                Box::new(|c| c.with_interpreter_version(Some("v2".into()))),
                "Some(\"v2\")",
            ),
            (
                Box::new(|c| {
                    c.with_ctx_key_fn(Some(Box::new(|ctx: Option<&u8>| format!("ctx {ctx:?}"))))
                }),
                "Some(\"ctx Some(9)\")",
            ),
        ],
    );
    setters += each_sets_its_field_alone::<TeranodeConfig>(
        "TeranodeConfig",
        &|| TeranodeConfig::new("https://teranode.invalid"),
        &teranode,
        vec![
            (
                Box::new(|c| c.with_api_key(Some("k".into()))),
                "Some(\"k\")",
            ),
            (Box::new(|c| c.with_timeout_ms(7)), "7"),
        ],
    );
    setters += each_sets_its_field_alone::<WocBroadcastConfig>(
        "WocBroadcastConfig",
        &WocBroadcastConfig::default,
        &|c| {
            vec![
                format!("{:?}", c.network),
                format!("{:?}", c.api_key),
                format!("{:?}", c.timeout_ms),
                format!("{:?}", c.base_url),
            ]
        },
        vec![
            (
                Box::new(|c| c.with_network(WocBroadcastNetwork::Testnet)),
                "Testnet",
            ),
            (
                Box::new(|c| c.with_api_key(Some("k".into()))),
                "Some(\"k\")",
            ),
            (Box::new(|c| c.with_timeout_ms(7)), "7"),
            (
                Box::new(|c| c.with_base_url(Some("https://woc.invalid".into()))),
                "Some(\"https://woc.invalid\")",
            ),
        ],
    );
    setters += each_sets_its_field_alone::<BlockHeadersServiceConfig>(
        "BlockHeadersServiceConfig",
        &BlockHeadersServiceConfig::default,
        &|c| {
            vec![
                format!("{:?}", c.base_url),
                format!("{:?}", c.auth_token),
                format!("{:?}", c.timeout_ms),
            ]
        },
        vec![
            (
                Box::new(|c| c.with_base_url("https://headers.invalid".into())),
                "\"https://headers.invalid\"",
            ),
            (
                Box::new(|c| c.with_auth_token(Some("t".into()))),
                "Some(\"t\")",
            ),
            (Box::new(|c| c.with_timeout_ms(7)), "7"),
        ],
    );
    setters += each_sets_its_field_alone::<LivePolicyConfig>(
        "LivePolicyConfig",
        &LivePolicyConfig::default,
        &|c| {
            vec![
                format!("{:?}", c.policy_url),
                format!("{:?}", c.api_key),
                format!("{:?}", c.cache_ttl),
                format!("{:?}", c.fallback_rate),
                format!("{:?}", c.timeout_ms),
            ]
        },
        vec![
            (
                Box::new(|c| c.with_policy_url("https://policy.invalid".into())),
                "\"https://policy.invalid\"",
            ),
            (
                Box::new(|c| c.with_api_key(Some("k".into()))),
                "Some(\"k\")",
            ),
            (Box::new(|c| c.with_cache_ttl(Duration::from_secs(9))), "9s"),
            (Box::new(|c| c.with_fallback_rate(250)), "250"),
            (Box::new(|c| c.with_timeout_ms(7)), "7"),
        ],
    );
    // The three new setters of the identity config, beside the fields its
    // older doors set (`with_network`, `with_token_amount`, `with_originator`),
    // which the last three positions hold still.
    setters += each_sets_its_field_alone::<IdentityClientConfig>(
        "IdentityClientConfig",
        &IdentityClientConfig::default,
        &|c| {
            vec![
                format!("{:?}", c.protocol_id),
                format!("{:?}", c.key_id),
                format!("{:?}", c.output_index),
                format!("{:?}", c.network_preset),
                format!("{:?}", c.token_amount),
                format!("{:?}", c.originator),
            ]
        },
        vec![
            (
                Box::new(|c| c.with_protocol_id((2, "other".into()))),
                "(2, \"other\")",
            ),
            (Box::new(|c| c.with_key_id("7".into())), "\"7\""),
            (Box::new(|c| c.with_output_index(3)), "3"),
            (Box::new(|c| c.with_network(NetworkPreset::Local)), "Local"),
            (Box::new(|c| c.with_token_amount(5)), "5"),
            (
                Box::new(|mut c| {
                    c.originator = Some("o".into());
                    c
                }),
                "Some(\"o\")",
            ),
        ],
    ) - 3;
    setters += each_sets_its_field_alone::<ContactsManagerConfig>(
        "ContactsManagerConfig",
        &ContactsManagerConfig::default,
        &|c| {
            vec![
                format!("{:?}", c.protocol_id),
                format!("{:?}", c.basket),
                format!("{:?}", c.originator),
            ]
        },
        vec![
            (
                Box::new(|c| c.with_protocol_id((1, "other".into()))),
                "(1, \"other\")",
            ),
            (Box::new(|c| c.with_basket("b".into())), "\"b\""),
            (
                Box::new(|mut c| {
                    c.originator = Some("o".into());
                    c
                }),
                "Some(\"o\")",
            ),
        ],
    ) - 1;
    assert_eq!(setters, 40, "the forty setters of #843d8c");
}

#[test]
fn teranode_config_new_carries_no_key_and_thirty_seconds_843d8c() {
    let config = TeranodeConfig::new("https://teranode.invalid");
    assert_eq!(config.url, "https://teranode.invalid");
    assert_eq!(config.api_key, None);
    assert_eq!(config.timeout_ms, 30_000);
    let owned = TeranodeConfig::new(String::from("https://teranode.invalid"));
    assert_eq!(owned.url, config.url);
    // The migration line: the three fields a literal named.
    let full = TeranodeConfig::new("u")
        .with_api_key(Some("k".into()))
        .with_timeout_ms(7);
    assert_eq!(
        (full.url.as_str(), full.api_key.as_deref(), full.timeout_ms),
        ("u", Some("k"), 7)
    );
}

/// A type with no `Default`, `Debug` or `Clone`.
struct Bare;

#[test]
fn a_historian_config_defaults_for_types_without_default_843d8c() {
    let config: HistorianConfig<Bare, Bare> = HistorianConfig::default();
    assert!(!config.debug);
    assert!(config.history_cache.is_none());
    assert!(config.interpreter_version.is_none());
    assert!(config.ctx_key_fn.is_none());
    let set = config.with_history_cache(Some(HashMap::from([("k".to_string(), vec![Bare])])));
    assert_eq!(set.history_cache.unwrap()["k"].len(), 1);
}

#[test]
fn every_default_keeps_its_values_843d8c() {
    let reputation = ReputationConfig::default();
    assert_eq!(
        (
            reputation.latency_smoothing,
            reputation.grace_failures,
            reputation.backoff_base_ms,
            reputation.backoff_max_ms,
            reputation.default_latency_ms,
            reputation.failure_penalty_ms,
            reputation.success_bonus_ms,
        ),
        (0.25, 2, 1000, 60_000, 1500.0, 400.0, 30.0)
    );
    let downloader = StorageDownloaderConfig::default();
    assert_eq!(downloader.network_preset, NetworkPreset::Mainnet);
    assert!(downloader.resolver.is_none());
    assert_eq!(downloader.timeout_ms, Some(30000));
    assert_eq!(CacheConfig::default().max_size, 1000);
    let totp = TotpOptions::default();
    assert_eq!(
        (totp.digits, totp.algorithm, totp.period, totp.timestamp),
        (6, Algorithm::Sha1, 30, None)
    );
    let validate = TotpValidateOptions::default();
    assert_eq!(
        format!("{:?}", validate.options),
        format!("{:?}", TotpOptions::default())
    );
    assert_eq!(validate.skew, 1);
    let historian: HistorianConfig<u8, u8> = HistorianConfig::default();
    assert!(!historian.debug);
    assert!(historian.history_cache.is_none());
    assert!(historian.interpreter_version.is_none());
    assert!(historian.ctx_key_fn.is_none());
    let woc = WocBroadcastConfig::default();
    assert_eq!(
        (woc.network, woc.api_key, woc.timeout_ms, woc.base_url),
        (WocBroadcastNetwork::Mainnet, None, 30_000, None)
    );
    let headers = BlockHeadersServiceConfig::default();
    assert_eq!(
        (
            headers.base_url.as_str(),
            headers.auth_token,
            headers.timeout_ms
        ),
        ("https://headers.spv.money", None, 30_000)
    );
    let policy = LivePolicyConfig::default();
    assert_eq!(
        (
            policy.policy_url.as_str(),
            policy.api_key,
            policy.cache_ttl,
            policy.fallback_rate,
            policy.timeout_ms,
        ),
        ("", None, Duration::from_secs(300), 100, 10_000)
    );
    let identity = IdentityClientConfig::default();
    assert_eq!(
        (
            identity.network_preset,
            identity.protocol_id,
            identity.key_id.as_str(),
            identity.token_amount,
            identity.output_index,
            identity.originator,
        ),
        (
            NetworkPreset::Mainnet,
            (1, "identity".to_string()),
            "1",
            1,
            0,
            None
        )
    );
    let contacts = ContactsManagerConfig::default();
    assert_eq!(
        (
            contacts.protocol_id,
            contacts.basket.as_str(),
            contacts.originator
        ),
        ((2, "contact".to_string()), "contacts", None)
    );
    // The six that took the attribute alone: their doors as they were.
    let uploader = StorageUploaderConfig::new("https://storage.invalid");
    assert_eq!(uploader.storage_url, "https://storage.invalid");
    assert_eq!(
        uploader.default_retention_minutes,
        StorageUploaderConfig::new("u")
            .with_retention_minutes(uploader.default_retention_minutes)
            .default_retention_minutes
    );
    let kv = KVStoreConfig::default();
    assert_eq!(
        format!("{:?}", KVStoreConfig::new()),
        format!("{kv:?}"),
        "KVStoreConfig::new is its default"
    );
    assert_eq!(kv.token_amount, 1);
    assert!(kv.originator.is_none());
    let get = KVStoreGetOptions::default();
    assert_eq!(
        format!("{get:?}"),
        format!("{:?}", KVStoreGetOptions::new())
    );
    let set = KVStoreSetOptions::default();
    assert_eq!(
        (
            set.protocol_id,
            set.description,
            set.token_amount,
            set.tags,
            set.ttl
        ),
        (None, None, None, None, None)
    );
    let remove = KVStoreRemoveOptions::default();
    assert_eq!((remove.protocol_id, remove.description), (None, None));
    let registry = RegistryClientConfig::default();
    assert_eq!(registry.network_preset, NetworkPreset::Mainnet);
    assert!(registry.resolver.is_none());
    assert!(registry.originator.is_none());
}
