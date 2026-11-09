//! #775 and #785 at the reference's default limits (`ts-stack@edf6e03`
//! `packages/sdk/src/overlay-tools/LookupResources.ts:16-27`: a response of
//! at most 32 MiB, an answer of at most 4096 outputs, 256 hosts).
//!
//! #775: a lookup answer past a limit is the reference's
//! `LookupResourceLimitError` (`Lookup resource limit reached: <limit>`,
//! `LookupResources.ts:29-34`) and neutral for host reputation, as the
//! tracked call rethrows it before `recordFailure`
//! (`LookupResolver.ts:2415`):
//!
//! ```text
//! if (err instanceof LookupResourceLimitError) throw err
//! if (isSemanticLookupRejection(err)) throw err
//! const normalized = normalizeLookupError(err, deadline.didTimeOut())
//! this.hostReputation.recordFailure(host, normalized)
//! ```
//!
//! Until #775 the facilitator read a body with reqwest's `.json()` and
//! `.bytes()`, unbounded, and no path counted an answer's outputs: a
//! 4,097-output answer was a success for its host, and a response declaring
//! a length past 32 MiB was read.
//!
//! #785: `find_competent_hosts` answers the hosts in the trackers' answer
//! order, each at its earliest occurrence (`LookupResolver.ts:2006-2009`,
//! `LookupDiscovery.ts:62-78`), where it answered a `HashSet`'s order.
//!
//! Every name here compiles on the base (the refusal is read by its text),
//! so each test is RED there on its assertion; the configured limits are
//! `lookup_limits_configured_775.rs`. Each test names hosts of its own: the
//! reputation tracker is one global keyed by URL. Every listener binds an
//! ephemeral port.
#![cfg(feature = "overlay")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/lookup_limits_775.rs"]
mod limits;
#[path = "support/pushdrop_lock_position_537.rs"]
mod lock_position;

use bsv_rs::overlay::{
    create_signed_overlay_admin_token, LookupAnswer, LookupQuestion, LookupResolver,
    LookupResolverConfig, Protocol,
};
use bsv_rs::primitives::PrivateKey;
use limits::{output_list, record, Scripted};
use serde_json::json;
use std::collections::HashMap;

/// A tracker's answer naming each host for `service`, in the order given,
/// SLAP advertisements signed by this crate's writer.
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

fn overriding(service: &str, hosts: &[&str]) -> LookupResolverConfig {
    LookupResolverConfig {
        slap_trackers: Some(vec![]),
        host_overrides: Some(HashMap::from([(
            service.to_string(),
            hosts.iter().map(|host| host.to_string()).collect(),
        )])),
        ..Default::default()
    }
}

/// The host's reputation entry: failures, successes and the last error.
fn failure_of(host: &str) -> (u64, u64, Option<String>) {
    let entry = bsv_rs::overlay::get_overlay_host_reputation_tracker()
        .snapshot(host)
        .expect("a record");
    (
        entry.total_failures,
        entry.total_successes,
        entry.last_error,
    )
}

/// A custom facilitator's answer is read by the reference's normalizer
/// before its limits (`trackLookupAnswer`, `LookupResolver.ts:2385-2392`):
/// past its constant 4096 (`MAX_LOOKUP_OUTPUTS`, `:254`, `:395`) the answer
/// is `Malformed lookup response`, a plain `Error`, recorded against the
/// host (`:2386-2390`), never the neutral limit (the captain's ruling of
/// 2026-11-09 on #775's question: conform). RED on the lane's `4046c534`,
/// which read it as the neutral `maxOutputs` and recorded nothing.
#[tokio::test]
async fn a_scripted_answer_of_4097_outputs_is_malformed_and_its_hosts_failure_775() {
    const SERVICE: &str = "ls_limits_bound_scripted";
    const OVER: &str = "https://over.scripted.limits-775.invalid";
    const AT: &str = "https://at.scripted.limits-775.invalid";
    let (facilitator, asked) = Scripted::new(vec![
        (OVER, Ok(output_list(4097, 1))),
        (AT, Ok(output_list(4096, 1))),
    ]);
    let resolver = LookupResolver::new(LookupResolverConfig {
        facilitator: Some(facilitator),
        ..overriding(SERVICE, &[OVER, AT])
    });

    let answer = resolver
        .query(&LookupQuestion::new(SERVICE, json!({})), None)
        .await
        .unwrap();
    assert!(
        matches!(&answer, LookupAnswer::OutputList { outputs } if outputs.is_empty()),
        "no output here is a BEEF: {answer:?}"
    );
    assert_eq!(asked.lock().unwrap().len(), 2);
    // 4,097 outputs: the normalizer's refusal, the host's failure.
    let (failures, successes, error) = failure_of(OVER);
    assert_eq!((failures, successes), (1, 0));
    assert!(
        error
            .as_deref()
            .is_some_and(|e| e.contains("Malformed lookup response")),
        "{error:?}"
    );
    // 4,096 outputs: an answer, its host's success.
    assert_eq!(record(AT), Some((0, 1)));
}

/// A tracker's answer is a tracked call too (`LookupResolver.ts:1974`):
/// 4,097 advertisements `Malformed lookup response`, the tracker's failure,
/// naming no host. RED on `4046c534` (nothing recorded).
#[tokio::test]
async fn a_tracker_answer_of_4097_outputs_is_malformed_and_names_no_host_775() {
    const SERVICE: &str = "ls_limits_bound_tracker";
    const OVER: &str = "https://over.tracker.limits-775.invalid";
    const NAMING: &str = "https://naming.tracker.limits-775.invalid";
    const HOST: &str = "https://host.tracker.limits-775.invalid";
    let mut flood = match advertising(SERVICE, &["https://flood.tracker.limits-775.invalid"]) {
        Ok(LookupAnswer::OutputList { outputs }) => outputs,
        other => panic!("{other:?}"),
    };
    let one = flood[0].clone();
    flood.resize(4097, one);
    let (facilitator, _asked) = Scripted::new(vec![
        (OVER, Ok(LookupAnswer::OutputList { outputs: flood })),
        (NAMING, advertising(SERVICE, &[HOST])),
    ]);
    let resolver = LookupResolver::new(LookupResolverConfig {
        facilitator: Some(facilitator),
        slap_trackers: Some(vec![OVER.to_string(), NAMING.to_string()]),
        ..Default::default()
    });

    let hosts = resolver.find_competent_hosts(SERVICE).await.unwrap();
    assert_eq!(hosts, [HOST], "the flooding tracker names no host");
    let (failures, successes, error) = failure_of(OVER);
    assert_eq!((failures, successes), (1, 0));
    assert!(
        error
            .as_deref()
            .is_some_and(|e| e.contains("Malformed lookup response")),
        "{error:?}"
    );
    assert_eq!(record(NAMING), Some((0, 1)));
}

/// The strength read's test of #783 (`tests/lookup_discovery_779.rs` sorted
/// before comparing, because the order could not be pinned).
#[tokio::test]
async fn the_discovered_hosts_keep_the_trackers_answer_order_785() {
    const SERVICE: &str = "ls_limits_order_order";
    const A: &str = "https://a.order.limits-785.invalid";
    const B: &str = "https://b.order.limits-785.invalid";
    const H1: &str = "https://h1.order.limits-785.invalid";
    const H2: &str = "https://h2.order.limits-785.invalid";
    const H3: &str = "https://h3.order.limits-785.invalid";
    let (facilitator, _asked) = Scripted::new(vec![
        (A, advertising(SERVICE, &[H2, H1])),
        (B, advertising(SERVICE, &[H1, H3])),
    ]);
    let resolver = LookupResolver::new(LookupResolverConfig {
        facilitator: Some(facilitator),
        slap_trackers: Some(vec![A.to_string(), B.to_string()]),
        ..Default::default()
    });

    // A fresh hasher per call on the base: ten discoveries, one order.
    for _ in 0..10 {
        let hosts = resolver.find_competent_hosts(SERVICE).await.unwrap();
        assert_eq!(hosts, [H2, H1, H3]);
    }
}

#[tokio::test]
async fn a_longer_answer_keeps_its_own_order_and_its_earliest_occurrences_785() {
    const SERVICE: &str = "ls_limits_order_long";
    const A: &str = "https://a.long.limits-785.invalid";
    const B: &str = "https://b.long.limits-785.invalid";
    let name = |n: usize| format!("https://h{n}.long.limits-785.invalid");
    let leading: Vec<String> = [9, 3, 7, 3, 1, 8, 9].map(name).to_vec();
    let trailing: Vec<String> = [1, 6, 9, 2, 6, 4].map(name).to_vec();
    fn borrowed(hosts: &[String]) -> Vec<&str> {
        hosts.iter().map(String::as_str).collect()
    }
    let (facilitator, _asked) = Scripted::new(vec![
        (A, advertising(SERVICE, &borrowed(&leading))),
        (B, advertising(SERVICE, &borrowed(&trailing))),
    ]);
    let resolver = LookupResolver::new(LookupResolverConfig {
        facilitator: Some(facilitator),
        slap_trackers: Some(vec![A.to_string(), B.to_string()]),
        ..Default::default()
    });

    let hosts = resolver.find_competent_hosts(SERVICE).await.unwrap();
    assert_eq!(hosts, [9, 3, 7, 1, 8, 6, 2, 4].map(name));
}

#[cfg(feature = "http")]
mod http {
    use super::limits::{
        binary_beef, binary_body, binary_outpoint, host_answering, raw_host, record,
    };
    use super::overriding;
    use bsv_rs::overlay::{
        HttpsOverlayLookupFacilitator, LookupAnswer, LookupQuestion, LookupResolver,
        LookupResolverConfig, OverlayLookupFacilitator,
    };
    use serde_json::json;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    const SERVICE: &str = "ls_limits_bound_http";

    fn question() -> LookupQuestion {
        LookupQuestion::new(SERVICE, json!({}))
    }

    fn http_resolver(host: &str) -> LookupResolver {
        LookupResolver::new(LookupResolverConfig {
            facilitator: Some(Arc::new(HttpsOverlayLookupFacilitator::new(true))),
            ..overriding(SERVICE, &[host])
        })
    }

    /// The facilitator refuses the host's answer as the limit named, in the
    /// reference's words, and a query records nothing for the host.
    async fn limit_and_neutral(host: &str, limit: &str) {
        let refusal = HttpsOverlayLookupFacilitator::new(true)
            .lookup(host, &question(), Some(3000))
            .await
            .map(|answer| match answer {
                LookupAnswer::OutputList { outputs } => format!("{} outputs read", outputs.len()),
                other => format!("{other:?}"),
            })
            .map_err(|e| e.to_string());
        assert_eq!(
            refusal,
            Err(format!("Lookup resource limit reached: {limit}"))
        );
        let answer = http_resolver(host)
            .query(&question(), Some(3000))
            .await
            .unwrap();
        assert!(
            matches!(&answer, LookupAnswer::OutputList { outputs } if outputs.is_empty()),
            "{answer:?}"
        );
        assert_eq!(record(host), None, "the reputation record is unchanged");
    }

    /// 4,097 outputs the limit and neutral; the control, 4,096, an answer
    /// and its host's success.
    async fn over_and_at(content_type: &str, body: impl Fn(usize) -> Vec<u8>) {
        let host = host_answering(content_type, body(4097));
        limit_and_neutral(&host, "maxOutputs").await;

        let host = host_answering(content_type, body(4096));
        let answer = HttpsOverlayLookupFacilitator::new(true)
            .lookup(&host, &question(), None)
            .await
            .unwrap();
        assert!(
            matches!(&answer, LookupAnswer::OutputList { outputs } if outputs.len() == 4096),
            "{answer:?}"
        );
        http_resolver(&host).query(&question(), None).await.unwrap();
        assert_eq!(record(&host), Some((0, 1)));
    }

    #[tokio::test]
    async fn a_json_answer_of_4097_outputs_is_the_limit_and_neutral_775() {
        let item = json!({ "beef": [1], "outputIndex": 0 });
        over_and_at("application/json", |count| {
            json!({ "type": "output-list", "outputs": vec![item.clone(); count] })
                .to_string()
                .into_bytes()
        })
        .await;
    }

    #[tokio::test]
    async fn a_binary_answer_of_4097_outpoints_is_the_limit_and_neutral_775() {
        let beef = binary_beef();
        over_and_at("application/octet-stream", |count| {
            binary_body(count, &beef)
        })
        .await;
    }

    /// The header alone: no body of that size is served. The server holds
    /// the connection open after one byte, so a client that reads the body
    /// waits for its timeout; the refusal comes before the read.
    async fn a_declared_length_is_refused_before_the_read(content_type: &str) {
        let declared = 32 * 1024 * 1024 + 1;
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {declared}\r\n\r\n"
        );
        let (host, _written) = raw_host(head, vec![b"{".to_vec()]);
        let started = Instant::now();
        let refusal = HttpsOverlayLookupFacilitator::new(true)
            .lookup(&host, &question(), Some(1500))
            .await
            .map(|_| ())
            .map_err(|e| e.to_string());
        assert_eq!(
            refusal,
            Err("Lookup resource limit reached: maxResponseBytes".to_string())
        );
        assert!(
            started.elapsed() < Duration::from_millis(1200),
            "refused at the head, not at the read's timeout: {:?}",
            started.elapsed()
        );
        assert_eq!(record(&host), None);
    }

    #[tokio::test]
    async fn a_json_content_length_past_32_mib_is_refused_before_the_read_775() {
        a_declared_length_is_refused_before_the_read("application/json").await;
    }

    #[tokio::test]
    async fn a_binary_content_length_past_32_mib_is_refused_before_the_read_775() {
        a_declared_length_is_refused_before_the_read("application/octet-stream").await;
    }

    #[tokio::test]
    async fn a_declared_length_past_32_mib_is_neutral_for_its_host_775() {
        let declared = 32 * 1024 * 1024 + 1;
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {declared}\r\n\r\n"
        );
        let (host, _written) = raw_host(head, vec![b"{".to_vec()]);
        let answer = http_resolver(&host)
            .query(&question(), Some(1500))
            .await
            .unwrap();
        assert!(
            matches!(&answer, LookupAnswer::OutputList { outputs } if outputs.is_empty()),
            "{answer:?}"
        );
        assert_eq!(record(&host), None, "the reputation record is unchanged");
    }

    /// A binary answer of one outpoint of `beef`'s transaction at `index`
    /// with `context`, built by this crate's writer, then the BEEF; `cut`
    /// the bytes kept after the outpoint's context length (the whole
    /// answer when `None`).
    fn one_outpoint(index: u64, context: &[u8], cut: Option<usize>) -> Vec<u8> {
        let beef = binary_beef();
        let mut body = bsv_rs::primitives::Writer::new();
        body.write_var_int(1);
        binary_outpoint(&mut body, &beef.txid, index, context);
        body.write_bytes(&beef.bytes);
        let mut body = body.into_bytes();
        if let Some(kept) = cut {
            // 1 (count) + 32 (txid) + the index's and the length's varints
            let head = 1
                + 32
                + bsv_rs::primitives::var_int_len(index)
                + bsv_rs::primitives::var_int_len(context.len() as u64);
            body.truncate(head + kept);
        }
        body
    }

    /// The facilitator's refusal of `body` and the host's record after a
    /// query: a plain `Error`, the host's failure (`:2408-2419`).
    async fn refused_as_a_failure(body: Vec<u8>, words: &str) {
        let host = host_answering("application/octet-stream", body);
        let refusal = HttpsOverlayLookupFacilitator::new(true)
            .lookup(&host, &question(), Some(3000))
            .await
            .map(|answer| format!("{answer:?}"))
            .map_err(|e| e.to_string());
        assert_eq!(refusal, Err(format!("overlay error: {words}")));
        http_resolver(&host)
            .query(&question(), Some(3000))
            .await
            .unwrap();
        assert_eq!(record(&host), Some((1, 0)), "the host's failure");
    }

    /// An output index past `0xffffffff` (the varint's nine-byte form)
    /// refuses the whole answer in the reference's words
    /// (`LookupResolver.ts:888`), a host failure; one at `0xffffffff` read.
    /// RED on `4046c534`, which cut it to its low 32 bits (index 0, read).
    #[tokio::test]
    async fn a_binary_output_index_past_u32_is_refused_as_a_host_failure_775() {
        refused_as_a_failure(
            one_outpoint(0x1_0000_0000, &[], None),
            "Overlay output index is out of range.",
        )
        .await;
        let host = host_answering(
            "application/octet-stream",
            one_outpoint(0xffff_ffff, &[], None),
        );
        let answer = HttpsOverlayLookupFacilitator::new(true)
            .lookup(&host, &question(), Some(3000))
            .await
            .unwrap();
        assert!(
            matches!(&answer, LookupAnswer::OutputList { outputs }
                if outputs.len() == 1 && outputs[0].output_index == u32::MAX),
            "{answer:?}"
        );
    }

    /// A context of 1 MiB plus one refuses the whole answer in the
    /// reference's words (`:889-891`), a host failure, before its bytes are
    /// read (the answer cut after one context byte gets the same words, not
    /// a read's); 1 MiB read. RED on `4046c534`, which read the context
    /// whole (and, cut, refused at the read).
    #[tokio::test]
    async fn a_binary_context_past_1_mib_is_refused_before_its_read_775() {
        const MIB: usize = 1024 * 1024;
        const WORDS: &str = "Overlay output context exceeds the maximum permitted size.";
        refused_as_a_failure(one_outpoint(0, &vec![7; MIB + 1], None), WORDS).await;
        refused_as_a_failure(one_outpoint(0, &vec![7; MIB + 1], Some(1)), WORDS).await;
        let host = host_answering(
            "application/octet-stream",
            one_outpoint(0, &vec![7; MIB], None),
        );
        let answer = HttpsOverlayLookupFacilitator::new(true)
            .lookup(&host, &question(), Some(3000))
            .await
            .unwrap();
        assert!(
            matches!(&answer, LookupAnswer::OutputList { outputs }
                if outputs.len() == 1 && outputs[0].context.as_ref().map(Vec::len) == Some(MIB)),
            "the 1 MiB context read"
        );
    }
}
