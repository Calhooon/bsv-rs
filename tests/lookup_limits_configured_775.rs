//! #775 and #785 at limits a host sets (`LookupResolverConfig::limits`, the
//! reference's `LookupLimits`, `ts-stack@edf6e03`
//! `packages/sdk/src/overlay-tools/LookupResources.ts:2-27`), small ones, so
//! no test serves 32 MiB: the response bound on a declared length and on a
//! body without one (the read stopped at the bound,
//! `LookupResponseReader.ts:150-214`), the output bound, the binary path's
//! extracted bytes (`LookupResolver.ts:929-932`), a query's total bytes
//! (`:1624-1631`, `:1734-1743`), a tracker's share and the discovery's and
//! the query's host bound (`LookupDiscovery.ts:62-78,105-108`,
//! `LookupResolver.ts:2006-2009`, `:1842-1849`).
//!
//! `LookupLimits`, `LookupRequestOptions`, `lookup_bounded` and
//! `Error::OverlayResourceLimit` are #775's additions: on the base this file
//! does not compile (its RED is the absent API); the tests RED there on an
//! assertion are `lookup_limits_775.rs`. Each test names hosts of its own;
//! every listener binds an ephemeral port.
#![cfg(feature = "overlay")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/lookup_limits_775.rs"]
mod limits;
#[path = "support/pushdrop_lock_position_537.rs"]
mod lock_position;

use bsv_rs::overlay::{
    create_signed_overlay_admin_token, LookupAnswer, LookupLimits, LookupQuestion, LookupResolver,
    LookupResolverConfig, Protocol,
};
use bsv_rs::primitives::PrivateKey;
use limits::{output_list, record, Scripted};
use serde_json::json;
use std::collections::HashMap;

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

fn limits(set: impl FnOnce(&mut LookupLimits)) -> LookupLimits {
    let mut limits = LookupLimits::default();
    set(&mut limits);
    limits
}

fn overriding(service: &str, hosts: &[&str], limits: LookupLimits) -> LookupResolverConfig {
    LookupResolverConfig {
        slap_trackers: Some(vec![]),
        host_overrides: Some(HashMap::from([(
            service.to_string(),
            hosts.iter().map(|host| host.to_string()).collect(),
        )])),
        limits,
        ..Default::default()
    }
}

fn tracking(trackers: &[&str], limits: LookupLimits) -> LookupResolverConfig {
    LookupResolverConfig {
        slap_trackers: Some(trackers.iter().map(|t| t.to_string()).collect()),
        limits,
        ..Default::default()
    }
}

#[tokio::test]
async fn a_configured_output_bound_is_the_limit_and_neutral_775() {
    const SERVICE: &str = "ls_limits_bound_outputs";
    const OVER: &str = "https://over.outputs.limits-775.invalid";
    const AT: &str = "https://at.outputs.limits-775.invalid";
    let (facilitator, _asked) = Scripted::new(vec![
        (OVER, Ok(output_list(3, 1))),
        (AT, Ok(output_list(2, 1))),
    ]);
    let resolver = LookupResolver::new(LookupResolverConfig {
        facilitator: Some(facilitator),
        ..overriding(SERVICE, &[OVER, AT], limits(|l| l.max_outputs = 2))
    });
    resolver
        .query(&LookupQuestion::new(SERVICE, json!({})), None)
        .await
        .unwrap();
    assert_eq!(record(OVER), None);
    assert_eq!(record(AT), Some((0, 1)));
}

/// A `max_outputs` raised past 4096 admits no larger answer from a custom
/// facilitator: the resolver's normalizer holds the constant 4096 before the
/// configured bound (`LookupResolver.ts:254`, `:395`, `:2385-2392`), so
/// 4,097 outputs are `Malformed lookup response` and the host's failure,
/// and 4,096 an answer (#775's fold, the captain's ruling of 2026-11-09).
/// RED on `4046c534`, which admitted the 4,097 under the raised bound.
#[tokio::test]
async fn a_raised_output_bound_admits_no_answer_past_the_normalizers_4096_775() {
    const SERVICE: &str = "ls_limits_bound_raised";
    const OVER: &str = "https://over.raised.limits-775.invalid";
    const AT: &str = "https://at.raised.limits-775.invalid";
    let (facilitator, _asked) = Scripted::new(vec![
        (OVER, Ok(output_list(4097, 1))),
        (AT, Ok(output_list(4096, 1))),
    ]);
    let resolver = LookupResolver::new(LookupResolverConfig {
        facilitator: Some(facilitator),
        ..overriding(SERVICE, &[OVER, AT], limits(|l| l.max_outputs = 8192))
    });
    resolver
        .query(&LookupQuestion::new(SERVICE, json!({})), None)
        .await
        .unwrap();
    assert_eq!(
        record(OVER),
        Some((1, 0)),
        "the normalizer's refusal, a failure"
    );
    assert_eq!(record(AT), Some((0, 1)));
}

#[tokio::test]
async fn a_scripted_answer_past_the_response_bytes_is_neutral_775() {
    const SERVICE: &str = "ls_limits_bound_bytes";
    const OVER: &str = "https://over.bytes.limits-775.invalid";
    const AT: &str = "https://at.bytes.limits-775.invalid";
    // Two outputs of 5 and of 4 bytes of BEEF against 8 bytes a response.
    let (facilitator, _asked) = Scripted::new(vec![
        (OVER, Ok(output_list(2, 5))),
        (AT, Ok(output_list(2, 4))),
    ]);
    let resolver = LookupResolver::new(LookupResolverConfig {
        facilitator: Some(facilitator),
        ..overriding(SERVICE, &[OVER, AT], limits(|l| l.max_response_bytes = 8))
    });
    resolver
        .query(&LookupQuestion::new(SERVICE, json!({})), None)
        .await
        .unwrap();
    assert_eq!(record(OVER), None);
    assert_eq!(record(AT), Some((0, 1)));
}

#[tokio::test]
async fn a_query_charges_its_hosts_to_one_total_and_the_host_past_it_is_neutral_775() {
    const SERVICE: &str = "ls_limits_bound_total";
    const ONE: &str = "https://one.total.limits-775.invalid";
    const TWO: &str = "https://two.total.limits-775.invalid";
    // 6 bytes each against 10 in all: the second charged finds 4 left.
    let (facilitator, asked) = Scripted::new(vec![
        (ONE, Ok(output_list(1, 6))),
        (TWO, Ok(output_list(1, 6))),
    ]);
    let resolver = LookupResolver::new(LookupResolverConfig {
        facilitator: Some(facilitator),
        ..overriding(SERVICE, &[ONE, TWO], limits(|l| l.max_total_bytes = 10))
    });
    resolver
        .query(&LookupQuestion::new(SERVICE, json!({})), None)
        .await
        .unwrap();
    assert_eq!(asked.lock().unwrap().len(), 2);
    let mut records = [record(ONE), record(TWO)];
    records.sort();
    assert_eq!(records, [None, Some((0, 1))]);
}

#[tokio::test]
async fn a_discovery_charges_its_trackers_to_one_total_775() {
    const SERVICE: &str = "ls_limits_bound_discovery_total";
    const A: &str = "https://a.dtotal.limits-775.invalid";
    const B: &str = "https://b.dtotal.limits-775.invalid";
    const HA: &str = "https://ha.dtotal.limits-775.invalid";
    const HB: &str = "https://hb.dtotal.limits-775.invalid";
    let one = advertising(SERVICE, &[HA]);
    let bytes = match &one {
        Ok(LookupAnswer::OutputList { outputs }) => outputs[0].beef.len(),
        other => panic!("{other:?}"),
    };
    let (facilitator, _asked) = Scripted::new(vec![(A, one), (B, advertising(SERVICE, &[HB]))]);
    // Room for one tracker's answer and not for two.
    let resolver = LookupResolver::new(LookupResolverConfig {
        facilitator: Some(facilitator),
        ..tracking(&[A, B], limits(|l| l.max_total_bytes = bytes + bytes / 2))
    });
    let hosts = resolver.find_competent_hosts(SERVICE).await.unwrap();
    assert_eq!(hosts, [HA]);
    assert_eq!(record(A), Some((0, 1)));
    assert_eq!(record(B), None, "the limit records nothing for the tracker");
}

#[tokio::test]
async fn a_tracker_answer_is_cut_to_its_share_785() {
    const SERVICE: &str = "ls_limits_order_share";
    const A: &str = "https://a.share.limits-785.invalid";
    const B: &str = "https://b.share.limits-785.invalid";
    let name = |n: usize| format!("https://h{n}.share.limits-785.invalid");
    let names = |ns: &[usize]| ns.iter().map(|n| name(*n)).collect::<Vec<_>>();
    let script = |ns: &[usize]| {
        let hosts = names(ns);
        advertising(
            SERVICE,
            &hosts.iter().map(String::as_str).collect::<Vec<_>>(),
        )
    };
    let build = |limits| {
        let (facilitator, _asked) =
            Scripted::new(vec![(A, script(&[1, 1, 2, 3])), (B, script(&[2, 4, 5]))]);
        LookupResolver::new(LookupResolverConfig {
            facilitator: Some(facilitator),
            ..tracking(&[A, B], limits)
        })
    };

    // `maxHostsPerTracker` 2: each answer's leading two distinct hosts.
    let hosts = build(limits(|l| l.max_hosts_per_tracker = 2))
        .find_competent_hosts(SERVICE)
        .await
        .unwrap();
    assert_eq!(hosts, names(&[1, 2, 4]));

    // `maxHosts` 2 over two trackers: a share of one each
    // (`LookupDiscovery.ts:105-108`).
    let hosts = build(limits(|l| l.max_hosts = 2))
        .find_competent_hosts(SERVICE)
        .await
        .unwrap();
    assert_eq!(hosts, names(&[1, 2]));

    // The defaults keep both answers whole.
    let hosts = build(LookupLimits::default())
        .find_competent_hosts(SERVICE)
        .await
        .unwrap();
    assert_eq!(hosts, names(&[1, 2, 3, 4, 5]));
}

#[tokio::test]
async fn the_discovered_hosts_are_cut_to_max_hosts_785() {
    const SERVICE: &str = "ls_limits_order_max_hosts";
    let tracker = |n: usize| format!("https://t{n}.max.limits-785.invalid");
    let host = |n: usize| format!("https://h{n}.max.limits-785.invalid");
    let trackers: Vec<String> = (0..3).map(tracker).collect();
    let hosts: Vec<String> = (0..3).map(host).collect();
    let script = trackers
        .iter()
        .zip(&hosts)
        .map(|(tracker, host)| (tracker.as_str(), advertising(SERVICE, &[host.as_str()])))
        .collect();
    let (facilitator, _asked) = Scripted::new(script);
    // Three trackers of one host each against two hosts: a share of one
    // each (the floor), then the whole cut to two.
    let resolver = LookupResolver::new(LookupResolverConfig {
        facilitator: Some(facilitator),
        ..tracking(
            &trackers.iter().map(String::as_str).collect::<Vec<_>>(),
            limits(|l| l.max_hosts = 2),
        )
    });
    let found = resolver.find_competent_hosts(SERVICE).await.unwrap();
    assert_eq!(found, hosts[..2]);
}

#[tokio::test]
async fn a_query_admits_the_leading_max_hosts_785() {
    const SERVICE: &str = "ls_limits_order_admission";
    const H1: &str = "https://h1.admission.limits-785.invalid";
    const H2: &str = "https://h2.admission.limits-785.invalid";
    const H3: &str = "https://h3.admission.limits-785.invalid";
    let (facilitator, asked) = Scripted::new(vec![
        (H1, Ok(output_list(0, 0))),
        (H2, Ok(output_list(0, 0))),
        (H3, Ok(output_list(0, 0))),
    ]);
    let resolver = LookupResolver::new(LookupResolverConfig {
        facilitator: Some(facilitator),
        ..overriding(SERVICE, &[H1, H2, H1, H3], limits(|l| l.max_hosts = 2))
    });
    resolver
        .query(&LookupQuestion::new(SERVICE, json!({})), None)
        .await
        .unwrap();
    let mut asked = asked.lock().unwrap().clone();
    asked.sort();
    assert_eq!(asked, [H1, H2]);
    assert_eq!(record(H3), None);
}

/// A [`Scripted`] facilitator whose answer for `slow` waits `delay_ms`
/// first: the trackers answer in another order than the configured one.
struct Delayed {
    inner: std::sync::Arc<Scripted>,
    slow: &'static str,
    delay_ms: u64,
}

#[async_trait::async_trait(?Send)]
impl bsv_rs::overlay::OverlayLookupFacilitator for Delayed {
    async fn lookup(
        &self,
        url: &str,
        question: &LookupQuestion,
        timeout_ms: Option<u64>,
    ) -> bsv_rs::Result<LookupAnswer> {
        if url == self.slow {
            tokio::time::sleep(std::time::Duration::from_millis(self.delay_ms)).await;
        }
        self.inner.lookup(url, question, timeout_ms).await
    }
}

/// The discovered hosts are in the order the trackers answer, not the order
/// they are configured (`LookupDiscovery.ts:62-78`: each tracker's hosts
/// pushed as its promise settles; #785): the tracker configured first
/// answers 300 ms late, so the other's host leads. The strength read's S1
/// (PR #801): with the trackers joined in configured order (`join_all`)
/// every other test passed; RED on a scratch copy of `c137649f` so planted
/// (`left: [ha, hb]`).
#[tokio::test]
async fn the_discovered_hosts_follow_the_trackers_arrival_order_785() {
    const SERVICE: &str = "ls_limits_order_arrival";
    const A: &str = "https://a.arrival.limits-785.invalid";
    const B: &str = "https://b.arrival.limits-785.invalid";
    const HA: &str = "https://ha.arrival.limits-785.invalid";
    const HB: &str = "https://hb.arrival.limits-785.invalid";
    let (inner, _asked) = Scripted::new(vec![
        (A, advertising(SERVICE, &[HA])),
        (B, advertising(SERVICE, &[HB])),
    ]);
    let resolver = LookupResolver::new(LookupResolverConfig {
        facilitator: Some(std::sync::Arc::new(Delayed {
            inner,
            slow: A,
            delay_ms: 300,
        })),
        ..tracking(&[A, B], LookupLimits::default())
    });
    let hosts = resolver.find_competent_hosts(SERVICE).await.unwrap();
    assert_eq!(hosts, [HB, HA]);
}

#[cfg(feature = "http")]
mod http {
    use super::limits::{binary_beef, binary_beef_spending, binary_body, host_answering, raw_host};
    use bsv_rs::overlay::{
        HttpsOverlayLookupFacilitator, LookupAnswer, LookupByteBudget, LookupQuestion,
        LookupRequestOptions, OverlayLookupFacilitator,
    };
    use bsv_rs::Error;
    use serde_json::json;

    fn question() -> LookupQuestion {
        LookupQuestion::new("ls_limits_bound_configured_http", json!({}))
    }

    fn options(set: impl FnOnce(&mut LookupRequestOptions)) -> LookupRequestOptions {
        let mut options = LookupRequestOptions::default();
        set(&mut options);
        options
    }

    async fn bounded(host: &str, options: &LookupRequestOptions) -> bsv_rs::Result<LookupAnswer> {
        HttpsOverlayLookupFacilitator::new(true)
            .lookup_bounded(host, &question(), None, Some(3000), options)
            .await
    }

    fn limit(name: &str) -> Error {
        Error::OverlayResourceLimit(name.to_string())
    }

    /// The facilitator's JSON parse runs the configured count, then the
    /// normalizer's constant (`LookupResolver.ts:859-866`): under a
    /// `max_outputs` of 8192, 4,097 outputs are `Malformed lookup
    /// response`, not the neutral limit. RED on `4046c534` (4,097 read).
    #[tokio::test]
    async fn a_json_answer_past_4096_under_a_raised_bound_is_malformed_775() {
        let item = json!({ "beef": [1], "outputIndex": 0 });
        let raised = options(|o| o.max_outputs = 8192);
        let body = |count| {
            json!({ "type": "output-list", "outputs": vec![item.clone(); count] })
                .to_string()
                .into_bytes()
        };
        let over = host_answering("application/json", body(4097));
        match bounded(&over, &raised).await {
            Err(Error::OverlayError(words)) => {
                assert!(words.starts_with("Malformed lookup response"), "{words}")
            }
            other => panic!("{:?}", other.map(|_| "an answer")),
        }
        let at = host_answering("application/json", body(4096));
        assert!(bounded(&at, &raised).await.is_ok());
    }

    #[tokio::test]
    async fn a_body_one_byte_past_the_bound_is_refused_and_one_at_it_is_read_775() {
        let body = json!({ "type": "freeform", "result": "0123456789" }).to_string();
        let host = host_answering("application/json", body.clone().into_bytes());
        let over = options(|o| o.max_response_bytes = body.len() - 1);
        assert_eq!(
            bounded(&host, &over).await.unwrap_err(),
            limit("maxResponseBytes")
        );
        let budget = LookupByteBudget::new(1024);
        let at = options(|o| {
            o.max_response_bytes = body.len();
            o.budget = Some(budget.clone());
        });
        let answer = bounded(&host, &at).await.unwrap();
        assert!(
            matches!(&answer, LookupAnswer::Freeform { result } if result == "0123456789"),
            "{answer:?}"
        );
        // The bytes read are charged to the budget (`consumeBytes`).
        assert_eq!(budget.received(), body.len());
    }

    /// A body without a length, chunk after chunk: the read stops at the
    /// chunk that passes the bound, the later chunks never asked for.
    async fn a_chunked_body_is_stopped_at_the_bound(content_type: &str) {
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nTransfer-Encoding: chunked\r\n\r\n"
        );
        let chunk = format!("28\r\n{}\r\n", " ".repeat(40)).into_bytes();
        let (host, written) = raw_host(head, vec![chunk; 200]);
        let bound = options(|o| o.max_response_bytes = 100);
        assert_eq!(
            bounded(&host, &bound).await.unwrap_err(),
            limit("maxResponseBytes")
        );
        // 8,000 bytes offered at 20 ms a chunk, three chunks to the bound.
        let written = *written.lock().unwrap();
        assert!(written < 100, "the read stopped early: {written} chunks");
    }

    #[tokio::test]
    async fn a_json_body_without_a_length_is_stopped_at_the_bound_775() {
        a_chunked_body_is_stopped_at_the_bound("application/json").await;
    }

    #[tokio::test]
    async fn a_binary_body_without_a_length_is_stopped_at_the_bound_775() {
        a_chunked_body_is_stopped_at_the_bound("application/octet-stream").await;
    }

    #[tokio::test]
    async fn a_body_past_what_the_budget_has_left_is_the_total_limit_775() {
        let body = json!({ "type": "freeform", "result": "0123456789" }).to_string();
        let host = host_answering("application/json", body.clone().into_bytes());
        let budget = LookupByteBudget::new(body.len() + 5);
        let shared = options(|o| o.budget = Some(budget.clone()));
        bounded(&host, &shared).await.unwrap();
        assert_eq!(
            bounded(&host, &shared).await.unwrap_err(),
            limit("maxTotalBytes")
        );
        assert_eq!(
            budget.received(),
            body.len(),
            "the refused charge is not made"
        );
    }

    #[tokio::test]
    async fn a_configured_output_bound_refuses_both_paths_at_the_parse_775() {
        const BINARY: &str = "application/octet-stream";
        let two = options(|o| o.max_outputs = 2);
        let item = json!({ "beef": [1], "outputIndex": 0 });
        let json_of = |count| {
            let body = json!({ "type": "output-list", "outputs": vec![item.clone(); count] });
            host_answering("application/json", body.to_string().into_bytes())
        };
        let beef = binary_beef();
        let binary_of = |count| host_answering(BINARY, binary_body(count, &beef));
        for (over, at) in [(json_of(3), json_of(2)), (binary_of(3), binary_of(2))] {
            assert_eq!(bounded(&over, &two).await.unwrap_err(), limit("maxOutputs"));
            let answer = bounded(&at, &two).await.unwrap();
            assert!(
                matches!(&answer, LookupAnswer::OutputList { outputs } if outputs.len() == 2),
                "{answer:?}"
            );
        }
        // A count the body does not hold is the limit before any outpoint
        // is read.
        let host = host_answering(BINARY, vec![0xfd, 0x01, 0x10]);
        assert_eq!(
            bounded(&host, &LookupRequestOptions::default())
                .await
                .unwrap_err(),
            limit("maxOutputs")
        );
    }

    #[tokio::test]
    async fn the_binary_outputs_bytes_are_bounded_before_each_copy_775() {
        // Three outpoints of one transaction: each output carries its Atomic
        // BEEF (#735's fold), so the outputs' bytes are three times its
        // length, counted per outpoint as `extractedBytes` counts them
        // (`LookupResolver.ts:929-932`), never the whole BEEF per outpoint.
        // One byte under, the body is read and the third output refused; at
        // the total, all three are built.
        let beef = binary_beef();
        let total = 3 * beef.atomic_len;
        let host = host_answering("application/octet-stream", binary_body(3, &beef));
        let under = options(|o| o.max_response_bytes = total - 1);
        assert_eq!(
            bounded(&host, &under).await.unwrap_err(),
            limit("maxResponseBytes")
        );
        let at = options(|o| o.max_response_bytes = total);
        let answer = bounded(&host, &at).await.unwrap();
        assert!(
            matches!(&answer, LookupAnswer::OutputList { outputs }
                if outputs.len() == 3 && outputs.iter().all(|o| o.beef.len() == beef.atomic_len
                    && o.txid.as_deref() == Some(beef.txid.as_str()))),
            "{answer:?}"
        );
    }

    /// A resolver over the HTTPS facilitator (plain HTTP allowed) asking
    /// `hosts` for `service` under `limits`.
    fn resolver_over(
        service: &str,
        hosts: &[String],
        limits: bsv_rs::overlay::LookupLimits,
    ) -> bsv_rs::overlay::LookupResolver {
        let hosts: Vec<&str> = hosts.iter().map(String::as_str).collect();
        bsv_rs::overlay::LookupResolver::new(bsv_rs::overlay::LookupResolverConfig {
            facilitator: Some(std::sync::Arc::new(HttpsOverlayLookupFacilitator::new(
                true,
            ))),
            ..super::overriding(service, &hosts, limits)
        })
    }

    async fn outputs_of(resolver: &bsv_rs::overlay::LookupResolver, service: &str) -> usize {
        match resolver
            .query(&LookupQuestion::new(service, json!({})), Some(3000))
            .await
            .unwrap()
        {
            LookupAnswer::OutputList { outputs } => outputs.len(),
            other => panic!("{other:?}"),
        }
    }

    /// An answer past what the query may still retain is dropped after its
    /// host's success (`retainLookupHostAnswer`, `LookupResolver.ts:1734-1743`):
    /// two hosts, each a binary answer of three outpoints of a transaction of
    /// its own, retain three Atomic BEEFs each, more than their bodies, which
    /// alone are charged to the budget as read. A total one byte under both
    /// answers' retained bytes keeps one host's three outputs; at both, all
    /// six. The strength read's S2 (PR #801): the drop deleted, or its `>`
    /// made `>=`, passed every test; RED on a scratch copy of `c137649f` so
    /// planted (`left: 6`, `right: 3`; `left: 3`, `right: 6`).
    #[tokio::test]
    async fn an_answer_past_what_the_query_may_retain_is_dropped_775() {
        let one = binary_beef_spending(&"21".repeat(32));
        let two = binary_beef_spending(&"22".repeat(32));
        let (body_one, body_two) = (binary_body(3, &one), binary_body(3, &two));
        let retained = 3 * one.atomic_len + 3 * two.atomic_len;
        assert!(body_one.len() + body_two.len() < retained - 1);
        let hosts = vec![
            host_answering("application/octet-stream", body_one),
            host_answering("application/octet-stream", body_two),
        ];
        let under = super::limits(|l| l.max_total_bytes = retained - 1);
        let service = "ls_limits_retained_under";
        assert_eq!(
            outputs_of(&resolver_over(service, &hosts, under), service).await,
            3
        );
        let at = super::limits(|l| l.max_total_bytes = retained);
        let service = "ls_limits_retained_at";
        assert_eq!(
            outputs_of(&resolver_over(service, &hosts, at), service).await,
            6
        );
    }

    /// The HTTPS facilitator charges the body as it reads it, so the
    /// resolver's check charges the retained bytes only when the facilitator
    /// charged none (`assertTrackedOutputBudget`, `LookupResolver.ts:2366-2375`):
    /// one host's binary answer under a total one byte short of its body and
    /// its retained bytes together is read whole. The strength read's S3
    /// (PR #801): the guard made to charge always passed every test; RED on
    /// a scratch copy of `c137649f` so planted (`left: 0`, `right: 3`).
    #[tokio::test]
    async fn a_body_the_facilitator_charged_is_not_charged_again_775() {
        let beef = binary_beef_spending(&"23".repeat(32));
        let body = binary_body(3, &beef);
        let total = body.len() + 3 * beef.atomic_len - 1;
        let hosts = vec![host_answering("application/octet-stream", body)];
        let service = "ls_limits_charged_once";
        let limits = super::limits(|l| l.max_total_bytes = total);
        assert_eq!(
            outputs_of(&resolver_over(service, &hosts, limits), service).await,
            3
        );
    }
}
