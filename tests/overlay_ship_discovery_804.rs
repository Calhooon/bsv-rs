//! #804: the SHIP discovery admits a host as the reference's
//! `#fetchInterestedHosts` admits it, and the constructor takes the
//! specific-host keys as its snapshot takes them (`ts-stack@edf6e03`
//! `packages/sdk/src/overlay-tools/SHIPBroadcaster.ts`):
//!
//! ```text
//! 737:    if (!isPlainRecord(answer) || answer.type !== 'output-list' ||
//!           !Array.isArray(answer.outputs) || answer.outputs.length > MAX_SHIP_ADVERTISEMENTS) {
//! 743:      throw new Error('SHIP answer is not a bounded output list.')
//! 752:        if (!isExactByteArray(output.beef) || output.beef.length === 0 ||
//! 755:          output.beef.length > MAX_SHIP_ADVERTISEMENT_BEEF_BYTES || ...
//! 761:          (output.txid !== undefined && (typeof output.txid !== 'string' ||
//! 762:            !/^[0-9a-fA-F]{64}$/.test(output.txid)))) { continue }
//! 765:        totalBeefBytes += output.beef.length
//! 766:        if (totalBeefBytes > MAX_SHIP_TOTAL_ADVERTISEMENT_BEEF_BYTES) {
//! 767:          throw new Error('SHIP advertisement answer exceeds its total BEEF byte budget.')
//! 771:        if (output.txid !== undefined && output.txid.toLowerCase() !== txid) continue
//! 773:        if (selectedOutput == null || selectedOutput.satoshis !== 1) continue
//! 779:        const host = shipEndpoint(parsed.domain, false).origin
//! 782:        if (Object.keys(results).length >= MAX_SHIP_HOSTS) break
//! 783:      } catch {
//! ```
//!
//! The throw at `:767` is inside the loop's `try` and swallowed at `:783`:
//! the crossing output is skipped and, the total staying over, every later
//! one; the discovery returns the hosts admitted before. The reference's
//! verdicts are recorded in `vectors/ship_discovery_admission_804.json` by
//! `support/ship_discovery_admission_804.mjs` (its own `TopicBroadcaster`
//! on a stub resolver and a recording facilitator, Node v22.18.0). Here the
//! answer travels through a real `LookupResolver` (the `ls_ship` host an
//! `.invalid` override, a scripted facilitator), which drops an output whose
//! BEEF does not parse: a padding output is therefore a parseable BEEF of
//! the recorded length, where the reference served zero bytes. Nothing is
//! dialled.
#![cfg(feature = "overlay")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::overlay::{
    create_signed_overlay_admin_token, AdmittanceInstructions, LookupAnswer, LookupLimits,
    LookupQuestion, LookupResolver, LookupResolverConfig, OutputListItem,
    OverlayBroadcastFacilitator, OverlayLookupFacilitator, Protocol, RequireAck, Steak, TaggedBEEF,
    TopicBroadcaster, TopicBroadcasterConfig,
};
use bsv_rs::primitives::PrivateKey;
use bsv_rs::script::LockingScript;
use bsv_rs::transaction::{
    Beef, MerklePath, MerklePathLeaf, Transaction, TransactionInput, TransactionOutput,
};
use bsv_rs::Error;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

const TOPIC: &str = "tm_ship_discovery";
const MIB: usize = 1024 * 1024;

/// A lookup facilitator answering every question with its one answer.
struct Scripted(LookupAnswer);

#[async_trait::async_trait(?Send)]
impl OverlayLookupFacilitator for Scripted {
    async fn lookup(
        &self,
        _url: &str,
        _question: &LookupQuestion,
        _timeout_ms: Option<u64>,
    ) -> bsv_rs::Result<LookupAnswer> {
        Ok(self.0.clone())
    }
}

/// A broadcast facilitator acknowledging every topic it is sent.
struct Acknowledging;

#[async_trait::async_trait(?Send)]
impl OverlayBroadcastFacilitator for Acknowledging {
    async fn send(&self, _url: &str, tagged: &TaggedBEEF) -> bsv_rs::Result<Steak> {
        Ok(tagged
            .topics
            .iter()
            .map(|t| {
                (
                    t.clone(),
                    AdmittanceInstructions {
                        outputs_to_admit: vec![0],
                        coins_to_retain: vec![],
                        coins_removed: None,
                    },
                )
            })
            .collect())
    }
}

/// The resolver's limits these tests run under: the reference's defaults
/// with `maxResponseBytes` and `maxTotalBytes` raised to 128 MiB. The
/// reference's resolver refuses a custom facilitator's answer past 32 MiB
/// (`assertTrackedOutputBudget`, `LookupResolver.ts:2351-2362`; #775 here),
/// so the SHIP bounds past it (`:765-767`) are reached only past the
/// resolver's; the recording ran on a stub resolver, which has none.
/// `the_resolvers_default_limits_take_an_answer_past_32_mib_first_775_804`
/// pins the default.
fn raised_limits() -> LookupLimits {
    let mut limits = LookupLimits::default();
    limits.max_response_bytes = 128 * MIB;
    limits.max_total_bytes = 128 * MIB;
    limits
}

/// A resolver whose `ls_ship` host (one of its own: the reputation tracker
/// is one global keyed by URL) answers `answer`, under `raised_limits`.
fn resolver(answer: LookupAnswer) -> Arc<LookupResolver> {
    resolver_under(answer, raised_limits())
}

/// `resolver` under the resolver limits `limits`.
fn resolver_under(answer: LookupAnswer, limits: LookupLimits) -> Arc<LookupResolver> {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    Arc::new(LookupResolver::new(LookupResolverConfig {
        facilitator: Some(Arc::new(Scripted(answer))),
        slap_trackers: Some(vec![]),
        host_overrides: Some(HashMap::from([(
            "ls_ship".to_string(),
            vec![format!("https://ls-ship-{n}.ship-discovery-804-rs.invalid")],
        )])),
        limits,
        ..Default::default()
    }))
}

fn broadcaster(
    answer: LookupAnswer,
    specific: HashMap<String, RequireAck>,
) -> bsv_rs::Result<TopicBroadcaster> {
    TopicBroadcaster::new(
        vec![TOPIC.to_string()],
        TopicBroadcasterConfig {
            resolver: Some(resolver(answer)),
            facilitator: Some(Arc::new(Acknowledging)),
            require_ack_from_any_host: RequireAck::Any,
            require_ack_from_specific_hosts: specific,
            ..Default::default()
        },
    )
}

/// The hosts the discovery admits from `outputs`, sorted, or its refusal.
async fn admitted(outputs: Vec<OutputListItem>) -> bsv_rs::Result<Vec<String>> {
    let b = broadcaster(LookupAnswer::OutputList { outputs }, HashMap::new()).unwrap();
    let mut hosts: Vec<String> = b.find_interested_hosts().await?.into_keys().collect();
    hosts.sort();
    Ok(hosts)
}

/// A transaction of one made-up input (`seed` its source index) carrying
/// `output`, proven by a block of its own (a lone leaf at offset 0), as a
/// lookup output at index 0 without a hint; and its txid.
fn proven(seed: u32, output: TransactionOutput) -> (String, OutputListItem) {
    let mut tx = Transaction::new();
    tx.add_input(TransactionInput::new("11".repeat(32), seed))
        .unwrap();
    tx.add_output(output).unwrap();
    let txid = tx.id();
    let mut beef = Beef::new();
    let index = beef.merge_bump(
        MerklePath::new(900, vec![vec![MerklePathLeaf::new_txid(0, txid.clone())]]).unwrap(),
    );
    beef.merge_raw_tx(tx.to_binary(), Some(index));
    (
        txid,
        OutputListItem {
            beef: beef.to_binary(),
            output_index: 0,
            context: None,
            txid: None,
        },
    )
}

/// A SHIP advertisement of `domain` by this crate's writer at `satoshis`.
fn advertisement(domain: &str, satoshis: u64, seed: u32) -> (String, OutputListItem) {
    let script =
        create_signed_overlay_admin_token(&PrivateKey::random(), Protocol::Ship, domain, TOPIC);
    proven(seed, TransactionOutput::new(satoshis, script))
}

fn host(name: &str) -> String {
    format!("https://{name}.ship-discovery-804.invalid")
}

fn ad(name: &str) -> OutputListItem {
    advertisement(&host(name), 1, 0).1
}

/// A parseable BEEF of exactly `bytes` bytes, no advertisement: one
/// `OP_FALSE OP_RETURN` output whose data fills the length.
fn padding(bytes: usize, seed: u32) -> OutputListItem {
    let build = |data: usize| {
        let mut script = vec![0x00, 0x6a, 0x4e];
        script.extend_from_slice(&(data as u32).to_le_bytes());
        script.resize(script.len() + data, 0x5a);
        proven(
            seed,
            TransactionOutput::new(0, LockingScript::from_binary(&script).unwrap()),
        )
        .1
    };
    let guess = bytes - 256;
    let overhead = build(guess).beef.len() - guess;
    let output = build(bytes - overhead);
    assert_eq!(output.beef.len(), bytes);
    output
}

/// Four BEEFs of 16 MiB and one of 16 MiB plus 1, built once.
fn paddings() -> &'static (Vec<OutputListItem>, OutputListItem) {
    static P: OnceLock<(Vec<OutputListItem>, OutputListItem)> = OnceLock::new();
    P.get_or_init(|| {
        (
            (0..4).map(|seed| padding(16 * MIB, seed)).collect(),
            padding(16 * MIB + 1, 4),
        )
    })
}

/// 257 advertisements of one host, distinct transactions, built once.
fn plain() -> &'static Vec<OutputListItem> {
    static P: OnceLock<Vec<OutputListItem>> = OnceLock::new();
    P.get_or_init(|| {
        (0..257)
            .map(|seed| advertisement(&host("plain"), 1, seed).1)
            .collect()
    })
}

fn refusal(words: &str) -> bsv_rs::Result<Vec<String>> {
    Err(Error::OverlayError(words.to_string()))
}

const NOT_BOUNDED: &str = "SHIP answer is not a bounded output list.";

#[tokio::test]
async fn a_ship_advertisement_of_zero_satoshis_admits_no_host_804() {
    let (_, output) = advertisement(&host("zero"), 0, 0);
    assert_eq!(admitted(vec![output]).await, Ok(vec![]));
}

#[tokio::test]
async fn a_ship_advertisement_of_two_satoshis_admits_no_host_804() {
    let (_, output) = advertisement(&host("two"), 2, 0);
    assert_eq!(admitted(vec![output]).await, Ok(vec![]));
}

#[tokio::test]
async fn a_ship_advertisement_whose_txid_hint_disagrees_admits_no_host_804() {
    let (_, mut output) = advertisement(&host("disagreeing"), 1, 0);
    output.txid = Some("ab".repeat(32));
    assert_eq!(admitted(vec![output]).await, Ok(vec![]));
}

#[tokio::test]
async fn a_txid_hint_in_upper_case_that_agrees_admits_the_host_804() {
    let (txid, mut output) = advertisement(&host("upper"), 1, 0);
    output.txid = Some(txid.to_ascii_uppercase());
    assert_eq!(admitted(vec![output]).await, Ok(vec![host("upper")]));
}

#[tokio::test]
async fn a_txid_hint_of_63_digits_or_not_hex_admits_no_host_804() {
    let (txid, output) = advertisement(&host("short"), 1, 0);
    for hint in [txid[..63].to_string(), format!("zz{}", &txid[2..])] {
        let mut output = output.clone();
        output.txid = Some(hint.clone());
        assert_eq!(admitted(vec![output]).await, Ok(vec![]), "{hint}");
    }
}

#[tokio::test]
async fn an_advertised_domain_is_admitted_as_its_origin_804() {
    let (_, output) = advertisement("https://Host.ship-discovery-804.invalid:443/", 1, 0);
    assert_eq!(admitted(vec![output]).await, Ok(vec![host("host")]));
}

#[tokio::test]
async fn an_advertisement_that_is_no_https_origin_admits_no_host_804() {
    for domain in [
        "https+bsvauth://bsvauth.ship-discovery-804.invalid/",
        "wss://wss.ship-discovery-804.invalid",
        "https://query.ship-discovery-804.invalid/?x=1",
    ] {
        let (_, output) = advertisement(domain, 1, 0);
        assert_eq!(admitted(vec![output]).await, Ok(vec![]), "{domain}");
    }
}

#[tokio::test]
async fn thirty_three_hosts_admit_the_leading_thirty_two_804() {
    let names: Vec<String> = (0..33).map(|i| format!("many-{i:02}")).collect();
    let outputs = names.iter().map(|n| ad(n)).collect();
    let expected: Vec<String> = names[..32].iter().map(|n| host(n)).collect();
    assert_eq!(admitted(outputs).await, Ok(expected));
}

#[tokio::test]
async fn two_hundred_fifty_seven_outputs_refuse_the_discovery_804() {
    assert_eq!(admitted(plain().clone()).await, refusal(NOT_BOUNDED));
    // 256 are a bounded list.
    assert_eq!(
        admitted(plain()[..256].to_vec()).await,
        Ok(vec![host("plain")])
    );
}

/// Since #815 a freeform `ls_ship` host is no refusal: `LookupResolver::query`
/// answers the empty output list, as the reference's resolver does
/// (`LookupResolver.ts:1445-1450`), and no host is admitted. The reader's
/// refusal of an answer that is no output list (the recording's
/// `not_output_list`, the reference's stub resolver handing it the answer)
/// is pinned below the resolver, `topic_broadcaster/discovery.rs`'s
/// `a_freeform_answer_handed_to_the_reader_is_refused_815`.
#[tokio::test]
async fn a_freeform_ls_ship_host_admits_no_host_and_refuses_nothing_815() {
    let b = broadcaster(
        LookupAnswer::Freeform {
            result: serde_json::json!({}),
        },
        HashMap::new(),
    )
    .unwrap();
    assert_eq!(b.find_interested_hosts().await.map(|h| h.len()), Ok(0));
}

/// A lookup facilitator answering each `ls_ship` host with its own answer.
struct ByHost(HashMap<String, LookupAnswer>);

#[async_trait::async_trait(?Send)]
impl OverlayLookupFacilitator for ByHost {
    async fn lookup(
        &self,
        url: &str,
        _question: &LookupQuestion,
        _timeout_ms: Option<u64>,
    ) -> bsv_rs::Result<LookupAnswer> {
        Ok(self.0[url].clone())
    }
}

/// #815: one `ls_ship` host answering freeform no longer blanks the SHIP
/// discovery: the host another `ls_ship` host advertises is admitted, in
/// either rank order. Until #815 the resolver answered the freeform answer
/// and the discovery refused in `SHIP answer is not a bounded output list.`
#[tokio::test]
async fn a_freeform_ls_ship_host_beside_an_advertising_one_admits_the_advertised_host_815() {
    static N: AtomicUsize = AtomicUsize::new(0);
    for freeform_ahead in [true, false] {
        let n = N.fetch_add(1, Ordering::Relaxed);
        let free = format!("https://free-{n}.ship-discovery-815-rs.invalid");
        let list = format!("https://list-{n}.ship-discovery-815-rs.invalid");
        let answers = HashMap::from([
            (
                free.clone(),
                LookupAnswer::Freeform {
                    result: serde_json::json!({}),
                },
            ),
            (
                list.clone(),
                LookupAnswer::OutputList {
                    outputs: vec![ad("advertised")],
                },
            ),
        ]);
        let hosts = if freeform_ahead {
            vec![free, list]
        } else {
            vec![list, free]
        };
        let resolver = Arc::new(LookupResolver::new(LookupResolverConfig {
            facilitator: Some(Arc::new(ByHost(answers))),
            slap_trackers: Some(vec![]),
            host_overrides: Some(HashMap::from([("ls_ship".to_string(), hosts)])),
            limits: raised_limits(),
            ..Default::default()
        }));
        let b = TopicBroadcaster::new(
            vec![TOPIC.to_string()],
            TopicBroadcasterConfig {
                resolver: Some(resolver),
                facilitator: Some(Arc::new(Acknowledging)),
                ..Default::default()
            },
        )
        .unwrap();
        let admitted: Vec<String> = b
            .find_interested_hosts()
            .await
            .unwrap()
            .into_keys()
            .collect();
        assert_eq!(
            admitted,
            vec![host("advertised")],
            "freeform ahead: {freeform_ahead}"
        );
    }
}

#[tokio::test]
async fn four_outputs_of_16_mib_then_an_advertisement_skip_it_804() {
    let (sixteen, _) = paddings();
    let mut outputs = vec![ad("before")];
    outputs.extend(sixteen.iter().cloned());
    outputs.push(ad("after"));
    assert_eq!(admitted(outputs).await, Ok(vec![host("before")]));
}

/// At the resolver's default limits the answer of four 16 MiB outputs
/// passes `maxResponseBytes` (32 MiB) and the resolver drops it, neutral for
/// the host, before the SHIP discovery reads it: no host is admitted, as the
/// reference's `TopicBroadcaster` on its own `LookupResolver` admits none
/// (`LookupResolver.ts:2351-2362`, `:2415`; #775 beside #804).
#[tokio::test]
async fn the_resolvers_default_limits_take_an_answer_past_32_mib_first_775_804() {
    let (sixteen, _) = paddings();
    let mut outputs = vec![ad("before")];
    outputs.extend(sixteen.iter().cloned());
    let b = TopicBroadcaster::new(
        vec![TOPIC.to_string()],
        TopicBroadcasterConfig {
            resolver: Some(resolver_under(
                LookupAnswer::OutputList { outputs },
                LookupLimits::default(),
            )),
            facilitator: Some(Arc::new(Acknowledging)),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(b.find_interested_hosts().await.map(|h| h.len()), Ok(0));
}

#[tokio::test]
async fn an_output_of_16_mib_plus_1_is_skipped_before_it_counts_804() {
    let (sixteen, over) = paddings();
    let mut outputs = vec![over.clone()];
    outputs.extend(sixteen[..3].iter().cloned());
    outputs.push(ad("after"));
    assert_eq!(admitted(outputs).await, Ok(vec![host("after")]));
}

/// `broadcast_tx` of a proven transaction under the specific-host keys
/// `keys` (each `RequireAck::All`), the discovery admitting `host("host")`.
async fn broadcast_under(keys: &[&str]) -> bsv_rs::Result<Result<(), String>> {
    let (_, output) = advertisement(&host("host"), 1, 0);
    let subject = Transaction::from_beef(&ad("subject").beef, None).unwrap();
    let specific = keys
        .iter()
        .map(|k| (k.to_string(), RequireAck::All))
        .collect();
    let b = broadcaster(
        LookupAnswer::OutputList {
            outputs: vec![output],
        },
        specific,
    )?;
    Ok(b.broadcast_tx(&subject)
        .await
        .map(|_| ())
        .map_err(|f| f.code))
}

#[tokio::test]
async fn a_specific_host_key_matches_its_discovered_origin_804() {
    for key in [
        "https://host.ship-discovery-804.invalid/",
        "https://HOST.ship-discovery-804.invalid:443",
    ] {
        assert_eq!(broadcast_under(&[key]).await, Ok(Ok(())), "{key}");
    }
    assert_eq!(
        broadcast_under(&["https://other.ship-discovery-804.invalid"]).await,
        Ok(Err("ERR_REQUIRE_ACK_FROM_SPECIFIC_HOSTS_FAILED".into()))
    );
}

#[tokio::test]
async fn thirty_three_specific_host_keys_or_two_of_one_origin_refuse_new_804() {
    let keys: Vec<String> = (0..33).map(|i| host(&format!("key-{i}"))).collect();
    let keys: Vec<&str> = keys.iter().map(String::as_str).collect();
    assert_eq!(
        broadcast_under(&keys).await,
        Err(Error::OverlayError(
            "Specific-host acknowledgment requirements contain too many hosts.".into()
        ))
    );
    assert_eq!(
        broadcast_under(&[
            "https://host.ship-discovery-804.invalid/",
            "https://HOST.ship-discovery-804.invalid:443",
        ])
        .await,
        Err(Error::OverlayError(
            "Specific-host acknowledgment requirements contain a duplicate host.".into()
        ))
    );
}

/// A recorded output: an advertisement's bytes and hint, or a padding of
/// the recorded length (zero bytes there, a parseable BEEF here).
fn recorded_output(v: &Value) -> OutputListItem {
    if let Some(bytes) = v["padding"].as_u64() {
        assert_eq!(
            bytes as usize,
            16 * MIB + 1,
            "a 16 MiB padding is `recorded_outputs`'"
        );
        return paddings().1.clone();
    }
    let beef = hex::decode(v["beef"].as_str().unwrap()).unwrap();
    let tx = Transaction::from_beef(&beef, None).unwrap();
    assert_eq!(tx.id(), v["txid"].as_str().unwrap());
    assert_eq!(tx.outputs[0].satoshis, v["satoshis"].as_u64());
    OutputListItem {
        beef,
        output_index: v["output_index"].as_u64().unwrap() as u32,
        context: None,
        txid: v["hint"].as_str().map(str::to_string),
    }
}

/// The recorded outputs, the four 16 MiB paddings of one answer each a
/// distinct transaction here (the resolver keeps one per txid and index).
fn recorded_outputs(case: &Value) -> Vec<OutputListItem> {
    let (sixteen, _) = paddings();
    let mut next = 0;
    case["outputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| {
            if o["padding"].as_u64() == Some(16 * MIB as u64) {
                next += 1;
                sixteen[next - 1].clone()
            } else {
                recorded_output(o)
            }
        })
        .collect()
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|h| h.as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn the_reference_recorded_ship_admissions_are_this_crates_804() {
    let recorded: Value =
        serde_json::from_str(include_str!("vectors/ship_discovery_admission_804.json")).unwrap();
    assert_eq!(recorded["topic"], TOPIC);
    let cases = recorded["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 17);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        if name == "not_output_list" {
            // The reference's stub resolver handed the reader a freeform
            // answer; this crate's resolver answers an output list in every
            // case since #815, so the discovery admits nothing and refuses
            // nothing here (the reader's refusal pinned in
            // `topic_broadcaster/discovery.rs`, `_815`).
            assert_eq!(case["refusal"], NOT_BOUNDED);
            let b = broadcaster(
                LookupAnswer::Freeform {
                    result: case["answer"]["result"].clone(),
                },
                HashMap::new(),
            )
            .unwrap();
            assert_eq!(b.find_interested_hosts().await.map(|h| h.len()), Ok(0));
            continue;
        }
        let ours = if let Some(count) = case["output_count"].as_u64() {
            admitted(plain()[..count as usize].to_vec()).await
        } else {
            admitted(recorded_outputs(case)).await
        };
        let theirs = match case["refusal"].as_str() {
            Some(words) => refusal(words),
            None => Ok(strings(&case["hosts"])),
        };
        assert_eq!(ours, theirs, "{name}");
    }
    // The constructor's keys: refused in the reference's words, or the
    // broadcast's verdict under them, the failure code the reference's
    // (`ERR_REQUIRE_ACK_FROM_SPECIFIC_HOSTS_FAILED` since lane fix-tb-acks).
    let specific = recorded["specific"].as_array().unwrap();
    assert_eq!(specific.len(), 8);
    for case in specific {
        let name = case["name"].as_str().unwrap();
        let keys = strings(&case["keys"]);
        let keys: Vec<&str> = keys.iter().map(String::as_str).collect();
        let ours = broadcast_under(&keys).await;
        match case["constructor_refusal"].as_str() {
            Some(words) => assert_eq!(ours, Err(Error::OverlayError(words.into())), "{name}"),
            None => {
                assert_eq!(strings(&case["hosts"]), [host("host")], "{name}");
                let theirs = match case["code"].as_str() {
                    Some(code) => Err(code.to_string()),
                    None => Ok(()),
                };
                assert_eq!(ours, Ok(theirs), "{name}");
            }
        }
    }
}
