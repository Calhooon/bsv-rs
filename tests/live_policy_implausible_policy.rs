//! The fee-policy reader refuses a policy no service could hold, and the
//! fee model refuses a fee that does not fit in a `u64`: an `Err`, the
//! cache left as it was; every policy a service can hold reads as before.
//!
//! Run with: `cargo test --features "full,http" --test live_policy_implausible_policy`

#![cfg(all(feature = "transaction", feature = "http"))]

use bsv_rs::primitives::{sha256, to_hex};
use bsv_rs::script::LockingScript;
use bsv_rs::transaction::{
    FeeModel, LivePolicy, SatoshisPerKilobyte, Transaction, TransactionOutput,
};
use bsv_rs::Error;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const FORMAT: &str = "Invalid policy response format";
const RATE: &str = "Invalid policy fee rate";

/// A server answering every `GET /v1/policy` with `body`.
async fn serving(body: Value) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/policy"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&server)
        .await;
    server
}

/// `refresh` against `body` on a model whose cache holds 500 sat/kB first:
/// the answer, and the rate the model holds after it.
async fn refresh_after_500(body: Value) -> (bsv_rs::Result<u64>, u64) {
    let server = serving(body).await;
    let model = LivePolicy::with_url(&format!("{}/v1/policy", server.uri()));
    model.set_rate(500);
    let answer = model.refresh().await;
    (answer, model.effective_rate())
}

fn refused(words: &str) -> bsv_rs::Result<u64> {
    Err(Error::FeeModelError(words.to_string()))
}

#[tokio::test]
async fn a_policy_outside_the_bounds_at_the_top_level_is_refused_and_the_cache_kept() {
    let (answer, held) = refresh_after_500(json!({"miningFee": {"satoshis": 1, "bytes": 0}})).await;
    assert_eq!(answer, refused(FORMAT));
    assert_eq!(held, 500);
}

#[tokio::test]
async fn a_policy_outside_the_bounds_under_policy_is_refused_and_the_cache_kept() {
    let (answer, held) =
        refresh_after_500(json!({"policy": {"miningFee": {"satoshis": 1, "bytes": 0}}})).await;
    assert_eq!(answer, refused(FORMAT));
    assert_eq!(held, 500);
}

#[tokio::test]
async fn a_policy_naming_more_satoshis_than_there_are_is_refused() {
    let (answer, held) =
        refresh_after_500(json!({"miningFee": {"satoshis": u64::MAX, "bytes": 1000}})).await;
    assert_eq!(answer, refused(FORMAT));
    assert_eq!(held, 500);
    let (answer, _) = refresh_after_500(
        json!({"miningFee": {"satoshis": 2_100_000_000_000_001u64, "bytes": 1_000_000_000}}),
    )
    .await;
    assert_eq!(answer, refused(FORMAT));
}

/// A body naming more than 1,000,000,000 `bytes` read its rate before (a
/// rate of 1000 sat/kB for 2e9 satoshis per 2e9 bytes, 0 for 1 per 1e9+1);
/// it is refused, as the reference refuses it.
#[tokio::test]
async fn a_policy_naming_more_bytes_than_a_policy_holds_is_refused() {
    let (answer, held) =
        refresh_after_500(json!({"miningFee": {"satoshis": 1, "bytes": 1_000_000_001u64}})).await;
    assert_eq!(answer, refused(FORMAT));
    assert_eq!(held, 500);
    let (answer, held) = refresh_after_500(
        json!({"miningFee": {"satoshis": 2_000_000_000u64, "bytes": 2_000_000_000u64}}),
    )
    .await;
    assert_eq!(answer, refused(FORMAT));
    assert_eq!(held, 500);
}

/// A rate above the ceiling by less than one satoshi per kilobyte is judged
/// before it is floored: refused, not read as the ceiling.
#[tokio::test]
async fn a_policy_rate_a_fraction_above_the_ceiling_is_refused_before_the_floor() {
    let (answer, held) =
        refresh_after_500(json!({"miningFee": {"satoshis": 2_000_000_001u64, "bytes": 2000}}))
            .await;
    assert_eq!(answer, refused(RATE));
    assert_eq!(held, 500);
    // exactly the ceiling, over a size that does not divide it evenly
    let (answer, _) =
        refresh_after_500(json!({"miningFee": {"satoshis": 2_000_000_000u64, "bytes": 2000}}))
            .await;
    assert_eq!(answer, Ok(1_000_000_000));
}

/// Every satoshi there is (21 million BSV) is a `satoshis` a policy may
/// name: over 1,000,000,000 bytes it is a rate above the ceiling, not a
/// body out of format.
#[tokio::test]
async fn a_policy_naming_every_satoshi_there_is_is_judged_by_its_rate() {
    let (answer, held) = refresh_after_500(
        json!({"miningFee": {"satoshis": 2_100_000_000_000_000u64, "bytes": 1_000_000_000u64}}),
    )
    .await;
    assert_eq!(answer, refused(RATE));
    assert_eq!(held, 500);
}

#[tokio::test]
async fn a_policy_rate_above_the_ceiling_is_refused_and_a_later_fee_uses_the_cache() {
    let server =
        serving(json!({"miningFee": {"satoshis": 2_000_000_000_000_000u64, "bytes": 1}})).await;
    let model = LivePolicy::with_url(&format!("{}/v1/policy", server.uri()));
    model.set_rate(500);
    assert_eq!(model.refresh().await, refused(RATE));
    assert_eq!(model.effective_rate(), 500);
    // the empty transaction is 10 bytes: 10 * 500 / 1000 = 5
    assert_eq!(model.compute_fee(&Transaction::new()), Ok(5));
    // one past the ceiling, and the ceiling itself
    let (answer, _) =
        refresh_after_500(json!({"miningFee": {"satoshis": 1_000_001, "bytes": 1}})).await;
    assert_eq!(answer, refused(RATE));
    let (answer, held) =
        refresh_after_500(json!({"miningFee": {"satoshis": 1_000_000, "bytes": 1}})).await;
    assert_eq!(answer, Ok(1_000_000_000));
    assert_eq!(held, 1_000_000_000);
}

#[test]
fn a_fee_that_does_not_fit_in_a_u64_is_refused_by_the_fee_model() {
    let tx = Transaction::new();
    let answer = SatoshisPerKilobyte::new(u64::MAX).compute_fee(&tx);
    assert!(
        matches!(answer, Err(Error::FeeModelError(ref m)) if m.starts_with("fee out of range")),
        "{answer:?}"
    );
    let model = LivePolicy::default();
    model.set_rate(u64::MAX);
    assert!(matches!(
        model.compute_fee(&tx),
        Err(Error::FeeModelError(_))
    ));
    // the largest rate whose fee for 10 bytes fits
    assert_eq!(
        SatoshisPerKilobyte::new(u64::MAX / 10).compute_fee(&tx),
        Ok(u64::MAX / 10 * 10 / 1000)
    );
}

#[tokio::test]
async fn the_policies_a_service_holds_read_as_before() {
    for (body, rate) in [
        (json!({"miningFee": {"satoshis": 1, "bytes": 1}}), 1000),
        (json!({"miningFee": {"satoshis": 1, "bytes": 1000}}), 1),
        (
            json!({"policy": {"miningFee": {"satoshis": 50, "bytes": 1000}}}),
            50,
        ),
        (json!({"miningFee": {"satoshis": 1}}), 1000),
        (json!({"miningFee": {"bytes": 1000}}), 1),
        (json!({"miningFee": {"satoshis": 0, "bytes": 1000}}), 0),
        (json!({"miningFee": {"satoshis": 1, "bytes": 2000}}), 0),
        (
            json!({"miningFee": {"satoshis": 1, "bytes": 1_000_000_000u64}}),
            0,
        ),
    ] {
        let (answer, held) = refresh_after_500(body.clone()).await;
        assert_eq!(answer, Ok(rate), "{body}");
        assert_eq!(held, rate, "{body}");
    }
}

/// A deterministic xorshift, so the differential's digest is one constant.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// The `i`th honest policy body: a fee a service can set (0 to 1,000
/// satoshis per 1 to 100,000 bytes), at either location, a member absent
/// now and then.
fn honest_body(i: u64) -> Value {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15 ^ (i + 1).wrapping_mul(0x2545_f491_4f6c_dd1d));
    let mut fee = serde_json::Map::new();
    if rng.below(20) != 0 {
        fee.insert("satoshis".into(), json!(rng.below(1001)));
    }
    if rng.below(20) != 0 {
        fee.insert("bytes".into(), json!(1 + rng.below(100_000)));
    }
    let fee = Value::Object(fee);
    if rng.below(2) == 0 {
        json!({"miningFee": fee})
    } else {
        json!({"policy": {"miningFee": fee}})
    }
}

/// Answers the `n`th `GET /v1/policy` with the `n`th honest body.
struct HonestPolicies(AtomicU64);
impl Respond for HonestPolicies {
    fn respond(&self, _: &Request) -> ResponseTemplate {
        let i = self.0.fetch_add(1, Ordering::SeqCst);
        ResponseTemplate::new(200).set_body_json(honest_body(i))
    }
}

/// The differential: 20,000 honest policies through `refresh` (one model,
/// so one pooled connection), and 20,000 honest rates through the fee model
/// on transactions of random size; the answers' digest equals the one the
/// code before this change gives.
#[tokio::test]
async fn twenty_thousand_honest_policies_and_fees_answer_as_before() {
    const N: u64 = 20_000;
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/policy"))
        .respond_with(HonestPolicies(AtomicU64::new(0)))
        .mount(&server)
        .await;
    let model = LivePolicy::with_url(&format!("{}/v1/policy", server.uri()));
    let mut transcript = String::new();
    for i in 0..N {
        let answer = model.refresh().await;
        transcript.push_str(&format!("{i}:{answer:?};"));
    }
    let mut rng = Rng(0x0123_4567_89ab_cdef);
    for i in 0..N {
        let mut tx = Transaction::new();
        for _ in 0..rng.below(4) {
            let script = vec![0x51u8; rng.below(300) as usize];
            tx.add_output(TransactionOutput::new(
                1,
                LockingScript::from_binary(&script).unwrap(),
            ))
            .unwrap();
        }
        let rate = rng.below(1_000_001);
        let answer = SatoshisPerKilobyte::new(rate).compute_fee(&tx);
        transcript.push_str(&format!("f{i}:{answer:?};"));
    }
    assert_eq!(
        to_hex(&sha256(transcript.as_bytes())),
        "62d87256d5d4da3fc2de8694a391a89f274954862415d01c57a987183552f914",
        "an honest policy or fee answers otherwise than before"
    );
}
