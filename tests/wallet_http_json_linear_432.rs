//! #432 cold review: the same 4 MiB payload at three depths, on both answer paths.
#![cfg(all(feature = "wallet", feature = "http"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::wallet::substrates::HttpWalletJson;
use std::{sync::LazyLock, time::Instant};
use wiremock::{matchers::path, Mock, MockServer, ResponseTemplate};

// Build each of the review's bodies once, outside every measurement.
static BODIES: LazyLock<Vec<String>> = LazyLock::new(|| {
    [2_000, 4_000, 8_000]
        .into_iter()
        .map(|depth| {
            format!(
                "{{\"version\":\"1.0.0.0\",\"pad\":{}\"{}\"{}}}",
                "[".repeat(depth),
                "x".repeat(4 * 1024 * 1024),
                "]".repeat(depth)
            )
        })
        .collect()
});

#[tokio::test]
async fn code_5_ignores_nonfinite_and_deep_extensions_inside_results() {
    let server = MockServer::start().await;
    let wallet = HttpWalletJson::new(Some("fixtures.invalid".into()), Some(server.uri())).unwrap();
    for extra in [
        "1e400".to_owned(),
        format!("{}0{}", "[".repeat(129), "]".repeat(129)),
    ] {
        server.reset().await;
        let body = format!(
            "{{\"isError\":true,\"code\":5,\"reviewActionResults\":[{{\"pad\":{extra}}}]}}"
        );
        Mock::given(path("/getVersion"))
            .respond_with(ResponseTemplate::new(400).set_body_raw(body, "application/json"))
            .mount(&server)
            .await;
        assert_eq!(
            wallet.get_version(None).await,
            Err(bsv_rs::Error::WalletError(
                "Invalid getVersion wallet error code".into()
            ))
        );
    }
}

#[tokio::test]
async fn raw_fallback_keeps_last_duplicate_fields_with_deep_or_nonfinite_extras() {
    let server = MockServer::start().await;
    let wallet = HttpWalletJson::new(Some("fixtures.invalid".into()), Some(server.uri())).unwrap();
    for extra in [
        "1e400".to_owned(),
        format!("{}0{}", "[".repeat(129), "]".repeat(129)),
    ] {
        server.reset().await;
        let body = format!("{{\"height\":0,\"height\":1.0,\"pad\":{extra}}}");
        Mock::given(path("/getHeight"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(body, "application/json"))
            .mount(&server)
            .await;
        assert_eq!(wallet.get_height(None).await.unwrap(), 1);
    }
}

// Timed rounds per body. The minimum of them is the cost without the host's
// noise: a pause can only add to a sample, never take from it. Seven because a
// median of three failed about one leg in three on the slowest hosted runner
// (a sample disturbed about one time in five); all seven of one body disturbed
// is then about one in 100,000.
const TIMED_ROUNDS: usize = 7;

#[tokio::test]
async fn nested_result_snapshot_scales_with_body_size_on_success_and_error() {
    let mut failures = Vec::new();
    for status in [200, 400] {
        // One server and one wallet per body, so the rounds interleave the
        // three depths: a slow stretch of the host falls on all of them alike.
        let mut doors = Vec::new();
        for body in BODIES.iter() {
            let server = MockServer::start().await;
            Mock::given(path("/getVersion"))
                .respond_with(
                    ResponseTemplate::new(status).set_body_raw(body.as_str(), "application/json"),
                )
                .mount(&server)
                .await;
            let wallet =
                HttpWalletJson::new(Some("fixtures.invalid".into()), Some(server.uri())).unwrap();
            doors.push((server, wallet));
        }
        // The round before the timed ones is the warm-up (the connection, the
        // allocator's pages); its samples are dropped. No absolute time bound.
        let mut times = vec![f64::INFINITY; BODIES.len()];
        for round in 0..=TIMED_ROUNDS {
            for (index, (_server, wallet)) in doors.iter().enumerate() {
                let start = Instant::now();
                let result = wallet.get_version(None).await;
                let elapsed = start.elapsed().as_secs_f64();
                if status == 200 {
                    assert_eq!(result.unwrap(), "1.0.0.0");
                } else {
                    assert!(result.is_err());
                }
                if round > 0 {
                    times[index] = times[index].min(elapsed);
                }
            }
        }
        for (index, body) in BODIES.iter().enumerate() {
            println!(
                "status={status} depth={} bytes={} seconds={:.6}",
                2_000 << index,
                body.len(),
                times[index]
            );
        }
        // A linear walk gives 1.0 at these equal sizes; a walk that reads each
        // subtree again gives the depth ratio, 2.0 and 4.0 (measured 1.990 and
        // 4.032), so the depth 8,000 leg is the one that refuses it.
        for index in 1..times.len() {
            let size_ratio = BODIES[index].len() as f64 / BODIES[0].len() as f64;
            let time_ratio = times[index] / times[0];
            if time_ratio > 2.5 * size_ratio {
                failures.push(format!(
                    "status={status} depth={} / depth=2000: time ratio {time_ratio:.3}, size ratio {size_ratio:.3}; repeated subtree parsing",
                    2_000 << index
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
