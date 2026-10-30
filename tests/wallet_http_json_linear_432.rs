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

#[tokio::test]
async fn nested_result_snapshot_scales_with_body_size_on_success_and_error() {
    let server = MockServer::start().await;
    let wallet = HttpWalletJson::new(Some("fixtures.invalid".into()), Some(server.uri())).unwrap();
    let mut failures = Vec::new();
    for status in [200, 400] {
        let mut times = Vec::new();
        for (index, body) in BODIES.iter().enumerate() {
            server.reset().await;
            Mock::given(path("/getVersion"))
                .respond_with(
                    ResponseTemplate::new(status).set_body_raw(body.as_str(), "application/json"),
                )
                .mount(&server)
                .await;
            // Median suppresses a single scheduler pause; no absolute time bound.
            let mut samples = Vec::new();
            for _ in 0..3 {
                let start = Instant::now();
                let result = wallet.get_version(None).await;
                samples.push(start.elapsed().as_secs_f64());
                if status == 200 {
                    assert_eq!(result.unwrap(), "1.0.0.0");
                } else {
                    assert!(result.is_err());
                }
            }
            samples.sort_by(f64::total_cmp);
            times.push(samples[1]);
            println!(
                "status={status} depth={} bytes={} seconds={:.6}",
                2_000 << index,
                body.len(),
                times[index]
            );
        }
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
