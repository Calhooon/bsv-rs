//! HTTP integration tests for LivePolicy fee model.
//!
//! These tests use `wiremock` to spin up a local mock HTTP server and verify that
//! the LivePolicy fee model correctly queries policy endpoints, caches results,
//! and falls back to defaults when the endpoint is unreachable.
//!
//! Run with: `cargo test --features "full,http" --test live_policy_http_tests`

#![cfg(all(feature = "transaction", feature = "http"))]

use bsv_sdk::transaction::{
    FeeModel, LivePolicy, LivePolicyConfig, Transaction, DEFAULT_CACHE_TTL_SECS,
    DEFAULT_FALLBACK_RATE, DEFAULT_POLICY_URL,
};
use std::time::Duration;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// =============================================================================
// LivePolicy HTTP Tests
// =============================================================================

#[tokio::test]
async fn test_live_policy_refresh_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/policy"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "miningFee": {
                "satoshis": 1,
                "bytes": 1000
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let fee_model = LivePolicy::with_url(&format!("{}/v1/policy", mock_server.uri()));
    let rate = fee_model.refresh().await.unwrap();

    // 1 satoshi per 1000 bytes = 1 sat/KB
    assert_eq!(rate, 1);
    assert_eq!(fee_model.cached_rate(), Some(1));
    assert_eq!(fee_model.effective_rate(), 1);
}

#[tokio::test]
async fn test_live_policy_refresh_higher_fee_rate() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/policy"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "miningFee": {
                "satoshis": 50,
                "bytes": 1000
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let fee_model = LivePolicy::with_url(&format!("{}/v1/policy", mock_server.uri()));
    let rate = fee_model.refresh().await.unwrap();

    // 50 satoshis per 1000 bytes = 50 sat/KB
    assert_eq!(rate, 50);
}

#[tokio::test]
async fn test_live_policy_refresh_nested_policy() {
    let mock_server = MockServer::start().await;

    // Some ARC endpoints return fee info nested under "policy"
    Mock::given(method("GET"))
        .and(path("/v1/policy"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "policy": {
                "miningFee": {
                    "satoshis": 5,
                    "bytes": 1000
                }
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let fee_model = LivePolicy::with_url(&format!("{}/v1/policy", mock_server.uri()));
    let rate = fee_model.refresh().await.unwrap();

    assert_eq!(rate, 5);
}

#[tokio::test]
async fn test_live_policy_refresh_with_api_key() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/policy"))
        .and(header("Authorization", "Bearer test-api-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "miningFee": {
                "satoshis": 1,
                "bytes": 1000
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = LivePolicyConfig {
        policy_url: format!("{}/v1/policy", mock_server.uri()),
        api_key: Some("test-api-key".to_string()),
        cache_ttl: Duration::from_secs(DEFAULT_CACHE_TTL_SECS),
        fallback_rate: DEFAULT_FALLBACK_RATE,
        timeout_ms: 10_000,
    };

    let fee_model = LivePolicy::with_config(config);
    let rate = fee_model.refresh().await.unwrap();
    assert_eq!(rate, 1);
}

#[tokio::test]
async fn test_live_policy_refresh_server_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/policy"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let fee_model = LivePolicy::with_url(&format!("{}/v1/policy", mock_server.uri()));
    let result = fee_model.refresh().await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("HTTP 500"));
}

#[tokio::test]
async fn test_live_policy_refresh_not_found() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/policy"))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&mock_server)
        .await;

    let fee_model = LivePolicy::with_url(&format!("{}/v1/policy", mock_server.uri()));
    let result = fee_model.refresh().await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("HTTP 404"));
}

#[tokio::test]
async fn test_live_policy_refresh_malformed_json() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/policy"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not json at all"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let fee_model = LivePolicy::with_url(&format!("{}/v1/policy", mock_server.uri()));
    let result = fee_model.refresh().await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("parse policy"));
}

#[tokio::test]
async fn test_live_policy_refresh_missing_mining_fee() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/policy"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "someOtherField": true
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let fee_model = LivePolicy::with_url(&format!("{}/v1/policy", mock_server.uri()));
    let result = fee_model.refresh().await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("No mining fee"));
}

#[tokio::test]
async fn test_live_policy_fallback_when_not_refreshed() {
    // Without refreshing, the fee model should use the fallback rate
    let fee_model = LivePolicy::new();
    assert_eq!(fee_model.effective_rate(), DEFAULT_FALLBACK_RATE);
    assert!(fee_model.cached_rate().is_none());
}

#[tokio::test]
async fn test_live_policy_compute_fee_after_refresh() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/policy"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "miningFee": {
                "satoshis": 1,
                "bytes": 1
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let fee_model = LivePolicy::with_url(&format!("{}/v1/policy", mock_server.uri()));
    fee_model.refresh().await.unwrap();

    // 1 sat/byte = 1000 sat/KB
    assert_eq!(fee_model.effective_rate(), 1000);

    let tx = Transaction::new();
    let fee = fee_model.compute_fee(&tx).unwrap();
    // Empty transaction: 10 bytes * 1000 sat/KB / 1000 = 10 sats
    assert_eq!(fee, 10);
}

#[tokio::test]
async fn test_live_policy_compute_fee_with_fallback() {
    // Without refreshing, should use fallback rate (100 sat/KB)
    let fee_model = LivePolicy::new();
    let tx = Transaction::new();
    let fee = fee_model.compute_fee(&tx).unwrap();
    // Empty transaction: 10 bytes * 100 sat/KB / 1000 = 1 sat
    assert_eq!(fee, 1);
}

#[tokio::test]
async fn test_live_policy_set_rate_overrides_fallback() {
    let fee_model = LivePolicy::new();
    fee_model.set_rate(500);

    assert_eq!(fee_model.cached_rate(), Some(500));
    assert_eq!(fee_model.effective_rate(), 500);

    let tx = Transaction::new();
    let fee = fee_model.compute_fee(&tx).unwrap();
    // Empty transaction: 10 bytes * 500 sat/KB / 1000 = 5 sats
    assert_eq!(fee, 5);
}

#[tokio::test]
async fn test_live_policy_cache_expiry() {
    let config = LivePolicyConfig {
        policy_url: "https://not-used.example.com/v1/policy".to_string(),
        api_key: None,
        cache_ttl: Duration::from_millis(50), // Very short TTL for testing
        fallback_rate: 100,
        timeout_ms: 10_000,
    };

    let fee_model = LivePolicy::with_config(config);
    fee_model.set_rate(500);

    assert_eq!(fee_model.cached_rate(), Some(500));

    // Wait for cache to expire
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Cache should have expired, so cached_rate returns None
    assert!(fee_model.cached_rate().is_none());

    // effective_rate falls back to fallback
    assert_eq!(fee_model.effective_rate(), 100);
}

#[tokio::test]
async fn test_live_policy_refresh_updates_cache() {
    let mock_server = MockServer::start().await;

    // First response: low fee
    Mock::given(method("GET"))
        .and(path("/v1/policy"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "miningFee": {
                "satoshis": 1,
                "bytes": 1000
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let fee_model = LivePolicy::with_url(&format!("{}/v1/policy", mock_server.uri()));

    let rate1 = fee_model.refresh().await.unwrap();
    assert_eq!(rate1, 1);
    assert_eq!(fee_model.effective_rate(), 1);
}

#[tokio::test]
async fn test_live_policy_custom_fallback_rate() {
    let config = LivePolicyConfig {
        policy_url: "https://not-used.example.com/v1/policy".to_string(),
        api_key: None,
        cache_ttl: Duration::from_secs(300),
        fallback_rate: 250,
        timeout_ms: 10_000,
    };

    let fee_model = LivePolicy::with_config(config);
    assert_eq!(fee_model.effective_rate(), 250);
}

#[tokio::test]
async fn test_live_policy_default_policy_url() {
    let fee_model = LivePolicy::new();
    assert_eq!(fee_model.policy_url(), DEFAULT_POLICY_URL);
}

#[tokio::test]
async fn test_live_policy_default_cache_ttl() {
    let fee_model = LivePolicy::new();
    assert_eq!(
        fee_model.cache_ttl(),
        Duration::from_secs(DEFAULT_CACHE_TTL_SECS)
    );
}

#[tokio::test]
async fn test_live_policy_refresh_converts_sat_per_byte_to_per_kb() {
    let mock_server = MockServer::start().await;

    // 1 sat per 2 bytes = 500 sat/KB
    Mock::given(method("GET"))
        .and(path("/v1/policy"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "miningFee": {
                "satoshis": 1,
                "bytes": 2
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let fee_model = LivePolicy::with_url(&format!("{}/v1/policy", mock_server.uri()));
    let rate = fee_model.refresh().await.unwrap();

    assert_eq!(rate, 500);
}

#[tokio::test]
async fn test_live_policy_refresh_defaults_missing_satoshis() {
    let mock_server = MockServer::start().await;

    // Missing satoshis defaults to 1
    Mock::given(method("GET"))
        .and(path("/v1/policy"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "miningFee": {
                "bytes": 1000
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let fee_model = LivePolicy::with_url(&format!("{}/v1/policy", mock_server.uri()));
    let rate = fee_model.refresh().await.unwrap();

    // Default satoshis=1, bytes=1000: 1*1000/1000 = 1
    assert_eq!(rate, 1);
}

#[tokio::test]
async fn test_live_policy_refresh_defaults_missing_bytes() {
    let mock_server = MockServer::start().await;

    // Missing bytes defaults to 1
    Mock::given(method("GET"))
        .and(path("/v1/policy"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "miningFee": {
                "satoshis": 5
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let fee_model = LivePolicy::with_url(&format!("{}/v1/policy", mock_server.uri()));
    let rate = fee_model.refresh().await.unwrap();

    // satoshis=5, default bytes=1: 5*1000/1 = 5000
    assert_eq!(rate, 5000);
}
