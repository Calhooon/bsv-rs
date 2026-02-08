//! HTTP integration tests for ChainTracker implementations.
//!
//! These tests use `wiremock` to spin up a local mock HTTP server and verify that
//! the WhatsOnChain chain tracker sends the correct requests and handles various
//! responses properly.
//!
//! Run with: `cargo test --features "full,http" --test chaintracker_http_tests`

#![cfg(all(feature = "transaction", feature = "http"))]

use bsv_sdk::transaction::{ChainTracker, ChainTrackerError, WhatsOnChainTracker, WocNetwork};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A realistic 64-char hex merkle root for testing.
const TEST_MERKLE_ROOT: &str = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";

const TEST_HEIGHT: u32 = 700_000;

// =============================================================================
// WhatsOnChain ChainTracker: is_valid_root_for_height Tests
// =============================================================================

#[tokio::test]
async fn test_woc_tracker_valid_root_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(format!("/block/{}/header", TEST_HEIGHT)))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "hash": "00000000000000000000abc123",
            "height": TEST_HEIGHT,
            "merkleroot": TEST_MERKLE_ROOT,
            "time": 1234567890,
            "nonce": 0
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let tracker = WhatsOnChainTracker::with_base_url(&mock_server.uri(), WocNetwork::Mainnet);
    let result = tracker
        .is_valid_root_for_height(TEST_MERKLE_ROOT, TEST_HEIGHT)
        .await;

    assert!(result.is_ok(), "Expected success, got: {:?}", result);
    assert!(result.unwrap(), "Expected root to be valid");
}

#[tokio::test]
async fn test_woc_tracker_invalid_root() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(format!("/block/{}/header", TEST_HEIGHT)))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "merkleroot": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let tracker = WhatsOnChainTracker::with_base_url(&mock_server.uri(), WocNetwork::Mainnet);
    let result = tracker
        .is_valid_root_for_height(TEST_MERKLE_ROOT, TEST_HEIGHT)
        .await;

    assert!(result.is_ok(), "Expected success, got: {:?}", result);
    assert!(!result.unwrap(), "Expected root to be invalid (mismatch)");
}

#[tokio::test]
async fn test_woc_tracker_case_insensitive_root() {
    let mock_server = MockServer::start().await;

    // Server returns uppercase, client sends lowercase
    let uppercase_root = TEST_MERKLE_ROOT.to_uppercase();

    Mock::given(method("GET"))
        .and(path(format!("/block/{}/header", TEST_HEIGHT)))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "merkleroot": uppercase_root
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let tracker = WhatsOnChainTracker::with_base_url(&mock_server.uri(), WocNetwork::Mainnet);
    let result = tracker
        .is_valid_root_for_height(TEST_MERKLE_ROOT, TEST_HEIGHT)
        .await;

    assert!(result.is_ok(), "Expected success, got: {:?}", result);
    assert!(
        result.unwrap(),
        "Expected case-insensitive comparison to match"
    );
}

#[tokio::test]
async fn test_woc_tracker_block_not_found() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/block/999999999/header"))
        .respond_with(ResponseTemplate::new(404).set_body_string("Not Found"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let tracker = WhatsOnChainTracker::with_base_url(&mock_server.uri(), WocNetwork::Mainnet);
    let result = tracker
        .is_valid_root_for_height(TEST_MERKLE_ROOT, 999_999_999)
        .await;

    assert!(result.is_err(), "Expected error, got: {:?}", result);
    let err = result.unwrap_err();
    assert!(
        matches!(err, ChainTrackerError::BlockNotFound(999_999_999)),
        "Expected BlockNotFound, got: {:?}",
        err
    );
}

#[tokio::test]
async fn test_woc_tracker_server_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(format!("/block/{}/header", TEST_HEIGHT)))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let tracker = WhatsOnChainTracker::with_base_url(&mock_server.uri(), WocNetwork::Mainnet);
    let result = tracker
        .is_valid_root_for_height(TEST_MERKLE_ROOT, TEST_HEIGHT)
        .await;

    assert!(result.is_err(), "Expected error, got: {:?}", result);
    let err = result.unwrap_err();
    assert!(
        matches!(err, ChainTrackerError::InvalidResponse(_)),
        "Expected InvalidResponse, got: {:?}",
        err
    );
    assert!(
        err.to_string().contains("500"),
        "Expected error to contain status code 500, got: {}",
        err
    );
}

#[tokio::test]
async fn test_woc_tracker_malformed_json() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(format!("/block/{}/header", TEST_HEIGHT)))
        .respond_with(ResponseTemplate::new(200).set_body_string("this is not json at all"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let tracker = WhatsOnChainTracker::with_base_url(&mock_server.uri(), WocNetwork::Mainnet);
    let result = tracker
        .is_valid_root_for_height(TEST_MERKLE_ROOT, TEST_HEIGHT)
        .await;

    assert!(
        result.is_err(),
        "Expected error on malformed JSON, got: {:?}",
        result
    );
    let err = result.unwrap_err();
    assert!(
        matches!(err, ChainTrackerError::InvalidResponse(_)),
        "Expected InvalidResponse, got: {:?}",
        err
    );
}

// =============================================================================
// WhatsOnChain ChainTracker: current_height Tests
// =============================================================================

#[tokio::test]
async fn test_woc_tracker_current_height_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/chain/info"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "chain": "main",
            "blocks": 800_000,
            "headers": 800_001,
            "bestblockhash": "0000000000000000000abc"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let tracker = WhatsOnChainTracker::with_base_url(&mock_server.uri(), WocNetwork::Mainnet);
    let result = tracker.current_height().await;

    assert!(result.is_ok(), "Expected success, got: {:?}", result);
    assert_eq!(result.unwrap(), 800_000);
}

#[tokio::test]
async fn test_woc_tracker_current_height_server_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/chain/info"))
        .respond_with(ResponseTemplate::new(503).set_body_string("Service Unavailable"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let tracker = WhatsOnChainTracker::with_base_url(&mock_server.uri(), WocNetwork::Mainnet);
    let result = tracker.current_height().await;

    assert!(result.is_err(), "Expected error, got: {:?}", result);
    let err = result.unwrap_err();
    assert!(
        matches!(err, ChainTrackerError::InvalidResponse(_)),
        "Expected InvalidResponse, got: {:?}",
        err
    );
}

#[tokio::test]
async fn test_woc_tracker_current_height_malformed_json() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/chain/info"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let tracker = WhatsOnChainTracker::with_base_url(&mock_server.uri(), WocNetwork::Mainnet);
    let result = tracker.current_height().await;

    assert!(
        result.is_err(),
        "Expected error on malformed JSON, got: {:?}",
        result
    );
}

// =============================================================================
// WhatsOnChain ChainTracker: Network Tests
// =============================================================================

#[tokio::test]
async fn test_woc_tracker_testnet_uses_correct_path() {
    let mock_server = MockServer::start().await;

    // Testnet path - but with base_url override, the path doesn't include /v1/bsv/test
    // because with_base_url overrides the entire base URL.
    // The tracker appends /block/{height}/header to whatever base URL is configured.
    Mock::given(method("GET"))
        .and(path(format!("/block/{}/header", TEST_HEIGHT)))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "merkleroot": TEST_MERKLE_ROOT
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let tracker = WhatsOnChainTracker::with_base_url(&mock_server.uri(), WocNetwork::Testnet);
    assert_eq!(tracker.network(), WocNetwork::Testnet);

    let result = tracker
        .is_valid_root_for_height(TEST_MERKLE_ROOT, TEST_HEIGHT)
        .await;
    assert!(result.is_ok(), "Expected success, got: {:?}", result);
}
