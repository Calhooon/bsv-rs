//! HTTP integration tests for broadcaster implementations.
//!
//! These tests use `wiremock` to spin up a local mock HTTP server and verify that
//! each broadcaster sends the correct request and handles various responses properly.
//!
//! Run with: `cargo test --features "full,http" --test broadcaster_http_tests`

#![cfg(all(feature = "transaction", feature = "http"))]

use bsv_rs::transaction::{
    ArcBroadcaster, ArcConfig, BroadcastStatus, Broadcaster, TeranodeBroadcaster, TeranodeConfig,
    Transaction, TransactionOutput, WhatsOnChainBroadcaster, WocBroadcastNetwork,
};
use wiremock::matchers::{body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A known valid transaction hex from the Go SDK test vectors.
const TEST_TX_HEX: &str = "0100000001a9b0c5a2437042e5d0c6288fad6abc2ef8725adb6fef5f1bab21b2124cfb7cf6dc9300006a47304402204c3f88aadc90a3f29669bba5c4369a2eebc10439e857a14e169d19626243ffd802205443013b187a5c7f23e2d5dd82bc4ea9a79d138a3dc6cae6e6ef68874bd23a42412103fd290068ae945c23a06775de8422ceb6010aaebab40b78e01a0af3f1322fa861ffffffff010000000000000000b1006a0963657274696861736822314c6d763150594d70387339594a556e374d3948565473446b64626155386b514e4a4032356163343531383766613035616532626436346562323632386666336432666636646338313665383335376364616366343765663862396331656433663531403064383963343363343636303262643865313831376530393137313736343134353938373337623161663865363939343930646364653462343937656338643300000000";

fn test_transaction() -> Transaction {
    Transaction::from_hex(TEST_TX_HEX).expect("Failed to parse test transaction hex")
}

/// Build a transaction that can be serialized to Extended Format (EF).
/// EF requires each input to have both an `unlocking_script` and a `source_transaction`
/// with the referenced output's satoshis and locking script available.
fn ef_capable_transaction() -> Transaction {
    // Parse the test transaction (this gives us an unlocking_script on the input)
    let mut tx = Transaction::from_hex(TEST_TX_HEX).unwrap();

    // Build a fake source transaction that the input references.
    // The test tx input references source_output_index=0xDC (220), so we need
    // a source tx with at least 221 outputs. Instead, set the output index to 0
    // and create a minimal source tx.
    let source_output_index = tx.inputs[0].source_output_index;

    // Create a source transaction with enough outputs to satisfy the index
    let mut source_tx = Transaction::new();
    for _ in 0..=source_output_index {
        source_tx
            .add_output(TransactionOutput::new(
                1_000_000,
                bsv_rs::script::LockingScript::from_hex(
                    "76a914000000000000000000000000000000000000000088ac",
                )
                .unwrap(),
            ))
            .unwrap();
    }

    // Attach the source transaction to the input so EF serialization works
    tx.inputs[0].source_transaction = Some(Box::new(source_tx));

    tx
}

// =============================================================================
// ARC Broadcaster Tests
// =============================================================================

#[tokio::test]
async fn test_arc_broadcast_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/tx"))
        .and(header("Content-Type", "application/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "txid": "4d76b00f29e480e0a933cef9d9ffe303d6ab919e2cdb265dd2cea41089baa85a",
            "txStatus": "SEEN_ON_NETWORK",
            "extraInfo": "extra info"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let broadcaster = ArcBroadcaster::new(&mock_server.uri(), None);
    let tx = test_transaction();
    let result = broadcaster.broadcast(&tx).await;

    assert!(result.is_ok(), "Expected success, got: {:?}", result);
    let response = result.unwrap();
    assert_eq!(response.status, BroadcastStatus::Success);
    assert_eq!(
        response.txid,
        "4d76b00f29e480e0a933cef9d9ffe303d6ab919e2cdb265dd2cea41089baa85a"
    );
    assert_eq!(response.message, "SEEN_ON_NETWORK");
}

#[tokio::test]
async fn test_arc_broadcast_success_with_api_key() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/tx"))
        .and(header("Authorization", "Bearer test-api-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "txid": "4d76b00f29e480e0a933cef9d9ffe303d6ab919e2cdb265dd2cea41089baa85a",
            "txStatus": "SEEN_ON_NETWORK"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let broadcaster = ArcBroadcaster::new(&mock_server.uri(), Some("test-api-key".to_string()));
    let tx = test_transaction();
    let result = broadcaster.broadcast(&tx).await;

    assert!(result.is_ok(), "Expected success, got: {:?}", result);
}

#[tokio::test]
async fn test_arc_broadcast_error_response() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/tx"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "status": 400,
            "title": "Bad Request",
            "detail": "Transaction validation failed",
            "extraInfo": "Missing inputs"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let broadcaster = ArcBroadcaster::new(&mock_server.uri(), None);
    let tx = test_transaction();
    let result = broadcaster.broadcast(&tx).await;

    assert!(result.is_err(), "Expected failure, got: {:?}", result);
    let failure = result.unwrap_err();
    assert_eq!(failure.status, BroadcastStatus::Error);
    assert_eq!(failure.code, "400");
    assert_eq!(failure.description, "Transaction validation failed");
}

#[tokio::test]
async fn test_arc_broadcast_server_error() {
    let mock_server = MockServer::start().await;

    // When detail is absent (null), the code falls back to title
    Mock::given(method("POST"))
        .and(path("/v1/tx"))
        .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
            "status": 500,
            "title": "Internal Server Error"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let broadcaster = ArcBroadcaster::new(&mock_server.uri(), None);
    let tx = test_transaction();
    let result = broadcaster.broadcast(&tx).await;

    assert!(result.is_err(), "Expected failure, got: {:?}", result);
    let failure = result.unwrap_err();
    assert_eq!(failure.status, BroadcastStatus::Error);
    assert_eq!(failure.code, "500");
    assert_eq!(failure.description, "Internal Server Error");
}

#[tokio::test]
async fn test_arc_broadcast_server_error_empty_detail() {
    let mock_server = MockServer::start().await;

    // When detail is present but empty string, it takes precedence over title
    // (this matches the actual implementation behavior: .detail.or(title))
    Mock::given(method("POST"))
        .and(path("/v1/tx"))
        .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
            "status": 500,
            "title": "Internal Server Error",
            "detail": ""
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let broadcaster = ArcBroadcaster::new(&mock_server.uri(), None);
    let tx = test_transaction();
    let result = broadcaster.broadcast(&tx).await;

    assert!(result.is_err(), "Expected failure, got: {:?}", result);
    let failure = result.unwrap_err();
    assert_eq!(failure.code, "500");
    // detail is Some("") which takes precedence over title in .or()
    assert_eq!(failure.description, "");
}

#[tokio::test]
async fn test_arc_broadcast_malformed_json() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/tx"))
        .respond_with(ResponseTemplate::new(200).set_body_string("this is not json at all"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let broadcaster = ArcBroadcaster::new(&mock_server.uri(), None);
    let tx = test_transaction();
    let result = broadcaster.broadcast(&tx).await;

    assert!(
        result.is_err(),
        "Expected failure on malformed JSON, got: {:?}",
        result
    );
    let failure = result.unwrap_err();
    assert_eq!(failure.code, "PARSE_ERROR");
    assert!(
        failure.description.contains("Failed to parse response"),
        "Expected parse error description, got: {}",
        failure.description
    );
}

#[tokio::test]
async fn test_arc_broadcast_sends_raw_tx_in_body() {
    let mock_server = MockServer::start().await;
    let tx = test_transaction();
    let expected_hex = tx.to_hex();

    Mock::given(method("POST"))
        .and(path("/v1/tx"))
        .and(body_string_contains(&expected_hex))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "txid": "abc123",
            "txStatus": "SEEN_ON_NETWORK"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let broadcaster = ArcBroadcaster::new(&mock_server.uri(), None);
    let result = broadcaster.broadcast(&tx).await;

    assert!(result.is_ok(), "Expected success, got: {:?}", result);
}

#[tokio::test]
async fn test_arc_broadcast_with_config_timeout() {
    let mock_server = MockServer::start().await;

    // Respond with a delay longer than our timeout
    Mock::given(method("POST"))
        .and(path("/v1/tx"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"txid": "abc", "txStatus": "ok"}))
                .set_delay(std::time::Duration::from_secs(5)),
        )
        .mount(&mock_server)
        .await;

    let config = ArcConfig {
        url: mock_server.uri(),
        api_key: None,
        timeout_ms: 100, // Very short timeout
    };
    let broadcaster = ArcBroadcaster::with_config(config);
    let tx = test_transaction();
    let result = broadcaster.broadcast(&tx).await;

    assert!(
        result.is_err(),
        "Expected timeout failure, got: {:?}",
        result
    );
    let failure = result.unwrap_err();
    assert_eq!(failure.code, "NETWORK_ERROR");
}

#[tokio::test]
async fn test_arc_broadcast_many() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/tx"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "txid": "abc123",
            "txStatus": "SEEN_ON_NETWORK"
        })))
        .expect(3)
        .mount(&mock_server)
        .await;

    let broadcaster = ArcBroadcaster::new(&mock_server.uri(), None);
    let txs = vec![test_transaction(), test_transaction(), test_transaction()];
    let results = broadcaster.broadcast_many(txs).await;

    assert_eq!(results.len(), 3);
    for result in &results {
        assert!(result.is_ok(), "Expected all broadcasts to succeed");
    }
}

// =============================================================================
// WhatsOnChain Broadcaster Tests
// =============================================================================

#[tokio::test]
async fn test_woc_broadcast_success() {
    let mock_server = MockServer::start().await;
    let tx = test_transaction();
    let expected_txid = tx.id();

    Mock::given(method("POST"))
        .and(path("/v1/bsv/main/tx/raw"))
        .and(header("Content-Type", "application/json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!("\"{}\"", expected_txid)))
        .expect(1)
        .mount(&mock_server)
        .await;

    let broadcaster = WhatsOnChainBroadcaster::with_base_url(
        &mock_server.uri(),
        WocBroadcastNetwork::Mainnet,
        None,
    );
    let result = broadcaster.broadcast(&tx).await;

    assert!(result.is_ok(), "Expected success, got: {:?}", result);
    let response = result.unwrap();
    assert_eq!(response.status, BroadcastStatus::Success);
    assert_eq!(response.txid, expected_txid);
    assert_eq!(response.message, "Transaction broadcast successfully");
}

#[tokio::test]
async fn test_woc_broadcast_success_testnet() {
    let mock_server = MockServer::start().await;
    let tx = test_transaction();

    Mock::given(method("POST"))
        .and(path("/v1/bsv/test/tx/raw"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!("\"{}\"", tx.id())))
        .expect(1)
        .mount(&mock_server)
        .await;

    let broadcaster = WhatsOnChainBroadcaster::with_base_url(
        &mock_server.uri(),
        WocBroadcastNetwork::Testnet,
        None,
    );
    let result = broadcaster.broadcast(&tx).await;

    assert!(result.is_ok(), "Expected success, got: {:?}", result);
}

#[tokio::test]
async fn test_woc_broadcast_success_stn() {
    let mock_server = MockServer::start().await;
    let tx = test_transaction();

    Mock::given(method("POST"))
        .and(path("/v1/bsv/stn/tx/raw"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!("\"{}\"", tx.id())))
        .expect(1)
        .mount(&mock_server)
        .await;

    let broadcaster =
        WhatsOnChainBroadcaster::with_base_url(&mock_server.uri(), WocBroadcastNetwork::Stn, None);
    let result = broadcaster.broadcast(&tx).await;

    assert!(result.is_ok(), "Expected success, got: {:?}", result);
}

#[tokio::test]
async fn test_woc_broadcast_bad_request() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/bsv/main/tx/raw"))
        .respond_with(ResponseTemplate::new(400).set_body_string("Bad Request"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let broadcaster = WhatsOnChainBroadcaster::with_base_url(
        &mock_server.uri(),
        WocBroadcastNetwork::Mainnet,
        None,
    );
    let tx = test_transaction();
    let result = broadcaster.broadcast(&tx).await;

    assert!(result.is_err(), "Expected failure, got: {:?}", result);
    let failure = result.unwrap_err();
    assert_eq!(failure.status, BroadcastStatus::Error);
    assert_eq!(failure.code, "400");
    assert_eq!(failure.description, "Bad Request");
}

#[tokio::test]
async fn test_woc_broadcast_unauthorized() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/bsv/main/tx/raw"))
        .respond_with(ResponseTemplate::new(401).set_body_string("Unauthorized"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let broadcaster = WhatsOnChainBroadcaster::with_base_url(
        &mock_server.uri(),
        WocBroadcastNetwork::Mainnet,
        Some("invalid_api_key".to_string()),
    );
    let tx = test_transaction();
    let result = broadcaster.broadcast(&tx).await;

    assert!(result.is_err(), "Expected failure, got: {:?}", result);
    let failure = result.unwrap_err();
    assert_eq!(failure.status, BroadcastStatus::Error);
    assert_eq!(failure.code, "401");
    assert_eq!(failure.description, "Unauthorized");
}

#[tokio::test]
async fn test_woc_broadcast_server_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/bsv/main/tx/raw"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let broadcaster = WhatsOnChainBroadcaster::with_base_url(
        &mock_server.uri(),
        WocBroadcastNetwork::Mainnet,
        None,
    );
    let tx = test_transaction();
    let result = broadcaster.broadcast(&tx).await;

    assert!(result.is_err(), "Expected failure, got: {:?}", result);
    let failure = result.unwrap_err();
    assert_eq!(failure.code, "500");
    assert_eq!(failure.description, "Internal Server Error");
}

#[tokio::test]
async fn test_woc_broadcast_with_api_key_header() {
    let mock_server = MockServer::start().await;
    let tx = test_transaction();

    // WoC uses Authorization header without "Bearer" prefix
    Mock::given(method("POST"))
        .and(path("/v1/bsv/main/tx/raw"))
        .and(header("Authorization", "my-woc-key"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!("\"{}\"", tx.id())))
        .expect(1)
        .mount(&mock_server)
        .await;

    let broadcaster = WhatsOnChainBroadcaster::with_base_url(
        &mock_server.uri(),
        WocBroadcastNetwork::Mainnet,
        Some("my-woc-key".to_string()),
    );
    let result = broadcaster.broadcast(&tx).await;

    assert!(result.is_ok(), "Expected success, got: {:?}", result);
}

#[tokio::test]
async fn test_woc_broadcast_sends_raw_hex_body() {
    let mock_server = MockServer::start().await;
    let tx = test_transaction();
    let expected_hex = tx.to_hex();

    Mock::given(method("POST"))
        .and(path("/v1/bsv/main/tx/raw"))
        .and(body_string_contains(&expected_hex))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!("\"{}\"", tx.id())))
        .expect(1)
        .mount(&mock_server)
        .await;

    let broadcaster = WhatsOnChainBroadcaster::with_base_url(
        &mock_server.uri(),
        WocBroadcastNetwork::Mainnet,
        None,
    );
    let result = broadcaster.broadcast(&tx).await;

    assert!(result.is_ok(), "Expected success, got: {:?}", result);
}

#[tokio::test]
async fn test_woc_broadcast_many() {
    let mock_server = MockServer::start().await;
    let tx = test_transaction();

    Mock::given(method("POST"))
        .and(path("/v1/bsv/main/tx/raw"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!("\"{}\"", tx.id())))
        .expect(2)
        .mount(&mock_server)
        .await;

    let broadcaster = WhatsOnChainBroadcaster::with_base_url(
        &mock_server.uri(),
        WocBroadcastNetwork::Mainnet,
        None,
    );
    let txs = vec![test_transaction(), test_transaction()];
    let results = broadcaster.broadcast_many(txs).await;

    assert_eq!(results.len(), 2);
    for result in &results {
        assert!(result.is_ok(), "Expected all broadcasts to succeed");
    }
}

// =============================================================================
// Teranode Broadcaster Tests
// =============================================================================

#[tokio::test]
async fn test_teranode_broadcast_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/tx"))
        .and(header("Content-Type", "application/octet-stream"))
        .respond_with(ResponseTemplate::new(200).set_body_string("Transaction accepted"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let broadcaster = TeranodeBroadcaster::new(&mock_server.uri(), None);
    let tx = ef_capable_transaction();
    let result = broadcaster.broadcast(&tx).await;

    assert!(result.is_ok(), "Expected success, got: {:?}", result);
    let response = result.unwrap();
    assert_eq!(response.status, BroadcastStatus::Success);
    assert_eq!(response.message, "Transaction accepted");
}

#[tokio::test]
async fn test_teranode_broadcast_with_api_key() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/tx"))
        .and(header("Authorization", "Bearer teranode-key"))
        .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let broadcaster =
        TeranodeBroadcaster::new(&mock_server.uri(), Some("teranode-key".to_string()));
    let tx = ef_capable_transaction();
    let result = broadcaster.broadcast(&tx).await;

    assert!(result.is_ok(), "Expected success, got: {:?}", result);
}

#[tokio::test]
async fn test_teranode_broadcast_error_response() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/tx"))
        .respond_with(ResponseTemplate::new(400).set_body_string("Invalid transaction format"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let broadcaster = TeranodeBroadcaster::new(&mock_server.uri(), None);
    let tx = ef_capable_transaction();
    let result = broadcaster.broadcast(&tx).await;

    assert!(result.is_err(), "Expected failure, got: {:?}", result);
    let failure = result.unwrap_err();
    assert_eq!(failure.status, BroadcastStatus::Error);
    assert_eq!(failure.code, "400");
    assert_eq!(failure.description, "Invalid transaction format");
}

#[tokio::test]
async fn test_teranode_broadcast_server_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/tx"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let broadcaster = TeranodeBroadcaster::new(&mock_server.uri(), None);
    let tx = ef_capable_transaction();
    let result = broadcaster.broadcast(&tx).await;

    assert!(result.is_err(), "Expected failure, got: {:?}", result);
    let failure = result.unwrap_err();
    assert_eq!(failure.code, "500");
    assert_eq!(failure.description, "Internal Server Error");
}

#[tokio::test]
async fn test_teranode_broadcast_empty_success_body() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/tx"))
        .respond_with(ResponseTemplate::new(200).set_body_string(""))
        .expect(1)
        .mount(&mock_server)
        .await;

    let broadcaster = TeranodeBroadcaster::new(&mock_server.uri(), None);
    let tx = ef_capable_transaction();
    let result = broadcaster.broadcast(&tx).await;

    assert!(result.is_ok(), "Expected success, got: {:?}", result);
    let response = result.unwrap();
    // Empty body should default to "Success"
    assert_eq!(response.message, "Success");
}

#[tokio::test]
async fn test_teranode_broadcast_timeout() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/tx"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("OK")
                .set_delay(std::time::Duration::from_secs(5)),
        )
        .mount(&mock_server)
        .await;

    let config = TeranodeConfig {
        url: mock_server.uri(),
        api_key: None,
        timeout_ms: 100, // Very short timeout
    };
    let broadcaster = TeranodeBroadcaster::with_config(config);
    let tx = ef_capable_transaction();
    let result = broadcaster.broadcast(&tx).await;

    assert!(
        result.is_err(),
        "Expected timeout failure, got: {:?}",
        result
    );
    let failure = result.unwrap_err();
    assert_eq!(failure.code, "NETWORK_ERROR");
}

#[tokio::test]
async fn test_teranode_broadcast_ef_serialization_error() {
    // A transaction parsed from hex has no source_transaction set.
    // Teranode requires EF format which needs source outputs, so this fails
    // before any HTTP call is made.
    let tx = Transaction::from_hex(TEST_TX_HEX).unwrap();

    let broadcaster = TeranodeBroadcaster::new("http://localhost:1", None);
    let result = broadcaster.broadcast(&tx).await;

    assert!(
        result.is_err(),
        "Expected EF serialization error, got: {:?}",
        result
    );
    let failure = result.unwrap_err();
    assert_eq!(failure.code, "EF_SERIALIZATION_ERROR");
    assert!(
        failure
            .description
            .contains("Failed to serialize transaction to EF format"),
        "Expected EF error description, got: {}",
        failure.description
    );
}

#[tokio::test]
async fn test_teranode_broadcast_many() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/tx"))
        .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
        .expect(2)
        .mount(&mock_server)
        .await;

    let broadcaster = TeranodeBroadcaster::new(&mock_server.uri(), None);
    let txs = vec![ef_capable_transaction(), ef_capable_transaction()];
    let results = broadcaster.broadcast_many(txs).await;

    assert_eq!(results.len(), 2);
    for result in &results {
        assert!(result.is_ok(), "Expected all broadcasts to succeed");
    }
}
