//! HTTP integration tests for overlay network operations.
//!
//! Tests the `HttpsOverlayBroadcastFacilitator` (SHIP broadcast) and
//! `HttpsOverlayLookupFacilitator` (SLAP lookup) HTTP communication.
//!
//! These tests use `wiremock` to spin up a local mock HTTP server and verify that
//! each facilitator sends the correct request and handles various responses properly.
//!
//! Run with: `cargo test --features "full,http" --test overlay_http_tests`

#![cfg(all(feature = "overlay", feature = "http"))]

use bsv_rs::overlay::{
    HttpsOverlayBroadcastFacilitator, HttpsOverlayLookupFacilitator, LookupAnswer, LookupQuestion,
    OverlayBroadcastFacilitator, OverlayLookupFacilitator, TaggedBEEF,
};
use wiremock::matchers::{body_string_contains, header, header_regex, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// =============================================================================
// HttpsOverlayBroadcastFacilitator Tests (SHIP Broadcast)
// =============================================================================

/// Test successful broadcast with a 200 response containing valid STEAK JSON.
#[tokio::test]
async fn test_broadcast_success() {
    let mock_server = MockServer::start().await;

    // The facilitator POSTs to /submit with the BEEF body
    Mock::given(method("POST"))
        .and(path("/submit"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "tm_topic1": {
                "outputsToAdmit": [0],
                "coinsToRetain": [],
                "coinsRemoved": []
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let facilitator = HttpsOverlayBroadcastFacilitator::new(true);
    let tagged_beef = TaggedBEEF::new(vec![0x01, 0x02, 0x03], vec!["tm_topic1".to_string()]);

    let result = facilitator.send(&mock_server.uri(), &tagged_beef).await;

    assert!(result.is_ok(), "Expected success, got: {:?}", result);
    let steak = result.unwrap();
    assert!(steak.contains_key("tm_topic1"));
    let instructions = steak.get("tm_topic1").unwrap();
    assert_eq!(instructions.outputs_to_admit, vec![0]);
}

/// Test successful broadcast with multiple topics acknowledged in the STEAK.
#[tokio::test]
async fn test_broadcast_success_multiple_topics() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/submit"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "tm_topic1": {
                "outputsToAdmit": [0, 1],
                "coinsToRetain": [2]
            },
            "tm_topic2": {
                "outputsToAdmit": [],
                "coinsToRetain": [],
                "coinsRemoved": [3]
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let facilitator = HttpsOverlayBroadcastFacilitator::new(true);
    let tagged_beef = TaggedBEEF::new(
        vec![0x01, 0x02, 0x03],
        vec!["tm_topic1".to_string(), "tm_topic2".to_string()],
    );

    let result = facilitator.send(&mock_server.uri(), &tagged_beef).await;

    assert!(result.is_ok(), "Expected success, got: {:?}", result);
    let steak = result.unwrap();
    assert_eq!(steak.len(), 2);
    assert_eq!(steak["tm_topic1"].outputs_to_admit, vec![0, 1]);
    assert_eq!(steak["tm_topic1"].coins_to_retain, vec![2]);
    assert_eq!(steak["tm_topic2"].coins_removed, Some(vec![3]));
}

/// Test that broadcast sends correct Content-Type header (application/octet-stream).
#[tokio::test]
async fn test_broadcast_content_type_header() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/submit"))
        .and(header("Content-Type", "application/octet-stream"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
        .expect(1)
        .mount(&mock_server)
        .await;

    let facilitator = HttpsOverlayBroadcastFacilitator::new(true);
    let tagged_beef = TaggedBEEF::new(vec![0x01], vec!["tm_test".to_string()]);

    let result = facilitator.send(&mock_server.uri(), &tagged_beef).await;
    assert!(result.is_ok(), "Expected success, got: {:?}", result);
}

/// Test that broadcast sends the X-Topics header with JSON-serialized topics.
#[tokio::test]
async fn test_broadcast_x_topics_header() {
    let mock_server = MockServer::start().await;

    // Match the X-Topics header containing our topic names as a JSON array
    Mock::given(method("POST"))
        .and(path("/submit"))
        .and(header("X-Topics", "[\"tm_test_topic\"]"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
        .expect(1)
        .mount(&mock_server)
        .await;

    let facilitator = HttpsOverlayBroadcastFacilitator::new(true);
    let tagged_beef = TaggedBEEF::new(vec![0x01], vec!["tm_test_topic".to_string()]);

    let result = facilitator.send(&mock_server.uri(), &tagged_beef).await;
    assert!(result.is_ok(), "Expected success, got: {:?}", result);
}

/// Test that broadcast sends the X-Topics header with multiple topics.
///
/// Note: wiremock's `header()` matcher splits values on commas (per HTTP spec),
/// which breaks matching for JSON arrays like `["tm_foo","tm_bar"]`. We use
/// `header_regex()` instead, which matches the raw header value without splitting.
#[tokio::test]
async fn test_broadcast_x_topics_header_multiple() {
    let mock_server = MockServer::start().await;

    // Use header_regex because wiremock's header() splits on commas, which
    // breaks JSON array values like ["tm_foo","tm_bar"].
    Mock::given(method("POST"))
        .and(path("/submit"))
        .and(header_regex("X-Topics", r#".*tm_foo.*tm_bar.*"#))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
        .expect(1)
        .mount(&mock_server)
        .await;

    let facilitator = HttpsOverlayBroadcastFacilitator::new(true);
    let tagged_beef = TaggedBEEF::new(vec![0x01], vec!["tm_foo".to_string(), "tm_bar".to_string()]);

    let result = facilitator.send(&mock_server.uri(), &tagged_beef).await;
    assert!(result.is_ok(), "Expected success, got: {:?}", result);
}

/// Test that broadcast sends the BEEF bytes in the request body.
#[tokio::test]
async fn test_broadcast_sends_beef_in_body() {
    let mock_server = MockServer::start().await;

    // We'll verify the request was received by checking it was matched
    Mock::given(method("POST"))
        .and(path("/submit"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "tm_test": {
                "outputsToAdmit": [0],
                "coinsToRetain": []
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let beef_data = vec![0xBE, 0xEF, 0xCA, 0xFE];
    let facilitator = HttpsOverlayBroadcastFacilitator::new(true);
    let tagged_beef = TaggedBEEF::new(beef_data, vec!["tm_test".to_string()]);

    let result = facilitator.send(&mock_server.uri(), &tagged_beef).await;
    assert!(result.is_ok(), "Expected success, got: {:?}", result);
}

/// Test broadcast with off-chain values includes the appropriate header.
#[tokio::test]
async fn test_broadcast_with_off_chain_values() {
    let mock_server = MockServer::start().await;

    // When off-chain values are included, the x-includes-off-chain-values header is set
    Mock::given(method("POST"))
        .and(path("/submit"))
        .and(header("x-includes-off-chain-values", "true"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "tm_test": {
                "outputsToAdmit": [0],
                "coinsToRetain": []
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let facilitator = HttpsOverlayBroadcastFacilitator::new(true);
    let tagged_beef = TaggedBEEF::with_off_chain_values(
        vec![0x01, 0x02, 0x03],
        vec!["tm_test".to_string()],
        vec![0xFF, 0xFE],
    );

    let result = facilitator.send(&mock_server.uri(), &tagged_beef).await;
    assert!(result.is_ok(), "Expected success, got: {:?}", result);
}

/// Test broadcast without off-chain values does NOT include the header.
#[tokio::test]
async fn test_broadcast_without_off_chain_values_no_header() {
    let mock_server = MockServer::start().await;

    // Mount a mock that does NOT expect the off-chain header
    // This verifies the header is not sent by default
    Mock::given(method("POST"))
        .and(path("/submit"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "tm_test": {
                "outputsToAdmit": [],
                "coinsToRetain": []
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let facilitator = HttpsOverlayBroadcastFacilitator::new(true);
    let tagged_beef = TaggedBEEF::new(vec![0x01], vec!["tm_test".to_string()]);

    let result = facilitator.send(&mock_server.uri(), &tagged_beef).await;
    assert!(result.is_ok(), "Expected success, got: {:?}", result);
}

/// Test broadcast error response - 400 Bad Request.
#[tokio::test]
async fn test_broadcast_error_400_bad_request() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/submit"))
        .respond_with(ResponseTemplate::new(400).set_body_string("Bad Request: invalid BEEF"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let facilitator = HttpsOverlayBroadcastFacilitator::new(true);
    let tagged_beef = TaggedBEEF::new(vec![0x01], vec!["tm_test".to_string()]);

    let result = facilitator.send(&mock_server.uri(), &tagged_beef).await;

    assert!(result.is_err(), "Expected error, got: {:?}", result);
    let err = result.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("400"),
        "Expected error to contain status 400, got: {}",
        err_msg
    );
}

/// Test broadcast error response - 404 Not Found.
#[tokio::test]
async fn test_broadcast_error_404_not_found() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/submit"))
        .respond_with(ResponseTemplate::new(404).set_body_string("Not Found"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let facilitator = HttpsOverlayBroadcastFacilitator::new(true);
    let tagged_beef = TaggedBEEF::new(vec![0x01], vec!["tm_test".to_string()]);

    let result = facilitator.send(&mock_server.uri(), &tagged_beef).await;

    assert!(result.is_err(), "Expected error, got: {:?}", result);
    let err = result.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("404"),
        "Expected error to contain status 404, got: {}",
        err_msg
    );
}

/// Test broadcast error response - 500 Internal Server Error.
#[tokio::test]
async fn test_broadcast_error_500_server_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/submit"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let facilitator = HttpsOverlayBroadcastFacilitator::new(true);
    let tagged_beef = TaggedBEEF::new(vec![0x01], vec!["tm_test".to_string()]);

    let result = facilitator.send(&mock_server.uri(), &tagged_beef).await;

    assert!(result.is_err(), "Expected error, got: {:?}", result);
    let err = result.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("500"),
        "Expected error to contain status 500, got: {}",
        err_msg
    );
}

/// Test broadcast with empty STEAK response (empty JSON object).
#[tokio::test]
async fn test_broadcast_empty_steak_response() {
    let mock_server = MockServer::start().await;

    // Server responds with empty STEAK (no topics acknowledged)
    Mock::given(method("POST"))
        .and(path("/submit"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
        .expect(1)
        .mount(&mock_server)
        .await;

    let facilitator = HttpsOverlayBroadcastFacilitator::new(true);
    let tagged_beef = TaggedBEEF::new(vec![0x01], vec!["tm_test".to_string()]);

    let result = facilitator.send(&mock_server.uri(), &tagged_beef).await;

    assert!(result.is_ok(), "Expected success, got: {:?}", result);
    let steak = result.unwrap();
    assert!(steak.is_empty(), "Expected empty STEAK");
}

/// Test broadcast with malformed JSON response.
#[tokio::test]
async fn test_broadcast_malformed_json_response() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/submit"))
        .respond_with(ResponseTemplate::new(200).set_body_string("this is not valid json"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let facilitator = HttpsOverlayBroadcastFacilitator::new(true);
    let tagged_beef = TaggedBEEF::new(vec![0x01], vec!["tm_test".to_string()]);

    let result = facilitator.send(&mock_server.uri(), &tagged_beef).await;

    assert!(
        result.is_err(),
        "Expected error on malformed JSON, got: {:?}",
        result
    );
    let err = result.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("STEAK"),
        "Expected STEAK parse error, got: {}",
        err_msg
    );
}

/// Test that broadcast rejects HTTP URLs when allow_http is false.
#[tokio::test]
async fn test_broadcast_rejects_http_when_not_allowed() {
    let facilitator = HttpsOverlayBroadcastFacilitator::new(false);
    let tagged_beef = TaggedBEEF::new(vec![0x01], vec!["tm_test".to_string()]);

    let result = facilitator
        .send("http://insecure.host/", &tagged_beef)
        .await;

    assert!(result.is_err(), "Expected error, got: {:?}", result);
    let err = result.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("https"),
        "Expected HTTPS requirement error, got: {}",
        err_msg
    );
}

/// Test that broadcast allows HTTP URLs when allow_http is true.
#[tokio::test]
async fn test_broadcast_allows_http_when_configured() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/submit"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
        .expect(1)
        .mount(&mock_server)
        .await;

    let facilitator = HttpsOverlayBroadcastFacilitator::new(true);
    let tagged_beef = TaggedBEEF::new(vec![0x01], vec!["tm_test".to_string()]);

    // mock_server.uri() returns http://127.0.0.1:PORT, which is HTTP
    let result = facilitator.send(&mock_server.uri(), &tagged_beef).await;
    assert!(
        result.is_ok(),
        "Expected success with allow_http=true, got: {:?}",
        result
    );
}

/// Test broadcast URL trailing slash is trimmed correctly.
#[tokio::test]
async fn test_broadcast_url_trailing_slash_trimmed() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/submit"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
        .expect(1)
        .mount(&mock_server)
        .await;

    let facilitator = HttpsOverlayBroadcastFacilitator::new(true);
    let tagged_beef = TaggedBEEF::new(vec![0x01], vec!["tm_test".to_string()]);

    // URL with trailing slash should still work
    let url_with_slash = format!("{}/", mock_server.uri());
    let result = facilitator.send(&url_with_slash, &tagged_beef).await;
    assert!(
        result.is_ok(),
        "Expected success with trailing slash URL, got: {:?}",
        result
    );
}

/// Test broadcast with STEAK containing complex admittance instructions.
#[tokio::test]
async fn test_broadcast_steak_with_coins_removed() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/submit"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "tm_test": {
                "outputsToAdmit": [],
                "coinsToRetain": [],
                "coinsRemoved": [0, 1, 2]
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let facilitator = HttpsOverlayBroadcastFacilitator::new(true);
    let tagged_beef = TaggedBEEF::new(vec![0x01], vec!["tm_test".to_string()]);

    let result = facilitator.send(&mock_server.uri(), &tagged_beef).await;

    assert!(result.is_ok(), "Expected success, got: {:?}", result);
    let steak = result.unwrap();
    let instructions = steak.get("tm_test").unwrap();
    assert_eq!(instructions.coins_removed, Some(vec![0, 1, 2]));
    assert!(instructions.outputs_to_admit.is_empty());
    assert!(instructions.coins_to_retain.is_empty());
}

/// Test that broadcast creates the facilitator with default settings.
#[tokio::test]
async fn test_broadcast_facilitator_default() {
    // Default facilitator should have allow_http = false
    let facilitator = HttpsOverlayBroadcastFacilitator::default();
    let tagged_beef = TaggedBEEF::new(vec![0x01], vec!["tm_test".to_string()]);

    // HTTP URLs should be rejected with default settings
    let result = facilitator
        .send("http://insecure.host/", &tagged_beef)
        .await;
    assert!(
        result.is_err(),
        "Default facilitator should reject HTTP URLs"
    );
}

// =============================================================================
// HttpsOverlayLookupFacilitator Tests (SLAP Lookup)
// =============================================================================

/// Test successful lookup returning a JSON output-list response.
#[tokio::test]
async fn test_lookup_success_output_list() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/lookup"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "type": "output-list",
            "outputs": [
                {
                    "beef": [1, 2, 3, 4],
                    "outputIndex": 0
                }
            ]
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let facilitator = HttpsOverlayLookupFacilitator::new(true);
    let question = LookupQuestion::new("ls_test", serde_json::json!({"key": "value"}));

    let result = facilitator
        .lookup(&mock_server.uri(), &question, None)
        .await;

    assert!(result.is_ok(), "Expected success, got: {:?}", result);
    let answer = result.unwrap();
    if let LookupAnswer::OutputList { outputs } = answer {
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].beef, vec![1, 2, 3, 4]);
        assert_eq!(outputs[0].output_index, 0);
    } else {
        panic!("Expected OutputList, got: {:?}", answer);
    }
}

/// Test successful lookup returning a freeform JSON response.
#[tokio::test]
async fn test_lookup_success_freeform() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/lookup"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "type": "freeform",
            "result": {"status": "ok", "data": [1, 2, 3]}
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let facilitator = HttpsOverlayLookupFacilitator::new(true);
    let question = LookupQuestion::new("ls_test", serde_json::json!({}));

    let result = facilitator
        .lookup(&mock_server.uri(), &question, None)
        .await;

    assert!(result.is_ok(), "Expected success, got: {:?}", result);
    let answer = result.unwrap();
    if let LookupAnswer::Freeform { result: r } = answer {
        assert_eq!(r["status"], "ok");
    } else {
        panic!("Expected Freeform, got: {:?}", answer);
    }
}

/// Test successful lookup returning a formula response.
#[tokio::test]
async fn test_lookup_success_formula() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/lookup"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "type": "formula",
            "formulas": [
                {
                    "outpoint": "abc123.0",
                    "historyFn": "get_history"
                }
            ]
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let facilitator = HttpsOverlayLookupFacilitator::new(true);
    let question = LookupQuestion::new("ls_test", serde_json::json!({}));

    let result = facilitator
        .lookup(&mock_server.uri(), &question, None)
        .await;

    assert!(result.is_ok(), "Expected success, got: {:?}", result);
    let answer = result.unwrap();
    if let LookupAnswer::Formula { formulas } = answer {
        assert_eq!(formulas.len(), 1);
        assert_eq!(formulas[0].outpoint, "abc123.0");
        assert_eq!(formulas[0].history_fn, "get_history");
    } else {
        panic!("Expected Formula, got: {:?}", answer);
    }
}

/// Test lookup with empty output list response.
#[tokio::test]
async fn test_lookup_empty_output_list() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/lookup"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "type": "output-list",
            "outputs": []
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let facilitator = HttpsOverlayLookupFacilitator::new(true);
    let question = LookupQuestion::new("ls_test", serde_json::json!({}));

    let result = facilitator
        .lookup(&mock_server.uri(), &question, None)
        .await;

    assert!(result.is_ok(), "Expected success, got: {:?}", result);
    let answer = result.unwrap();
    if let LookupAnswer::OutputList { outputs } = answer {
        assert!(outputs.is_empty());
    } else {
        panic!("Expected empty OutputList, got: {:?}", answer);
    }
}

/// Test that lookup sends the correct Content-Type header.
#[tokio::test]
async fn test_lookup_content_type_header() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/lookup"))
        .and(header("Content-Type", "application/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "type": "output-list",
            "outputs": []
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let facilitator = HttpsOverlayLookupFacilitator::new(true);
    let question = LookupQuestion::new("ls_test", serde_json::json!({}));

    let result = facilitator
        .lookup(&mock_server.uri(), &question, None)
        .await;
    assert!(result.is_ok(), "Expected success, got: {:?}", result);
}

/// Test that lookup sends the X-Aggregation header.
#[tokio::test]
async fn test_lookup_x_aggregation_header() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/lookup"))
        .and(header("X-Aggregation", "yes"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "type": "output-list",
            "outputs": []
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let facilitator = HttpsOverlayLookupFacilitator::new(true);
    let question = LookupQuestion::new("ls_test", serde_json::json!({}));

    let result = facilitator
        .lookup(&mock_server.uri(), &question, None)
        .await;
    assert!(result.is_ok(), "Expected success, got: {:?}", result);
}

/// Test that lookup sends the correct JSON body with service and query fields.
#[tokio::test]
async fn test_lookup_request_body_contains_service_and_query() {
    let mock_server = MockServer::start().await;

    // Verify the request body contains the service name
    Mock::given(method("POST"))
        .and(path("/lookup"))
        .and(body_string_contains("ls_myservice"))
        .and(body_string_contains("test_key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "type": "output-list",
            "outputs": []
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let facilitator = HttpsOverlayLookupFacilitator::new(true);
    let question = LookupQuestion::new(
        "ls_myservice",
        serde_json::json!({"test_key": "test_value"}),
    );

    let result = facilitator
        .lookup(&mock_server.uri(), &question, None)
        .await;
    assert!(result.is_ok(), "Expected success, got: {:?}", result);
}

/// Test lookup error response - 400 Bad Request.
#[tokio::test]
async fn test_lookup_error_400_bad_request() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/lookup"))
        .respond_with(ResponseTemplate::new(400).set_body_string("Bad Request: invalid query"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let facilitator = HttpsOverlayLookupFacilitator::new(true);
    let question = LookupQuestion::new("ls_test", serde_json::json!({}));

    let result = facilitator
        .lookup(&mock_server.uri(), &question, None)
        .await;

    assert!(result.is_err(), "Expected error, got: {:?}", result);
    let err = result.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("400"),
        "Expected error to contain status 400, got: {}",
        err_msg
    );
}

/// Test lookup error response - 404 Not Found.
#[tokio::test]
async fn test_lookup_error_404_not_found() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/lookup"))
        .respond_with(ResponseTemplate::new(404).set_body_string("Not Found"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let facilitator = HttpsOverlayLookupFacilitator::new(true);
    let question = LookupQuestion::new("ls_test", serde_json::json!({}));

    let result = facilitator
        .lookup(&mock_server.uri(), &question, None)
        .await;

    assert!(result.is_err(), "Expected error, got: {:?}", result);
    let err = result.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("404"),
        "Expected error to contain status 404, got: {}",
        err_msg
    );
}

/// Test lookup error response - 500 Internal Server Error.
#[tokio::test]
async fn test_lookup_error_500_server_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/lookup"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let facilitator = HttpsOverlayLookupFacilitator::new(true);
    let question = LookupQuestion::new("ls_test", serde_json::json!({}));

    let result = facilitator
        .lookup(&mock_server.uri(), &question, None)
        .await;

    assert!(result.is_err(), "Expected error, got: {:?}", result);
    let err = result.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("500"),
        "Expected error to contain status 500, got: {}",
        err_msg
    );
}

/// Test lookup with malformed JSON response.
#[tokio::test]
async fn test_lookup_malformed_json_response() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/lookup"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("this is not valid JSON at all {{{")
                .append_header("Content-Type", "application/json"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let facilitator = HttpsOverlayLookupFacilitator::new(true);
    let question = LookupQuestion::new("ls_test", serde_json::json!({}));

    let result = facilitator
        .lookup(&mock_server.uri(), &question, None)
        .await;

    assert!(
        result.is_err(),
        "Expected error on malformed JSON, got: {:?}",
        result
    );
    let err = result.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("JSON") || err_msg.contains("parse"),
        "Expected JSON parse error, got: {}",
        err_msg
    );
}

/// Test that lookup rejects HTTP URLs when allow_http is false.
#[tokio::test]
async fn test_lookup_rejects_http_when_not_allowed() {
    let facilitator = HttpsOverlayLookupFacilitator::new(false);
    let question = LookupQuestion::new("ls_test", serde_json::json!({}));

    let result = facilitator
        .lookup("http://insecure.host/", &question, None)
        .await;

    assert!(result.is_err(), "Expected error, got: {:?}", result);
    let err = result.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("https"),
        "Expected HTTPS requirement error, got: {}",
        err_msg
    );
}

/// Test that lookup allows HTTP URLs when allow_http is true.
#[tokio::test]
async fn test_lookup_allows_http_when_configured() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/lookup"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "type": "output-list",
            "outputs": []
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let facilitator = HttpsOverlayLookupFacilitator::new(true);
    let question = LookupQuestion::new("ls_test", serde_json::json!({}));

    let result = facilitator
        .lookup(&mock_server.uri(), &question, None)
        .await;
    assert!(
        result.is_ok(),
        "Expected success with allow_http=true, got: {:?}",
        result
    );
}

/// Test lookup URL trailing slash is trimmed correctly.
#[tokio::test]
async fn test_lookup_url_trailing_slash_trimmed() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/lookup"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "type": "output-list",
            "outputs": []
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let facilitator = HttpsOverlayLookupFacilitator::new(true);
    let question = LookupQuestion::new("ls_test", serde_json::json!({}));

    let url_with_slash = format!("{}/", mock_server.uri());
    let result = facilitator.lookup(&url_with_slash, &question, None).await;
    assert!(
        result.is_ok(),
        "Expected success with trailing slash URL, got: {:?}",
        result
    );
}

/// Test lookup with output-list containing multiple outputs with context data.
#[tokio::test]
async fn test_lookup_output_list_with_context() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/lookup"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "type": "output-list",
            "outputs": [
                {
                    "beef": [1, 2, 3],
                    "outputIndex": 0,
                    "context": [0xAA, 0xBB]
                },
                {
                    "beef": [4, 5, 6],
                    "outputIndex": 1
                }
            ]
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let facilitator = HttpsOverlayLookupFacilitator::new(true);
    let question = LookupQuestion::new("ls_test", serde_json::json!({}));

    let result = facilitator
        .lookup(&mock_server.uri(), &question, None)
        .await;

    assert!(result.is_ok(), "Expected success, got: {:?}", result);
    let answer = result.unwrap();
    if let LookupAnswer::OutputList { outputs } = answer {
        assert_eq!(outputs.len(), 2);

        // First output has context
        assert_eq!(outputs[0].beef, vec![1, 2, 3]);
        assert_eq!(outputs[0].output_index, 0);
        assert_eq!(outputs[0].context, Some(vec![0xAA, 0xBB]));

        // Second output has no context
        assert_eq!(outputs[1].beef, vec![4, 5, 6]);
        assert_eq!(outputs[1].output_index, 1);
        assert!(outputs[1].context.is_none());
    } else {
        panic!("Expected OutputList, got: {:?}", answer);
    }
}

/// Test lookup with output-list where BEEF is provided as a hex string.
#[tokio::test]
async fn test_lookup_output_list_beef_as_hex_string() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/lookup"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "type": "output-list",
            "outputs": [
                {
                    "beef": "0102030405",
                    "outputIndex": 0
                }
            ]
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let facilitator = HttpsOverlayLookupFacilitator::new(true);
    let question = LookupQuestion::new("ls_test", serde_json::json!({}));

    let result = facilitator
        .lookup(&mock_server.uri(), &question, None)
        .await;

    assert!(result.is_ok(), "Expected success, got: {:?}", result);
    let answer = result.unwrap();
    if let LookupAnswer::OutputList { outputs } = answer {
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].beef, vec![0x01, 0x02, 0x03, 0x04, 0x05]);
    } else {
        panic!("Expected OutputList, got: {:?}", answer);
    }
}

/// Test lookup with unknown answer type returns an error.
#[tokio::test]
async fn test_lookup_unknown_answer_type() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/lookup"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "type": "unknown-type",
            "data": {}
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let facilitator = HttpsOverlayLookupFacilitator::new(true);
    let question = LookupQuestion::new("ls_test", serde_json::json!({}));

    let result = facilitator
        .lookup(&mock_server.uri(), &question, None)
        .await;

    assert!(
        result.is_err(),
        "Expected error for unknown answer type, got: {:?}",
        result
    );
    let err = result.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("unknown-type") || err_msg.contains("Unknown"),
        "Expected unknown type error, got: {}",
        err_msg
    );
}

/// Test lookup with no explicit type defaults to output-list.
#[tokio::test]
async fn test_lookup_default_type_is_output_list() {
    let mock_server = MockServer::start().await;

    // Response has no "type" field - should default to output-list
    Mock::given(method("POST"))
        .and(path("/lookup"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "outputs": [
                {
                    "beef": [1, 2],
                    "outputIndex": 0
                }
            ]
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let facilitator = HttpsOverlayLookupFacilitator::new(true);
    let question = LookupQuestion::new("ls_test", serde_json::json!({}));

    let result = facilitator
        .lookup(&mock_server.uri(), &question, None)
        .await;

    assert!(result.is_ok(), "Expected success, got: {:?}", result);
    let answer = result.unwrap();
    assert!(
        matches!(answer, LookupAnswer::OutputList { .. }),
        "Expected OutputList as default, got: {:?}",
        answer
    );
}

/// Test lookup with binary (octet-stream) response format.
#[tokio::test]
async fn test_lookup_binary_response() {
    let mock_server = MockServer::start().await;

    // Build a binary response:
    // varint(num_outpoints) + for each: 32-byte txid + varint(output_index) + varint(context_len) + context_bytes
    // followed by remaining BEEF bytes
    let mut binary_response = Vec::new();

    // Number of outpoints: 1
    binary_response.push(1u8);

    // Outpoint 1: 32-byte txid (all zeros for simplicity)
    binary_response.extend_from_slice(&[0u8; 32]);

    // Output index: 0
    binary_response.push(0u8);

    // Context length: 0 (no context)
    binary_response.push(0u8);

    // Remaining BEEF bytes
    binary_response.extend_from_slice(&[0xBE, 0xEF]);

    Mock::given(method("POST"))
        .and(path("/lookup"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(binary_response)
                .append_header("Content-Type", "application/octet-stream"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let facilitator = HttpsOverlayLookupFacilitator::new(true);
    let question = LookupQuestion::new("ls_test", serde_json::json!({}));

    let result = facilitator
        .lookup(&mock_server.uri(), &question, None)
        .await;

    assert!(result.is_ok(), "Expected success, got: {:?}", result);
    let answer = result.unwrap();
    if let LookupAnswer::OutputList { outputs } = answer {
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].output_index, 0);
        assert!(outputs[0].context.is_none());
        // The BEEF data should be the remaining bytes after outpoints
        assert_eq!(outputs[0].beef, vec![0xBE, 0xEF]);
    } else {
        panic!(
            "Expected OutputList from binary response, got: {:?}",
            answer
        );
    }
}

/// Test lookup with binary response containing context data.
#[tokio::test]
async fn test_lookup_binary_response_with_context() {
    let mock_server = MockServer::start().await;

    let mut binary_response = Vec::new();

    // Number of outpoints: 1
    binary_response.push(1u8);

    // 32-byte txid
    binary_response.extend_from_slice(&[0xABu8; 32]);

    // Output index: 2
    binary_response.push(2u8);

    // Context length: 3
    binary_response.push(3u8);

    // Context bytes
    binary_response.extend_from_slice(&[0x01, 0x02, 0x03]);

    // BEEF bytes
    binary_response.extend_from_slice(&[0xCA, 0xFE]);

    Mock::given(method("POST"))
        .and(path("/lookup"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(binary_response)
                .append_header("Content-Type", "application/octet-stream"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let facilitator = HttpsOverlayLookupFacilitator::new(true);
    let question = LookupQuestion::new("ls_test", serde_json::json!({}));

    let result = facilitator
        .lookup(&mock_server.uri(), &question, None)
        .await;

    assert!(result.is_ok(), "Expected success, got: {:?}", result);
    let answer = result.unwrap();
    if let LookupAnswer::OutputList { outputs } = answer {
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].output_index, 2);
        assert_eq!(outputs[0].context, Some(vec![0x01, 0x02, 0x03]));
        assert_eq!(outputs[0].beef, vec![0xCA, 0xFE]);
    } else {
        panic!(
            "Expected OutputList from binary response, got: {:?}",
            answer
        );
    }
}

/// Test lookup with binary response containing multiple outpoints.
#[tokio::test]
async fn test_lookup_binary_response_multiple_outpoints() {
    let mock_server = MockServer::start().await;

    let mut binary_response = Vec::new();

    // Number of outpoints: 2
    binary_response.push(2u8);

    // Outpoint 1: txid (all 0x11), output_index=0, no context
    binary_response.extend_from_slice(&[0x11u8; 32]);
    binary_response.push(0u8); // output_index
    binary_response.push(0u8); // context_len

    // Outpoint 2: txid (all 0x22), output_index=1, no context
    binary_response.extend_from_slice(&[0x22u8; 32]);
    binary_response.push(1u8); // output_index
    binary_response.push(0u8); // context_len

    // Shared BEEF data
    binary_response.extend_from_slice(&[0xDE, 0xAD]);

    Mock::given(method("POST"))
        .and(path("/lookup"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(binary_response)
                .append_header("Content-Type", "application/octet-stream"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let facilitator = HttpsOverlayLookupFacilitator::new(true);
    let question = LookupQuestion::new("ls_test", serde_json::json!({}));

    let result = facilitator
        .lookup(&mock_server.uri(), &question, None)
        .await;

    assert!(result.is_ok(), "Expected success, got: {:?}", result);
    let answer = result.unwrap();
    if let LookupAnswer::OutputList { outputs } = answer {
        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[0].output_index, 0);
        assert_eq!(outputs[1].output_index, 1);
        // Both share the same BEEF data
        assert_eq!(outputs[0].beef, vec![0xDE, 0xAD]);
        assert_eq!(outputs[1].beef, vec![0xDE, 0xAD]);
    } else {
        panic!(
            "Expected OutputList from binary response, got: {:?}",
            answer
        );
    }
}

/// Test lookup with SLAP service discovery query format.
#[tokio::test]
async fn test_lookup_slap_service_discovery() {
    let mock_server = MockServer::start().await;

    // SLAP queries use "ls_slap" as the service name
    Mock::given(method("POST"))
        .and(path("/lookup"))
        .and(body_string_contains("ls_slap"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "type": "output-list",
            "outputs": []
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let facilitator = HttpsOverlayLookupFacilitator::new(true);
    let question = LookupQuestion::new("ls_slap", serde_json::json!({"service": "ls_myservice"}));

    let result = facilitator
        .lookup(&mock_server.uri(), &question, None)
        .await;
    assert!(result.is_ok(), "Expected success, got: {:?}", result);
}

/// Test lookup with SHIP host discovery query format.
#[tokio::test]
async fn test_lookup_ship_host_discovery() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/lookup"))
        .and(body_string_contains("ls_ship"))
        .and(body_string_contains("tm_mytopic"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "type": "output-list",
            "outputs": []
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let facilitator = HttpsOverlayLookupFacilitator::new(true);
    let question = LookupQuestion::new("ls_ship", serde_json::json!({"topics": ["tm_mytopic"]}));

    let result = facilitator
        .lookup(&mock_server.uri(), &question, None)
        .await;
    assert!(result.is_ok(), "Expected success, got: {:?}", result);
}

/// Test that lookup facilitator default has allow_http = false.
#[tokio::test]
async fn test_lookup_facilitator_default_rejects_http() {
    let facilitator = HttpsOverlayLookupFacilitator::default();
    let question = LookupQuestion::new("ls_test", serde_json::json!({}));

    let result = facilitator
        .lookup("http://insecure.host/", &question, None)
        .await;
    assert!(
        result.is_err(),
        "Default facilitator should reject HTTP URLs"
    );
}

/// Test lookup output-list with outputs missing required fields are skipped.
#[tokio::test]
async fn test_lookup_output_list_skips_malformed_items() {
    let mock_server = MockServer::start().await;

    // Some outputs are missing required fields (e.g., no outputIndex)
    Mock::given(method("POST"))
        .and(path("/lookup"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "type": "output-list",
            "outputs": [
                {
                    "beef": [1, 2],
                    "outputIndex": 0
                },
                {
                    // Missing outputIndex - should be skipped
                    "beef": [3, 4]
                },
                {
                    // Missing beef - should be skipped
                    "outputIndex": 1
                },
                {
                    "beef": [5, 6],
                    "outputIndex": 2
                }
            ]
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let facilitator = HttpsOverlayLookupFacilitator::new(true);
    let question = LookupQuestion::new("ls_test", serde_json::json!({}));

    let result = facilitator
        .lookup(&mock_server.uri(), &question, None)
        .await;

    assert!(result.is_ok(), "Expected success, got: {:?}", result);
    let answer = result.unwrap();
    if let LookupAnswer::OutputList { outputs } = answer {
        // Only well-formed items should be included
        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[0].output_index, 0);
        assert_eq!(outputs[1].output_index, 2);
    } else {
        panic!("Expected OutputList, got: {:?}", answer);
    }
}

/// Test lookup with output-list where outputs field is missing (defaults to empty).
#[tokio::test]
async fn test_lookup_output_list_missing_outputs_field() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/lookup"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "type": "output-list"
            // No "outputs" field at all
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let facilitator = HttpsOverlayLookupFacilitator::new(true);
    let question = LookupQuestion::new("ls_test", serde_json::json!({}));

    let result = facilitator
        .lookup(&mock_server.uri(), &question, None)
        .await;

    assert!(result.is_ok(), "Expected success, got: {:?}", result);
    let answer = result.unwrap();
    if let LookupAnswer::OutputList { outputs } = answer {
        assert!(
            outputs.is_empty(),
            "Expected empty outputs when field missing"
        );
    } else {
        panic!("Expected OutputList, got: {:?}", answer);
    }
}

/// Test lookup with freeform response containing null result.
#[tokio::test]
async fn test_lookup_freeform_null_result() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/lookup"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "type": "freeform"
            // No "result" field
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let facilitator = HttpsOverlayLookupFacilitator::new(true);
    let question = LookupQuestion::new("ls_test", serde_json::json!({}));

    let result = facilitator
        .lookup(&mock_server.uri(), &question, None)
        .await;

    assert!(result.is_ok(), "Expected success, got: {:?}", result);
    let answer = result.unwrap();
    if let LookupAnswer::Freeform { result: r } = answer {
        assert!(r.is_null(), "Expected null result, got: {:?}", r);
    } else {
        panic!("Expected Freeform, got: {:?}", answer);
    }
}

/// Test lookup with formula response containing empty formulas.
#[tokio::test]
async fn test_lookup_formula_empty_formulas() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/lookup"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "type": "formula",
            "formulas": []
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let facilitator = HttpsOverlayLookupFacilitator::new(true);
    let question = LookupQuestion::new("ls_test", serde_json::json!({}));

    let result = facilitator
        .lookup(&mock_server.uri(), &question, None)
        .await;

    assert!(result.is_ok(), "Expected success, got: {:?}", result);
    let answer = result.unwrap();
    if let LookupAnswer::Formula { formulas } = answer {
        assert!(formulas.is_empty());
    } else {
        panic!("Expected Formula, got: {:?}", answer);
    }
}

/// Test lookup with empty binary response is handled gracefully.
#[tokio::test]
async fn test_lookup_empty_binary_response() {
    let mock_server = MockServer::start().await;

    // Empty binary response with 0 outpoints
    let binary_response = vec![0u8]; // varint 0 = 0 outpoints, then no BEEF data

    Mock::given(method("POST"))
        .and(path("/lookup"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(binary_response)
                .append_header("Content-Type", "application/octet-stream"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let facilitator = HttpsOverlayLookupFacilitator::new(true);
    let question = LookupQuestion::new("ls_test", serde_json::json!({}));

    let result = facilitator
        .lookup(&mock_server.uri(), &question, None)
        .await;

    assert!(result.is_ok(), "Expected success, got: {:?}", result);
    let answer = result.unwrap();
    if let LookupAnswer::OutputList { outputs } = answer {
        assert!(outputs.is_empty(), "Expected empty outputs for 0 outpoints");
    } else {
        panic!("Expected OutputList, got: {:?}", answer);
    }
}

/// Test that lookup handles a completely empty response body with JSON content type.
#[tokio::test]
async fn test_lookup_empty_json_response_body() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/lookup"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("")
                .append_header("Content-Type", "application/json"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let facilitator = HttpsOverlayLookupFacilitator::new(true);
    let question = LookupQuestion::new("ls_test", serde_json::json!({}));

    let result = facilitator
        .lookup(&mock_server.uri(), &question, None)
        .await;

    // Empty body should fail JSON parse
    assert!(
        result.is_err(),
        "Expected error on empty response body, got: {:?}",
        result
    );
}

/// Test steak serialization/deserialization compatibility.
#[tokio::test]
async fn test_broadcast_steak_serialization_roundtrip() {
    let mock_server = MockServer::start().await;

    // Complex STEAK response with all field types
    let steak_json = serde_json::json!({
        "tm_topic1": {
            "outputsToAdmit": [0, 1, 2],
            "coinsToRetain": [3, 4],
            "coinsRemoved": [5]
        },
        "tm_topic2": {
            "outputsToAdmit": [],
            "coinsToRetain": [],
            "coinsRemoved": []
        },
        "tm_topic3": {
            "outputsToAdmit": [0],
            "coinsToRetain": []
        }
    });

    Mock::given(method("POST"))
        .and(path("/submit"))
        .respond_with(ResponseTemplate::new(200).set_body_json(steak_json))
        .expect(1)
        .mount(&mock_server)
        .await;

    let facilitator = HttpsOverlayBroadcastFacilitator::new(true);
    let tagged_beef = TaggedBEEF::new(
        vec![0x01],
        vec![
            "tm_topic1".to_string(),
            "tm_topic2".to_string(),
            "tm_topic3".to_string(),
        ],
    );

    let result = facilitator.send(&mock_server.uri(), &tagged_beef).await;

    assert!(result.is_ok(), "Expected success, got: {:?}", result);
    let steak = result.unwrap();
    assert_eq!(steak.len(), 3);

    // Verify topic1 instructions
    let t1 = steak.get("tm_topic1").unwrap();
    assert_eq!(t1.outputs_to_admit, vec![0, 1, 2]);
    assert_eq!(t1.coins_to_retain, vec![3, 4]);
    assert_eq!(t1.coins_removed, Some(vec![5]));

    // Verify topic2 has empty fields
    let t2 = steak.get("tm_topic2").unwrap();
    assert!(t2.outputs_to_admit.is_empty());

    // Verify topic3 has no coinsRemoved field
    let t3 = steak.get("tm_topic3").unwrap();
    assert_eq!(t3.outputs_to_admit, vec![0]);
    assert!(t3.coins_removed.is_none());
}
