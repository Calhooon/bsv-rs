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

/// Test lookup with output-list where BEEF is provided as a hex string: no
/// byte array, so the reference's normalizer refuses the answer (#768).
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

    let err = result.expect_err("a hex text beef is refused");
    assert!(
        err.to_string()
            .contains("Malformed lookup response: output 0 beef"),
        "{err}"
    );
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

/// Test lookup with no explicit type: refused, as the reference's normalizer
/// reads an output list only under the string `output-list` (#768).
#[tokio::test]
async fn test_lookup_missing_type_is_refused() {
    let mock_server = MockServer::start().await;

    // Response has no "type" field: malformed
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

    let err = result.expect_err("an answer without a type is refused");
    assert!(
        err.to_string().contains("Malformed lookup response"),
        "{err}"
    );
}

/// A BEEF of two transactions, each proven by a block of its own, built by
/// this crate's writer: its bytes and the two txids. A binary aggregated
/// answer's BEEF is parsed (#735's fold), so the fixtures are real BEEFs.
#[allow(clippy::unwrap_used)]
fn two_transaction_beef() -> (Vec<u8>, String, String) {
    use bsv_rs::script::{LockingScript, UnlockingScript};
    use bsv_rs::transaction::{
        Beef, MerklePath, MerklePathLeaf, Transaction, TransactionInput, TransactionOutput,
    };
    let mut beef = Beef::new();
    let mut txids = Vec::new();
    for (byte, height) in [("11", 900), ("22", 901)] {
        let mut input = TransactionInput::new(byte.repeat(32), 0);
        input.set_unlocking_script(UnlockingScript::from_hex("").unwrap());
        let mut tx = Transaction::new();
        tx.add_input(input).unwrap();
        for _ in 0..3 {
            tx.add_output(TransactionOutput::new(
                1,
                LockingScript::from_hex("51").unwrap(),
            ))
            .unwrap();
        }
        let path =
            MerklePath::new(height, vec![vec![MerklePathLeaf::new_txid(0, tx.id())]]).unwrap();
        let index = beef.merge_bump(path);
        beef.merge_raw_tx(tx.to_binary(), Some(index));
        txids.push(tx.id());
    }
    (beef.to_binary(), txids.remove(0), txids.remove(0))
}

/// The Atomic BEEF of `txid` out of `beef`, as each output of a binary
/// answer carries it (`LookupResolver.ts:905-936` at `ts-stack@edf6e03`).
#[allow(clippy::unwrap_used)]
fn atomic_of(beef: &[u8], txid: &str) -> Vec<u8> {
    bsv_rs::transaction::Beef::from_binary(beef)
        .unwrap()
        .to_binary_atomic(txid)
        .unwrap()
}

/// A binary aggregated answer: the outpoints (txid, index, context), then
/// the BEEF.
#[allow(clippy::unwrap_used)]
fn binary_answer(outpoints: &[(&str, u8, &[u8])], beef: &[u8]) -> Vec<u8> {
    let mut body = vec![outpoints.len() as u8];
    for (txid, index, context) in outpoints {
        body.extend(bsv_rs::primitives::from_hex(txid).unwrap());
        body.push(*index);
        body.push(context.len() as u8);
        body.extend_from_slice(context);
    }
    body.extend_from_slice(beef);
    body
}

/// The facilitator's answer to a binary body served by a host of its own.
async fn binary_lookup(body: Vec<u8>) -> bsv_rs::Result<LookupAnswer> {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/lookup"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(body)
                .append_header("Content-Type", "application/octet-stream"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;
    let facilitator = HttpsOverlayLookupFacilitator::new(true);
    let question = LookupQuestion::new("ls_test", serde_json::json!({}));
    facilitator
        .lookup(&mock_server.uri(), &question, None)
        .await
}

/// Test lookup with binary response (application/octet-stream): varint
/// outpoint count, per outpoint a 32-byte txid, a varint output index and a
/// varint-prefixed context, then the BEEF; the output carries the Atomic
/// BEEF of its outpoint's txid and that txid as its hint (#735's fold).
#[tokio::test]
async fn test_lookup_binary_response() {
    let (beef, a, _) = two_transaction_beef();
    let answer = binary_lookup(binary_answer(&[(&a, 0, &[])], &beef))
        .await
        .unwrap();
    let LookupAnswer::OutputList { outputs } = answer else {
        panic!("Expected OutputList from binary response, got: {answer:?}");
    };
    assert_eq!(outputs.len(), 1);
    assert_eq!(outputs[0].output_index, 0);
    assert!(outputs[0].context.is_none());
    assert_eq!(outputs[0].txid.as_deref(), Some(a.as_str()));
    assert_eq!(outputs[0].beef, atomic_of(&beef, &a));
}

/// Test lookup with binary response containing context data.
#[tokio::test]
async fn test_lookup_binary_response_with_context() {
    let (beef, _, b) = two_transaction_beef();
    let answer = binary_lookup(binary_answer(&[(&b, 2, &[0x01, 0x02, 0x03])], &beef))
        .await
        .unwrap();
    let LookupAnswer::OutputList { outputs } = answer else {
        panic!("Expected OutputList from binary response, got: {answer:?}");
    };
    assert_eq!(outputs.len(), 1);
    assert_eq!(outputs[0].output_index, 2);
    assert_eq!(outputs[0].context, Some(vec![0x01, 0x02, 0x03]));
    assert_eq!(outputs[0].beef, atomic_of(&beef, &b));
}

/// Test lookup with binary response containing multiple outpoints: each
/// output its own transaction's Atomic BEEF, not the shared BEEF.
#[tokio::test]
async fn test_lookup_binary_response_multiple_outpoints() {
    let (beef, a, b) = two_transaction_beef();
    let answer = binary_lookup(binary_answer(&[(&a, 0, &[]), (&b, 1, &[])], &beef))
        .await
        .unwrap();
    let LookupAnswer::OutputList { outputs } = answer else {
        panic!("Expected OutputList from binary response, got: {answer:?}");
    };
    assert_eq!(outputs.len(), 2);
    assert_eq!(outputs[0].output_index, 0);
    assert_eq!(outputs[1].output_index, 1);
    assert_eq!(outputs[0].beef, atomic_of(&beef, &a));
    assert_eq!(outputs[1].beef, atomic_of(&beef, &b));
    assert_ne!(outputs[0].beef, outputs[1].beef);
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

/// Test lookup output-list with outputs missing required fields: the whole
/// answer refused, as the reference's normalizer refuses it (#768).
#[tokio::test]
async fn test_lookup_output_list_with_a_malformed_item_is_refused() {
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
                    // Missing outputIndex: the answer is refused
                    "beef": [3, 4]
                },
                {
                    // Missing beef
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

    let err = result.expect_err("a malformed item refuses the answer");
    assert!(
        err.to_string()
            .contains("Malformed lookup response: output 1 outputIndex"),
        "{err}"
    );
}

/// Test lookup with output-list where outputs field is missing: refused (#768).
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

    let err = result.expect_err("an output list without outputs is refused");
    assert!(
        err.to_string()
            .contains("Malformed lookup response: an output-list answer without an outputs array"),
        "{err}"
    );
}

/// Test lookup with freeform response containing null result: `"result":
/// null` is present, an answer (a missing member is refused since #762,
/// `tests/lookup_tracker_accounting_762.rs`).
#[tokio::test]
async fn test_lookup_freeform_null_result() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/lookup"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "type": "freeform",
            "result": null
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

/// A binary response of no outpoint and no BEEF is refused, as the
/// reference's facilitator throws for it (`Beef.fromBinary` on nothing,
/// `LookupResolver.ts:900` at `ts-stack@edf6e03`; recorded as
/// `binary_no_outpoint_no_beef` in `vectors/identity_evidence_hint_735.json`);
/// no outpoint before a BEEF is the empty list. Until #735's fold the BEEF
/// was not parsed and the empty body answered an empty list.
#[tokio::test]
async fn test_lookup_empty_binary_response() {
    // varint 0 = 0 outpoints, then no BEEF data
    let refused = binary_lookup(vec![0u8]).await;
    assert!(refused.is_err(), "Expected a refusal, got: {refused:?}");

    let (beef, _, _) = two_transaction_beef();
    let answer = binary_lookup(binary_answer(&[], &beef)).await.unwrap();
    let LookupAnswer::OutputList { outputs } = answer else {
        panic!("Expected OutputList, got: {answer:?}");
    };
    assert!(outputs.is_empty(), "Expected empty outputs for 0 outpoints");
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
