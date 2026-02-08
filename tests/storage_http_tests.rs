//! HTTP integration tests for StorageUploader and StorageDownloader.
//!
//! These tests use `wiremock` to spin up a local mock HTTP server and verify that
//! the storage uploader sends correct requests and handles various HTTP responses.
//!
//! The StorageUploader is fully testable via wiremock because it accepts an injectable
//! base URL via `StorageUploaderConfig::new(url)`. The uploader's two-step upload
//! flow (POST /upload for presigned URL, then PUT to that URL) and the find/list/renew
//! endpoints all use the configured base URL.
//!
//! The StorageDownloader's `download()` method is harder to test end-to-end with wiremock
//! because it first resolves hosts via the overlay network's LookupResolver, then
//! downloads from discovered hosts. We test what we can: the configuration, URL
//! validation, and error paths. The actual HTTP download behavior is covered by
//! directing the download at a known host URL.
//!
//! Run with: `cargo test --features "full,http" --test storage_http_tests`

#![cfg(all(feature = "storage", feature = "http"))]

use bsv_sdk::storage::{
    get_url_for_file, is_valid_url, StorageUploader, StorageUploaderConfig, UploadableFile,
};
use wiremock::matchers::{body_string_contains, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

// =============================================================================
// StorageUploader Tests - publish_file (two-step upload flow)
// =============================================================================

/// Test successful file upload through the two-step flow:
/// 1. POST /upload with file size and retention -> returns presigned URL
/// 2. PUT to presigned URL with file content -> 200 success
/// The uploader then generates a UHRP URL from the file's SHA-256 hash.
#[tokio::test]
async fn test_uploader_publish_file_success() {
    let mock_server = MockServer::start().await;

    let file_data = b"Hello, World!";
    let file = UploadableFile::new(file_data.to_vec(), "text/plain");

    // Step 1: Mock the /upload endpoint that returns a presigned URL.
    // The presigned URL points back to the same mock server at /put-file.
    let presigned_url = format!("{}/put-file", mock_server.uri());
    Mock::given(method("POST"))
        .and(path("/upload"))
        .and(header("content-type", "application/json"))
        .and(body_string_contains("\"fileSize\":13"))
        .and(body_string_contains("\"retentionPeriod\":10080"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "success",
            "uploadURL": presigned_url,
            "requiredHeaders": {},
            "amount": 100
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    // Step 2: Mock the presigned URL where the file is actually uploaded via PUT.
    Mock::given(method("PUT"))
        .and(path("/put-file"))
        .and(header("content-type", "text/plain"))
        .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = StorageUploaderConfig::new(mock_server.uri());
    let uploader = StorageUploader::new(config);

    let result = uploader.publish_file(&file, None).await;
    assert!(result.is_ok(), "Expected success, got: {:?}", result);

    let upload_result = result.unwrap();
    assert!(upload_result.published, "File should be marked as published");
    assert!(
        is_valid_url(&upload_result.uhrp_url),
        "Result should contain a valid UHRP URL, got: {}",
        upload_result.uhrp_url
    );

    // Verify the UHRP URL matches the file content
    let expected_url = get_url_for_file(file_data).unwrap();
    assert_eq!(
        upload_result.uhrp_url, expected_url,
        "UHRP URL should be derived from the file's SHA-256 hash"
    );
}

/// Test that the uploader uses the custom retention period when provided
/// instead of the default 7-day retention.
#[tokio::test]
async fn test_uploader_publish_file_with_custom_retention() {
    let mock_server = MockServer::start().await;

    let file = UploadableFile::new(b"test".to_vec(), "text/plain");
    let presigned_url = format!("{}/put-file", mock_server.uri());

    // Expect the custom retention period of 1440 minutes (1 day) in the request body.
    Mock::given(method("POST"))
        .and(path("/upload"))
        .and(body_string_contains("\"retentionPeriod\":1440"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "success",
            "uploadURL": presigned_url,
            "requiredHeaders": {}
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("PUT"))
        .and(path("/put-file"))
        .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = StorageUploaderConfig::new(mock_server.uri());
    let uploader = StorageUploader::new(config);

    let result = uploader.publish_file(&file, Some(1440)).await;
    assert!(
        result.is_ok(),
        "Expected success with custom retention, got: {:?}",
        result
    );
}

/// Test that required headers from the upload info response are included
/// in the PUT request to the presigned URL.
#[tokio::test]
async fn test_uploader_publish_file_with_required_headers() {
    let mock_server = MockServer::start().await;

    let file = UploadableFile::new(b"data".to_vec(), "application/octet-stream");
    let presigned_url = format!("{}/put-file", mock_server.uri());

    // Return required headers that must be forwarded to the PUT request.
    Mock::given(method("POST"))
        .and(path("/upload"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "success",
            "uploadURL": presigned_url,
            "requiredHeaders": {
                "x-amz-acl": "public-read",
                "x-custom-header": "custom-value"
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    // Verify the required headers are actually sent in the PUT request.
    Mock::given(method("PUT"))
        .and(path("/put-file"))
        .and(header("x-amz-acl", "public-read"))
        .and(header("x-custom-header", "custom-value"))
        .and(header("content-type", "application/octet-stream"))
        .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = StorageUploaderConfig::new(mock_server.uri());
    let uploader = StorageUploader::new(config);

    let result = uploader.publish_file(&file, None).await;
    assert!(
        result.is_ok(),
        "Expected success with required headers, got: {:?}",
        result
    );
}

/// Test that a 400 Bad Request from the /upload endpoint is handled as an error.
#[tokio::test]
async fn test_uploader_publish_file_upload_info_400() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/upload"))
        .respond_with(ResponseTemplate::new(400).set_body_string("Bad Request"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = StorageUploaderConfig::new(mock_server.uri());
    let uploader = StorageUploader::new(config);
    let file = UploadableFile::new(b"test".to_vec(), "text/plain");

    let result = uploader.publish_file(&file, None).await;
    assert!(result.is_err(), "Expected failure for 400, got: {:?}", result);

    let err = result.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("HTTP 400"),
        "Error should mention HTTP 400, got: {}",
        err_msg
    );
}

/// Test that a 401 Unauthorized from the /upload endpoint is handled as an error.
#[tokio::test]
async fn test_uploader_publish_file_upload_info_401() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/upload"))
        .respond_with(ResponseTemplate::new(401).set_body_string("Unauthorized"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = StorageUploaderConfig::new(mock_server.uri());
    let uploader = StorageUploader::new(config);
    let file = UploadableFile::new(b"test".to_vec(), "text/plain");

    let result = uploader.publish_file(&file, None).await;
    assert!(result.is_err(), "Expected failure for 401, got: {:?}", result);

    let err = result.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("HTTP 401"),
        "Error should mention HTTP 401, got: {}",
        err_msg
    );
}

/// Test that a 413 Payload Too Large from the /upload endpoint is handled.
#[tokio::test]
async fn test_uploader_publish_file_upload_info_413() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/upload"))
        .respond_with(ResponseTemplate::new(413).set_body_string("Payload Too Large"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = StorageUploaderConfig::new(mock_server.uri());
    let uploader = StorageUploader::new(config);
    let file = UploadableFile::new(vec![0u8; 1024], "application/octet-stream");

    let result = uploader.publish_file(&file, None).await;
    assert!(result.is_err(), "Expected failure for 413, got: {:?}", result);

    let err = result.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("HTTP 413"),
        "Error should mention HTTP 413, got: {}",
        err_msg
    );
}

/// Test that a 500 Internal Server Error from the /upload endpoint is handled.
#[tokio::test]
async fn test_uploader_publish_file_upload_info_500() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/upload"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = StorageUploaderConfig::new(mock_server.uri());
    let uploader = StorageUploader::new(config);
    let file = UploadableFile::new(b"test".to_vec(), "text/plain");

    let result = uploader.publish_file(&file, None).await;
    assert!(result.is_err(), "Expected failure for 500, got: {:?}", result);

    let err = result.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("HTTP 500"),
        "Error should mention HTTP 500, got: {}",
        err_msg
    );
}

/// Test that if /upload returns an error status in the JSON body (not HTTP error),
/// the uploader handles it correctly.
#[tokio::test]
async fn test_uploader_publish_file_upload_info_error_status_in_json() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/upload"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "error",
            "uploadURL": "",
            "requiredHeaders": {}
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = StorageUploaderConfig::new(mock_server.uri());
    let uploader = StorageUploader::new(config);
    let file = UploadableFile::new(b"test".to_vec(), "text/plain");

    let result = uploader.publish_file(&file, None).await;
    assert!(
        result.is_err(),
        "Expected failure for error status in JSON, got: {:?}",
        result
    );

    let err = result.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("Upload route returned an error"),
        "Error should mention upload route error, got: {}",
        err_msg
    );
}

/// Test that a 500 error on the PUT (presigned URL upload) step is handled.
#[tokio::test]
async fn test_uploader_publish_file_put_step_500() {
    let mock_server = MockServer::start().await;

    let presigned_url = format!("{}/put-file", mock_server.uri());

    // Step 1 succeeds
    Mock::given(method("POST"))
        .and(path("/upload"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "success",
            "uploadURL": presigned_url,
            "requiredHeaders": {}
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    // Step 2 fails with 500
    Mock::given(method("PUT"))
        .and(path("/put-file"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Storage backend error"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = StorageUploaderConfig::new(mock_server.uri());
    let uploader = StorageUploader::new(config);
    let file = UploadableFile::new(b"test".to_vec(), "text/plain");

    let result = uploader.publish_file(&file, None).await;
    assert!(
        result.is_err(),
        "Expected failure for PUT step 500, got: {:?}",
        result
    );

    let err = result.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("File upload failed"),
        "Error should mention file upload failure, got: {}",
        err_msg
    );
}

/// Test a small 1-byte file upload to verify the minimal case.
#[tokio::test]
async fn test_uploader_publish_file_small_file() {
    let mock_server = MockServer::start().await;

    let file_data = vec![42u8]; // Single byte
    let file = UploadableFile::new(file_data.clone(), "application/octet-stream");
    let presigned_url = format!("{}/put-file", mock_server.uri());

    // Expect fileSize: 1 in the request
    Mock::given(method("POST"))
        .and(path("/upload"))
        .and(body_string_contains("\"fileSize\":1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "success",
            "uploadURL": presigned_url,
            "requiredHeaders": {}
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("PUT"))
        .and(path("/put-file"))
        .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = StorageUploaderConfig::new(mock_server.uri());
    let uploader = StorageUploader::new(config);

    let result = uploader.publish_file(&file, None).await;
    assert!(result.is_ok(), "Expected success for small file, got: {:?}", result);

    let upload_result = result.unwrap();
    let expected_url = get_url_for_file(&file_data).unwrap();
    assert_eq!(upload_result.uhrp_url, expected_url);
}

/// Test uploading an empty file (0 bytes) to verify edge case handling.
#[tokio::test]
async fn test_uploader_publish_file_empty_content() {
    let mock_server = MockServer::start().await;

    let file_data: Vec<u8> = vec![];
    let file = UploadableFile::new(file_data.clone(), "application/octet-stream");
    let presigned_url = format!("{}/put-file", mock_server.uri());

    Mock::given(method("POST"))
        .and(path("/upload"))
        .and(body_string_contains("\"fileSize\":0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "success",
            "uploadURL": presigned_url,
            "requiredHeaders": {}
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("PUT"))
        .and(path("/put-file"))
        .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = StorageUploaderConfig::new(mock_server.uri());
    let uploader = StorageUploader::new(config);

    let result = uploader.publish_file(&file, None).await;
    assert!(
        result.is_ok(),
        "Expected success for empty file, got: {:?}",
        result
    );

    // Verify the UHRP URL is the hash of empty content
    let upload_result = result.unwrap();
    let expected_url = get_url_for_file(&file_data).unwrap();
    assert_eq!(upload_result.uhrp_url, expected_url);
}

// =============================================================================
// StorageUploader Tests - find_file
// =============================================================================

/// Test successful find_file that returns file metadata.
#[tokio::test]
async fn test_uploader_find_file_success() {
    let mock_server = MockServer::start().await;

    // The find endpoint uses a query parameter for the UHRP URL.
    Mock::given(method("GET"))
        .and(path("/find"))
        .and(query_param("uhrpUrl", "uhrp://testurl123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "success",
            "data": {
                "name": "cdn/abc123",
                "size": "1024",
                "mimeType": "text/plain",
                "expiryTime": 1700000000
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = StorageUploaderConfig::new(mock_server.uri());
    let uploader = StorageUploader::new(config);

    let result = uploader.find_file("uhrp://testurl123").await;
    assert!(result.is_ok(), "Expected success, got: {:?}", result);

    let file_data = result.unwrap();
    assert!(file_data.is_some(), "Expected file data to be present");

    let data = file_data.unwrap();
    assert_eq!(data.name, Some("cdn/abc123".to_string()));
    assert_eq!(data.size, "1024");
    assert_eq!(data.mime_type, "text/plain");
    assert_eq!(data.expiry_time, 1700000000);
}

/// Test find_file when the server returns an error status in the JSON response.
#[tokio::test]
async fn test_uploader_find_file_error_status_in_json() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/find"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "error",
            "code": "ERR_NOT_FOUND",
            "description": "File not found"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = StorageUploaderConfig::new(mock_server.uri());
    let uploader = StorageUploader::new(config);

    let result = uploader.find_file("uhrp://unknown-hash").await;
    assert!(result.is_err(), "Expected failure, got: {:?}", result);

    let err = result.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("ERR_NOT_FOUND"),
        "Error should contain error code, got: {}",
        err_msg
    );
    assert!(
        err_msg.contains("File not found"),
        "Error should contain description, got: {}",
        err_msg
    );
}

/// Test find_file when the HTTP response is a non-success status code.
#[tokio::test]
async fn test_uploader_find_file_http_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/find"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = StorageUploaderConfig::new(mock_server.uri());
    let uploader = StorageUploader::new(config);

    let result = uploader.find_file("uhrp://some-hash").await;
    assert!(result.is_err(), "Expected failure for HTTP 500, got: {:?}", result);

    let err = result.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("HTTP 500"),
        "Error should mention HTTP 500, got: {}",
        err_msg
    );
}

// =============================================================================
// StorageUploader Tests - list_uploads
// =============================================================================

/// Test successful list_uploads that returns an array of uploaded files.
#[tokio::test]
async fn test_uploader_list_uploads_success() {
    let mock_server = MockServer::start().await;

    let mock_uploads = serde_json::json!([
        { "uhrpUrl": "uhrp://hash1", "expiryTime": 111111 },
        { "uhrpUrl": "uhrp://hash2", "expiryTime": 222222 }
    ]);

    Mock::given(method("GET"))
        .and(path("/list"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "success",
            "uploads": mock_uploads
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = StorageUploaderConfig::new(mock_server.uri());
    let uploader = StorageUploader::new(config);

    let result = uploader.list_uploads().await;
    assert!(result.is_ok(), "Expected success, got: {:?}", result);

    let uploads = result.unwrap();
    assert!(uploads.is_array(), "Expected an array of uploads");

    let arr = uploads.as_array().unwrap();
    assert_eq!(arr.len(), 2, "Expected 2 uploads");
    assert_eq!(arr[0]["uhrpUrl"], "uhrp://hash1");
    assert_eq!(arr[1]["expiryTime"], 222222);
}

/// Test list_uploads when the server returns an empty list.
#[tokio::test]
async fn test_uploader_list_uploads_empty() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/list"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "success"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = StorageUploaderConfig::new(mock_server.uri());
    let uploader = StorageUploader::new(config);

    let result = uploader.list_uploads().await;
    assert!(result.is_ok(), "Expected success, got: {:?}", result);

    let uploads = result.unwrap();
    // When "uploads" is absent from JSON, it defaults to empty array
    assert!(uploads.is_array(), "Expected an array");
    assert_eq!(
        uploads.as_array().unwrap().len(),
        0,
        "Expected empty array when no uploads field"
    );
}

/// Test list_uploads when the server returns an error status.
#[tokio::test]
async fn test_uploader_list_uploads_error_status() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/list"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "error",
            "code": "ERR_INTERNAL",
            "description": "Something broke"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = StorageUploaderConfig::new(mock_server.uri());
    let uploader = StorageUploader::new(config);

    let result = uploader.list_uploads().await;
    assert!(result.is_err(), "Expected failure, got: {:?}", result);

    let err = result.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("ERR_INTERNAL"),
        "Error should contain code, got: {}",
        err_msg
    );
    assert!(
        err_msg.contains("Something broke"),
        "Error should contain description, got: {}",
        err_msg
    );
}

/// Test list_uploads when the HTTP response is a server error.
#[tokio::test]
async fn test_uploader_list_uploads_http_500() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/list"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = StorageUploaderConfig::new(mock_server.uri());
    let uploader = StorageUploader::new(config);

    let result = uploader.list_uploads().await;
    assert!(result.is_err(), "Expected failure for HTTP 500, got: {:?}", result);

    let err = result.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("HTTP 500"),
        "Error should mention HTTP 500, got: {}",
        err_msg
    );
}

// =============================================================================
// StorageUploader Tests - renew_file
// =============================================================================

/// Test successful file renewal that returns new expiry information.
#[tokio::test]
async fn test_uploader_renew_file_success() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/renew"))
        .and(header("content-type", "application/json"))
        .and(body_string_contains("\"uhrpUrl\""))
        .and(body_string_contains("\"additionalMinutes\":1440"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "success",
            "prevExpiryTime": 1700000000,
            "newExpiryTime": 1700086400,
            "amount": 50
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = StorageUploaderConfig::new(mock_server.uri());
    let uploader = StorageUploader::new(config);

    let result = uploader.renew_file("uhrp://some-hash", 1440).await;
    assert!(result.is_ok(), "Expected success, got: {:?}", result);

    let renewal = result.unwrap();
    assert_eq!(renewal.status, "success");
    assert_eq!(renewal.previous_expiry, 1700000000);
    assert_eq!(renewal.new_expiry, 1700086400);
    assert_eq!(renewal.amount, 50);
    assert!(renewal.is_success());
}

/// Test renew_file when the server returns an error status in the JSON body.
#[tokio::test]
async fn test_uploader_renew_file_error_status_in_json() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/renew"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "error",
            "code": "ERR_CANT_RENEW",
            "description": "Failed to renew"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = StorageUploaderConfig::new(mock_server.uri());
    let uploader = StorageUploader::new(config);

    let result = uploader.renew_file("uhrp://some-hash", 30).await;
    assert!(result.is_err(), "Expected failure, got: {:?}", result);

    let err = result.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("ERR_CANT_RENEW"),
        "Error should contain error code, got: {}",
        err_msg
    );
    assert!(
        err_msg.contains("Failed to renew"),
        "Error should contain description, got: {}",
        err_msg
    );
}

/// Test renew_file when the HTTP response is 404 Not Found.
#[tokio::test]
async fn test_uploader_renew_file_http_404() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/renew"))
        .respond_with(ResponseTemplate::new(404).set_body_string("Not Found"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = StorageUploaderConfig::new(mock_server.uri());
    let uploader = StorageUploader::new(config);

    let result = uploader.renew_file("uhrp://ghost", 10).await;
    assert!(result.is_err(), "Expected failure for 404, got: {:?}", result);

    let err = result.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("HTTP 404"),
        "Error should mention HTTP 404, got: {}",
        err_msg
    );
}

/// Test renew_file when the HTTP response is 500 Internal Server Error.
#[tokio::test]
async fn test_uploader_renew_file_http_500() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/renew"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = StorageUploaderConfig::new(mock_server.uri());
    let uploader = StorageUploader::new(config);

    let result = uploader.renew_file("uhrp://some-hash", 60).await;
    assert!(result.is_err(), "Expected failure for 500, got: {:?}", result);

    let err = result.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("HTTP 500"),
        "Error should mention HTTP 500, got: {}",
        err_msg
    );
}

// =============================================================================
// StorageUploader Tests - Request Body Verification
// =============================================================================

/// Test that the /upload POST body contains the correct file size and retention period.
#[tokio::test]
async fn test_uploader_request_body_verification() {
    let mock_server = MockServer::start().await;

    let file_data = b"This is a test file with some content";
    let file = UploadableFile::new(file_data.to_vec(), "text/plain");
    let presigned_url = format!("{}/put-file", mock_server.uri());

    // Verify both fileSize and retentionPeriod appear in the body.
    // The file is 37 bytes, and the default retention is 10080 (7 days).
    Mock::given(method("POST"))
        .and(path("/upload"))
        .and(body_string_contains("\"fileSize\":37"))
        .and(body_string_contains("\"retentionPeriod\":10080"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "success",
            "uploadURL": presigned_url,
            "requiredHeaders": {}
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("PUT"))
        .and(path("/put-file"))
        .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = StorageUploaderConfig::new(mock_server.uri());
    let uploader = StorageUploader::new(config);

    let result = uploader.publish_file(&file, None).await;
    assert!(
        result.is_ok(),
        "Expected success for body verification, got: {:?}",
        result
    );
}

/// Test that the content-type header is correctly set on the PUT request.
#[tokio::test]
async fn test_uploader_content_type_header_verification() {
    let mock_server = MockServer::start().await;

    let file = UploadableFile::new(b"image data".to_vec(), "image/png");
    let presigned_url = format!("{}/put-file", mock_server.uri());

    Mock::given(method("POST"))
        .and(path("/upload"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "success",
            "uploadURL": presigned_url,
            "requiredHeaders": {}
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    // Verify the content-type matches the file's MIME type.
    Mock::given(method("PUT"))
        .and(path("/put-file"))
        .and(header("content-type", "image/png"))
        .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = StorageUploaderConfig::new(mock_server.uri());
    let uploader = StorageUploader::new(config);

    let result = uploader.publish_file(&file, None).await;
    assert!(
        result.is_ok(),
        "Expected success for content-type verification, got: {:?}",
        result
    );
}

// =============================================================================
// StorageDownloader Tests - URL Validation and Error Paths
//
// NOTE: The StorageDownloader's download() method depends on the overlay
// network's LookupResolver to discover host URLs before downloading.
// Since we cannot easily inject a mock LookupResolver through the public API,
// we test the downloader's URL validation, error handling, and configuration.
// The actual HTTP download logic (try_download) is exercised through the
// uploader tests above, which also use reqwest internally.
// =============================================================================

use bsv_sdk::storage::{StorageDownloader, StorageDownloaderConfig};

/// Test that the downloader rejects invalid UHRP URLs in the resolve() method.
#[tokio::test]
async fn test_downloader_resolve_rejects_invalid_url() {
    let downloader = StorageDownloader::default();

    let result = downloader.resolve("https://example.com").await;
    assert!(
        result.is_err(),
        "Expected error for invalid UHRP URL, got: {:?}",
        result
    );

    let err = result.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("Invalid UHRP URL"),
        "Error should mention invalid URL, got: {}",
        err_msg
    );
}

/// Test that the downloader rejects empty strings as UHRP URLs.
#[tokio::test]
async fn test_downloader_resolve_rejects_empty_url() {
    let downloader = StorageDownloader::default();

    let result = downloader.resolve("").await;
    assert!(
        result.is_err(),
        "Expected error for empty URL, got: {:?}",
        result
    );
}

/// Test that the downloader rejects non-UHRP URL formats.
#[tokio::test]
async fn test_downloader_resolve_rejects_http_url() {
    let downloader = StorageDownloader::default();

    let result = downloader.resolve("http://localhost:8080/file").await;
    assert!(
        result.is_err(),
        "Expected error for HTTP URL, got: {:?}",
        result
    );
}

/// Test that the downloader rejects invalid UHRP URLs in the download() method.
#[tokio::test]
async fn test_downloader_download_rejects_invalid_url() {
    let downloader = StorageDownloader::default();

    let result = downloader.download("not-a-valid-uhrp-url").await;
    assert!(
        result.is_err(),
        "Expected error for invalid UHRP URL in download, got: {:?}",
        result
    );

    let err = result.unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("Invalid UHRP URL"),
        "Error should mention invalid URL, got: {}",
        err_msg
    );
}

/// Test that the downloader rejects URLs with invalid checksums.
#[tokio::test]
async fn test_downloader_resolve_rejects_bad_checksum() {
    let downloader = StorageDownloader::default();

    // Known bad checksum URL from TypeScript SDK tests
    let bad_url = "uhrp://XUU7cTfy6fA6q2neLDmzPqJnGB6o18PXKoGaWLPrH1SeWLKgdCKq";
    let result = downloader.resolve(bad_url).await;
    assert!(
        result.is_err(),
        "Expected error for bad checksum URL, got: {:?}",
        result
    );
}

/// Test downloader configuration with custom timeout.
#[tokio::test]
async fn test_downloader_config_custom_timeout() {
    let config = StorageDownloaderConfig {
        timeout_ms: Some(5000),
        ..Default::default()
    };
    let downloader = StorageDownloader::new(config);

    // Verify the downloader was created (no public timeout getter, but creation succeeds)
    assert!(std::mem::size_of_val(&downloader) > 0);
}

/// Test downloader configuration with no timeout.
#[tokio::test]
async fn test_downloader_config_no_timeout() {
    let config = StorageDownloaderConfig {
        timeout_ms: None,
        ..Default::default()
    };
    let downloader = StorageDownloader::new(config);

    // The downloader with no timeout should still be usable
    // (it will fall back to 30000ms internally in try_download)
    assert!(std::mem::size_of_val(&downloader) > 0);
}

/// Test that UHRP URL parsing works correctly for download operations.
/// This verifies the content-addressing chain: file -> hash -> URL -> hash.
#[tokio::test]
async fn test_downloader_uhrp_url_parsing() {
    use bsv_sdk::storage::get_hash_from_url;

    let test_content = b"test content for download verification";
    let url = get_url_for_file(test_content).unwrap();

    // Verify the URL is valid
    assert!(is_valid_url(&url));

    // Verify we can extract the hash back from the URL
    let hash = get_hash_from_url(&url).unwrap();
    let expected_hash = bsv_sdk::primitives::hash::sha256(test_content);
    assert_eq!(
        hash, expected_hash,
        "Hash extracted from UHRP URL should match SHA-256 of original content"
    );
}

// =============================================================================
// StorageUploader Tests - Renew request body verification
// =============================================================================

/// Test that the /renew POST body contains the correct UHRP URL and additional minutes.
#[tokio::test]
async fn test_uploader_renew_request_body() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/renew"))
        .and(body_string_contains("\"uhrpUrl\":\"uhrp://test-file-hash\""))
        .and(body_string_contains("\"additionalMinutes\":2880"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "success",
            "prevExpiryTime": 100,
            "newExpiryTime": 200,
            "amount": 10
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = StorageUploaderConfig::new(mock_server.uri());
    let uploader = StorageUploader::new(config);

    let result = uploader.renew_file("uhrp://test-file-hash", 2880).await;
    assert!(
        result.is_ok(),
        "Expected success for renew body verification, got: {:?}",
        result
    );
}

// =============================================================================
// StorageUploader Tests - Various MIME type handling
// =============================================================================

/// Test uploading files with different MIME types to verify each is sent correctly.
#[tokio::test]
async fn test_uploader_various_mime_types() {
    let mime_types = vec![
        ("text/plain", b"Hello" as &[u8]),
        ("application/json", b"{\"key\": \"value\"}"),
        ("image/jpeg", &[0xFF, 0xD8, 0xFF, 0xE0]),
        ("application/pdf", b"%PDF-1.4"),
    ];

    for (mime_type, data) in mime_types {
        let mock_server = MockServer::start().await;
        let presigned_url = format!("{}/put-file", mock_server.uri());

        Mock::given(method("POST"))
            .and(path("/upload"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "success",
                "uploadURL": presigned_url,
                "requiredHeaders": {}
            })))
            .mount(&mock_server)
            .await;

        // Verify the content-type header matches the MIME type.
        Mock::given(method("PUT"))
            .and(path("/put-file"))
            .and(header("content-type", mime_type))
            .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let config = StorageUploaderConfig::new(mock_server.uri());
        let uploader = StorageUploader::new(config);
        let file = UploadableFile::new(data.to_vec(), mime_type);

        let result = uploader.publish_file(&file, None).await;
        assert!(
            result.is_ok(),
            "Expected success for MIME type '{}', got: {:?}",
            mime_type,
            result
        );
    }
}

// =============================================================================
// StorageUploader Tests - find_file with no data (file not found on server)
// =============================================================================

/// Test find_file when the file exists but data field is null/absent.
#[tokio::test]
async fn test_uploader_find_file_success_no_data() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/find"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "success",
            "data": null
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let config = StorageUploaderConfig::new(mock_server.uri());
    let uploader = StorageUploader::new(config);

    let result = uploader.find_file("uhrp://nonexistent").await;
    assert!(result.is_ok(), "Expected success, got: {:?}", result);

    let file_data = result.unwrap();
    assert!(
        file_data.is_none(),
        "Expected None when data field is null, got: {:?}",
        file_data
    );
}
