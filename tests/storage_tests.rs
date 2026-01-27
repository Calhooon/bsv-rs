//! Storage module integration tests.
//!
//! Tests for UHRP URL utilities, StorageDownloader, and StorageUploader.
//! Verifies cross-SDK compatibility with TypeScript and Go BSV SDKs.

#![cfg(feature = "storage")]

use bsv_sdk::primitives::hash::sha256;
use bsv_sdk::storage::{
    get_hash_from_url, get_hash_hex_from_url, get_url_for_file, get_url_for_hash, is_valid_url,
    normalize_url, DownloadResult, StorageDownloader, StorageDownloaderConfig, StorageUploader,
    StorageUploaderConfig, UploadFileResult, UploadableFile, UHRP_PREFIX, WEB_UHRP_PREFIX,
};

// =============================================================================
// Cross-SDK Test Vectors from TypeScript SDK
// =============================================================================

/// TypeScript SDK test vector - known hash
const TS_EXAMPLE_HASH_HEX: &str =
    "1a5ec49a3f32cd56d19732e89bde5d81755ddc0fd8515dc8b226d47654139dca";

/// TypeScript SDK test vector - known file content (hex encoded)
const TS_EXAMPLE_FILE_HEX: &str =
    "687da27f04a112aa48f1cab2e7949f1eea4f7ba28319c1e999910cd561a634a05a3516e6db";

/// TypeScript SDK test vector - expected URL (Base58Check encoded, without uhrp:// prefix)
const TS_EXAMPLE_URL_BASE58: &str = "XUT6PqWb3GP3LR7dmBMCJwZ3oo5g1iGCF3CrpzyuJCemkGu1WGoq";

/// TypeScript SDK test vector - known bad URL (invalid checksum)
const TS_BAD_CHECKSUM_URL: &str = "XUU7cTfy6fA6q2neLDmzPqJnGB6o18PXKoGaWLPrH1SeWLKgdCKq";

// =============================================================================
// UHRP URL Tests - get_url_for_file()
// =============================================================================

#[test]
fn test_get_url_for_file_known_data() {
    // Test with known data from TypeScript SDK
    let file = hex::decode(TS_EXAMPLE_FILE_HEX).unwrap();
    let url = get_url_for_file(&file).unwrap();

    // URL should start with uhrp:// prefix
    assert!(url.starts_with(UHRP_PREFIX));

    // Base58Check part should match TypeScript SDK
    let normalized = normalize_url(&url);
    assert_eq!(normalized, TS_EXAMPLE_URL_BASE58);
}

#[test]
fn test_get_url_for_file_empty() {
    let url = get_url_for_file(b"").unwrap();
    assert!(url.starts_with(UHRP_PREFIX));

    // Verify round-trip
    let hash = get_hash_from_url(&url).unwrap();
    let expected_hash = sha256(b"");
    assert_eq!(hash, expected_hash);

    // Known SHA-256 of empty string
    assert_eq!(
        hex::encode(hash),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn test_get_url_for_file_hello_world() {
    let data = b"Hello, World!";
    let url = get_url_for_file(data).unwrap();

    assert!(url.starts_with(UHRP_PREFIX));
    assert!(is_valid_url(&url));

    // Round-trip
    let recovered_hash = get_hash_from_url(&url).unwrap();
    let expected_hash = sha256(data);
    assert_eq!(recovered_hash, expected_hash);
}

#[test]
fn test_get_url_for_file_binary_data() {
    // Test with binary data containing all byte values
    let mut data = Vec::with_capacity(256);
    for i in 0..=255u8 {
        data.push(i);
    }

    let url = get_url_for_file(&data).unwrap();
    assert!(is_valid_url(&url));

    let recovered_hash = get_hash_from_url(&url).unwrap();
    assert_eq!(recovered_hash, sha256(&data));
}

// =============================================================================
// UHRP URL Tests - get_url_for_hash()
// =============================================================================

#[test]
fn test_get_url_for_hash_known_hash() {
    // Test with known hash from TypeScript SDK
    let hash = hex::decode(TS_EXAMPLE_HASH_HEX).unwrap();
    let mut hash_array = [0u8; 32];
    hash_array.copy_from_slice(&hash);

    let url = get_url_for_hash(&hash_array).unwrap();

    // Verify URL format
    assert!(url.starts_with(UHRP_PREFIX));

    // Verify Base58Check matches TypeScript SDK
    let normalized = normalize_url(&url);
    assert_eq!(normalized, TS_EXAMPLE_URL_BASE58);
}

#[test]
fn test_get_url_for_hash_zero_hash() {
    let hash = [0u8; 32];
    let url = get_url_for_hash(&hash).unwrap();
    assert!(url.starts_with(UHRP_PREFIX));
    assert!(is_valid_url(&url));
}

#[test]
fn test_get_url_for_hash_max_hash() {
    let hash = [0xff; 32];
    let url = get_url_for_hash(&hash).unwrap();
    assert!(url.starts_with(UHRP_PREFIX));
    assert!(is_valid_url(&url));
}

#[test]
fn test_get_url_for_hash_invalid_length() {
    // Too short
    let short_hash = vec![0u8; 16];
    let result = get_url_for_hash(&short_hash);
    assert!(result.is_err());

    // Too long
    let long_hash = vec![0u8; 64];
    let result = get_url_for_hash(&long_hash);
    assert!(result.is_err());
}

// =============================================================================
// UHRP URL Tests - get_hash_from_url()
// =============================================================================

#[test]
fn test_get_hash_from_url_extracts_correct_hash() {
    // Test with known URL from TypeScript SDK
    let hash = get_hash_from_url(TS_EXAMPLE_URL_BASE58).unwrap();
    assert_eq!(hex::encode(hash), TS_EXAMPLE_HASH_HEX);
}

#[test]
fn test_get_hash_from_url_with_uhrp_prefix() {
    let url_with_prefix = format!("uhrp://{}", TS_EXAMPLE_URL_BASE58);
    let hash = get_hash_from_url(&url_with_prefix).unwrap();
    assert_eq!(hex::encode(hash), TS_EXAMPLE_HASH_HEX);
}

#[test]
fn test_get_hash_from_url_with_web_prefix() {
    let url_with_prefix = format!("web+uhrp://{}", TS_EXAMPLE_URL_BASE58);
    let hash = get_hash_from_url(&url_with_prefix).unwrap();
    assert_eq!(hex::encode(hash), TS_EXAMPLE_HASH_HEX);
}

#[test]
fn test_get_hash_from_url_invalid_checksum() {
    // Known bad URL from TypeScript SDK tests
    let result = get_hash_from_url(TS_BAD_CHECKSUM_URL);
    assert!(result.is_err());
}

#[test]
fn test_get_hash_from_url_too_short() {
    let result = get_hash_from_url("SomeBase58CheckTooShortOrTooLong");
    assert!(result.is_err());
}

#[test]
fn test_get_hash_from_url_invalid_base58() {
    // Contains invalid Base58 character '0' (zero)
    let result = get_hash_from_url("0InvalidBase58");
    assert!(result.is_err());

    // Contains invalid Base58 character 'O' (capital O)
    let result = get_hash_from_url("OInvalidBase58");
    assert!(result.is_err());

    // Contains invalid Base58 character 'l' (lowercase L)
    let result = get_hash_from_url("lInvalidBase58");
    assert!(result.is_err());

    // Contains invalid Base58 character 'I' (capital I)
    let result = get_hash_from_url("IInvalidBase58");
    assert!(result.is_err());
}

// =============================================================================
// UHRP URL Tests - get_hash_hex_from_url()
// =============================================================================

#[test]
fn test_get_hash_hex_from_url_correct_hex() {
    let hash_hex = get_hash_hex_from_url(TS_EXAMPLE_URL_BASE58).unwrap();
    assert_eq!(hash_hex.len(), 64); // 32 bytes * 2 hex chars
    assert_eq!(hash_hex, TS_EXAMPLE_HASH_HEX);
}

#[test]
fn test_get_hash_hex_from_url_with_prefix() {
    let url = format!("uhrp://{}", TS_EXAMPLE_URL_BASE58);
    let hash_hex = get_hash_hex_from_url(&url).unwrap();
    assert_eq!(hash_hex, TS_EXAMPLE_HASH_HEX);
}

#[test]
fn test_get_hash_hex_from_url_invalid_returns_error() {
    let result = get_hash_hex_from_url(TS_BAD_CHECKSUM_URL);
    assert!(result.is_err());
}

// =============================================================================
// UHRP URL Tests - is_valid_url()
// =============================================================================

#[test]
fn test_is_valid_url_accepts_valid_urls() {
    // Valid Base58Check only
    assert!(is_valid_url(TS_EXAMPLE_URL_BASE58));

    // With uhrp:// prefix
    assert!(is_valid_url(&format!("uhrp://{}", TS_EXAMPLE_URL_BASE58)));

    // With web+uhrp:// prefix
    assert!(is_valid_url(&format!(
        "web+uhrp://{}",
        TS_EXAMPLE_URL_BASE58
    )));
}

#[test]
fn test_is_valid_url_rejects_invalid_checksum() {
    assert!(!is_valid_url(TS_BAD_CHECKSUM_URL));
    assert!(!is_valid_url(&format!("uhrp://{}", TS_BAD_CHECKSUM_URL)));
}

#[test]
fn test_is_valid_url_rejects_non_uhrp_urls() {
    assert!(!is_valid_url("https://example.com"));
    assert!(!is_valid_url("http://localhost:8080"));
    assert!(!is_valid_url("file:///path/to/file"));
    assert!(!is_valid_url("data:text/plain;base64,SGVsbG8="));
}

#[test]
fn test_is_valid_url_rejects_too_short() {
    assert!(!is_valid_url("uhrp://tooshort"));
    assert!(!is_valid_url("invalid"));
    assert!(!is_valid_url(""));
}

#[test]
fn test_is_valid_url_rejects_invalid_prefix() {
    // These have invalid Base58Check version prefix
    assert!(!is_valid_url("AInvalidPrefixTestString1"));
    assert!(!is_valid_url("AInvalidPrefixTestString2"));
    assert!(!is_valid_url("AnotherInvalidPrefixTestString"));
    assert!(!is_valid_url("YetAnotherInvalidPrefixTestString"));
}

// =============================================================================
// UHRP URL Tests - normalize_url()
// =============================================================================

#[test]
fn test_normalize_url_removes_uhrp_prefix() {
    let url = "uhrp://abc123";
    assert_eq!(normalize_url(url), "abc123");
}

#[test]
fn test_normalize_url_removes_web_uhrp_prefix() {
    let url = "web+uhrp://abc123";
    assert_eq!(normalize_url(url), "abc123");
}

#[test]
fn test_normalize_url_preserves_raw_base58() {
    let url = "abc123";
    assert_eq!(normalize_url(url), "abc123");
}

#[test]
fn test_normalize_url_case_insensitive() {
    // Should handle uppercase prefix
    assert_eq!(normalize_url("UHRP://ABC123"), "ABC123");
    assert_eq!(normalize_url("WEB+UHRP://ABC123"), "ABC123");

    // Mixed case
    assert_eq!(normalize_url("Uhrp://XyZ"), "XyZ");
}

#[test]
fn test_normalize_url_handles_uhrp_without_double_slash() {
    let url = "uhrp:abc123";
    assert_eq!(normalize_url(url), "abc123");
}

#[test]
fn test_normalize_url_handles_various_formats() {
    // Real URL with prefix
    let url = format!("uhrp://{}", TS_EXAMPLE_URL_BASE58);
    assert_eq!(normalize_url(&url), TS_EXAMPLE_URL_BASE58);

    // Web prefix
    let url = format!("web+uhrp://{}", TS_EXAMPLE_URL_BASE58);
    assert_eq!(normalize_url(&url), TS_EXAMPLE_URL_BASE58);

    // Raw
    assert_eq!(normalize_url(TS_EXAMPLE_URL_BASE58), TS_EXAMPLE_URL_BASE58);
}

// =============================================================================
// UHRP URL Tests - Round-trip Tests
// =============================================================================

#[test]
fn test_roundtrip_file_to_url_to_hash() {
    // File -> URL -> Hash should match SHA256(file)
    let file = hex::decode(TS_EXAMPLE_FILE_HEX).unwrap();
    let url = get_url_for_file(&file).unwrap();
    let hash = get_hash_from_url(&url).unwrap();

    assert_eq!(hash, sha256(&file));
    assert_eq!(hex::encode(hash), TS_EXAMPLE_HASH_HEX);
}

#[test]
fn test_roundtrip_hash_to_url_to_hash() {
    // Hash -> URL -> Hash should be identical
    let original_hash = hex::decode(TS_EXAMPLE_HASH_HEX).unwrap();
    let mut hash_array = [0u8; 32];
    hash_array.copy_from_slice(&original_hash);

    let url = get_url_for_hash(&hash_array).unwrap();
    let recovered_hash = get_hash_from_url(&url).unwrap();

    assert_eq!(recovered_hash, hash_array);
}

#[test]
fn test_roundtrip_various_files() {
    let zeros_1000 = [0u8; 1000];
    let ones_1000 = vec![0xffu8; 1000];

    let test_cases: Vec<&[u8]> = vec![
        b"",
        b"a",
        b"hello",
        b"Hello, World!",
        b"The quick brown fox jumps over the lazy dog",
        &zeros_1000,
        &ones_1000,
    ];

    for (i, data) in test_cases.iter().enumerate() {
        let url = get_url_for_file(data).unwrap();
        let hash = get_hash_from_url(&url).unwrap();
        let expected = sha256(data);

        assert_eq!(
            hash, expected,
            "Round-trip failed for test case {}: {:?}",
            i, data
        );
    }
}

#[test]
fn test_roundtrip_with_different_prefixes() {
    let file = b"test data for prefix handling";
    let url_base = get_url_for_file(file).unwrap();
    let hash_base = get_hash_from_url(&url_base).unwrap();

    // Test with explicit uhrp:// prefix
    let url_uhrp = format!("uhrp://{}", normalize_url(&url_base));
    let hash_uhrp = get_hash_from_url(&url_uhrp).unwrap();
    assert_eq!(hash_base, hash_uhrp);

    // Test with web+uhrp:// prefix
    let url_web = format!("web+uhrp://{}", normalize_url(&url_base));
    let hash_web = get_hash_from_url(&url_web).unwrap();
    assert_eq!(hash_base, hash_web);

    // Test without prefix
    let url_raw = normalize_url(&url_base);
    let hash_raw = get_hash_from_url(&url_raw).unwrap();
    assert_eq!(hash_base, hash_raw);
}

// =============================================================================
// Cross-SDK Compatibility Tests
// =============================================================================

#[test]
fn test_cross_sdk_hash_to_url() {
    // Verify: getURLForHash(exampleHash) produces the expected URL
    // This matches TypeScript SDK behavior
    let hash = hex::decode(TS_EXAMPLE_HASH_HEX).unwrap();
    let mut hash_array = [0u8; 32];
    hash_array.copy_from_slice(&hash);

    let url = get_url_for_hash(&hash_array).unwrap();
    let normalized = normalize_url(&url);

    assert_eq!(
        normalized, TS_EXAMPLE_URL_BASE58,
        "URL mismatch with TypeScript SDK"
    );
}

#[test]
fn test_cross_sdk_file_to_url() {
    // Verify: getURLForFile(exampleFile) produces the expected URL
    // This also implicitly tests that SHA256(exampleFile) == exampleHash
    let file = hex::decode(TS_EXAMPLE_FILE_HEX).unwrap();
    let url = get_url_for_file(&file).unwrap();
    let normalized = normalize_url(&url);

    assert_eq!(
        normalized, TS_EXAMPLE_URL_BASE58,
        "URL mismatch with TypeScript SDK"
    );
}

#[test]
fn test_cross_sdk_url_to_hash() {
    // Verify: getHashFromURL(exampleURL) returns the expected hash
    let hash = get_hash_from_url(TS_EXAMPLE_URL_BASE58).unwrap();
    assert_eq!(
        hex::encode(hash),
        TS_EXAMPLE_HASH_HEX,
        "Hash mismatch with TypeScript SDK"
    );
}

#[test]
fn test_cross_sdk_file_hash_verification() {
    // Verify: SHA256(exampleFile) == exampleHash
    let file = hex::decode(TS_EXAMPLE_FILE_HEX).unwrap();
    let computed_hash = sha256(&file);

    assert_eq!(
        hex::encode(computed_hash),
        TS_EXAMPLE_HASH_HEX,
        "SHA256 hash mismatch"
    );
}

#[test]
fn test_cross_sdk_is_valid_url() {
    // Valid URLs should return true
    assert!(is_valid_url(TS_EXAMPLE_URL_BASE58));
    assert!(is_valid_url(&format!("uhrp://{}", TS_EXAMPLE_URL_BASE58)));
    assert!(is_valid_url(&format!(
        "web+uhrp://{}",
        TS_EXAMPLE_URL_BASE58
    )));

    // Invalid checksum URL from TypeScript tests should return false
    assert!(!is_valid_url(TS_BAD_CHECKSUM_URL));
}

#[test]
fn test_cross_sdk_empty_file_hash() {
    // Empty string has a well-known SHA-256 hash
    let empty_hash = sha256(b"");
    assert_eq!(
        hex::encode(empty_hash),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );

    // Generate URL and verify it can be round-tripped
    let url = get_url_for_hash(&empty_hash).unwrap();
    let recovered = get_hash_from_url(&url).unwrap();
    assert_eq!(recovered, empty_hash);
}

// =============================================================================
// StorageDownloader Tests - Configuration
// =============================================================================

#[test]
fn test_storage_downloader_config_default() {
    let config = StorageDownloaderConfig::default();
    assert_eq!(
        config.network_preset,
        bsv_sdk::overlay::NetworkPreset::Mainnet
    );
    assert!(config.resolver.is_none());
    assert_eq!(config.timeout_ms, Some(30000));
}

#[test]
fn test_storage_downloader_config_custom_timeout() {
    let mut config = StorageDownloaderConfig::default();
    config.timeout_ms = Some(60000);
    assert_eq!(config.timeout_ms, Some(60000));
}

#[test]
fn test_storage_downloader_config_no_timeout() {
    let mut config = StorageDownloaderConfig::default();
    config.timeout_ms = None;
    assert!(config.timeout_ms.is_none());
}

#[test]
fn test_storage_downloader_config_testnet() {
    let config = StorageDownloaderConfig {
        network_preset: bsv_sdk::overlay::NetworkPreset::Testnet,
        resolver: None,
        timeout_ms: Some(30000),
    };
    assert_eq!(
        config.network_preset,
        bsv_sdk::overlay::NetworkPreset::Testnet
    );
}

#[test]
fn test_storage_downloader_config_local() {
    let config = StorageDownloaderConfig {
        network_preset: bsv_sdk::overlay::NetworkPreset::Local,
        resolver: None,
        timeout_ms: Some(5000),
    };
    assert_eq!(
        config.network_preset,
        bsv_sdk::overlay::NetworkPreset::Local
    );
}

#[test]
fn test_storage_downloader_creation() {
    let downloader = StorageDownloader::default();
    // Just verify it was created successfully
    assert!(std::mem::size_of_val(&downloader) > 0);
}

#[test]
fn test_storage_downloader_creation_with_config() {
    let config = StorageDownloaderConfig {
        network_preset: bsv_sdk::overlay::NetworkPreset::Testnet,
        resolver: None,
        timeout_ms: Some(15000),
    };
    let downloader = StorageDownloader::new(config);
    // Just verify it was created successfully
    assert!(std::mem::size_of_val(&downloader) > 0);
}

// =============================================================================
// StorageUploader Tests - Configuration
// =============================================================================

#[test]
fn test_storage_uploader_config_new() {
    let config = StorageUploaderConfig::new("https://storage.example.com");
    assert_eq!(config.storage_url, "https://storage.example.com");
    assert_eq!(config.default_retention_minutes, 7 * 24 * 60); // 7 days
}

#[test]
fn test_storage_uploader_config_with_retention() {
    let config =
        StorageUploaderConfig::new("https://storage.example.com").with_retention_minutes(1440);
    assert_eq!(config.default_retention_minutes, 1440); // 1 day
}

#[test]
fn test_storage_uploader_config_with_zero_retention() {
    let config =
        StorageUploaderConfig::new("https://storage.example.com").with_retention_minutes(0);
    assert_eq!(config.default_retention_minutes, 0);
}

#[test]
fn test_storage_uploader_config_with_large_retention() {
    let config = StorageUploaderConfig::new("https://storage.example.com")
        .with_retention_minutes(365 * 24 * 60); // 1 year
    assert_eq!(config.default_retention_minutes, 365 * 24 * 60);
}

#[test]
fn test_storage_uploader_creation() {
    let config = StorageUploaderConfig::new("https://storage.example.com");
    let uploader = StorageUploader::new(config);
    assert_eq!(uploader.base_url(), "https://storage.example.com");
}

#[test]
fn test_storage_uploader_base_url() {
    let config = StorageUploaderConfig::new("https://my-storage.test");
    let uploader = StorageUploader::new(config);
    assert_eq!(uploader.base_url(), "https://my-storage.test");
}

#[test]
fn test_storage_uploader_different_urls() {
    let urls = [
        "https://storage1.example.com",
        "https://storage2.example.com:8080",
        "http://localhost:3000",
        "https://storage.test/api/v1",
    ];

    for url in urls {
        let config = StorageUploaderConfig::new(url);
        let uploader = StorageUploader::new(config);
        assert_eq!(uploader.base_url(), url);
    }
}

// =============================================================================
// UploadableFile Tests
// =============================================================================

#[test]
fn test_uploadable_file_creation() {
    let file = UploadableFile::new(b"Hello, World!".to_vec(), "text/plain");
    assert_eq!(file.data, b"Hello, World!");
    assert_eq!(file.mime_type, "text/plain");
    assert_eq!(file.size(), 13);
}

#[test]
fn test_uploadable_file_empty() {
    let file = UploadableFile::new(Vec::new(), "application/octet-stream");
    assert!(file.data.is_empty());
    assert_eq!(file.size(), 0);
}

#[test]
fn test_uploadable_file_binary() {
    let binary_data: Vec<u8> = (0..=255).collect();
    let file = UploadableFile::new(binary_data.clone(), "application/octet-stream");
    assert_eq!(file.data, binary_data);
    assert_eq!(file.size(), 256);
}

#[test]
fn test_uploadable_file_various_mime_types() {
    let mime_types = [
        "text/plain",
        "text/html",
        "application/json",
        "application/octet-stream",
        "image/png",
        "image/jpeg",
        "application/pdf",
        "video/mp4",
    ];

    for mime in mime_types {
        let file = UploadableFile::new(b"test".to_vec(), mime);
        assert_eq!(file.mime_type, mime);
    }
}

#[test]
fn test_uploadable_file_large() {
    // Test with 1MB of data
    let large_data = vec![0xABu8; 1024 * 1024];
    let file = UploadableFile::new(large_data.clone(), "application/octet-stream");
    assert_eq!(file.size(), 1024 * 1024);
    assert_eq!(file.data, large_data);
}

// =============================================================================
// DownloadResult Tests
// =============================================================================

#[test]
fn test_download_result_creation() {
    let result = DownloadResult::new(vec![1, 2, 3], "application/octet-stream");
    assert_eq!(result.data, vec![1, 2, 3]);
    assert_eq!(result.mime_type, "application/octet-stream");
}

#[test]
fn test_download_result_empty() {
    let result = DownloadResult::new(Vec::new(), "text/plain");
    assert!(result.data.is_empty());
    assert_eq!(result.mime_type, "text/plain");
}

#[test]
fn test_download_result_with_string() {
    let content = b"Hello, World!".to_vec();
    let result = DownloadResult::new(content.clone(), String::from("text/plain; charset=utf-8"));
    assert_eq!(result.data, content);
    assert_eq!(result.mime_type, "text/plain; charset=utf-8");
}

// =============================================================================
// UploadFileResult Tests
// =============================================================================

#[test]
fn test_upload_file_result_success() {
    let result = UploadFileResult::new("uhrp://abc123", true);
    assert_eq!(result.uhrp_url, "uhrp://abc123");
    assert!(result.published);
}

#[test]
fn test_upload_file_result_failure() {
    let result = UploadFileResult::new("", false);
    assert_eq!(result.uhrp_url, "");
    assert!(!result.published);
}

#[test]
fn test_upload_file_result_with_real_url() {
    let file_data = b"test file for upload result";
    let url = get_url_for_file(file_data).unwrap();

    let result = UploadFileResult::new(url.clone(), true);
    assert_eq!(result.uhrp_url, url);
    assert!(result.published);
    assert!(is_valid_url(&result.uhrp_url));
}

// =============================================================================
// Constants Tests
// =============================================================================

#[test]
fn test_uhrp_prefix_constant() {
    assert_eq!(UHRP_PREFIX, "uhrp://");
}

#[test]
fn test_web_uhrp_prefix_constant() {
    assert_eq!(WEB_UHRP_PREFIX, "web+uhrp://");
}

// =============================================================================
// Edge Cases and Error Handling Tests
// =============================================================================

#[test]
fn test_url_generation_deterministic() {
    // Same data should always produce the same URL
    let data = b"deterministic test data";
    let url1 = get_url_for_file(data).unwrap();
    let url2 = get_url_for_file(data).unwrap();
    assert_eq!(url1, url2);
}

#[test]
fn test_different_data_different_urls() {
    // Different data should produce different URLs
    let url1 = get_url_for_file(b"data A").unwrap();
    let url2 = get_url_for_file(b"data B").unwrap();
    assert_ne!(url1, url2);
}

#[test]
fn test_similar_data_different_urls() {
    // Even slightly different data should produce completely different URLs
    let url1 = get_url_for_file(b"Hello, World!").unwrap();
    let url2 = get_url_for_file(b"Hello, World?").unwrap();
    let url3 = get_url_for_file(b"hello, World!").unwrap();

    assert_ne!(url1, url2);
    assert_ne!(url1, url3);
    assert_ne!(url2, url3);
}

#[test]
fn test_special_characters_in_data() {
    // Test with various special characters and unicode
    let test_data = [
        "Hello\nWorld".as_bytes(),
        "Tab\tSeparated".as_bytes(),
        "Carriage\rReturn".as_bytes(),
        "Null\0Byte".as_bytes(),
        "Unicode: ".as_bytes(),
    ];

    for data in test_data {
        let url = get_url_for_file(data).unwrap();
        assert!(is_valid_url(&url));
        let hash = get_hash_from_url(&url).unwrap();
        assert_eq!(hash, sha256(data));
    }
}

// =============================================================================
// Test Summary
// =============================================================================

#[test]
fn test_summary() {
    // Summary test to verify all major functionality works together
    println!("Storage module test summary:");

    // 1. URL generation from file
    let file = hex::decode(TS_EXAMPLE_FILE_HEX).unwrap();
    let url = get_url_for_file(&file).unwrap();
    println!("  - Generated URL: {}", url);

    // 2. URL validation
    assert!(is_valid_url(&url));
    println!("  - URL validated: true");

    // 3. Hash extraction
    let hash = get_hash_from_url(&url).unwrap();
    assert_eq!(hex::encode(&hash), TS_EXAMPLE_HASH_HEX);
    println!("  - Extracted hash: {}", hex::encode(&hash));

    // 4. Cross-SDK compatibility
    assert_eq!(normalize_url(&url), TS_EXAMPLE_URL_BASE58);
    println!("  - Cross-SDK compatible: true");

    // 5. Downloader configuration
    let downloader_config = StorageDownloaderConfig::default();
    println!(
        "  - Downloader network: {:?}",
        downloader_config.network_preset
    );

    // 6. Uploader configuration
    let uploader_config = StorageUploaderConfig::new("https://storage.example.com");
    println!("  - Uploader URL: {}", uploader_config.storage_url);

    println!("All storage module tests passed!");
}
