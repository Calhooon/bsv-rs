# BSV Storage Module
> UHRP (Universal Hash Resolution Protocol) file storage for BSV

## Overview

This module provides decentralized file storage using content-addressed UHRP URLs. Files are identified by their SHA-256 hash and stored on overlay network hosts. The storage system uses the overlay network's `ls_uhrp` lookup service to discover hosts that store specific files.

**Status**: Complete - UHRP URL utilities, downloader, and uploader implemented.

## Files

| File | Lines | Purpose |
|------|-------|---------|
| `mod.rs` | 98 | Module root; re-exports public API |
| `types.rs` | 202 | Core types (UploadableFile, DownloadResult, etc.) |
| `utils.rs` | 503 | UHRP URL generation, parsing, validation, and cross-SDK test vectors |
| `downloader.rs` | 344 | Download files from UHRP URLs via overlay lookup |
| `uploader.rs` | 445 | Upload files to storage services with retention management |

## Key Exports

```rust
// Types
pub use types::{
    DownloadResult, FindFileData, RenewFileResult,
    UploadFileResult, UploadMetadata, UploadableFile,
};

// Downloader
pub use downloader::{StorageDownloader, StorageDownloaderConfig};

// Uploader
pub use uploader::{StorageUploader, StorageUploaderConfig};

// Utilities
pub use utils::{
    get_hash_from_url, get_hash_hex_from_url, get_url_for_file,
    get_url_for_hash, is_valid_url, normalize_url,
    UHRP_PREFIX, WEB_UHRP_PREFIX,
};
```

## UHRP URL Format

UHRP URLs are content-addressed identifiers using Base58Check encoding:

```
uhrp://<base58check_encoded_hash>
```

### Encoding Components

| Component | Size | Description |
|-----------|------|-------------|
| Prefix | 2 bytes | `0xce00` |
| Hash | 32 bytes | SHA-256 of file content |
| Checksum | 4 bytes | First 4 bytes of SHA256(SHA256(prefix + hash)) |

### Example URL

```
uhrp://5P3xLaNMFwAQGpDxgwvkGDHCw8o8rvbFQ9c2W1wMxwNHX1hm
```

## Core Types

### UploadableFile

```rust
pub struct UploadableFile {
    pub data: Vec<u8>,      // File content
    pub mime_type: String,  // MIME type (e.g., "image/png")
}

impl UploadableFile {
    pub fn new(data: Vec<u8>, mime_type: impl Into<String>) -> Self
    pub fn size(&self) -> usize
}
```

### DownloadResult

```rust
pub struct DownloadResult {
    pub data: Vec<u8>,      // File content
    pub mime_type: String,  // MIME type from server
}

impl DownloadResult {
    pub fn new(data: Vec<u8>, mime_type: impl Into<String>) -> Self
}
```

### UploadFileResult

```rust
pub struct UploadFileResult {
    pub uhrp_url: String,  // UHRP URL for the file (JSON: "uhrpUrl")
    pub published: bool,   // Whether upload succeeded
}

impl UploadFileResult {
    pub fn new(uhrp_url: impl Into<String>, published: bool) -> Self
}
```

### FindFileData

```rust
pub struct FindFileData {
    pub name: Option<String>,  // File name (if provided)
    pub size: String,          // File size as string
    pub mime_type: String,     // MIME type (JSON: "mimeType")
    pub expiry_time: i64,      // Expiration timestamp (Unix seconds, JSON: "expiryTime")
}
```

### UploadMetadata

```rust
pub struct UploadMetadata {
    pub uhrp_url: String,   // UHRP URL (JSON: "uhrpUrl")
    pub expiry_time: i64,   // Expiration timestamp (Unix seconds, JSON: "expiryTime")
}
```

### RenewFileResult

```rust
pub struct RenewFileResult {
    pub status: String,       // "success" or "error"
    pub previous_expiry: i64, // Previous expiration (JSON: "prevExpiryTime")
    pub new_expiry: i64,      // New expiration (JSON: "newExpiryTime")
    pub amount: i64,          // Amount charged
}

impl RenewFileResult {
    pub fn is_success(&self) -> bool  // Returns true if status == "success"
}
```

## UHRP URL Utilities

### Generate URLs

```rust
use bsv_rs::storage::{get_url_for_file, get_url_for_hash};
use bsv_rs::primitives::hash::sha256;

// From file content
let url = get_url_for_file(b"Hello, World!").unwrap();

// From existing hash
let hash = sha256(b"Hello, World!");
let url = get_url_for_hash(&hash).unwrap();
```

### Parse URLs

```rust
use bsv_rs::storage::{get_hash_from_url, get_hash_hex_from_url, normalize_url};

// Get 32-byte hash
let hash: [u8; 32] = get_hash_from_url("uhrp://...").unwrap();

// Get hash as hex string
let hash_hex: String = get_hash_hex_from_url("uhrp://...").unwrap();

// Normalize URL (remove prefix)
let encoded = normalize_url("uhrp://abc123"); // Returns "abc123"
let encoded = normalize_url("web+uhrp://abc123"); // Returns "abc123"
```

### Validate URLs

```rust
use bsv_rs::storage::is_valid_url;

assert!(is_valid_url("uhrp://..."));
assert!(!is_valid_url("https://example.com"));
```

## StorageDownloader

Downloads files from UHRP URLs via overlay network lookup. Uses the `ls_uhrp` lookup service to discover storage hosts.

### Configuration

```rust
pub struct StorageDownloaderConfig {
    pub network_preset: NetworkPreset,         // Mainnet/Testnet/Local
    pub resolver: Option<Arc<LookupResolver>>, // Custom resolver (optional)
    pub timeout_ms: Option<u64>,               // Download timeout in ms
}

impl Default for StorageDownloaderConfig {
    fn default() -> Self {
        Self {
            network_preset: NetworkPreset::Mainnet,
            resolver: None,
            timeout_ms: Some(30000),  // 30 seconds
        }
    }
}
```

### Methods

```rust
impl StorageDownloader {
    pub fn new(config: StorageDownloaderConfig) -> Self
    pub async fn resolve(&self, uhrp_url: &str) -> Result<Vec<String>>
    pub async fn download(&self, uhrp_url: &str) -> Result<DownloadResult>  // requires 'http' feature
}

impl Default for StorageDownloader {
    fn default() -> Self  // Uses default config
}
```

### Usage

```rust
use bsv_rs::storage::{StorageDownloader, StorageDownloaderConfig};

let downloader = StorageDownloader::new(StorageDownloaderConfig::default());

// Resolve hosts without downloading
let hosts = downloader.resolve("uhrp://...").await?;
println!("Found {} hosts", hosts.len());

// Download file (requires 'http' feature)
let result = downloader.download("uhrp://...").await?;
println!("Downloaded {} bytes", result.data.len());
```

### How Resolution Works

1. Query `ls_uhrp` lookup service with the UHRP URL
2. Parse BEEF outputs to get PushDrop advertisement tokens
3. Extract host URLs and expiry times from token fields (fields: protocol, identity, domain, expiry)
4. Filter out expired advertisements (compares expiry time against current time)
5. Validate host URLs (must start with `http://` or `https://`)
6. Return list of available host URLs

### How Download Works

1. Validate the UHRP URL format and checksum
2. Extract expected hash from URL
3. Resolve hosts for the UHRP URL
4. Try each host in order until success
5. Verify downloaded content hash matches URL (SHA-256)
6. Return content with MIME type from response headers

## StorageUploader

Uploads files to storage services with retention period management.

### Configuration

```rust
pub struct StorageUploaderConfig {
    pub storage_url: String,             // Base URL of storage service
    pub default_retention_minutes: u32,  // Default retention (7 days = 10080 minutes)
}

impl StorageUploaderConfig {
    pub fn new(storage_url: impl Into<String>) -> Self
    pub fn with_retention_minutes(self, minutes: u32) -> Self
}
```

### Methods

```rust
impl StorageUploader {
    pub fn new(config: StorageUploaderConfig) -> Self
    pub fn base_url(&self) -> &str

    // All async methods require 'http' feature
    pub async fn publish_file(&self, file: &UploadableFile, retention_minutes: Option<u32>) -> Result<UploadFileResult>
    pub async fn find_file(&self, uhrp_url: &str) -> Result<Option<FindFileData>>
    pub async fn list_uploads(&self) -> Result<serde_json::Value>
    pub async fn renew_file(&self, uhrp_url: &str, additional_minutes: u32) -> Result<RenewFileResult>
}
```

### Usage

```rust
use bsv_rs::storage::{StorageUploader, StorageUploaderConfig, UploadableFile};

let config = StorageUploaderConfig::new("https://storage.example.com")
    .with_retention_minutes(24 * 60); // 1 day

let uploader = StorageUploader::new(config);

// Upload a file
let file = UploadableFile::new(b"Hello".to_vec(), "text/plain");
let result = uploader.publish_file(&file, None).await?;
println!("Uploaded to: {}", result.uhrp_url);

// Find file info
if let Some(info) = uploader.find_file(&result.uhrp_url).await? {
    println!("Size: {}, Expires: {}", info.size, info.expiry_time);
}

// List uploads
let uploads = uploader.list_uploads().await?;

// Renew retention
let renewal = uploader.renew_file(&result.uhrp_url, 60 * 24).await?;
println!("New expiry: {}", renewal.new_expiry);
```

### Upload Flow

1. Request upload info from `/upload` endpoint (POST with `fileSize` and `retentionPeriod`)
2. Receive presigned URL and required headers from response
3. PUT file to presigned URL with content-type header and any required headers
4. Generate UHRP URL from file content hash using `get_url_for_file`

### API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/upload` | POST | Get upload URL and required headers |
| `/find` | GET | Find file metadata by UHRP URL |
| `/list` | GET | List uploaded files |
| `/renew` | POST | Extend file retention period |

## Feature Requirements

| Feature | Required For |
|---------|--------------|
| `storage` | Module access |
| `http` | File download/upload operations |
| `overlay` | Host resolution (dependency) |

## Error Handling

Storage operations use `Error::OverlayError(String)` for failures:

| Error | Description |
|-------|-------------|
| Invalid UHRP URL | URL format/checksum validation failed |
| No hosts found | `ls_uhrp` lookup returned no results |
| Download failed | All host attempts failed |
| Hash mismatch | Downloaded content hash doesn't match URL |
| Upload failed | Storage service returned error |
| HTTP not enabled | Operation requires `http` feature |

## Cross-SDK Compatibility

UHRP URL encoding is compatible with TypeScript and Go SDKs:

- Same Base58Check encoding with `0xce00` prefix
- Same checksum algorithm (double SHA-256)
- Same URL format (`uhrp://` or `web+uhrp://`)

### Test Vectors from TypeScript SDK

```rust
// Known test vector
const HASH_HEX: &str = "1a5ec49a3f32cd56d19732e89bde5d81755ddc0fd8515dc8b226d47654139dca";
const FILE_HEX: &str = "687da27f04a112aa48f1cab2e7949f1eea4f7ba28319c1e999910cd561a634a05a3516e6db";
const URL_BASE58: &str = "XUT6PqWb3GP3LR7dmBMCJwZ3oo5g1iGCF3CrpzyuJCemkGu1WGoq";

// Hash to URL
let hash = hex::decode(HASH_HEX).unwrap();
let url = get_url_for_hash(&hash).unwrap();
assert_eq!(normalize_url(&url), URL_BASE58);

// File to URL (verifies SHA-256 produces expected hash)
let file = hex::decode(FILE_HEX).unwrap();
let url = get_url_for_file(&file).unwrap();
assert_eq!(normalize_url(&url), URL_BASE58);

// URL to Hash
let hash = get_hash_from_url(URL_BASE58).unwrap();
assert_eq!(hex::encode(hash), HASH_HEX);

// Invalid URL detection (bad checksum)
let bad_url = "XUU7cTfy6fA6q2neLDmzPqJnGB6o18PXKoGaWLPrH1SeWLKgdCKq";
assert!(!is_valid_url(bad_url));
```

### Round-Trip Examples

```rust
// Empty file
let url = get_url_for_file(b"").unwrap();
let hash = get_hash_from_url(&url).unwrap();
assert_eq!(
    hex::encode(hash),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
);

// Arbitrary data
let data = b"test data";
let url = get_url_for_file(data).unwrap();
let recovered = get_hash_from_url(&url).unwrap();
assert_eq!(recovered, sha256(data));
```

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `UHRP_PREFIX` | `"uhrp://"` | Standard URL prefix |
| `WEB_UHRP_PREFIX` | `"web+uhrp://"` | Alternative web prefix |

## Internal Types

These types are used internally (`pub(crate)`) and not exported:

### UploadInfo

```rust
pub(crate) struct UploadInfo {
    pub status: String,
    pub upload_url: String,                           // JSON: "uploadURL"
    pub required_headers: HashMap<String, String>,    // JSON: "requiredHeaders"
    pub amount: Option<i64>,
}
```

### Status Constants

```rust
pub(crate) const STATUS_SUCCESS: &str = "success";
pub(crate) const STATUS_ERROR: &str = "error";
```

## Dependencies

| Crate | Purpose |
|-------|---------|
| `serde` | JSON serialization for API types |
| `hex` | Hash encoding for `get_hash_hex_from_url` |
| `reqwest` | HTTP client (with `http` feature) |
| `urlencoding` | URL parameter encoding |

Internal dependencies:
- `crate::overlay` - `LookupResolver`, `LookupQuestion`, `LookupAnswer`, `NetworkPreset`
- `crate::primitives` - `sha256`, `sha256d`, `to_base58`, `from_base58`, `Reader`
- `crate::script::templates` - `PushDrop` for parsing advertisement tokens
- `crate::transaction` - `Transaction::from_beef` for parsing BEEF outputs

## Related Documentation

- `../overlay/CLAUDE.md` - Overlay module (lookup resolution)
- `../primitives/CLAUDE.md` - Hash functions and encoding
- `../CLAUDE.md` - Root SDK documentation
