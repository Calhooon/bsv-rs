# BSV Storage Module
> UHRP (Universal Hash Resolution Protocol) file storage for BSV

## Overview

This module provides decentralized file storage using content-addressed UHRP URLs. Files are identified by their SHA-256 hash and stored on overlay network hosts.

**Status**: Complete - UHRP URL utilities, downloader, and uploader implemented.

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | Module root; re-exports |
| `types.rs` | Core types (UploadableFile, DownloadResult, etc.) |
| `utils.rs` | UHRP URL generation, parsing, and validation |
| `downloader.rs` | Download files from UHRP URLs via overlay lookup |
| `uploader.rs` | Upload files to storage services |

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
```

### UploadFileResult

```rust
pub struct UploadFileResult {
    pub uhrp_url: String,  // UHRP URL for the file
    pub published: bool,   // Whether upload succeeded
}
```

### FindFileData

```rust
pub struct FindFileData {
    pub name: Option<String>,  // File name (if provided)
    pub size: String,          // File size
    pub mime_type: String,     // MIME type
    pub expiry_time: i64,      // Expiration timestamp (Unix seconds)
}
```

### RenewFileResult

```rust
pub struct RenewFileResult {
    pub status: String,       // "success" or "error"
    pub previous_expiry: i64, // Previous expiration
    pub new_expiry: i64,      // New expiration
    pub amount: i64,          // Amount charged
}
```

## UHRP URL Utilities

### Generate URLs

```rust
use bsv_sdk::storage::{get_url_for_file, get_url_for_hash};
use bsv_sdk::primitives::hash::sha256;

// From file content
let url = get_url_for_file(b"Hello, World!").unwrap();

// From existing hash
let hash = sha256(b"Hello, World!");
let url = get_url_for_hash(&hash).unwrap();
```

### Parse URLs

```rust
use bsv_sdk::storage::{get_hash_from_url, get_hash_hex_from_url, normalize_url};

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
use bsv_sdk::storage::is_valid_url;

assert!(is_valid_url("uhrp://..."));
assert!(!is_valid_url("https://example.com"));
```

## StorageDownloader

Downloads files from UHRP URLs via overlay network lookup.

### Configuration

```rust
pub struct StorageDownloaderConfig {
    pub network_preset: NetworkPreset,       // Mainnet/Testnet/Local
    pub resolver: Option<Arc<LookupResolver>>, // Custom resolver
    pub timeout_ms: Option<u64>,             // Download timeout
}

impl Default for StorageDownloaderConfig {
    fn default() -> Self {
        Self {
            network_preset: NetworkPreset::Mainnet,
            resolver: None,
            timeout_ms: Some(30000),
        }
    }
}
```

### Usage

```rust
use bsv_sdk::storage::{StorageDownloader, StorageDownloaderConfig};

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
3. Extract host URLs and expiry times from token fields
4. Filter out expired advertisements
5. Return list of available host URLs

### How Download Works

1. Resolve hosts for the UHRP URL
2. Try each host in order until success
3. Verify downloaded content hash matches URL
4. Return content with MIME type

## StorageUploader

Uploads files to storage services.

### Configuration

```rust
pub struct StorageUploaderConfig {
    pub storage_url: String,             // Base URL of storage service
    pub default_retention_minutes: u32,  // Default retention (7 days)
}

impl StorageUploaderConfig {
    pub fn new(storage_url: impl Into<String>) -> Self
    pub fn with_retention_minutes(self, minutes: u32) -> Self
}
```

### Usage

```rust
use bsv_sdk::storage::{StorageUploader, StorageUploaderConfig, UploadableFile};

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

1. Request upload info from `/upload` endpoint
2. Receive presigned URL and required headers
3. PUT file to presigned URL
4. Generate UHRP URL from file content hash

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

### Test Vectors

```rust
// Empty file
let url = get_url_for_file(b"").unwrap();
let hash = get_hash_from_url(&url).unwrap();
assert_eq!(
    hex::encode(hash),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
);

// Round-trip
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

## Related Documentation

- `../overlay/CLAUDE.md` - Overlay module (lookup resolution)
- `../primitives/CLAUDE.md` - Hash functions and encoding
- `../CLAUDE.md` - Root SDK documentation
