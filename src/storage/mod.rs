//! # Storage Module
//!
//! UHRP (Universal Hash Resolution Protocol) file storage for BSV.
//!
//! ## Overview
//!
//! This module provides decentralized file storage using content-addressed UHRP URLs.
//! Files are identified by their SHA-256 hash and stored on overlay network hosts.
//!
//! ## Components
//!
//! - **UHRP URL utilities**: Generate and parse content-addressed URLs
//! - **StorageDownloader**: Download files from UHRP URLs via overlay lookup
//! - **StorageUploader**: Upload files to storage services
//!
//! ## UHRP URL Format
//!
//! UHRP URLs encode a SHA-256 file hash using Base58Check:
//!
//! ```text
//! uhrp://<base58check_encoded_hash>
//! ```
//!
//! The encoding uses:
//! - Prefix: `0xce00` (2 bytes)
//! - Payload: SHA-256 hash (32 bytes)
//! - Checksum: First 4 bytes of SHA256(SHA256(prefix || payload))
//!
//! ## Example
//!
//! ```rust
//! use bsv_sdk::storage::{get_url_for_file, get_hash_from_url, is_valid_url};
//!
//! // Generate a UHRP URL for file content
//! let content = b"Hello, World!";
//! let url = get_url_for_file(content).unwrap();
//! assert!(url.starts_with("uhrp://"));
//!
//! // Validate and parse the URL
//! assert!(is_valid_url(&url));
//! let hash = get_hash_from_url(&url).unwrap();
//! assert_eq!(hash.len(), 32);
//! ```
//!
//! ## Downloading Files
//!
//! ```rust,ignore
//! use bsv_sdk::storage::{StorageDownloader, StorageDownloaderConfig};
//!
//! let downloader = StorageDownloader::new(StorageDownloaderConfig::default());
//!
//! // Resolve hosts for a UHRP URL
//! let hosts = downloader.resolve("uhrp://...").await?;
//!
//! // Download the file (requires 'http' feature)
//! let result = downloader.download("uhrp://...").await?;
//! println!("Downloaded {} bytes of {}", result.data.len(), result.mime_type);
//! ```
//!
//! ## Uploading Files
//!
//! ```rust,ignore
//! use bsv_sdk::storage::{StorageUploader, StorageUploaderConfig, UploadableFile};
//!
//! let config = StorageUploaderConfig::new("https://storage.example.com");
//! let uploader = StorageUploader::new(config);
//!
//! let file = UploadableFile::new(b"Hello".to_vec(), "text/plain");
//! let result = uploader.publish_file(&file, None).await?;
//! println!("Uploaded to: {}", result.uhrp_url);
//! ```
//!
//! ## Feature Requirements
//!
//! - `storage` - Enables the storage module
//! - `http` - Required for actual file download/upload operations

pub mod downloader;
pub mod types;
pub mod uploader;
pub mod utils;

// Re-export types
pub use types::{
    DownloadResult, FindFileData, RenewFileResult, UploadFileResult, UploadMetadata, UploadableFile,
};

// Re-export downloader
pub use downloader::{StorageDownloader, StorageDownloaderConfig};

// Re-export uploader
pub use uploader::{StorageUploader, StorageUploaderConfig};

// Re-export utilities
pub use utils::{
    get_hash_from_url, get_hash_hex_from_url, get_url_for_file, get_url_for_hash, is_valid_url,
    normalize_url, UHRP_PREFIX, WEB_UHRP_PREFIX,
};
