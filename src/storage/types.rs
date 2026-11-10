//! Core types for storage operations.
//!
//! This module defines the data structures used for file upload, download,
//! and management operations in the UHRP storage system.

use serde::{Deserialize, Serialize};

/// A file ready for upload to UHRP storage.
///
/// Contains the file content and MIME type for proper handling by storage hosts.
#[derive(Debug, Clone)]
pub struct UploadableFile {
    /// File content as bytes.
    pub data: Vec<u8>,
    /// MIME type (e.g., "image/png", "application/pdf").
    pub mime_type: String,
}

impl UploadableFile {
    /// Create a new uploadable file.
    ///
    /// # Arguments
    ///
    /// * `data` - The file content as bytes
    /// * `mime_type` - The MIME type of the file
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_rs::storage::UploadableFile;
    ///
    /// let file = UploadableFile::new(b"Hello, World!".to_vec(), "text/plain");
    /// assert_eq!(file.mime_type, "text/plain");
    /// ```
    pub fn new(data: Vec<u8>, mime_type: impl Into<String>) -> Self {
        Self {
            data,
            mime_type: mime_type.into(),
        }
    }

    /// Get the size of the file in bytes.
    pub fn size(&self) -> usize {
        self.data.len()
    }
}

/// Result of a file download.
#[derive(Debug, Clone)]
pub struct DownloadResult {
    /// File content.
    pub data: Vec<u8>,
    /// MIME type of the downloaded content.
    pub mime_type: String,
}

impl DownloadResult {
    /// Create a new download result.
    pub fn new(data: Vec<u8>, mime_type: impl Into<String>) -> Self {
        Self {
            data,
            mime_type: mime_type.into(),
        }
    }
}

/// Result of a file upload operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadFileResult {
    /// The UHRP URL for the uploaded file.
    #[serde(rename = "uhrpUrl")]
    pub uhrp_url: String,
    /// Whether the file was successfully published.
    pub published: bool,
}

impl UploadFileResult {
    /// Create a new upload result.
    pub fn new(uhrp_url: impl Into<String>, published: bool) -> Self {
        Self {
            uhrp_url: uhrp_url.into(),
            published,
        }
    }
}

/// Information about a stored file retrieved via find operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindFileData {
    /// File name or path on the CDN.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// File size as returned by the service.
    pub size: String,
    /// MIME type of the file.
    #[serde(rename = "mimeType")]
    pub mime_type: String,
    /// Expiration timestamp (Unix seconds).
    #[serde(rename = "expiryTime")]
    pub expiry_time: i64,
}

/// Metadata for an uploaded file in a list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadMetadata {
    /// UHRP URL of the file.
    #[serde(rename = "uhrpUrl")]
    pub uhrp_url: String,
    /// Expiration timestamp (Unix seconds).
    #[serde(rename = "expiryTime")]
    pub expiry_time: i64,
}

/// Result of a file renewal operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenewFileResult {
    /// Status returned by the service (e.g., "success").
    pub status: String,
    /// Previous expiration timestamp (Unix seconds).
    #[serde(rename = "prevExpiryTime")]
    pub previous_expiry: i64,
    /// New expiration timestamp (Unix seconds).
    #[serde(rename = "newExpiryTime")]
    pub new_expiry: i64,
    /// Amount charged or refilled.
    pub amount: i64,
}

impl RenewFileResult {
    /// Check if the renewal was successful.
    pub fn is_success(&self) -> bool {
        self.status == "success"
    }
}

/// Response from upload info endpoint.
#[cfg(feature = "http")]
#[derive(Clone, Serialize, Deserialize)] // Debug redacts the URL and headers (below)
pub(crate) struct UploadInfo {
    /// Status of the request.
    pub status: String,
    /// URL to upload the file to.
    #[serde(rename = "uploadURL")]
    pub upload_url: String,
    /// Required headers for the upload request.
    #[serde(rename = "requiredHeaders", default)]
    pub required_headers: std::collections::HashMap<String, String>,
    /// Amount charged (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<i64>,
}

/// A presigned upload's URL carries its credential in its query and its
/// required headers may carry another (the second fold of the secret Debug
/// lane): the URL through `debug_redact::Url`, every header value redacted
/// save the public names.
#[cfg(feature = "http")]
impl std::fmt::Debug for UploadInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use crate::util::debug_redact::{HeaderMap, Url};
        f.debug_struct("UploadInfo")
            .field("status", &self.status)
            .field("upload_url", &Url(&self.upload_url))
            .field("required_headers", &HeaderMap(&self.required_headers))
            .field("amount", &self.amount)
            .finish()
    }
}

#[cfg(all(test, feature = "http"))]
mod upload_info_debug_tests {
    use super::UploadInfo;

    #[test]
    fn an_upload_info_debug_prints_no_signature_and_no_header_value() {
        let info = UploadInfo {
            status: "success".into(),
            upload_url: "https://bucket.invalid/obj?X-Amz-Signature=sig0123&X-Amz-Credential=cred"
                .into(),
            required_headers: [
                ("x-amz-security-token".to_owned(), "tok4567".to_owned()),
                (
                    "Content-Type".to_owned(),
                    "application/octet-stream".to_owned(),
                ),
            ]
            .into(),
            amount: Some(5),
        };
        for out in [format!("{info:?}"), format!("{info:#?}")] {
            for secret in ["sig0123", "cred", "tok4567", "X-Amz-Signature"] {
                assert!(!out.contains(secret), "{out}");
            }
            assert!(
                out.contains("https://bucket.invalid/obj?<redacted>"),
                "{out}"
            );
            assert!(out.contains("x-amz-security-token"), "{out}");
            assert!(out.contains("application/octet-stream"), "{out}");
            assert!(out.starts_with("UploadInfo"), "{out}");
        }
    }
}

/// API response status constants.
#[allow(dead_code)]
pub(crate) const STATUS_SUCCESS: &str = "success";
#[allow(dead_code)]
pub(crate) const STATUS_ERROR: &str = "error";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uploadable_file_new() {
        let file = UploadableFile::new(b"content".to_vec(), "text/plain");
        assert_eq!(file.data, b"content");
        assert_eq!(file.mime_type, "text/plain");
        assert_eq!(file.size(), 7);
    }

    #[test]
    fn test_download_result_new() {
        let result = DownloadResult::new(vec![1, 2, 3], "application/octet-stream");
        assert_eq!(result.data, vec![1, 2, 3]);
        assert_eq!(result.mime_type, "application/octet-stream");
    }

    #[test]
    fn test_upload_file_result_new() {
        let result = UploadFileResult::new("uhrp://abc123", true);
        assert_eq!(result.uhrp_url, "uhrp://abc123");
        assert!(result.published);
    }

    #[test]
    fn test_renew_file_result_is_success() {
        let success = RenewFileResult {
            status: "success".to_string(),
            previous_expiry: 1000,
            new_expiry: 2000,
            amount: 100,
        };
        assert!(success.is_success());

        let failure = RenewFileResult {
            status: "error".to_string(),
            previous_expiry: 1000,
            new_expiry: 1000,
            amount: 0,
        };
        assert!(!failure.is_success());
    }
}
