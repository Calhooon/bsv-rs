//! UHRP file uploader.
//!
//! Uploads files to UHRP storage hosts with authenticated API access.
//! Requires wallet authentication for secure operations.

use crate::{Error, Result};

use super::types::{FindFileData, RenewFileResult, UploadFileResult, UploadableFile};

#[cfg(feature = "http")]
use super::types::{UploadInfo, STATUS_ERROR};
#[cfg(feature = "http")]
use super::utils::get_url_for_file;

/// Configuration for StorageUploader.
#[derive(Clone)]
pub struct StorageUploaderConfig {
    /// Base URL of the storage service.
    pub storage_url: String,
    /// Default retention period in minutes.
    pub default_retention_minutes: u32,
}

impl StorageUploaderConfig {
    /// Create a new uploader configuration.
    ///
    /// # Arguments
    ///
    /// * `storage_url` - Base URL of the storage service
    pub fn new(storage_url: impl Into<String>) -> Self {
        Self {
            storage_url: storage_url.into(),
            default_retention_minutes: 7 * 24 * 60, // 7 days in minutes
        }
    }

    /// Set the default retention period.
    pub fn with_retention_minutes(mut self, minutes: u32) -> Self {
        self.default_retention_minutes = minutes;
        self
    }
}

/// Uploads files to UHRP storage hosts.
///
/// The uploader communicates with a storage service to:
/// - Upload files with retention periods
/// - Find file metadata
/// - List uploaded files
/// - Renew file retention
///
/// # Note
///
/// Full functionality requires the `http` feature and authenticated
/// HTTP client integration with a wallet.
///
/// # Example
///
/// ```rust,ignore
/// use bsv_rs::storage::{StorageUploader, StorageUploaderConfig, UploadableFile};
///
/// let config = StorageUploaderConfig::new("https://storage.example.com");
/// let uploader = StorageUploader::new(config);
///
/// let file = UploadableFile::new(b"Hello, World!".to_vec(), "text/plain");
/// let result = uploader.publish_file(&file, None).await?;
/// println!("Uploaded to: {}", result.uhrp_url);
/// ```
pub struct StorageUploader {
    base_url: String,
    #[allow(dead_code)]
    default_retention_minutes: u32,
    #[cfg(feature = "http")]
    client: reqwest::Client,
}

impl StorageUploader {
    /// Create a new StorageUploader.
    pub fn new(config: StorageUploaderConfig) -> Self {
        Self {
            base_url: config.storage_url,
            default_retention_minutes: config.default_retention_minutes,
            #[cfg(feature = "http")]
            client: reqwest::Client::new(),
        }
    }

    /// Get the base URL of the storage service.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Upload a file to storage.
    ///
    /// # Arguments
    ///
    /// * `file` - The file to upload
    /// * `retention_minutes` - Optional override for retention period (in minutes)
    ///
    /// # Returns
    ///
    /// Upload result with UHRP URL if successful.
    #[cfg(feature = "http")]
    pub async fn publish_file(
        &self,
        file: &UploadableFile,
        retention_minutes: Option<u32>,
    ) -> Result<UploadFileResult> {
        let retention = retention_minutes.unwrap_or(self.default_retention_minutes);

        // Step 1: Get upload info from server
        let upload_info = self.get_upload_info(file.size(), retention).await?;

        // Step 2: Upload file to presigned URL
        self.upload_file(&upload_info, file).await
    }

    /// Upload a file to storage (without http feature).
    #[cfg(not(feature = "http"))]
    pub async fn publish_file(
        &self,
        _file: &UploadableFile,
        _retention_minutes: Option<u32>,
    ) -> Result<UploadFileResult> {
        Err(Error::OverlayError(
            "HTTP feature not enabled. Enable the 'http' feature to use upload functionality."
                .to_string(),
        ))
    }

    /// Find information about a stored file.
    ///
    /// # Arguments
    ///
    /// * `uhrp_url` - The UHRP URL to look up
    ///
    /// # Returns
    ///
    /// File metadata if found.
    #[cfg(feature = "http")]
    pub async fn find_file(&self, uhrp_url: &str) -> Result<Option<FindFileData>> {
        let url = format!(
            "{}/find?uhrpUrl={}",
            self.base_url,
            urlencoding::encode(uhrp_url)
        );

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| Error::OverlayError(format!("findFile request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::OverlayError(format!(
                "findFile request failed: HTTP {}",
                response.status()
            )));
        }

        #[derive(serde::Deserialize)]
        struct FindResponse {
            status: String,
            data: Option<FindFileData>,
            #[serde(default)]
            code: Option<String>,
            #[serde(default)]
            description: Option<String>,
        }

        let resp: FindResponse = response.json().await.map_err(|e| {
            Error::OverlayError(format!("Failed to parse findFile response: {}", e))
        })?;

        if resp.status == STATUS_ERROR {
            return Err(Error::OverlayError(format!(
                "findFile returned an error: {} - {}",
                resp.code.unwrap_or_else(|| "unknown-code".to_string()),
                resp.description
                    .unwrap_or_else(|| "no-description".to_string())
            )));
        }

        Ok(resp.data)
    }

    /// Find information about a stored file (without http feature).
    #[cfg(not(feature = "http"))]
    pub async fn find_file(&self, _uhrp_url: &str) -> Result<Option<FindFileData>> {
        Err(Error::OverlayError(
            "HTTP feature not enabled. Enable the 'http' feature to use find functionality."
                .to_string(),
        ))
    }

    /// List files uploaded by this client.
    ///
    /// # Returns
    ///
    /// A JSON value containing the list of uploads.
    #[cfg(feature = "http")]
    pub async fn list_uploads(&self) -> Result<serde_json::Value> {
        let url = format!("{}/list", self.base_url);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| Error::OverlayError(format!("listUploads request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::OverlayError(format!(
                "listUploads request failed: HTTP {}",
                response.status()
            )));
        }

        #[derive(serde::Deserialize)]
        struct ListResponse {
            status: String,
            uploads: Option<serde_json::Value>,
            #[serde(default)]
            code: Option<String>,
            #[serde(default)]
            description: Option<String>,
        }

        let resp: ListResponse = response.json().await.map_err(|e| {
            Error::OverlayError(format!("Failed to parse listUploads response: {}", e))
        })?;

        if resp.status == STATUS_ERROR {
            return Err(Error::OverlayError(format!(
                "listUploads returned an error: {} - {}",
                resp.code.unwrap_or_else(|| "unknown-code".to_string()),
                resp.description
                    .unwrap_or_else(|| "no-description".to_string())
            )));
        }

        Ok(resp.uploads.unwrap_or(serde_json::Value::Array(vec![])))
    }

    /// List files uploaded by this client (without http feature).
    #[cfg(not(feature = "http"))]
    pub async fn list_uploads(&self) -> Result<serde_json::Value> {
        Err(Error::OverlayError(
            "HTTP feature not enabled. Enable the 'http' feature to use list functionality."
                .to_string(),
        ))
    }

    /// Renew a file's retention period.
    ///
    /// # Arguments
    ///
    /// * `uhrp_url` - The UHRP URL to renew
    /// * `additional_minutes` - Minutes to add to retention
    ///
    /// # Returns
    ///
    /// Renewal result with new expiry time.
    #[cfg(feature = "http")]
    pub async fn renew_file(
        &self,
        uhrp_url: &str,
        additional_minutes: u32,
    ) -> Result<RenewFileResult> {
        let url = format!("{}/renew", self.base_url);

        let body = serde_json::json!({
            "uhrpUrl": uhrp_url,
            "additionalMinutes": additional_minutes,
        });

        let response = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::OverlayError(format!("renewFile request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::OverlayError(format!(
                "renewFile request failed: HTTP {}",
                response.status()
            )));
        }

        #[derive(serde::Deserialize)]
        struct RenewResponse {
            status: String,
            #[serde(rename = "prevExpiryTime")]
            prev_expiry_time: Option<i64>,
            #[serde(rename = "newExpiryTime")]
            new_expiry_time: Option<i64>,
            amount: Option<i64>,
            #[serde(default)]
            code: Option<String>,
            #[serde(default)]
            description: Option<String>,
        }

        let resp: RenewResponse = response.json().await.map_err(|e| {
            Error::OverlayError(format!("Failed to parse renewFile response: {}", e))
        })?;

        if resp.status == STATUS_ERROR {
            return Err(Error::OverlayError(format!(
                "renewFile returned an error: {} - {}",
                resp.code.unwrap_or_else(|| "unknown-code".to_string()),
                resp.description
                    .unwrap_or_else(|| "no-description".to_string())
            )));
        }

        Ok(RenewFileResult {
            status: resp.status,
            previous_expiry: resp.prev_expiry_time.unwrap_or(0),
            new_expiry: resp.new_expiry_time.unwrap_or(0),
            amount: resp.amount.unwrap_or(0),
        })
    }

    /// Renew a file's retention period (without http feature).
    #[cfg(not(feature = "http"))]
    pub async fn renew_file(
        &self,
        _uhrp_url: &str,
        _additional_minutes: u32,
    ) -> Result<RenewFileResult> {
        Err(Error::OverlayError(
            "HTTP feature not enabled. Enable the 'http' feature to use renew functionality."
                .to_string(),
        ))
    }

    #[cfg(feature = "http")]
    async fn get_upload_info(
        &self,
        file_size: usize,
        retention_minutes: u32,
    ) -> Result<UploadInfo> {
        let url = format!("{}/upload", self.base_url);

        let body = serde_json::json!({
            "fileSize": file_size,
            "retentionPeriod": retention_minutes,
        });

        let response = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::OverlayError(format!("Failed to get upload info: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::OverlayError(format!(
                "Upload info request failed: HTTP {}",
                response.status()
            )));
        }

        let info: UploadInfo = response
            .json()
            .await
            .map_err(|e| Error::OverlayError(format!("Failed to parse upload info: {}", e)))?;

        if info.status == STATUS_ERROR {
            return Err(Error::OverlayError(
                "Upload route returned an error".to_string(),
            ));
        }

        Ok(info)
    }

    #[cfg(feature = "http")]
    async fn upload_file(
        &self,
        upload_info: &UploadInfo,
        file: &UploadableFile,
    ) -> Result<UploadFileResult> {
        let mut request = self
            .client
            .put(&upload_info.upload_url)
            .header("content-type", &file.mime_type)
            .body(file.data.clone());

        // Add required headers
        for (key, value) in &upload_info.required_headers {
            request = request.header(key, value);
        }

        let response = request
            .send()
            .await
            .map_err(|e| Error::OverlayError(format!("File upload failed: {}", e)))?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(Error::OverlayError(format!(
                "File upload failed: HTTP {} - {}",
                status, body
            )));
        }

        // Generate UHRP URL for the uploaded file
        let uhrp_url = get_url_for_file(&file.data)?;

        Ok(UploadFileResult::new(uhrp_url, true))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_new() {
        let config = StorageUploaderConfig::new("https://storage.example.com");
        assert_eq!(config.storage_url, "https://storage.example.com");
        assert_eq!(config.default_retention_minutes, 7 * 24 * 60);
    }

    #[test]
    fn test_config_with_retention() {
        let config =
            StorageUploaderConfig::new("https://storage.example.com").with_retention_minutes(1440);
        assert_eq!(config.default_retention_minutes, 1440);
    }

    #[test]
    fn test_uploader_creation() {
        let config = StorageUploaderConfig::new("https://storage.example.com");
        let uploader = StorageUploader::new(config);
        assert_eq!(uploader.base_url(), "https://storage.example.com");
    }
}
