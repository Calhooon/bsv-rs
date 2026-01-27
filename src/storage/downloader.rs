//! UHRP file downloader.
//!
//! Downloads files from UHRP URLs by resolving storage hosts via the overlay
//! network lookup service and fetching content with hash verification.

use crate::overlay::{
    LookupAnswer, LookupQuestion, LookupResolver, LookupResolverConfig, NetworkPreset,
};
use crate::primitives::Reader;
use crate::script::templates::PushDrop;
use crate::transaction::Transaction;
use crate::{Error, Result};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use super::types::DownloadResult;
use super::utils::is_valid_url;

#[cfg(feature = "http")]
use super::utils::get_hash_from_url;
#[cfg(feature = "http")]
use crate::primitives::hash::sha256;

/// Configuration for StorageDownloader.
#[derive(Clone)]
pub struct StorageDownloaderConfig {
    /// Network preset (mainnet, testnet, local).
    pub network_preset: NetworkPreset,
    /// Custom lookup resolver (uses default if None).
    pub resolver: Option<Arc<LookupResolver>>,
    /// Timeout for download operations in milliseconds.
    pub timeout_ms: Option<u64>,
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

/// Downloads files from UHRP URLs via the overlay network.
///
/// The downloader resolves storage hosts by querying the `ls_uhrp` lookup service,
/// then downloads the file from available hosts with content verification.
///
/// # Example
///
/// ```rust,ignore
/// use bsv_sdk::storage::{StorageDownloader, StorageDownloaderConfig};
///
/// let downloader = StorageDownloader::new(StorageDownloaderConfig::default());
/// let result = downloader.download("uhrp://...").await?;
/// println!("Downloaded {} bytes", result.data.len());
/// ```
pub struct StorageDownloader {
    resolver: Arc<LookupResolver>,
    #[allow(dead_code)]
    timeout_ms: Option<u64>,
}

impl StorageDownloader {
    /// Create a new StorageDownloader with the given configuration.
    pub fn new(config: StorageDownloaderConfig) -> Self {
        let resolver = config.resolver.unwrap_or_else(|| {
            Arc::new(LookupResolver::new(LookupResolverConfig {
                network_preset: config.network_preset,
                ..Default::default()
            }))
        });

        Self {
            resolver,
            timeout_ms: config.timeout_ms,
        }
    }

    /// Resolve a UHRP URL to find storage hosts.
    ///
    /// Queries the `ls_uhrp` lookup service to find hosts that have the file.
    ///
    /// # Arguments
    ///
    /// * `uhrp_url` - The UHRP URL to resolve
    ///
    /// # Returns
    ///
    /// A list of host URLs that have the file.
    pub async fn resolve(&self, uhrp_url: &str) -> Result<Vec<String>> {
        if !is_valid_url(uhrp_url) {
            return Err(Error::InvalidBase58("Invalid UHRP URL".to_string()));
        }

        let question = LookupQuestion::new("ls_uhrp", serde_json::json!({ "uhrpUrl": uhrp_url }));

        let answer = self.resolver.query(&question, self.timeout_ms).await?;

        let outputs = match answer {
            LookupAnswer::OutputList { outputs } => outputs,
            _ => return Ok(Vec::new()),
        };

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let mut hosts = Vec::new();

        for output in outputs {
            // Parse BEEF to get transaction
            let tx = match Transaction::from_beef(&output.beef, None) {
                Ok(tx) => tx,
                Err(_) => continue,
            };

            // Get the output
            let tx_output = match tx.outputs.get(output.output_index as usize) {
                Some(o) => o,
                None => continue,
            };

            // Decode PushDrop fields
            let pd = match PushDrop::decode(&tx_output.locking_script) {
                Ok(pd) => pd,
                Err(_) => continue,
            };

            // Need at least 4 fields: protocol, identity, domain, expiry
            if pd.fields.len() < 4 {
                continue;
            }

            // Check expiry time (field 3 is expiry as varint)
            let expiry_time = match parse_expiry(&pd.fields[3]) {
                Some(t) => t,
                None => continue,
            };

            if expiry_time < current_time {
                continue; // Expired
            }

            // Field 2 is the host URL
            if let Ok(host_url) = String::from_utf8(pd.fields[2].clone()) {
                if !host_url.is_empty() && is_valid_host_url(&host_url) {
                    hosts.push(host_url);
                }
            }
        }

        Ok(hosts)
    }

    /// Download a file from a UHRP URL.
    ///
    /// Resolves storage hosts and downloads the file, verifying the content
    /// hash matches the URL.
    ///
    /// # Arguments
    ///
    /// * `uhrp_url` - The UHRP URL to download
    ///
    /// # Returns
    ///
    /// The file content and MIME type.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The UHRP URL is invalid
    /// - No hosts are found
    /// - All download attempts fail
    /// - Content hash verification fails
    #[cfg(feature = "http")]
    pub async fn download(&self, uhrp_url: &str) -> Result<DownloadResult> {
        if !is_valid_url(uhrp_url) {
            return Err(Error::InvalidBase58("Invalid UHRP URL".to_string()));
        }

        let expected_hash = get_hash_from_url(uhrp_url)?;
        let hosts = self.resolve(uhrp_url).await?;

        if hosts.is_empty() {
            return Err(Error::OverlayError(
                "No one currently hosts this file".to_string(),
            ));
        }

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(
                self.timeout_ms.unwrap_or(30000),
            ))
            .build()
            .map_err(|e| Error::OverlayError(format!("Failed to create HTTP client: {}", e)))?;

        let mut last_error = None;

        for host in &hosts {
            match self.try_download(&client, host, &expected_hash).await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    last_error = Some(e);
                    continue;
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            Error::OverlayError(format!("Unable to download content from {}", uhrp_url))
        }))
    }

    /// Download without http feature (returns error).
    #[cfg(not(feature = "http"))]
    pub async fn download(&self, _uhrp_url: &str) -> Result<DownloadResult> {
        Err(Error::OverlayError(
            "HTTP feature not enabled. Enable the 'http' feature to use download functionality."
                .to_string(),
        ))
    }

    #[cfg(feature = "http")]
    async fn try_download(
        &self,
        client: &reqwest::Client,
        host: &str,
        expected_hash: &[u8; 32],
    ) -> Result<DownloadResult> {
        let response = client
            .get(host)
            .send()
            .await
            .map_err(|e| Error::OverlayError(format!("HTTP request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::OverlayError(format!(
                "HTTP {} from {}",
                response.status(),
                host
            )));
        }

        let mime_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/octet-stream")
            .to_string();

        let data = response
            .bytes()
            .await
            .map_err(|e| Error::OverlayError(format!("Failed to read response body: {}", e)))?
            .to_vec();

        // Verify hash
        let content_hash = sha256(&data);
        if &content_hash != expected_hash {
            return Err(Error::OverlayError(format!(
                "Content hash mismatch from {}",
                host
            )));
        }

        Ok(DownloadResult::new(data, mime_type))
    }
}

impl Default for StorageDownloader {
    fn default() -> Self {
        Self::new(StorageDownloaderConfig::default())
    }
}

/// Parse expiry time from PushDrop field (varint encoding).
fn parse_expiry(field: &[u8]) -> Option<i64> {
    if field.is_empty() {
        return None;
    }

    // Try to read as varint
    let mut reader = Reader::new(field);
    reader.read_var_int().ok().map(|v| v as i64)
}

/// Validate a host URL is well-formed.
fn is_valid_host_url(url: &str) -> bool {
    url.starts_with("http://") || url.starts_with("https://")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = StorageDownloaderConfig::default();
        assert_eq!(config.network_preset, NetworkPreset::Mainnet);
        assert!(config.resolver.is_none());
        assert_eq!(config.timeout_ms, Some(30000));
    }

    #[test]
    fn test_downloader_creation() {
        let downloader = StorageDownloader::default();
        assert!(downloader.timeout_ms.is_some());
    }

    #[test]
    fn test_parse_expiry_valid() {
        // Varint 0x01 = 1
        assert_eq!(parse_expiry(&[0x01]), Some(1));

        // Varint 0xFC = 252
        assert_eq!(parse_expiry(&[0xFC]), Some(252));

        // Varint 0xFD 0x00 0x01 = 256
        assert_eq!(parse_expiry(&[0xFD, 0x00, 0x01]), Some(256));
    }

    #[test]
    fn test_parse_expiry_empty() {
        assert_eq!(parse_expiry(&[]), None);
    }

    #[test]
    fn test_is_valid_host_url() {
        assert!(is_valid_host_url("https://example.com"));
        assert!(is_valid_host_url("http://localhost:8080"));
        assert!(!is_valid_host_url("ftp://example.com"));
        assert!(!is_valid_host_url("example.com"));
    }
}
