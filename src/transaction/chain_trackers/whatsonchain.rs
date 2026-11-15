//! WhatsOnChain Chain Tracker
//!
//! Implements the [`ChainTracker`] trait using the WhatsOnChain API.
//!
//! WhatsOnChain is a blockchain explorer that provides free API access
//! for querying block headers and chain information.
//!
//! # Example
//!
//! ```rust,ignore
//! use bsv_rs::transaction::{ChainTracker, WhatsOnChainTracker, WocNetwork};
//!
//! #[tokio::main]
//! async fn main() {
//!     // Use mainnet
//!     let tracker = WhatsOnChainTracker::mainnet();
//!
//!     // Or testnet
//!     let tracker = WhatsOnChainTracker::testnet();
//!
//!     // Verify a merkle root
//!     let is_valid = tracker
//!         .is_valid_root_for_height("abc123...", 700000)
//!         .await
//!         .unwrap();
//!
//!     // Get current height
//!     let height = tracker.current_height().await.unwrap();
//! }
//! ```
//!
//! # Reference
//!
//! - [WhatsOnChain API](https://developers.whatsonchain.com/)

use async_trait::async_trait;

#[cfg(feature = "http")]
use crate::transaction::broadcasters::transport_fault as fault;
use crate::transaction::{ChainTracker, ChainTrackerError};

/// WhatsOnChain network selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WocNetwork {
    /// BSV Mainnet
    #[default]
    Mainnet,
    /// BSV Testnet
    Testnet,
}

impl WocNetwork {
    /// Get the base URL for this network.
    pub fn base_url(&self) -> &'static str {
        match self {
            WocNetwork::Mainnet => "https://api.whatsonchain.com/v1/bsv/main",
            WocNetwork::Testnet => "https://api.whatsonchain.com/v1/bsv/test",
        }
    }
}

/// Default per-request timeout, in milliseconds (30 s).
///
/// Every request this tracker makes is bounded by this, matching the sibling
/// [`BlockHeadersServiceTracker`](super::BlockHeadersServiceTracker) (whose
/// `timeout_ms` defaults to the same) and the TypeScript reference's default
/// HTTP client, which its tracker takes when it is given none
/// (`ts-stack@edf6e03` `transaction/chaintrackers/WhatsOnChain.ts:64`;
/// `DEFAULT_HTTP_CLIENT_TIMEOUT_MS = 30_000`,
/// `transaction/http/HttpClientResponseUtils.ts:4,15`, applied to each
/// request at `FetchHttpClient.ts:49` and `NodejsHttpRequestUtils.ts:145-156`).
/// Without a bound a response whose body never arrives would hold the call,
/// and any `Transaction::verify` awaiting it, without end.
///
/// Public as `bsv_rs::transaction::DEFAULT_WOC_TIMEOUT_MS` and
/// `bsv_rs::transaction::chain_trackers::DEFAULT_WOC_TIMEOUT_MS`.
pub const DEFAULT_WOC_TIMEOUT_MS: u64 = 30_000;

/// WhatsOnChain chain tracker.
///
/// Verifies merkle roots and queries chain height using the WhatsOnChain API.
///
/// # Example
///
/// ```rust,ignore
/// use bsv_rs::transaction::{ChainTracker, WhatsOnChainTracker};
///
/// let tracker = WhatsOnChainTracker::mainnet();
/// let height = tracker.current_height().await?;
/// ```
pub struct WhatsOnChainTracker {
    network: WocNetwork,
    base_url_override: Option<String>,
    /// Per-request timeout, in milliseconds (default [`DEFAULT_WOC_TIMEOUT_MS`]).
    timeout_ms: u64,
    #[cfg(feature = "http")]
    client: reqwest::Client,
}

impl WhatsOnChainTracker {
    /// Create a tracker for mainnet.
    pub fn mainnet() -> Self {
        Self::new(WocNetwork::Mainnet)
    }

    /// Create a tracker for testnet.
    pub fn testnet() -> Self {
        Self::new(WocNetwork::Testnet)
    }

    /// Create a tracker for the specified network.
    pub fn new(network: WocNetwork) -> Self {
        Self {
            network,
            base_url_override: None,
            timeout_ms: DEFAULT_WOC_TIMEOUT_MS,
            #[cfg(feature = "http")]
            client: reqwest::Client::new(),
        }
    }

    /// Create a tracker with a custom base URL (useful for testing).
    pub fn with_base_url(base_url: &str, network: WocNetwork) -> Self {
        Self {
            network,
            base_url_override: Some(base_url.to_string()),
            timeout_ms: DEFAULT_WOC_TIMEOUT_MS,
            #[cfg(feature = "http")]
            client: reqwest::Client::new(),
        }
    }

    /// Set the per-request timeout, in milliseconds (default
    /// [`DEFAULT_WOC_TIMEOUT_MS`], 30 s). Bounds every request this tracker
    /// makes, as the sibling `BlockHeadersServiceTracker` and the reference do.
    ///
    /// The bound runs from the request's start until its body is read; a
    /// request it ends is a transport fault
    /// (`TransportFault::MayHaveBeenReceived`), never a verdict. A timeout of
    /// `0` is no value of its own and does not turn the bound off: the bound
    /// is then the timer's next tick (about a millisecond), so a request ends
    /// as that fault unless its whole answer arrives inside the tick, which a
    /// server on the same host can do. A very large one (up to `u64::MAX`) is
    /// taken without a panic and is, in effect, no bound.
    #[must_use]
    pub fn with_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Get the configured network.
    pub fn network(&self) -> WocNetwork {
        self.network
    }

    /// Get the configured per-request timeout, in milliseconds.
    #[must_use]
    pub fn timeout_ms(&self) -> u64 {
        self.timeout_ms
    }

    /// Get the effective base URL.
    #[cfg(feature = "http")]
    fn base_url(&self) -> &str {
        self.base_url_override
            .as_deref()
            .unwrap_or_else(|| self.network.base_url())
    }
}

impl Default for WhatsOnChainTracker {
    fn default() -> Self {
        Self::mainnet()
    }
}

impl std::fmt::Debug for WhatsOnChainTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WhatsOnChainTracker")
            .field("network", &self.network)
            .field("base_url_override", &self.base_url_override)
            .field("timeout_ms", &self.timeout_ms)
            .finish()
    }
}

#[async_trait]
impl ChainTracker for WhatsOnChainTracker {
    #[cfg(feature = "http")]
    async fn is_valid_root_for_height(
        &self,
        root: &str,
        height: u32,
    ) -> Result<bool, ChainTrackerError> {
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct BlockHeader {
            merkleroot: String,
        }

        let url = format!("{}/block/{}/header", self.base_url(), height);

        let response = self
            .client
            .get(&url)
            .timeout(std::time::Duration::from_millis(self.timeout_ms))
            .send()
            .await
            .map_err(|e| fault::tracker_send_error(&e))?;

        if response.status().as_u16() == 404 {
            return Err(ChainTrackerError::BlockNotFound(height));
        }

        if !response.status().is_success() {
            return Err(fault::tracker_status_error(&response));
        }

        let header: BlockHeader = response
            .json()
            .await
            .map_err(|e| fault::tracker_body_error(&e))?;

        // Compare merkle roots case-insensitively
        Ok(header.merkleroot.to_lowercase() == root.to_lowercase())
    }

    #[cfg(not(feature = "http"))]
    async fn is_valid_root_for_height(
        &self,
        _root: &str,
        _height: u32,
    ) -> Result<bool, ChainTrackerError> {
        Err(ChainTrackerError::NetworkError(
            "HTTP feature not enabled. Add 'http' feature to Cargo.toml".to_string(),
        ))
    }

    #[cfg(feature = "http")]
    async fn current_height(&self) -> Result<u32, ChainTrackerError> {
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct ChainInfo {
            blocks: u32,
        }

        let url = format!("{}/chain/info", self.base_url());

        let response = self
            .client
            .get(&url)
            .timeout(std::time::Duration::from_millis(self.timeout_ms))
            .send()
            .await
            .map_err(|e| fault::tracker_send_error(&e))?;

        if !response.status().is_success() {
            return Err(fault::tracker_status_error(&response));
        }

        let info: ChainInfo = response
            .json()
            .await
            .map_err(|e| fault::tracker_body_error(&e))?;

        Ok(info.blocks)
    }

    #[cfg(not(feature = "http"))]
    async fn current_height(&self) -> Result<u32, ChainTrackerError> {
        Err(ChainTrackerError::NetworkError(
            "HTTP feature not enabled. Add 'http' feature to Cargo.toml".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_woc_network_urls() {
        assert_eq!(
            WocNetwork::Mainnet.base_url(),
            "https://api.whatsonchain.com/v1/bsv/main"
        );
        assert_eq!(
            WocNetwork::Testnet.base_url(),
            "https://api.whatsonchain.com/v1/bsv/test"
        );
    }

    #[test]
    fn test_woc_network_default() {
        assert_eq!(WocNetwork::default(), WocNetwork::Mainnet);
    }

    #[test]
    fn test_woc_tracker_mainnet() {
        let tracker = WhatsOnChainTracker::mainnet();
        assert_eq!(tracker.network(), WocNetwork::Mainnet);
    }

    #[test]
    fn test_woc_tracker_testnet() {
        let tracker = WhatsOnChainTracker::testnet();
        assert_eq!(tracker.network(), WocNetwork::Testnet);
    }

    #[test]
    fn test_woc_tracker_new() {
        let tracker = WhatsOnChainTracker::new(WocNetwork::Testnet);
        assert_eq!(tracker.network(), WocNetwork::Testnet);
    }

    #[test]
    fn test_woc_tracker_default() {
        let tracker = WhatsOnChainTracker::default();
        assert_eq!(tracker.network(), WocNetwork::Mainnet);
    }

    #[test]
    fn the_woc_tracker_default_timeout_is_30s_98() {
        // The bound matches the sibling BlockHeadersServiceTracker and the
        // reference's default HTTP client (30 s), so no request is unbounded.
        assert_eq!(DEFAULT_WOC_TIMEOUT_MS, 30_000);
        assert_eq!(WhatsOnChainTracker::mainnet().timeout_ms(), 30_000);
        assert_eq!(
            WhatsOnChainTracker::with_base_url("http://localhost", WocNetwork::Testnet)
                .timeout_ms(),
            30_000
        );
    }

    #[test]
    fn the_woc_tracker_with_timeout_ms_overrides_98() {
        let tracker = WhatsOnChainTracker::mainnet().with_timeout_ms(500);
        assert_eq!(tracker.timeout_ms(), 500);
        // The builder preserves the rest of the tracker's configuration.
        assert_eq!(tracker.network(), WocNetwork::Mainnet);
    }
}
