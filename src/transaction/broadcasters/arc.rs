//! ARC (Avalanche Relay Client) Broadcaster
//!
//! Implements the [`Broadcaster`] trait for the ARC network.
//!
//! ARC is TAAL's transaction processing service that provides reliable
//! transaction broadcasting with callback notifications.
//!
//! # The verdict
//!
//! ARC answers `POST /v1/tx` with an HTTP 2xx whenever it processed the
//! request, and puts the transaction's fate in the body's `txStatus`
//! (`arc@e7efc5b internal/api/handler/default.go:489-500`). The HTTP code is a
//! word about transport, not about the transaction, so the broadcaster reads
//! `txStatus` and applies the reference's rule
//! (`ts-stack@edf6e03 packages/sdk/src/transaction/broadcasters/ARC.ts:110-180`):
//!
//! - `DOUBLE_SPEND_ATTEMPTED`, `REJECTED`, `INVALID`, `MALFORMED`,
//!   `MINED_IN_STALE_BLOCK`, and any status or `extraInfo` containing `ORPHAN`,
//!   are a [`BroadcastFailure`] whose `code` is the status word, whose
//!   `description` is the status word and the `extraInfo`, and whose `more`
//!   carries `extraInfo` and `competingTxs` when ARC sent them;
//! - a 2xx with no `txStatus` is a failure (`ERR_INVALID_RESPONSE`), never a
//!   success; so is a status word the reference does not accept, and a
//!   `competingTxs` list that is not a list of distinct transaction ids;
//! - a failure that names another transaction's id is `ERR_TXID_MISMATCH`;
//! - `SUCCESS`, `RECEIVED`, `SENT_TO_NETWORK`, `ANNOUNCED_TO_NETWORK`,
//!   `ACCEPTED_BY_NETWORK`, `SEEN_ON_NETWORK`, `STORED`, `MINED` and
//!   `IMMUTABLE` are a [`BroadcastResponse`] whose `message` is the status word
//!   and whose `competing_txs` are ARC's, normalized to lower case.
//!
//! Before 0.3.34 every 2xx was a success with the status word as its message,
//! so a wallet recorded as accepted a transaction the node refused.
//!
//! # Example
//!
//! ```rust,ignore
//! use bsv_rs::transaction::{ArcBroadcaster, Broadcaster, Transaction};
//!
//! #[tokio::main]
//! async fn main() {
//!     let broadcaster = ArcBroadcaster::new("https://arc.taal.com", None);
//!     let tx = Transaction::from_hex("...").unwrap();
//!
//!     match broadcaster.broadcast(&tx).await {
//!         Ok(response) => println!("Broadcast success: {}", response.txid),
//!         Err(failure) => println!("Broadcast failed: {}", failure.description),
//!     }
//! }
//! ```
//!
//! # Reference
//!
//! - [ARC Documentation](https://github.com/bitcoin-sv/arc)

use async_trait::async_trait;

use crate::transaction::{
    BroadcastFailure, BroadcastResult, BroadcastStatus, Broadcaster, Transaction,
};

/// The verdict on a 2xx answer and its pieces. Only the `http` broadcast path
/// and the tests use them, so a build without `http` is allowed the dead code.
#[cfg_attr(not(feature = "http"), allow(dead_code))]
mod verdict {
    use serde::Deserialize;
    use serde_json::Value;

    use crate::transaction::{
        BroadcastFailure, BroadcastResponse, BroadcastResult, BroadcastStatus,
    };

    /// The `txStatus` words the reference maps to a failure even on an HTTP 2xx
    /// (`ts-stack@edf6e03 packages/sdk/src/transaction/broadcasters/ARC.ts:16-22`).
    const ARC_FAILURE_STATUSES: [&str; 5] = [
        "DOUBLE_SPEND_ATTEMPTED",
        "REJECTED",
        "INVALID",
        "MALFORMED",
        "MINED_IN_STALE_BLOCK",
    ];

    /// The `txStatus` words accepted on a 2xx: the reference's set (`ARC.ts:28-38`)
    /// plus the three non-error states the reference's own spec and go-sdk accept
    /// and the reference's code does not (`specs/broadcast/arc.yaml:407-415` lists
    /// REQUESTED_BY_NETWORK as a success status; `go-sdk transaction/broadcaster/arc.go:18-31`
    /// accepts QUEUED, REQUESTED_BY_NETWORK and CONFIRMED). Every accepted word is a
    /// hint about the transaction, never evidence (bsv-stack-lean, the tracker);
    /// any other word on a 2xx is an invalid response (`ARC.ts:157-159`).
    const ARC_ACCEPTED_STATUSES: [&str; 12] = [
        "SUCCESS",
        "RECEIVED",
        "QUEUED",
        "STORED",
        "ANNOUNCED_TO_NETWORK",
        "REQUESTED_BY_NETWORK",
        "SENT_TO_NETWORK",
        "ACCEPTED_BY_NETWORK",
        "SEEN_ON_NETWORK",
        "MINED",
        "CONFIRMED",
        "IMMUTABLE",
    ];

    /// The reference's bounds on the body's words (`ARC.ts:24-26`).
    const MAX_ARC_STATUS_BYTES: usize = 128;
    const MAX_ARC_INFO_BYTES: usize = 8192;
    const MAX_COMPETING_TXS: usize = 256;

    /// The body of an ARC `POST /v1/tx` answer: the fields of the success envelope
    /// (`arc@e7efc5b internal/api/handler/default.go:489-500`) and of the error
    /// envelope (`status`, `title`, `detail`). Unknown fields are ignored.
    #[derive(Debug, Default, Deserialize)]
    pub(crate) struct ArcTxResponse {
        pub(crate) txid: Option<String>,
        #[serde(rename = "txStatus")]
        pub(crate) tx_status: Option<String>,
        #[serde(rename = "extraInfo")]
        pub(crate) extra_info: Option<String>,
        /// ARC sends `null` here on an ordinary answer (`pkg/api/arc.go:429` has no
        /// `omitempty`); `Option` reads a `null` as absent. Anything else is judged
        /// by [`snapshot_competing_txs`].
        #[serde(rename = "competingTxs")]
        pub(crate) competing_txs: Option<Value>,
        pub(crate) status: Option<u16>,
        pub(crate) title: Option<String>,
        pub(crate) detail: Option<String>,
    }

    /// The reference's `boundedText` (`ARC.ts:40-47`, `primitives/UTF8.ts:11-17`):
    /// within the byte bound, no control character, and non-empty unless allowed.
    fn bounded_text(value: &str, max_bytes: usize, allow_empty: bool) -> bool {
        (allow_empty || !value.is_empty())
            && value.len() <= max_bytes
            && !value
                .chars()
                .any(|c| matches!(c as u32, 0x00..=0x1f | 0x7f..=0x9f))
    }

    /// 64 hexadecimal digits, either case.
    fn is_txid(value: &str) -> bool {
        value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
    }

    /// The reference's `snapshotCompetingTxs` (`ARC.ts:64-93`): a list of at most
    /// [`MAX_COMPETING_TXS`] distinct transaction ids, normalized to lower case;
    /// `None` for anything else.
    fn snapshot_competing_txs(value: &Value) -> Option<Vec<String>> {
        let list = value.as_array()?;
        if list.len() > MAX_COMPETING_TXS {
            return None;
        }
        let mut result: Vec<String> = Vec::with_capacity(list.len());
        for entry in list {
            let candidate = entry.as_str()?;
            if !is_txid(candidate) {
                return None;
            }
            let normalized = candidate.to_ascii_lowercase();
            if result.contains(&normalized) {
                return None;
            }
            result.push(normalized);
        }
        Some(result)
    }

    fn failure(code: &str, txid: &str, description: &str) -> BroadcastFailure {
        BroadcastFailure {
            status: BroadcastStatus::Error,
            code: code.to_string(),
            txid: Some(txid.to_string()),
            description: description.to_string(),
            more: None,
        }
    }

    /// The verdict on an HTTP 2xx answer from ARC: the body's `txStatus` decides,
    /// never the HTTP code (`ts-stack@edf6e03 ARC.ts:110-180`; the module docs).
    pub(crate) fn arc_success_verdict(body: ArcTxResponse, expected_txid: &str) -> BroadcastResult {
        let invalid =
            |description: &str| failure("ERR_INVALID_RESPONSE", expected_txid, description);

        // ARC.ts:123-128: a missing, empty, oversized or unprintable status word,
        // or an oversized or unprintable extraInfo, is an invalid response.
        let tx_status = match body.tx_status {
            Some(status) if bounded_text(&status, MAX_ARC_STATUS_BYTES, false) => status,
            _ => return Err(invalid("ARC returned invalid transaction status metadata.")),
        };
        let extra_info = match body.extra_info {
            Some(info) if !bounded_text(&info, MAX_ARC_INFO_BYTES, true) => {
                return Err(invalid("ARC returned invalid transaction status metadata."))
            }
            other => other,
        };

        // ARC.ts:129-132: competingTxs, when sent, is a list of distinct txids.
        let competing_txs = match body.competing_txs {
            None => None,
            Some(value) => match snapshot_competing_txs(&value) {
                Some(list) => Some(list),
                None => {
                    return Err(invalid(
                        "ARC returned invalid competing transaction identifiers.",
                    ))
                }
            },
        };

        // ARC.ts:133-155: the failure set and the ORPHAN rule, even on a 2xx.
        let upper_status = tx_status.to_uppercase();
        let is_orphan = upper_status.contains("ORPHAN")
            || extra_info
                .as_deref()
                .is_some_and(|info| info.to_uppercase().contains("ORPHAN"));
        if ARC_FAILURE_STATUSES.contains(&upper_status.as_str()) || is_orphan {
            if body.txid.as_deref().is_some_and(|echoed| {
                is_txid(echoed) && !echoed.eq_ignore_ascii_case(expected_txid)
            }) {
                return Err(failure(
                    "ERR_TXID_MISMATCH",
                    expected_txid,
                    "ARC returned a failure for another transaction.",
                ));
            }
            let description = match extra_info.as_deref() {
                Some(info) => format!("{} {}", tx_status, info).trim().to_string(),
                None => tx_status.clone(),
            };
            let mut more = serde_json::Map::new();
            if let Some(info) = extra_info.filter(|info| !info.is_empty()) {
                more.insert("extraInfo".to_string(), Value::String(info));
            }
            if let Some(list) = competing_txs {
                more.insert(
                    "competingTxs".to_string(),
                    Value::Array(list.into_iter().map(Value::String).collect()),
                );
            }
            return Err(BroadcastFailure {
                status: BroadcastStatus::Error,
                code: tx_status,
                txid: Some(expected_txid.to_string()),
                description,
                more: if more.is_empty() {
                    None
                } else {
                    Some(Value::Object(more))
                },
            });
        }

        // ARC.ts:157-159: a word the reference does not accept is not a success.
        if !ARC_ACCEPTED_STATUSES.contains(&upper_status.as_str()) {
            return Err(invalid("ARC returned an unknown transaction status."));
        }

        Ok(BroadcastResponse {
            status: BroadcastStatus::Success,
            txid: body.txid.unwrap_or_else(|| expected_txid.to_string()),
            message: tx_status,
            competing_txs,
        })
    }
}

/// ARC broadcaster configuration.
#[derive(Debug, Clone)]
pub struct ArcConfig {
    /// ARC API URL (e.g., `https://arc.taal.com`)
    pub url: String,
    /// API key for authentication (optional)
    pub api_key: Option<String>,
    /// Request timeout in milliseconds
    pub timeout_ms: u64,
}

impl Default for ArcConfig {
    fn default() -> Self {
        Self {
            url: "https://arc.taal.com".to_string(),
            api_key: None,
            timeout_ms: 30_000,
        }
    }
}

/// ARC broadcaster implementation.
///
/// Broadcasts transactions to the BSV network via TAAL's ARC service.
///
/// # Example
///
/// ```rust,ignore
/// use bsv_rs::transaction::{ArcBroadcaster, Broadcaster};
///
/// // Create with default URL
/// let broadcaster = ArcBroadcaster::default();
///
/// // Or with custom configuration
/// let broadcaster = ArcBroadcaster::new(
///     "https://arc.taal.com",
///     Some("your-api-key".to_string())
/// );
/// ```
pub struct ArcBroadcaster {
    config: ArcConfig,
    #[cfg(feature = "http")]
    client: reqwest::Client,
}

impl Default for ArcBroadcaster {
    fn default() -> Self {
        Self::new("https://arc.taal.com", None)
    }
}

impl ArcBroadcaster {
    /// Create a new ARC broadcaster.
    ///
    /// # Arguments
    ///
    /// * `url` - The ARC API URL
    /// * `api_key` - Optional API key for authentication
    pub fn new(url: &str, api_key: Option<String>) -> Self {
        Self {
            config: ArcConfig {
                url: url.to_string(),
                api_key,
                ..Default::default()
            },
            #[cfg(feature = "http")]
            client: reqwest::Client::new(),
        }
    }

    /// Create with full configuration.
    pub fn with_config(config: ArcConfig) -> Self {
        Self {
            config,
            #[cfg(feature = "http")]
            client: reqwest::Client::new(),
        }
    }

    /// Get the configured URL.
    pub fn url(&self) -> &str {
        &self.config.url
    }

    /// Get the configured API key.
    pub fn api_key(&self) -> Option<&str> {
        self.config.api_key.as_deref()
    }
}

#[async_trait(?Send)]
impl Broadcaster for ArcBroadcaster {
    #[cfg(feature = "http")]
    async fn broadcast(&self, tx: &Transaction) -> BroadcastResult {
        use serde::Serialize;

        #[derive(Serialize)]
        struct ArcRequest {
            #[serde(rename = "rawTx")]
            raw_tx: String,
        }

        let url = format!("{}/v1/tx", self.config.url);
        let raw_tx = tx.to_hex();
        let txid = tx.id();

        let mut request = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&ArcRequest { raw_tx });

        if let Some(ref api_key) = self.config.api_key {
            request = request.header("Authorization", format!("Bearer {}", api_key));
        }

        let response = request
            .timeout(std::time::Duration::from_millis(self.config.timeout_ms))
            .send()
            .await
            .map_err(|e| BroadcastFailure {
                status: BroadcastStatus::Error,
                code: "NETWORK_ERROR".to_string(),
                txid: Some(txid.clone()),
                description: format!("Network error: {}", e),
                more: None,
            })?;

        let status_code = response.status();
        let body: verdict::ArcTxResponse = response.json().await.map_err(|e| BroadcastFailure {
            status: BroadcastStatus::Error,
            code: "PARSE_ERROR".to_string(),
            txid: Some(txid.clone()),
            description: format!("Failed to parse response: {}", e),
            more: None,
        })?;

        if status_code.is_success() {
            verdict::arc_success_verdict(body, &txid)
        } else {
            Err(BroadcastFailure {
                status: BroadcastStatus::Error,
                code: body
                    .status
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "UNKNOWN".to_string()),
                txid: Some(txid),
                description: body
                    .detail
                    .or(body.title)
                    .unwrap_or_else(|| "Unknown error".to_string()),
                more: body.extra_info.map(serde_json::Value::String),
            })
        }
    }

    #[cfg(not(feature = "http"))]
    async fn broadcast(&self, tx: &Transaction) -> BroadcastResult {
        Err(BroadcastFailure {
            status: BroadcastStatus::Error,
            code: "NO_HTTP".to_string(),
            txid: Some(tx.id()),
            description: "HTTP feature not enabled. Add 'http' feature to Cargo.toml".to_string(),
            more: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::verdict::{arc_success_verdict, ArcTxResponse};
    use super::*;
    use serde_json::Value;

    const TXID: &str = "4d76b00f29e480e0a933cef9d9ffe303d6ab919e2cdb265dd2cea41089baa85a";

    fn body(json: Value) -> ArcTxResponse {
        serde_json::from_value(json).expect("an ARC body")
    }

    #[test]
    fn test_arc_config_default() {
        let config = ArcConfig::default();
        assert_eq!(config.url, "https://arc.taal.com");
        assert!(config.api_key.is_none());
        assert_eq!(config.timeout_ms, 30_000);
    }

    #[test]
    fn test_arc_broadcaster_new() {
        let broadcaster =
            ArcBroadcaster::new("https://custom.arc.com", Some("api_key".to_string()));
        assert_eq!(broadcaster.url(), "https://custom.arc.com");
        assert_eq!(broadcaster.api_key(), Some("api_key"));
    }

    #[test]
    fn test_arc_broadcaster_default() {
        let broadcaster = ArcBroadcaster::default();
        assert_eq!(broadcaster.url(), "https://arc.taal.com");
        assert!(broadcaster.api_key().is_none());
    }

    #[test]
    fn test_arc_broadcaster_with_config() {
        let config = ArcConfig {
            url: "https://test.arc.com".to_string(),
            api_key: Some("test-key".to_string()),
            timeout_ms: 60_000,
        };
        let broadcaster = ArcBroadcaster::with_config(config);
        assert_eq!(broadcaster.url(), "https://test.arc.com");
        assert_eq!(broadcaster.api_key(), Some("test-key"));
    }

    // The verdict on a 2xx (bsv-stack-lean #35, P0-2).

    #[test]
    fn a_rejected_tx_status_on_an_http_2xx_is_a_failure_with_the_status_as_code() {
        let verdict = arc_success_verdict(
            body(serde_json::json!({
                "txid": TXID, "txStatus": "REJECTED", "extraInfo": "insufficient fee",
                "competingTxs": null, "status": 200, "title": "OK"
            })),
            TXID,
        );
        let failure = verdict.expect_err("REJECTED on HTTP 200 is a failure");
        assert_eq!(failure.status, BroadcastStatus::Error);
        assert_eq!(failure.code, "REJECTED");
        assert_eq!(failure.description, "REJECTED insufficient fee");
        assert_eq!(failure.txid.as_deref(), Some(TXID));
        assert_eq!(
            failure.more,
            Some(serde_json::json!({"extraInfo": "insufficient fee"}))
        );
    }

    #[test]
    fn a_2xx_with_no_tx_status_is_a_failure_not_a_success() {
        let verdict = arc_success_verdict(
            body(serde_json::json!({"txid": TXID, "status": 200, "title": "OK"})),
            TXID,
        );
        let failure = verdict.expect_err("no txStatus is no verdict");
        assert_eq!(failure.code, "ERR_INVALID_RESPONSE");
        assert_eq!(
            failure.description,
            "ARC returned invalid transaction status metadata."
        );
    }

    #[test]
    fn double_spend_attempted_carries_the_competing_txs_into_the_failure() {
        let competitor = "F67CFB4C12B221AB1B5FEF6FDB5A72F82EBC6AAD8F28C6D0E5427043A2C5B0A9";
        let verdict = arc_success_verdict(
            body(serde_json::json!({
                "txid": TXID, "txStatus": "DOUBLE_SPEND_ATTEMPTED", "extraInfo": "",
                "competingTxs": [competitor], "status": 200, "title": "OK"
            })),
            TXID,
        );
        let failure = verdict.expect_err("DOUBLE_SPEND_ATTEMPTED on HTTP 200 is a failure");
        assert_eq!(failure.code, "DOUBLE_SPEND_ATTEMPTED");
        assert_eq!(failure.description, "DOUBLE_SPEND_ATTEMPTED");
        assert_eq!(
            failure.more,
            Some(serde_json::json!({"competingTxs": [competitor.to_ascii_lowercase()]}))
        );
    }

    #[test]
    fn an_accepted_tx_status_is_a_success_whose_message_is_the_status_word() {
        let verdict = arc_success_verdict(
            body(serde_json::json!({
                "txid": TXID, "txStatus": "SEEN_ON_NETWORK", "extraInfo": "extra info",
                "competingTxs": null, "status": 200, "title": "OK"
            })),
            TXID,
        );
        let response = verdict.expect("SEEN_ON_NETWORK is a success");
        assert_eq!(response.status, BroadcastStatus::Success);
        assert_eq!(response.txid, TXID);
        assert_eq!(response.message, "SEEN_ON_NETWORK");
        assert!(response.competing_txs.is_none());
    }

    /// Every recorded body of `tests/vectors/arc_tx_status_verdicts.json`, the
    /// same vector the HTTP test serves through wiremock, replayed through the
    /// verdict alone.
    #[test]
    fn the_recorded_arc_bodies_replay_through_the_verdict() {
        let vectors: Value = serde_json::from_str(include_str!(
            "../../../tests/vectors/arc_tx_status_verdicts.json"
        ))
        .expect("the vector parses");
        let txid = vectors["txid"].as_str().expect("txid");
        let cases = vectors["cases"].as_array().expect("cases");
        assert!(!cases.is_empty());

        let mut mismatches = Vec::new();
        for case in cases {
            let name = case["name"].as_str().expect("name");
            let http_status = case["http_status"].as_u64().expect("http_status");
            assert!(
                (200..300).contains(&http_status),
                "{name}: the verdict judges 2xx answers only"
            );
            let expect = &case["expect"];
            let verdict = arc_success_verdict(body(case["body"].clone()), txid);
            let why = match (expect["result"].as_str(), &verdict) {
                (Some("success"), Ok(response)) => {
                    let competing: Option<Vec<String>> =
                        expect["competing_txs"].as_array().map(|list| {
                            list.iter()
                                .map(|v| v.as_str().unwrap().to_string())
                                .collect()
                        });
                    if response.txid != txid
                        || Some(response.message.as_str()) != expect["message"].as_str()
                        || response.competing_txs != competing
                    {
                        Some(format!("success differs: {:?}", response))
                    } else {
                        None
                    }
                }
                (Some("failure"), Err(failure)) => {
                    let more = if expect["more"].is_null() {
                        None
                    } else {
                        Some(expect["more"].clone())
                    };
                    if Some(failure.code.as_str()) != expect["code"].as_str()
                        || Some(failure.description.as_str()) != expect["description"].as_str()
                        || failure.txid.as_deref() != Some(txid)
                        || failure.more != more
                    {
                        Some(format!("failure differs: {:?}", failure))
                    } else {
                        None
                    }
                }
                (expected, got) => Some(format!("expected {:?}, got {:?}", expected, got)),
            };
            if let Some(why) = why {
                mismatches.push(format!("  {name}: {why}"));
            }
        }
        assert!(
            mismatches.is_empty(),
            "{} of {} recorded bodies get the wrong verdict:\n{}",
            mismatches.len(),
            cases.len(),
            mismatches.join("\n")
        );
    }
}
