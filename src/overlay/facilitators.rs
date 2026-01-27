//! HTTP facilitators for overlay lookup and broadcast.
//!
//! Provides traits and implementations for communicating with overlay services
//! over HTTP(S).

#[cfg(feature = "http")]
use crate::overlay::types::OutputListItem;
use crate::overlay::types::{LookupAnswer, LookupQuestion, Steak, TaggedBEEF};
use crate::{Error, Result};
use async_trait::async_trait;

/// Facilitator for overlay lookup operations.
///
/// Implementations send lookup queries to overlay service hosts and
/// parse the responses.
#[async_trait(?Send)]
pub trait OverlayLookupFacilitator: Send + Sync {
    /// Execute a lookup query against a host.
    ///
    /// # Arguments
    ///
    /// * `url` - The overlay service URL
    /// * `question` - The lookup question to send
    /// * `timeout_ms` - Optional timeout in milliseconds
    ///
    /// # Returns
    ///
    /// The lookup answer from the service.
    async fn lookup(
        &self,
        url: &str,
        question: &LookupQuestion,
        timeout_ms: Option<u64>,
    ) -> Result<LookupAnswer>;
}

/// Facilitator for overlay broadcast operations.
///
/// Implementations send tagged BEEF transactions to overlay service hosts
/// and parse the STEAK responses.
#[async_trait(?Send)]
pub trait OverlayBroadcastFacilitator: Send + Sync {
    /// Send a tagged BEEF to a host.
    ///
    /// # Arguments
    ///
    /// * `url` - The overlay service URL
    /// * `tagged_beef` - The BEEF transaction with topic tags
    ///
    /// # Returns
    ///
    /// The STEAK response indicating which topics admitted the transaction.
    async fn send(&self, url: &str, tagged_beef: &TaggedBEEF) -> Result<Steak>;
}

/// HTTPS implementation of lookup facilitator.
///
/// Uses HTTP POST to `/lookup` endpoint with JSON body.
#[derive(Clone)]
pub struct HttpsOverlayLookupFacilitator {
    #[cfg(feature = "http")]
    client: reqwest::Client,
    #[allow(dead_code)]
    allow_http: bool,
}

impl HttpsOverlayLookupFacilitator {
    /// Create a new facilitator.
    ///
    /// # Arguments
    ///
    /// * `allow_http` - Whether to allow plain HTTP (not HTTPS) connections
    pub fn new(allow_http: bool) -> Self {
        Self {
            #[cfg(feature = "http")]
            client: reqwest::Client::new(),
            allow_http,
        }
    }
}

impl Default for HttpsOverlayLookupFacilitator {
    fn default() -> Self {
        Self::new(false)
    }
}

#[async_trait(?Send)]
impl OverlayLookupFacilitator for HttpsOverlayLookupFacilitator {
    async fn lookup(
        &self,
        url: &str,
        question: &LookupQuestion,
        timeout_ms: Option<u64>,
    ) -> Result<LookupAnswer> {
        #[cfg(not(feature = "http"))]
        {
            let _ = (url, question, timeout_ms);
            return Err(Error::OverlayError(
                "HTTP feature not enabled. Enable the 'http' feature to use HTTP facilitators."
                    .into(),
            ));
        }

        #[cfg(feature = "http")]
        {
            // Validate URL scheme
            if !self.allow_http && url.starts_with("http://") {
                return Err(Error::OverlayError(
                    "HTTPS facilitator can only use URLs that start with \"https:\"".into(),
                ));
            }

            let lookup_url = format!("{}/lookup", url.trim_end_matches('/'));
            let timeout = std::time::Duration::from_millis(timeout_ms.unwrap_or(5000));

            let request = self
                .client
                .post(&lookup_url)
                .header("Content-Type", "application/json")
                .header("X-Aggregation", "yes")
                .json(&serde_json::json!({
                    "service": question.service,
                    "query": question.query,
                }))
                .timeout(timeout);

            let response = request
                .send()
                .await
                .map_err(|e| Error::OverlayError(format!("Request failed: {}", e)))?;

            if !response.status().is_success() {
                return Err(Error::OverlayError(format!(
                    "Lookup failed with HTTP status: {}",
                    response.status()
                )));
            }

            // Check content type for binary vs JSON response
            let content_type = response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");

            if content_type.contains("octet-stream") {
                // Binary response - parse as output list with outpoints and BEEF
                let bytes = response
                    .bytes()
                    .await
                    .map_err(|e| Error::OverlayError(format!("Failed to read response: {}", e)))?;

                parse_binary_lookup_response(&bytes)
            } else {
                // JSON response
                let json: serde_json::Value = response
                    .json()
                    .await
                    .map_err(|e| Error::OverlayError(format!("Failed to parse JSON: {}", e)))?;

                parse_json_lookup_answer(json)
            }
        }
    }
}

/// HTTPS implementation of broadcast facilitator.
///
/// Uses HTTP POST to `/submit` endpoint with binary BEEF body.
#[derive(Clone)]
pub struct HttpsOverlayBroadcastFacilitator {
    #[cfg(feature = "http")]
    client: reqwest::Client,
    #[allow(dead_code)]
    allow_http: bool,
}

impl HttpsOverlayBroadcastFacilitator {
    /// Create a new facilitator.
    ///
    /// # Arguments
    ///
    /// * `allow_http` - Whether to allow plain HTTP connections
    pub fn new(allow_http: bool) -> Self {
        Self {
            #[cfg(feature = "http")]
            client: reqwest::Client::new(),
            allow_http,
        }
    }
}

impl Default for HttpsOverlayBroadcastFacilitator {
    fn default() -> Self {
        Self::new(false)
    }
}

#[async_trait(?Send)]
impl OverlayBroadcastFacilitator for HttpsOverlayBroadcastFacilitator {
    async fn send(&self, url: &str, tagged_beef: &TaggedBEEF) -> Result<Steak> {
        #[cfg(not(feature = "http"))]
        {
            let _ = (url, tagged_beef);
            return Err(Error::OverlayError(
                "HTTP feature not enabled. Enable the 'http' feature to use HTTP facilitators."
                    .into(),
            ));
        }

        #[cfg(feature = "http")]
        {
            // Validate URL scheme
            if !self.allow_http && url.starts_with("http://") {
                return Err(Error::OverlayError(
                    "HTTPS facilitator can only use URLs that start with \"https:\"".into(),
                ));
            }

            let submit_url = format!("{}/submit", url.trim_end_matches('/'));

            // Build request body
            let (body, has_off_chain) = if let Some(ref off_chain) = tagged_beef.off_chain_values {
                // Include off-chain values with length prefix
                let mut buf = Vec::new();
                buf.extend_from_slice(&varint_encode(tagged_beef.beef.len() as u64));
                buf.extend_from_slice(&tagged_beef.beef);
                buf.extend_from_slice(off_chain);
                (buf, true)
            } else {
                (tagged_beef.beef.clone(), false)
            };

            let topics_header = serde_json::to_string(&tagged_beef.topics)
                .map_err(|e| Error::OverlayError(format!("Failed to serialize topics: {}", e)))?;

            let mut request = self
                .client
                .post(&submit_url)
                .header("Content-Type", "application/octet-stream")
                .header("X-Topics", topics_header);

            if has_off_chain {
                request = request.header("x-includes-off-chain-values", "true");
            }

            let response = request
                .body(body)
                .send()
                .await
                .map_err(|e| Error::OverlayError(format!("Request failed: {}", e)))?;

            if !response.status().is_success() {
                return Err(Error::OverlayError(format!(
                    "Broadcast failed with HTTP status: {}",
                    response.status()
                )));
            }

            let steak: Steak = response
                .json()
                .await
                .map_err(|e| Error::OverlayError(format!("Failed to parse STEAK: {}", e)))?;

            Ok(steak)
        }
    }
}

/// Parse a JSON lookup answer into our enum type.
#[cfg(feature = "http")]
fn parse_json_lookup_answer(json: serde_json::Value) -> Result<LookupAnswer> {
    let answer_type = json
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("output-list");

    match answer_type {
        "output-list" => {
            let outputs = json
                .get("outputs")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|item| {
                            let beef = item.get("beef").and_then(|v| {
                                // Handle both array of numbers and base64/hex strings
                                if let Some(arr) = v.as_array() {
                                    Some(
                                        arr.iter()
                                            .filter_map(|n| n.as_u64().map(|n| n as u8))
                                            .collect(),
                                    )
                                } else if let Some(s) = v.as_str() {
                                    // Try hex first, then base64
                                    hex::decode(s).ok().or_else(|| {
                                        base64::Engine::decode(
                                            &base64::engine::general_purpose::STANDARD,
                                            s,
                                        )
                                        .ok()
                                    })
                                } else {
                                    None
                                }
                            })?;

                            let output_index =
                                item.get("outputIndex").and_then(|v| v.as_u64())? as u32;

                            let context = item.get("context").and_then(|v| {
                                if let Some(arr) = v.as_array() {
                                    Some(
                                        arr.iter()
                                            .filter_map(|n| n.as_u64().map(|n| n as u8))
                                            .collect(),
                                    )
                                } else {
                                    None
                                }
                            });

                            Some(OutputListItem {
                                beef,
                                output_index,
                                context,
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();

            Ok(LookupAnswer::OutputList { outputs })
        }
        "freeform" => {
            let result = json
                .get("result")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            Ok(LookupAnswer::Freeform { result })
        }
        "formula" => {
            let formulas = json
                .get("formulas")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_default();
            Ok(LookupAnswer::Formula { formulas })
        }
        _ => Err(Error::OverlayError(format!(
            "Unknown answer type: {}",
            answer_type
        ))),
    }
}

/// Parse binary lookup response (compact outpoints + BEEF format).
#[cfg(feature = "http")]
fn parse_binary_lookup_response(data: &[u8]) -> Result<LookupAnswer> {
    use crate::primitives::{to_hex, Reader};

    let mut reader = Reader::new(data);

    // Read number of outpoints
    let n_outpoints = reader
        .read_var_int()
        .map_err(|e| Error::OverlayError(format!("Failed to read outpoint count: {}", e)))?
        as usize;

    let mut outpoints = Vec::with_capacity(n_outpoints);

    for _ in 0..n_outpoints {
        // Read 32-byte txid
        let txid_bytes = reader
            .read_bytes(32)
            .map_err(|e| Error::OverlayError(format!("Failed to read txid: {}", e)))?;
        let txid = to_hex(&txid_bytes);

        // Read output index
        let output_index = reader
            .read_var_int()
            .map_err(|e| Error::OverlayError(format!("Failed to read output index: {}", e)))?
            as u32;

        // Read context length and data
        let context_len = reader
            .read_var_int()
            .map_err(|e| Error::OverlayError(format!("Failed to read context length: {}", e)))?
            as usize;

        let context = if context_len > 0 {
            Some(
                reader
                    .read_bytes(context_len)
                    .map_err(|e| Error::OverlayError(format!("Failed to read context: {}", e)))?
                    .to_vec(),
            )
        } else {
            None
        };

        outpoints.push((txid, output_index, context));
    }

    // Remaining bytes are BEEF
    let beef_data = reader.read_remaining().to_vec();

    // Parse BEEF and create OutputListItems for each outpoint
    let outputs = outpoints
        .into_iter()
        .filter_map(|(txid, output_index, context)| {
            // For each outpoint, we need to extract the relevant tx from BEEF
            // and create a standalone BEEF for it
            // For now, we return the full BEEF for each output
            // A more efficient implementation would parse the BEEF once
            // and extract individual transaction BEEFs
            Some(OutputListItem {
                beef: beef_data.clone(),
                output_index,
                context,
            })
        })
        .collect();

    Ok(LookupAnswer::OutputList { outputs })
}

/// Encode a u64 as a Bitcoin-style varint.
#[cfg(feature = "http")]
fn varint_encode(n: u64) -> Vec<u8> {
    if n < 0xfd {
        vec![n as u8]
    } else if n <= 0xffff {
        let mut buf = vec![0xfd];
        buf.extend_from_slice(&(n as u16).to_le_bytes());
        buf
    } else if n <= 0xffffffff {
        let mut buf = vec![0xfe];
        buf.extend_from_slice(&(n as u32).to_le_bytes());
        buf
    } else {
        let mut buf = vec![0xff];
        buf.extend_from_slice(&n.to_le_bytes());
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "http")]
    #[test]
    fn test_parse_json_output_list() {
        let json = serde_json::json!({
            "type": "output-list",
            "outputs": [
                {
                    "beef": [1, 2, 3, 4],
                    "outputIndex": 0,
                }
            ]
        });

        let answer = parse_json_lookup_answer(json).unwrap();
        match answer {
            LookupAnswer::OutputList { outputs } => {
                assert_eq!(outputs.len(), 1);
                assert_eq!(outputs[0].beef, vec![1, 2, 3, 4]);
                assert_eq!(outputs[0].output_index, 0);
            }
            _ => panic!("Expected OutputList"),
        }
    }

    #[cfg(feature = "http")]
    #[test]
    fn test_parse_json_freeform() {
        let json = serde_json::json!({
            "type": "freeform",
            "result": {"key": "value"}
        });

        let answer = parse_json_lookup_answer(json).unwrap();
        match answer {
            LookupAnswer::Freeform { result } => {
                assert_eq!(result["key"], "value");
            }
            _ => panic!("Expected Freeform"),
        }
    }

    #[cfg(feature = "http")]
    #[test]
    fn test_parse_json_default_type() {
        let json = serde_json::json!({
            "outputs": []
        });

        let answer = parse_json_lookup_answer(json).unwrap();
        assert!(matches!(answer, LookupAnswer::OutputList { .. }));
    }

    #[cfg(feature = "http")]
    #[test]
    fn test_varint_encode() {
        assert_eq!(varint_encode(0), vec![0]);
        assert_eq!(varint_encode(252), vec![252]);
        assert_eq!(varint_encode(253), vec![0xfd, 253, 0]);
        assert_eq!(varint_encode(0x1234), vec![0xfd, 0x34, 0x12]);
        assert_eq!(
            varint_encode(0x12345678),
            vec![0xfe, 0x78, 0x56, 0x34, 0x12]
        );
    }

    #[test]
    fn test_https_lookup_facilitator_rejects_http() {
        let facilitator = HttpsOverlayLookupFacilitator::new(false);
        assert!(!facilitator.allow_http);
    }

    #[test]
    fn test_https_lookup_facilitator_allows_http_when_configured() {
        let facilitator = HttpsOverlayLookupFacilitator::new(true);
        assert!(facilitator.allow_http);
    }
}
