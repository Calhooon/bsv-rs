//! HTTP facilitators for overlay lookup and broadcast.
//!
//! Provides traits and implementations for communicating with overlay services
//! over HTTP(S).

use crate::overlay::lookup_limits::LookupRequestOptions;
#[cfg(feature = "http")]
use crate::overlay::lookup_limits::{normalized_output_count, resource_limit};
#[cfg(feature = "http")]
use crate::overlay::types::OutputListItem;
use crate::overlay::types::{LookupAnswer, LookupQuestion, Steak, TaggedBEEF};
use crate::{Error, Result};
use async_trait::async_trait;
use serde_json::value::RawValue;

#[cfg(feature = "http")]
mod answer_body; // the body read as the reference reads it: type, length, BOM, count (#815)
#[cfg(feature = "http")]
mod binary_answer;
#[cfg(feature = "http")]
mod steak_body; // a `/submit` answer read as the reference reads it: size, UTF-8, JSON, `validateSTEAK` (#815's fold)

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

    /// Execute a lookup query whose query is sent as `query_text` when given:
    /// `question.query` with its objects' keys in the order they were built,
    /// where the `serde_json::Value` sorts them (#394). The default ignores
    /// the text and calls `lookup`, so a facilitator that keeps it, or a wrapper
    /// that delegates to another facilitator's `lookup`, sends the attributes
    /// sorted; an implementation overrides this method to send `query_text`.
    async fn lookup_ordered(
        &self,
        url: &str,
        question: &LookupQuestion,
        query_text: Option<&RawValue>,
        timeout_ms: Option<u64>,
    ) -> Result<LookupAnswer> {
        let _ = query_text;
        self.lookup(url, question, timeout_ms).await
    }

    /// Execute a lookup query under the bounds of `options` (#775), the
    /// reference's `options?: LookupRequestOptions` (`ts-stack@edf6e03`
    /// `LookupResolver.ts:740-746`): the resolver calls this method with its
    /// limits and its query's byte budget. The default ignores the options
    /// and calls `lookup_ordered`, so a facilitator that keeps it is bounded
    /// only by the resolver's check of the answer it returns, after that
    /// answer is in memory; an implementation that reads a response
    /// overrides this method, refuses a body above
    /// `options.max_response_bytes` and an output list above
    /// `options.max_outputs` as [`Error::OverlayResourceLimit`], and charges
    /// the bytes it reads with `options.consume`.
    async fn lookup_bounded(
        &self,
        url: &str,
        question: &LookupQuestion,
        query_text: Option<&RawValue>,
        timeout_ms: Option<u64>,
        options: &LookupRequestOptions,
    ) -> Result<LookupAnswer> {
        let _ = options;
        self.lookup_ordered(url, question, query_text, timeout_ms)
            .await
    }
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
        self.lookup_ordered(url, question, None, timeout_ms).await
    }

    async fn lookup_ordered(
        &self,
        url: &str,
        question: &LookupQuestion,
        query_text: Option<&RawValue>,
        timeout_ms: Option<u64>,
    ) -> Result<LookupAnswer> {
        let options = LookupRequestOptions::default();
        self.lookup_bounded(url, question, query_text, timeout_ms, &options)
            .await
    }

    /// The reference's bounded read (`ts-stack@edf6e03`
    /// `LookupResolver.ts:829-866`, `LookupResponseReader.ts:150-214`; #775):
    /// a declared `Content-Length` above `options.max_response_bytes` is
    /// refused before the body is read, a body is read chunk by chunk and
    /// refused at the chunk that passes the bound, each chunk charged to the
    /// options' budget; an output list above `options.max_outputs` is
    /// refused at the parse, on the JSON path (`:859-860`) and on the binary
    /// path's outpoint count (`:878-883`). Each is
    /// [`Error::OverlayResourceLimit`].
    async fn lookup_bounded(
        &self,
        url: &str,
        question: &LookupQuestion,
        query_text: Option<&RawValue>,
        timeout_ms: Option<u64>,
        options: &LookupRequestOptions,
    ) -> Result<LookupAnswer> {
        #[cfg(not(feature = "http"))]
        {
            let _ = (url, question, query_text, timeout_ms, options);
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

            // `query` before `service`, the order the body always had (a
            // `Value` sorts its keys); the query's own keys as built (#394).
            #[derive(serde::Serialize)]
            struct LookupBody<'a> {
                query: Box<serde_json::value::RawValue>,
                service: &'a str,
            }
            let body = LookupBody {
                query: match query_text {
                    Some(text) => text.to_owned(),
                    None => serde_json::value::to_raw_value(&question.query)
                        .map_err(|e| Error::OverlayError(e.to_string()))?,
                },
                service: &question.service,
            };

            let request = self
                .client
                .post(&lookup_url)
                .header("Content-Type", "application/json")
                .header("X-Aggregation", "yes")
                .json(&body)
                .timeout(timeout);

            let mut response = request
                .send()
                .await
                .map_err(|e| Error::OverlayError(format!("Request failed: {}", e)))?;

            if !response.status().is_success() {
                return Err(Error::OverlayError(format!(
                    "Lookup failed with HTTP status: {}",
                    response.status()
                )));
            }

            // The binary path for `application/octet-stream` alone, as the
            // reference's `isOctetStream` reads the type
            // (`LookupResolver.ts:512-516`, #815)
            let binary = answer_body::is_octet_stream(
                response
                    .headers()
                    .get("content-type")
                    .map(|v| answer_body::header_text(v.as_bytes()))
                    .as_deref(),
            );

            let payload = read_bounded_body(&mut response, options).await?;

            if binary {
                // Binary response - parse as output list with outpoints and BEEF
                parse_binary_lookup_response(&payload, options)
            } else {
                // JSON: strict UTF-8 less one leading BOM, the count judged
                // before the tree (`:847-866`, #815)
                answer_body::read_json_answer(&payload, options.max_outputs)
            }
        }
    }
}

/// Read a lookup response's body under `options.max_response_bytes`, the
/// reference's `readLookupResponseBytes` (`ts-stack@edf6e03`
/// `LookupResponseReader.ts:150-214`): a declared length above the bound is
/// refused before any read (`assertDeclaredLengthIsWithinLimit`), and a body
/// with no length, or a longer one than declared, at the chunk that passes
/// the bound, the bytes read until then dropped. Each chunk is charged to
/// the options' budget (`consumeBytes`). Never `reqwest`'s `.bytes()` or
/// `.json()`, which buffer the whole body before a limit can apply (#775).
#[cfg(feature = "http")]
async fn read_bounded_body(
    response: &mut reqwest::Response,
    options: &LookupRequestOptions,
) -> Result<Vec<u8>> {
    let max = options.max_response_bytes;
    // The header's text by the reference's rule (`LookupResponseReader.ts:
    // 23-36`, #815), the length hyper read beside it
    answer_body::assert_declared_length(
        response
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .map(|v| answer_body::header_text(v.as_bytes()))
            .as_deref(),
        max,
    )?;
    if response
        .content_length()
        .is_some_and(|length| length > max as u64)
    {
        return Err(resource_limit("maxResponseBytes"));
    }
    let mut payload: Vec<u8> = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| Error::OverlayError(format!("Failed to read response: {}", e)))?
    {
        if chunk.len() > max - payload.len() {
            return Err(resource_limit("maxResponseBytes"));
        }
        options.consume(chunk.len())?;
        payload.extend_from_slice(&chunk);
    }
    Ok(payload)
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

            let mut response = request
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

            // The answer read as the reference reads it, never `.json()`
            // (#815's fold; `tests/arch_steak_door_815.rs`)
            let declared = response.headers().get(reqwest::header::CONTENT_LENGTH);
            let mut answer = steak_body::Answer::declared(declared.map(|v| v.as_bytes()))?;
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|e| Error::OverlayError(format!("Failed to read response: {}", e)))?
            {
                answer.push(&chunk)?;
            }
            answer.steak(&tagged_beef.topics)
        }
    }
}

/// The reference's bounds on an output-list item (`ts-stack@edf6e03`
/// `packages/sdk/src/overlay-tools/LookupResolver.ts:252-256`): a BEEF at
/// most the 32 MiB response bound, a context at most 1 MiB
/// (`MAX_LOOKUP_CONTEXT_BYTES`, `:255`; the JSON reader's item bound and the
/// binary reader's context bound, `:889-891`).
#[cfg(feature = "http")]
const MAX_LOOKUP_BEEF_BYTES: usize = 32 * 1024 * 1024;
#[cfg(feature = "http")]
const MAX_LOOKUP_CONTEXT_BYTES: usize = 1024 * 1024;

/// The reference's facilitator's refusal of what its normalizer cannot read
/// (`LookupResolver.ts:865-866`), the member named after the colon.
#[cfg(feature = "http")]
fn malformed(what: std::fmt::Arguments<'_>) -> Error {
    Error::OverlayError(format!("Malformed lookup response: {what}"))
}

/// Parse a JSON lookup answer as the reference's normalizer reads it
/// (`ts-stack@edf6e03` `LookupResolver.ts:389-448`, `normalizeLookupAnswer`,
/// run by its HTTPS facilitator, which throws `Malformed lookup response` on
/// what it refuses, `:865-866`; #768). Refused, each an `Err` the resolver
/// records as the host's failure: a body that is not a JSON object (`[]`,
/// `"x"`, `null`, `5`; `dataRecord`, `:305-307`), a missing or non-string
/// `type`, an `output-list` answer whose `outputs` is missing or not an array
/// (`:390-397`), and any item the normalizer refuses, the whole answer with
/// it, where until #768 a missing `type` read as `output-list`, a missing
/// `outputs` as empty and a malformed item was dropped. An item
/// (`normalizeLookupOutput`, `:327-357`) is an object whose `beef` is an array
/// of 1 to 32 MiB bytes, `outputIndex` an integer from 0 to 4294967295, an
/// optional `context` an array of at most 1 MiB bytes and an optional `txid`
/// 64 hex digits; `beef` and `context` may be the historical object form
/// `{"0": 1, ..}` and `context` `{}`, as `normalizeBRC100ByteFields` repairs
/// them first (`:858-863`), and a hex or base64 text is no byte array. A
/// well-formed empty list is an answer. An unknown string `type` stays this
/// crate's `Unknown answer type`.
#[cfg(feature = "http")]
fn parse_json_lookup_answer(json: serde_json::Value, max_outputs: usize) -> Result<LookupAnswer> {
    let json = json
        .as_object()
        .ok_or_else(|| malformed(format_args!("the answer is not a JSON object")))?;
    let answer_type = json
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| malformed(format_args!("the answer has no string type member")))?;

    match answer_type {
        "output-list" => {
            let items = json
                .get("outputs")
                .and_then(|v| v.as_array())
                .ok_or_else(|| {
                    malformed(format_args!(
                        "an output-list answer without an outputs array"
                    ))
                })?;
            // The facilitator's count check, before any item is read
            // (`LookupResolver.ts:859-860`, #775).
            if items.len() > max_outputs {
                return Err(resource_limit("maxOutputs"));
            }
            // Then the normalizer's constant (`:395`, `:865-866`): past 4096
            // `Malformed lookup response` whatever `max_outputs` is (#775's
            // fold)
            normalized_output_count(items.len())?;
            let outputs = items
                .iter()
                .enumerate()
                .map(|(index, item)| parse_lookup_output(index, item))
                .collect::<Result<_>>()?;
            Ok(LookupAnswer::OutputList { outputs })
        }
        // Presence, not non-null: `"result": null` is an answer, a missing
        // member the reference's normalizer's refusal (`ts-stack@edf6e03`
        // `LookupResolver.ts:430-433`, `Object.hasOwn`; #762).
        "freeform" => match json.get("result") {
            Some(result) => Ok(LookupAnswer::Freeform {
                result: result.clone(),
            }),
            None => Err(Error::OverlayError(
                "Malformed lookup response: a freeform answer without a result member".into(),
            )),
        },
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

/// One output-list item as `normalizeLookupOutput` reads it
/// (`LookupResolver.ts:327-357`), after `normalizeBRC100ByteFields` repaired
/// its `beef` and `context` (`:858-863`).
#[cfg(feature = "http")]
fn parse_lookup_output(index: usize, item: &serde_json::Value) -> Result<OutputListItem> {
    let item = item
        .as_object()
        .ok_or_else(|| malformed(format_args!("output {index} is not a JSON object")))?;
    let beef = item
        .get("beef")
        .and_then(lookup_byte_field)
        .filter(|beef| !beef.is_empty() && beef.len() <= MAX_LOOKUP_BEEF_BYTES)
        .ok_or_else(|| {
            malformed(format_args!(
                "output {index} beef is not an array of 1 to {MAX_LOOKUP_BEEF_BYTES} bytes"
            ))
        })?;
    let output_index = item
        .get("outputIndex")
        .and_then(lookup_output_index)
        .ok_or_else(|| {
            malformed(format_args!(
                "output {index} outputIndex is not an integer from 0 to 4294967295"
            ))
        })?;
    let context = match item.get("context") {
        None => None,
        Some(value) => Some(
            lookup_byte_field(value)
                .filter(|context| context.len() <= MAX_LOOKUP_CONTEXT_BYTES)
                .ok_or_else(|| {
                    malformed(format_args!(
                        "output {index} context is not an array of at most \
                         {MAX_LOOKUP_CONTEXT_BYTES} bytes"
                    ))
                })?,
        ),
    };
    // A present `txid` kept as given (`:356`, #735); not 64 hex digits, the
    // whole answer refused, as `normalizeLookupOutput` refuses it (`:347-350`)
    let txid_ok = |t: &str| t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit());
    let txid = match item.get("txid") {
        None => None,
        Some(value) => Some(
            value
                .as_str()
                .filter(|t| txid_ok(t))
                .ok_or_else(|| malformed(format_args!("output {index} txid is not 64 hex digits")))?
                .to_string(),
        ),
    };
    Ok(OutputListItem {
        beef,
        output_index,
        context,
        txid,
    })
}

/// A schema-owned byte field (`normalizeBRC100ByteFields`,
/// `BRC100ByteEncoding.ts:126-146`): `{}` the empty array, else
/// `normalizeBRC100ByteArray`'s reading, an array of bytes or the historical
/// object form.
#[cfg(feature = "http")]
fn lookup_byte_field(value: &serde_json::Value) -> Option<Vec<u8>> {
    match value.as_object() {
        Some(object) if object.is_empty() => Some(Vec::new()),
        _ => crate::wallet::substrates::byte_fields::byte_array(value),
    }
}

/// `Number.isInteger` from 0 to `0xffffffff` (`LookupResolver.ts:336-340`):
/// an integral float such as `1.0` is an index, as `JSON.parse` reads it.
#[cfg(feature = "http")]
fn lookup_output_index(value: &serde_json::Value) -> Option<u32> {
    if let Some(n) = value.as_u64() {
        return u32::try_from(n).ok();
    }
    let n = value
        .as_f64()
        .filter(|n| (0.0..=f64::from(u32::MAX)).contains(n) && n.fract() == 0.0)?;
    Some(n as u32)
}

/// Parse binary lookup response (compact outpoints + BEEF format): the
/// outpoints, then one BEEF, each output carrying the Atomic BEEF of its
/// outpoint's txid and that txid as its hint
/// ([`binary_answer::atomic_outputs`], `LookupResolver.ts:876-936`).
///
/// An outpoint count above `options.max_outputs` is refused before any
/// outpoint is read (`ts-stack@edf6e03` `LookupResolver.ts:877-883`), and
/// each outpoint's Atomic BEEF and context bytes, summed over the outputs,
/// once they pass `options.max_response_bytes` (`:929-932`); each
/// [`Error::OverlayResourceLimit`] (#775), the reference's
/// reputation-neutral `LookupResourceLimitError`, and the only two neutral
/// refusals of this path. Every other refusal is an
/// [`Error::OverlayError`] the resolver records against the host, as the
/// reference's plain `Error`s are (`throwTrackedLookupFailure`,
/// `:2408-2419`): an output index past `0xffffffff` (`:888`, `Overlay output
/// index is out of range.`), a context past 1 MiB (`:889-891`, `Overlay
/// output context exceeds the maximum permitted size.`, checked before the
/// context is read), a BEEF that does not parse (`:900`), an outpoint whose
/// txid the BEEF lacks, and the 64 MiB of generated Atomic BEEF (`:926`).
#[cfg(feature = "http")]
fn parse_binary_lookup_response(
    data: &[u8],
    options: &LookupRequestOptions,
) -> Result<LookupAnswer> {
    use crate::primitives::{bounded_capacity, to_hex, Reader};

    let mut reader = Reader::new(data);

    // Read number of outpoints
    let n_outpoints = reader
        .read_var_int()
        .map_err(|e| Error::OverlayError(format!("Failed to read outpoint count: {}", e)))?;
    // Compared before the cast: on wasm32 a `usize` is 32 bits
    if n_outpoints > options.max_outputs as u64 {
        return Err(resource_limit("maxOutputs"));
    }
    let n_outpoints = n_outpoints as usize;

    // Each outpoint is >= 34 bytes (txid 32 + vout varint 1 + context len 1);
    // bound the pre-allocation so a bogus count cannot OOM-abort before any read.
    let mut outpoints = Vec::with_capacity(bounded_capacity(n_outpoints, reader.remaining(), 34));

    for _ in 0..n_outpoints {
        // Read 32-byte txid
        let txid_bytes = reader
            .read_bytes(32)
            .map_err(|e| Error::OverlayError(format!("Failed to read txid: {}", e)))?;
        let txid = to_hex(txid_bytes);

        // Read output index: past `0xffffffff` the whole answer refused in
        // the reference's words (`:888`, a plain `Error`, a host failure),
        // never cut to its low 32 bits
        let output_index = reader
            .read_var_int()
            .map_err(|e| Error::OverlayError(format!("Failed to read output index: {}", e)))?;
        let output_index = u32::try_from(output_index)
            .map_err(|_| Error::OverlayError("Overlay output index is out of range.".into()))?;

        // Read context length and data: past 1 MiB the whole answer refused
        // in the reference's words before the context is read or held
        // (`:889-891`, a plain `Error`, a host failure), the JSON reader's
        // bound
        let context_len = reader
            .read_var_int()
            .map_err(|e| Error::OverlayError(format!("Failed to read context length: {}", e)))?;
        if context_len > MAX_LOOKUP_CONTEXT_BYTES as u64 {
            return Err(Error::OverlayError(
                "Overlay output context exceeds the maximum permitted size.".into(),
            ));
        }
        let context_len = context_len as usize;

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

    // The rest is the BEEF: parsed once, each output carrying the Atomic
    // BEEF of its own outpoint's txid (`:900-936`; #735's fold), the
    // extracted bytes bounded by `options.max_response_bytes` (#775)
    let outputs = binary_answer::atomic_outputs(
        outpoints,
        reader.read_remaining(),
        options.max_response_bytes,
    )?;

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

        let answer = parse_json_lookup_answer(json, 4096).unwrap();
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

        let answer = parse_json_lookup_answer(json, 4096).unwrap();
        match answer {
            LookupAnswer::Freeform { result } => {
                assert_eq!(result["key"], "value");
            }
            _ => panic!("Expected Freeform"),
        }
    }

    #[cfg(feature = "http")]
    #[test]
    fn test_parse_json_missing_type_is_malformed() {
        let json = serde_json::json!({
            "outputs": []
        });

        let err = parse_json_lookup_answer(json, 4096).unwrap_err();
        assert!(
            err.to_string().contains("Malformed lookup response"),
            "{err}"
        );
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
