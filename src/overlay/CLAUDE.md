# BSV Overlay Module
> SHIP/SLAP overlay network client for BSV transactions

## Overview

This module provides client-side support for the BSV overlay network, enabling:
- **SLAP** (Service Lookup Availability Protocol): Discover and query lookup services
- **SHIP** (Submit Hierarchical Information Protocol): Broadcast transactions to overlay topics

The module maintains cross-SDK compatibility with the TypeScript and Go BSV SDKs.

## Files

| File | Purpose |
|------|---------|
| `mod.rs` | Module root; re-exports |
| `types.rs` | Core types (Protocol, TaggedBEEF, Steak, LookupQuestion/Answer, etc.) and constants |
| `host_reputation_tracker.rs` | Host performance tracking with exponential backoff |
| `facilitators.rs` | HTTP lookup/broadcast facilitators with binary/JSON response parsing |
| `overlay_admin_token_template.rs` | SHIP/SLAP advertisement token encoding/decoding via PushDrop |
| `historian.rs` | Transaction ancestry traversal for building chronological history |
| `lookup_resolver.rs` | SLAP query resolution with host discovery and caching |
| `topic_broadcaster.rs` | SHIP topic broadcasting with acknowledgment requirements |
| `retry.rs` | Double-spend retry helper for overlay broadcast operations |

## Key Exports

```rust
// Core types
pub use types::{
    Protocol, NetworkPreset, LookupQuestion, LookupAnswer, LookupAnswerType,
    OutputListItem, LookupFormula, TaggedBEEF, AdmittanceInstructions, Steak,
    HostResponse, ServiceMetadata,
    DEFAULT_HOSTS_CACHE_MAX_ENTRIES, DEFAULT_HOSTS_CACHE_TTL_MS,
    DEFAULT_TX_MEMO_MAX_ENTRIES, DEFAULT_TX_MEMO_TTL_MS,
    MAX_SHIP_QUERY_TIMEOUT_MS, MAX_TRACKER_WAIT_TIME_MS,
};

// Lookup resolver
pub use lookup_resolver::{LookupResolver, LookupResolverConfig};

// Topic broadcaster
pub use topic_broadcaster::{
    TopicBroadcaster, TopicBroadcasterConfig, RequireAck,
    SHIPBroadcaster, SHIPCast,
};

// Admin token functions
pub use overlay_admin_token_template::{
    decode_overlay_admin_token, create_overlay_admin_token,
    is_overlay_admin_token, is_ship_token, is_slap_token,
    OverlayAdminTokenData,
};

// Host reputation
pub use host_reputation_tracker::{
    HostReputationTracker, HostReputationEntry, RankedHost, RankChangeEvent,
    ReputationConfig, ReputationStorage, get_overlay_host_reputation_tracker,
};

// Retry helper
pub use retry::{with_double_spend_retry, DEFAULT_MAX_RETRIES};

// Historian
pub use historian::{Historian, HistorianConfig, InterpreterFn, SyncHistorian};

// Facilitators
pub use facilitators::{
    OverlayLookupFacilitator, OverlayBroadcastFacilitator,
    HttpsOverlayLookupFacilitator, HttpsOverlayBroadcastFacilitator,
};
```

## Core Types

- **`Protocol`** - `Ship` or `Slap` enum with `as_str()` and `parse()` methods
- **`NetworkPreset`** - `Mainnet`, `Testnet`, or `Local` with `slap_trackers()` and `allow_http()` methods
- **`LookupQuestion`** - Service identifier + JSON query payload; `new(service, query)`
- **`LookupAnswer`** - Tagged enum: `OutputList`, `Freeform`, or `Formula` variants
- **`OutputListItem`** - BEEF bytes + output index + optional context
- **`LookupFormula`** - Outpoint string + history function name
- **`TaggedBEEF`** - BEEF bytes + topic list + optional off-chain values
- **`AdmittanceInstructions`** - Outputs admitted, coins retained, coins removed; `has_activity()`
- **`Steak`** - `HashMap<String, AdmittanceInstructions>` (Submitted Transaction Execution AcKnowledgment)
- **`HostResponse`** - Host URL + success/failure + optional Steak or error
- **`ServiceMetadata`** - Name, description, icon URL, version, info URL

## Facilitators

Traits and HTTPS implementations for overlay communication.

- **`OverlayLookupFacilitator`** trait: `async fn lookup(url, question, timeout_ms) -> Result<LookupAnswer>`
- **`OverlayBroadcastFacilitator`** trait: `async fn send(url, tagged_beef) -> Result<Steak>`
- **`HttpsOverlayLookupFacilitator`** - POST to `/lookup` endpoint; handles JSON and binary (octet-stream) responses
- **`HttpsOverlayBroadcastFacilitator`** - POST to `/submit` endpoint with binary BEEF body and `X-Topics` header

## LookupResolver

Resolves lookup queries by discovering competent hosts via SLAP trackers. Includes TX memoization cache for deduplication.

```rust
pub struct LookupResolverConfig {
    pub network_preset: NetworkPreset,
    pub facilitator: Option<Arc<dyn OverlayLookupFacilitator>>,
    pub slap_trackers: Option<Vec<String>>,
    pub host_overrides: Option<HashMap<String, Vec<String>>>,
    pub additional_hosts: Option<HashMap<String, Vec<String>>>,
    pub hosts_cache_ttl_ms: u64,
    pub hosts_cache_max_entries: usize,
    pub tx_memo_ttl_ms: u64,            // Default 10 min
    pub tx_memo_max_entries: usize,      // Default 4096
}

impl LookupResolver {
    pub fn new(config: LookupResolverConfig) -> Self
    pub async fn query(&self, question: &LookupQuestion, timeout_ms: Option<u64>) -> Result<LookupAnswer>
    pub async fn prune_tx_memo_cache(&self) -> usize
    pub async fn tx_memo_cache_size(&self) -> usize
}
```

- **TX Memoization**: Caches parsed transaction IDs from BEEF, deduplicating outputs using `txId.outputIndex` as the unique key (matches TS SDK behavior)
- **Request Coalescing**: Concurrent requests for the same service share a single SLAP tracker query via `tokio::sync::watch` channels
- **Validation**: Host override service names must start with `ls_` or the constructor will panic

## TopicBroadcaster

Broadcasts transactions to SHIP overlay topics. Implements the `Broadcaster` trait.

```rust
pub struct TopicBroadcasterConfig {
    pub network_preset: NetworkPreset,
    pub facilitator: Option<Arc<dyn OverlayBroadcastFacilitator>>,
    pub resolver: Option<Arc<LookupResolver>>,
    pub require_ack_from_all_hosts: RequireAck,       // Default: None
    pub require_ack_from_any_host: RequireAck,         // Default: All
    pub require_ack_from_specific_hosts: HashMap<String, RequireAck>,
}

pub enum RequireAck { None, Any, Some(Vec<String>), All }

impl TopicBroadcaster {
    pub fn new(topics: Vec<String>, config: TopicBroadcasterConfig) -> Result<Self>
    pub async fn broadcast_tx(&self, tx: &Transaction) -> BroadcastResult
    pub async fn find_interested_hosts(&self) -> Result<HashMap<String, HashSet<String>>>
}

// Also implements Broadcaster trait (broadcast, broadcast_many)
// Type aliases: SHIPBroadcaster, SHIPCast
```

**Validation**: At least one topic is required, and all topics must start with `tm_`.

## HostReputationTracker

Tracks host performance for intelligent selection. Thread-safe with `RwLock`. Emits `RankChangeEvent` notifications via `tokio::sync::broadcast`.

```rust
impl HostReputationTracker {
    pub fn new() -> Self
    pub fn with_config(config: ReputationConfig) -> Self
    pub fn with_storage(storage: Box<dyn ReputationStorage>) -> Self
    pub fn with_config_and_storage(config: ReputationConfig, storage: Box<dyn ReputationStorage>) -> Self
    pub fn record_success(&self, host: &str, latency_ms: u64)
    pub fn record_failure(&self, host: &str, reason: Option<&str>)
    pub fn rank_hosts(&self, hosts: &[String]) -> Vec<RankedHost>
    pub fn rank_hosts_at(&self, hosts: &[String], now: u64) -> Vec<RankedHost>
    pub fn snapshot(&self, host: &str) -> Option<HostReputationEntry>
    pub fn reset(&self)
    pub fn has_storage(&self) -> bool
    pub fn flush(&self)
    pub fn to_json(&self) -> String
    pub fn from_json(&self, json: &str) -> bool
    pub fn subscribe(&self) -> broadcast::Receiver<RankChangeEvent>
    pub fn on_rank_change(&self, callback: impl Fn(RankChangeEvent) + Send + Sync + 'static) -> JoinHandle<()>
}

// Global singleton (OnceLock)
pub fn get_overlay_host_reputation_tracker() -> &'static HostReputationTracker
```

- **ReputationConfig** defaults: latency_smoothing=0.25, grace_failures=2, backoff_base_ms=1000, backoff_max_ms=60000, default_latency_ms=1500, failure_penalty_ms=400, success_bonus_ms=30
- **ReputationStorage** trait: `get/set/remove` for custom persistence backends; auto-saves after each update
- **Immediate backoff** for DNS errors (ERR_NAME_NOT_RESOLVED, ENOTFOUND, etc.)
- **Scoring**: latency + failure_penalty + backoff_penalty - success_bonus (lower = better)

### Rank Change Events

The tracker emits `RankChangeEvent` via `tokio::sync::broadcast` whenever `record_success()` or `record_failure()` causes a change in a host's computed reputation score.

```rust
pub struct RankChangeEvent {
    pub host: String,      // The host whose rank changed
    pub old_rank: f64,     // Previous score (lower = better)
    pub new_rank: f64,     // New score (lower = better)
    pub reason: String,    // Human-readable reason (e.g. "success (latency: 100ms)")
}
```

- **`subscribe()`** returns a `broadcast::Receiver<RankChangeEvent>` for manual async polling
- **`on_rank_change(callback)`** spawns a tokio task that invokes the callback for each event; returns `JoinHandle` for cancellation
- Dropping all receivers is safe — send errors are silently ignored
- Channel capacity: 64 events (older events dropped if receiver falls behind)

## Historian

Traverses transaction ancestry to build chronological history.

- **`Historian<T, C>`** - Async version with `InterpreterFn<T, C>` callback, optional caching, and `interpreter_version` for cache invalidation
- **`SyncHistorian<T, C>`** - Synchronous version with builder methods `with_debug()` and `with_version()`

Both return values in **chronological order** (oldest first) and prevent cycles via visited set.

## Admin Token Template

Create and decode SHIP/SLAP advertisement tokens using PushDrop format (4 fields: protocol, identity key, domain, topic/service).

```rust
pub fn create_overlay_admin_token(protocol, identity_key, domain, topic_or_service) -> LockingScript
pub fn decode_overlay_admin_token(script: &LockingScript) -> Result<OverlayAdminTokenData>
pub fn is_overlay_admin_token(script) -> bool
pub fn is_ship_token(script) -> bool
pub fn is_slap_token(script) -> bool
```

## Double-Spend Retry

Generic async retry wrapper for operations that fail due to double-spend conflicts.

```rust
pub const DEFAULT_MAX_RETRIES: u32 = 3;

pub async fn with_double_spend_retry<T, F, Fut>(
    max_retries: Option<u32>,  // None = DEFAULT_MAX_RETRIES
    operation: F,
) -> Result<T>
```

Detects double-spend errors by matching: `double spend`, `double-spend`, `txn-mempool-conflict`, `already spent`, `missing inputs`. Non-double-spend errors are returned immediately without retry.

## Implementation Notes

### Host Discovery
1. `LookupResolver` queries SLAP trackers to find hosts advertising a service
2. Responses are admin tokens decoded via `decode_overlay_admin_token`
3. Results are cached with configurable TTL (default 5 minutes)
4. Additional hosts can be specified via `additional_hosts` config

### Acknowledgment Requirements
- `require_ack_from_all_hosts`: All hosts must acknowledge specified topics
- `require_ack_from_any_host`: At least one host must acknowledge
- `require_ack_from_specific_hosts`: Per-host requirements

### Naming Conventions
- Topics must start with `tm_` (Topic Manager prefix)
- Services must start with `ls_` (Lookup Service prefix)

### HTTP Feature
The `http` feature enables HTTP communication via `reqwest`. Without it, facilitators return errors.

## Error Handling

Overlay operations use `Error::OverlayError(String)`. The `TopicBroadcaster` returns `BroadcastResult` with error codes:

| Error Code | Description |
|------------|-------------|
| `ERR_BEEF_SERIALIZATION` | Transaction cannot be serialized to BEEF |
| `ERR_HOST_DISCOVERY` | Failed to discover interested hosts |
| `ERR_NO_HOSTS_INTERESTED` | No hosts want the transaction |
| `ERR_ALL_HOSTS_REJECTED` | All hosts rejected the broadcast |
| `ERR_REQUIRE_ACK_FAILED` | Acknowledgment requirements not met |

## Constants

| Constant | Value | Source | Description |
|----------|-------|--------|-------------|
| `MAX_TRACKER_WAIT_TIME_MS` | 5000 | `types.rs` | SLAP tracker query timeout (ms) |
| `MAX_SHIP_QUERY_TIMEOUT_MS` | 5000 | `types.rs` | SHIP host discovery timeout (ms) |
| `DEFAULT_HOSTS_CACHE_TTL_MS` | 300000 | `types.rs` | Hosts cache TTL (5 minutes) |
| `DEFAULT_HOSTS_CACHE_MAX_ENTRIES` | 128 | `types.rs` | Max cached service entries |
| `DEFAULT_TX_MEMO_TTL_MS` | 600000 | `types.rs` | TX memoization cache TTL (10 minutes) |
| `DEFAULT_TX_MEMO_MAX_ENTRIES` | 4096 | `types.rs` | Max TX memoization cache entries |
| `DEFAULT_MAX_RETRIES` | 3 | `retry.rs` | Double-spend retry attempts |

## Related Documentation

- `../transaction/CLAUDE.md` - Transaction module (BEEF, broadcasting)
- `../script/templates/CLAUDE.md` - PushDrop template (admin tokens)
- `../CLAUDE.md` - Root SDK documentation
