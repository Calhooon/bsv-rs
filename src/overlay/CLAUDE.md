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

## Key Exports

```rust
// Core types
pub use types::{
    Protocol, NetworkPreset, LookupQuestion, LookupAnswer, LookupAnswerType,
    OutputListItem, LookupFormula, TaggedBEEF, AdmittanceInstructions, Steak,
    HostResponse, ServiceMetadata,
    // Constants
    DEFAULT_HOSTS_CACHE_MAX_ENTRIES, DEFAULT_HOSTS_CACHE_TTL_MS,
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
    HostReputationTracker, HostReputationEntry, RankedHost, ReputationConfig,
    get_overlay_host_reputation_tracker,
};

// Historian
pub use historian::{Historian, HistorianConfig, InterpreterFn, SyncHistorian};

// Facilitators
pub use facilitators::{
    OverlayLookupFacilitator, OverlayBroadcastFacilitator,
    HttpsOverlayLookupFacilitator, HttpsOverlayBroadcastFacilitator,
};
```

## Core Types

### Protocol

```rust
pub enum Protocol {
    Ship,  // Submit Hierarchical Information Protocol
    Slap,  // Service Lookup Availability Protocol
}

impl Protocol {
    pub fn as_str(&self) -> &'static str
    pub fn parse(s: &str) -> Option<Self>
}
```

### NetworkPreset

```rust
pub enum NetworkPreset {
    Mainnet,  // Production network
    Testnet,  // Testing network
    Local,    // localhost:8080, allows HTTP
}

impl NetworkPreset {
    pub fn slap_trackers(&self) -> Vec<&'static str>
    pub fn allow_http(&self) -> bool
}
```

### LookupQuestion / LookupAnswer

```rust
pub struct LookupQuestion {
    pub service: String,           // e.g., "ls_slap", "ls_ship", "ls_myservice"
    pub query: serde_json::Value,  // Service-specific query
}

impl LookupQuestion {
    pub fn new(service: impl Into<String>, query: serde_json::Value) -> Self
}

pub enum LookupAnswer {
    OutputList { outputs: Vec<OutputListItem> },
    Freeform { result: serde_json::Value },
    Formula { formulas: Vec<LookupFormula> },
}

impl LookupAnswer {
    pub fn answer_type(&self) -> LookupAnswerType
    pub fn empty_output_list() -> Self
}

pub struct OutputListItem {
    pub beef: Vec<u8>,
    pub output_index: u32,
    pub context: Option<Vec<u8>>,
}

pub struct LookupFormula {
    pub outpoint: String,
    pub history_fn: String,
}
```

### TaggedBEEF / Steak

```rust
pub struct TaggedBEEF {
    pub beef: Vec<u8>,
    pub topics: Vec<String>,
    pub off_chain_values: Option<Vec<u8>>,
}

impl TaggedBEEF {
    pub fn new(beef: Vec<u8>, topics: Vec<String>) -> Self
    pub fn with_off_chain_values(beef: Vec<u8>, topics: Vec<String>, off_chain: Vec<u8>) -> Self
}

pub struct AdmittanceInstructions {
    pub outputs_to_admit: Vec<u32>,
    pub coins_to_retain: Vec<u32>,
    pub coins_removed: Option<Vec<u32>>,
}

impl AdmittanceInstructions {
    pub fn has_activity(&self) -> bool  // True if any admits, retains, or removals
}

/// STEAK = Submitted Transaction Execution AcKnowledgment
pub type Steak = HashMap<String, AdmittanceInstructions>;
```

### HostResponse

```rust
pub struct HostResponse {
    pub host: String,
    pub success: bool,
    pub steak: Option<Steak>,
    pub error: Option<String>,
}

impl HostResponse {
    pub fn success(host: String, steak: Steak) -> Self
    pub fn failure(host: String, error: String) -> Self
}
```

### ServiceMetadata

```rust
pub struct ServiceMetadata {
    pub name: String,
    pub description: Option<String>,
    pub icon_url: Option<String>,
    pub version: Option<String>,
    pub info_url: Option<String>,
}
```

## Facilitators

Traits and implementations for HTTP communication with overlay services.

```rust
/// Trait for lookup operations
#[async_trait(?Send)]
pub trait OverlayLookupFacilitator: Send + Sync {
    async fn lookup(&self, url: &str, question: &LookupQuestion, timeout_ms: Option<u64>) -> Result<LookupAnswer>;
}

/// Trait for broadcast operations
#[async_trait(?Send)]
pub trait OverlayBroadcastFacilitator: Send + Sync {
    async fn send(&self, url: &str, tagged_beef: &TaggedBEEF) -> Result<Steak>;
}

/// HTTPS lookup facilitator - POST to /lookup endpoint
pub struct HttpsOverlayLookupFacilitator { .. }

impl HttpsOverlayLookupFacilitator {
    pub fn new(allow_http: bool) -> Self
}

/// HTTPS broadcast facilitator - POST to /submit endpoint
pub struct HttpsOverlayBroadcastFacilitator { .. }

impl HttpsOverlayBroadcastFacilitator {
    pub fn new(allow_http: bool) -> Self
}
```

The lookup facilitator handles both JSON and binary response formats:
- **JSON**: Standard output-list, freeform, or formula responses
- **Binary**: Compact outpoints + BEEF format (octet-stream content type)

## LookupResolver

Resolves lookup queries by discovering competent hosts via SLAP trackers.

```rust
pub struct LookupResolverConfig {
    pub network_preset: NetworkPreset,
    pub facilitator: Option<Arc<dyn OverlayLookupFacilitator>>,
    pub slap_trackers: Option<Vec<String>>,
    pub host_overrides: Option<HashMap<String, Vec<String>>>,
    pub additional_hosts: Option<HashMap<String, Vec<String>>>,
    pub hosts_cache_ttl_ms: u64,
    pub hosts_cache_max_entries: usize,
}

impl LookupResolver {
    pub fn new(config: LookupResolverConfig) -> Self
    pub async fn query(&self, question: &LookupQuestion, timeout_ms: Option<u64>) -> Result<LookupAnswer>
}

impl Default for LookupResolver { .. }
```

**Validation**: Host override service names must start with `ls_` or the constructor will panic.

## TopicBroadcaster

Broadcasts transactions to SHIP overlay topics. Implements the `Broadcaster` trait from the transaction module.

```rust
pub struct TopicBroadcasterConfig {
    pub network_preset: NetworkPreset,
    pub facilitator: Option<Arc<dyn OverlayBroadcastFacilitator>>,
    pub resolver: Option<Arc<LookupResolver>>,
    pub require_ack_from_all_hosts: RequireAck,
    pub require_ack_from_any_host: RequireAck,   // Default: RequireAck::All
    pub require_ack_from_specific_hosts: HashMap<String, RequireAck>,
}

pub enum RequireAck {
    None,                    // No acknowledgment required
    Any,                     // Any topic acknowledged
    Some(Vec<String>),       // Specific topics required
    All,                     // All topics required
}

impl TopicBroadcaster {
    pub fn new(topics: Vec<String>, config: TopicBroadcasterConfig) -> Result<Self>
    pub async fn broadcast_tx(&self, tx: &Transaction) -> BroadcastResult
    pub async fn find_interested_hosts(&self) -> Result<HashMap<String, HashSet<String>>>
}

#[async_trait(?Send)]
impl Broadcaster for TopicBroadcaster {
    async fn broadcast(&self, tx: &Transaction) -> BroadcastResult
    async fn broadcast_many(&self, txs: Vec<Transaction>) -> Vec<BroadcastResult>
}

// Type aliases for TypeScript SDK compatibility
pub type SHIPBroadcaster = TopicBroadcaster;
pub type SHIPCast = TopicBroadcaster;
```

**Validation**: At least one topic is required, and all topics must start with `tm_`.

## HostReputationTracker

Tracks host performance for intelligent selection.

```rust
pub struct ReputationConfig {
    pub latency_smoothing: f64,     // EMA smoothing factor (default: 0.25)
    pub grace_failures: u32,        // Failures before backoff (default: 2)
    pub backoff_base_ms: u64,       // Base backoff time (default: 1000)
    pub backoff_max_ms: u64,        // Max backoff time (default: 60000)
    pub default_latency_ms: f64,    // Default for new hosts (default: 1500)
    pub failure_penalty_ms: f64,    // Penalty per failure (default: 400)
    pub success_bonus_ms: f64,      // Bonus per success (default: 30)
}

impl HostReputationTracker {
    pub fn new() -> Self
    pub fn with_config(config: ReputationConfig) -> Self
    pub fn record_success(&self, host: &str, latency_ms: u64)
    pub fn record_failure(&self, host: &str, reason: Option<&str>)
    pub fn rank_hosts(&self, hosts: &[String]) -> Vec<RankedHost>
    pub fn snapshot(&self, host: &str) -> Option<HostReputationEntry>
    pub fn reset(&self)
}

// Global singleton
pub fn get_overlay_host_reputation_tracker() -> &'static HostReputationTracker
```

## Historian

Traverses transaction ancestry to build chronological history.

```rust
pub type InterpreterFn<T, C> = Box<
    dyn Fn(&Transaction, u32, Option<&C>) -> Pin<Box<dyn Future<Output = Option<T>> + Send>>
        + Send + Sync
>;

impl Historian<T, C> {
    pub fn new(interpreter: InterpreterFn<T, C>, config: HistorianConfig<T, C>) -> Self
    pub async fn build_history(&self, tx: &Transaction, ctx: Option<&C>) -> Result<Vec<T>>
}

// Synchronous version
impl SyncHistorian<T, C> {
    pub fn new<F>(interpreter: F) -> Self
    pub fn build_history(&self, tx: &Transaction, ctx: Option<&C>) -> Vec<T>
}
```

## Admin Token Template

Create and decode SHIP/SLAP advertisement tokens.

```rust
pub struct OverlayAdminTokenData {
    pub protocol: Protocol,
    pub identity_key: PublicKey,
    pub domain: String,
    pub topic_or_service: String,
}

pub fn decode_overlay_admin_token(script: &LockingScript) -> Result<OverlayAdminTokenData>
pub fn create_overlay_admin_token(
    protocol: Protocol,
    identity_key: &PublicKey,
    domain: &str,
    topic_or_service: &str,
) -> LockingScript

pub fn is_overlay_admin_token(script: &LockingScript) -> bool
pub fn is_ship_token(script: &LockingScript) -> bool
pub fn is_slap_token(script: &LockingScript) -> bool
```

## Usage Examples

### Query a Lookup Service

```rust
use bsv_sdk::overlay::{LookupResolver, LookupQuestion, LookupAnswer};

let resolver = LookupResolver::default();

let question = LookupQuestion::new("ls_myservice", serde_json::json!({
    "key": "value"
}));

let answer = resolver.query(&question, Some(5000)).await?;

match answer {
    LookupAnswer::OutputList { outputs } => {
        for output in outputs {
            println!("Found output: index {}", output.output_index);
        }
    }
    LookupAnswer::Freeform { result } => {
        println!("Freeform result: {}", result);
    }
    _ => {}
}
```

### Broadcast to Topic

```rust
use bsv_sdk::overlay::{TopicBroadcaster, TopicBroadcasterConfig};
use bsv_sdk::transaction::Transaction;

let broadcaster = TopicBroadcaster::new(
    vec!["tm_mytopic".to_string()],
    TopicBroadcasterConfig::default(),
)?;

let tx = Transaction::from_hex("...")?;
let result = broadcaster.broadcast_tx(&tx).await;

match result {
    Ok(response) => println!("Broadcast success: {}", response.txid),
    Err(failure) => println!("Broadcast failed: {}", failure.description),
}
```

### Create Admin Token

```rust
use bsv_sdk::overlay::{create_overlay_admin_token, Protocol};
use bsv_sdk::primitives::PrivateKey;

let private_key = PrivateKey::random();
let public_key = private_key.public_key();

let script = create_overlay_admin_token(
    Protocol::Ship,
    &public_key,
    "https://example.com",
    "tm_mytopic",
);
```

### Track Host Reputation

```rust
use bsv_sdk::overlay::get_overlay_host_reputation_tracker;

let tracker = get_overlay_host_reputation_tracker();

// Record metrics
tracker.record_success("https://host1.example.com", 150);
tracker.record_failure("https://host2.example.com", Some("Connection timeout"));

// Rank hosts
let hosts = vec![
    "https://host1.example.com".to_string(),
    "https://host2.example.com".to_string(),
];
let ranked = tracker.rank_hosts(&hosts);

println!("Best host: {}", ranked[0].entry.host);
```

### Traverse Transaction History

```rust
use bsv_sdk::overlay::SyncHistorian;
use bsv_sdk::transaction::Transaction;

let historian = SyncHistorian::<String, ()>::new(|tx, output_idx, _ctx| {
    // Extract relevant data from output
    Some(format!("{}:{}", tx.id(), output_idx))
});

let history = historian.build_history(&tip_tx, None);
// Returns values in chronological order (oldest first)
```

## Implementation Notes

### Host Discovery

1. `LookupResolver` queries SLAP trackers to find hosts advertising a service
2. Responses are admin tokens decoded via `decode_overlay_admin_token`
3. Results are cached with configurable TTL (default 5 minutes)
4. Additional hosts can be specified via `additional_hosts` config

### Host Ranking

Hosts are ranked by a score combining:
- Average latency (EMA with configurable smoothing)
- Consecutive failure penalty
- Backoff status penalty
- Success bonus (capped)

Lower score = better host. Hosts in backoff are deprioritized.

### Acknowledgment Requirements

The `TopicBroadcaster` supports flexible acknowledgment requirements:
- `require_ack_from_all_hosts`: All hosts must acknowledge specified topics
- `require_ack_from_any_host`: At least one host must acknowledge
- `require_ack_from_specific_hosts`: Per-host requirements

### Topic Naming

- Topics must start with `tm_` (Topic Manager prefix)
- Services must start with `ls_` (Lookup Service prefix)

### HTTP Feature

The `http` feature enables actual HTTP communication via `reqwest`.
Without it, facilitators return errors indicating HTTP is not available.

## Error Types

| Error | Description |
|-------|-------------|
| `OverlayError(String)` | General overlay operation error |
| `NoHostsFound(String)` | No hosts found for the requested service |
| `OverlayBroadcastFailed(String)` | Broadcast operation failed |

## Constants

| Constant | Default | Description |
|----------|---------|-------------|
| `MAX_TRACKER_WAIT_TIME_MS` | 5000 | SLAP tracker query timeout |
| `MAX_SHIP_QUERY_TIMEOUT_MS` | 5000 | SHIP host discovery timeout |
| `DEFAULT_HOSTS_CACHE_TTL_MS` | 300000 | Hosts cache TTL (5 minutes) |
| `DEFAULT_HOSTS_CACHE_MAX_ENTRIES` | 128 | Max cached services |

## Related Documentation

- `../transaction/CLAUDE.md` - Transaction module (BEEF, broadcasting)
- `../script/templates/CLAUDE.md` - PushDrop template (admin tokens)
- `../CLAUDE.md` - Root SDK documentation
