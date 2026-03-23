//! # Overlay Tools Module
//!
//! SHIP/SLAP overlay network client for BSV.
//!
//! ## Overview
//!
//! This module provides client-side support for the BSV overlay network:
//! - **SLAP** (Service Lookup Availability Protocol): Discover services
//! - **SHIP** (Submit Hierarchical Information Protocol): Broadcast transactions
//!
//! ## Components
//!
//! - **LookupResolver**: Query overlay lookup services
//! - **TopicBroadcaster**: Broadcast transactions to overlay topics
//! - **OverlayAdminTokenTemplate**: Create/decode advertisement tokens
//! - **HostReputationTracker**: Track host performance
//! - **Historian**: Traverse transaction ancestry
//!
//! ## Example
//!
//! ```rust,ignore
//! use bsv_rs::overlay::{LookupResolver, TopicBroadcaster, LookupQuestion};
//!
//! // Query a lookup service
//! let resolver = LookupResolver::default();
//! let answer = resolver.query(&LookupQuestion::new("ls_myservice", json!({}))).await?;
//!
//! // Broadcast to a topic
//! let broadcaster = TopicBroadcaster::new(
//!     vec!["tm_mytopic".to_string()],
//!     Default::default()
//! )?;
//! let result = broadcaster.broadcast(&tx).await?;
//! ```
//!
//! ## Network Presets
//!
//! Three network presets are available:
//!
//! - `Mainnet`: Production network with default SLAP trackers
//! - `Testnet`: Testing network with testnet SLAP trackers
//! - `Local`: Development with localhost:8080 (allows HTTP)
//!
//! ## Host Reputation
//!
//! The module automatically tracks host reputation:
//! - Latency measurements (exponential moving average)
//! - Success/failure counts
//! - Automatic backoff after repeated failures
//! - Host ranking for optimal selection
//!
//! A global reputation tracker is shared across all operations.

pub mod facilitators;
pub mod historian;
pub mod host_reputation_tracker;
pub mod lookup_resolver;
pub mod overlay_admin_token_template;
pub mod retry;
pub mod topic_broadcaster;
pub mod types;

// Re-exports from facilitators
pub use facilitators::{
    HttpsOverlayBroadcastFacilitator, HttpsOverlayLookupFacilitator, OverlayBroadcastFacilitator,
    OverlayLookupFacilitator,
};

// Re-exports from historian
pub use historian::{Historian, HistorianConfig, InterpreterFn, SyncHistorian};

// Re-exports from host_reputation_tracker
pub use host_reputation_tracker::{
    get_overlay_host_reputation_tracker, HostReputationEntry, HostReputationTracker,
    RankChangeEvent, RankedHost, ReputationConfig, ReputationStorage,
};

// Re-exports from lookup_resolver
pub use lookup_resolver::{LookupResolver, LookupResolverConfig};

// Re-exports from overlay_admin_token_template
pub use overlay_admin_token_template::{
    create_overlay_admin_token, decode_overlay_admin_token, is_overlay_admin_token, is_ship_token,
    is_slap_token, OverlayAdminTokenData,
};

// Re-exports from topic_broadcaster
pub use topic_broadcaster::{
    RequireAck, SHIPBroadcaster, SHIPCast, TopicBroadcaster, TopicBroadcasterConfig,
};

// Re-exports from retry
pub use retry::{with_double_spend_retry, DEFAULT_MAX_RETRIES};

// Re-exports from types
pub use types::{
    AdmittanceInstructions, HostResponse, LookupAnswer, LookupAnswerType, LookupFormula,
    LookupQuestion, NetworkPreset, OutputListItem, Protocol, ServiceMetadata, Steak, TaggedBEEF,
    DEFAULT_HOSTS_CACHE_MAX_ENTRIES, DEFAULT_HOSTS_CACHE_TTL_MS, DEFAULT_TX_MEMO_MAX_ENTRIES,
    DEFAULT_TX_MEMO_TTL_MS, MAX_SHIP_QUERY_TIMEOUT_MS, MAX_TRACKER_WAIT_TIME_MS,
};
