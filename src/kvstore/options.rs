//! The per-operation option records, `KVStoreGetOptions`, `KVStoreSetOptions`
//! and `KVStoreRemoveOptions` (moved from `types.rs` by #843d8c for that
//! file's line ceiling; re-exported there, so every public path still names
//! them).

/// Options for get operations.
///
/// `#[non_exhaustive]` (#843d8c): no struct expression builds one outside the
/// crate, a functional update that names no field included:
///
/// ```compile_fail,E0639
/// fn rebuilt(value: bsv_rs::kvstore::KVStoreGetOptions) -> bsv_rs::kvstore::KVStoreGetOptions {
///     bsv_rs::kvstore::KVStoreGetOptions { ..value }
/// }
/// ```
///
/// ```
/// fn kept(value: bsv_rs::kvstore::KVStoreGetOptions) -> bsv_rs::kvstore::KVStoreGetOptions {
///     value
/// }
/// ```
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct KVStoreGetOptions {
    /// Include full history chain.
    pub history: bool,
    /// Include token data in result.
    pub include_token: bool,
    /// Override service name.
    pub service_name: Option<String>,
}

crate::util::non_exhaustive::assert_no_drop!(KVStoreGetOptions, bsv_rs::kvstore::KVStoreGetOptions);

impl KVStoreGetOptions {
    /// Creates default options.
    pub fn new() -> Self {
        Self::default()
    }

    /// Include history.
    pub fn with_history(mut self, history: bool) -> Self {
        self.history = history;
        self
    }

    /// Include token data.
    pub fn with_include_token(mut self, include: bool) -> Self {
        self.include_token = include;
        self
    }

    /// Override service name.
    pub fn with_service_name(mut self, name: impl Into<String>) -> Self {
        self.service_name = Some(name.into());
        self
    }
}

/// Options for set operations.
///
/// `#[non_exhaustive]` (#843d8c): no struct expression builds one outside the
/// crate, a functional update that names no field included:
///
/// ```compile_fail,E0639
/// fn rebuilt(value: bsv_rs::kvstore::KVStoreSetOptions) -> bsv_rs::kvstore::KVStoreSetOptions {
///     bsv_rs::kvstore::KVStoreSetOptions { ..value }
/// }
/// ```
///
/// ```
/// fn kept(value: bsv_rs::kvstore::KVStoreSetOptions) -> bsv_rs::kvstore::KVStoreSetOptions {
///     value
/// }
/// ```
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct KVStoreSetOptions {
    /// Override protocol ID.
    pub protocol_id: Option<String>,
    /// Description for the operation.
    pub description: Option<String>,
    /// Token amount override.
    pub token_amount: Option<u64>,
    /// Tags to attach.
    pub tags: Option<Vec<String>>,
    /// Optional time-to-live duration. When set, the entry will be treated as
    /// expired after this duration elapses. Expiration is enforced client-side
    /// on `get()` — the on-chain data remains immutable.
    pub ttl: Option<std::time::Duration>,
}

crate::util::non_exhaustive::assert_no_drop!(KVStoreSetOptions, bsv_rs::kvstore::KVStoreSetOptions);

impl KVStoreSetOptions {
    /// Creates default options.
    pub fn new() -> Self {
        Self::default()
    }

    /// Override protocol ID.
    pub fn with_protocol_id(mut self, protocol_id: impl Into<String>) -> Self {
        self.protocol_id = Some(protocol_id.into());
        self
    }

    /// Set description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Override token amount.
    pub fn with_token_amount(mut self, amount: u64) -> Self {
        self.token_amount = Some(amount);
        self
    }

    /// Set tags.
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = Some(tags);
        self
    }

    /// Set time-to-live. The entry will be treated as expired after this duration.
    pub fn with_ttl(mut self, ttl: std::time::Duration) -> Self {
        self.ttl = Some(ttl);
        self
    }
}

/// Options for remove operations.
///
/// `#[non_exhaustive]` (#843d8c): no struct expression builds one outside the
/// crate, a functional update that names no field included:
///
/// ```compile_fail,E0639
/// fn rebuilt(value: bsv_rs::kvstore::KVStoreRemoveOptions) -> bsv_rs::kvstore::KVStoreRemoveOptions {
///     bsv_rs::kvstore::KVStoreRemoveOptions { ..value }
/// }
/// ```
///
/// ```
/// fn kept(value: bsv_rs::kvstore::KVStoreRemoveOptions) -> bsv_rs::kvstore::KVStoreRemoveOptions {
///     value
/// }
/// ```
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct KVStoreRemoveOptions {
    /// Override protocol ID.
    pub protocol_id: Option<String>,
    /// Description for the operation.
    pub description: Option<String>,
}

crate::util::non_exhaustive::assert_no_drop!(
    KVStoreRemoveOptions,
    bsv_rs::kvstore::KVStoreRemoveOptions
);

impl KVStoreRemoveOptions {
    /// Creates default options.
    pub fn new() -> Self {
        Self::default()
    }

    /// Override protocol ID.
    pub fn with_protocol_id(mut self, protocol_id: impl Into<String>) -> Self {
        self.protocol_id = Some(protocol_id.into());
        self
    }

    /// Set description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }
}
