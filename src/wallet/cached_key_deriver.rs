//! Cached Key Derivation.
//!
//! This module provides the [`CachedKeyDeriver`] struct, which wraps [`KeyDeriver`]
//! with an LRU cache to optimize performance when the same keys are derived repeatedly.
//!
//! # Overview
//!
//! Key derivation involves computationally expensive elliptic curve operations.
//! When an application repeatedly derives the same keys (e.g., for a specific
//! counterparty and protocol), caching can significantly improve performance.
//!
//! The [`CachedKeyDeriver`] maintains separate caches for:
//! - Public keys
//! - Private keys
//! - Symmetric keys
//!
//! Each cache uses an LRU (Least Recently Used) eviction policy with a configurable
//! maximum size (default: 1000 entries).
//!
//! # Example
//!
//! ```rust
//! use bsv_sdk::wallet::{CachedKeyDeriver, Protocol, SecurityLevel, Counterparty, CacheConfig, KeyDeriverApi};
//! use bsv_sdk::primitives::PrivateKey;
//!
//! // Create with default cache size (1000)
//! let deriver = CachedKeyDeriver::new(Some(PrivateKey::random()), None);
//!
//! // Or with custom cache size
//! let config = CacheConfig { max_size: 500 };
//! let deriver = CachedKeyDeriver::new(Some(PrivateKey::random()), Some(config));
//!
//! // Use like KeyDeriver - results are cached automatically
//! let protocol = Protocol::new(SecurityLevel::App, "my application");
//! let key1 = deriver.derive_public_key(&protocol, "key-1", &Counterparty::Self_, true).unwrap();
//! let key2 = deriver.derive_public_key(&protocol, "key-1", &Counterparty::Self_, true).unwrap(); // Cached!
//! ```

use std::collections::HashMap;
use std::sync::Mutex;

use crate::error::Result;
use crate::primitives::{PrivateKey, PublicKey, SymmetricKey};

use super::key_deriver::{KeyDeriver, KeyDeriverApi};
use super::types::{Counterparty, Protocol};

/// Configuration for the cached key deriver.
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Maximum number of entries in each cache.
    pub max_size: usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self { max_size: 1000 }
    }
}

/// Entry in the LRU cache with a timestamp for LRU eviction.
#[derive(Clone)]
struct CacheEntry<T: Clone> {
    value: T,
    access_order: u64,
}

/// A simple LRU cache implementation.
struct LruCache<T: Clone> {
    entries: HashMap<String, CacheEntry<T>>,
    max_size: usize,
    access_counter: u64,
}

impl<T: Clone> LruCache<T> {
    fn new(max_size: usize) -> Self {
        Self {
            entries: HashMap::with_capacity(max_size),
            max_size: if max_size == 0 { 1 } else { max_size },
            access_counter: 0,
        }
    }

    fn get(&mut self, key: &str) -> Option<T> {
        if let Some(entry) = self.entries.get_mut(key) {
            // Update access order for LRU
            self.access_counter += 1;
            entry.access_order = self.access_counter;
            Some(entry.value.clone())
        } else {
            None
        }
    }

    fn put(&mut self, key: String, value: T) {
        // If at capacity, evict the least recently used entry
        if self.entries.len() >= self.max_size && !self.entries.contains_key(&key) {
            self.evict_lru();
        }

        self.access_counter += 1;
        self.entries.insert(
            key,
            CacheEntry {
                value,
                access_order: self.access_counter,
            },
        );
    }

    fn evict_lru(&mut self) {
        if self.entries.is_empty() {
            return;
        }

        // Find the entry with the lowest access order
        let lru_key = self
            .entries
            .iter()
            .min_by_key(|(_, entry)| entry.access_order)
            .map(|(k, _)| k.clone());

        if let Some(key) = lru_key {
            self.entries.remove(&key);
        }
    }

    #[allow(dead_code)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Cached wrapper around KeyDeriver using LRU caching.
///
/// This implementation caches derived keys to improve performance when the
/// same keys are requested multiple times. It maintains separate LRU caches
/// for public keys, private keys, and symmetric keys.
///
/// The cache is thread-safe using interior mutability with `Mutex`.
pub struct CachedKeyDeriver {
    inner: KeyDeriver,
    public_key_cache: Mutex<LruCache<PublicKey>>,
    private_key_cache: Mutex<LruCache<PrivateKey>>,
    symmetric_key_cache: Mutex<LruCache<SymmetricKey>>,
}

impl CachedKeyDeriver {
    /// Creates a new CachedKeyDeriver with optional root key and cache configuration.
    ///
    /// # Arguments
    ///
    /// * `root_key` - The root private key, or None to use the "anyone" key
    /// * `config` - Optional cache configuration; defaults to 1000 max entries
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_sdk::wallet::{CachedKeyDeriver, CacheConfig};
    /// use bsv_sdk::primitives::PrivateKey;
    ///
    /// // Default cache size
    /// let deriver = CachedKeyDeriver::new(Some(PrivateKey::random()), None);
    ///
    /// // Custom cache size
    /// let config = CacheConfig { max_size: 2000 };
    /// let deriver = CachedKeyDeriver::new(Some(PrivateKey::random()), Some(config));
    /// ```
    pub fn new(root_key: Option<PrivateKey>, config: Option<CacheConfig>) -> Self {
        let config = config.unwrap_or_default();
        let max_size = if config.max_size == 0 {
            1000
        } else {
            config.max_size
        };

        Self {
            inner: KeyDeriver::new(root_key),
            public_key_cache: Mutex::new(LruCache::new(max_size)),
            private_key_cache: Mutex::new(LruCache::new(max_size)),
            symmetric_key_cache: Mutex::new(LruCache::new(max_size)),
        }
    }

    /// Generates a cache key for lookups.
    fn cache_key(
        method: &str,
        protocol: &Protocol,
        key_id: &str,
        counterparty: &Counterparty,
        for_self: Option<bool>,
    ) -> String {
        let cp_str = match counterparty {
            Counterparty::Self_ => "self".to_string(),
            Counterparty::Anyone => "anyone".to_string(),
            Counterparty::Other(pk) => pk.to_hex(),
        };
        let for_self_str = for_self.map(|b| b.to_string()).unwrap_or_default();
        format!(
            "{}:{}:{}:{}:{}:{}",
            method,
            protocol.security_level.as_u8(),
            protocol.protocol_name,
            key_id,
            cp_str,
            for_self_str
        )
    }

    /// Returns the inner KeyDeriver for operations that don't benefit from caching.
    pub fn inner(&self) -> &KeyDeriver {
        &self.inner
    }

    /// Returns the root key.
    pub fn root_key(&self) -> &PrivateKey {
        self.inner.root_key()
    }
}

impl KeyDeriverApi for CachedKeyDeriver {
    fn identity_key(&self) -> PublicKey {
        self.inner.identity_key()
    }

    fn derive_public_key(
        &self,
        protocol: &Protocol,
        key_id: &str,
        counterparty: &Counterparty,
        for_self: bool,
    ) -> Result<PublicKey> {
        let cache_key = Self::cache_key("pub", protocol, key_id, counterparty, Some(for_self));

        // Check cache first
        {
            let mut cache = self.public_key_cache.lock().unwrap();
            if let Some(cached) = cache.get(&cache_key) {
                return Ok(cached);
            }
        }

        // Derive and cache
        let derived = self
            .inner
            .derive_public_key(protocol, key_id, counterparty, for_self)?;
        {
            let mut cache = self.public_key_cache.lock().unwrap();
            cache.put(cache_key, derived.clone());
        }

        Ok(derived)
    }

    fn derive_private_key(
        &self,
        protocol: &Protocol,
        key_id: &str,
        counterparty: &Counterparty,
    ) -> Result<PrivateKey> {
        let cache_key = Self::cache_key("priv", protocol, key_id, counterparty, None);

        // Check cache first
        {
            let mut cache = self.private_key_cache.lock().unwrap();
            if let Some(cached) = cache.get(&cache_key) {
                return Ok(cached);
            }
        }

        // Derive and cache
        let derived = self
            .inner
            .derive_private_key(protocol, key_id, counterparty)?;
        {
            let mut cache = self.private_key_cache.lock().unwrap();
            cache.put(cache_key, derived.clone());
        }

        Ok(derived)
    }

    fn derive_private_key_raw(
        &self,
        invoice_number: &str,
        counterparty: &Counterparty,
    ) -> Result<PrivateKey> {
        // For raw derivation, we use invoice_number as the cache key component
        // We create a synthetic protocol just for caching purposes
        let cache_key = format!(
            "priv_raw:{}:{}",
            invoice_number,
            match counterparty {
                Counterparty::Self_ => "self".to_string(),
                Counterparty::Anyone => "anyone".to_string(),
                Counterparty::Other(pk) => pk.to_hex(),
            }
        );

        // Check cache first
        {
            let mut cache = self.private_key_cache.lock().unwrap();
            if let Some(cached) = cache.get(&cache_key) {
                return Ok(cached);
            }
        }

        // Derive and cache
        let derived = self
            .inner
            .derive_private_key_raw(invoice_number, counterparty)?;
        {
            let mut cache = self.private_key_cache.lock().unwrap();
            cache.put(cache_key, derived.clone());
        }

        Ok(derived)
    }

    fn derive_symmetric_key(
        &self,
        protocol: &Protocol,
        key_id: &str,
        counterparty: &Counterparty,
    ) -> Result<SymmetricKey> {
        let cache_key = Self::cache_key("sym", protocol, key_id, counterparty, None);

        // Check cache first
        {
            let mut cache = self.symmetric_key_cache.lock().unwrap();
            if let Some(cached) = cache.get(&cache_key) {
                return Ok(cached);
            }
        }

        // Derive and cache
        let derived = self
            .inner
            .derive_symmetric_key(protocol, key_id, counterparty)?;
        {
            let mut cache = self.symmetric_key_cache.lock().unwrap();
            cache.put(cache_key, derived.clone());
        }

        Ok(derived)
    }

    fn reveal_specific_secret(
        &self,
        counterparty: &Counterparty,
        protocol: &Protocol,
        key_id: &str,
    ) -> Result<Vec<u8>> {
        // Secrets are not cached for security reasons
        self.inner
            .reveal_specific_secret(counterparty, protocol, key_id)
    }

    fn reveal_counterparty_secret(&self, counterparty: &Counterparty) -> Result<PublicKey> {
        // Secrets are not cached for security reasons
        self.inner.reveal_counterparty_secret(counterparty)
    }
}

impl std::fmt::Debug for CachedKeyDeriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedKeyDeriver")
            .field("identity_key", &self.identity_key_hex())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::SecurityLevel;

    #[test]
    fn test_cached_key_deriver_creation() {
        let key = PrivateKey::random();
        let deriver = CachedKeyDeriver::new(Some(key.clone()), None);
        assert_eq!(deriver.identity_key(), key.public_key());
    }

    #[test]
    fn test_cached_key_deriver_with_config() {
        let config = CacheConfig { max_size: 100 };
        let deriver = CachedKeyDeriver::new(Some(PrivateKey::random()), Some(config));
        assert!(!deriver.identity_key().to_hex().is_empty());
    }

    #[test]
    fn test_public_key_caching() {
        let deriver = CachedKeyDeriver::new(Some(PrivateKey::random()), None);
        let protocol = Protocol::new(SecurityLevel::App, "test application");
        let key_id = "test-key";

        // First call should derive
        let key1 = deriver
            .derive_public_key(&protocol, key_id, &Counterparty::Self_, true)
            .unwrap();

        // Second call should hit cache and return same value
        let key2 = deriver
            .derive_public_key(&protocol, key_id, &Counterparty::Self_, true)
            .unwrap();

        assert_eq!(key1.to_compressed(), key2.to_compressed());
    }

    #[test]
    fn test_private_key_caching() {
        let deriver = CachedKeyDeriver::new(Some(PrivateKey::random()), None);
        let protocol = Protocol::new(SecurityLevel::App, "test application");
        let key_id = "test-key";

        let key1 = deriver
            .derive_private_key(&protocol, key_id, &Counterparty::Self_)
            .unwrap();
        let key2 = deriver
            .derive_private_key(&protocol, key_id, &Counterparty::Self_)
            .unwrap();

        assert_eq!(key1.to_bytes(), key2.to_bytes());
    }

    #[test]
    fn test_symmetric_key_caching() {
        let deriver = CachedKeyDeriver::new(Some(PrivateKey::random()), None);
        let protocol = Protocol::new(SecurityLevel::App, "test application");
        let key_id = "test-key";

        let key1 = deriver
            .derive_symmetric_key(&protocol, key_id, &Counterparty::Self_)
            .unwrap();
        let key2 = deriver
            .derive_symmetric_key(&protocol, key_id, &Counterparty::Self_)
            .unwrap();

        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_different_parameters_produce_different_cache_entries() {
        let deriver = CachedKeyDeriver::new(Some(PrivateKey::random()), None);
        let protocol = Protocol::new(SecurityLevel::App, "test application");

        let key1 = deriver
            .derive_public_key(&protocol, "key-1", &Counterparty::Self_, true)
            .unwrap();
        let key2 = deriver
            .derive_public_key(&protocol, "key-2", &Counterparty::Self_, true)
            .unwrap();

        assert_ne!(key1.to_compressed(), key2.to_compressed());
    }

    #[test]
    fn test_for_self_flag_produces_different_cache_entries() {
        let alice = CachedKeyDeriver::new(Some(PrivateKey::random()), None);
        let bob = PrivateKey::random();
        let protocol = Protocol::new(SecurityLevel::App, "test application");
        let key_id = "test-key";
        let bob_counterparty = Counterparty::Other(bob.public_key());

        let key_for_self = alice
            .derive_public_key(&protocol, key_id, &bob_counterparty, true)
            .unwrap();
        let key_for_other = alice
            .derive_public_key(&protocol, key_id, &bob_counterparty, false)
            .unwrap();

        assert_ne!(key_for_self.to_compressed(), key_for_other.to_compressed());
    }

    #[test]
    fn test_lru_cache_eviction() {
        // Create a cache with very small size
        let config = CacheConfig { max_size: 2 };
        let deriver = CachedKeyDeriver::new(Some(PrivateKey::random()), Some(config));
        let protocol = Protocol::new(SecurityLevel::App, "test application");

        // Fill the cache
        let _key1 = deriver
            .derive_public_key(&protocol, "key-1", &Counterparty::Self_, true)
            .unwrap();
        let _key2 = deriver
            .derive_public_key(&protocol, "key-2", &Counterparty::Self_, true)
            .unwrap();

        // This should evict key-1 (LRU)
        let _key3 = deriver
            .derive_public_key(&protocol, "key-3", &Counterparty::Self_, true)
            .unwrap();

        // All keys should still derive correctly (just not from cache for key-1)
        let key1_again = deriver
            .derive_public_key(&protocol, "key-1", &Counterparty::Self_, true)
            .unwrap();
        assert!(!key1_again.to_hex().is_empty());
    }

    #[test]
    fn test_cached_deriver_implements_api_trait() {
        fn use_deriver<D: KeyDeriverApi>(deriver: &D) -> PublicKey {
            let protocol = Protocol::new(SecurityLevel::App, "trait test");
            deriver
                .derive_public_key(&protocol, "key-1", &Counterparty::Self_, true)
                .unwrap()
        }

        let cached = CachedKeyDeriver::new(Some(PrivateKey::random()), None);
        let key = use_deriver(&cached);
        assert!(!key.to_hex().is_empty());
    }

    #[test]
    fn test_inner_access() {
        let root_key = PrivateKey::random();
        let deriver = CachedKeyDeriver::new(Some(root_key.clone()), None);

        // Can access inner deriver
        assert_eq!(
            deriver.inner().identity_key().to_compressed(),
            root_key.public_key().to_compressed()
        );
    }
}
