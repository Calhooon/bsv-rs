//! Contacts manager for encrypted contact storage.
//!
//! The [`ContactsManager`] provides encrypted storage of contacts using
//! the wallet's basket system with PushDrop tokens.

use crate::wallet::WalletInterface;
use crate::{Error, Result};

use super::types::{Contact, ContactsManagerConfig};

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Cache entry for contacts.
#[derive(Debug, Clone, Default)]
struct ContactsCache {
    /// Cached contacts indexed by identity key.
    contacts: HashMap<String, Contact>,
    /// Whether the cache has been populated.
    initialized: bool,
}

/// Manager for encrypted contact storage.
///
/// Contacts are stored encrypted in the wallet's basket system using
/// PushDrop tokens. Each contact is:
/// - Encrypted with a per-contact key
/// - Tagged with a hashed identity key for fast lookup
/// - Stored in the "contacts" basket
///
/// # Example
///
/// ```rust,ignore
/// use bsv_sdk::identity::{ContactsManager, ContactsManagerConfig, Contact};
/// use bsv_sdk::wallet::ProtoWallet;
///
/// let wallet = ProtoWallet::new(None);
/// let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());
///
/// // Add a contact
/// manager.add_contact(Contact {
///     identity_key: "02abc123...".to_string(),
///     name: "Alice".to_string(),
///     ..Default::default()
/// }).await?;
///
/// // List all contacts
/// let contacts = manager.list_contacts().await?;
/// ```
pub struct ContactsManager<W: WalletInterface> {
    wallet: W,
    config: ContactsManagerConfig,
    cache: Arc<RwLock<ContactsCache>>,
}

impl<W: WalletInterface> ContactsManager<W> {
    /// Create a new ContactsManager with the given wallet and configuration.
    pub fn new(wallet: W, config: ContactsManagerConfig) -> Self {
        Self {
            wallet,
            config,
            cache: Arc::new(RwLock::new(ContactsCache::default())),
        }
    }

    /// Get the originator string for wallet calls.
    fn originator(&self) -> &str {
        self.config.originator.as_deref().unwrap_or("")
    }

    // =========================================================================
    // CRUD Operations
    // =========================================================================

    /// Add a new contact.
    ///
    /// If a contact with the same identity key already exists, it will be updated.
    ///
    /// # Arguments
    /// * `contact` - The contact to add
    ///
    /// # Example
    /// ```rust,ignore
    /// manager.add_contact(Contact {
    ///     identity_key: "02abc123...".to_string(),
    ///     name: "Alice".to_string(),
    ///     avatar_url: Some("https://example.com/avatar.png".to_string()),
    ///     added_at: chrono::Utc::now().timestamp_millis() as u64,
    ///     notes: Some("Met at conference".to_string()),
    ///     tags: vec!["work".to_string()],
    ///     metadata: None,
    /// }).await?;
    /// ```
    pub async fn add_contact(&self, contact: Contact) -> Result<()> {
        // Update local cache
        {
            let mut cache = self.cache.write().await;
            cache
                .contacts
                .insert(contact.identity_key.clone(), contact.clone());
        }

        // In a full implementation, this would:
        // 1. Create a hashed tag for the identity key
        // 2. Encrypt the contact data
        // 3. Create a PushDrop locking script
        // 4. Store via wallet.createAction()

        // For now, we just use the in-memory cache
        // TODO: Implement blockchain storage when full wallet is available

        Ok(())
    }

    /// Get a contact by identity key.
    ///
    /// # Arguments
    /// * `identity_key` - The hex-encoded public key of the contact
    ///
    /// # Returns
    /// The contact if found, or None if not found.
    pub async fn get_contact(&self, identity_key: &str) -> Result<Option<Contact>> {
        let cache = self.cache.read().await;
        Ok(cache.contacts.get(identity_key).cloned())
    }

    /// Update an existing contact.
    ///
    /// # Arguments
    /// * `identity_key` - The identity key of the contact to update
    /// * `updates` - The updated contact data
    ///
    /// # Errors
    /// Returns an error if the contact is not found.
    pub async fn update_contact(&self, identity_key: &str, updates: Contact) -> Result<()> {
        {
            let cache = self.cache.read().await;
            if !cache.contacts.contains_key(identity_key) {
                return Err(Error::ContactNotFound(identity_key.to_string()));
            }
        }

        // Update in cache
        {
            let mut cache = self.cache.write().await;
            cache.contacts.insert(identity_key.to_string(), updates);
        }

        // TODO: Implement blockchain update when full wallet is available

        Ok(())
    }

    /// Remove a contact.
    ///
    /// # Arguments
    /// * `identity_key` - The identity key of the contact to remove
    ///
    /// # Errors
    /// Returns an error if the contact is not found.
    pub async fn remove_contact(&self, identity_key: &str) -> Result<()> {
        // Remove from cache
        {
            let mut cache = self.cache.write().await;
            if cache.contacts.remove(identity_key).is_none() {
                return Err(Error::ContactNotFound(identity_key.to_string()));
            }
        }

        // TODO: Implement blockchain removal when full wallet is available

        Ok(())
    }

    /// List all contacts.
    ///
    /// # Returns
    /// A list of all stored contacts.
    pub async fn list_contacts(&self) -> Result<Vec<Contact>> {
        let cache = self.cache.read().await;
        Ok(cache.contacts.values().cloned().collect())
    }

    /// List contacts with optional cache refresh.
    ///
    /// # Arguments
    /// * `force_refresh` - If true, reload from storage even if cache exists
    pub async fn list_contacts_with_refresh(&self, force_refresh: bool) -> Result<Vec<Contact>> {
        if force_refresh {
            // TODO: Reload from blockchain storage
            // For now, just return cached contacts
        }
        self.list_contacts().await
    }

    // =========================================================================
    // Search Operations
    // =========================================================================

    /// Search contacts by name or tag.
    ///
    /// Performs a case-insensitive search across contact names and tags.
    ///
    /// # Arguments
    /// * `query` - The search query string
    ///
    /// # Returns
    /// A list of contacts matching the query.
    pub async fn search_contacts(&self, query: &str) -> Result<Vec<Contact>> {
        let query_lower = query.to_lowercase();
        let cache = self.cache.read().await;

        let matches: Vec<Contact> = cache
            .contacts
            .values()
            .filter(|c| {
                c.name.to_lowercase().contains(&query_lower)
                    || c.tags
                        .iter()
                        .any(|t| t.to_lowercase().contains(&query_lower))
                    || c.notes
                        .as_ref()
                        .map(|n| n.to_lowercase().contains(&query_lower))
                        .unwrap_or(false)
            })
            .cloned()
            .collect();

        Ok(matches)
    }

    /// Get contacts with a specific tag.
    ///
    /// # Arguments
    /// * `tag` - The tag to filter by
    ///
    /// # Returns
    /// A list of contacts with the specified tag.
    pub async fn get_contacts_by_tag(&self, tag: &str) -> Result<Vec<Contact>> {
        let tag_lower = tag.to_lowercase();
        let cache = self.cache.read().await;

        let matches: Vec<Contact> = cache
            .contacts
            .values()
            .filter(|c| c.tags.iter().any(|t| t.to_lowercase() == tag_lower))
            .cloned()
            .collect();

        Ok(matches)
    }

    // =========================================================================
    // Cache Management
    // =========================================================================

    /// Clear the contacts cache.
    ///
    /// This does not remove contacts from storage, only clears the in-memory cache.
    pub async fn clear_cache(&self) {
        let mut cache = self.cache.write().await;
        cache.contacts.clear();
        cache.initialized = false;
    }

    /// Check if the cache is initialized.
    pub async fn is_cache_initialized(&self) -> bool {
        let cache = self.cache.read().await;
        cache.initialized
    }

    /// Get the number of cached contacts.
    pub async fn cached_count(&self) -> usize {
        let cache = self.cache.read().await;
        cache.contacts.len()
    }

    // =========================================================================
    // Helper Methods
    // =========================================================================

    /// Create a hashed tag for privacy-preserving lookup.
    ///
    /// Uses HMAC to hash the identity key so contacts can be looked up
    /// without revealing the actual identity key in the tag.
    #[allow(dead_code)]
    async fn create_identity_tag(&self, identity_key: &str) -> Result<String> {
        let protocol = crate::wallet::Protocol::new(
            crate::wallet::SecurityLevel::App,
            &self.config.protocol_id.1,
        );

        let result = self
            .wallet
            .create_hmac(
                crate::wallet::CreateHmacArgs {
                    data: identity_key.as_bytes().to_vec(),
                    protocol_id: protocol,
                    key_id: identity_key.to_string(),
                    counterparty: Some(crate::wallet::Counterparty::Self_),
                },
                self.originator(),
            )
            .await?;

        Ok(format!(
            "identityKey {}",
            crate::primitives::to_hex(&result.hmac)
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::ProtoWallet;

    fn create_test_contact(key: &str, name: &str) -> Contact {
        Contact {
            identity_key: key.to_string(),
            name: name.to_string(),
            avatar_url: Some("https://example.com/avatar.png".to_string()),
            added_at: 1700000000000,
            notes: None,
            tags: Vec::new(),
            metadata: None,
        }
    }

    #[tokio::test]
    async fn test_add_and_get_contact() {
        let wallet = ProtoWallet::new(None);
        let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

        let contact = create_test_contact("02abc123", "Alice");
        manager.add_contact(contact.clone()).await.unwrap();

        let retrieved = manager.get_contact("02abc123").await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name, "Alice");
    }

    #[tokio::test]
    async fn test_get_nonexistent_contact() {
        let wallet = ProtoWallet::new(None);
        let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

        let result = manager.get_contact("nonexistent").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_update_contact() {
        let wallet = ProtoWallet::new(None);
        let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

        // Add initial contact
        let contact = create_test_contact("02abc123", "Alice");
        manager.add_contact(contact).await.unwrap();

        // Update the contact
        let updated = Contact {
            identity_key: "02abc123".to_string(),
            name: "Alice Updated".to_string(),
            notes: Some("Updated notes".to_string()),
            ..Default::default()
        };
        manager.update_contact("02abc123", updated).await.unwrap();

        // Verify update
        let retrieved = manager.get_contact("02abc123").await.unwrap().unwrap();
        assert_eq!(retrieved.name, "Alice Updated");
        assert_eq!(retrieved.notes, Some("Updated notes".to_string()));
    }

    #[tokio::test]
    async fn test_update_nonexistent_contact() {
        let wallet = ProtoWallet::new(None);
        let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

        let contact = create_test_contact("02abc123", "Alice");
        let result = manager.update_contact("nonexistent", contact).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_remove_contact() {
        let wallet = ProtoWallet::new(None);
        let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

        let contact = create_test_contact("02abc123", "Alice");
        manager.add_contact(contact).await.unwrap();

        // Verify contact exists
        assert!(manager.get_contact("02abc123").await.unwrap().is_some());

        // Remove contact
        manager.remove_contact("02abc123").await.unwrap();

        // Verify contact is removed
        assert!(manager.get_contact("02abc123").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_remove_nonexistent_contact() {
        let wallet = ProtoWallet::new(None);
        let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

        let result = manager.remove_contact("nonexistent").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_list_contacts() {
        let wallet = ProtoWallet::new(None);
        let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

        // Add multiple contacts
        manager
            .add_contact(create_test_contact("02abc123", "Alice"))
            .await
            .unwrap();
        manager
            .add_contact(create_test_contact("02def456", "Bob"))
            .await
            .unwrap();
        manager
            .add_contact(create_test_contact("02ghi789", "Charlie"))
            .await
            .unwrap();

        let contacts = manager.list_contacts().await.unwrap();
        assert_eq!(contacts.len(), 3);
    }

    #[tokio::test]
    async fn test_search_contacts_by_name() {
        let wallet = ProtoWallet::new(None);
        let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

        manager
            .add_contact(create_test_contact("02abc123", "Alice Smith"))
            .await
            .unwrap();
        manager
            .add_contact(create_test_contact("02def456", "Bob Jones"))
            .await
            .unwrap();
        manager
            .add_contact(create_test_contact("02ghi789", "Alice Johnson"))
            .await
            .unwrap();

        let results = manager.search_contacts("alice").await.unwrap();
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn test_search_contacts_by_tag() {
        let wallet = ProtoWallet::new(None);
        let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

        let mut contact1 = create_test_contact("02abc123", "Alice");
        contact1.tags = vec!["work".to_string(), "engineering".to_string()];

        let mut contact2 = create_test_contact("02def456", "Bob");
        contact2.tags = vec!["personal".to_string()];

        let mut contact3 = create_test_contact("02ghi789", "Charlie");
        contact3.tags = vec!["work".to_string()];

        manager.add_contact(contact1).await.unwrap();
        manager.add_contact(contact2).await.unwrap();
        manager.add_contact(contact3).await.unwrap();

        let results = manager.search_contacts("work").await.unwrap();
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn test_get_contacts_by_tag() {
        let wallet = ProtoWallet::new(None);
        let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

        let mut contact1 = create_test_contact("02abc123", "Alice");
        contact1.tags = vec!["work".to_string(), "engineering".to_string()];

        let mut contact2 = create_test_contact("02def456", "Bob");
        contact2.tags = vec!["personal".to_string()];

        manager.add_contact(contact1).await.unwrap();
        manager.add_contact(contact2).await.unwrap();

        let work_contacts = manager.get_contacts_by_tag("work").await.unwrap();
        assert_eq!(work_contacts.len(), 1);
        assert_eq!(work_contacts[0].name, "Alice");

        let personal_contacts = manager.get_contacts_by_tag("Personal").await.unwrap();
        assert_eq!(personal_contacts.len(), 1);
        assert_eq!(personal_contacts[0].name, "Bob");
    }

    #[tokio::test]
    async fn test_search_contacts_by_notes() {
        let wallet = ProtoWallet::new(None);
        let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

        let mut contact = create_test_contact("02abc123", "Alice");
        contact.notes = Some("Met at the blockchain conference".to_string());

        manager.add_contact(contact).await.unwrap();

        let results = manager.search_contacts("conference").await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "Alice");
    }

    #[tokio::test]
    async fn test_cache_management() {
        let wallet = ProtoWallet::new(None);
        let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

        assert!(!manager.is_cache_initialized().await);
        assert_eq!(manager.cached_count().await, 0);

        manager
            .add_contact(create_test_contact("02abc123", "Alice"))
            .await
            .unwrap();
        assert_eq!(manager.cached_count().await, 1);

        manager.clear_cache().await;
        assert_eq!(manager.cached_count().await, 0);
    }

    #[tokio::test]
    async fn test_case_insensitive_search() {
        let wallet = ProtoWallet::new(None);
        let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

        manager
            .add_contact(create_test_contact("02abc123", "ALICE"))
            .await
            .unwrap();

        // Search should be case insensitive
        let results = manager.search_contacts("alice").await.unwrap();
        assert_eq!(results.len(), 1);

        let results = manager.search_contacts("ALICE").await.unwrap();
        assert_eq!(results.len(), 1);

        let results = manager.search_contacts("Alice").await.unwrap();
        assert_eq!(results.len(), 1);
    }

    #[tokio::test]
    async fn test_add_contact_replaces_existing() {
        let wallet = ProtoWallet::new(None);
        let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

        let contact1 = create_test_contact("02abc123", "Alice V1");
        manager.add_contact(contact1).await.unwrap();

        let contact2 = Contact {
            identity_key: "02abc123".to_string(),
            name: "Alice V2".to_string(),
            notes: Some("Updated".to_string()),
            ..Default::default()
        };
        manager.add_contact(contact2).await.unwrap();

        let contacts = manager.list_contacts().await.unwrap();
        assert_eq!(contacts.len(), 1);

        let retrieved = manager.get_contact("02abc123").await.unwrap().unwrap();
        assert_eq!(retrieved.name, "Alice V2");
    }
}
