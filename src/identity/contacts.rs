//! Contacts manager for encrypted contact storage.
//!
//! The [`ContactsManager`] provides encrypted storage of contacts using
//! the wallet's basket system with PushDrop tokens.

use crate::primitives::bsv::sighash::{
    parse_transaction, SighashParams, SIGHASH_ALL, SIGHASH_FORKID,
};
use crate::primitives::to_base64;
use crate::transaction::Transaction;
use crate::wallet::{
    Counterparty, CreateActionArgs, CreateActionInput, CreateActionOptions, CreateActionOutput,
    EncryptArgs, ListOutputsArgs, OutputInclude, Protocol, SignActionArgs, SignActionSpend,
    WalletInterface,
};
use crate::{Error, Result};

use super::types::{Contact, ContactsManagerConfig};
#[path = "contacts_actions.rs"]
mod actions;
#[path = "contacts_auth.rs"]
mod auth;
#[path = "contacts_cache.rs"]
mod cache;
#[path = "contacts_record.rs"]
mod record;
#[path = "contacts_spend.rs"]
mod spend;

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// `validateIdentityKey` (`ContactsManager.ts:83-94`) on a text, the rule the
/// reference's `getContacts(identityKey)` judges the asked key by before it
/// reads a contact (`:316-317`; the identity client's by-key door, #818b).
pub(super) fn contact_identity_key(identity_key: &str) -> crate::Result<String> {
    record::identity_key(&serde_json::Value::String(identity_key.to_string()))
}

/// The contacts cache, held in the reference's order (#904's eighth fold):
/// the reference's cache is an array (`ContactsManager.ts:376`, `:381-391`),
/// in the listing's order on a load, a new contact appended and an update
/// written in place (`saveContact`, `:532-534`), a removal filtering it
/// (`#commitCachedRemoval`, `:934`). A plain read answers that array, and a
/// read by key its first entry for the key (`:390`). The index names each
/// key's first position, so a lookup costs one hash; a load and a removal
/// rebuild it, as the reference rewrites its array there.
#[derive(Debug, Clone, Default)]
struct ContactsCache {
    /// Cached contacts in the reference's order.
    contacts: Vec<Contact>,
    /// Each identity key's first position in `contacts`.
    index: HashMap<String, usize>,
    /// Whether the cache has been populated.
    initialized: bool,
}

impl ContactsCache {
    /// The first cached contact of the key.
    fn get(&self, identity_key: &str) -> Option<&Contact> {
        self.index.get(identity_key).map(|&at| &self.contacts[at])
    }

    /// The contacts in order.
    fn ordered(&self) -> Vec<Contact> {
        self.contacts.clone()
    }

    /// `saveContact`'s write (`:532-534`): the first entry of the key
    /// replaced in place, else the contact appended.
    fn save(&mut self, contact: Contact) {
        match self.index.get(&contact.identity_key) {
            Some(&at) => self.contacts[at] = contact,
            None => {
                self.index
                    .insert(contact.identity_key.clone(), self.contacts.len());
                self.contacts.push(contact);
            }
        }
    }

    /// The cache replaced by a load, in the listing's order.
    fn load(&mut self, contacts: Vec<Contact>) {
        self.contacts = contacts;
        self.reindex();
    }

    /// `#commitCachedRemoval`'s filter (`:934`): every entry of the key
    /// removed, the others kept in order.
    fn remove(&mut self, identity_key: &str) {
        if self.index.contains_key(identity_key) {
            self.contacts.retain(|c| c.identity_key != identity_key);
            self.reindex();
        }
    }

    /// The cache emptied and marked unloaded.
    fn clear(&mut self) {
        self.contacts.clear();
        self.index.clear();
        self.initialized = false;
    }

    fn reindex(&mut self) {
        self.index.clear();
        for (at, contact) in self.contacts.iter().enumerate() {
            self.index.entry(contact.identity_key.clone()).or_insert(at);
        }
    }
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
/// use bsv_rs::identity::{ContactsManager, ContactsManagerConfig, Contact};
/// use bsv_rs::wallet::ProtoWallet;
///
/// let wallet = ProtoWallet::new(None);
/// let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());
///
/// // Add a contact
/// manager.add_contact(Contact::new("Alice", "02abc123...")).await?;
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
    fn originator(&self) -> Option<&str> {
        self.config.originator.as_deref()
    }

    /// The contact protocol from the configuration, `[2, 'contact']` by
    /// default, the reference's for every contact key (`ContactsManager.ts:30`,
    /// #542).
    fn protocol(&self) -> Result<Protocol> {
        let (level, name) = (self.config.protocol_id.0, &self.config.protocol_id.1);
        Protocol::from_tuple((level, name))
            .ok_or_else(|| Error::IdentityError(format!("Invalid protocol ID: ({level}, {name})")))
    }

    // =========================================================================
    // CRUD Operations
    // =========================================================================

    /// Add a new contact.
    ///
    /// If a contact with the same identity key already exists, it will be updated.
    /// The contact is encrypted and stored on-chain using a PushDrop token.
    ///
    /// # Arguments
    /// * `contact` - The contact to add
    ///
    /// # Example
    /// ```rust,ignore
    /// manager.add_contact(
    ///     Contact::new("Alice", "02abc123...")
    ///         .with_avatar_url("https://example.com/avatar.png")
    ///         .with_notes("Met at conference")
    ///         .with_tags(["work"]),
    /// ).await?;
    /// ```
    pub async fn add_contact(&self, contact: Contact) -> Result<()> {
        // The reference's record, validated before any wallet call
        // (`saveContact`, `ContactsManager.ts:527-528`; #544). Every wallet
        // failure is the caller's, as `saveContact` lets it through, and the
        // cache is written after the chain alone (`:536-566`; #904).
        let record = record::record_of(&contact)?;
        let tag = self.create_identity_tag(&record.identity_key).await?;
        let existing = self
            .contact_outputs(
                Some(vec![tag.clone()]),
                OutputInclude::EntireTransactions,
                100,
            )
            .await?;
        let found = self.find_existing(&existing, &record.identity_key).await?;
        let key_id = found
            .as_ref()
            .map_or_else(|| self.generate_key_id(), |(_, key_id)| key_id.clone());
        let lock = self.contact_lock(&record, &key_id).await?;
        match found {
            Some(found) => {
                self.update_contact_on_chain(&existing, found, &contact, &lock, &tag)
                    .await?
            }
            None => {
                let instructions = serde_json::json!({ "keyID": key_id }).to_string();
                self.create_contact(&contact, &lock, &tag, &instructions)
                    .await?
            }
        }
        self.cache.write().await.save(contact);
        Ok(())
    }

    /// Generate a random key ID for contact encryption.
    fn generate_key_id(&self) -> String {
        let random_bytes: [u8; 32] = rand::random();
        to_base64(&random_bytes)
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
        Ok(cache.get(identity_key).cloned())
    }

    /// Update an existing contact.
    ///
    /// This method updates both the in-memory cache and the blockchain.
    /// It finds the existing contact output, spends it, and creates a new
    /// output with the updated contact data atomically.
    ///
    /// # Arguments
    /// * `identity_key` - The identity key of the contact to update
    /// * `updates` - The updated contact data
    ///
    /// # Errors
    /// Returns an error if the contact is not found in cache.
    pub async fn update_contact(&self, identity_key: &str, updates: Contact) -> Result<()> {
        // Verify contact exists in cache
        {
            let cache = self.cache.read().await;
            if cache.get(identity_key).is_none() {
                return Err(Error::ContactNotFound(identity_key.to_string()));
            }
        }

        // Use add_contact which handles the update-if-exists flow
        // It will find the existing output by tag and spend/replace it
        self.add_contact(updates).await
    }

    // =========================================================================
    // Helper Methods
    // =========================================================================

    /// Create a hashed tag for privacy-preserving lookup.
    ///
    /// Uses HMAC to hash the identity key so contacts can be looked up
    /// without revealing the actual identity key in the tag.
    async fn create_identity_tag(&self, identity_key: &str) -> Result<String> {
        let protocol = self.protocol()?;

        let result = self
            .wallet
            .create_hmac(
                crate::wallet::CreateHmacArgs {
                    data: identity_key.as_bytes().to_vec(),
                    protocol_id: protocol,
                    key_id: identity_key.to_string(),
                    counterparty: Some(crate::wallet::Counterparty::Self_),
                    ..Default::default()
                },
                self.originator(),
            )
            .await?;
        // `bytes(hmac, 'contact identity HMAC', 32, 32)` (`:411`, `:583`):
        // the result's type holds 32 bytes.
        Ok(format!(
            "identityKey {}",
            crate::primitives::to_hex(&result.hmac)
        ))
    }
}

#[cfg(test)]
#[path = "contacts_tests.rs"]
mod tests;
