//! Contacts manager for encrypted contact storage.
//!
//! The [`ContactsManager`] provides encrypted storage of contacts using
//! the wallet's basket system with PushDrop tokens.

use crate::primitives::bsv::sighash::{
    parse_transaction, SighashParams, SIGHASH_ALL, SIGHASH_FORKID,
};
use crate::primitives::{to_base64, PublicKey};
use crate::script::templates::PushDrop;
use crate::transaction::{Beef, Transaction};
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
/// use bsv_rs::identity::{ContactsManager, ContactsManagerConfig, Contact};
/// use bsv_rs::wallet::ProtoWallet;
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
        // The reference's record, validated before any wallet call
        // (`saveContact`, `ContactsManager.ts:527-528`; #544).
        let record = record::record_of(&contact)?;
        let tag = self.create_identity_tag(&contact.identity_key).await.ok();
        let existing = if let Some(tag) = &tag {
            self.contact_outputs(
                Some(vec![tag.clone()]),
                OutputInclude::EntireTransactions,
                100,
            )
            .await
            .ok()
        } else {
            None
        };
        let found = match &existing {
            Some(existing) => self.find_existing(existing, &record.identity_key).await?,
            None => None,
        };
        let key_id = found
            .as_ref()
            .map_or_else(|| self.generate_key_id(), |(_, key_id)| key_id.clone());
        let lock = self.contact_lock(&record, &key_id).await?;
        let instructions = serde_json::json!({ "keyID": key_id }).to_string();
        match (existing.as_ref(), tag.as_ref(), found) {
            (Some(existing), Some(tag), Some(found)) => {
                self.update_contact_on_chain(existing, found, &contact, &lock, tag)
                    .await?;
            }
            (_, Some(tag), _) => {
                let _ = self
                    .create_contact(&contact, &lock, tag, &instructions)
                    .await;
            }
            _ => {}
        }
        self.cache
            .write()
            .await
            .contacts
            .insert(contact.identity_key.clone(), contact);
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
        Ok(cache.contacts.get(identity_key).cloned())
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
            if !cache.contacts.contains_key(identity_key) {
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
    #[allow(dead_code)]
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

        Ok(format!(
            "identityKey {}",
            crate::primitives::to_hex(&result.hmac)
        ))
    }
}

#[cfg(test)]
#[path = "contacts_tests.rs"]
mod tests;
