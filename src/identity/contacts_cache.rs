//! Contact cache reads and refresh.
use super::*;

impl<W: WalletInterface> ContactsManager<W> {
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
    /// * `force_refresh` - If true, reload from blockchain even if cache exists
    pub async fn list_contacts_with_refresh(&self, force_refresh: bool) -> Result<Vec<Contact>> {
        // Return cached contacts if available and not forcing refresh
        if !force_refresh {
            let cache = self.cache.read().await;
            if cache.initialized {
                return Ok(cache.contacts.values().cloned().collect());
            }
        }

        // Load contacts from blockchain
        let contacts = self.load_contacts_from_chain().await?;

        // Update cache
        {
            let mut cache = self.cache.write().await;
            cache.contacts.clear();
            for contact in &contacts {
                cache
                    .contacts
                    .insert(contact.identity_key.clone(), contact.clone());
            }
            cache.initialized = true;
        }

        Ok(contacts)
    }

    /// Load all contacts from the blockchain.
    async fn load_contacts_from_chain(&self) -> Result<Vec<Contact>> {
        let result = self
            .contact_outputs(None, OutputInclude::LockingScripts, 1000)
            .await;
        let Ok(result) = result else {
            return Ok(Vec::new());
        };
        let mut contacts = Vec::new();
        for output in result.outputs {
            if let Some(contact) = self.decode_cached_contact(output).await? {
                contacts.push(contact);
            }
        }
        Ok(contacts)
    }

    async fn decode_cached_contact(
        &self,
        output: crate::wallet::WalletOutput,
    ) -> Result<Option<Contact>> {
        let Some(key_id) = super::actions::stored_key_id(&output) else {
            return Ok(None);
        };
        let Some(bytes) = output.locking_script else {
            return Ok(None);
        };
        let script = crate::script::LockingScript::from_binary(&bytes)
            .map_err(|e| Error::IdentityError(format!("Failed to parse locking script: {e}")))?;
        // Lock-before alone, as ContactsManager.ts:432 decodes it (#537).
        let Ok(decoded) = PushDrop::decode_before(&script) else {
            return Ok(None);
        };
        let Some(ciphertext) = decoded.fields.first() else {
            return Ok(None);
        };
        let plaintext = self
            .wallet
            .decrypt(
                DecryptArgs {
                    ciphertext: ciphertext.clone(),
                    protocol_id: Protocol::new(SecurityLevel::App, &self.config.protocol_id.1),
                    key_id,
                    counterparty: Some(Counterparty::Self_),
                    ..Default::default()
                },
                self.originator(),
            )
            .await;
        Ok(plaintext
            .ok()
            .and_then(|r| serde_json::from_slice(&r.plaintext).ok()))
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
}
