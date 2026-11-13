//! Contact cache reads and refresh.
use super::*;

impl<W: WalletInterface> ContactsManager<W> {
    /// List all contacts.
    ///
    /// # Returns
    /// A list of all stored contacts.
    pub async fn list_contacts(&self) -> Result<Vec<Contact>> {
        let cache = self.cache.read().await;
        Ok(cache.ordered())
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
                return Ok(cache.ordered());
            }
        }

        // Load contacts from blockchain. A forced refresh drops the cache
        // before it loads in the reference (`getContacts`'s `#invalidate`,
        // `ContactsManager.ts:321`, `:343-347`), so one whose load fails
        // leaves it cold; it is dropped here when the load fails, the
        // decode reading each contact's saved-at time from it until then
        // (#904's fourth fold).
        let contacts = match self.load_contacts_from_chain().await {
            Ok(contacts) => contacts,
            Err(error) => {
                if force_refresh {
                    self.cache.write().await.clear();
                }
                return Err(error);
            }
        };

        // The cache in the listing's order (`ContactsManager.ts:376`).
        {
            let mut cache = self.cache.write().await;
            cache.load(contacts.clone());
            cache.initialized = true;
        }

        Ok(contacts)
    }

    /// Load all contacts from the blockchain.
    async fn load_contacts_from_chain(&self) -> Result<Vec<Contact>> {
        // `#loadContactsFromWallet` (`ContactsManager.ts:353-368`): the
        // listing's failure the caller's, as the reference throws it (#904).
        let result = self
            .contact_outputs(None, OutputInclude::LockingScripts, 1000)
            .await?;
        if result.outputs.len() > 1000 {
            return Err(Error::IdentityError(
                "Invalid contacts result: outputs must be an array of at most 1000 entries".into(),
            ));
        }
        let mut contacts = Vec::new();
        for output in result.outputs {
            if let Some(contact) = self.decode_cached_contact(output).await? {
                contacts.push(contact);
            }
        }
        Ok(contacts)
    }

    /// `#decryptContactOutputs`' read of one output (`ContactsManager.ts:480-503`):
    /// the script and the custom instructions present, the script bounded,
    /// the key ID read, the token authenticated, decrypted and read as the
    /// reference's record; any refusal drops the output, as the reference's
    /// `Promise.allSettled` does (`:507-513`). The saved-at time is the
    /// cache's, never the token's (#544).
    async fn decode_cached_contact(
        &self,
        output: crate::wallet::WalletOutput,
    ) -> Result<Option<Contact>> {
        let (Some(bytes), Some(_)) = (&output.locking_script, &output.custom_instructions) else {
            return Ok(None);
        };
        if bytes.len() > super::record::MAX_CIPHERTEXT + 2048 {
            return Ok(None);
        }
        let Ok(key_id) = super::record::read_key_id(output.custom_instructions.as_deref()) else {
            return Ok(None);
        };
        let Ok(script) = crate::script::LockingScript::from_binary(bytes) else {
            return Ok(None);
        };
        let Ok(record) = self.open_contact(&script, &key_id).await else {
            return Ok(None);
        };
        let added_at = self
            .cache
            .read()
            .await
            .get(&record.identity_key)
            .map_or(0, |cached| cached.added_at);
        Ok(Some(super::record::contact_of(record, added_at)))
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
            .iter()
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
            .iter()
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
        self.cache.write().await.clear();
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
