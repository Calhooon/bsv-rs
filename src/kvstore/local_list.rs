//! Local convenience listing, separate from single-key lookup authentication.
use super::LocalKVStore;
use crate::kvstore::{KVStoreEntry, KVStoreInterpreter, KVStoreQuery};
use crate::script::LockingScript;
use crate::wallet::{
    GetPublicKeyArgs, ListOutputsArgs, OutputInclude, QueryMode, WalletInterface, WalletOutput,
};
use crate::Result;

impl<W: WalletInterface + std::fmt::Debug> LocalKVStore<W> {
    pub(super) async fn list_entries(&self, query: KVStoreQuery) -> Result<Vec<KVStoreEntry>> {
        let listed = self
            .wallet
            .list_outputs(
                ListOutputsArgs {
                    basket: self.config.protocol_id.clone(),
                    tags: query.key.as_ref().map(|key| vec![key.clone()]),
                    tag_query_mode: Some(QueryMode::All),
                    include: Some(OutputInclude::EntireTransactions),
                    include_custom_instructions: None,
                    include_tags: Some(true),
                    include_labels: None,
                    limit: query.limit,
                    offset: query.skip.map(|skip| skip as i32),
                    seek_permission: None,
                },
                self.originator(),
            )
            .await?;
        let key = self
            .wallet
            .get_public_key(
                GetPublicKeyArgs {
                    identity_key: true,
                    ..Default::default()
                },
                self.originator(),
            )
            .await?;
        let mut entries = Vec::new();
        for output in &listed.outputs {
            if let Some(entry) = self.list_entry(output, &key.public_key).await {
                entries.push(entry);
            }
        }
        if let Some(filter) = &query.tags {
            let mode = query.tag_query_mode.as_deref().unwrap_or("all");
            entries.retain(|entry| {
                if mode == "any" {
                    filter.iter().any(|tag| entry.tags.contains(tag))
                } else {
                    filter.iter().all(|tag| entry.tags.contains(tag))
                }
            });
        }
        Ok(entries)
    }

    async fn list_entry(&self, output: &WalletOutput, controller: &str) -> Option<KVStoreEntry> {
        let script = LockingScript::from_binary(output.locking_script.as_ref()?).ok()?;
        let fields = KVStoreInterpreter::extract_fields(&script)?;
        let key = fields.key_string()?;
        let value = if self.config.encrypt {
            self.decrypt_value(&key, fields.value_bytes()).await.ok()?
        } else {
            fields.value.clone()
        };
        Some(
            KVStoreEntry::new(
                &key,
                String::from_utf8(value).unwrap_or_default(),
                controller,
                &self.config.protocol_id,
            )
            .with_tags(fields.tags_vec()),
        )
    }
}
