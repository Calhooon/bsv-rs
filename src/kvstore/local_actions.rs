//! Local replacement/removal with a signer for every existing token (#343).
use super::LocalKVStore;
use crate::kvstore::token_spends::{complete_token_action, SigningProtocol};
use crate::kvstore::types::{encode_value_with_ttl, LookupValueResult};
use crate::kvstore::{KVStoreRemoveOptions, KVStoreSetOptions};
use crate::primitives::to_hex;
use crate::script::LockingScript;
use crate::wallet::{Counterparty, CreateActionArgs, CreateActionOutput, WalletInterface};
use crate::{Error, Result};

impl<W: WalletInterface + std::fmt::Debug> LocalKVStore<W> {
    pub(super) async fn set_internal(
        &self,
        key: &str,
        value: &str,
        _protocol_id: &str,
        options: &KVStoreSetOptions,
    ) -> Result<String> {
        let stored = options.ttl.map_or_else(
            || value.to_string(),
            |ttl| encode_value_with_ttl(value, ttl),
        );
        let current = self.lookup_value(key, 10).await?;
        if current.value_exists && current.value == stored && current.outpoints.len() == 1 {
            if let Some(outpoint) = current.outpoints.last() {
                return Ok(outpoint.clone());
            }
        }
        let bytes = if self.config.encrypt {
            self.encrypt_value(key, stored.as_bytes()).await?
        } else {
            stored.into_bytes()
        };
        let lock = self.create_locking_script(key, &bytes).await?;
        self.replace_outputs(key, options, &current, lock).await
    }

    async fn replace_outputs(
        &self,
        key: &str,
        options: &KVStoreSetOptions,
        current: &LookupValueResult,
        lock: LockingScript,
    ) -> Result<String> {
        let inputs = self.build_inputs(current)?;
        let result = complete_token_action(
            &self.wallet,
            CreateActionArgs {
                description: options
                    .description
                    .clone()
                    .unwrap_or_else(|| format!("Update {key} in {}", self.config.protocol_id)),
                inputs: (!inputs.is_empty()).then_some(inputs),
                input_beef: current.input_beef.clone(),
                outputs: Some(vec![CreateActionOutput {
                    locking_script: lock.to_binary(),
                    satoshis: options.token_amount.unwrap_or(self.config.token_amount),
                    output_description: format!("KV entry: {key}"),
                    basket: Some(self.config.protocol_id.clone()),
                    custom_instructions: None,
                    tags: Some(options.tags.clone().unwrap_or_else(|| vec![key.into()])),
                }]),
                lock_time: None,
                version: None,
                labels: None,
                options: Some(self.action_options.for_action(false, false)),
            },
            self.signing_protocol(key),
            self.originator(),
        )
        .await?;
        result
            .txid
            .map(|id| format!("{}.0", to_hex(&id)))
            .ok_or_else(|| Error::KvStoreError("No txid in result".into()))
    }

    pub(super) async fn remove_internal(
        &self,
        key: &str,
        options: &KVStoreRemoveOptions,
    ) -> Result<Vec<String>> {
        let mut txids = Vec::new();
        loop {
            let current = self.lookup_value(key, 100).await?;
            if !current.value_exists || current.outputs.is_empty() {
                break;
            }
            let inputs = self.build_inputs(&current)?;
            if inputs.is_empty() {
                break;
            }
            let result = complete_token_action(
                &self.wallet,
                CreateActionArgs {
                    description: options.description.clone().unwrap_or_else(|| {
                        format!("Remove {key} from {}", self.config.protocol_id)
                    }),
                    inputs: Some(inputs),
                    input_beef: current.input_beef,
                    outputs: None,
                    lock_time: None,
                    version: None,
                    labels: None,
                    options: Some(self.action_options.for_action(false, true)),
                },
                self.signing_protocol(key),
                self.originator(),
            )
            .await?;
            if let Some(txid) = result.txid {
                txids.push(to_hex(&txid));
            }
            if current.outputs.len() < 100 {
                break;
            }
        }
        Ok(txids)
    }

    fn signing_protocol(&self, key: &str) -> SigningProtocol {
        SigningProtocol {
            protocol: self.get_protocol(key),
            key_id: key.into(),
            counterparty: Counterparty::Self_,
        }
    }
}
