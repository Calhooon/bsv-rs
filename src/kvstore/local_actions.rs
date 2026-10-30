//! Local replacement/removal with a signer for every existing token (#343).
use super::lookup::{LookupValueResult, MAX_LOCAL_OUTPUTS};
use super::LocalKVStore;
use crate::kvstore::token_spends::{complete_token_action, SigningProtocol};
use crate::kvstore::types::encode_value_with_ttl;
use crate::kvstore::{KVStoreRemoveOptions, KVStoreSetOptions};
use crate::primitives::to_hex;
use crate::script::LockingScript;
use crate::wallet::{Counterparty, CreateActionArgs, CreateActionOutput, WalletInterface};
use crate::{Error, Result};

/// Policy (#483): cap removal at two rounds (one listed page spent per round).
/// The reference keeps one current token per key; a second round covers a token
/// written during the first. One token per page under a larger total is inconsistent
/// and must not expose a key to 10,000 spends. Beneath the cap, totals must shrink.
/// The reference has no bound (LocalKVStore.ts:574-590 at edf6e03).
/// Change this policy only with a measurement, never silently.
const MAX_LOCAL_REMOVE_ROUNDS: usize = 2;

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
        let current = self.lookup_current(key, MAX_LOCAL_OUTPUTS, true).await?;
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
        self.replace_outputs(key, options, &current, lock)
            .await
            .map_err(|error| unlock_error(current.outputs.len() as u32, key, error))
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
                    output_description: "Key-value token".into(),
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
        super::outpoint::token_outpoint(&result, &lock)
    }

    pub(super) async fn remove_internal(
        &self,
        key: &str,
        options: &KVStoreRemoveOptions,
    ) -> Result<Vec<String>> {
        let mut txids = Vec::new();
        let mut consumed = std::collections::HashSet::new();
        let mut rounds_completed = 0;
        let mut first_total = 0;
        let mut previous_total = u32::MAX;
        loop {
            let listed = self.get_outputs(key, MAX_LOCAL_OUTPUTS).await?;
            let count = listed.outputs.len();
            // Each batch requests offset zero after spending the previous page.
            // Unlike the reference loop, refuse a page that cannot make progress (#479).
            if count == 0 && listed.total_outputs > 0 {
                return Err(super::lookup::refused(format!(
                    "Wallet returned an inconsistent KVStore output list: totalOutputs is {}, but page at offset 0 is empty for key {key}",
                    listed.total_outputs
                )));
            }
            if rounds_completed >= MAX_LOCAL_REMOVE_ROUNDS && count > 0 {
                return Err(super::lookup::refused(format!(
                    "Wallet returned an inconsistent KVStore output list: after {rounds_completed} removal rounds, first totalOutputs was {first_total}, previous totalOutputs was {previous_total} and current totalOutputs is {} for key {key}",
                    listed.total_outputs
                )));
            }
            if rounds_completed > 0 && listed.total_outputs >= previous_total {
                return Err(super::lookup::refused(format!(
                    "Wallet returned an inconsistent KVStore output list: after {rounds_completed} removal round, previous totalOutputs was {previous_total} and current totalOutputs is {} for key {key}",
                    listed.total_outputs
                )));
            }
            if rounds_completed == 0 {
                first_total = listed.total_outputs;
            }
            previous_total = listed.total_outputs;
            if count > 0 {
                let outputs = self.authenticate_outputs(key, &listed).await?;
                for output in &outputs {
                    if !consumed.insert(output.outpoint.clone()) {
                        return Err(super::lookup::refused(
                            "Wallet repeated a KVStore output after it was removed",
                        ));
                    }
                }
                let result = self
                    .remove_outputs(key, options, outputs, listed.beef)
                    .await
                    .map_err(|error| unlock_error(listed.total_outputs, key, error))?;
                if let Some(txid) = result.txid {
                    txids.push(to_hex(&txid));
                }
                rounds_completed += 1;
            }
            if count == listed.total_outputs as usize {
                break;
            }
        }
        Ok(txids)
    }

    async fn remove_outputs(
        &self,
        key: &str,
        options: &KVStoreRemoveOptions,
        outputs: Vec<super::lookup::WalletOutput>,
        input_beef: Option<Vec<u8>>,
    ) -> Result<crate::wallet::CreateActionResult> {
        let inputs = crate::kvstore::token_spends::inputs(
            outputs.into_iter().map(|output| output.outpoint),
            "Previous key-value token",
        )?;
        complete_token_action(
            &self.wallet,
            CreateActionArgs {
                description: options
                    .description
                    .clone()
                    .unwrap_or_else(|| format!("Remove {key} in {}", self.config.protocol_id)),
                inputs: Some(inputs),
                input_beef,
                outputs: None,
                lock_time: None,
                version: None,
                labels: None,
                options: Some(self.action_options.for_action(false, true)),
            },
            self.signing_protocol(key),
            self.originator(),
        )
        .await
    }

    fn signing_protocol(&self, key: &str) -> SigningProtocol {
        SigningProtocol {
            protocol: self.get_protocol(key),
            key_id: key.into(),
            counterparty: Counterparty::Self_,
        }
    }
}

fn unlock_error(total: u32, key: &str, error: Error) -> Error {
    super::lookup::refused(format!(
        "There are {total} outputs with tag {key} that cannot be unlocked. Original error: {}",
        super::lookup::original_error_message(&error)
    ))
}
