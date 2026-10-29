//! Global token replacement/removal, sharing the bound-action checks (#343).
use super::GlobalKVStore;
use crate::kvstore::token_spends::{complete_token_action, inputs, merge_beef, SigningProtocol};
use crate::kvstore::{
    KVStoreGetOptions, KVStoreQuery, KVStoreRemoveOptions, KVStoreSetOptions, KVStoreToken,
};
use crate::overlay::{with_wallet_double_spend_retry, LookupQuestion};
use crate::primitives::{from_hex, to_hex, PublicKey};
use crate::script::{templates::PushDrop, LockingScript};
use crate::wallet::{
    Counterparty, CreateActionArgs, CreateActionOutput, CreateActionResult, CreateSignatureArgs,
    GetPublicKeyArgs, Protocol, SecurityLevel, WalletInterface,
};
use crate::{Error, Result};

impl<W: WalletInterface> GlobalKVStore<W> {
    pub(super) async fn set_internal(
        &self,
        key: &str,
        value: &str,
        controller: &str,
        protocol_id: &str,
        options: &KVStoreSetOptions,
    ) -> Result<String> {
        let locking_script = self
            .token_lock(key, value, controller, protocol_id, options)
            .await?;
        with_wallet_double_spend_retry(
            || self.set_tokens(key, controller, protocol_id, options, &locking_script),
            || self.topic_broadcaster(),
            Error::KvStoreError,
        )
        .await
    }

    async fn set_tokens(
        &self,
        key: &str,
        controller: &str,
        protocol_id: &str,
        options: &KVStoreSetOptions,
        locking_script: &LockingScript,
    ) -> Result<String> {
        let tokens = self.current_tokens(key, controller, protocol_id).await?;
        let inputs = inputs(
            tokens.iter().map(KVStoreToken::outpoint_string),
            "Previous KVStore token",
        )?;
        let input_beef = token_beef(&tokens)?;
        let args = CreateActionArgs {
            description: options
                .description
                .clone()
                .unwrap_or_else(|| format!("Set {key} in kvstore")),
            inputs: (!inputs.is_empty()).then_some(inputs),
            input_beef,
            outputs: Some(vec![CreateActionOutput {
                locking_script: locking_script.to_binary(),
                satoshis: options.token_amount.unwrap_or(self.config.token_amount),
                output_description: format!("KV token: {key}"),
                basket: None,
                custom_instructions: None,
                tags: Some(vec![key.to_string()]),
            }]),
            lock_time: None,
            version: None,
            labels: Some(self.config.topics.clone()),
            options: Some(self.action_options.for_action(true, false)),
        };
        let result = complete_token_action(
            &self.wallet,
            args,
            signing_protocol(protocol_id, key),
            self.originator(),
        )
        .await?;
        Ok(format!("{}.0", self.finish_action(result).await?))
    }

    pub(super) async fn remove_internal(
        &self,
        key: &str,
        controller: &str,
        options: &KVStoreRemoveOptions,
    ) -> Result<String> {
        let protocol_id = options
            .protocol_id
            .as_deref()
            .unwrap_or(&self.config.protocol_id);
        let tokens = self.current_tokens(key, controller, protocol_id).await?;
        if tokens.is_empty() {
            return Err(Error::KvStoreKeyNotFound(key.into()));
        }
        let args = CreateActionArgs {
            description: options
                .description
                .clone()
                .unwrap_or_else(|| format!("Remove {key} from kvstore")),
            inputs: Some(inputs(
                tokens.iter().map(KVStoreToken::outpoint_string),
                "KVStore token to remove",
            )?),
            input_beef: token_beef(&tokens)?,
            outputs: None,
            lock_time: None,
            version: None,
            labels: Some(self.config.topics.clone()),
            options: Some(self.action_options.for_action(true, true)),
        };
        let result = complete_token_action(
            &self.wallet,
            args,
            signing_protocol(protocol_id, key),
            self.originator(),
        )
        .await?;
        self.finish_action(result).await
    }

    async fn current_tokens(
        &self,
        key: &str,
        controller: &str,
        protocol_id: &str,
    ) -> Result<Vec<KVStoreToken>> {
        let query = KVStoreQuery::new()
            .with_key(key)
            .with_controller(controller)
            .with_protocol_id(protocol_id);
        let entries = self
            .query_overlay(
                &query,
                &self.config.service_name,
                &KVStoreGetOptions::new().with_include_token(true),
            )
            .await?;
        let namespace = serde_json::to_string(&(SecurityLevel::App.as_u8(), protocol_id))
            .map_err(|error| Error::KvStoreError(error.to_string()))?;
        Ok(entries
            .into_iter()
            .filter(|entry| entry.controller == controller && entry.protocol_id == namespace)
            .filter_map(|entry| entry.token)
            .collect())
    }

    async fn token_lock(
        &self,
        key: &str,
        value: &str,
        controller: &str,
        protocol_id: &str,
        options: &KVStoreSetOptions,
    ) -> Result<LockingScript> {
        let signing = signing_protocol(protocol_id, key);
        let mut fields = vec![
            serde_json::to_vec(&(SecurityLevel::App.as_u8(), protocol_id))
                .map_err(|e| Error::KvStoreError(e.to_string()))?,
            key.as_bytes().to_vec(),
            value.as_bytes().to_vec(),
            from_hex(controller)?,
        ];
        if let Some(tags) = options.tags.as_ref().filter(|tags| !tags.is_empty()) {
            fields.push(serde_json::to_vec(tags).map_err(|e| Error::KvStoreError(e.to_string()))?);
        }
        let signed = self
            .wallet
            .create_signature(
                CreateSignatureArgs {
                    data: Some(fields.concat()),
                    protocol_id: signing.protocol.clone(),
                    key_id: key.into(),
                    counterparty: Some(Counterparty::Anyone),
                    ..Default::default()
                },
                self.originator(),
            )
            .await?;
        fields.push(signed.signature);
        let public_key = self
            .wallet
            .get_public_key(
                GetPublicKeyArgs {
                    protocol_id: Some(signing.protocol),
                    key_id: Some(key.into()),
                    counterparty: Some(Counterparty::Anyone),
                    for_self: Some(true),
                    ..Default::default()
                },
                self.originator(),
            )
            .await?;
        Ok(PushDrop::new(PublicKey::from_hex(&public_key.public_key)?, fields).lock())
    }

    async fn finish_action(&self, result: CreateActionResult) -> Result<String> {
        if let Some(bytes) = result.tx {
            self.broadcast_to_overlay(&bytes).await?;
        }
        result
            .txid
            .map(|id| to_hex(&id))
            .ok_or_else(|| Error::KvStoreError("No txid in result".into()))
    }
}

pub(super) fn lookup_question(service: &str, query: &KVStoreQuery) -> LookupQuestion {
    let mut value = query.to_json();
    if let Some(protocol_id) = &query.protocol_id {
        if let Some(fields) = value.as_object_mut() {
            fields.remove("protocolId");
            fields.insert("protocolID".into(), serde_json::json!([1, protocol_id]));
        }
    }
    LookupQuestion::new(service, value)
}

fn signing_protocol(protocol_id: &str, key: &str) -> SigningProtocol {
    SigningProtocol {
        protocol: Protocol::new(SecurityLevel::App, protocol_id),
        key_id: key.into(),
        counterparty: Counterparty::Anyone,
    }
}

fn token_beef(tokens: &[KVStoreToken]) -> Result<Option<Vec<u8>>> {
    if tokens.is_empty() {
        return Ok(None);
    }
    let beefs: Result<Vec<_>> = tokens
        .iter()
        .map(|token| {
            token
                .beef
                .as_deref()
                .ok_or_else(|| Error::KvStoreError("Token data not available".into()))
        })
        .collect();
    merge_beef(beefs?).map(Some)
}
