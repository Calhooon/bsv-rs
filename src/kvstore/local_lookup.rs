//! Local output enumeration and authentication (TS LocalKVStore.ts:173-370).
use super::parser_words::{decode_pushdrop, parse_public_key};
use super::LocalKVStore;
use crate::script::templates::{LockPosition, PushDrop};
use crate::script::LockingScript;
use crate::transaction::{Beef, TransactionOutput};
use crate::wallet::{
    Counterparty, GetPublicKeyArgs, ListOutputsArgs, ListOutputsResult, OutputInclude, QueryMode,
    VerifySignatureArgs, WalletInterface,
};
use crate::{Error, Result};
use std::collections::HashSet;

pub(super) const MAX_LOCAL_OUTPUTS: u32 = 10_000;
const MAX_LOCAL_TOKEN_BYTES: usize = 2 * 1024 * 1024;
const MAX_LOCAL_BEEF_BYTES: usize = 256 * 1024 * 1024;

/// Private lookup state, including the wallet's total for removal batches.
#[derive(Debug, Clone)]
pub(crate) struct LookupValueResult {
    pub value: String,
    pub outpoints: Vec<String>,
    pub input_beef: Option<Vec<u8>>,
    pub outputs: Vec<WalletOutput>,
    pub value_exists: bool,
    pub total_outputs: u32,
}

impl LookupValueResult {
    pub(crate) fn not_found(value: String) -> Self {
        Self {
            value,
            outpoints: Vec::new(),
            input_beef: None,
            outputs: Vec::new(),
            value_exists: false,
            total_outputs: 0,
        }
    }

    pub(crate) fn found(
        value: String,
        outpoints: Vec<String>,
        input_beef: Option<Vec<u8>>,
        outputs: Vec<WalletOutput>,
    ) -> Self {
        Self {
            total_outputs: outputs.len() as u32,
            value,
            outpoints,
            input_beef,
            outputs,
            value_exists: true,
        }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct WalletOutput {
    pub outpoint: String,
    pub satoshis: u64,
    pub locking_script: Vec<u8>,
    pub tags: Vec<String>,
}

pub(super) fn refused(message: impl Into<String>) -> Error {
    Error::KvStoreLocalError(message.into())
}

impl<W: WalletInterface + std::fmt::Debug> LocalKVStore<W> {
    pub(super) async fn get_outputs(&self, key: &str, limit: u32) -> Result<ListOutputsResult> {
        let result = self
            .wallet
            .list_outputs(
                ListOutputsArgs {
                    basket: self.config.protocol_id.clone(),
                    tags: Some(vec![key.into()]),
                    tag_query_mode: Some(QueryMode::All),
                    include: Some(OutputInclude::EntireTransactions),
                    limit: Some(limit),
                    include_custom_instructions: None,
                    include_tags: None,
                    include_labels: None,
                    offset: None,
                    seek_permission: None,
                },
                self.originator(),
            )
            .await?;
        if result.total_outputs < result.outputs.len() as u32
            || result.total_outputs > MAX_LOCAL_OUTPUTS
            || result.outputs.len() > MAX_LOCAL_OUTPUTS as usize
        {
            return Err(refused("Wallet returned an invalid KVStore output list"));
        }
        if !result.outputs.is_empty() {
            beef_bytes(&result)?;
        }
        Ok(result)
    }

    pub(super) async fn lookup_value(&self, key: &str, limit: u32) -> Result<LookupValueResult> {
        self.lookup_current(key, limit, false).await
    }

    pub(super) async fn lookup_current(
        &self,
        key: &str,
        limit: u32,
        allow_multiple: bool,
    ) -> Result<LookupValueResult> {
        let listed = self
            .get_outputs(key, limit)
            .await
            .map_err(|e| self.invalid_value(e))?;
        if listed.outputs.is_empty() {
            let mut empty = LookupValueResult::not_found(String::new());
            empty.input_beef = listed.beef;
            empty.total_outputs = listed.total_outputs;
            return Ok(empty);
        }
        if !allow_multiple && (listed.outputs.len() != 1 || listed.total_outputs != 1) {
            return Err(refused("Multiple KVStore outputs make the current value ambiguous; call set to collapse them"));
        }
        if allow_multiple && listed.outputs.len() != listed.total_outputs as usize {
            return Err(refused(
                "Wallet did not return every KVStore output needed for an atomic collapse",
            ));
        }
        let outputs = self
            .authenticate_outputs(key, &listed)
            .await
            .map_err(|e| self.invalid_value(e))?;
        let selected = outputs
            .last()
            .ok_or_else(|| refused("Wallet returned an invalid KVStore output list"))?;
        let token = decode_pushdrop(&LockingScript::from_binary(&selected.locking_script)?)?;
        let value = if self.config.encrypt {
            self.decrypt_value(key, &token.fields[0]).await?
        } else {
            token.fields[0].clone()
        };
        if self.config.encrypt && (value.is_empty() || value.len() > MAX_LOCAL_TOKEN_BYTES) {
            return Err(refused("Wallet KVStore plaintext is invalid"));
        }
        let value = String::from_utf8(value)
            .map_err(|_| refused("The encoded data was not valid for encoding utf-8"))?;
        if value.is_empty() || value.len() > 1024 * 1024 {
            return Err(refused("KVStore value has an invalid length"));
        }
        let outpoints = outputs.iter().map(|o| o.outpoint.clone()).collect();
        let mut result = LookupValueResult::found(value, outpoints, listed.beef, outputs);
        result.total_outputs = listed.total_outputs;
        Ok(result)
    }

    pub(super) async fn authenticate_outputs(
        &self,
        key: &str,
        listed: &ListOutputsResult,
    ) -> Result<Vec<WalletOutput>> {
        if listed.outputs.is_empty() {
            return Ok(Vec::new());
        }
        let beef = Beef::from_binary(beef_bytes(listed)?)?;
        let public_key = self
            .wallet
            .get_public_key(
                GetPublicKeyArgs {
                    protocol_id: Some(self.get_protocol(key)),
                    key_id: Some(key.into()),
                    counterparty: Some(Counterparty::Self_),
                    ..Default::default()
                },
                self.originator(),
            )
            .await?;
        let expected = parse_public_key(&public_key.public_key)?;
        let mut seen = HashSet::new();
        let mut outputs = Vec::with_capacity(listed.outputs.len());
        for output in &listed.outputs {
            let outpoint = output.outpoint.to_string();
            if !seen.insert(outpoint.clone()) {
                return Err(refused("Wallet returned a duplicate KVStore output"));
            }
            let source = source_output(&beef, output)?;
            let token = decode_token(&source.locking_script)?;
            if token.locking_public_key != expected {
                return Err(refused(
                    "KVStore token locking key does not belong to the wallet",
                ));
            }
            self.verify_token(key, &token).await?;
            outputs.push(WalletOutput {
                outpoint,
                satoshis: output.satoshis,
                locking_script: source.locking_script.to_binary(),
                tags: output.tags.clone().unwrap_or_default(),
            });
        }
        Ok(outputs)
    }

    async fn verify_token(&self, key: &str, token: &PushDrop) -> Result<()> {
        let verified = self
            .wallet
            .verify_signature(
                VerifySignatureArgs {
                    data: Some(token.fields[0].clone()),
                    signature: token.fields[1].clone(),
                    protocol_id: self.get_protocol(key),
                    key_id: key.into(),
                    counterparty: Some(Counterparty::Self_),
                    ..Default::default()
                },
                self.originator(),
            )
            .await?;
        if !verified.valid {
            return Err(refused("KVStore token signature is invalid"));
        }
        Ok(())
    }

    fn invalid_value(&self, error: Error) -> Error {
        refused(format!("Invalid value found. Relinquish the corrupted output from the {} basket before using this key again. Original error: {}", self.config.protocol_id, original_error_message(&error)))
    }
}

fn beef_bytes(result: &ListOutputsResult) -> Result<&[u8]> {
    result
        .beef
        .as_deref()
        .filter(|b| !b.is_empty() && b.len() <= MAX_LOCAL_BEEF_BYTES)
        .ok_or_else(|| refused("Wallet KVStore BEEF is invalid"))
}

fn source_output<'a>(
    beef: &'a Beef,
    output: &crate::wallet::WalletOutput,
) -> Result<&'a TransactionOutput> {
    if !output.spendable || output.satoshis > 2_100_000_000_000_000 {
        return Err(refused("Wallet returned invalid KVStore output metadata"));
    }
    let txid = crate::primitives::to_hex(&output.outpoint.txid);
    let tx = beef
        .find_txid(&txid)
        .and_then(|entry| entry.tx())
        .filter(|tx| tx.id() == txid)
        .ok_or_else(|| refused("KVStore BEEF does not contain the exact listed transaction"))?;
    tx.outputs
        .get(output.outpoint.vout as usize)
        .filter(|source| {
            source.satoshis == Some(output.satoshis)
                && output
                    .locking_script
                    .as_ref()
                    .is_none_or(|script| *script == source.locking_script.to_binary())
        })
        .ok_or_else(|| refused("KVStore BEEF does not match the listed output"))
}

fn decode_token(script: &LockingScript) -> Result<PushDrop> {
    // Lock-before alone, as LocalKVStore.ts:278-282 decodes it (#499).
    let token = decode_pushdrop(script)?;
    if token.fields.len() != 2 {
        return Err(refused("Unexpected PushDrop token field count"));
    }
    let mut total = 0;
    for field in &token.fields {
        if field.len() > MAX_LOCAL_TOKEN_BYTES {
            return Err(refused("PushDrop token contains an oversized field"));
        }
        total += field.len();
        if total > MAX_LOCAL_TOKEN_BYTES + 1024 {
            return Err(refused("PushDrop token payload is too large"));
        }
    }
    if token
        .clone()
        .with_position(LockPosition::Before)
        .lock()
        .to_binary()
        != script.to_binary()
    {
        return Err(refused(
            "PushDrop token must use the canonical PushDrop envelope",
        ));
    }
    Ok(token)
}

// Local catches use Error.message, not these variants' display categories.
// Read payloads directly: their own text may legitimately start with a prefix.
pub(super) fn original_error_message(error: &Error) -> String {
    match error {
        Error::WalletError(text)
        | Error::KvStoreError(text)
        | Error::KvStoreLocalError(text)
        | Error::BeefError(text)
        | Error::TransactionError(text) => text.clone(),
        Error::WalletFault(fault) => fault.message.clone(),
        _ => error.to_string(),
    }
}
