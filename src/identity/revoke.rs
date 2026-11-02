//! [`IdentityClient::revoke_certificate_revelation`], the reference's
//! `revokeCertificateRevelation` step by step and in its words
//! (`ts-stack@edf6e03` `packages/sdk/src/identity/IdentityClient.ts:705-950`;
//! #327): the serial number read as base64 of 32 bytes; the identity key
//! and the revelation token's locking key; the `ls_identity` lookup, its
//! answer bounded; each output's token decoded and authenticated (the
//! canonical signed PushDrop, the locking key, the subject and the serial
//! number, the certificate's signature, the token's signature by the
//! wallet), a malformed or unauthenticated output skipped; then each
//! authenticated output spent at its own index, the spend wrapped in the
//! reference's double-spend retry ([`crate::overlay::wallet_retry`]), a failure after
//! createAction aborting the action.
//!
//! [`IdentityClient::revoke_certificate_revelation`]: super::IdentityClient::revoke_certificate_revelation

use super::types::IdentityClientConfig;
use crate::auth::certificates::Certificate;
use crate::overlay::{
    with_wallet_double_spend_retry, LookupAnswer, LookupQuestion, LookupResolver, OutputListItem,
    OverlayBroadcastFacilitator, TopicBroadcaster, TopicBroadcasterConfig,
};
use crate::primitives::bsv::sighash::{
    parse_transaction, SighashParams, SIGHASH_ALL, SIGHASH_FORKID,
};
use crate::primitives::{to_base64, to_hex};
use crate::script::templates::PushDrop;
use crate::transaction::{Transaction, TransactionOutput};
use crate::wallet::{
    AbortActionArgs, Counterparty, CreateActionArgs, CreateActionInput, CreateActionOptions,
    GetPublicKeyArgs, Outpoint, Protocol, SignActionArgs, SignActionOptions, SignActionSpend,
    SignableTransaction, VerifySignatureArgs, WalletInterface,
};
use crate::{Error, Result};
use std::collections::HashMap;
use std::sync::Arc;

/// The most outputs a lookup answer may carry (`MAX_IDENTITY_RESULTS`,
/// `IdentityClient.ts:40`).
const MAX_IDENTITY_RESULTS: usize = 10000;

/// The most BEEF bytes across a lookup answer's outputs
/// (`MAX_IDENTITY_LOOKUP_BEEF_BYTES`, `IdentityClient.ts:41`).
const MAX_IDENTITY_LOOKUP_BEEF_BYTES: usize = 16 * 1024 * 1024;

fn refused(words: impl Into<String>) -> Error {
    Error::IdentityError(words.into())
}

/// What the revocation reads of its client.
pub(super) struct Revocation<'a, W: ?Sized> {
    pub wallet: &'a W,
    pub originator: Option<&'a str>,
    pub config: &'a IdentityClientConfig,
    pub resolver: &'a LookupResolver,
    pub facilitator: Option<Arc<dyn OverlayBroadcastFacilitator>>,
}

/// An authenticated output: its BEEF as the lookup answered it, its index,
/// the BEEF's subject and its txid (`IdentityClient.ts:762-767`, `:817-822`).
struct Revelation {
    beef: Vec<u8>,
    output_index: u32,
    tx: Transaction,
    txid: String,
}

impl<W: WalletInterface + ?Sized> Revocation<'_, W> {
    /// `revokeCertificateRevelation` (`IdentityClient.ts:711-950`): the
    /// broadcaster `tm_identity`'s on the client's network (`:832-835`), each
    /// authenticated output spent in turn under the retry (`:837-948`).
    pub(super) async fn run(&self, serial_number: &str) -> Result<()> {
        let serial_number = super::reveal::base64_parameter(serial_number, "serialNumber", 32, 32)?;
        let (identity_key, locking_key) = self.keys().await?;
        let outputs = self.lookup(&serial_number).await?;
        let mut revelations = Vec::new();
        for output in &outputs {
            if let Some(revelation) = self
                .authenticated(output, &serial_number, &identity_key, &locking_key)
                .await
            {
                revelations.push(revelation);
            }
        }
        if revelations.is_empty() {
            return Err(refused(
                "No authenticated revelation output matches the requested certificate.",
            ));
        }
        let broadcaster = Arc::new(TopicBroadcaster::new(
            vec!["tm_identity".to_string()],
            TopicBroadcasterConfig {
                network_preset: self.config.network_preset,
                facilitator: self.facilitator.clone(),
                ..Default::default()
            },
        )?);
        for revelation in &revelations {
            with_wallet_double_spend_retry(
                || self.spend(revelation, &broadcaster),
                || Ok(broadcaster.clone()),
                Error::IdentityError,
            )
            .await?;
        }
        Ok(())
    }

    fn protocol(&self) -> Result<Protocol> {
        let (level, name) = (self.config.protocol_id.0, &self.config.protocol_id.1);
        Protocol::from_tuple((level, name))
            .ok_or_else(|| refused(format!("Invalid protocol ID: ({level}, {name})")))
    }

    /// The identity key, then the token's locking key: the client's protocol
    /// and key ID, counterparty `anyone`, `forSelf: true` (`:718-730`).
    async fn keys(&self) -> Result<(String, String)> {
        let identity_key = self
            .wallet
            .get_public_key(
                GetPublicKeyArgs {
                    identity_key: true,
                    ..Default::default()
                },
                self.originator,
            )
            .await?
            .public_key;
        let locking_key = self
            .wallet
            .get_public_key(
                GetPublicKeyArgs {
                    protocol_id: Some(self.protocol()?),
                    key_id: Some(self.config.key_id.clone()),
                    counterparty: Some(Counterparty::Anyone),
                    for_self: Some(true),
                    ..Default::default()
                },
                self.originator,
            )
            .await?
            .public_key;
        Ok((identity_key, locking_key))
    }

    /// The `ls_identity` lookup by serial number and the reference's bounds
    /// on its answer (`:732-758`): an output list of 1 to 10000 outputs and
    /// at most 16 MiB of BEEF across them.
    async fn lookup(&self, serial_number: &str) -> Result<Vec<OutputListItem>> {
        let question = LookupQuestion::new(
            "ls_identity",
            serde_json::json!({ "serialNumber": serial_number }),
        );
        let outputs = match self.resolver.query(&question, None).await? {
            LookupAnswer::OutputList { outputs } if !outputs.is_empty() => outputs,
            _ => return Err(refused("Failed to get lookup result")),
        };
        if outputs.len() > MAX_IDENTITY_RESULTS {
            return Err(refused(format!(
                "Identity revelation lookup exceeded {MAX_IDENTITY_RESULTS} results"
            )));
        }
        let mut beef_bytes = 0usize;
        for output in &outputs {
            beef_bytes = beef_bytes.saturating_add(output.beef.len());
            if beef_bytes > MAX_IDENTITY_LOOKUP_BEEF_BYTES {
                return Err(refused(format!(
                    "Identity revelation lookup exceeded {MAX_IDENTITY_LOOKUP_BEEF_BYTES} BEEF bytes"
                )));
            }
        }
        Ok(outputs)
    }

    /// One output, authenticated as the reference authenticates it
    /// (`:768-825`), or `None` where the reference's `continue` or `catch`
    /// skips it: the BEEF's subject, its output at the lookup's index, a
    /// canonical signed PushDrop of two fields locked to the revelation
    /// key, the certificate JSON naming the serial number and the identity
    /// key as subject, the certificate's signature, then the token's
    /// signature verified by the wallet.
    async fn authenticated(
        &self,
        output: &OutputListItem,
        serial_number: &str,
        identity_key: &str,
        locking_key: &str,
    ) -> Option<Revelation> {
        let tx = Transaction::from_beef(&output.beef, None).ok()?;
        let source = tx.outputs.get(output.output_index as usize)?;
        let token = PushDrop::decode_before(&source.locking_script).ok()?;
        if token.fields.len() != 2
            || !super::token_envelope::is_canonical_signed_pushdrop(
                &source.locking_script,
                &token.fields,
            )
        {
            return None;
        }
        if token.locking_public_key.to_hex() != locking_key {
            return None;
        }
        let text = std::str::from_utf8(&token.fields[0]).ok()?;
        let parsed: serde_json::Value = serde_json::from_str(text).ok()?;
        let parsed = parsed.as_object()?;
        if parsed.get("serialNumber").and_then(|v| v.as_str()) != Some(serial_number)
            || parsed.get("subject").and_then(|v| v.as_str()) != Some(identity_key)
        {
            return None;
        }
        if !certificate_verifies(parsed) {
            return None;
        }
        let verdict = self
            .wallet
            .verify_signature(
                VerifySignatureArgs {
                    data: Some(token.fields[0].clone()),
                    signature: token.fields[1].clone(),
                    protocol_id: self.protocol().ok()?,
                    key_id: self.config.key_id.clone(),
                    counterparty: Some(Counterparty::Anyone),
                    for_self: Some(true),
                    ..Default::default()
                },
                self.originator,
            )
            .await;
        if !matches!(verdict, Ok(result) if result.valid) {
            return None;
        }
        let txid = tx.id();
        Some(Revelation {
            beef: output.beef.clone(),
            output_index: output.output_index,
            tx,
            txid,
        })
    }

    /// One attempt at spending `revelation` (`:837-947`, the operation the
    /// retry repeats): createAction, then the signing and broadcast, the
    /// action aborted when either fails and the failure kept, whatever the
    /// abort answers (`:940-946`).
    async fn spend(&self, revelation: &Revelation, broadcaster: &TopicBroadcaster) -> Result<()> {
        let source = revelation
            .tx
            .outputs
            .get(revelation.output_index as usize)
            .filter(|o| o.satoshis.is_some())
            .ok_or_else(|| refused("Failed to get the revelation source output."))?;
        let outpoint = format!("{}.{}", revelation.txid, revelation.output_index);
        let signable = self.create_action(revelation, &outpoint).await?;
        let reference = to_base64(&signable.reference);
        let done = self
            .sign_and_broadcast(&signable, &reference, source, &outpoint, broadcaster)
            .await;
        if done.is_err() {
            let _ = self
                .wallet
                .abort_action(AbortActionArgs { reference }, self.originator)
                .await;
        }
        done
    }

    /// The reference's createAction (`:845-867`, #318).
    async fn create_action(
        &self,
        revelation: &Revelation,
        outpoint: &str,
    ) -> Result<SignableTransaction> {
        let result = self
            .wallet
            .create_action(
                CreateActionArgs {
                    description: "Spend certificate revelation token".to_string(),
                    input_beef: Some(revelation.beef.clone()),
                    inputs: Some(vec![CreateActionInput {
                        outpoint: Outpoint::from_string(outpoint)?,
                        input_description: "Revelation token".to_string(),
                        unlocking_script: None,
                        unlocking_script_length: Some(74),
                        sequence_number: None,
                    }]),
                    outputs: None,
                    lock_time: None,
                    version: None,
                    labels: None,
                    options: Some(CreateActionOptions {
                        randomize_outputs: Some(false),
                        accept_delayed_broadcast: Some(false),
                        no_send: Some(true),
                        ..Default::default()
                    }),
                },
                self.originator,
            )
            .await?;
        result
            .signable_transaction
            .ok_or_else(|| refused("Failed to create signable transaction"))
    }

    /// The signing and broadcast inside the reference's `try` (`:870-939`):
    /// the one input of the signable transaction that spends the outpoint,
    /// the PushDrop unlocking script for it, signAction, the signed
    /// transaction checked against the signable one, then the broadcast.
    async fn sign_and_broadcast(
        &self,
        signable: &SignableTransaction,
        reference: &str,
        source: &TransactionOutput,
        outpoint: &str,
        broadcaster: &TopicBroadcaster,
    ) -> Result<()> {
        let partial = Transaction::from_atomic_beef(&signable.tx)?;
        let outpoint = outpoint.to_lowercase();
        let mut matching = Vec::new();
        for index in 0..partial.inputs.len() {
            if input_outpoint(&partial, index)? == outpoint {
                matching.push(index);
            }
        }
        let [input_index] = matching[..] else {
            return Err(refused(
                "Wallet signable transaction does not contain the requested revelation input.",
            ));
        };
        let unlocking_script = self.unlocking_script(&partial, input_index, source).await?;
        let unlocking_hex = to_hex(&unlocking_script);
        let signed = self
            .sign_action(reference, input_index, unlocking_script)
            .await?;
        let signed_tx = Transaction::from_atomic_beef(&signed.0)?;
        check_signed(&partial, &signed_tx, input_index, &outpoint, &unlocking_hex)?;
        if signed
            .1
            .is_some_and(|txid| txid.to_lowercase() != signed_tx.id())
        {
            return Err(refused(
                "Signed revelation transaction ID does not match its transaction data.",
            ));
        }
        broadcaster.broadcast_tx(&signed_tx).await.map_err(|f| {
            refused(format!(
                "Failed to broadcast certificate revelation revocation: {}: {}",
                f.code, f.description
            ))
        })?;
        Ok(())
    }

    /// `new PushDrop(wallet).unlock(protocolID, keyID, 'anyone', 'all',
    /// false, satoshis, lockingScript).sign(partialTx, inputIndex)`
    /// (`:884-894`): the digest the node verifies under `SIGHASH_ALL |
    /// FORKID`, signed by the wallet for anyone, pushed alone.
    async fn unlocking_script(
        &self,
        partial: &Transaction,
        input_index: usize,
        source: &TransactionOutput,
    ) -> Result<Vec<u8>> {
        let parsed = parse_transaction(&partial.to_binary())?;
        let scope = SIGHASH_ALL | SIGHASH_FORKID;
        let subscript = source.locking_script.to_binary();
        crate::wallet::pushdrop::sign(
            self.wallet,
            &SighashParams {
                version: parsed.version,
                inputs: &parsed.inputs,
                outputs: &parsed.outputs,
                locktime: parsed.locktime,
                input_index,
                subscript: &subscript,
                satoshis: source.satoshis.unwrap_or_default(),
                scope,
            },
            self.protocol()?,
            self.config.key_id.clone(),
            Counterparty::Anyone,
            self.originator,
        )
        .await
    }

    /// The reference's signAction (`:896-915`, #318); the signed
    /// transaction and the txid the wallet answered, or `Failed to sign
    /// transaction` when it answered none.
    async fn sign_action(
        &self,
        reference: &str,
        input_index: usize,
        unlocking_script: Vec<u8>,
    ) -> Result<(Vec<u8>, Option<String>)> {
        let index = u32::try_from(input_index)
            .map_err(|_| refused("Revelation transaction input is malformed"))?;
        let mut spends = HashMap::new();
        spends.insert(
            index,
            SignActionSpend {
                unlocking_script,
                sequence_number: None,
            },
        );
        let result = self
            .wallet
            .sign_action(
                SignActionArgs {
                    spends,
                    reference: reference.to_string(),
                    options: Some(SignActionOptions {
                        accept_delayed_broadcast: Some(false),
                        return_txid_only: Some(false),
                        no_send: Some(true),
                        send_with: None,
                    }),
                },
                self.originator,
            )
            .await?;
        let tx = result
            .tx
            .ok_or_else(|| refused("Failed to sign transaction"))?;
        Ok((tx, result.txid.map(|txid| to_hex(&txid))))
    }
}

/// The reference builds a `Certificate` of the token's seven members and
/// asks `verify` (`:789-802`); here the certificate is read from those
/// members' JSON, a member it cannot hold a `false`, as the reference's
/// constructor throwing is caught.
fn certificate_verifies(parsed: &serde_json::Map<String, serde_json::Value>) -> bool {
    let members = [
        "type",
        "serialNumber",
        "subject",
        "certifier",
        "revocationOutpoint",
        "fields",
        "signature",
    ];
    let certificate: serde_json::Map<String, serde_json::Value> = members
        .iter()
        .filter_map(|name| Some((name.to_string(), parsed.get(*name)?.clone())))
        .collect();
    serde_json::from_value::<Certificate>(certificate.into())
        .is_ok_and(|certificate| matches!(certificate.verify(), Ok(true)))
}

/// `revelationInputOutpoint` (`IdentityClient.ts:149-172`): an input's
/// outpoint as `<txid>.<index>`, its txid the one it names or the one of
/// the source it carries, the two equal when both are present.
fn input_outpoint(tx: &Transaction, index: usize) -> Result<String> {
    let input = tx
        .inputs
        .get(index)
        .ok_or_else(|| refused("Revelation transaction input is malformed"))?;
    let embedded = input.source_transaction.as_ref().map(|t| t.id());
    if let (Some(named), Some(embedded)) = (&input.source_txid, &embedded) {
        if !named.eq_ignore_ascii_case(embedded) {
            return Err(refused("Revelation transaction input source mismatch"));
        }
    }
    let txid = input
        .source_txid
        .clone()
        .or(embedded)
        .filter(|t| t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(|| refused("Revelation transaction input has no canonical source ID"))?;
    Ok(format!(
        "{}.{}",
        txid.to_lowercase(),
        input.source_output_index
    ))
}

/// The reference's checks of the signed transaction (`:917-932`,
/// `assertRevelationTransactionTemplate` at `:174-200`): the signable
/// transaction's version, lock time, inputs (outpoint and sequence) and
/// outputs (satoshis and script) kept, the revelation input spending the
/// outpoint with the unlocking script authorized.
fn check_signed(
    signable: &Transaction,
    signed: &Transaction,
    input_index: usize,
    outpoint: &str,
    unlocking_hex: &str,
) -> Result<()> {
    if signable.version != signed.version
        || signable.lock_time != signed.lock_time
        || signable.inputs.len() != signed.inputs.len()
        || signable.outputs.len() != signed.outputs.len()
    {
        return Err(refused(
            "Signed revelation transaction substituted the authorized template",
        ));
    }
    for index in 0..signable.inputs.len() {
        if input_outpoint(signable, index)? != input_outpoint(signed, index)?
            || signable.inputs[index].sequence != signed.inputs[index].sequence
        {
            return Err(refused(
                "Signed revelation transaction substituted an authorized input",
            ));
        }
    }
    for (a, b) in signable.outputs.iter().zip(&signed.outputs) {
        if a.satoshis != b.satoshis || a.locking_script.to_hex() != b.locking_script.to_hex() {
            return Err(refused(
                "Signed revelation transaction substituted an authorized output",
            ));
        }
    }
    if input_outpoint(signed, input_index)? != outpoint {
        return Err(refused(
            "Signed transaction does not spend the requested revelation output.",
        ));
    }
    let script = signed.inputs[input_index].unlocking_script.as_ref();
    if script.map(|s| s.to_hex()).as_deref() != Some(unlocking_hex) {
        return Err(refused(
            "Signed transaction substituted the authorized revelation script.",
        ));
    }
    Ok(())
}
