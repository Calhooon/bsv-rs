//! Contact action construction and PushDrop signing, kept separate from cache operations.
use super::*;
use crate::script::LockingScript;
use crate::wallet::{
    ListOutputsResult, Outpoint, SignActionResult, SignableTransaction, WalletOutput,
};

impl<W: WalletInterface> ContactsManager<W> {
    pub(super) async fn contact_outputs(
        &self,
        tags: Option<Vec<String>>,
        include: OutputInclude,
        limit: u32,
    ) -> Result<ListOutputsResult> {
        self.wallet
            .list_outputs(
                ListOutputsArgs {
                    basket: self.config.basket.clone(),
                    tags,
                    tag_query_mode: None,
                    include: Some(include),
                    include_custom_instructions: Some(true),
                    include_tags: None,
                    include_labels: None,
                    limit: Some(limit),
                    offset: None,
                    seek_permission: None,
                },
                self.originator(),
            )
            .await
    }

    pub(super) async fn contact_lock(
        &self,
        contact: &Contact,
        key_id: &str,
    ) -> Result<LockingScript> {
        let protocol = Protocol::new(SecurityLevel::App, &self.config.protocol_id.1);
        let plaintext =
            serde_json::to_vec(contact).map_err(|e| Error::IdentityError(e.to_string()))?;
        let encrypted = self
            .wallet
            .encrypt(
                EncryptArgs {
                    plaintext,
                    protocol_id: protocol.clone(),
                    key_id: key_id.into(),
                    counterparty: Some(Counterparty::Self_),
                    ..Default::default()
                },
                self.originator(),
            )
            .await?;
        let key = self
            .wallet
            .get_public_key(
                crate::wallet::GetPublicKeyArgs {
                    protocol_id: Some(protocol),
                    key_id: Some(key_id.into()),
                    counterparty: Some(Counterparty::Self_),
                    for_self: Some(true),
                    ..Default::default()
                },
                self.originator(),
            )
            .await?;
        Ok(PushDrop::new(
            PublicKey::from_hex(&key.public_key)?,
            vec![encrypted.ciphertext],
        )
        .lock())
    }

    fn contact_output(
        &self,
        contact: &Contact,
        lock: &LockingScript,
        tag: &str,
        instructions: &str,
        update: bool,
    ) -> CreateActionOutput {
        let description = if update {
            format!(
                "Updated Contact: {}",
                contact.name.chars().take(20).collect::<String>()
            )
        } else {
            format!(
                "Contact: {}",
                contact.identity_key.chars().take(10).collect::<String>()
            )
        };
        CreateActionOutput {
            locking_script: lock.to_binary(),
            satoshis: 1,
            output_description: description,
            basket: Some(self.config.basket.clone()),
            custom_instructions: Some(instructions.into()),
            tags: Some(vec![tag.into()]),
        }
    }

    pub(super) async fn create_contact(
        &self,
        contact: &Contact,
        lock: &LockingScript,
        tag: &str,
        instructions: &str,
    ) -> Result<()> {
        self.wallet
            .create_action(
                CreateActionArgs {
                    description: format!(
                        "Add Contact: {}",
                        contact.name.chars().take(20).collect::<String>()
                    ),
                    inputs: None,
                    input_beef: None,
                    outputs: Some(vec![self.contact_output(
                        contact,
                        lock,
                        tag,
                        instructions,
                        false,
                    )]),
                    lock_time: None,
                    version: None,
                    labels: Some(vec!["contacts".into()]),
                    options: Some(CreateActionOptions {
                        sign_and_process: Some(true),
                        accept_delayed_broadcast: Some(false),
                        randomize_outputs: Some(false),
                        ..Default::default()
                    }),
                },
                self.originator(),
            )
            .await?;
        Ok(())
    }

    pub(super) async fn update_contact_on_chain(
        &self,
        existing: &ListOutputsResult,
        contact: &Contact,
        lock: &LockingScript,
        tag: &str,
        instructions: &str,
    ) -> Result<()> {
        for output in &existing.outputs {
            let (Some(key_id), Some(beef)) = (stored_key_id(output), existing.beef.as_deref())
            else {
                continue;
            };
            let args = edit_action(
                format!(
                    "Update Contact: {}",
                    contact.name.chars().take(20).collect::<String>()
                ),
                "Previous contact output",
                output.outpoint.clone(),
                beef,
                Some(vec![self.contact_output(
                    contact,
                    lock,
                    tag,
                    instructions,
                    true,
                )]),
            );
            let Some(signed) = self
                .sign_contact_action(args, key_id, beef, output.outpoint.vout)
                .await?
            else {
                continue;
            };
            if signed.tx.is_none() && signed.txid.is_none() {
                return Err(Error::IdentityError("Failed to update contact".into()));
            }
            self.cache
                .write()
                .await
                .contacts
                .insert(contact.identity_key.clone(), contact.clone());
            return Ok(());
        }
        Err(Error::IdentityError(
            "Failed to find existing contact output".into(),
        ))
    }

    /// Remove a contact.
    ///
    /// This method removes the contact from both the in-memory cache and the blockchain.
    /// It finds the contact output by its HMAC-hashed tag and spends it with no
    /// replacement output (deletion).
    ///
    /// # Arguments
    /// * `identity_key` - The identity key of the contact to remove
    ///
    /// # Errors
    /// Returns an error if the contact is not found.
    pub async fn remove_contact(&self, identity_key: &str) -> Result<()> {
        if self
            .cache
            .write()
            .await
            .contacts
            .remove(identity_key)
            .is_none()
        {
            return Err(Error::ContactNotFound(identity_key.into()));
        }
        let Ok(tag) = self.create_identity_tag(identity_key).await else {
            return Ok(());
        };
        let Ok(existing) = self
            .contact_outputs(Some(vec![tag]), OutputInclude::EntireTransactions, 100)
            .await
        else {
            return Ok(());
        };
        for output in &existing.outputs {
            let (Some(key_id), Some(beef)) = (stored_key_id(output), existing.beef.as_deref())
            else {
                continue;
            };
            let args = edit_action(
                format!(
                    "Remove Contact: {}",
                    identity_key.chars().take(10).collect::<String>()
                ),
                "Contact output to remove",
                output.outpoint.clone(),
                beef,
                None,
            );
            let Some(signed) = self
                .sign_contact_action(args, key_id, beef, output.outpoint.vout)
                .await?
            else {
                continue;
            };
            if signed.tx.is_none() && signed.txid.is_none() {
                return Err(Error::IdentityError(
                    "Failed to remove contact from blockchain".into(),
                ));
            }
            return Ok(());
        }
        Ok(())
    }

    async fn sign_contact_action(
        &self,
        args: CreateActionArgs,
        key_id: String,
        beef: &[u8],
        output_index: u32,
    ) -> Result<Option<SignActionResult>> {
        let created = self.wallet.create_action(args, self.originator()).await?;
        let Some(signable) = created.signable_transaction else {
            return Ok(None);
        };
        let Some(unlocking_script) = self
            .contact_unlock(beef, &signable, output_index, key_id)
            .await?
        else {
            return Ok(None);
        };
        let spends = [(
            0,
            SignActionSpend {
                unlocking_script,
                sequence_number: None,
            },
        )]
        .into();
        self.wallet
            .sign_action(
                SignActionArgs {
                    spends,
                    reference: to_base64(&signable.reference),
                    options: None,
                },
                self.originator(),
            )
            .await
            .map(Some)
    }

    async fn contact_unlock(
        &self,
        beef: &[u8],
        signable: &SignableTransaction,
        output_index: u32,
        key_id: String,
    ) -> Result<Option<Vec<u8>>> {
        let beef = Beef::from_binary(beef)
            .map_err(|e| Error::IdentityError(format!("Failed to parse BEEF: {e}")))?;
        let tx = beef
            .txs
            .first()
            .ok_or_else(|| Error::IdentityError("BEEF contains no transactions".into()))?;
        let raw = tx
            .raw_tx()
            .ok_or_else(|| Error::IdentityError("Failed to get raw tx from BEEF".into()))?;
        let source = parse_transaction(raw)
            .map_err(|e| Error::IdentityError(format!("Failed to parse transaction: {e}")))?;
        let Some(output) = source.outputs.get(output_index as usize) else {
            return Ok(None);
        };
        let partial = Transaction::from_beef(&signable.tx, None)
            .map_err(|e| Error::IdentityError(format!("Failed to parse signable tx: {e}")))?;
        let parsed = parse_transaction(&partial.to_binary())
            .map_err(|e| Error::IdentityError(format!("Failed to parse partial tx: {e}")))?;
        crate::wallet::pushdrop::sign(
            &self.wallet,
            &SighashParams {
                version: parsed.version,
                inputs: &parsed.inputs,
                outputs: &parsed.outputs,
                locktime: parsed.locktime,
                input_index: 0,
                subscript: &output.script,
                satoshis: output.satoshis,
                scope: SIGHASH_ALL | SIGHASH_FORKID,
            },
            Protocol::new(SecurityLevel::App, &self.config.protocol_id.1),
            key_id,
            Counterparty::Self_,
            self.originator(),
        )
        .await
        .map(Some)
    }
}

pub(super) fn stored_key_id(output: &WalletOutput) -> Option<String> {
    let instructions = output.custom_instructions.as_ref()?;
    let value: serde_json::Value = serde_json::from_str(instructions).ok()?;
    Some(value["keyID"].as_str().unwrap_or("").into())
}

fn edit_action(
    description: String,
    input_description: &str,
    outpoint: Outpoint,
    beef: &[u8],
    outputs: Option<Vec<CreateActionOutput>>,
) -> CreateActionArgs {
    CreateActionArgs {
        description,
        input_beef: Some(beef.to_vec()),
        inputs: Some(vec![CreateActionInput {
            outpoint,
            input_description: input_description.into(),
            unlocking_script: None,
            unlocking_script_length: Some(74),
            sequence_number: None,
        }]),
        outputs,
        lock_time: None,
        version: None,
        labels: Some(vec!["contacts".into()]),
        options: Some(CreateActionOptions {
            sign_and_process: Some(false),
            accept_delayed_broadcast: Some(false),
            no_send: Some(true),
            randomize_outputs: Some(false),
            ..Default::default()
        }),
    }
}
