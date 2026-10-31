//! Contact action construction and PushDrop signing, kept separate from cache operations.
use super::record;
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

    /// `#encryptAndLock` (`ContactsManager.ts:748-772`): the validated
    /// record's JSON encrypted under the protocol, `key_id` and self, then
    /// `PushDrop.lock([ciphertext], protocol, keyID, 'self')` with its
    /// signature on (`PushDrop.ts:146-202`): the wallet's key for self
    /// (`forSelf` false), its signature over the ciphertext as the second
    /// field (#544; the ciphertext alone until then).
    pub(super) async fn contact_lock(
        &self,
        record: &record::ContactRecord,
        key_id: &str,
    ) -> Result<LockingScript> {
        let protocol = self.protocol()?;
        let plaintext =
            serde_json::to_vec(record).map_err(|e| Error::IdentityError(e.to_string()))?;
        if plaintext.len() > record::MAX_PLAINTEXT {
            return Err(Error::IdentityError(
                "Contact plaintext is too large".into(),
            ));
        }
        let ciphertext = self
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
            .await?
            .ciphertext;
        if ciphertext.is_empty() || ciphertext.len() > record::MAX_CIPHERTEXT {
            return Err(Error::IdentityError(format!(
                "contact ciphertext must contain 1-{} bytes",
                record::MAX_CIPHERTEXT
            )));
        }
        let key = self
            .wallet
            .get_public_key(
                crate::wallet::GetPublicKeyArgs {
                    protocol_id: Some(protocol.clone()),
                    key_id: Some(key_id.into()),
                    counterparty: Some(Counterparty::Self_),
                    for_self: Some(false),
                    ..Default::default()
                },
                self.originator(),
            )
            .await?;
        let signature = self
            .wallet
            .create_signature(
                crate::wallet::CreateSignatureArgs {
                    data: Some(ciphertext.clone()),
                    protocol_id: protocol,
                    key_id: key_id.into(),
                    counterparty: Some(Counterparty::Self_),
                    ..Default::default()
                },
                self.originator(),
            )
            .await?
            .signature;
        Ok(PushDrop::new(
            PublicKey::from_hex(&key.public_key)?,
            vec![ciphertext, signature],
        )
        .lock())
    }

    /// `#readListedSource` (`ContactsManager.ts:628-658`): the listed
    /// output's script from the BEEF, its transaction by the outpoint's txid.
    fn listed_source(existing: &ListOutputsResult, output: &WalletOutput) -> Result<LockingScript> {
        let refused = |words: &str| Error::IdentityError(words.into());
        let beef = existing
            .beef
            .as_deref()
            .ok_or_else(|| refused("Contact output is missing source BEEF"))?;
        let beef = Beef::from_binary(beef)?;
        let txid = crate::primitives::to_hex(&output.outpoint.txid);
        let tx = beef
            .find_txid(&txid)
            .and_then(|entry| entry.tx())
            .filter(|tx| tx.id() == txid)
            .ok_or_else(|| refused("Contact source transaction ID mismatch"))?;
        let source = tx
            .outputs
            .get(output.outpoint.vout as usize)
            .ok_or_else(|| refused("Contact source output is missing"))?;
        if output
            .locking_script
            .as_ref()
            .is_some_and(|script| *script != source.locking_script.to_binary())
        {
            return Err(refused("Contact locking script does not match source BEEF"));
        }
        Ok(source.locking_script.clone())
    }

    /// One listed output opened (`ContactsManager.ts:598-612`, `:946-959`):
    /// its key ID, its source script, the token authenticated, decrypted and
    /// read; the key ID and the stored identity key.
    async fn open_listed(
        &self,
        existing: &ListOutputsResult,
        output: &WalletOutput,
    ) -> Result<(String, String)> {
        let key_id = record::read_key_id(output.custom_instructions.as_deref())?;
        let script = Self::listed_source(existing, output)?;
        let stored = self.open_contact(&script, &key_id).await?;
        Ok((key_id, stored.identity_key))
    }

    /// `#findExistingOutput` (`ContactsManager.ts:586-626`): every listed
    /// output authenticated, the one stored for `identity_key` and its key
    /// ID; none when nothing is listed, refused otherwise in the
    /// reference's words.
    pub(super) async fn find_existing(
        &self,
        existing: &ListOutputsResult,
        identity_key: &str,
    ) -> Result<Option<(usize, String)>> {
        if existing.outputs.len() > 100 {
            return Err(Error::IdentityError("Invalid contact lookup result".into()));
        }
        let mut matches = Vec::new();
        for (index, output) in existing.outputs.iter().enumerate() {
            let (key_id, stored) = self.open_listed(existing, output).await.map_err(|_| {
                Error::IdentityError("Unable to authenticate a contact lookup result".into())
            })?;
            if stored == identity_key {
                matches.push((index, key_id));
            }
        }
        match matches.len() {
            0 if existing.outputs.is_empty() => Ok(None),
            0 => Err(Error::IdentityError(
                "Contact lookup returned an output for a different identity".into(),
            )),
            1 => Ok(matches.pop()),
            _ => Err(Error::IdentityError(
                "Multiple contact outputs exist for this identity".into(),
            )),
        }
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

    /// `#updateContactOutput` (`ContactsManager.ts:775-858`): the output
    /// `find_existing` authenticated, spent under its key ID, the new token
    /// its replacement.
    pub(super) async fn update_contact_on_chain(
        &self,
        existing: &ListOutputsResult,
        found: (usize, String),
        contact: &Contact,
        lock: &LockingScript,
        tag: &str,
    ) -> Result<()> {
        let (index, key_id) = found;
        let output = &existing.outputs[index];
        let beef = existing
            .beef
            .as_deref()
            .ok_or_else(|| Error::IdentityError("Contact output is missing source BEEF".into()))?;
        let instructions = serde_json::json!({ "keyID": key_id }).to_string();
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
                &instructions,
                true,
            )]),
        );
        let signed = self
            .sign_contact_action(args, key_id, beef, output.outpoint.vout)
            .await?
            .ok_or_else(|| Error::IdentityError("Unable to update contact".into()))?;
        if signed.tx.is_none() && signed.txid.is_none() {
            return Err(Error::IdentityError("Failed to update contact".into()));
        }
        Ok(())
    }

    /// Remove a contact.
    ///
    /// This method removes the contact from both the in-memory cache and the blockchain.
    /// It finds the contact output by its HMAC-hashed tag, authenticates it as
    /// the reference's `#trySpendContactOutput` does (`ContactsManager.ts:941-959`,
    /// #544), and spends it with no replacement output (deletion).
    ///
    /// # Arguments
    /// * `identity_key` - The identity key of the contact to remove
    ///
    /// # Errors
    /// Returns an error if the identity key is not a canonical compressed
    /// key, if the contact is not found, or, in the reference's words, if a
    /// listed output does not authenticate.
    pub async fn remove_contact(&self, identity_key: &str) -> Result<()> {
        record::identity_key(&identity_key.into())?;
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
        if existing.outputs.len() > 100 {
            return Err(Error::IdentityError(
                "Invalid contact removal lookup result".into(),
            ));
        }
        for output in &existing.outputs {
            if output.custom_instructions.is_none() {
                continue;
            }
            if self
                .remove_listed(&existing, output, identity_key)
                .await
                .map_err(|_| {
                    Error::IdentityError("Unable to authenticate or remove a contact output".into())
                })?
            {
                return Ok(());
            }
        }
        Ok(())
    }

    /// `#trySpendContactOutput` (`ContactsManager.ts:941-1010`): the output
    /// opened, skipped when it stores another identity, else spent.
    async fn remove_listed(
        &self,
        existing: &ListOutputsResult,
        output: &WalletOutput,
        identity_key: &str,
    ) -> Result<bool> {
        let (key_id, stored) = self.open_listed(existing, output).await?;
        if stored != identity_key {
            return Ok(false);
        }
        let beef = existing.beef.as_deref().unwrap_or_default();
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
        let signed = self
            .sign_contact_action(args, key_id, beef, output.outpoint.vout)
            .await?
            .ok_or_else(|| Error::IdentityError("Unable to delete contact".into()))?;
        if signed.tx.is_none() && signed.txid.is_none() {
            return Err(Error::IdentityError(
                "Failed to remove contact from blockchain".into(),
            ));
        }
        Ok(true)
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
            self.protocol()?,
            key_id,
            Counterparty::Self_,
            self.originator(),
        )
        .await
        .map(Some)
    }
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
