//! Contact action construction and PushDrop signing, kept separate from cache operations.
use super::record;
use super::spend::{self, SpendWords};
use super::*;
use crate::script::templates::{LockPosition, PushDrop};
use crate::script::LockingScript;
use crate::wallet::{AbortActionArgs, ListOutputsResult, Outpoint, WalletOutput};

/// `Number.isSafeInteger`'s bound on a source's satoshis
/// (`ContactsManager.ts:645-647`).
const MAX_SAFE_SATOSHIS: u64 = (1 << 53) - 1;

/// `#readListedSource`'s answer (`ContactsManager.ts:633-659`): the listed
/// outpoint as `<txid>.<vout>`, the output's script and satoshis, read from
/// the listing's BEEF by the outpoint's txid; the one reading the
/// authentication and the spend share (#904).
pub(super) struct ListedSource {
    pub outpoint: String,
    pub lock: LockingScript,
    pub satoshis: u64,
}

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
        // The one door (#816): the key asked, its text judged, then the
        // signature over the ciphertext (`PushDrop.ts:155-185`).
        PushDrop::lock_with_wallet(
            &self.wallet,
            self.originator(),
            vec![ciphertext],
            protocol,
            key_id,
            Counterparty::Self_,
            false,
            true,
            LockPosition::Before,
        )
        .await
    }

    /// `#readListedSource` (`ContactsManager.ts:633-659`): the listed
    /// output's transaction read from the BEEF by the outpoint's txid
    /// (`Transaction.fromBEEF(outputs.BEEF, txid)`), its output at the
    /// outpoint's index, its script and satoshis (#904: until then the
    /// spend read the BEEF's leading entry, the token's parent when the
    /// token is unmined).
    pub(super) fn listed_source(
        existing: &ListOutputsResult,
        output: &WalletOutput,
    ) -> Result<ListedSource> {
        let refused = |words: &str| Error::IdentityError(words.into());
        let beef = existing
            .beef
            .as_deref()
            .ok_or_else(|| refused("Contact output is missing source BEEF"))?;
        let beef = spend::bounded_beef(beef, "contact source BEEF")?;
        let txid = crate::primitives::to_hex(&output.outpoint.txid);
        let tx = Transaction::from_beef(beef, Some(&txid))?;
        if tx.id() != txid {
            return Err(refused("Contact source transaction ID mismatch"));
        }
        let source = tx
            .outputs()
            .get(output.outpoint.vout as usize)
            .ok_or_else(|| refused("Contact source output is missing"))?;
        let satoshis = source
            .satoshis
            .filter(|s| *s <= MAX_SAFE_SATOSHIS)
            .ok_or_else(|| refused("Contact source output has invalid satoshis"))?;
        if output
            .locking_script
            .as_ref()
            .is_some_and(|script| *script != source.locking_script.to_binary())
        {
            return Err(refused("Contact locking script does not match source BEEF"));
        }
        Ok(ListedSource {
            outpoint: format!("{txid}.{}", output.outpoint.vout),
            lock: source.locking_script.clone(),
            satoshis,
        })
    }

    /// One listed output opened (`ContactsManager.ts:598-612`, `:946-959`):
    /// its key ID, its source, the token authenticated, decrypted and read;
    /// the key ID, the stored identity key and the source.
    async fn open_listed(
        &self,
        existing: &ListOutputsResult,
        output: &WalletOutput,
    ) -> Result<(String, String, ListedSource)> {
        let key_id = record::read_key_id(output.custom_instructions.as_deref())?;
        let source = Self::listed_source(existing, output)?;
        let stored = self.open_contact(&source.lock, &key_id).await?;
        Ok((key_id, stored.identity_key, source))
    }

    /// `#findExistingOutput` (`ContactsManager.ts:587-626`): every listed
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
            let (key_id, stored, _) = self.open_listed(existing, output).await.map_err(|_| {
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

    /// The new token's output (`ContactsManager.ts:798-807`, `:868-876`):
    /// `Contact: <name>` or `Updated Contact: <name>` (the name, which the
    /// record requires non-empty, so never the key's ten characters).
    fn contact_output(
        &self,
        contact: &Contact,
        lock: &LockingScript,
        tag: &str,
        instructions: &str,
        update: bool,
    ) -> CreateActionOutput {
        let prefix = if update { "Updated Contact" } else { "Contact" };
        CreateActionOutput {
            locking_script: lock.to_binary(),
            satoshis: 1,
            output_description: format!("{prefix}: {}", contact.name),
            basket: Some(self.config.basket.clone()),
            custom_instructions: Some(instructions.into()),
            tags: Some(vec![tag.into()]),
        }
    }

    /// `#createContactOutput` (`ContactsManager.ts:859-885`): `Add
    /// Contact`, the reference's options, no label; the finished
    /// transaction required and holding the token once.
    pub(super) async fn create_contact(
        &self,
        contact: &Contact,
        lock: &LockingScript,
        tag: &str,
        instructions: &str,
    ) -> Result<()> {
        let created = self
            .wallet
            .create_action(
                CreateActionArgs {
                    description: "Add Contact".into(),
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
                    labels: None,
                    options: Some(reference_options()),
                },
                self.originator(),
            )
            .await?;
        let tx = created
            .tx
            .ok_or_else(|| Error::IdentityError("Failed to create contact output".into()))?;
        let created = spend::parse_atomic(&tx, "created contact transaction")?;
        spend::require_contact_output(&created, &lock.to_binary())
    }

    /// `#updateContactOutput` (`ContactsManager.ts:775-856`): the output
    /// `find_existing` authenticated, read again from the BEEF by its txid,
    /// spent under its key ID at the input the wallet bound, the new token
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
        let source = Self::listed_source(existing, &existing.outputs[index])?;
        let beef = existing.beef.as_deref().unwrap_or_default();
        let instructions = serde_json::json!({ "keyID": key_id }).to_string();
        let args = edit_action(
            "Update Contact",
            "Spend previous contact output",
            existing.outputs[index].outpoint.clone(),
            beef,
            vec![self.contact_output(contact, lock, tag, &instructions, true)],
        );
        self.spend_listed(
            args,
            key_id,
            &source,
            Some(&lock.to_binary()),
            &spend::UPDATE,
        )
        .await
    }

    /// Remove a contact.
    ///
    /// As the reference's `removeContact` (`ContactsManager.ts:891-920`):
    /// the wallet is asked whatever the cache holds; each listed output is
    /// authenticated as `#trySpendContactOutput` does (`:941-959`, #544) and
    /// the one stored for `identity_key` spent with no replacement output;
    /// the cache entry is removed after the spend, or when nothing listed
    /// stores the contact (#904).
    ///
    /// # Arguments
    /// * `identity_key` - The identity key of the contact to remove
    ///
    /// # Errors
    /// Returns an error if the identity key is not a canonical compressed
    /// key, if the wallet's HMAC or listing fails (the wallet's error as it
    /// came), or, in the reference's words, `Unable to authenticate or remove
    /// a contact output`, if a listed output does not authenticate or its
    /// spend fails, the wallet's own createAction, signAction and decrypt
    /// failures among them (`ContactsManager.ts:908-918` wraps them all).
    pub async fn remove_contact(&self, identity_key: &str) -> Result<()> {
        record::identity_key(&identity_key.into())?;
        let tag = self.create_identity_tag(identity_key).await?;
        let existing = self
            .contact_outputs(Some(vec![tag]), OutputInclude::EntireTransactions, 100)
            .await?;
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
                break;
            }
        }
        self.cache.write().await.remove(identity_key);
        Ok(())
    }

    /// `#trySpendContactOutput` (`ContactsManager.ts:941-1021`): the output
    /// opened, skipped when it stores another identity, else spent.
    async fn remove_listed(
        &self,
        existing: &ListOutputsResult,
        output: &WalletOutput,
        identity_key: &str,
    ) -> Result<bool> {
        let (key_id, stored, source) = self.open_listed(existing, output).await?;
        if stored != identity_key {
            return Ok(false);
        }
        let beef = existing.beef.as_deref().unwrap_or_default();
        let args = edit_action(
            "Delete Contact",
            "Spend contact output to delete",
            output.outpoint.clone(),
            beef,
            Vec::new(),
        );
        self.spend_listed(args, key_id, &source, None, &spend::DELETE)
            .await?;
        Ok(true)
    }

    /// The spend of a listed token (`ContactsManager.ts:787-855`,
    /// `:964-1020`): createAction; no signable transaction refused before
    /// anything is held; then, any failure aborting the action by its
    /// reference and returned as it came (`#abortPartialAction`, `:738-745`).
    async fn spend_listed(
        &self,
        args: CreateActionArgs,
        key_id: String,
        source: &ListedSource,
        lock: Option<&[u8]>,
        words: &SpendWords,
    ) -> Result<()> {
        let created = self.wallet.create_action(args, self.originator()).await?;
        let signable = created
            .signable_transaction
            .ok_or_else(|| Error::IdentityError(words.unsigned.into()))?;
        let reference = to_base64(&signable.reference);
        let result = self
            .sign_bound(&signable.tx, &reference, key_id, source, lock, words)
            .await;
        if result.is_err() {
            // The primary failure is kept; a refused abort is not reported
            // (`:741-744`).
            let _ = self
                .wallet
                .abort_action(
                    AbortActionArgs {
                        reference: reference.clone(),
                    },
                    self.originator(),
                )
                .await;
        }
        result
    }

    /// The signable transaction read, the input bound to the token's
    /// outpoint found (`#findBoundInput`), the token's input signed there
    /// over the source's satoshis and script, the spend keyed by its index,
    /// and the signed transaction checked (#904: until then input 0 and
    /// key 0, whatever the wallet bound).
    async fn sign_bound(
        &self,
        signable: &[u8],
        reference: &str,
        key_id: String,
        source: &ListedSource,
        lock: Option<&[u8]>,
        words: &SpendWords,
    ) -> Result<()> {
        let signable = spend::parse_atomic(signable, words.signable_field)?;
        let input_index = spend::find_bound_input(&signable, &source.outpoint)?;
        if let Some(lock) = lock {
            spend::require_contact_output(&signable, lock)?;
        }
        let parsed = parse_transaction(&signable.to_binary())?;
        let unlocking_script = crate::wallet::pushdrop::sign(
            &self.wallet,
            &SighashParams {
                version: parsed.version,
                inputs: &parsed.inputs,
                outputs: &parsed.outputs,
                locktime: parsed.locktime,
                input_index,
                subscript: &source.lock.to_binary(),
                satoshis: source.satoshis,
                scope: SIGHASH_ALL | SIGHASH_FORKID,
            },
            self.protocol()?,
            key_id,
            Counterparty::Self_,
            self.originator(),
        )
        .await?;
        let key = u32::try_from(input_index)
            .map_err(|_| Error::IdentityError("Contact transaction input is malformed".into()))?;
        let spends = [(
            key,
            SignActionSpend {
                unlocking_script: unlocking_script.clone(),
                sequence_number: None,
            },
        )]
        .into();
        let signed = self
            .wallet
            .sign_action(
                SignActionArgs {
                    spends,
                    reference: reference.into(),
                    options: None,
                },
                self.originator(),
            )
            .await?;
        let tx = signed
            .tx
            .ok_or_else(|| Error::IdentityError(words.no_tx.into()))?;
        spend::check_signed(
            &signable,
            &tx,
            input_index,
            &source.outpoint,
            &unlocking_script,
            lock,
            words,
        )
    }
}

/// `{ acceptDelayedBroadcast: false, randomizeOutputs: false }`, the
/// reference's options at all three actions (`ContactsManager.ts:808`,
/// `:878`, `:976`): no `signAndProcess`, no `noSend` (#904).
fn reference_options() -> CreateActionOptions {
    CreateActionOptions {
        accept_delayed_broadcast: Some(false),
        randomize_outputs: Some(false),
        ..Default::default()
    }
}

/// The update's and the removal's createAction (`:787-811`, `:964-979`):
/// one input of 74 bytes at the outpoint, the outputs given (`[]` for the
/// removal), no label.
fn edit_action(
    description: &str,
    input_description: &str,
    outpoint: Outpoint,
    beef: &[u8],
    outputs: Vec<CreateActionOutput>,
) -> CreateActionArgs {
    CreateActionArgs {
        description: description.into(),
        input_beef: Some(beef.to_vec()),
        inputs: Some(vec![CreateActionInput {
            outpoint,
            input_description: input_description.into(),
            unlocking_script: None,
            unlocking_script_length: Some(74),
            sequence_number: None,
        }]),
        outputs: Some(outputs),
        lock_time: None,
        version: None,
        labels: None,
        options: Some(reference_options()),
    }
}
