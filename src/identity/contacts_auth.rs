//! A listed contact token authenticated and opened as the reference's
//! manager does (#544): `#authenticateContactScript`
//! (`ts-stack@edf6e03` `ContactsManager.ts:431-466`), then the decryption
//! and `#parseContactPlaintext` (`:468-472`, `:489-503`). The token is read
//! as `PushDrop.decode` reads it (#718), so a key alone or a key without
//! `OP_CHECKSIG` second reaches the count, the bounds and the envelope in
//! the reference's order and words.
use super::record::{self, ContactRecord, MAX_CIPHERTEXT};
use super::ContactsManager;
use crate::identity::token_envelope::is_canonical_signed_pushdrop;
use crate::primitives::PublicKey;
use crate::script::templates::pushdrop_position::point_message;
use crate::script::templates::PushDrop;
use crate::script::LockingScript;
use crate::wallet::{Counterparty, DecryptArgs, WalletInterface};
use crate::wallet::{GetPublicKeyArgs, VerifySignatureArgs};
use crate::{Error, Result};

fn refused(words: impl Into<String>) -> Error {
    Error::IdentityError(words.into())
}

/// `PushDrop.decode(lockingScript)` at its default position, as
/// `#authenticateContactScript` calls it (`ContactsManager.ts:432`;
/// `PushDrop.ts:63-121`): the key the first chunk, refused in the words its
/// read and `Point.fromDER` throw (`Point.ts:303-325`), the second chunk
/// never read, the fields from the third. A key the reference reads and
/// this crate refuses (#498's row) keeps the native words.
fn decode(script: &LockingScript) -> Result<PushDrop> {
    let chunks = script.chunks();
    let Some(first) = chunks.first() else {
        return Err(refused(
            "Cannot read properties of undefined (reading 'data')",
        ));
    };
    let Some(key) = first.data.as_deref() else {
        return Err(refused("script.chunks[0].data must have value"));
    };
    if let Some(words) = PublicKey::from_bytes(key)
        .is_err()
        .then(|| point_message(key))
        .flatten()
    {
        return Err(refused(words));
    }
    PushDrop::decode_reference_before(&chunks)
}

/// `bytes(value, field, minimum, maximum)` (`ContactsManager.ts:200-216`).
fn bounded<'a>(value: &'a [u8], field: &str, min: usize, max: usize) -> Result<&'a [u8]> {
    if value.len() < min || value.len() > max {
        return Err(refused(format!("{field} must contain {min}-{max} bytes")));
    }
    Ok(value)
}

impl<W: WalletInterface> ContactsManager<W> {
    /// `#authenticateContactScript` (`ContactsManager.ts:431-466`): exactly
    /// two fields, the ciphertext and the signature in their bounds, the
    /// canonical five-chunk script, the lock the wallet's key for the
    /// protocol, `key_id` and self, the signature the wallet's over the
    /// ciphertext; the ciphertext.
    pub(super) async fn authenticate_contact(
        &self,
        script: &LockingScript,
        key_id: &str,
    ) -> Result<Vec<u8>> {
        let decoded = decode(script)?;
        if decoded.fields.len() != 2 {
            return Err(refused("Invalid contact PushDrop field count"));
        }
        let ciphertext = bounded(&decoded.fields[0], "contact ciphertext", 1, MAX_CIPHERTEXT)?;
        let signature = bounded(&decoded.fields[1], "contact signature", 8, 80)?;
        if !is_canonical_signed_pushdrop(script, &decoded.fields) {
            return Err(refused(
                "Contact output must use the canonical signed PushDrop script",
            ));
        }
        let protocol = self.protocol()?;
        let key = self
            .wallet
            .get_public_key(
                GetPublicKeyArgs {
                    protocol_id: Some(protocol.clone()),
                    key_id: Some(key_id.into()),
                    counterparty: Some(Counterparty::Self_),
                    ..Default::default()
                },
                self.originator(),
            )
            .await?;
        let expected = record::identity_key(&key.public_key.clone().into())?;
        if decoded.locking_public_key.to_hex() != expected {
            return Err(refused(
                "Contact output is not locked to its declared keyID",
            ));
        }
        let verified = self
            .wallet
            .verify_signature(
                VerifySignatureArgs {
                    data: Some(ciphertext.to_vec()),
                    signature: signature.to_vec(),
                    protocol_id: protocol,
                    key_id: key_id.into(),
                    counterparty: Some(Counterparty::Self_),
                    ..Default::default()
                },
                self.originator(),
            )
            .await?;
        if !verified.valid {
            return Err(refused("Invalid contact field signature"));
        }
        Ok(ciphertext.to_vec())
    }

    /// A listed token authenticated, decrypted and read as the reference's
    /// record (`ContactsManager.ts:489-503`, `:600-612`, `:947-959`).
    pub(super) async fn open_contact(
        &self,
        script: &LockingScript,
        key_id: &str,
    ) -> Result<ContactRecord> {
        let ciphertext = self.authenticate_contact(script, key_id).await?;
        let plaintext = self
            .wallet
            .decrypt(
                DecryptArgs {
                    ciphertext,
                    protocol_id: self.protocol()?,
                    key_id: key_id.into(),
                    counterparty: Some(Counterparty::Self_),
                    ..Default::default()
                },
                self.originator(),
            )
            .await?
            .plaintext;
        record::parse_plaintext(&plaintext)
    }
}

#[cfg(test)]
#[path = "contacts_auth_718_tests.rs"]
mod canonical_718_tests;
