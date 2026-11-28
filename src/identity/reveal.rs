//! The identity token this crate's writer publishes and its reader
//! authenticates (#310): the certificate JSON and the subject's signature over
//! it, locked with the subject's key for anyone, the canonical signed
//! two-field PushDrop the reference builds and reads.
//!
//! Hand port of the token shape of the 0.9 line's reveal step (`ts-stack@edf6e03`
//! `packages/sdk/src/identity/IdentityClient.ts:501-509`,
//! `PushDrop.ts:146-202`): the key `getPublicKey` answers for the client's
//! protocol and key ID, counterparty `anyone`, `forSelf: true` (the subject's
//! key for anyone, which the overlay reader derives as the anyone wallet's key
//! for the subject, so [`IdentityClient::is_authenticated_token`] reads it);
//! then `createSignature`'s signature over the certificate JSON, for the same
//! protocol, key ID and counterparty, pushed as the token's second field. The
//! 0.9 line's reveal-side input validation (#307) and its createAction wording
//! (#310) are not ported here; this is the token shape alone, so the stable
//! writer and reader agree.
//!
//! [`IdentityClient::is_authenticated_token`]: super::IdentityClient

use crate::primitives::PublicKey;
use crate::script::templates::PushDrop;
use crate::script::LockingScript;
use crate::wallet::{
    Counterparty, CreateSignatureArgs, GetPublicKeyArgs, Protocol, WalletInterface,
};
use crate::{Error, Result};

/// Builds the canonical signed two-field identity token for `cert_json`, the
/// reference's `PushDrop.lock([json], protocolID, keyID, 'anyone', true, true)`
/// (`IdentityClient.ts:501-509`, #310): the key `getPublicKey` answers for
/// `protocol_id`, `key_id`, counterparty anyone and `forSelf` true, then the
/// wallet's signature over `cert_json` for the same protocol, key ID and
/// counterparty, the two dropped fields of a lock-before PushDrop.
///
/// The locking key is the subject's key for anyone, which equals the anyone
/// wallet's key for the subject, so the overlay reader authenticates it
/// (`identityUtils.ts:497-559`).
pub(super) async fn identity_token<W: WalletInterface + ?Sized>(
    wallet: &W,
    originator: &str,
    protocol_id: (u8, &str),
    key_id: &str,
    cert_json: Vec<u8>,
) -> Result<LockingScript> {
    let protocol = Protocol::from_tuple(protocol_id).ok_or_else(|| {
        Error::IdentityError(format!(
            "Invalid protocol ID: ({}, {})",
            protocol_id.0, protocol_id.1
        ))
    })?;

    let wallet_pubkey = wallet
        .get_public_key(
            GetPublicKeyArgs {
                identity_key: false,
                protocol_id: Some(protocol.clone()),
                key_id: Some(key_id.to_string()),
                counterparty: Some(Counterparty::Anyone),
                for_self: Some(true),
            },
            originator,
        )
        .await?;
    let locking_pubkey = PublicKey::from_hex(&wallet_pubkey.public_key)?;

    let field_signature = wallet
        .create_signature(
            CreateSignatureArgs {
                data: Some(cert_json.clone()),
                hash_to_directly_sign: None,
                protocol_id: protocol,
                key_id: key_id.to_string(),
                counterparty: Some(Counterparty::Anyone),
            },
            originator,
        )
        .await?
        .signature;

    Ok(PushDrop::new(locking_pubkey, vec![cert_json, field_signature]).lock())
}

#[cfg(test)]
mod tests {
    use super::identity_token;
    use crate::identity::token_envelope::is_canonical_signed_pushdrop;
    use crate::primitives::{PrivateKey, PublicKey};
    use crate::script::templates::PushDrop;
    use crate::wallet::{Counterparty, KeyDeriver, ProtoWallet, Protocol, VerifySignatureArgs};

    /// The three checks `IdentityClient::is_authenticated_token`
    /// (`client_token.rs`) runs on a token for `subject`: exactly two fields in
    /// the canonical signed envelope, the locking key the anyone wallet derives
    /// for the subject, and the subject's signature over the first field. The
    /// reader reads the token only when all three hold.
    fn reader_accepts(script: &crate::script::LockingScript, subject: &PublicKey) -> bool {
        let token = match PushDrop::decode(script) {
            Ok(t) => t,
            Err(_) => return false,
        };
        if token.fields.len() != 2 || !is_canonical_signed_pushdrop(script, &token.fields) {
            return false;
        }
        let protocol = Protocol::from_tuple((1, "identity")).unwrap();
        let counterparty = Counterparty::Other(subject.clone());
        let expected = KeyDeriver::new(None)
            .derive_public_key(&protocol, "1", &counterparty, false)
            .unwrap();
        if expected != token.locking_public_key {
            return false;
        }
        ProtoWallet::anyone()
            .verify_signature(VerifySignatureArgs {
                data: Some(token.fields[0].clone()),
                hash_to_directly_verify: None,
                signature: token.fields[1].clone(),
                protocol_id: protocol,
                key_id: "1".to_string(),
                counterparty: Some(counterparty),
                for_self: None,
            })
            .is_ok_and(|v| v.valid)
    }

    /// The token this crate's own writer builds satisfies every check this
    /// crate's own reader runs: the subject's wallet locks for anyone with
    /// forSelf true and signs the first field. A reader that refused what the
    /// writer wrote would leave a record this crate publishes unseen by this
    /// crate (#310, the writer/reader agreement). This is RED if the writer
    /// locks forSelf false, drops the signature, or writes one field.
    #[tokio::test]
    async fn the_writers_token_passes_the_readers_authentication_1118e() {
        let subject = PrivateKey::random();
        let subject_pub = subject.public_key();
        let wallet = ProtoWallet::new(Some(subject.clone()));
        let cert_json = br#"{"type":"AQ==","subject":"deadbeef"}"#.to_vec();

        let script = identity_token(&wallet, "identity-client", (1, "identity"), "1", cert_json)
            .await
            .expect("the writer builds the token");

        assert!(
            reader_accepts(&script, &subject_pub),
            "the reader authenticates the token the writer published"
        );
        // Bound to its one subject: a different key does not authenticate it.
        let other = PrivateKey::random().public_key();
        assert!(
            !reader_accepts(&script, &other),
            "the token authenticates only for its own subject"
        );
    }
}
