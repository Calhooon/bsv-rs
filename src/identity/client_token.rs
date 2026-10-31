//! An `ls_identity` token authenticated before either parser reads its
//! certificate (#544): the checks the reference runs on a revelation token
//! (`ts-stack@edf6e03` `IdentityClient.ts:773-815`: exactly two fields, the
//! canonical signed envelope, the locking key, the field signature) with the
//! key and the signature the subject's, as the reference's discovery reads a
//! published token (the toolbox's `decodeIdentityOutput`,
//! `wallet-toolbox/src/utility/identityUtils.ts:497-540`: the anyone
//! wallet's key for counterparty the subject, `verifySignature` as anyone
//! with counterparty the subject). A token that fails is skipped, as the
//! reference skips it (`IdentityClient.ts:823`, `identityUtils.ts:563`).

use super::IdentityClient;
use crate::identity::token_envelope::is_canonical_signed_pushdrop;
use crate::primitives::PublicKey;
use crate::script::templates::PushDrop;
use crate::script::LockingScript;
use crate::wallet::{
    Counterparty, KeyDeriver, ProtoWallet, Protocol, VerifySignatureArgs, WalletInterface,
};

impl<W: WalletInterface> IdentityClient<W> {
    /// Whether `token`, decoded from `script`, is `subject`'s signed
    /// revelation: two fields, the canonical five chunks, locked with the
    /// subject's key for `anyone` under the client's protocol and key ID,
    /// its second field the subject's signature over the first.
    pub(super) fn is_authenticated_token(
        &self,
        script: &LockingScript,
        token: &PushDrop,
        subject: &PublicKey,
    ) -> bool {
        if token.fields.len() != 2 || !is_canonical_signed_pushdrop(script, &token.fields) {
            return false;
        }
        let (level, name) = (self.config.protocol_id.0, &self.config.protocol_id.1);
        let Some(protocol) = Protocol::from_tuple((level, name)) else {
            return false;
        };
        let counterparty = Counterparty::Other(subject.clone());
        let expected = KeyDeriver::new(None).derive_public_key(
            &protocol,
            &self.config.key_id,
            &counterparty,
            false,
        );
        if !expected.is_ok_and(|key| key == token.locking_public_key) {
            return false;
        }
        ProtoWallet::anyone()
            .verify_signature(VerifySignatureArgs {
                data: Some(token.fields[0].clone()),
                signature: token.fields[1].clone(),
                protocol_id: protocol,
                key_id: self.config.key_id.clone(),
                counterparty: Some(counterparty),
                ..Default::default()
            })
            .is_ok_and(|verified| verified.valid)
    }
}
