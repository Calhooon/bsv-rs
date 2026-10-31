//! Local signed value envelope (TS PushDrop.lock, LocalKVStore.ts:486-492).
use super::LocalKVStore;
use crate::script::templates::pushdrop_key_bytes::wallet_key_lock;
use crate::script::LockingScript;
use crate::wallet::{Counterparty, CreateSignatureArgs, GetPublicKeyArgs, WalletInterface};
use crate::Result;

impl<W: WalletInterface + std::fmt::Debug> LocalKVStore<W> {
    pub(super) async fn create_locking_script(
        &self,
        key: &str,
        value: &[u8],
    ) -> Result<LockingScript> {
        let public_key = self
            .wallet
            .get_public_key(
                GetPublicKeyArgs {
                    protocol_id: Some(self.get_protocol(key)),
                    key_id: Some(key.into()),
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
                CreateSignatureArgs {
                    data: Some(value.to_vec()),
                    protocol_id: self.get_protocol(key),
                    key_id: key.into(),
                    counterparty: Some(Counterparty::Self_),
                    ..Default::default()
                },
                self.originator(),
            )
            .await?;
        wallet_key_lock(
            &public_key.public_key,
            vec![value.to_vec(), signature.signature],
        )
    }
}
