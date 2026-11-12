//! Local signed value envelope (TS PushDrop.lock, LocalKVStore.ts:486-492).
use super::LocalKVStore;
use crate::script::templates::{LockPosition, PushDrop};
use crate::script::LockingScript;
use crate::wallet::{Counterparty, WalletInterface};
use crate::Result;

impl<W: WalletInterface + std::fmt::Debug> LocalKVStore<W> {
    pub(super) async fn create_locking_script(
        &self,
        key: &str,
        value: &[u8],
    ) -> Result<LockingScript> {
        // The one door (#816): the key asked, its text judged, then the
        // signature over the value (`PushDrop.ts:155-185`).
        PushDrop::lock_with_wallet(
            &self.wallet,
            self.originator(),
            vec![value.to_vec()],
            self.get_protocol(key),
            key,
            Counterparty::Self_,
            false,
            true,
            LockPosition::Before,
        )
        .await
    }
}
