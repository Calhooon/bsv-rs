//! The instance substrate of [`WalletClient`](super::WalletClient) (#335):
//! the reference's `substrate: WalletInterface` alternative
//! (`ts-stack@edf6e03` `packages/sdk/src/wallet/WalletClient.ts:83-107`).
//!
//! [`Instance`] dereferences to the wallet, so the client's forwarding
//! reaches every `WalletInterface` method by its own name; the six methods
//! whose answer the client's own substrates give in another shape (a
//! status call's bare value, `get_header` for `getHeaderForHeight`) are
//! adapted here to the shape the client returns.

use std::ops::Deref;
use std::sync::Arc;

use crate::wallet::interface::WalletInterface;
use crate::wallet::types::Network;
use crate::wallet::{GetHeaderArgs, GetHeaderResult};
use crate::Error;

/// A `WalletInterface` instance the client was handed.
pub(super) struct Instance(pub(super) Arc<dyn WalletInterface>);

impl Deref for Instance {
    type Target = dyn WalletInterface;

    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

impl Instance {
    pub(super) async fn is_authenticated(&self, originator: Option<&str>) -> Result<bool, Error> {
        Ok(self.0.is_authenticated(originator).await?.authenticated)
    }

    pub(super) async fn wait_for_authentication(
        &self,
        originator: Option<&str>,
    ) -> Result<bool, Error> {
        Ok(self
            .0
            .wait_for_authentication(originator)
            .await?
            .authenticated)
    }

    pub(super) async fn get_height(&self, originator: Option<&str>) -> Result<u64, Error> {
        Ok(u64::from(self.0.get_height(originator).await?.height))
    }

    pub(super) async fn get_network(&self, originator: Option<&str>) -> Result<Network, Error> {
        Ok(self.0.get_network(originator).await?.network)
    }

    pub(super) async fn get_version(&self, originator: Option<&str>) -> Result<String, Error> {
        Ok(self.0.get_version(originator).await?.version)
    }

    pub(super) async fn get_header(
        &self,
        args: GetHeaderArgs,
        originator: Option<&str>,
    ) -> Result<GetHeaderResult, Error> {
        self.0.get_header_for_height(args, originator).await
    }
}
