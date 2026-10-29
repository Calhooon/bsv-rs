//! The signAction options the key-value stores send (#326): the reference's
//! stores sign through `completeBoundAction` (`ts-stack@edf6e03`
//! `packages/sdk/src/wallet/completeBoundAction.ts:1111-1120`), whose
//! signAction carries the createAction's `acceptDelayedBroadcast`, `noSend`
//! and `sendWith` and asks for the whole transaction (`returnTXIDOnly: false`).

use crate::wallet::{CreateActionOptions, SignActionOptions};

mod action;
mod checks;
pub(crate) use action::complete_action;
pub(super) use action::complete_with_signers;

/// The options `completeBoundAction` signs with, carried from `create`, the
/// options of the createAction the signAction completes.
pub(crate) fn bound_sign_options(create: Option<&CreateActionOptions>) -> SignActionOptions {
    SignActionOptions {
        accept_delayed_broadcast: create.and_then(|o| o.accept_delayed_broadcast),
        return_txid_only: Some(false),
        no_send: create.and_then(|o| o.no_send),
        send_with: create.and_then(|o| o.send_with.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bound_sign_options_carry_the_create_options_and_ask_for_the_transaction() {
        let none = bound_sign_options(None);
        assert_eq!(none.return_txid_only, Some(false));
        assert_eq!(none.accept_delayed_broadcast, None);
        assert_eq!(none.no_send, None);
        assert_eq!(none.send_with, None);

        let create = CreateActionOptions {
            accept_delayed_broadcast: Some(true),
            no_send: Some(false),
            send_with: Some(vec![[7u8; 32]]),
            return_txid_only: Some(true),
            ..Default::default()
        };
        let carried = bound_sign_options(Some(&create));
        assert_eq!(carried.accept_delayed_broadcast, Some(true));
        assert_eq!(carried.no_send, Some(false));
        assert_eq!(carried.send_with, Some(vec![[7u8; 32]]));
        assert_eq!(carried.return_txid_only, Some(false));
    }
}
