//! The by-key, attribute and discovery doors' argument checks (#818b, #905):
//! the reference's identity client hands its arguments to its wallet
//! (`ts-stack@edf6e03` `packages/sdk/src/identity/IdentityClient.ts:569`,
//! `:614`), whose door validates them before it connects or asks a host
//! (`packages/sdk/src/wallet/WalletClient.ts:509-511`, `:524`;
//! `packages/wallet/wallet-toolbox/src/Wallet.ts:971`, `:1029`). These doors
//! refuse what that door refuses, in its words, before any lookup and so
//! before any host is charged; until #818b they sent the argument and read
//! the overlay's refusal as an empty answer.

use crate::primitives::PublicKey;
use crate::wallet::{
    validate_discover_by_attributes_args, validate_discover_by_identity_key_args,
    DiscoverByAttributesArgs, DiscoverByIdentityKeyArgs,
};
use crate::Result;
use indexmap::IndexMap;

/// `validateDiscoverByIdentityKeyArgs` on the asked key (`Wallet.ts:971`):
/// the key the validated text names, the one the subject filter compares
/// with (`Wallet.ts:1012`), where the question carries the text as given
/// (`:1004`).
pub(super) fn identity_key(identity_key: &str) -> Result<PublicKey> {
    validate_discover_by_identity_key_args(&DiscoverByIdentityKeyArgs {
        identity_key: identity_key.to_string(),
        limit: None,
        offset: None,
        seek_permission: None,
    })
}

/// The contact read's rule ahead of it (`IdentityClient.ts:575`,
/// `ContactsManager.ts:316-317`, `:83-94`): `Error::IdentityError` in the
/// contacts manager's words, a stricter rule than the wallet's (lower case
/// alone, no padding).
pub(super) fn contact_key(identity_key: &str) -> Result<()> {
    super::super::contacts::contact_identity_key(identity_key).map(drop)
}

/// `validateDiscoverByAttributesArgs` on the caller's map as given
/// (`Wallet.ts:1029`), before the contacts load and the lone attribute's
/// rewrite to `any`.
pub(super) fn attributes(attributes: &IndexMap<String, String>) -> Result<()> {
    validate_discover_by_attributes_args(&DiscoverByAttributesArgs {
        attributes: attributes.clone(),
        limit: None,
        offset: None,
        seek_permission: None,
    })
}

/// `discover_certificates_by_type`'s type: no reference door takes one
/// (`DiscoverByIdentityKeyArgs` carries no type), so the overlay's rule
/// `query` judges it by (#756's fold), in the overlay's words; this crate's
/// own.
pub(super) fn certificate_type(cert_type: &str) -> Result<()> {
    super::super::query_bounds::certificate_type(cert_type)
}
