//! Argument-side checks needed by the result bindings (#487).
//! `validateWalletArgs` precedes transmission at `WalletWireTransceiver.ts`
//! :162,624,1476,1565 (ts-stack@edf6e03). These use the same typed byte and
//! InvalidParameter helpers as the processor's crypto argument validators.

use super::{crypto, originator::invalid_parameter};
use crate::primitives::PublicKey;
use crate::wallet::{
    CreateActionArgs, DiscoverByAttributesArgs, DiscoverByIdentityKeyArgs, ProveCertificateArgs,
};
use crate::Result;
use indexmap::IndexMap;
use std::collections::HashMap;

/// `validationHelpers.ts:775-781`: even unused inputBEEF must be framed.
pub(crate) fn create_action_sources(args: &CreateActionArgs) -> Result<HashMap<String, u64>> {
    let Some(bytes) = &args.input_beef else {
        return Ok(HashMap::new());
    };
    crypto::byte_array(bytes.len(), "inputBEEF")?;
    crate::wallet::substrates::result_values::input_sources(
        bytes,
        args.inputs.as_deref().unwrap_or_default(),
    )
    .map_err(|_| invalid_parameter("inputBEEF", "a complete, exactly framed BEEF envelope"))
}

/// `validationHelpers.ts:1199,1647`: validateInteger(limit, 'limit', 10, 1, 10000).
pub(crate) fn limit(limit: Option<u32>) -> Result<()> {
    match limit {
        Some(0) => Err(invalid_parameter("limit", "at least 1 length.")),
        Some(10001..) => Err(invalid_parameter("limit", "no more than 10000 length.")),
        _ => Ok(()),
    }
}

/// `validationHelpers.ts:1476-1480,93-96`: validateCertificateFields first
/// validates its record's safe own keys, ahead of checking individual names.
pub(crate) fn prove_certificate(args: &ProveCertificateArgs) -> Result<()> {
    if args
        .certificate
        .fields
        .keys()
        .any(|key| matches!(key.as_str(), "__proto__" | "constructor" | "prototype"))
    {
        return Err(invalid_parameter(
            "fields",
            "an object with safe string keys",
        ));
    }
    Ok(())
}

/// `validateRecord`'s bound on a record's own keys
/// (`MAXIMUM_WALLET_COLLECTION_ITEMS`, `validationHelpers.ts:67,90-92`).
const MAXIMUM_WALLET_COLLECTION_ITEMS: usize = 100_000;

/// `MAXIMUM_DISCOVERY_ATTRIBUTES` (`validationHelpers.ts:71`).
const MAXIMUM_DISCOVERY_ATTRIBUTES: usize = 32;

/// The reference's `validateDiscoverByIdentityKeyArgs`
/// (`ts-stack@edf6e03` `packages/sdk/src/wallet/validationHelpers.ts:1535-1546`),
/// which its `WalletClient` and the toolbox wallet run before any lookup
/// (`WalletClient.ts:509`, `wallet-toolbox/src/Wallet.ts:971`; #818b, #905):
/// `identityKey` by [`validate_public_key`](crate::wallet::validate_public_key)
/// (trimmed as JavaScript trims, even length, hex, 66 digits, then a
/// compressed point), then `limit` from 1 to 10000. `offset`, `seekPermission`
/// and the record are held by their types.
///
/// Returns the key the validated text names; a refusal is
/// `Error::WalletRefusal` of class `InvalidParameter` (code 6) in the
/// reference's words, `The <parameter> parameter must be ...`.
///
/// ```
/// use bsv_rs::wallet::{validate_discover_by_identity_key_args, DiscoverByIdentityKeyArgs};
///
/// let g = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
/// let args = DiscoverByIdentityKeyArgs {
///     identity_key: format!("  {}  ", g.to_uppercase()),
///     limit: None,
///     offset: None,
///     seek_permission: None,
/// };
/// assert_eq!(validate_discover_by_identity_key_args(&args).unwrap().to_hex(), g);
/// let args = DiscoverByIdentityKeyArgs { identity_key: "zz".into(), ..args };
/// assert_eq!(
///     validate_discover_by_identity_key_args(&args).unwrap_err().to_string(),
///     "The identityKey parameter must be hexadecimal string."
/// );
/// ```
pub fn validate_discover_by_identity_key_args(
    args: &DiscoverByIdentityKeyArgs,
) -> Result<PublicKey> {
    let key = crypto::validate_public_key(&args.identity_key, "identityKey")?;
    limit(args.limit)?;
    Ok(key)
}

/// The reference's `validateDiscoverByAttributesArgs`
/// (`ts-stack@edf6e03` `packages/sdk/src/wallet/validationHelpers.ts:1555-1587`),
/// which its `WalletClient` and the toolbox wallet run before any lookup
/// (`WalletClient.ts:524`, `wallet-toolbox/src/Wallet.ts:1029`; #818b, #905),
/// in its order: the attributes as `validateRecord` reads a record (at most
/// 100000 names, then none of `__proto__`, `constructor`, `prototype`,
/// `:81-103`), then 1 to 32 of them (`:1559-1562`), then each name (1 to 50
/// UTF-8 bytes, as `field name <name>`) and its value (1 to 500, as
/// `attributes.<name>`) in the order `Object.keys` walks the object built in
/// the map's order (array-index names ahead, ascending; `:1564-1565`), then
/// `limit` from 1 to 10000.
///
/// A refusal is `Error::WalletRefusal` of class `InvalidParameter` (code 6)
/// in the reference's words.
///
/// ```
/// use bsv_rs::wallet::{validate_discover_by_attributes_args, DiscoverByAttributesArgs};
/// use indexmap::IndexMap;
///
/// let mut args = DiscoverByAttributesArgs {
///     attributes: IndexMap::from([("email".to_string(), "bob".to_string())]),
///     limit: None,
///     offset: None,
///     seek_permission: None,
/// };
/// assert!(validate_discover_by_attributes_args(&args).is_ok());
/// args.attributes.clear();
/// assert_eq!(
///     validate_discover_by_attributes_args(&args).unwrap_err().to_string(),
///     "The attributes parameter must be an object containing 1-32 fields"
/// );
/// ```
pub fn validate_discover_by_attributes_args(args: &DiscoverByAttributesArgs) -> Result<()> {
    let attributes = &args.attributes;
    if attributes.len() > MAXIMUM_WALLET_COLLECTION_ITEMS {
        return Err(invalid_parameter(
            "attributes",
            &format!("an object with at most {MAXIMUM_WALLET_COLLECTION_ITEMS} properties"),
        ));
    }
    if attributes
        .keys()
        .any(|key| matches!(key.as_str(), "__proto__" | "constructor" | "prototype"))
    {
        return Err(invalid_parameter(
            "attributes",
            "an object with safe string keys",
        ));
    }
    if !(1..=MAXIMUM_DISCOVERY_ATTRIBUTES).contains(&attributes.len()) {
        return Err(invalid_parameter(
            "attributes",
            &format!("an object containing 1-{MAXIMUM_DISCOVERY_ATTRIBUTES} fields"),
        ));
    }
    for (name, value) in js_order(attributes) {
        crypto::string_length(name, &format!("field name {name}"), 1, 50)?;
        crypto::string_length(value, &format!("attributes.{name}"), 1, 500)?;
    }
    limit(args.limit)
}

/// The order `Object.entries` walks a JavaScript object built in `fields`'
/// order: array-index names ahead, ascending, then the rest as inserted.
pub(crate) fn js_order(fields: &IndexMap<String, String>) -> Vec<(&str, &str)> {
    let index = |name: &str| {
        name.parse::<u32>()
            .ok()
            .filter(|n| *n != u32::MAX && n.to_string() == name)
    };
    let mut entries: Vec<_> = fields
        .iter()
        .map(|(name, value)| (index(name), name.as_str(), value.as_str()))
        .collect();
    entries.sort_by_key(|(index, _, _)| index.map_or((1, 0), |n| (0, n)));
    entries
        .into_iter()
        .map(|(_, name, value)| (name, value))
        .collect()
}
