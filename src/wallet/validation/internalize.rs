//! Validation of `internalizeAction` arguments.
//!
//! BRC-100 at `5119a9b` (`wallet/0100.md:867`) bounds a basket insertion's
//! `customInstructions` at 1,000 UTF-8 bytes and says a longer string must be
//! rejected; the TypeScript SDK's `validateBasketInsertion` carries the same
//! bound in bytes (`validationHelpers.ts:942-946`). The createAction output's
//! `customInstructions` carries no bound in either, and none here.
//!
//! Each output is judged in the reference's `validateInternalizeOutput` order
//! (`ts-stack@edf6e03` `validationHelpers.ts:966-984`): the protocol
//! (`:968-970`), then the one remittance its protocol names and no other
//! (`:971-977`), then the remittances' fields (`:978-983`; bsv-rs#384).

use super::validate_optional_string_length;
use crate::error::{Error, Result, WalletRefusalClass};
use crate::wallet::types::InternalizeActionArgs;

/// The most UTF-8 bytes a basket insertion's `customInstructions` may carry.
const MAX_INSERTION_CUSTOM_INSTRUCTIONS_BYTES: usize = 1000;

/// Validates internalize action arguments.
///
/// Per output, in the reference's order (`ts-stack@edf6e03`
/// `validationHelpers.ts:966-984`):
///
/// 1. the protocol is `wallet payment` or `basket insertion`, else
///    `The protocol parameter must be 'basket insertion' or 'wallet payment'`;
/// 2. a wallet payment carries a `paymentRemittance` and no
///    `insertionRemittance`, else `The output remittance parameter must be
///    only paymentRemittance for wallet payment`, and a basket insertion the
///    twin, `The output remittance parameter must be only insertionRemittance
///    for basket insertion` (bsv-rs#384);
/// 3. the insertion's `customInstructions`, when present, is at most 1,000
///    UTF-8 bytes (`str::len`, bytes not characters): `Error::WalletError`
///    naming the field with its output index and the byte count,
///    `Invalid outputs[1].insertionRemittance.customInstructions: must be no
///    more than 1000 bytes, got 1001`.
///
/// The first two are [`Error::WalletRefusal`] of class
/// [`WalletRefusalClass::InvalidParameter`] in the reference's words, which
/// name no output index. BRC-100's scoped exception for a supported module
/// (such as BRC-207) is not modelled: no such module is.
///
/// [`Error::WalletRefusal`]: crate::error::Error::WalletRefusal
/// [`WalletRefusalClass::InvalidParameter`]: crate::error::WalletRefusalClass::InvalidParameter
pub fn validate_internalize_action_args(args: &InternalizeActionArgs) -> Result<()> {
    for (index, output) in args.outputs.iter().enumerate() {
        if let Some(message) = remittance_error(
            &output.protocol,
            output.payment_remittance.is_some(),
            output.insertion_remittance.is_some(),
        ) {
            return Err(Error::WalletRefusal {
                class: WalletRefusalClass::InvalidParameter,
                message: message.into(),
            });
        }
        if let Some(insertion) = &output.insertion_remittance {
            validate_optional_string_length(
                insertion.custom_instructions.as_deref(),
                &format!("outputs[{index}].insertionRemittance.customInstructions"),
                None,
                Some(MAX_INSERTION_CUSTOM_INSTRUCTIONS_BYTES),
            )?;
        }
    }
    Ok(())
}

/// The protocol and its one remittance (`validationHelpers.ts:968-977`).
pub(crate) fn remittance_error(
    protocol: &str,
    payment: bool,
    insertion: bool,
) -> Option<&'static str> {
    match protocol {
        "wallet payment" if !payment || insertion => Some(
            "The output remittance parameter must be only paymentRemittance for wallet payment",
        ),
        "basket insertion" if !insertion || payment => Some(
            "The output remittance parameter must be only insertionRemittance for basket insertion",
        ),
        "wallet payment" | "basket insertion" => None,
        _ => Some("The protocol parameter must be 'basket insertion' or 'wallet payment'"),
    }
}
