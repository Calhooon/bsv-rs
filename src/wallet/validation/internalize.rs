//! Validation of `internalizeAction` arguments.
//!
//! BRC-100 at `5119a9b` (`wallet/0100.md:867`) bounds a basket insertion's
//! `customInstructions` at 1,000 UTF-8 bytes and says a longer string must be
//! rejected; the TypeScript SDK's `validateBasketInsertion` carries the same
//! bound in bytes (`validationHelpers.ts:942-946`). The createAction output's
//! `customInstructions` carries no bound in either, and none here.

use super::validate_optional_string_length;
use crate::error::Result;
use crate::wallet::types::InternalizeActionArgs;

/// The most UTF-8 bytes a basket insertion's `customInstructions` may carry.
const MAX_INSERTION_CUSTOM_INSTRUCTIONS_BYTES: usize = 1000;

/// Validates internalize action arguments.
///
/// Every output's `insertionRemittance.customInstructions`, when present, is at
/// most 1,000 UTF-8 bytes (`str::len`, bytes not characters). A longer one is
/// refused with `Error::WalletError` naming the field with its output index and
/// the byte count: `Invalid outputs[1].insertionRemittance.customInstructions:
/// must be no more than 1000 bytes, got 1001`. BRC-100's scoped exception for a
/// supported module (such as BRC-207) is not modelled: no such module is.
pub fn validate_internalize_action_args(args: &InternalizeActionArgs) -> Result<()> {
    for (index, output) in args.outputs.iter().enumerate() {
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
