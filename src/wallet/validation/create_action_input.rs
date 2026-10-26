//! Validation of a `createAction` input.
//!
//! The reference's `validateCreateActionInput` (`ts-stack@edf6e03`
//! `validationHelpers.ts:587-614`): an `unlockingScript` of one or more hex
//! characters (`:595`, `:522-530`), and BRC-100's positive integer for
//! `unlockingScriptLength` (`brcs@5119a9b` `wallet/0100.md:649`), which the
//! reference's helper does not enforce (`:598`; bsv-rs#282).

use super::{
    parse_wallet_outpoint, validate_description_5_2000, validate_hex_string, CreateActionInputRaw,
    ValidCreateActionInput,
};
use crate::error::{Error, Result};

/// Validates a create action input.
///
/// An `unlockingScript` of no hex characters (empty, or whitespace alone) is
/// refused as the reference's `validateOptionalHexString` refuses it
/// (`ts-stack@edf6e03` `validationHelpers.ts:595`, `:522-530`), class
/// [`WalletRefusalClass::InvalidParameter`] in its words: `The unlockingScript
/// parameter must be hexadecimal string.` An `unlockingScriptLength` of 0 is
/// refused as BRC-100's positive integer (`brcs@5119a9b` `wallet/0100.md:649`)
/// in `#requireInteger`'s form, `Invalid createAction input
/// unlockingScriptLength: expected an integer from 1 to 4294967295, received
/// 0`, the same class; the reference's helper permits 0 (`:598`, a minimum
/// of 0, though its `ValidCreateActionInput` types the field `PositiveInteger`
/// at `:577`; bsv-rs#282).
///
/// [`WalletRefusalClass::InvalidParameter`]: crate::error::WalletRefusalClass::InvalidParameter
pub fn validate_create_action_input(
    input: &CreateActionInputRaw,
) -> Result<ValidCreateActionInput> {
    if input.unlocking_script.is_none() && input.unlocking_script_length.is_none() {
        return Err(Error::WalletError(
            "unlockingScript or unlockingScriptLength must be provided".to_string(),
        ));
    }

    let unlocking_script = input
        .unlocking_script
        .as_ref()
        .map(|s| validate_hex_string(s, "unlockingScript", None, None))
        .transpose()?
        .map(|s| {
            if s.is_empty() {
                return Err(invalid_parameter(
                    "The unlockingScript parameter must be hexadecimal string.",
                ));
            }
            crate::primitives::from_hex(&s)
        })
        .transpose()?;

    let unlocking_script_length = input
        .unlocking_script_length
        .or_else(|| unlocking_script.as_ref().map(|s| s.len() as u32))
        .unwrap_or(0);

    if unlocking_script_length == 0 {
        return Err(invalid_parameter(crate::wallet::wire::integer_refusal(
            "createAction input unlockingScriptLength",
            0,
            1,
            u32::MAX.into(),
        )));
    }

    if let Some(ref script) = unlocking_script {
        if unlocking_script_length != script.len() as u32 {
            return Err(Error::WalletError(
                "unlockingScriptLength must match unlockingScript length if both provided"
                    .to_string(),
            ));
        }
    }

    Ok(ValidCreateActionInput {
        outpoint: parse_wallet_outpoint(&input.outpoint)?,
        input_description: validate_description_5_2000(
            &input.input_description,
            "inputDescription",
        )?,
        sequence_number: input.sequence_number.unwrap_or(0xffffffff),
        unlocking_script,
        unlocking_script_length,
    })
}

/// A `WERR_INVALID_PARAMETER` refusal in the given words (code 6).
fn invalid_parameter(message: impl Into<String>) -> Error {
    Error::WalletRefusal {
        class: crate::error::WalletRefusalClass::InvalidParameter,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::super::{validate_create_action_args, CreateActionArgsRaw};
    use super::*;

    fn create_action_input(
        unlocking_script: Option<&str>,
        unlocking_script_length: Option<u32>,
    ) -> CreateActionInputRaw {
        CreateActionInputRaw {
            outpoint: format!("{}.0", "11".repeat(32)),
            input_description: "spend the coin".to_string(),
            unlocking_script: unlocking_script.map(str::to_string),
            unlocking_script_length,
            sequence_number: None,
        }
    }

    fn invalid_parameter_refusal(message: &str) -> Error {
        Error::WalletRefusal {
            class: crate::error::WalletRefusalClass::InvalidParameter,
            message: message.to_string(),
        }
    }

    const EMPTY_UNLOCKING_SCRIPT: &str =
        "The unlockingScript parameter must be hexadecimal string.";
    const ZERO_UNLOCKING_SCRIPT_LENGTH: &str = "Invalid createAction input unlockingScriptLength: \
        expected an integer from 1 to 4294967295, received 0";

    #[test]
    fn an_empty_create_action_unlocking_script_is_refused_in_the_reference_words() {
        for (script, length) in [(Some(""), None), (Some(""), Some(0)), (Some("  "), None)] {
            let err = validate_create_action_input(&create_action_input(script, length))
                .expect_err("an empty unlockingScript is no hex string");
            assert_eq!(err, invalid_parameter_refusal(EMPTY_UNLOCKING_SCRIPT));
        }
    }

    #[test]
    fn a_zero_create_action_unlocking_script_length_is_refused_as_brc100_positive_integer() {
        let err = validate_create_action_input(&create_action_input(None, Some(0)))
            .expect_err("BRC-100 types unlockingScriptLength a positive integer");
        assert_eq!(err, invalid_parameter_refusal(ZERO_UNLOCKING_SCRIPT_LENGTH));
    }

    #[test]
    fn the_create_action_args_refuse_an_empty_unlocking_script_and_a_zero_length() {
        let args = |input| CreateActionArgsRaw {
            description: "pay the invoice".to_string(),
            input_beef: None,
            inputs: vec![input],
            outputs: vec![],
            lock_time: None,
            version: None,
            labels: vec![],
            options: None,
        };
        let empty = validate_create_action_args(&args(create_action_input(Some(""), None)));
        assert_eq!(
            empty.unwrap_err(),
            invalid_parameter_refusal(EMPTY_UNLOCKING_SCRIPT)
        );
        let zero = validate_create_action_args(&args(create_action_input(None, Some(0))));
        assert_eq!(
            zero.unwrap_err(),
            invalid_parameter_refusal(ZERO_UNLOCKING_SCRIPT_LENGTH)
        );
        let one = validate_create_action_args(&args(create_action_input(Some("51"), None)))
            .expect("a one-byte unlocking script");
        assert_eq!(one.inputs[0].unlocking_script.as_deref(), Some(&[0x51][..]));
        assert_eq!(one.inputs[0].unlocking_script_length, 1);
        let later = validate_create_action_args(&args(create_action_input(None, Some(1))))
            .expect("a length of 1 for a script signAction supplies");
        assert_eq!(later.inputs[0].unlocking_script_length, 1);
    }
}
