//! The processor's validation of a request's arguments ahead of the wallet
//! call and of the wallet's result after it (bsv-rs#216), in the reference's
//! rules and words: `validateWalletArgs` (`ts-stack@edf6e03`
//! `WalletArgumentValidation.ts:36-121`, the rules in `validationHelpers.ts`)
//! and `validateWalletResult` through `#invokeValidatedWallet`
//! (`WalletWireProcessor.ts:2421-2431`, the checks in
//! `WalletResultValidation.ts:2179-2306`).
//!
//! An argument refused is `WERR_INVALID_PARAMETER` (`WERR_INVALID_PARAMETER.ts`),
//! code 6, `The <parameter> parameter must be <mustBe>`; the outer catch keeps
//! a code in 2 to 8 (`WalletWireProcessor.ts:2379-2384`). A result refused is
//! a plain `Error` (`WalletResultValidation.ts:510-512`), code 1,
//! `Invalid <call> result <field>: expected <expectation>`. A rule the
//! processor's reader already enforces, as the reference's reader does (the
//! security level, a key-related counterparty that is no point, the
//! data-type flag, a 32-byte hash or HMAC read as 32 bytes), or the crate's
//! types carry (a boolean, a `u8`) is not repeated here; the two linkage
//! calls' keys, read raw as the reference reads them, are judged here (#226).

use super::encoding::WireReader;
use super::requests::{RevealCounterpartyRequest, RevealSpecificRequest};
use crate::primitives::PublicKey;
use crate::wallet::interface::{RevealCounterpartyKeyLinkageArgs, RevealSpecificKeyLinkageArgs};
use crate::wallet::validation::crypto;
use crate::wallet::{
    CreateHmacArgs, CreateSignatureArgs, DecryptArgs, EncryptArgs, GetPublicKeyArgs,
    RevealCounterpartyKeyLinkageResult, RevealSpecificKeyLinkageResult, VerifyHmacArgs,
    VerifySignatureArgs,
};
use crate::Error;
use std::fmt::Display;

/// `walletErrors.invalidParameter` (`WalletError.ts:78`), the code
/// `WERR_INVALID_PARAMETER` carries.
const INVALID_PARAMETER: u8 = 6;
/// `walletErrors.unknownError` (`WalletError.ts:72`).
const UNKNOWN_ERROR: u8 = 1;
/// `MAX_WALLET_WIRE_FRAME_BYTES` (`WalletWire.ts:9`), `validateByteArray`'s
/// and the result's `bytes` default bound: the substrates' one byte bound,
/// `byte_fields::MAX_BYTES` (#532).
const MAX_WALLET_WIRE_FRAME_BYTES: usize = crate::wallet::substrates::byte_fields::MAX_BYTES;
/// A refusal the processor frames with its own code and words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Refusal {
    pub(super) code: u8,
    pub(super) words: String,
}

impl Refusal {
    /// A refusal with the unknownError code (1).
    pub(super) fn plain(words: impl Into<String>) -> Self {
        Self {
            code: UNKNOWN_ERROR,
            words: words.into(),
        }
    }
}

impl From<Error> for Refusal {
    /// The reference's outer catch (`WalletWireProcessor.ts:2379-2387`): an
    /// explicit wallet code or unknownError, and the error's own words.
    fn from(error: Error) -> Self {
        Self {
            code: explicit_wallet_code(&error).unwrap_or(UNKNOWN_ERROR),
            words: wire_message(&error),
        }
    }
}

/// The code of an explicit wallet error, 2 to 8 (`WalletWireProcessor.ts:2405-2416`:
/// a `WalletError`, or a `WERR_` error, whose `code` lies in unsupportedAction
/// to abortRefused): a [`Error::WalletRefusal`]'s or [`Error::AbortAccepted`]'s
/// class with an SDK code (`WalletRefusalClass::wire_code`, #137), which keeps
/// its words and its code on the wire. Every other error has none, a class whose code is its
/// name among them (the toolbox's `WERR_*`, whose `code` is no integer).
/// A `WERR_REVIEW_ACTIONS` with its results is code 5 and its words, its
/// results not on the wire (#327).
pub(super) fn explicit_wallet_code(error: &Error) -> Option<u8> {
    match error {
        Error::WalletRefusal { class, .. } => class.wire_code(),
        Error::AbortAccepted(a) => a.class.wire_code(),
        Error::WalletReviewActions(_) => {
            crate::error::WalletRefusalClass::ReviewActions.wire_code()
        }
        _ => None,
    }
}

/// The words an error frame carries: the reference writes `error.message`
/// (`WalletWireProcessor.ts:2387`), never this crate's `Display` prefix. A
/// `WalletError` is its own words (the replacement's constant, a stub's
/// refusal), a `WalletRefusal` or `AbortAccepted` its message (#137, #439);
/// every other variant, the processor's own reading of the request, is this
/// crate's own sentence, written as its `Display` reads.
fn wire_message(error: &Error) -> String {
    match error {
        Error::WalletError(words) | Error::WalletRefusal { message: words, .. } => words.clone(),
        Error::AbortAccepted(a) => a.message.clone(),
        other => other.to_string(),
    }
}

type Checked<T = ()> = Result<T, Refusal>;

/// `new WERR_INVALID_PARAMETER(name, mustBe)` (`validationHelpers.ts:77-79`).
fn invalid(name: &str, must_be: impl Display) -> Refusal {
    Refusal {
        code: INVALID_PARAMETER,
        words: format!("The {name} parameter must be {must_be}"),
    }
}

/// The result checks' `invalid` (`WalletResultValidation.ts:510-512`).
fn invalid_result(call: &str, field: &str, expectation: impl Display) -> Refusal {
    Refusal::plain(format!(
        "Invalid {call} result {field}: expected {expectation}"
    ))
}

// ============================================================================
// The arguments (`validationHelpers.ts`)
// ============================================================================

/// The common typed checks use the same validators as ProtoWallet (#415).
#[cfg(test)]
fn byte_array(length: usize, name: &str) -> Checked {
    crypto::byte_array(length, name).map_err(Into::into)
}

/// `validateAbortActionArgs` (`:893-899`, `WalletArgumentValidation.ts:44-46`):
/// the reference a base64 string (`validateBase64String`, `:488-498`). The
/// processor builds it from the request's bytes as the reference does
/// (`toBase64`, `WalletWireProcessor.ts:786`), a canonical encoding, so the
/// one rule it can break is the empty string's (`:491`, `invalidBase64`,
/// `:439-441`).
pub(super) fn abort_action_args(reference: &str) -> Checked {
    if reference.is_empty() {
        return Err(invalid("reference", "valid base64 string"));
    }
    Ok(())
}

/// `validateGetPublicKeyArgs` (`:1717-1732`): for the identity key the
/// privilege alone (the wire carries no protocol, key ID or counterparty),
/// otherwise the encryption arguments.
pub(super) fn get_public_key_args(args: &GetPublicKeyArgs) -> Checked {
    crypto::get_public_key_args(args)
        .map(|_| ())
        .map_err(Into::into)
}

/// `validateWalletEncryptArgs` (`:1752-1756`).
pub(super) fn encrypt_args(args: &EncryptArgs) -> Checked {
    crypto::encrypt_args(args).map_err(Into::into)
}

/// `validateWalletDecryptArgs` (`:1758-1762`).
pub(super) fn decrypt_args(args: &DecryptArgs) -> Checked {
    crypto::decrypt_args(args).map_err(Into::into)
}

/// The four signature/HMAC validators shared with ProtoWallet (#415).
pub(super) fn create_hmac_args(args: &CreateHmacArgs) -> Checked {
    crypto::create_hmac_args(args).map_err(Into::into)
}

pub(super) fn verify_hmac_args(args: &VerifyHmacArgs) -> Checked {
    crypto::verify_hmac_args(args).map_err(Into::into)
}

pub(super) fn create_signature_args(args: &CreateSignatureArgs) -> Checked {
    crypto::create_signature_args(args).map_err(Into::into)
}

pub(super) fn verify_signature_args(args: &VerifySignatureArgs) -> Checked {
    crypto::verify_signature_args(args).map_err(Into::into)
}

/// `isValidCompressedPublicKey` (`Secp256k1Validation.ts:15-22`): a `02` or
/// `03` prefix, x below the field prime, a point on the curve.
fn compressed_key(bytes: &[u8]) -> Option<PublicKey> {
    crypto::public_key(bytes, "publicKey").ok()
}

/// `validateRevealCounterpartyKeyLinkageArgs` (`:1734-1741`): the
/// counterparty, the verifier, then the privilege without seekPermission;
/// the args the wallet is called with (#226).
pub(super) fn reveal_counterparty_args(
    request: RevealCounterpartyRequest,
) -> Checked<RevealCounterpartyKeyLinkageArgs> {
    let (counterparty, verifier) = crypto::reveal_counterparty_args(
        &request.counterparty,
        &request.verifier,
        request.privileged,
        request.privileged_reason.as_deref(),
    )?;
    Ok(RevealCounterpartyKeyLinkageArgs {
        counterparty,
        verifier,
        privileged: request.privileged,
        privileged_reason: request.privileged_reason,
    })
}

/// `validateRevealSpecificKeyLinkageArgs` (`:1743-1750`): the counterparty
/// (`validateCounterparty` `:190-193`: absent, it reaches `validateHexString`
/// `:523`, a point by the reader otherwise), the verifier, the protocol, the
/// key ID, the privilege; the args the wallet is called with (#226).
pub(super) fn reveal_specific_args(
    request: RevealSpecificRequest,
) -> Checked<RevealSpecificKeyLinkageArgs> {
    let (counterparty, verifier) = crypto::reveal_specific_args(
        request.counterparty.as_ref(),
        &request.verifier,
        &request.protocol_id,
        &request.key_id,
        request.privileged,
        request.privileged_reason.as_deref(),
    )?;
    Ok(RevealSpecificKeyLinkageArgs {
        counterparty: counterparty.clone(),
        verifier,
        protocol_id: request.protocol_id,
        key_id: request.key_id,
        privileged: request.privileged,
        privileged_reason: request.privileged_reason,
    })
}

/// getHeaderForHeight's height (`WalletWireProcessor.ts:1670-1675`): read by
/// `readVarIntNumStrict(false)`, then `#requireInteger(..., 1, 0xffffffff)`
/// (`:138-148`), a plain `Error`, ahead of `#assertRequestConsumed`.
pub(super) fn read_header_height(reader: &mut WireReader<'_>) -> Result<u32, Refusal> {
    let height = reader.read_var_int_num_strict()?;
    match u32::try_from(height) {
        Ok(height) if height >= 1 => Ok(height),
        _ => Err(Refusal::plain(super::integer_refusal(
            "getHeaderForHeight height",
            height,
            1,
            u32::MAX.into(),
        ))),
    }
}

// ============================================================================
// The results (`WalletResultValidation.ts`)
// ============================================================================

/// `bytes(value, call, field)` (`:868-906`) on a length: at most the frame.
fn result_bytes(length: usize, call: &str, field: &str) -> Checked {
    if length > MAX_WALLET_WIRE_FRAME_BYTES {
        return Err(invalid_result(
            call,
            field,
            format!("at most {MAX_WALLET_WIRE_FRAME_BYTES} bytes"),
        ));
    }
    Ok(())
}

/// encrypt's ciphertext and decrypt's plaintext (`:2210-2215`).
pub(super) fn bytes_result(bytes: &[u8], call: &str, field: &str) -> Checked {
    result_bytes(bytes.len(), call, field)
}

/// getPublicKey's key (`:2207-2209`, `publicKey` `:928-933` over `hex`
/// `:917-926`): an even-length hex string of 33 bytes that is a valid
/// compressed key; the 33 bytes the frame carries.
pub(super) fn public_key_result(public_key: &str) -> Checked<Vec<u8>> {
    const CALL: &str = "getPublicKey";
    let is_hex =
        public_key.len().is_multiple_of(2) && public_key.bytes().all(|b| b.is_ascii_hexdigit());
    if !is_hex {
        return Err(invalid_result(
            CALL,
            "publicKey",
            "an even-length hex string",
        ));
    }
    if public_key.len() != 66 {
        return Err(invalid_result(CALL, "publicKey", "33 hexadecimal bytes"));
    }
    let bytes = crate::primitives::from_hex(public_key)?;
    if compressed_key(&bytes).is_none() {
        return Err(invalid_result(
            CALL,
            "publicKey",
            "a valid compressed secp256k1 public key",
        ));
    }
    Ok(bytes)
}

/// createSignature's signature (`:2219-2225`): at most 72 bytes, canonical DER.
pub(super) fn signature_result(signature: &[u8]) -> Checked {
    super::result_validation::signature(signature).map_err(Into::into)
}

/// getHeight's height (`:2293-2295`, `rangedInteger` `:946-961`): 1 to 2^32 - 1.
pub(super) fn height_result(height: u32) -> Checked<u32> {
    if height == 0 {
        return Err(invalid_result(
            "getHeight",
            "height",
            format!("an integer from 1 to {}", u32::MAX),
        ));
    }
    Ok(height)
}

/// `string(value, call, field, min, max)` (`:908-915`).
fn result_string(value: &str, call: &str, field: &str, min: usize, max: usize) -> Checked {
    if value.len() < min || value.len() > max {
        return Err(invalid_result(
            call,
            field,
            format!("{min}\u{2013}{max} UTF-8 bytes"),
        ));
    }
    Ok(())
}

/// getVersion's version (`:2304-2306`): 7 to 30 UTF-8 bytes, BRC-100's
/// "wallet's version string (e.g., `vendor-1.0.0`)" (`wallet/0100.md:2517`
/// at `5119a9b`). getNetwork's rule (`:2299-2303`, mainnet or testnet) is
/// the `Network` type's: a wallet answers one of its two values, so the
/// processor has no third to refuse (bsv-rs#222).
pub(super) fn version_result(version: &str) -> Checked {
    result_string(version, "getVersion", "version", 7, 30)
}

/// The shared result rows also validate processor linkages before encoding.
pub(super) fn reveal_counterparty_result(
    args: &RevealCounterpartyKeyLinkageArgs,
    result: &RevealCounterpartyKeyLinkageResult,
) -> Checked {
    super::result_validation::Binding::counterparty(args)?.check(result)?;
    Ok(())
}

/// Specific linkage uses the same field order and request bindings as HTTP.
pub(super) fn reveal_specific_result(
    args: &RevealSpecificKeyLinkageArgs,
    result: &RevealSpecificKeyLinkageResult,
) -> Checked {
    super::result_validation::Binding::specific(args)?.check(result)?;
    Ok(())
}

#[cfg(test)]
fn iso_timestamp(value: &str, call: &str, field: &str) -> Checked {
    crate::wallet::substrates::result_values::timestamp::validate(value, call, field)
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_byte_array_past_the_frame_bound_is_refused_with_code_6() {
        assert_eq!(byte_array(MAX_WALLET_WIRE_FRAME_BYTES, "plaintext"), Ok(()));
        assert_eq!(
            byte_array(MAX_WALLET_WIRE_FRAME_BYTES + 1, "plaintext"),
            Err(Refusal {
                code: 6,
                words: "The plaintext parameter must be at most 268435456 bytes".into()
            })
        );
        assert_eq!(
            result_bytes(MAX_WALLET_WIRE_FRAME_BYTES + 1, "encrypt", "ciphertext"),
            Err(Refusal::plain(
                "Invalid encrypt result ciphertext: expected at most 268435456 bytes"
            ))
        );
    }

    #[test]
    fn date_parse_ranges_follow_v8() {
        for good in [
            "2024-02-30T00:00:00Z",
            "2024-01-01T24:00Z",
            "2024-01-01T24:00:00.000Z",
            "2024-01-01T00:00:00.123456789Z",
            "2024-01-01T10:00+05:00",
            "2024-01-01T00:00+23:59",
            "2024-01-01T10:00:00.5-00:00",
        ] {
            assert_eq!(iso_timestamp(good, "c", "f"), Ok(()), "{good}");
        }
        for bad in [
            "2024-13-01T00:00Z",
            "2024-01-01T25:00Z",
            "2024-01-01T24:00:01Z",
            "2024-01-01T00:00:60Z",
            "2024-01-01T00Z",
            "2024-01-01T00:00:00.Z",
            "2024-01-01T1:00Z",
            "2024-01-32T00:00Z",
            "2024-00-01T00:00Z",
            "2024-01-01T00:00+24:00",
            "2024-01-01T10:00:00+05:60",
            "2024-01-01T00:00:00 Z",
            "2024-01-01Tfoo Z",
            "2024-01-01TZ",
        ] {
            assert_eq!(
                iso_timestamp(bad, "c", "f"),
                Err(Refusal::plain(
                    "Invalid c result f: expected a valid ISO timestamp"
                )),
                "{bad}"
            );
        }
    }
}
