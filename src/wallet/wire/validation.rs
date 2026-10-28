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
use crate::wallet::types::{Counterparty, Protocol};
use crate::wallet::validation::crypto;
use crate::wallet::{
    CreateHmacArgs, CreateSignatureArgs, DecryptArgs, EncryptArgs, GetPublicKeyArgs,
    RevealCounterpartyKeyLinkageResult, RevealSpecificKeyLinkageResult, VerifyHmacArgs,
    VerifySignatureArgs,
};
use crate::Error;
pub(super) use crypto::is_canonical_der_signature;
use std::fmt::Display;

/// `walletErrors.invalidParameter` (`WalletError.ts:78`), the code
/// `WERR_INVALID_PARAMETER` carries.
const INVALID_PARAMETER: u8 = 6;
/// `walletErrors.unknownError` (`WalletError.ts:72`).
const UNKNOWN_ERROR: u8 = 1;
/// `MAX_WALLET_WIRE_FRAME_BYTES` (`WalletWire.ts:9`), `validateByteArray`'s
/// and the result's `bytes` default bound.
const MAX_WALLET_WIRE_FRAME_BYTES: usize = 256 * 1024 * 1024;
/// The DER signature's bound (`validationHelpers.ts:1801`, `WalletResultValidation.ts:2220`).
const MAX_SIGNATURE_BYTES: usize = 72;
/// The canonical anyone key, `PrivateKey(1)`'s (`WalletResultValidation.ts:221`).
const ANYONE_PUBLIC_KEY: &str =
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
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
/// to abortRefused): a [`Error::WalletRefusal`]'s class with an SDK code
/// (`WalletRefusalClass::wire_code`, #137), which keeps its words and its
/// code on the wire. Every other error has none, a class whose code is its
/// name among them (the toolbox's `WERR_*`, whose `code` is no integer).
/// A `WERR_REVIEW_ACTIONS` with its results is code 5 and its words, its
/// results not on the wire (#327).
pub(super) fn explicit_wallet_code(error: &Error) -> Option<u8> {
    match error {
        Error::WalletRefusal { class, .. } => class.wire_code(),
        Error::WalletReviewActions(_) => {
            crate::error::WalletRefusalClass::ReviewActions.wire_code()
        }
        _ => None,
    }
}

/// The words an error frame carries: the reference writes `error.message`
/// (`WalletWireProcessor.ts:2387`), never this crate's `Display` prefix. A
/// `WalletError` is its own words (the replacement's constant, a stub's
/// refusal), a `WalletRefusal` its message (#137); every other variant, the
/// processor's own reading of the request, is this crate's own sentence,
/// written as its `Display` reads.
fn wire_message(error: &Error) -> String {
    match error {
        Error::WalletError(words) | Error::WalletRefusal { message: words, .. } => words.clone(),
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
fn string_length(value: &str, name: &str, min: usize, max: usize) -> Checked {
    crypto::string_length(value, name, min, max).map_err(Into::into)
}

fn byte_array(length: usize, name: &str) -> Checked {
    crypto::byte_array(length, name).map_err(Into::into)
}

fn protocol(protocol: &Protocol) -> Checked {
    crypto::protocol(protocol).map_err(Into::into)
}

fn privilege(privileged: Option<bool>, reason: Option<&str>) -> Checked {
    crypto::privilege(privileged, reason).map_err(Into::into)
}

fn encryption(
    protocol_id: &Protocol,
    key_id: &str,
    privileged: Option<bool>,
    reason: Option<&str>,
) -> Checked {
    crypto::encryption(protocol_id, key_id, privileged, reason).map_err(Into::into)
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
    let reason = args.privileged_reason.as_deref();
    match (&args.protocol_id, &args.key_id) {
        (Some(protocol_id), Some(key_id)) if !args.identity_key => {
            encryption(protocol_id, key_id, args.privileged, reason)
        }
        _ => privilege(args.privileged, reason),
    }
}

/// `validateWalletEncryptArgs` (`:1752-1756`).
pub(super) fn encrypt_args(args: &EncryptArgs) -> Checked {
    let reason = args.privileged_reason.as_deref();
    encryption(&args.protocol_id, &args.key_id, args.privileged, reason)?;
    byte_array(args.plaintext.len(), "plaintext")
}

/// `validateWalletDecryptArgs` (`:1758-1762`).
pub(super) fn decrypt_args(args: &DecryptArgs) -> Checked {
    let reason = args.privileged_reason.as_deref();
    encryption(&args.protocol_id, &args.key_id, args.privileged, reason)?;
    byte_array(args.ciphertext.len(), "ciphertext")
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
    if !matches!(bytes.first(), Some(0x02 | 0x03)) {
        return None;
    }
    PublicKey::from_bytes(bytes).ok()
}

/// `validatePublicKey` (`:182-188`) on 33 bytes the reader read raw: their
/// hex is 66 characters, so the point check is what can fail.
fn public_key(bytes: &[u8; 33], name: &str) -> Checked<PublicKey> {
    compressed_key(bytes).ok_or_else(|| invalid(name, "a valid compressed secp256k1 public key"))
}

/// `validateRevealCounterpartyKeyLinkageArgs` (`:1734-1741`): the
/// counterparty, the verifier, then the privilege without seekPermission;
/// the args the wallet is called with (#226).
pub(super) fn reveal_counterparty_args(
    request: RevealCounterpartyRequest,
) -> Checked<RevealCounterpartyKeyLinkageArgs> {
    let counterparty = public_key(&request.counterparty, "counterparty")?;
    let verifier = public_key(&request.verifier, "verifier")?;
    privilege(request.privileged, request.privileged_reason.as_deref())?;
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
    let counterparty = request
        .counterparty
        .ok_or_else(|| invalid("counterparty", "a hexadecimal string"))?;
    let verifier = public_key(&request.verifier, "verifier")?;
    protocol(&request.protocol_id)?;
    string_length(&request.key_id, "keyID", 1, 800)?;
    privilege(request.privileged, request.privileged_reason.as_deref())?;
    Ok(RevealSpecificKeyLinkageArgs {
        counterparty,
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
    const CALL: &str = "createSignature";
    if signature.len() > MAX_SIGNATURE_BYTES {
        return Err(invalid_result(
            CALL,
            "signature",
            format!("at most {MAX_SIGNATURE_BYTES} bytes"),
        ));
    }
    if !is_canonical_der_signature(signature) {
        return Err(invalid_result(
            CALL,
            "signature",
            "a canonical DER-encoded ECDSA signature",
        ));
    }
    Ok(())
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

/// The two linkages' bytes (`validateKeyLinkage`, `:2165-2177`; the three
/// keys are `PublicKey`s by their type).
fn linkage_bytes(linkage: &crate::wallet::KeyLinkageResult, call: &str) -> Checked {
    result_bytes(linkage.encrypted_linkage.len(), call, "encryptedLinkage")?;
    result_bytes(
        linkage.encrypted_linkage_proof.len(),
        call,
        "encryptedLinkageProof",
    )
}

/// revealCounterpartyKeyLinkage's result (`:2226-2241`): the linkage, the
/// revelation time, then the requested verifier and counterparty.
pub(super) fn reveal_counterparty_result(
    args: &RevealCounterpartyKeyLinkageArgs,
    result: &RevealCounterpartyKeyLinkageResult,
) -> Checked {
    const CALL: &str = "revealCounterpartyKeyLinkage";
    linkage_bytes(&result.linkage, CALL)?;
    iso_timestamp(&result.revelation_time, CALL, "revelationTime")?;
    if result.linkage.verifier != args.verifier {
        return Err(invalid_result(CALL, "verifier", "the requested verifier"));
    }
    if result.linkage.counterparty != args.counterparty {
        return Err(invalid_result(
            CALL,
            "counterparty",
            "the requested counterparty",
        ));
    }
    Ok(())
}

/// revealSpecificKeyLinkage's result (`:2242-2281`): the linkage, the
/// protocol name 5 to 400 bytes, the key ID 1 to 800 (the level and
/// proofType by their types), then the requested verifier, counterparty
/// (the prover for self, the anyone key for anyone), protocol and key ID.
pub(super) fn reveal_specific_result(
    args: &RevealSpecificKeyLinkageArgs,
    result: &RevealSpecificKeyLinkageResult,
) -> Checked {
    const CALL: &str = "revealSpecificKeyLinkage";
    let linkage = &result.linkage;
    linkage_bytes(linkage, CALL)?;
    result_string(
        &result.protocol.protocol_name,
        CALL,
        "protocolID[1]",
        5,
        400,
    )?;
    result_string(&result.key_id, CALL, "keyID", 1, 800)?;
    if linkage.verifier != args.verifier {
        return Err(invalid_result(CALL, "verifier", "the requested verifier"));
    }
    match &args.counterparty {
        Counterparty::Self_ if linkage.counterparty != linkage.prover => {
            return Err(invalid_result(
                CALL,
                "counterparty",
                "the prover's identity key for counterparty self",
            ));
        }
        Counterparty::Anyone if linkage.counterparty.to_hex() != ANYONE_PUBLIC_KEY => {
            return Err(invalid_result(
                CALL,
                "counterparty",
                "the canonical anyone public key",
            ));
        }
        Counterparty::Other(key) if linkage.counterparty != *key => {
            return Err(invalid_result(
                CALL,
                "counterparty",
                "the requested counterparty",
            ));
        }
        _ => {}
    }
    if result.protocol != args.protocol_id {
        return Err(invalid_result(CALL, "protocolID", "the requested protocol"));
    }
    if result.key_id != args.key_id {
        return Err(invalid_result(CALL, "keyID", "the requested key ID"));
    }
    Ok(())
}

/// `isoTimestamp` (`:992-999`): 1 to 64 bytes, the pattern
/// `^\d{4}-\d{2}-\d{2}T.*(?:Z|[+-]\d{2}:\d{2})$`, then a time `Date.parse`
/// reads, which for a string of that pattern is the ECMAScript date-time
/// format: `HH:mm`, `:ss` and a fraction optional, the fields in range
/// (24:00 alone at the end of a day), an offset's hours to 23.
fn iso_timestamp(value: &str, call: &str, field: &str) -> Checked {
    result_string(value, call, field, 1, 64)?;
    let bytes = value.as_bytes();
    let digits = |range: std::ops::Range<usize>| {
        bytes
            .get(range)
            .filter(|d| d.iter().all(u8::is_ascii_digit))
    };
    let zone_ok = match bytes.last() {
        Some(b'Z') => true,
        _ => {
            let n = bytes.len();
            n >= 6
                && matches!(bytes[n - 6], b'+' | b'-')
                && digits(n - 5..n - 3).is_some()
                && bytes[n - 3] == b':'
                && digits(n - 2..n).is_some()
        }
    };
    let pattern = digits(0..4).is_some()
        && bytes.get(4) == Some(&b'-')
        && digits(5..7).is_some()
        && bytes.get(7) == Some(&b'-')
        && digits(8..10).is_some()
        && bytes.get(10) == Some(&b'T')
        && bytes.len() >= 12
        && zone_ok
        && !value[11..].contains(['\n', '\r', '\u{2028}', '\u{2029}']);
    if !pattern {
        return Err(invalid_result(
            call,
            field,
            "an ISO timestamp with a timezone",
        ));
    }
    if !date_time_parses(value) {
        return Err(invalid_result(call, field, "a valid ISO timestamp"));
    }
    Ok(())
}

/// The ECMAScript date-time string format after a `YYYY-MM-DDT` prefix,
/// as V8's `Date.parse` ranges it.
fn date_time_parses(value: &str) -> bool {
    let number = |s: &str| -> Option<u32> {
        (s.len() == 2 && s.bytes().all(|b| b.is_ascii_digit()))
            .then(|| s.parse().ok())
            .flatten()
    };
    let (month, day) = (number(&value[5..7]), number(&value[8..10]));
    if !matches!(month, Some(1..=12)) || !matches!(day, Some(1..=31)) {
        return false;
    }
    let time = &value[11..];
    let (clock, zone) = match time.strip_suffix('Z') {
        Some(clock) => (clock, None),
        None => {
            let (clock, zone) = time.split_at(time.len() - 6);
            (clock, Some(zone))
        }
    };
    if let Some(zone) = zone {
        if !matches!(number(&zone[1..3]), Some(0..=23))
            || !matches!(number(&zone[4..6]), Some(0..=59))
        {
            return false;
        }
    }
    let (clock, fraction) = match clock.split_once('.') {
        Some((clock, fraction)) => (clock, Some(fraction)),
        None => (clock, None),
    };
    if let Some(fraction) = fraction {
        if fraction.is_empty() || !fraction.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
    }
    let parts: Vec<&str> = clock.split(':').collect();
    let fields: Option<Vec<u32>> = parts.iter().map(|p| number(p)).collect();
    let Some(fields) = fields else {
        return false;
    };
    let (hour, minute, second) = match fields[..] {
        [hour, minute] if fraction.is_none() => (hour, minute, 0),
        [hour, minute, second] => (hour, minute, second),
        _ => return false,
    };
    let fraction_zero = fraction.is_none_or(|f| f.bytes().all(|b| b == b'0'));
    let end_of_day = hour == 24 && minute == 0 && second == 0 && fraction_zero;
    (hour <= 23 || end_of_day) && minute <= 59 && second <= 59
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
