//! All nine ProtoWallet argument validators, shared with the wire (#415, #420);
//! the seven key calls' public since #609 (`validate_<site>_args`, re-exported
//! at `wallet::`, each named for its reference validator).
//!
//! `ts-stack@edf6e03`, `validationHelpers.ts:146-230,1717-1804`.
//! Encoded keys are bounded before parsing; typed keys already hold points.
//! Rust's types already enforce records, byte elements, security levels,
//! counterparties, booleans and the 32-byte hashes/HMACs. The wire processor
//! shares these checks; its decoder additionally enforces those types.

use super::originator::invalid_parameter;
use crate::error::Result;
use crate::primitives::PublicKey;
use crate::wallet::{
    Counterparty, CreateHmacArgs, CreateSignatureArgs, DecryptArgs, EncryptArgs, GetPublicKeyArgs,
    Protocol, VerifyHmacArgs, VerifySignatureArgs,
};

/// `validateByteArray`'s default bound (`validationHelpers.ts:150`), the
/// reference's `MAX_WALLET_WIRE_FRAME_BYTES`: the substrates' one byte bound,
/// `byte_fields::MAX_BYTES` (#532).
const MAX_WALLET_WIRE_FRAME_BYTES: usize = crate::wallet::substrates::byte_fields::MAX_BYTES;
const MAX_SIGNATURE_BYTES: usize = 72;
const GROUP_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// `validateStringLength`: UTF-8 bytes, without trimming or normalization.
pub(crate) fn string_length(value: &str, name: &str, min: usize, max: usize) -> Result<()> {
    if value.len() < min {
        return Err(invalid_parameter(name, &format!("at least {min} length.")));
    }
    if value.len() > max {
        return Err(invalid_parameter(
            name,
            &format!("no more than {max} length."),
        ));
    }
    Ok(())
}

/// `validateByteArray` on typed bytes: only its inclusive size bound remains.
pub(crate) fn byte_array(length: usize, name: &str) -> Result<()> {
    if length > MAX_WALLET_WIRE_FRAME_BYTES {
        return Err(invalid_parameter(
            name,
            &format!("at most {MAX_WALLET_WIRE_FRAME_BYTES} bytes"),
        ));
    }
    Ok(())
}

/// `validateProtocol`: SecurityLevel already represents exactly 0, 1 and 2.
pub(crate) fn protocol(protocol: &Protocol) -> Result<()> {
    string_length(&protocol.protocol_name, "protocolID[1]", 5, 400)
}

/// `validatePrivilege`: validate a present reason even without privilege.
pub(crate) fn privilege(privileged: Option<bool>, reason: Option<&str>) -> Result<()> {
    if let Some(reason) = reason {
        string_length(reason, "privilegedReason", 5, 50)?;
    }
    if privileged == Some(true) && reason.is_none() {
        return Err(invalid_parameter(
            "privilegedReason",
            "a value when 'privileged' is true",
        ));
    }
    Ok(())
}

/// `validateEncryptionArgs`: protocol, key ID, counterparty, privilege.
pub(crate) fn encryption(
    protocol_id: &Protocol,
    key_id: &str,
    privileged: Option<bool>,
    reason: Option<&str>,
) -> Result<()> {
    protocol(protocol_id)?;
    string_length(key_id, "keyID", 1, 800)?;
    privilege(privileged, reason)
}

/// `validateGetPublicKeyArgs`: identity still validates every supplied field.
/// `identity_key: false` represents the reference's absent flag in this API.
pub(crate) fn get_public_key_args(args: &GetPublicKeyArgs) -> Result<Option<(&Protocol, &str)>> {
    let protocol_id = args.protocol_id.as_ref();
    if let Some(protocol_id) = protocol_id {
        protocol(protocol_id)?;
    } else if !args.identity_key {
        return Err(invalid_parameter(
            "protocolID",
            "a [securityLevel, protocolName] tuple",
        ));
    }
    let key_id = args.key_id.as_deref();
    if let Some(key_id) = key_id {
        string_length(key_id, "keyID", 1, 800)?;
    } else if !args.identity_key {
        return Err(invalid_parameter("keyID", "a string"));
    }
    // An optional Counterparty is already either a special value or a point.
    privilege(args.privileged, args.privileged_reason.as_deref())?;
    Ok(protocol_id.zip(key_id).filter(|_| !args.identity_key))
}

/// The reference's `validateGetPublicKeyArgs` (`ts-stack@edf6e03`
/// `packages/sdk/src/wallet/validationHelpers.ts:1717-1732`), public since
/// #609: the argument rule of getPublicKey, so a host that routes a
/// privileged request elsewhere (the reference's `Wallet.ts:455-466`) judges
/// it first by the one definition [`ProtoWallet::get_public_key`](crate::wallet::ProtoWallet::get_public_key) runs.
///
/// Without `identity_key` the protocol and key ID are required
/// (`The protocolID parameter must be a [securityLevel, protocolName] tuple`,
/// `The keyID parameter must be a string`) and judged as the shared rules
/// judge them; with it, each one supplied is still judged, and the privilege
/// always. `identity_key: false` is the reference's absent flag (its
/// `identityKey: false`, refused there as `true or undefined`, cannot be
/// written in this type).
///
/// The shared rules (`validateEncryptionArgs`,
/// `:224-230`): `protocolID[1]` 5 to 400 UTF-8 bytes (`validateProtocol`,
/// `:198-205`; the security level is [`SecurityLevel`](crate::wallet::SecurityLevel)'s
/// own), `keyID` 1 to 800 UTF-8 bytes, then `validatePrivilege` (`:207-222`):
/// a present `privilegedReason` 5 to 50 UTF-8 bytes whether or not
/// `privileged`, and `privileged: Some(true)` without a reason refused,
/// `The privilegedReason parameter must be a value when 'privileged' is true`.
/// The counterparty, `seekPermission` and the booleans are their types' own
/// (a key text is judged where it is read, [`Counterparty::from_hex`]
/// through [`validate_public_key`]). Nothing is trimmed or normalized.
///
/// # Errors
///
/// [`Error::WalletRefusal`](crate::Error::WalletRefusal) of class
/// [`InvalidParameter`](crate::WalletRefusalClass::InvalidParameter), code 6,
/// in `WERR_INVALID_PARAMETER`'s words, `The <name> parameter must be <rule>`,
/// the first rule broken in the reference's order; byte for byte the refusal
/// [`ProtoWallet`](crate::wallet::ProtoWallet) and the wire processor make,
/// since both call this helper.
///
/// ```
/// use bsv_rs::wallet::{validate_get_public_key_args, GetPublicKeyArgs};
///
/// let identity = GetPublicKeyArgs { identity_key: true, ..Default::default() };
/// assert!(validate_get_public_key_args(&identity).is_ok());
/// let privileged = GetPublicKeyArgs { privileged: Some(true), ..identity };
/// assert_eq!(
///     validate_get_public_key_args(&privileged).unwrap_err().to_string(),
///     "The privilegedReason parameter must be a value when 'privileged' is true"
/// );
/// ```
pub fn validate_get_public_key_args(args: &GetPublicKeyArgs) -> Result<()> {
    get_public_key_args(args).map(|_| ())
}

/// The reference's `validateWalletEncryptArgs` (`ts-stack@edf6e03`
/// `packages/sdk/src/wallet/validationHelpers.ts:1752-1756`), public since #609:
/// the argument rule of encrypt, so a host that routes a privileged request
/// elsewhere (the reference's `Wallet.ts:455-570`) judges it first by the one
/// definition [`ProtoWallet::encrypt`](crate::wallet::ProtoWallet::encrypt) runs.
///
/// The shared rules, in the reference's order (`validateEncryptionArgs`,
/// `:224-230`): `protocolID[1]` 5 to 400 UTF-8 bytes (`validateProtocol`,
/// `:198-205`; the security level is [`SecurityLevel`](crate::wallet::SecurityLevel)'s
/// own), `keyID` 1 to 800 UTF-8 bytes, then `validatePrivilege` (`:207-222`):
/// a present `privilegedReason` 5 to 50 UTF-8 bytes whether or not
/// `privileged`, and `privileged: Some(true)` without a reason refused,
/// `The privilegedReason parameter must be a value when 'privileged' is true`.
/// The counterparty, `seekPermission` and the booleans are their types' own
/// (a key text is judged where it is read, [`Counterparty::from_hex`]
/// through [`validate_public_key`]). Nothing is trimmed or normalized.
/// Then `plaintext` at most 268,435,456 bytes (`validateByteArray`, `:146-177`).
///
/// # Errors
///
/// [`Error::WalletRefusal`](crate::Error::WalletRefusal) of class
/// [`InvalidParameter`](crate::WalletRefusalClass::InvalidParameter), code 6,
/// in `WERR_INVALID_PARAMETER`'s words, `The <name> parameter must be <rule>`,
/// the first rule broken in the reference's order; byte for byte the refusal
/// [`ProtoWallet`](crate::wallet::ProtoWallet) and the wire processor make,
/// since both call this helper.
///
/// ```
/// use bsv_rs::wallet::{validate_wallet_encrypt_args, EncryptArgs, Protocol, SecurityLevel};
///
/// let args = EncryptArgs { protocol_id: Protocol::new(SecurityLevel::App, "wallet tests"), key_id: "key".into(), privileged: Some(true), ..Default::default() };
/// assert_eq!(
///     validate_wallet_encrypt_args(&args).unwrap_err().to_string(),
///     "The privilegedReason parameter must be a value when 'privileged' is true"
/// );
/// ```
pub fn validate_wallet_encrypt_args(args: &EncryptArgs) -> Result<()> {
    encryption(
        &args.protocol_id,
        &args.key_id,
        args.privileged,
        args.privileged_reason.as_deref(),
    )?;
    byte_array(args.plaintext.len(), "plaintext")
}

/// The reference's `validateWalletDecryptArgs` (`ts-stack@edf6e03`
/// `packages/sdk/src/wallet/validationHelpers.ts:1758-1762`), public since #609:
/// the argument rule of decrypt, so a host that routes a privileged request
/// elsewhere (the reference's `Wallet.ts:455-570`) judges it first by the one
/// definition [`ProtoWallet::decrypt`](crate::wallet::ProtoWallet::decrypt) runs.
///
/// The shared rules, in the reference's order (`validateEncryptionArgs`,
/// `:224-230`): `protocolID[1]` 5 to 400 UTF-8 bytes (`validateProtocol`,
/// `:198-205`; the security level is [`SecurityLevel`](crate::wallet::SecurityLevel)'s
/// own), `keyID` 1 to 800 UTF-8 bytes, then `validatePrivilege` (`:207-222`):
/// a present `privilegedReason` 5 to 50 UTF-8 bytes whether or not
/// `privileged`, and `privileged: Some(true)` without a reason refused,
/// `The privilegedReason parameter must be a value when 'privileged' is true`.
/// The counterparty, `seekPermission` and the booleans are their types' own
/// (a key text is judged where it is read, [`Counterparty::from_hex`]
/// through [`validate_public_key`]). Nothing is trimmed or normalized.
/// Then `ciphertext` at most 268,435,456 bytes; an empty or unauthentic
/// ciphertext passes here and fails at the cipher.
///
/// # Errors
///
/// [`Error::WalletRefusal`](crate::Error::WalletRefusal) of class
/// [`InvalidParameter`](crate::WalletRefusalClass::InvalidParameter), code 6,
/// in `WERR_INVALID_PARAMETER`'s words, `The <name> parameter must be <rule>`,
/// the first rule broken in the reference's order; byte for byte the refusal
/// [`ProtoWallet`](crate::wallet::ProtoWallet) and the wire processor make,
/// since both call this helper.
///
/// ```
/// use bsv_rs::wallet::{validate_wallet_decrypt_args, DecryptArgs, Protocol, SecurityLevel};
///
/// let args = DecryptArgs { protocol_id: Protocol::new(SecurityLevel::App, "wallet tests"), key_id: "key".into(), privileged: Some(true), ..Default::default() };
/// assert_eq!(
///     validate_wallet_decrypt_args(&args).unwrap_err().to_string(),
///     "The privilegedReason parameter must be a value when 'privileged' is true"
/// );
/// ```
pub fn validate_wallet_decrypt_args(args: &DecryptArgs) -> Result<()> {
    encryption(
        &args.protocol_id,
        &args.key_id,
        args.privileged,
        args.privileged_reason.as_deref(),
    )?;
    byte_array(args.ciphertext.len(), "ciphertext")
}

/// The reference's `validatePublicKey` (`ts-stack@edf6e03`
/// `packages/sdk/src/wallet/validationHelpers.ts:185-191`), public since #579:
/// the canonical compressed form of `isValidCompressedPublicKey`
/// (`Secp256k1Validation.ts:15-22`), read as the reference's wallet argument
/// validators read a key, so a host judging a caller's key at its own door
/// holds the one definition (#579).
///
/// In the reference's order: the text trimmed as JavaScript's `trim` trims it,
/// an even UTF-16 length, hexadecimal digits (either case, `validateHexString`,
/// `:522-534`), exactly 66 characters, then `02` or `03` and an x below the
/// field prime that is a point's. Returns the parsed key, equal to
/// [`PublicKey::from_hex`] of the trimmed text (that reader trims nothing,
/// so it refuses the padded text this helper reads); the lenient forms it
/// accepts (#498: an odd-length key, an uncompressed or hybrid key, an x at or
/// above p) are refused here.
///
/// # Errors
///
/// [`Error::WalletRefusal`](crate::Error::WalletRefusal) of class
/// [`InvalidParameter`](crate::WalletRefusalClass::InvalidParameter), code 6,
/// in `WERR_INVALID_PARAMETER`'s words, `The <name> parameter must be `
/// followed by `even length, not N.`, `hexadecimal string.`,
/// `at least 66 length.`, `no more than 66 length.` or
/// `a valid compressed secp256k1 public key`.
///
/// ```
/// use bsv_rs::wallet::validate_public_key;
///
/// let g = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
/// assert_eq!(validate_public_key(g, "counterparty").unwrap().to_hex(), g);
/// assert!(validate_public_key(&g[1..], "counterparty").is_err());
/// ```
pub fn validate_public_key(value: &str, name: &str) -> Result<PublicKey> {
    let value = super::originator::trim_js(value);
    let length = value.encode_utf16().count();
    if !length.is_multiple_of(2) {
        return Err(invalid_parameter(
            name,
            &format!("even length, not {length}."),
        ));
    }
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid_parameter(name, "hexadecimal string."));
    }
    string_length(value, name, 66, 66)?;
    // The byte length is checked before either decoding or parsing the point.
    let bytes = hex::decode(value).map_err(|_| invalid_parameter(name, "hexadecimal string."))?;
    public_key(&bytes, name)
}

/// The reference's result validator's `publicKey` (`ts-stack@edf6e03`
/// `packages/sdk/src/wallet/WalletResultValidation.ts:928-933`, over `hex` at
/// `:917-926`), as `validateCertificate` applies it to a wallet certificate's
/// `subject` and `certifier` (`:1489-1493`) on a listCertificates or discovery
/// answer: the wallet's key read as the reference's client reads a result,
/// where [`validate_public_key`] reads it as an argument (#582).
///
/// In the reference's order: hexadecimal digits of either case in pairs
/// (`/^(?:[0-9a-fA-F]{2})*$/`, nothing trimmed, so a space-padded text is
/// refused where [`validate_public_key`] trims and reads it), exactly 33
/// bytes, then `02` or `03` and an x below the field prime that is a point's
/// (`isValidCompressedPublicKey`, `Secp256k1Validation.ts:15-22`). Returns the
/// parsed key. `validateCertificate` catches the refusal and throws its own,
/// `Invalid <call> result <field>: expected a canonical signed wallet
/// certificate` (`:1534-1536`); this helper answers the inner words.
///
/// # Errors
///
/// [`Error::WalletError`](crate::Error::WalletError) in the result
/// validator's words (`:510-512`), `Invalid <call> result <field>: expected `
/// followed by `an even-length hex string`, `33 hexadecimal bytes` or
/// `a valid compressed secp256k1 public key`.
///
/// ```
/// use bsv_rs::wallet::validate_result_public_key;
///
/// let g = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
/// let read = validate_result_public_key(g, "listCertificates", "certificates[0].subject");
/// assert_eq!(read.unwrap().to_hex(), g);
/// let padded = format!(" {g}");
/// assert!(validate_result_public_key(&padded, "listCertificates", "subject").is_err());
/// ```
pub fn validate_result_public_key(value: &str, call: &str, field: &str) -> Result<PublicKey> {
    let invalid = |expected: &str| {
        crate::Error::WalletError(format!(
            "Invalid {call} result {field}: expected {expected}"
        ))
    };
    if !value.len().is_multiple_of(2) || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid("an even-length hex string"));
    }
    if value.len() != 66 {
        return Err(invalid("33 hexadecimal bytes"));
    }
    let bytes = hex::decode(value).map_err(|_| invalid("an even-length hex string"))?;
    public_key(&bytes, field).map_err(|_| invalid("a valid compressed secp256k1 public key"))
}

/// `isValidCompressedPublicKey`, including the 02/03 prefix before parsing.
pub(crate) fn public_key(bytes: &[u8], name: &str) -> Result<PublicKey> {
    let invalid = || invalid_parameter(name, "a valid compressed secp256k1 public key");
    if bytes.len() != 33 || !matches!(bytes.first(), Some(0x02 | 0x03)) {
        return Err(invalid());
    }
    PublicKey::from_bytes(bytes).map_err(|_| invalid())
}

/// `validateRevealCounterpartyKeyLinkageArgs`: both keys, then privilege.
/// The wire supplies raw keys; ProtoWallet supplies its already parsed keys.
pub(crate) fn reveal_counterparty_args(
    counterparty: &[u8],
    verifier: &[u8],
    privileged: Option<bool>,
    reason: Option<&str>,
) -> Result<(PublicKey, PublicKey)> {
    let counterparty = public_key(counterparty, "counterparty")?;
    let verifier = public_key(verifier, "verifier")?;
    privilege(privileged, reason)?;
    Ok((counterparty, verifier))
}

/// `validateRevealSpecificKeyLinkageArgs`: counterparty, verifier, protocol,
/// key ID, privilege. Returns the required counterparty and checked verifier.
pub(crate) fn reveal_specific_args<'a>(
    counterparty: Option<&'a Counterparty>,
    verifier: &[u8],
    protocol_id: &Protocol,
    key_id: &str,
    privileged: Option<bool>,
    reason: Option<&str>,
) -> Result<(&'a Counterparty, PublicKey)> {
    let counterparty =
        counterparty.ok_or_else(|| invalid_parameter("counterparty", "a hexadecimal string"))?;
    let verifier = public_key(verifier, "verifier")?;
    protocol(protocol_id)?;
    string_length(key_id, "keyID", 1, 800)?;
    privilege(privileged, reason)?;
    Ok((counterparty, verifier))
}

/// The reference's `validateCreateHmacArgs` (`ts-stack@edf6e03`
/// `packages/sdk/src/wallet/validationHelpers.ts:1764-1768`), public since #609:
/// the argument rule of createHmac, so a host that routes a privileged request
/// elsewhere (the reference's `Wallet.ts:455-570`) judges it first by the one
/// definition [`ProtoWallet::create_hmac`](crate::wallet::ProtoWallet::create_hmac) runs.
///
/// The shared rules, in the reference's order (`validateEncryptionArgs`,
/// `:224-230`): `protocolID[1]` 5 to 400 UTF-8 bytes (`validateProtocol`,
/// `:198-205`; the security level is [`SecurityLevel`](crate::wallet::SecurityLevel)'s
/// own), `keyID` 1 to 800 UTF-8 bytes, then `validatePrivilege` (`:207-222`):
/// a present `privilegedReason` 5 to 50 UTF-8 bytes whether or not
/// `privileged`, and `privileged: Some(true)` without a reason refused,
/// `The privilegedReason parameter must be a value when 'privileged' is true`.
/// The counterparty, `seekPermission` and the booleans are their types' own
/// (a key text is judged where it is read, [`Counterparty::from_hex`]
/// through [`validate_public_key`]). Nothing is trimmed or normalized.
/// Then `data` at most 268,435,456 bytes.
///
/// # Errors
///
/// [`Error::WalletRefusal`](crate::Error::WalletRefusal) of class
/// [`InvalidParameter`](crate::WalletRefusalClass::InvalidParameter), code 6,
/// in `WERR_INVALID_PARAMETER`'s words, `The <name> parameter must be <rule>`,
/// the first rule broken in the reference's order; byte for byte the refusal
/// [`ProtoWallet`](crate::wallet::ProtoWallet) and the wire processor make,
/// since both call this helper.
///
/// ```
/// use bsv_rs::wallet::{validate_create_hmac_args, CreateHmacArgs, Protocol, SecurityLevel};
///
/// let args = CreateHmacArgs { protocol_id: Protocol::new(SecurityLevel::App, "wallet tests"), key_id: "key".into(), privileged: Some(true), ..Default::default() };
/// assert_eq!(
///     validate_create_hmac_args(&args).unwrap_err().to_string(),
///     "The privilegedReason parameter must be a value when 'privileged' is true"
/// );
/// ```
pub fn validate_create_hmac_args(args: &CreateHmacArgs) -> Result<()> {
    encryption(
        &args.protocol_id,
        &args.key_id,
        args.privileged,
        args.privileged_reason.as_deref(),
    )?;
    byte_array(args.data.len(), "data")
}

/// The reference's `validateVerifyHmacArgs` (`ts-stack@edf6e03`
/// `packages/sdk/src/wallet/validationHelpers.ts:1770-1775`), public since #609:
/// the argument rule of verifyHmac, so a host that routes a privileged request
/// elsewhere (the reference's `Wallet.ts:455-570`) judges it first by the one
/// definition [`ProtoWallet::verify_hmac`](crate::wallet::ProtoWallet::verify_hmac) runs.
///
/// The shared rules, in the reference's order (`validateEncryptionArgs`,
/// `:224-230`): `protocolID[1]` 5 to 400 UTF-8 bytes (`validateProtocol`,
/// `:198-205`; the security level is [`SecurityLevel`](crate::wallet::SecurityLevel)'s
/// own), `keyID` 1 to 800 UTF-8 bytes, then `validatePrivilege` (`:207-222`):
/// a present `privilegedReason` 5 to 50 UTF-8 bytes whether or not
/// `privileged`, and `privileged: Some(true)` without a reason refused,
/// `The privilegedReason parameter must be a value when 'privileged' is true`.
/// The counterparty, `seekPermission` and the booleans are their types' own
/// (a key text is judged where it is read, [`Counterparty::from_hex`]
/// through [`validate_public_key`]). Nothing is trimmed or normalized.
/// Then `data` at most 268,435,456 bytes; the HMAC's 32 bytes are its type's.
///
/// # Errors
///
/// [`Error::WalletRefusal`](crate::Error::WalletRefusal) of class
/// [`InvalidParameter`](crate::WalletRefusalClass::InvalidParameter), code 6,
/// in `WERR_INVALID_PARAMETER`'s words, `The <name> parameter must be <rule>`,
/// the first rule broken in the reference's order; byte for byte the refusal
/// [`ProtoWallet`](crate::wallet::ProtoWallet) and the wire processor make,
/// since both call this helper.
///
/// ```
/// use bsv_rs::wallet::{validate_verify_hmac_args, VerifyHmacArgs, Protocol, SecurityLevel};
///
/// let args = VerifyHmacArgs { protocol_id: Protocol::new(SecurityLevel::App, "wallet tests"), key_id: "key".into(), privileged: Some(true), ..Default::default() };
/// assert_eq!(
///     validate_verify_hmac_args(&args).unwrap_err().to_string(),
///     "The privilegedReason parameter must be a value when 'privileged' is true"
/// );
/// ```
pub fn validate_verify_hmac_args(args: &VerifyHmacArgs) -> Result<()> {
    encryption(
        &args.protocol_id,
        &args.key_id,
        args.privileged,
        args.privileged_reason.as_deref(),
    )?;
    byte_array(args.data.len(), "data")
}

/// `validateExclusiveDataAndHash`: presence, then the chosen bytes.
fn exclusive_data_and_hash(data: Option<&[u8]>, has_hash: bool, hash_field: &str) -> Result<()> {
    if data.is_some() == has_hash {
        return Err(invalid_parameter(
            &format!("data, {hash_field}"),
            "exactly one value",
        ));
    }
    if let Some(data) = data {
        byte_array(data.len(), "data")?;
    }
    Ok(())
}

/// The reference's `validateCreateSignatureArgs` (`ts-stack@edf6e03`
/// `packages/sdk/src/wallet/validationHelpers.ts:1789-1793`), public since #609:
/// the argument rule of createSignature, so a host that routes a privileged request
/// elsewhere (the reference's `Wallet.ts:455-570`) judges it first by the one
/// definition [`ProtoWallet::create_signature`](crate::wallet::ProtoWallet::create_signature) runs.
///
/// The shared rules, in the reference's order (`validateEncryptionArgs`,
/// `:224-230`): `protocolID[1]` 5 to 400 UTF-8 bytes (`validateProtocol`,
/// `:198-205`; the security level is [`SecurityLevel`](crate::wallet::SecurityLevel)'s
/// own), `keyID` 1 to 800 UTF-8 bytes, then `validatePrivilege` (`:207-222`):
/// a present `privilegedReason` 5 to 50 UTF-8 bytes whether or not
/// `privileged`, and `privileged: Some(true)` without a reason refused,
/// `The privilegedReason parameter must be a value when 'privileged' is true`.
/// The counterparty, `seekPermission` and the booleans are their types' own
/// (a key text is judged where it is read, [`Counterparty::from_hex`]
/// through [`validate_public_key`]). Nothing is trimmed or normalized.
/// Then exactly one of `data` and `hash_to_directly_sign`
/// (`validateExclusiveDataAndHash`, `:1777-1787`: `The data, hashToDirectlySign
/// parameter must be exactly one value`), `data` at most 268,435,456 bytes.
///
/// # Errors
///
/// [`Error::WalletRefusal`](crate::Error::WalletRefusal) of class
/// [`InvalidParameter`](crate::WalletRefusalClass::InvalidParameter), code 6,
/// in `WERR_INVALID_PARAMETER`'s words, `The <name> parameter must be <rule>`,
/// the first rule broken in the reference's order; byte for byte the refusal
/// [`ProtoWallet`](crate::wallet::ProtoWallet) and the wire processor make,
/// since both call this helper.
///
/// ```
/// use bsv_rs::wallet::{validate_create_signature_args, CreateSignatureArgs, Protocol, SecurityLevel};
///
/// let args = CreateSignatureArgs { protocol_id: Protocol::new(SecurityLevel::App, "wallet tests"), key_id: "key".into(), data: Some(vec![1]), privileged: Some(true), ..Default::default() };
/// assert_eq!(
///     validate_create_signature_args(&args).unwrap_err().to_string(),
///     "The privilegedReason parameter must be a value when 'privileged' is true"
/// );
/// ```
pub fn validate_create_signature_args(args: &CreateSignatureArgs) -> Result<()> {
    encryption(
        &args.protocol_id,
        &args.key_id,
        args.privileged,
        args.privileged_reason.as_deref(),
    )?;
    exclusive_data_and_hash(
        args.data.as_deref(),
        args.hash_to_directly_sign.is_some(),
        "hashToDirectlySign",
    )
}

/// The reference's `validateVerifySignatureArgs` (`ts-stack@edf6e03`
/// `packages/sdk/src/wallet/validationHelpers.ts:1795-1804`), public since #609:
/// the argument rule of verifySignature, so a host that routes a privileged request
/// elsewhere (the reference's `Wallet.ts:455-570`) judges it first by the one
/// definition [`ProtoWallet::verify_signature`](crate::wallet::ProtoWallet::verify_signature) runs.
///
/// The shared rules, in the reference's order (`validateEncryptionArgs`,
/// `:224-230`): `protocolID[1]` 5 to 400 UTF-8 bytes (`validateProtocol`,
/// `:198-205`; the security level is [`SecurityLevel`](crate::wallet::SecurityLevel)'s
/// own), `keyID` 1 to 800 UTF-8 bytes, then `validatePrivilege` (`:207-222`):
/// a present `privilegedReason` 5 to 50 UTF-8 bytes whether or not
/// `privileged`, and `privileged: Some(true)` without a reason refused,
/// `The privilegedReason parameter must be a value when 'privileged' is true`.
/// The counterparty, `seekPermission` and the booleans are their types' own
/// (a key text is judged where it is read, [`Counterparty::from_hex`]
/// through [`validate_public_key`]). Nothing is trimmed or normalized.
/// Then exactly one of `data` and `hash_to_directly_verify` (`The data,
/// hashToDirectlyVerify parameter must be exactly one value`), `data` at most
/// 268,435,456 bytes, then the signature: at most 72 bytes, then canonical
/// DER with each scalar in 1..n, high S accepted (`isCanonicalDERSignature`,
/// `Secp256k1Validation.ts:33-53`), all before any DER parsing.
///
/// # Errors
///
/// [`Error::WalletRefusal`](crate::Error::WalletRefusal) of class
/// [`InvalidParameter`](crate::WalletRefusalClass::InvalidParameter), code 6,
/// in `WERR_INVALID_PARAMETER`'s words, `The <name> parameter must be <rule>`,
/// the first rule broken in the reference's order; byte for byte the refusal
/// [`ProtoWallet`](crate::wallet::ProtoWallet) and the wire processor make,
/// since both call this helper.
///
/// ```
/// use bsv_rs::wallet::{validate_verify_signature_args, VerifySignatureArgs, Protocol, SecurityLevel};
///
/// let args = VerifySignatureArgs { protocol_id: Protocol::new(SecurityLevel::App, "wallet tests"), key_id: "key".into(), data: Some(vec![1]), privileged: Some(true), ..Default::default() };
/// assert_eq!(
///     validate_verify_signature_args(&args).unwrap_err().to_string(),
///     "The privilegedReason parameter must be a value when 'privileged' is true"
/// );
/// ```
pub fn validate_verify_signature_args(args: &VerifySignatureArgs) -> Result<()> {
    encryption(
        &args.protocol_id,
        &args.key_id,
        args.privileged,
        args.privileged_reason.as_deref(),
    )?;
    exclusive_data_and_hash(
        args.data.as_deref(),
        args.hash_to_directly_verify.is_some(),
        "hashToDirectlyVerify",
    )?;
    if args.signature.len() > MAX_SIGNATURE_BYTES {
        return Err(invalid_parameter("signature", "at most 72 bytes"));
    }
    if !is_canonical_der_signature(&args.signature) {
        return Err(invalid_parameter(
            "signature",
            "a canonical DER-encoded ECDSA signature",
        ));
    }
    Ok(())
}

/// `isCanonicalDERSignature` (`Secp256k1Validation.ts:33-53`): strict,
/// minimally encoded DER with each scalar in 1..n, without requiring low-S.
pub(crate) fn is_canonical_der_signature(bytes: &[u8]) -> bool {
    if bytes.len() < 8 || bytes.len() > MAX_SIGNATURE_BYTES || bytes[0] != 0x30 {
        return false;
    }
    if usize::from(bytes[1]) != bytes.len() - 2 {
        return false;
    }
    let mut offset = 2;
    for _ in 0..2 {
        if bytes.get(offset) != Some(&0x02) {
            return false;
        }
        let Some(&length) = bytes.get(offset + 1) else {
            return false;
        };
        let length = usize::from(length);
        offset += 2;
        if !(1..=33).contains(&length) || offset + length > bytes.len() {
            return false;
        }
        let scalar = &bytes[offset..offset + length];
        if scalar[0] & 0x80 != 0 || (length > 1 && scalar[0] == 0 && scalar[1] & 0x80 == 0) {
            return false;
        }
        if !scalar_in_range(scalar) {
            return false;
        }
        offset += length;
    }
    offset == bytes.len()
}

fn scalar_in_range(scalar: &[u8]) -> bool {
    let Some(leading) = scalar.iter().position(|&b| b != 0) else {
        return false;
    };
    let digits = &scalar[leading..];
    if digits.len() > 32 {
        return false;
    }
    let mut padded = [0u8; 32];
    padded[32 - digits.len()..].copy_from_slice(digits);
    padded < GROUP_ORDER
}
