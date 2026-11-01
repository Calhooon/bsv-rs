//! #609: the seven key calls' argument validators as public helpers, each
//! named for its reference site (`ts-stack@edf6e03`
//! `packages/sdk/src/wallet/validationHelpers.ts:1717-1804`), replayed against
//! `vectors/key_args_validators_609.json` (written by
//! `support/key_args_validators_609.mjs` under Node v22.18.0 from the exported
//! reference validators). Every case through its helper, and every refusal
//! through `ProtoWallet`, whose path calls the helper: the same `Error`, byte
//! for byte. The host the helpers are for: a wallet that routes a privileged
//! request to its own key manager (`Wallet.ts:455-570`; the toolbox's #186,
//! the CLI's privileged refusals) validates with them before routing.
#![cfg(feature = "wallet")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bsv_rs::primitives::PrivateKey;
use bsv_rs::wallet::{
    validate_create_hmac_args, validate_create_signature_args, validate_get_public_key_args,
    validate_verify_hmac_args, validate_verify_signature_args, validate_wallet_decrypt_args,
    validate_wallet_encrypt_args, Counterparty, CreateHmacArgs, CreateSignatureArgs, DecryptArgs,
    EncryptArgs, GetPublicKeyArgs, ProtoWallet, Protocol, SecurityLevel, VerifyHmacArgs,
    VerifySignatureArgs,
};
use bsv_rs::{Error, Result, WalletRefusalClass};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
#[serde(untagged)]
enum Bytes {
    Literal(Vec<u8>),
    Repeated { length: usize, byte: u8 },
}

impl Bytes {
    fn bytes(&self) -> Vec<u8> {
        match self {
            Self::Literal(bytes) => bytes.clone(),
            Self::Repeated { length, byte } => vec![*byte; *length],
        }
    }

    fn hash(&self) -> [u8; 32] {
        self.bytes().try_into().unwrap()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    #[serde(rename = "protocolID")]
    protocol: Option<(u8, String)>,
    #[serde(rename = "keyID")]
    key_id: Option<String>,
    counterparty: Option<String>,
    #[serde(default)]
    identity_key: bool,
    for_self: Option<bool>,
    plaintext: Option<Bytes>,
    ciphertext: Option<Bytes>,
    data: Option<Bytes>,
    hmac: Option<Bytes>,
    hash_to_directly_sign: Option<Bytes>,
    hash_to_directly_verify: Option<Bytes>,
    signature: Option<Bytes>,
    privileged: Option<bool>,
    privileged_reason: Option<String>,
    seek_permission: Option<bool>,
}

impl Request {
    fn protocol(&self) -> Option<Protocol> {
        self.protocol
            .as_ref()
            .map(|(level, name)| Protocol::new(SecurityLevel::from_u8(*level).unwrap(), name))
    }

    fn counterparty(&self) -> Option<Counterparty> {
        self.counterparty.as_deref().map(|key| match key {
            "self" => Counterparty::Self_,
            "anyone" => Counterparty::Anyone,
            other => Counterparty::from_hex(other).unwrap(),
        })
    }
}

/// One call's args, typed as this crate types them.
enum Args {
    GetPublicKey(GetPublicKeyArgs),
    Encrypt(EncryptArgs),
    Decrypt(DecryptArgs),
    CreateHmac(CreateHmacArgs),
    VerifyHmac(VerifyHmacArgs),
    CreateSignature(CreateSignatureArgs),
    VerifySignature(VerifySignatureArgs),
}

macro_rules! args {
    ($kind:ident, $r:ident, $($field:ident: $value:expr),* $(,)?) => {
        $kind {
            protocol_id: $r.protocol().unwrap(),
            key_id: $r.key_id.clone().unwrap(),
            counterparty: $r.counterparty(),
            privileged: $r.privileged,
            privileged_reason: $r.privileged_reason.clone(),
            seek_permission: $r.seek_permission,
            $($field: $value,)*
        }
    };
}

fn build(case: &Value) -> Args {
    let r: Request = serde_json::from_value(case["args"].clone()).unwrap();
    let bytes = |b: &Option<Bytes>| b.as_ref().map(Bytes::bytes);
    match case["call"].as_str().unwrap() {
        "getPublicKey" => Args::GetPublicKey(GetPublicKeyArgs {
            identity_key: r.identity_key,
            protocol_id: r.protocol(),
            key_id: r.key_id.clone(),
            counterparty: r.counterparty(),
            for_self: r.for_self,
            privileged: r.privileged,
            privileged_reason: r.privileged_reason.clone(),
            seek_permission: r.seek_permission,
        }),
        "encrypt" => Args::Encrypt(args!(EncryptArgs, r, plaintext: bytes(&r.plaintext).unwrap())),
        "decrypt" => {
            Args::Decrypt(args!(DecryptArgs, r, ciphertext: bytes(&r.ciphertext).unwrap()))
        }
        "createHmac" => Args::CreateHmac(args!(CreateHmacArgs, r, data: bytes(&r.data).unwrap())),
        "verifyHmac" => Args::VerifyHmac(args!(VerifyHmacArgs, r,
            data: bytes(&r.data).unwrap(), hmac: r.hmac.as_ref().unwrap().hash())),
        "createSignature" => Args::CreateSignature(args!(CreateSignatureArgs, r,
            data: bytes(&r.data),
            hash_to_directly_sign: r.hash_to_directly_sign.as_ref().map(Bytes::hash))),
        "verifySignature" => Args::VerifySignature(args!(VerifySignatureArgs, r,
            data: bytes(&r.data),
            hash_to_directly_verify: r.hash_to_directly_verify.as_ref().map(Bytes::hash),
            signature: bytes(&r.signature).unwrap(), for_self: r.for_self)),
        call => panic!("unknown call {call}"),
    }
}

/// The public helper of the case's call.
fn validate(args: &Args) -> Result<()> {
    match args {
        Args::GetPublicKey(a) => validate_get_public_key_args(a),
        Args::Encrypt(a) => validate_wallet_encrypt_args(a),
        Args::Decrypt(a) => validate_wallet_decrypt_args(a),
        Args::CreateHmac(a) => validate_create_hmac_args(a),
        Args::VerifyHmac(a) => validate_verify_hmac_args(a),
        Args::CreateSignature(a) => validate_create_signature_args(a),
        Args::VerifySignature(a) => validate_verify_signature_args(a),
    }
}

/// The `ProtoWallet` path's refusal, if it refuses, for comparison.
fn proto_wallet(args: Args) -> Result<()> {
    let wallet = ProtoWallet::new(Some(PrivateKey::from_hex(&format!("{:064x}", 42)).unwrap()));
    match args {
        Args::GetPublicKey(a) => wallet.get_public_key(a).map(|_| ()),
        Args::Encrypt(a) => wallet.encrypt(a).map(|_| ()),
        Args::Decrypt(a) => wallet.decrypt(a).map(|_| ()),
        Args::CreateHmac(a) => wallet.create_hmac(a).map(|_| ()),
        Args::VerifyHmac(a) => wallet.verify_hmac(a).map(|_| ()),
        Args::CreateSignature(a) => wallet.create_signature(a).map(|_| ()),
        Args::VerifySignature(a) => wallet.verify_signature(a).map(|_| ()),
    }
}

fn cases() -> Vec<Value> {
    let fixture: Value =
        serde_json::from_str(include_str!("vectors/key_args_validators_609.json")).unwrap();
    assert_eq!(fixture["reference"], "ts-stack@edf6e03");
    fixture["cases"].as_array().unwrap().clone()
}

fn expected(case: &Value) -> Result<()> {
    if case["expected"]["ok"] == true {
        return Ok(());
    }
    assert_eq!(case["expected"]["code"], 6, "{}", case["name"]);
    Err(Error::WalletRefusal {
        class: WalletRefusalClass::InvalidParameter,
        message: case["expected"]["message"].as_str().unwrap().into(),
    })
}

fn assert_case(case: &Value) {
    let label = format!("{} / {}", case["call"], case["name"]);
    let want = expected(case);
    assert_eq!(validate(&build(case)), want, "helper: {label}");
    if want.is_err() {
        // The ProtoWallet path calls the helper: its refusal is the helper's.
        assert_eq!(proto_wallet(build(case)), want, "ProtoWallet: {label}");
    }
}

/// Replays the cases of one rule (selected by the reference's refusal words,
/// or by name for an acceptance) across all seven helpers.
fn assert_rule(select: impl Fn(&Value) -> bool) {
    let selected: Vec<_> = cases().into_iter().filter(|c| select(c)).collect();
    assert!(!selected.is_empty(), "no recorded case selected");
    for case in &selected {
        assert_case(case);
    }
}

fn refused_with(words: &'static str) -> impl Fn(&Value) -> bool {
    move |c| c["expected"]["message"] == words
}

#[test]
fn every_recorded_case_through_its_helper_and_the_proto_wallet_609() {
    let cases = cases();
    let calls: std::collections::BTreeSet<_> =
        cases.iter().map(|c| c["call"].as_str().unwrap()).collect();
    assert_eq!(calls.len(), 7, "the seven calls");
    let refused = cases
        .iter()
        .filter(|c| c["expected"]["ok"] == false)
        .count();
    assert_eq!(
        (cases.len(), refused),
        (222, 120),
        "recorded case split changed"
    );
    for case in &cases {
        assert_case(case);
    }
}

#[test]
fn privileged_without_a_reason_is_refused_by_all_seven_609() {
    assert_rule(refused_with(
        "The privilegedReason parameter must be a value when 'privileged' is true",
    ));
}

#[test]
fn a_reason_is_bounded_whether_or_not_privileged_609() {
    assert_rule(refused_with(
        "The privilegedReason parameter must be at least 5 length.",
    ));
    assert_rule(refused_with(
        "The privilegedReason parameter must be no more than 50 length.",
    ));
}

#[test]
fn the_protocol_name_is_bounded_609() {
    assert_rule(refused_with(
        "The protocolID[1] parameter must be at least 5 length.",
    ));
    assert_rule(refused_with(
        "The protocolID[1] parameter must be no more than 400 length.",
    ));
}

#[test]
fn the_key_id_is_bounded_609() {
    assert_rule(refused_with(
        "The keyID parameter must be at least 1 length.",
    ));
    assert_rule(refused_with(
        "The keyID parameter must be no more than 800 length.",
    ));
}

#[test]
fn get_public_key_requires_a_protocol_and_key_id_without_identity_609() {
    assert_rule(refused_with(
        "The protocolID parameter must be a [securityLevel, protocolName] tuple",
    ));
    assert_rule(refused_with("The keyID parameter must be a string"));
}

#[test]
fn the_bytes_are_bounded_609() {
    for field in ["plaintext", "ciphertext", "data"] {
        let words = format!("The {field} parameter must be at most 268435456 bytes");
        assert_rule(move |c| c["expected"]["message"] == words.as_str());
    }
}

#[test]
fn a_signature_call_takes_exactly_one_of_data_and_hash_609() {
    assert_rule(refused_with(
        "The data, hashToDirectlySign parameter must be exactly one value",
    ));
    assert_rule(refused_with(
        "The data, hashToDirectlyVerify parameter must be exactly one value",
    ));
}

#[test]
fn a_signature_to_verify_is_bounded_then_canonical_der_609() {
    assert_rule(refused_with(
        "The signature parameter must be at most 72 bytes",
    ));
    assert_rule(refused_with(
        "The signature parameter must be a canonical DER-encoded ECDSA signature",
    ));
}

#[test]
fn the_reference_accepts_what_the_helpers_accept_609() {
    assert_rule(|c| c["expected"]["ok"] == true);
}
