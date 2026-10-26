//! The wallet calls the response-decoder targets drive: one fixed set of
//! arguments per call, the serde-shaped ones read from the shared vectors
//! (`tests/vectors/wallet_wire/*-args.json`, the Go SDK's), so the request a
//! call sends is a request the reference sends; the target varies only the
//! answer.
#![allow(dead_code)]

use bsv_rs::primitives::PrivateKey;
use bsv_rs::wallet::{
    Counterparty, CreateHmacArgs, CreateSignatureArgs, DecryptArgs, EncryptArgs, GetPublicKeyArgs,
    Protocol, SecurityLevel, VerifyHmacArgs, VerifySignatureArgs, WalletRevealCounterpartyArgs,
    WalletRevealSpecificArgs,
};
use serde::de::DeserializeOwned;

/// The calls both the HTTP JSON substrate and the wire transceiver carry.
pub const SHARED_CALLS: u8 = 26;

/// A vector's `json` member as the call's arguments. Two of the Go JSON's
/// shapes are not this crate's serde shapes (a transaction as an array of
/// bytes, read here as hex; a public-key `keyringRevealer`, which
/// `acquire_certificate`'s issuance vector does not carry): the vector is
/// reshaped to this crate's form before it is read, so the call sends what
/// this crate sends. A certificate's `type` is this crate's since #105.
pub fn vector<T: DeserializeOwned>(text: &str) -> T {
    let value: serde_json::Value = serde_json::from_str(text).expect("a vector is JSON");
    serde_json::from_value(reshape(value["json"].clone()))
        .expect("a vector's arguments deserialize")
}

fn reshape(value: serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| match (key.as_str(), value) {
                    ("tx", Value::Array(bytes)) => {
                        let hex: String = bytes
                            .iter()
                            .map(|b| format!("{:02x}", b.as_u64().unwrap_or(0)))
                            .collect();
                        ("tx".to_string(), Value::String(hex))
                    }
                    (_, value) => (key, reshape(value)),
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.into_iter().map(reshape).collect()),
        other => other,
    }
}

macro_rules! args_from_vector {
    ($($name:ident: $ty:ty = $file:literal;)*) => {
        $(
            pub fn $name() -> $ty {
                vector(include_str!(concat!("../../../tests/vectors/wallet_wire/", $file)))
            }
        )*
    };
}

args_from_vector! {
    create_action: bsv_rs::wallet::CreateActionArgs = "createAction-1-out-args.json";
    sign_action: bsv_rs::wallet::SignActionArgs = "signAction-simple-args.json";
    abort_action: bsv_rs::wallet::AbortActionArgs = "abortAction-simple-args.json";
    list_actions: bsv_rs::wallet::ListActionsArgs = "listActions-simple-args.json";
    internalize_action: bsv_rs::wallet::InternalizeActionArgs = "internalizeAction-simple-args.json";
    list_outputs: bsv_rs::wallet::ListOutputsArgs = "listOutputs-simple-args.json";
    relinquish_output: bsv_rs::wallet::RelinquishOutputArgs = "relinquishOutput-simple-args.json";
    acquire_certificate: bsv_rs::wallet::AcquireCertificateArgs = "acquireCertificate-issuance-args.json";
    list_certificates: bsv_rs::wallet::ListCertificatesArgs = "listCertificates-simple-args.json";
    prove_certificate: bsv_rs::wallet::ProveCertificateArgs = "proveCertificate-simple-args.json";
    relinquish_certificate: bsv_rs::wallet::RelinquishCertificateArgs = "relinquishCertificate-simple-args.json";
    discover_by_identity_key: bsv_rs::wallet::DiscoverByIdentityKeyArgs = "discoverByIdentityKey-simple-args.json";
    discover_by_attributes: bsv_rs::wallet::DiscoverByAttributesArgs = "discoverByAttributes-simple-args.json";
    get_header: bsv_rs::wallet::GetHeaderArgs = "getHeaderForHeight-simple-args.json";
}

fn protocol() -> Protocol {
    Protocol::new(SecurityLevel::App, "fuzz tests")
}

fn key(byte: u8) -> PrivateKey {
    PrivateKey::from_bytes(&[byte; 32]).expect("a fixed key")
}

pub fn get_public_key() -> GetPublicKeyArgs {
    GetPublicKeyArgs {
        identity_key: false,
        protocol_id: Some(protocol()),
        key_id: Some("1".into()),
        counterparty: Some(Counterparty::Self_),
        for_self: Some(true),
        ..Default::default()
    }
}

pub fn encrypt() -> EncryptArgs {
    EncryptArgs {
        plaintext: b"fuzz".to_vec(),
        protocol_id: protocol(),
        key_id: "1".into(),
        counterparty: None,
        ..Default::default()
    }
}

pub fn decrypt() -> DecryptArgs {
    DecryptArgs {
        ciphertext: b"fuzz".to_vec(),
        protocol_id: protocol(),
        key_id: "1".into(),
        counterparty: None,
        ..Default::default()
    }
}

pub fn create_hmac() -> CreateHmacArgs {
    CreateHmacArgs {
        data: b"fuzz".to_vec(),
        protocol_id: protocol(),
        key_id: "1".into(),
        counterparty: None,
        ..Default::default()
    }
}

pub fn verify_hmac() -> VerifyHmacArgs {
    VerifyHmacArgs {
        data: b"fuzz".to_vec(),
        hmac: [7; 32],
        protocol_id: protocol(),
        key_id: "1".into(),
        counterparty: None,
        ..Default::default()
    }
}

pub fn create_signature() -> CreateSignatureArgs {
    CreateSignatureArgs {
        data: Some(b"fuzz".to_vec()),
        hash_to_directly_sign: None,
        protocol_id: protocol(),
        key_id: "1".into(),
        counterparty: None,
        ..Default::default()
    }
}

pub fn verify_signature() -> VerifySignatureArgs {
    VerifySignatureArgs {
        data: Some(b"fuzz".to_vec()),
        hash_to_directly_verify: None,
        signature: vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],
        protocol_id: protocol(),
        key_id: "1".into(),
        counterparty: None,
        for_self: None,
        ..Default::default()
    }
}

pub fn reveal_counterparty() -> WalletRevealCounterpartyArgs {
    WalletRevealCounterpartyArgs {
        counterparty: key(2).public_key(),
        verifier: key(3).public_key(),
        privileged: None,
        privileged_reason: None,
    }
}

pub fn reveal_specific() -> WalletRevealSpecificArgs {
    WalletRevealSpecificArgs {
        counterparty: Counterparty::Other(key(2).public_key()),
        verifier: key(3).public_key(),
        protocol_id: protocol(),
        key_id: "1".into(),
        privileged: None,
        privileged_reason: None,
    }
}

/// Calls the wallet method `index % SHARED_CALLS` with its fixed arguments
/// and drops the answer: the target's assertion is that it returns.
macro_rules! call_shared {
    ($wallet:expr, $index:expr, $originator:expr) => {{
        use crate::support as a;
        let w = $wallet;
        let o = $originator;
        match $index % crate::support::SHARED_CALLS {
            0 => drop(w.create_action(a::create_action(), o).await),
            1 => drop(w.sign_action(a::sign_action(), o).await),
            2 => drop(w.abort_action(a::abort_action(), o).await),
            3 => drop(w.list_actions(a::list_actions(), o).await),
            4 => drop(w.internalize_action(a::internalize_action(), o).await),
            5 => drop(w.list_outputs(a::list_outputs(), o).await),
            6 => drop(w.relinquish_output(a::relinquish_output(), o).await),
            7 => drop(w.get_public_key(a::get_public_key(), o).await),
            8 => drop(w.encrypt(a::encrypt(), o).await),
            9 => drop(w.decrypt(a::decrypt(), o).await),
            10 => drop(w.create_hmac(a::create_hmac(), o).await),
            11 => drop(w.verify_hmac(a::verify_hmac(), o).await),
            12 => drop(w.create_signature(a::create_signature(), o).await),
            13 => drop(w.verify_signature(a::verify_signature(), o).await),
            14 => drop(w.acquire_certificate(a::acquire_certificate(), o).await),
            15 => drop(w.list_certificates(a::list_certificates(), o).await),
            16 => drop(w.prove_certificate(a::prove_certificate(), o).await),
            17 => drop(
                w.relinquish_certificate(a::relinquish_certificate(), o)
                    .await,
            ),
            18 => drop(
                w.discover_by_identity_key(a::discover_by_identity_key(), o)
                    .await,
            ),
            19 => drop(
                w.discover_by_attributes(a::discover_by_attributes(), o)
                    .await,
            ),
            20 => drop(w.is_authenticated(o).await),
            21 => drop(w.wait_for_authentication(o).await),
            22 => drop(w.get_height(o).await),
            23 => drop(w.get_header(a::get_header(), o).await),
            24 => drop(w.get_network(o).await),
            _ => drop(w.get_version(o).await),
        }
    }};
}
pub(crate) use call_shared;
