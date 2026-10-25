//! Test data adapters for the crypto types that deliberately have no Serde impl.
//! These describe inputs/results only. Production code writes every wire byte
//! and HTTP request in the golden files.
use bsv_rs::primitives::PublicKey;
use bsv_rs::wallet::interface::{RevealCounterpartyKeyLinkageArgs, RevealSpecificKeyLinkageArgs};
use bsv_rs::wallet::*;
use serde::de::DeserializeOwned;
use serde_json::{json, Value};

pub trait FixtureJson: Sized {
    fn from_fixture(value: Value) -> Self;
    fn fixture(&self) -> Value;
}

macro_rules! serde_types {
    ($($ty:ty),* $(,)?) => {$(
        impl FixtureJson for $ty {
            fn from_fixture(value: Value) -> Self { serde_json::from_value(value).unwrap() }
            fn fixture(&self) -> Value { serde_json::to_value(self).unwrap() }
        }
    )*};
}

serde_types!(
    CreateActionArgs,
    CreateActionResult,
    SignActionArgs,
    SignActionResult,
    AbortActionArgs,
    AbortActionResult,
    ListActionsArgs,
    ListActionsResult,
    InternalizeActionArgs,
    InternalizeActionResult,
    ListOutputsArgs,
    ListOutputsResult,
    RelinquishOutputArgs,
    RelinquishOutputResult,
    AcquireCertificateArgs,
    WalletCertificate,
    ListCertificatesArgs,
    ListCertificatesResult,
    ProveCertificateArgs,
    ProveCertificateResult,
    RelinquishCertificateArgs,
    RelinquishCertificateResult,
    DiscoverByIdentityKeyArgs,
    DiscoverByAttributesArgs,
    DiscoverCertificatesResult,
    AuthenticatedResult,
    GetHeightResult,
    GetHeaderArgs,
    GetHeaderResult,
    GetNetworkResult,
    GetVersionResult,
    RevealCounterpartyKeyLinkageResult,
    RevealSpecificKeyLinkageResult,
);

fn field<T: DeserializeOwned>(v: &Value, name: &str) -> T {
    serde_json::from_value(v[name].clone()).unwrap_or_else(|e| panic!("{name}: {e}; input {v}"))
}

fn protocol(v: &Value) -> Protocol {
    let p = &v["protocolID"];
    Protocol::new(
        SecurityLevel::from_u8(p[0].as_u64().unwrap() as u8).unwrap(),
        p[1].as_str().unwrap(),
    )
}

fn protocol_json(p: &Protocol) -> Value {
    json!([p.security_level.as_u8(), p.protocol_name])
}

fn public_key(v: &Value) -> PublicKey {
    PublicKey::from_hex(v.as_str().unwrap()).unwrap()
}

fn counterparty(v: &Value) -> Option<Counterparty> {
    match v.as_str() {
        None => None,
        Some("self") => Some(Counterparty::Self_),
        Some("anyone") => Some(Counterparty::Anyone),
        Some(_) => Some(Counterparty::Other(public_key(v))),
    }
}

fn counterparty_json(c: Option<&Counterparty>) -> Value {
    match c {
        None => Value::Null,
        Some(Counterparty::Self_) => json!("self"),
        Some(Counterparty::Anyone) => json!("anyone"),
        Some(Counterparty::Other(p)) => json!(p.to_hex()),
    }
}

macro_rules! codec {
    ($ty:ty, |$v:ident| $from:expr, |$s:ident| $to:expr) => {
        impl FixtureJson for $ty {
            fn from_fixture($v: Value) -> Self { $from }
            fn fixture(&$s) -> Value { $to }
        }
    };
}

codec!(
    GetPublicKeyArgs,
    |v| Self {
        identity_key: v["identityKey"].as_bool().unwrap_or(false),
        protocol_id: if v["protocolID"].is_null() {
            None
        } else {
            Some(protocol(&v))
        },
        key_id: field(&v, "keyID"),
        counterparty: counterparty(&v["counterparty"]),
        for_self: field(&v, "forSelf"),
        privileged: field(&v, "privileged"),
        privileged_reason: field(&v, "privilegedReason"),
        seek_permission: field(&v, "seekPermission"),
    },
    |self| json!({"identityKey": self.identity_key.then_some(true),
    "protocolID": self.protocol_id.as_ref().map(protocol_json), "keyID": self.key_id,
    "counterparty": counterparty_json(self.counterparty.as_ref()), "forSelf": self.for_self,
    "privileged": self.privileged, "privilegedReason": self.privileged_reason,
    "seekPermission": self.seek_permission})
);

macro_rules! data_args {
    ($ty:ty, $field:ident, $name:literal) => {
        codec!($ty, |v| Self {
            $field: field(&v, $name), protocol_id: protocol(&v), key_id: field(&v, "keyID"),
            counterparty: counterparty(&v["counterparty"]), privileged: field(&v, "privileged"),
            privileged_reason: field(&v, "privilegedReason"),
            seek_permission: field(&v, "seekPermission"),
        }, |self| json!({$name: self.$field, "protocolID": protocol_json(&self.protocol_id),
            "keyID": self.key_id, "counterparty": counterparty_json(self.counterparty.as_ref()),
            "privileged": self.privileged, "privilegedReason": self.privileged_reason,
            "seekPermission": self.seek_permission}));
    };
}
data_args!(EncryptArgs, plaintext, "plaintext");
data_args!(DecryptArgs, ciphertext, "ciphertext");
data_args!(CreateHmacArgs, data, "data");

codec!(
    VerifyHmacArgs,
    |v| Self {
        data: field(&v, "data"),
        hmac: field(&v, "hmac"),
        protocol_id: protocol(&v),
        key_id: field(&v, "keyID"),
        counterparty: counterparty(&v["counterparty"]),
        privileged: field(&v, "privileged"),
        privileged_reason: field(&v, "privilegedReason"),
        seek_permission: field(&v, "seekPermission"),
    },
    |self| json!({"data": self.data, "hmac": self.hmac, "protocolID": protocol_json(&self.protocol_id),
    "keyID": self.key_id, "counterparty": counterparty_json(self.counterparty.as_ref()),
    "privileged": self.privileged, "privilegedReason": self.privileged_reason,
    "seekPermission": self.seek_permission})
);

codec!(
    CreateSignatureArgs,
    |v| Self {
        data: field(&v, "data"),
        hash_to_directly_sign: field(&v, "hashToDirectlySign"),
        protocol_id: protocol(&v),
        key_id: field(&v, "keyID"),
        counterparty: counterparty(&v["counterparty"]),
        privileged: field(&v, "privileged"),
        privileged_reason: field(&v, "privilegedReason"),
        seek_permission: field(&v, "seekPermission"),
    },
    |self| json!({"data": self.data, "hashToDirectlySign": self.hash_to_directly_sign,
    "protocolID": protocol_json(&self.protocol_id), "keyID": self.key_id,
    "counterparty": counterparty_json(self.counterparty.as_ref()),
    "privileged": self.privileged, "privilegedReason": self.privileged_reason,
    "seekPermission": self.seek_permission})
);

codec!(
    VerifySignatureArgs,
    |v| Self {
        data: field(&v, "data"),
        hash_to_directly_verify: field(&v, "hashToDirectlyVerify"),
        signature: field(&v, "signature"),
        protocol_id: protocol(&v),
        key_id: field(&v, "keyID"),
        counterparty: counterparty(&v["counterparty"]),
        for_self: field(&v, "forSelf"),
        privileged: field(&v, "privileged"),
        privileged_reason: field(&v, "privilegedReason"),
        seek_permission: field(&v, "seekPermission"),
    },
    |self| json!({"data": self.data, "hashToDirectlyVerify": self.hash_to_directly_verify,
    "signature": self.signature, "protocolID": protocol_json(&self.protocol_id), "keyID": self.key_id,
    "counterparty": counterparty_json(self.counterparty.as_ref()), "forSelf": self.for_self,
    "privileged": self.privileged, "privilegedReason": self.privileged_reason,
    "seekPermission": self.seek_permission})
);

codec!(
    RevealCounterpartyKeyLinkageArgs,
    |v| Self {
        counterparty: public_key(&v["counterparty"]),
        verifier: public_key(&v["verifier"]),
        privileged: field(&v, "privileged"),
        privileged_reason: field(&v, "privilegedReason"),
    },
    |self| json!({"counterparty": self.counterparty.to_hex(), "verifier": self.verifier.to_hex(),
    "privileged": self.privileged, "privilegedReason": self.privileged_reason})
);

codec!(
    RevealSpecificKeyLinkageArgs,
    |v| Self {
        counterparty: counterparty(&v["counterparty"]).unwrap(),
        verifier: public_key(&v["verifier"]),
        protocol_id: protocol(&v),
        key_id: field(&v, "keyID"),
        privileged: field(&v, "privileged"),
        privileged_reason: field(&v, "privilegedReason"),
    },
    |self| json!({"counterparty": counterparty_json(Some(&self.counterparty)), "verifier": self.verifier.to_hex(),
    "protocolID": protocol_json(&self.protocol_id), "keyID": self.key_id,
    "privileged": self.privileged, "privilegedReason": self.privileged_reason})
);

macro_rules! result_field {
    ($ty:ty, $field:ident, $name:literal) => {
        codec!($ty, |v| Self { $field: field(&v, $name) }, |self| json!({$name: self.$field}));
    };
}
result_field!(GetPublicKeyResult, public_key, "publicKey");
result_field!(EncryptResult, ciphertext, "ciphertext");
result_field!(DecryptResult, plaintext, "plaintext");
result_field!(CreateHmacResult, hmac, "hmac");
result_field!(VerifyHmacResult, valid, "valid");
result_field!(CreateSignatureResult, signature, "signature");
result_field!(VerifySignatureResult, valid, "valid");
