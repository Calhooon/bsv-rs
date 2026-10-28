//! Invocation and deterministic observations of #420's recorded calls.
use bsv_rs::primitives::{PrivateKey, PublicKey};
use bsv_rs::wallet::{
    Counterparty, CreateHmacArgs, CreateSignatureArgs, DecryptArgs, EncryptArgs, GetPublicKeyArgs,
    KeyDeriverApi, ProtoWallet, Protocol, SecurityLevel, VerifyHmacArgs, VerifySignatureArgs,
    WalletInterface,
};
use bsv_rs::{Result, SymmetricKey};
use serde::Deserialize;
use serde_json::{json, Value};

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
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Request {
    #[serde(rename = "protocolID")]
    protocol: Option<(u8, String)>,
    #[serde(rename = "keyID")]
    key_id: Option<String>,
    counterparty: Option<String>,
    verifier: Option<String>,
    #[serde(default)]
    identity_key: bool,
    plaintext: Option<Bytes>,
    ciphertext: Option<Bytes>,
    privileged: Option<bool>,
    privileged_reason: Option<String>,
    seek_permission: Option<bool>,
    for_self: Option<bool>,
}

impl Request {
    fn protocol(&self) -> Option<Protocol> {
        self.protocol
            .as_ref()
            .map(|(level, name)| Protocol::new(SecurityLevel::from_u8(*level).unwrap(), name))
    }

    fn counterparty(&self) -> Result<Option<Counterparty>> {
        self.counterparty
            .as_deref()
            .map(|key| match key {
                "self" => Ok(Counterparty::Self_),
                "anyone" => Ok(Counterparty::Anyone),
                other => Counterparty::from_hex(other),
            })
            .transpose()
    }
}

fn wallet(key: u8) -> ProtoWallet {
    ProtoWallet::new(Some(PrivateKey::from_hex(&format!("{key:064x}")).unwrap()))
}

macro_rules! args {
    ($kind:ident, $r:ident, $($field:ident: $value:expr),* $(,)?) => {
        $kind {
            protocol_id: $r.protocol().unwrap(), key_id: $r.key_id.clone().unwrap(),
            counterparty: $r.counterparty()?, privileged: $r.privileged,
            privileged_reason: $r.privileged_reason.clone(), seek_permission: $r.seek_permission,
            $($field: $value,)*
        }
    };
}

pub fn invoke(case: &Value) -> Result<Value> {
    let r: Request = serde_json::from_value(case["args"].clone()).unwrap();
    let wallet = wallet(42);
    match case["method"].as_str().unwrap() {
        "getPublicKey" => wallet
            .get_public_key(GetPublicKeyArgs {
                identity_key: r.identity_key,
                protocol_id: r.protocol(),
                key_id: r.key_id.clone(),
                counterparty: r.counterparty()?,
                for_self: r.for_self,
                privileged: r.privileged,
                privileged_reason: r.privileged_reason,
                seek_permission: r.seek_permission,
            })
            .map(|r| json!({ "publicKey": r.public_key })),
        "encrypt" => {
            let encrypted = wallet.encrypt(args!(EncryptArgs, r,
                plaintext: r.plaintext.as_ref().unwrap().bytes()))?;
            if case["expected"]["code"] == 6 {
                return Ok(json!({ "accepted": true }));
            }
            let decoded =
                wallet.decrypt(args!(DecryptArgs, r, ciphertext: encrypted.ciphertext.clone()))?;
            Ok(
                json!({ "plaintext": decoded.plaintext, "ciphertextLength": encrypted.ciphertext.len() }),
            )
        }
        "decrypt" => wallet
            .decrypt(args!(DecryptArgs, r, ciphertext: r.ciphertext.as_ref().unwrap().bytes()))
            .map(|r| json!({ "plaintext": r.plaintext })),
        "revealCounterpartyKeyLinkage" => {
            counterparty_linkage(&wallet, &r, case["inherent"] == true)
        }
        "revealSpecificKeyLinkage" => specific_linkage(&wallet, &r, case["inherent"] == true),
        method => old_crypto(&wallet, &r, method),
    }
}

fn old_crypto(wallet: &ProtoWallet, r: &Request, method: &str) -> Result<Value> {
    // These four rows stop at encoded-counterparty intake, before cryptography.
    r.counterparty()?;
    match method {
        "createSignature" => wallet
            .create_signature(args!(CreateSignatureArgs, r,
            data: Some(vec![1, 2, 3]), hash_to_directly_sign: None))
            .map(|r| json!(r.signature)),
        "verifySignature" => wallet
            .verify_signature(args!(VerifySignatureArgs, r,
            data: Some(vec![1, 2, 3]), hash_to_directly_verify: None,
            signature: vec![], for_self: None))
            .map(|r| json!(r.valid)),
        "createHmac" => wallet
            .create_hmac(args!(CreateHmacArgs, r, data: vec![1, 2, 3]))
            .map(|r| json!(r.hmac)),
        "verifyHmac" => wallet
            .verify_hmac(args!(VerifyHmacArgs, r,
            data: vec![1, 2, 3], hmac: [0; 32]))
            .map(|r| json!(r.valid)),
        _ => panic!("unknown method {method}"),
    }
}

fn decrypt_key(
    prover: &PublicKey,
    verifier: &PublicKey,
    protocol: &Protocol,
    key: &str,
) -> SymmetricKey {
    wallet(if verifier == &wallet(88).identity_key() {
        88
    } else {
        69
    })
    .key_deriver()
    .derive_symmetric_key(protocol, key, &Counterparty::Other(prover.clone()))
    .unwrap()
}

fn counterparty_linkage(wallet: &ProtoWallet, r: &Request, inherent: bool) -> Result<Value> {
    use bsv_rs::wallet::interface::RevealCounterpartyKeyLinkageArgs;
    use bsv_rs::wallet::types::RevealCounterpartyKeyLinkageResult;
    use bsv_rs::wallet::RevealCounterpartyKeyLinkageArgs as InherentArgs;
    let counterparty = PublicKey::from_hex(r.counterparty.as_ref().unwrap()).unwrap();
    let verifier = PublicKey::from_hex(r.verifier.as_ref().unwrap()).unwrap();
    let result: RevealCounterpartyKeyLinkageResult = if inherent {
        let result = wallet.reveal_counterparty_key_linkage(InherentArgs {
            counterparty: counterparty.clone(),
            verifier: verifier.clone(),
        })?;
        RevealCounterpartyKeyLinkageResult {
            linkage: bsv_rs::wallet::KeyLinkageResult {
                prover: wallet.identity_key(),
                verifier,
                counterparty,
                encrypted_linkage: result.encrypted_linkage,
                encrypted_linkage_proof: result.encrypted_linkage_proof,
            },
            revelation_time: result.revelation_time,
        }
    } else {
        futures::executor::block_on(WalletInterface::reveal_counterparty_key_linkage(
            wallet,
            RevealCounterpartyKeyLinkageArgs {
                counterparty,
                verifier,
                privileged: r.privileged,
                privileged_reason: r.privileged_reason.clone(),
            },
            None,
        ))?
    };
    let key = decrypt_key(
        &result.linkage.prover,
        &result.linkage.verifier,
        &Protocol::new(
            SecurityLevel::Counterparty,
            "counterparty linkage revelation",
        ),
        &result.revelation_time,
    );
    observe_linkage(&result.linkage, &key, None)
}

fn specific_result(
    wallet: &ProtoWallet,
    r: &Request,
    inherent: bool,
) -> Result<bsv_rs::wallet::RevealSpecificKeyLinkageResult> {
    use bsv_rs::wallet::interface::RevealSpecificKeyLinkageArgs;
    use bsv_rs::wallet::types::RevealSpecificKeyLinkageResult;
    use bsv_rs::wallet::RevealSpecificKeyLinkageArgs as InherentArgs;
    let counterparty = r.counterparty()?.unwrap();
    let verifier = PublicKey::from_hex(r.verifier.as_ref().unwrap()).unwrap();
    let protocol = r.protocol().unwrap();
    let key_id = r.key_id.clone().unwrap();
    if inherent {
        let result = wallet.reveal_specific_key_linkage(InherentArgs {
            counterparty: counterparty.clone(),
            verifier: verifier.clone(),
            protocol_id: protocol.clone(),
            key_id: key_id.clone(),
        })?;
        Ok(RevealSpecificKeyLinkageResult {
            linkage: bsv_rs::wallet::KeyLinkageResult {
                prover: wallet.identity_key(),
                verifier,
                counterparty: counterparty
                    .public_key()
                    .cloned()
                    .unwrap_or_else(|| wallet.identity_key()),
                encrypted_linkage: result.encrypted_linkage,
                encrypted_linkage_proof: result.encrypted_linkage_proof,
            },
            protocol: result.protocol_id,
            key_id: result.key_id,
            proof_type: result.proof_type,
        })
    } else {
        futures::executor::block_on(WalletInterface::reveal_specific_key_linkage(
            wallet,
            RevealSpecificKeyLinkageArgs {
                counterparty,
                verifier,
                protocol_id: protocol.clone(),
                key_id: key_id.clone(),
                privileged: r.privileged,
                privileged_reason: r.privileged_reason.clone(),
            },
            None,
        ))
    }
}

fn specific_linkage(wallet: &ProtoWallet, r: &Request, inherent: bool) -> Result<Value> {
    let result = specific_result(wallet, r, inherent)?;
    let protocol = &result.protocol;
    let key_id = &result.key_id;
    let encryption = Protocol::new(
        SecurityLevel::Counterparty,
        format!(
            "specific linkage revelation {} {}",
            protocol.security_level.as_u8(),
            protocol.protocol_name
        ),
    );
    let key = decrypt_key(
        &result.linkage.prover,
        &result.linkage.verifier,
        &encryption,
        key_id,
    );
    observe_linkage(
        &result.linkage,
        &key,
        Some((&result.protocol, &result.key_id, result.proof_type)),
    )
}

fn observe_linkage(
    linkage: &bsv_rs::wallet::KeyLinkageResult,
    key: &SymmetricKey,
    specific: Option<(&Protocol, &str, u8)>,
) -> Result<Value> {
    let mut value = json!({ "prover": linkage.prover.to_hex(), "verifier": linkage.verifier.to_hex(),
        "counterparty": linkage.counterparty.to_hex(), "linkage": key.decrypt(&linkage.encrypted_linkage)?,
        "proofLength": key.decrypt(&linkage.encrypted_linkage_proof)?.len() });
    if let Some((protocol, key_id, proof_type)) = specific {
        value["protocolID"] = json!([protocol.security_level.as_u8(), protocol.protocol_name]);
        value["keyID"] = key_id.into();
        value["proofType"] = proof_type.into();
    }
    Ok(value)
}
