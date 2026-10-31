//! #489: local authentication preserves the reference's parser words.
#![cfg(feature = "kvstore")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/identity_reveal_wallet.rs"]
mod identity_reveal_wallet;

use bsv_rs::kvstore::{KVStoreConfig, LocalKVStore};
use bsv_rs::primitives::{from_hex, PublicKey};
use bsv_rs::script::{
    templates::{LockPosition, PushDrop},
    LockingScript,
};
use bsv_rs::transaction::Transaction;
use bsv_rs::wallet::*;
use bsv_rs::{Error, Result};
use identity_reveal_wallet::Counting;
use serde_json::Value;

#[derive(Debug)]
struct CorruptKeyWallet {
    inner: Counting,
    public_key: Option<String>,
}

macro_rules! delegate_wallet {
    ($(($method:ident, $args:ty, $result:ty)),* $(,)?;
     $(($status:ident, $status_result:ty)),* $(,)?) => {
        #[async_trait::async_trait]
        impl WalletInterface for CorruptKeyWallet {
            async fn get_public_key(&self, args: GetPublicKeyArgs, originator: Option<&str>)
                -> Result<GetPublicKeyResult> {
                if args.for_self.is_none() {
                    if let Some(public_key) = &self.public_key {
                        return Ok(GetPublicKeyResult { public_key: public_key.clone() });
                    }
                }
                self.inner.get_public_key(args, originator).await
            }

            $(async fn $method(&self, args: $args, originator: Option<&str>) -> Result<$result> {
                self.inner.$method(args, originator).await
            })*

            $(async fn $status(&self, originator: Option<&str>) -> Result<$status_result> {
                self.inner.$status(originator).await
            })*
        }
    };
}

delegate_wallet! {
    (list_outputs, ListOutputsArgs, ListOutputsResult),
    (verify_signature, VerifySignatureArgs, VerifySignatureResult),
    (create_signature, CreateSignatureArgs, CreateSignatureResult),
    (create_action, CreateActionArgs, CreateActionResult),
    (sign_action, SignActionArgs, SignActionResult),
    (abort_action, AbortActionArgs, AbortActionResult),
    (encrypt, EncryptArgs, EncryptResult),
    (decrypt, DecryptArgs, DecryptResult),
    (create_hmac, CreateHmacArgs, CreateHmacResult),
    (verify_hmac, VerifyHmacArgs, VerifyHmacResult),
    (reveal_counterparty_key_linkage, WalletRevealCounterpartyArgs, RevealCounterpartyKeyLinkageResult),
    (reveal_specific_key_linkage, WalletRevealSpecificArgs, RevealSpecificKeyLinkageResult),
    (list_actions, ListActionsArgs, ListActionsResult),
    (internalize_action, InternalizeActionArgs, InternalizeActionResult),
    (relinquish_output, RelinquishOutputArgs, RelinquishOutputResult),
    (acquire_certificate, AcquireCertificateArgs, WalletCertificate),
    (list_certificates, ListCertificatesArgs, ListCertificatesResult),
    (prove_certificate, ProveCertificateArgs, ProveCertificateResult),
    (relinquish_certificate, RelinquishCertificateArgs, RelinquishCertificateResult),
    (discover_by_identity_key, DiscoverByIdentityKeyArgs, DiscoverCertificatesResult),
    (discover_by_attributes, DiscoverByAttributesArgs, DiscoverCertificatesResult),
    (get_header_for_height, GetHeaderArgs, GetHeaderResult);
    (is_authenticated, AuthenticatedResult),
    (wait_for_authentication, AuthenticatedResult),
    (get_height, GetHeightResult),
    (get_network, GetNetworkResult),
    (get_version, GetVersionResult),
}

fn wallet(case: &Value) -> CorruptKeyWallet {
    let bytes = from_hex(case["source_beef"].as_str().unwrap()).unwrap();
    let source = Transaction::from_beef(&bytes, None).unwrap();
    assert_eq!(
        source.outputs[0].locking_script.to_hex(),
        case["locking_script"].as_str().unwrap()
    );
    let inner = Counting::of_scalar(9);
    *inner.listed.lock().unwrap() = Some(ListOutputsResult {
        total_outputs: 1,
        beef: Some(bytes),
        outputs: vec![WalletOutput {
            outpoint: Outpoint::from_string(&format!("{}.0", source.id())).unwrap(),
            satoshis: source.outputs[0].satoshis.unwrap(),
            locking_script: Some(source.outputs[0].locking_script.to_binary()),
            spendable: true,
            tags: Some(vec!["alpha".into()]),
            labels: None,
            custom_instructions: None,
        }],
    });
    CorruptKeyWallet {
        inner,
        public_key: case["public_key"].as_str().map(str::to_owned),
    }
}

async fn assert_cases(kind: &str, count: usize) {
    let recorded: Value =
        serde_json::from_str(include_str!("vectors/kvstore_local_454.json")).unwrap();
    let cases: Vec<_> = recorded["parser_words_489"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case["kind"] == kind)
        .collect();
    assert_eq!(
        cases.len(),
        count,
        "each corruption recorded for get and set"
    );
    for case in cases {
        let actual = local_failure(case).await;
        let expected = case["error"].as_str().unwrap();
        assert_eq!(actual.to_string(), expected, "{}", case["name"]);
        assert_eq!(actual, Error::KvStoreLocalError(expected.into()));
    }
}

async fn local_failure(case: &Value) -> Error {
    let store =
        LocalKVStore::new(wallet(case), KVStoreConfig::default().with_encrypt(false)).unwrap();
    match case["operation"].as_str().unwrap() {
        "get" => store.get("alpha", "missing").await.map(|_| ()),
        "set" => store.set("alpha", "two", None).await.map(|_| ()),
        operation => panic!("unrecorded operation {operation}"),
    }
    .unwrap_err()
}

fn divergence_cases(kind: &str) -> Vec<Value> {
    let recorded: Value =
        serde_json::from_str(include_str!("vectors/kvstore_local_454.json")).unwrap();
    let cases: Vec<_> = recorded["parser_words_489"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case["kind"] == kind)
        .cloned()
        .collect();
    assert_eq!(cases.len(), 2, "each divergence recorded for get and set");
    cases
}

fn wrapped(message: &str) -> String {
    format!("Invalid value found. Relinquish the corrupted output from the kvstore basket before using this key again. Original error: {message}")
}

async fn assert_stricter_key(kind: &str, native: Error) {
    for case in divergence_cases(kind) {
        assert_eq!(case["parser_accepted"], true, "reference accepts this key");
        assert!(case["parser_error"].is_null());
        let (actual_native, reference_later_check) = match case["public_key"].as_str() {
            Some(key) => (
                PublicKey::from_hex(key).unwrap_err(),
                "KVStore token locking key does not belong to the wallet",
            ),
            None => (
                PushDrop::decode(
                    &LockingScript::from_hex(case["locking_script"].as_str().unwrap()).unwrap(),
                )
                .unwrap_err(),
                "PushDrop token must use the canonical PushDrop envelope",
            ),
        };
        assert_eq!(actual_native, native, "standalone parser still refuses");
        assert_eq!(case["error"], wrapped(reference_later_check));
        assert_eq!(
            local_failure(&case).await,
            Error::KvStoreLocalError(wrapped(&native.to_string())),
            "{} {}: use native words when the reference parser accepts",
            case["name"],
            case["operation"]
        );
    }
}

/// #498: the reference's parser and `PublicKey::from_hex` both accept the key,
/// and the local store refuses it in the reference's later words.
async fn assert_accepted_key(kind: &str) {
    for case in divergence_cases(kind) {
        assert_eq!(case["parser_accepted"], true, "reference accepts this key");
        assert!(case["parser_error"].is_null());
        PublicKey::from_hex(case["public_key"].as_str().unwrap()).unwrap();
        let reference = wrapped("KVStore token locking key does not belong to the wallet");
        assert_eq!(case["error"], reference);
        assert_eq!(
            local_failure(&case).await,
            Error::KvStoreLocalError(reference),
            "{} {}: the reference's words now the key parses",
            case["name"],
            case["operation"]
        );
    }
}

#[tokio::test]
async fn non_hex_locking_key_uses_reference_words_489() {
    assert_eq!(
        PublicKey::from_hex("zz").unwrap_err(),
        Error::InvalidHex("Invalid character 'z' at position 0".into())
    );
    assert_cases("invalid_hex", 4).await;
}

#[tokio::test]
async fn wrong_length_or_prefix_locking_key_uses_reference_words_489() {
    assert_cases("unknown_point", 12).await;
}

#[tokio::test]
async fn off_curve_locking_key_uses_reference_words_489() {
    assert_eq!(
        PublicKey::from_hex(&format!("02{}", "00".repeat(32))).unwrap_err(),
        Error::InvalidPublicKey("Point not on curve".into())
    );
    assert_cases("invalid_point", 6).await;
}

#[tokio::test]
async fn hybrid_key_parity_uses_reference_words_489() {
    assert_cases("hybrid_length", 6).await;
}

#[tokio::test]
async fn non_pushdrop_token_uses_reference_words_489() {
    assert_eq!(
        PushDrop::decode(&LockingScript::from_hex("51").unwrap()).unwrap_err(),
        Error::ScriptParseError("Script too short for PushDrop".into())
    );
    assert_cases("token", 8).await;
}

#[tokio::test]
async fn reference_and_local_accept_odd_valid_key_489_498() {
    // #498: from_hex reads this key as the reference does, so the local lookup
    // reaches the reference's later words; strictness returns on the upstream's
    // answer (this test's #489 form was assert_stricter_key with native words).
    assert_accepted_key("key_odd_valid").await;
}

#[tokio::test]
async fn reference_and_local_accept_hybrid_key_489_498() {
    // #498: from_hex reads this key as the reference does, so the local lookup
    // reaches the reference's later words; strictness returns on the upstream's
    // answer (this test's #489 form was assert_stricter_key with native words).
    assert_accepted_key("key_hybrid_valid").await;
}

#[tokio::test]
async fn reference_and_local_accept_odd_hybrid_key_489_498() {
    // #498: from_hex reads this key as the reference does, so the local lookup
    // reaches the reference's later words; strictness returns on the upstream's
    // answer (this test's #489 form was assert_stricter_key with native words).
    assert_accepted_key("key_odd_hybrid_valid").await;
}

#[tokio::test]
async fn reference_and_local_accept_reduced_x_key_489_498() {
    // #498: from_hex reads this key as the reference does, so the local lookup
    // reaches the reference's later words; strictness returns on the upstream's
    // answer (this test's #489 form was assert_stricter_key with native words).
    assert_accepted_key("key_reduced_x").await;
}

#[tokio::test]
async fn reference_decodes_hybrid_token_but_local_keeps_native_words_489() {
    assert_stricter_key(
        "token_hybrid_valid",
        Error::InvalidPublicKey(
            "Invalid public key encoding: elliptic curve point encoding error".into(),
        ),
    )
    .await;
}

#[tokio::test]
async fn reference_decodes_reduced_x_token_but_local_keeps_native_words_489() {
    assert_stricter_key(
        "token_reduced_x",
        Error::InvalidPublicKey("Point not on curve".into()),
    )
    .await;
}

#[tokio::test]
async fn a_lock_after_token_is_refused_by_the_reference_lock_before_read_499() {
    // The general decoder still reads these as lock-after (#499 leaves it).
    let recorded: Value =
        serde_json::from_str(include_str!("vectors/kvstore_local_454.json")).unwrap();
    for case in recorded["parser_words_489"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| case["kind"] == "token_lock_after")
    {
        let script = LockingScript::from_hex(case["locking_script"].as_str().unwrap()).unwrap();
        assert_eq!(
            PushDrop::decode(&script).unwrap().lock_position,
            LockPosition::After
        );
        assert_eq!(
            case["error"],
            wrapped(case["parser_error"].as_str().unwrap())
        );
    }
    assert_cases("token_lock_after", 12).await;
}
