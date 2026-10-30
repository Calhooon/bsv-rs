//! #477: local wrappers retain the original message, without family prefixes.
#![cfg(feature = "kvstore")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/identity_reveal_wallet.rs"]
mod identity_reveal_wallet;

use bsv_rs::error::{WalletFault, WalletFaultFamily};
use bsv_rs::kvstore::{KVStoreConfig, LocalKVStore};
use bsv_rs::primitives::from_hex;
use bsv_rs::transaction::Transaction;
use bsv_rs::wallet::*;
use bsv_rs::{Error, Result};
use identity_reveal_wallet::Counting;
use serde_json::Value;

#[derive(Debug)]
struct FailingWallet {
    inner: Counting,
    failure: Option<(String, Error)>,
    listed_beef: Option<Vec<u8>>,
    action_beef: Option<Vec<u8>>,
}

impl FailingWallet {
    fn check(&self, method: &str) -> Result<()> {
        if let Some((stage, error)) = &self.failure {
            if stage == method {
                return Err(error.clone());
            }
        }
        Ok(())
    }
}

macro_rules! failing_wallet {
    ($(($method:ident, $args:ty, $result:ty)),* $(,)?;
     $(($status:ident, $status_result:ty)),* $(,)?) => {
        #[async_trait::async_trait]
        impl WalletInterface for FailingWallet {
            async fn list_outputs(&self, args: ListOutputsArgs, originator: Option<&str>)
                -> Result<ListOutputsResult> {
                self.check("listOutputs")?;
                let mut result = self.inner.list_outputs(args, originator).await?;
                if let Some(beef) = &self.listed_beef {
                    result.beef = Some(beef.clone());
                }
                Ok(result)
            }

            async fn create_action(&self, args: CreateActionArgs, originator: Option<&str>)
                -> Result<CreateActionResult> {
                self.check("createAction")?;
                let mut result = self.inner.create_action(args, originator).await?;
                if let Some(beef) = &self.action_beef {
                    result.signable_transaction.as_mut().unwrap().tx = beef.clone();
                }
                Ok(result)
            }

            $(async fn $method(&self, args: $args, originator: Option<&str>) -> Result<$result> {
                self.check(match stringify!($method) {
                    "get_public_key" => "getPublicKey",
                    "verify_signature" => "verifySignature",
                    "sign_action" => "signAction",
                    name => name,
                })?;
                self.inner.$method(args, originator).await
            })*

            $(async fn $status(&self, originator: Option<&str>) -> Result<$status_result> {
                self.inner.$status(originator).await
            })*
        }
    };
}

failing_wallet! {
    (get_public_key, GetPublicKeyArgs, GetPublicKeyResult),
    (verify_signature, VerifySignatureArgs, VerifySignatureResult),
    (create_signature, CreateSignatureArgs, CreateSignatureResult),
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

fn fixture() -> Value {
    let recorded: Value =
        serde_json::from_str(include_str!("vectors/kvstore_local_454.json")).unwrap();
    recorded["original_errors_477"].clone()
}

fn wallet() -> FailingWallet {
    let bytes = from_hex(fixture()["source_beef"].as_str().unwrap()).unwrap();
    let source = Transaction::from_beef(&bytes, None).unwrap();
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
    *inner.spending.lock().unwrap() = Some(source);
    FailingWallet {
        inner,
        failure: None,
        listed_beef: None,
        action_beef: None,
    }
}

async fn run(wallet: FailingWallet, operation: &str) -> Error {
    let store = LocalKVStore::new(wallet, KVStoreConfig::default().with_encrypt(false)).unwrap();
    match operation {
        "get" => store.get("alpha", "missing").await.map(|_| ()),
        "set" => store.set("alpha", "two", None).await.map(|_| ()),
        "remove" => store.remove("alpha", None).await.map(|_| ()),
        other => panic!("unknown operation {other}"),
    }
    .unwrap_err()
}

async fn assert_injected(kind: &str, error: Error) {
    let recorded = fixture();
    let mut count = 0;
    for case in recorded["injected"].as_array().unwrap() {
        if case["kind"] != kind {
            continue;
        }
        let mut wallet = wallet();
        wallet.failure = Some((case["stage"].as_str().unwrap().into(), error.clone()));
        let actual = run(wallet, case["operation"].as_str().unwrap()).await;
        let expected = case["error"].as_str().unwrap();
        assert_eq!(actual.to_string(), expected, "{case}");
        assert_eq!(actual, Error::KvStoreLocalError(expected.into()));
        count += 1;
    }
    assert_eq!(count, 10, "both lookup catches and both action wrappers");
}

#[tokio::test]
async fn wallet_fault_uses_its_message_at_every_local_wrap_477() {
    for family in [
        WalletFaultFamily::Transport,
        WalletFaultFamily::Service,
        WalletFaultFamily::Storage,
        WalletFaultFamily::Internal,
    ] {
        let message: String = fixture()["messages"]["wallet_fault"]
            .as_str()
            .unwrap()
            .into();
        assert_injected(
            "wallet_fault",
            Error::WalletFault(WalletFault::new(family, message)),
        )
        .await;
    }
}

#[tokio::test]
async fn beef_error_uses_its_own_words_at_every_local_wrap_477() {
    let message = fixture()["messages"]["beef_error"].as_str().unwrap().into();
    assert_injected("beef_error", Error::BeefError(message)).await;
}

#[tokio::test]
async fn transaction_error_uses_its_own_words_at_every_local_wrap_477() {
    let message = fixture()["messages"]["transaction_error"]
        .as_str()
        .unwrap()
        .into();
    assert_injected("transaction_error", Error::TransactionError(message)).await;
}

#[tokio::test]
async fn wallet_error_preserves_its_entire_string_477() {
    let message = fixture()["messages"]["wallet_error"]
        .as_str()
        .unwrap()
        .into();
    assert_injected("wallet_error", Error::WalletError(message)).await;
}

#[tokio::test]
async fn kvstore_error_preserves_its_entire_string_477() {
    let message = fixture()["messages"]["kvstore_error"]
        .as_str()
        .unwrap()
        .into();
    assert_injected("kvstore_error", Error::KvStoreError(message)).await;
}

#[tokio::test]
async fn kvstore_local_error_preserves_its_entire_string_477() {
    let message = fixture()["messages"]["kvstore_local_error"]
        .as_str()
        .unwrap()
        .into();
    assert_injected("kvstore_local_error", Error::KvStoreLocalError(message)).await;
}

#[tokio::test]
async fn corrupt_beef_keeps_the_parser_words_without_the_family_prefix_477() {
    assert_corrupt(
        "beef_error",
        "invalid BEEF at byte 0: BadVersion { word: 0 }",
    )
    .await;
}

#[tokio::test]
async fn non_atomic_transaction_keeps_the_parser_words_without_the_family_prefix_477() {
    assert_corrupt("transaction_error", "Not an Atomic BEEF format").await;
}

async fn assert_corrupt(kind: &str, message: &str) {
    let recorded = fixture();
    let mut count = 0;
    for case in recorded["malformed"].as_array().unwrap() {
        if case["kind"] != kind {
            continue;
        }
        let mut wallet = wallet();
        let bytes = from_hex(case["bytes"].as_str().unwrap()).unwrap();
        if case["stage"] == "listOutputs" {
            wallet.listed_beef = Some(bytes);
        } else {
            wallet.action_beef = Some(bytes);
        }
        // This lane removes the family prefix, preserving the parser's own
        // pre-existing words. The recorder also retains the TS parser words.
        let expected = if case["stage"] == "listOutputs" {
            format!("Invalid value found. Relinquish the corrupted output from the kvstore basket before using this key again. Original error: {message}")
        } else {
            format!("There are 1 outputs with tag alpha that cannot be unlocked. Original error: {message}")
        };
        let actual = run(wallet, case["operation"].as_str().unwrap()).await;
        assert_eq!(actual.to_string(), expected, "{case}");
        assert_eq!(actual, Error::KvStoreLocalError(expected));
        count += 1;
    }
    assert_eq!(count, if kind == "beef_error" { 4 } else { 2 });
}

#[tokio::test]
async fn other_variants_keep_their_display_in_both_wrappers_477() {
    for (error, message) in [
        (
            Error::InvalidPublicKey("Point not on curve".into()),
            "invalid public key: Point not on curve",
        ),
        (
            Error::WalletBusy {
                detail: "store busy".into(),
                retry_after_ms: Some(2),
            },
            "wallet busy: store busy",
        ),
        (
            Error::WalletRefusal {
                class: bsv_rs::error::WalletRefusalClass::InvalidParameter,
                message: "Invalid parameter: example".into(),
            },
            "Invalid parameter: example",
        ),
    ] {
        for (stage, operation, expected) in [
            ("listOutputs", "get", format!("Invalid value found. Relinquish the corrupted output from the kvstore basket before using this key again. Original error: {message}")),
            ("createAction", "set", format!("There are 1 outputs with tag alpha that cannot be unlocked. Original error: {message}")),
        ] {
            let mut wallet = wallet();
            wallet.failure = Some((stage.into(), error.clone()));
            assert_eq!(run(wallet, operation).await.to_string(), expected);
        }
    }
}
