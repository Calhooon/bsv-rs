//! #537, site 2: the contacts manager decodes a stored contact's token
//! lock-before alone, as its counterpart does (`ts-stack@edf6e03`
//! `ContactsManager.ts:432`, `PushDrop.decode` at its default position): a
//! lock-after token is dropped, as the reference's `Promise.allSettled` at
//! `:478`, `:507-513` drops it, before the wallet is asked to decrypt.
#![cfg(feature = "identity")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "support/pushdrop_decode_618.rs"]
mod decode_618;
#[path = "support/identity_reveal_wallet.rs"]
mod identity_reveal_wallet;
#[path = "support/pushdrop_lock_position_537.rs"]
mod lock_position;

use bsv_rs::identity::{ContactsManager, ContactsManagerConfig};
use bsv_rs::script::LockingScript;
use bsv_rs::wallet::*;
use bsv_rs::Result;
use identity_reveal_wallet::Counting;
use serde_json::Value;

/// The counting wallet listing one contact output, whose decrypt answers the
/// contact's plaintext as the reference's wallet decrypted it.
#[derive(Debug)]
struct ContactWallet {
    inner: Counting,
    plaintext: Vec<u8>,
}

macro_rules! delegate_wallet {
    ($(($method:ident, $args:ty, $result:ty)),* $(,)?;
     $(($status:ident, $status_result:ty)),* $(,)?) => {
        #[async_trait::async_trait]
        impl WalletInterface for ContactWallet {
            async fn decrypt(&self, _args: DecryptArgs, _originator: Option<&str>)
                -> Result<DecryptResult> {
                Ok(DecryptResult { plaintext: self.plaintext.clone() })
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
    (get_public_key, GetPublicKeyArgs, GetPublicKeyResult),
    (list_outputs, ListOutputsArgs, ListOutputsResult),
    (verify_signature, VerifySignatureArgs, VerifySignatureResult),
    (create_signature, CreateSignatureArgs, CreateSignatureResult),
    (create_action, CreateActionArgs, CreateActionResult),
    (sign_action, SignActionArgs, SignActionResult),
    (abort_action, AbortActionArgs, AbortActionResult),
    (encrypt, EncryptArgs, EncryptResult),
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

/// The contacts the manager loads from a wallet listing `script`.
async fn contacts(case: &Value, script: LockingScript) -> usize {
    let inner = Counting::of_scalar(9);
    *inner.listed.lock().unwrap() = Some(ListOutputsResult {
        total_outputs: 1,
        beef: None,
        outputs: vec![WalletOutput {
            outpoint: Outpoint::from_string(&format!("{}.0", "22".repeat(32))).unwrap(),
            satoshis: 1,
            locking_script: Some(script.to_binary()),
            spendable: true,
            tags: None,
            labels: None,
            custom_instructions: Some(serde_json::json!({ "keyID": case["key_id"] }).to_string()),
        }],
    });
    let wallet = ContactWallet {
        inner,
        plaintext: case["plaintext"].as_str().unwrap().as_bytes().to_vec(),
    };
    let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());
    manager
        .list_contacts_with_refresh(true)
        .await
        .unwrap()
        .len()
}

#[tokio::test]
async fn a_lock_after_contact_token_is_dropped_as_the_reference_drops_it_537() {
    let cases = lock_position::cases("contacts_cache");
    assert_eq!(cases.len(), 2);
    for case in &cases {
        assert_eq!(case["outcome"], "skipped", "{}", case["name"]);
        assert_eq!(
            contacts(case, lock_position::script(case)).await,
            0,
            "{}",
            case["name"]
        );
    }
    // The same fields locked before were loaded until #544; since then the
    // reference's authentication drops them too: the key is not the
    // wallet's for the key ID (`ContactsManager.ts:447-449`).
    let control = lock_position::relocked_before(&cases[0]);
    assert_eq!(contacts(&cases[0], control).await, 0);
}

/// The #537 case a #618 case was built from.
fn from_537<'a>(cases: &'a [Value], case: &Value) -> &'a Value {
    cases
        .iter()
        .find(|old| old["name"] == case["from_537"])
        .unwrap()
}

/// #618: a key alone and a token without CHECKSIG second, which the public
/// `PushDrop::decode` reads as the reference does, are dropped, as the
/// reference's field count and canonical-script check drop them
/// (`ContactsManager.ts:432`, `:225-242`; `Invalid contact PushDrop field
/// count`, `Contact output must use the canonical signed PushDrop script`).
#[tokio::test]
async fn a_key_only_and_a_no_checksig_contact_token_are_dropped_as_the_reference_drops_them_618() {
    let old = lock_position::cases("contacts_cache");
    let cases = decode_618::cases("contacts_cache");
    assert_eq!(cases.len(), 2);
    for case in &cases {
        assert_eq!(case["outcome"], "skipped", "{}", case["name"]);
        let from = from_537(&old, case);
        let script = decode_618::script(case, from);
        assert_eq!(contacts(from, script).await, 0, "{}", case["name"]);
    }
}
