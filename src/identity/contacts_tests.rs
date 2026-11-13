//! Contacts manager unit tests.
#![cfg(test)]

use super::*;
use crate::transaction::{TransactionInput, TransactionOutput};
use crate::wallet::*;

/// A ProtoWallet that holds no contact and answers a create: listOutputs an
/// empty listing, createAction without inputs its finished transaction.
/// Since #904 the manager returns a wallet's failure, so these tests, which
/// leaned on the ProtoWallet's refused listOutputs and createAction being
/// swallowed, run over a wallet that answers them.
#[derive(Clone)]
struct Answering(ProtoWallet);

macro_rules! forward {
    ($(($method:ident, $args:ty, $result:ty)),* ; $(($status:ident, $sresult:ty)),*) => {
        #[async_trait::async_trait]
        impl WalletInterface for Answering {
            $(async fn $method(&self, args: $args, o: Option<&str>) -> Result<$result> {
                WalletInterface::$method(&self.0, args, o).await
            })*
            $(async fn $status(&self, o: Option<&str>) -> Result<$sresult> {
                WalletInterface::$status(&self.0, o).await
            })*
            async fn list_outputs(
                &self,
                _args: ListOutputsArgs,
                _o: Option<&str>,
            ) -> Result<ListOutputsResult> {
                Ok(ListOutputsResult { outputs: vec![], total_outputs: 0, beef: None })
            }
            async fn create_action(
                &self,
                args: CreateActionArgs,
                _o: Option<&str>,
            ) -> Result<CreateActionResult> {
                let mut tx = Transaction::new();
                let mut input = TransactionInput::new("11".repeat(32), 0);
                input.unlocking_script =
                    Some(crate::script::UnlockingScript::from_binary(&[0x51])?);
                tx.add_input(input)?;
                for output in args.outputs.iter().flatten() {
                    let lock = crate::script::LockingScript::from_binary(&output.locking_script)?;
                    tx.add_output(TransactionOutput::new(output.satoshis, lock))?;
                }
                Ok(CreateActionResult { tx: Some(tx.to_atomic_beef(true)?), ..Default::default() })
            }
        }
    };
}

forward! {
    (get_public_key, GetPublicKeyArgs, GetPublicKeyResult),
    (encrypt, EncryptArgs, EncryptResult),
    (decrypt, DecryptArgs, DecryptResult),
    (create_hmac, CreateHmacArgs, CreateHmacResult),
    (verify_hmac, VerifyHmacArgs, VerifyHmacResult),
    (create_signature, CreateSignatureArgs, CreateSignatureResult),
    (verify_signature, VerifySignatureArgs, VerifySignatureResult),
    (reveal_counterparty_key_linkage, WalletRevealCounterpartyArgs, RevealCounterpartyKeyLinkageResult),
    (reveal_specific_key_linkage, WalletRevealSpecificArgs, RevealSpecificKeyLinkageResult),
    (sign_action, SignActionArgs, SignActionResult),
    (abort_action, AbortActionArgs, AbortActionResult),
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
    (get_version, GetVersionResult)
}

/// The answering wallet of a fresh ProtoWallet.
fn answering() -> Answering {
    Answering(ProtoWallet::new(None))
}

// Canonical compressed keys (1G, 2G, 3G): the reference's record admits no
// other identity key (`validateIdentityKey`, `ContactsManager.ts:83-94`; #544).
const ALICE: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const BOB: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const CHARLIE: &str = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";

fn create_test_contact(key: &str, name: &str) -> Contact {
    Contact::new(name, key)
        .with_avatar_url("https://example.com/avatar.png")
        .with_added_at(1700000000000)
}

#[tokio::test]
async fn test_add_and_get_contact() {
    let wallet = answering();
    let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

    let contact = create_test_contact(ALICE, "Alice");
    manager.add_contact(contact.clone()).await.unwrap();

    let retrieved = manager.get_contact(ALICE).await.unwrap();
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().name, "Alice");
}

#[tokio::test]
async fn test_get_nonexistent_contact() {
    let wallet = answering();
    let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

    let result = manager.get_contact("nonexistent").await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn test_update_contact() {
    let wallet = answering();
    let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

    // Add initial contact
    let contact = create_test_contact(ALICE, "Alice");
    manager.add_contact(contact).await.unwrap();

    // Update the contact
    let updated = Contact::new("Alice Updated", ALICE).with_notes("Updated notes");
    manager.update_contact(ALICE, updated).await.unwrap();

    // Verify update
    let retrieved = manager.get_contact(ALICE).await.unwrap().unwrap();
    assert_eq!(retrieved.name, "Alice Updated");
    assert_eq!(retrieved.notes, Some("Updated notes".to_string()));
}

#[tokio::test]
async fn test_update_nonexistent_contact() {
    let wallet = answering();
    let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

    let contact = create_test_contact(ALICE, "Alice");
    let result = manager.update_contact("nonexistent", contact).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_remove_contact() {
    let wallet = answering();
    let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

    let contact = create_test_contact(ALICE, "Alice");
    manager.add_contact(contact).await.unwrap();

    // Verify contact exists
    assert!(manager.get_contact(ALICE).await.unwrap().is_some());

    // Remove contact
    manager.remove_contact(ALICE).await.unwrap();

    // Verify contact is removed
    assert!(manager.get_contact(ALICE).await.unwrap().is_none());
}

#[tokio::test]
async fn test_remove_nonexistent_contact() {
    let wallet = answering();
    let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

    // Not a canonical key: refused before any wallet call. A canonical key
    // the cache lacks asks the wallet, `Ok` when nothing is listed (#904).
    let result = manager.remove_contact("nonexistent").await;
    assert!(result.is_err());
    manager.remove_contact(ALICE).await.unwrap();
}

#[tokio::test]
async fn test_list_contacts() {
    let wallet = answering();
    let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

    // Add multiple contacts
    manager
        .add_contact(create_test_contact(ALICE, "Alice"))
        .await
        .unwrap();
    manager
        .add_contact(create_test_contact(BOB, "Bob"))
        .await
        .unwrap();
    manager
        .add_contact(create_test_contact(CHARLIE, "Charlie"))
        .await
        .unwrap();

    let contacts = manager.list_contacts().await.unwrap();
    assert_eq!(contacts.len(), 3);
}

#[tokio::test]
async fn test_search_contacts_by_name() {
    let wallet = answering();
    let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

    manager
        .add_contact(create_test_contact(ALICE, "Alice Smith"))
        .await
        .unwrap();
    manager
        .add_contact(create_test_contact(BOB, "Bob Jones"))
        .await
        .unwrap();
    manager
        .add_contact(create_test_contact(CHARLIE, "Alice Johnson"))
        .await
        .unwrap();

    let results = manager.search_contacts("alice").await.unwrap();
    assert_eq!(results.len(), 2);
}

#[tokio::test]
async fn test_search_contacts_by_tag() {
    let wallet = answering();
    let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

    let mut contact1 = create_test_contact(ALICE, "Alice");
    contact1.tags = vec!["work".to_string(), "engineering".to_string()];

    let mut contact2 = create_test_contact(BOB, "Bob");
    contact2.tags = vec!["personal".to_string()];

    let mut contact3 = create_test_contact(CHARLIE, "Charlie");
    contact3.tags = vec!["work".to_string()];

    manager.add_contact(contact1).await.unwrap();
    manager.add_contact(contact2).await.unwrap();
    manager.add_contact(contact3).await.unwrap();

    let results = manager.search_contacts("work").await.unwrap();
    assert_eq!(results.len(), 2);
}

#[tokio::test]
async fn test_get_contacts_by_tag() {
    let wallet = answering();
    let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

    let mut contact1 = create_test_contact(ALICE, "Alice");
    contact1.tags = vec!["work".to_string(), "engineering".to_string()];

    let mut contact2 = create_test_contact(BOB, "Bob");
    contact2.tags = vec!["personal".to_string()];

    manager.add_contact(contact1).await.unwrap();
    manager.add_contact(contact2).await.unwrap();

    let work_contacts = manager.get_contacts_by_tag("work").await.unwrap();
    assert_eq!(work_contacts.len(), 1);
    assert_eq!(work_contacts[0].name, "Alice");

    let personal_contacts = manager.get_contacts_by_tag("Personal").await.unwrap();
    assert_eq!(personal_contacts.len(), 1);
    assert_eq!(personal_contacts[0].name, "Bob");
}

#[tokio::test]
async fn test_search_contacts_by_notes() {
    let wallet = answering();
    let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

    let mut contact = create_test_contact(ALICE, "Alice");
    contact.notes = Some("Met at the blockchain conference".to_string());

    manager.add_contact(contact).await.unwrap();

    let results = manager.search_contacts("conference").await.unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "Alice");
}

#[tokio::test]
async fn test_cache_management() {
    let wallet = answering();
    let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

    assert!(!manager.is_cache_initialized().await);
    assert_eq!(manager.cached_count().await, 0);

    manager
        .add_contact(create_test_contact(ALICE, "Alice"))
        .await
        .unwrap();
    assert_eq!(manager.cached_count().await, 1);

    manager.clear_cache().await;
    assert_eq!(manager.cached_count().await, 0);
}

#[tokio::test]
async fn test_case_insensitive_search() {
    let wallet = answering();
    let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

    manager
        .add_contact(create_test_contact(ALICE, "ALICE"))
        .await
        .unwrap();

    // Search should be case insensitive
    let results = manager.search_contacts("alice").await.unwrap();
    assert_eq!(results.len(), 1);

    let results = manager.search_contacts("ALICE").await.unwrap();
    assert_eq!(results.len(), 1);

    let results = manager.search_contacts("Alice").await.unwrap();
    assert_eq!(results.len(), 1);
}

#[tokio::test]
async fn test_add_contact_replaces_existing() {
    let wallet = answering();
    let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

    let contact1 = create_test_contact(ALICE, "Alice V1");
    manager.add_contact(contact1).await.unwrap();

    let contact2 = Contact::new("Alice V2", ALICE).with_notes("Updated");
    manager.add_contact(contact2).await.unwrap();

    let contacts = manager.list_contacts().await.unwrap();
    assert_eq!(contacts.len(), 1);

    let retrieved = manager.get_contact(ALICE).await.unwrap().unwrap();
    assert_eq!(retrieved.name, "Alice V2");
}
