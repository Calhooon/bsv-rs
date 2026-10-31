//! Contacts manager unit tests.
#![cfg(test)]

use super::*;
use crate::wallet::ProtoWallet;

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
    let wallet = ProtoWallet::new(None);
    let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

    let contact = create_test_contact(ALICE, "Alice");
    manager.add_contact(contact.clone()).await.unwrap();

    let retrieved = manager.get_contact(ALICE).await.unwrap();
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().name, "Alice");
}

#[tokio::test]
async fn test_get_nonexistent_contact() {
    let wallet = ProtoWallet::new(None);
    let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

    let result = manager.get_contact("nonexistent").await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn test_update_contact() {
    let wallet = ProtoWallet::new(None);
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
    let wallet = ProtoWallet::new(None);
    let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

    let contact = create_test_contact(ALICE, "Alice");
    let result = manager.update_contact("nonexistent", contact).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_remove_contact() {
    let wallet = ProtoWallet::new(None);
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
    let wallet = ProtoWallet::new(None);
    let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());

    let result = manager.remove_contact("nonexistent").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_list_contacts() {
    let wallet = ProtoWallet::new(None);
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
    let wallet = ProtoWallet::new(None);
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
    let wallet = ProtoWallet::new(None);
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
    let wallet = ProtoWallet::new(None);
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
    let wallet = ProtoWallet::new(None);
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
    let wallet = ProtoWallet::new(None);
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
    let wallet = ProtoWallet::new(None);
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
    let wallet = ProtoWallet::new(None);
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
