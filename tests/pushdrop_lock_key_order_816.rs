//! #816, line 2: the four wallet PushDrop lock sites (the identity reveal,
//! the contacts manager, the registry, the local key-value store) judge the
//! wallet's key text before any signature is asked, as the reference's
//! `PushDrop.lock` does (`ts-stack@edf6e03`
//! `packages/sdk/src/script/templates/PushDrop.ts:155-163` `getPublicKey`,
//! `:166-172` `toArray(publicKey, 'hex')`, which throws on a text that is not
//! hex, and only then `:173-185` `createSignature`). The four counterparts
//! call that one method (`IdentityClient.ts:502`, `ContactsManager.ts:767`,
//! `RegistryClient.ts:320,622`, `LocalKVStore.ts:487`). Until #816 each site
//! asked the key, then the signature, then read the key: a key text that is
//! not hex was refused after a `createSignature` the reference never makes
//! (a text that decodes as hex and is no key the reference signs for and
//! pushes, #782's residue (a); here it is refused after the key call alone).
//! Each site now locks through `PushDrop::lock_with_wallet` (#782).
//!
//! Each test asserts the refusal's words (the parser's, unchanged by #816)
//! and then the calls: none after the lock key's `getPublicKey`, no
//! `createSignature`, no `createAction`. No vector: the reference's order is
//! read at the pin. The good-key path is the older witnesses'
//! (`script_pushdrop_key_bytes_545.rs` and each site's own).
//!
//! Hermetic: the counting wallet of #318 (`tests/support/identity_reveal_wallet.rs`),
//! its derived-key answer replaced by a text that is not hex; no network, no
//! port.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

#[cfg(any(feature = "kvstore", feature = "registry", feature = "identity"))]
#[path = "support/identity_reveal_wallet.rs"]
mod identity_reveal_wallet;

#[cfg(any(feature = "kvstore", feature = "registry", feature = "identity"))]
mod sites {
    use super::identity_reveal_wallet::Counting;
    use bsv_rs::primitives::PublicKey;
    use bsv_rs::wallet::ListOutputsResult;

    /// The wallet's answer for a derived key: a text that is not hex, which
    /// the reference's `toArray(_, 'hex')` refuses (`Invalid hex string`,
    /// `primitives/hex.ts:6-17`) before `createSignature`.
    pub const NO_KEY: &str = "zz";

    fn no_key(_: &str) -> String {
        NO_KEY.to_string()
    }

    /// The scalar 9's wallet, every derived key answered `zz` (its identity
    /// key unchanged), nothing listed.
    pub fn wallet() -> Counting {
        let wallet = Counting::of_scalar(9);
        *wallet.key_form.lock().unwrap() = Some(no_key);
        *wallet.listed.lock().unwrap() = Some(ListOutputsResult {
            total_outputs: 0,
            beef: None,
            outputs: Vec::new(),
        });
        wallet
    }

    /// The words: the key parser's for the text, as before #816 (the
    /// refusal moved ahead of a wallet call, its text did not move). Then
    /// the calls: the lock key's `getPublicKey` is the last call the wallet
    /// saw, and no signature and no action was asked.
    pub fn assert_refused_before_any_signature<T: std::fmt::Debug>(
        site: &str,
        wallet: &Counting,
        answer: bsv_rs::Result<T>,
    ) {
        let error = answer.expect_err(site);
        assert_eq!(
            error,
            PublicKey::from_hex(NO_KEY).unwrap_err(),
            "{site}: the parser's words"
        );
        let asked = wallet.public_key_args.lock().unwrap().clone();
        let lock_keys = asked.iter().filter(|args| !args.identity_key).count();
        assert_eq!(lock_keys, 1, "{site}: the lock key asked once");
        let calls = wallet.calls();
        assert_eq!(
            calls.last(),
            Some(&"get_public_key"),
            "{site}: nothing asked after the key: {calls:?}"
        );
        assert!(
            !asked.last().unwrap().identity_key,
            "{site}: the last key asked is the lock's"
        );
        assert!(
            !calls.contains(&"create_signature"),
            "{site}: a signature was asked for a key text that is no key: {calls:?}"
        );
        assert!(
            wallet.signature_args.lock().unwrap().is_empty(),
            "{site}: createSignature's arguments"
        );
        assert!(!calls.contains(&"create_action"), "{site}: {calls:?}");
    }
}

/// `src/identity/reveal.rs` `identity_token` (`IdentityClient.ts:502-509`):
/// counterparty `anyone`, `forSelf` true, the certificate's JSON.
#[cfg(feature = "identity")]
#[tokio::test]
async fn the_identity_token_refuses_a_key_text_that_is_no_key_before_any_signature_is_asked_816() {
    use bsv_rs::identity::{IdentityClient, IdentityClientConfig};
    use bsv_rs::wallet::WalletCertificate;
    use serde_json::Value;
    let v: Value = serde_json::from_str(include_str!(
        "vectors/identity_reveal_create_action_315.json"
    ))
    .unwrap();
    let certificate: WalletCertificate = serde_json::from_value(v["certificate"].clone()).unwrap();
    let witness = &v["witnesses"][0];
    let names: Vec<String> = serde_json::from_value(witness["fields_to_reveal"].clone()).unwrap();
    let mut wallet = sites::wallet();
    wallet.keyring = Some(serde_json::from_value(witness["keyring"].clone()).unwrap());
    let client = IdentityClient::new(wallet.clone(), IdentityClientConfig::default());
    let answer = client.publicly_reveal_attributes(certificate, names).await;
    sites::assert_refused_before_any_signature("identity reveal", &wallet, answer);
}

/// `src/identity/contacts_actions.rs` `contact_lock`
/// (`ContactsManager.ts:748-772`): counterparty `self`, `forSelf` false, the
/// ciphertext.
#[cfg(feature = "identity")]
#[tokio::test]
async fn the_contact_lock_refuses_a_key_text_that_is_no_key_before_any_signature_is_asked_816() {
    use bsv_rs::identity::{Contact, ContactsManager, ContactsManagerConfig};
    use bsv_rs::primitives::PrivateKey;
    let wallet = sites::wallet();
    let manager = ContactsManager::new(wallet.clone(), ContactsManagerConfig::default());
    let contact = Contact::new(
        "Contact 816",
        PrivateKey::from_bytes(&[7; 32])
            .unwrap()
            .public_key()
            .to_hex(),
    );
    let answer = manager.add_contact(contact).await;
    sites::assert_refused_before_any_signature("contacts manager", &wallet, answer);
}

/// `src/registry/token.rs` `lock_definition` (`RegistryClient.ts:320`):
/// counterparty `anyone`, `forSelf` true, the data fields concatenated.
#[cfg(feature = "registry")]
#[tokio::test]
async fn the_registry_lock_refuses_a_key_text_that_is_no_key_before_any_signature_is_asked_816() {
    use bsv_rs::registry::{BasketDefinitionData, RegistryClient, RegistryClientConfig};
    let wallet = sites::wallet();
    let client = RegistryClient::new(wallet.clone(), RegistryClientConfig::new());
    let basket = BasketDefinitionData::new("basket_816", "Basket 816");
    let answer = client.register_definition(basket.into()).await;
    sites::assert_refused_before_any_signature("registry", &wallet, answer);
}

/// `src/kvstore/local_token.rs` `create_locking_script`
/// (`LocalKVStore.ts:486-492`): counterparty `self`, `forSelf` false, the
/// value.
#[cfg(feature = "kvstore")]
#[tokio::test]
async fn the_local_kvstore_lock_refuses_a_key_text_that_is_no_key_before_any_signature_is_asked_816(
) {
    use bsv_rs::kvstore::{KVStoreConfig, LocalKVStore};
    let wallet = sites::wallet();
    let config = KVStoreConfig::default().with_encrypt(false);
    let store = LocalKVStore::new(wallet.clone(), config).unwrap();
    let answer = store.set("alpha", "one", None).await;
    sites::assert_refused_before_any_signature("local store", &wallet, answer);
}
