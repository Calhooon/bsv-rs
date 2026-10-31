//! #545: PushDrop pushes a wallet's public key as the wallet returned it, as
//! the reference's `lock` does (`ts-stack@edf6e03`
//! `packages/sdk/src/script/templates/PushDrop.ts:158-175`:
//! `toArray(publicKey, 'hex')` under the opcode `publicKey.length / 2`), where
//! this crate re-encoded the key compressed: the wallet sites (the local and
//! global key-value stores, the registry, the contacts manager, the identity
//! reveal) pushing the answer of a wallet that returns its derived keys
//! uncompressed or hybrid. The template's own witnesses against
//! `tests/vectors/pushdrop_key_bytes_545.json` are the unit tests beside its
//! crate-visible helper (`src/script/templates/pushdrop_key_bytes_545_tests.rs`).
//!
//! Hermetic: the counting wallet of #318 (`tests/support/identity_reveal_wallet.rs`)
//! with #545's key form, an injected facilitator for the global store's
//! `.invalid` lookup host; no network, no port.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

#[cfg(any(feature = "kvstore", feature = "registry", feature = "identity"))]
#[path = "support/identity_reveal_wallet.rs"]
mod identity_reveal_wallet;

#[cfg(any(feature = "kvstore", feature = "registry", feature = "identity"))]
mod sites {
    use super::identity_reveal_wallet::Counting;
    use bsv_rs::primitives::{from_hex, to_hex, PublicKey};
    use bsv_rs::script::LockingScript;
    use bsv_rs::wallet::{ListOutputsResult, WalletInterface};

    pub fn uncompressed(answer: &str) -> String {
        PublicKey::from_hex(answer).unwrap().to_hex_uncompressed()
    }

    /// `06`/`07` + x + y, the prefix's low bit y's.
    pub fn hybrid(answer: &str) -> String {
        let bytes = PublicKey::from_hex(answer).unwrap().to_uncompressed();
        let prefix = if bytes[64] & 1 == 1 { "07" } else { "06" };
        format!("{prefix}{}", to_hex(&bytes[1..]))
    }

    /// The scalar 9's wallet, its derived keys answered in `form`, nothing
    /// listed.
    pub fn wallet(form: fn(&str) -> String) -> Counting {
        let wallet = Counting::of_scalar(9);
        *wallet.key_form.lock().unwrap() = Some(form);
        *wallet.listed.lock().unwrap() = Some(ListOutputsResult {
            total_outputs: 0,
            beef: None,
            outputs: Vec::new(),
        });
        wallet
    }

    /// The token's first push is the bytes of the wallet's answer for the
    /// lock key, as the reference pushes them, and that answer is no
    /// compressed key.
    pub async fn assert_pushed_as_returned(site: &str, wallet: &Counting) {
        let created = wallet.created.lock().unwrap().clone().unwrap();
        let output = &created.outputs.as_ref().unwrap()[0];
        let script = LockingScript::from_binary(&output.locking_script).unwrap();
        let args = wallet.public_key_args.lock().unwrap().clone();
        let lock_key = args
            .into_iter()
            .rev()
            .find(|args| !args.identity_key)
            .unwrap();
        let answer = wallet.get_public_key(lock_key, None).await.unwrap();
        let bytes = from_hex(&answer.public_key).unwrap();
        assert_eq!(bytes.len(), 65, "{site}: the wallet answers a 65-byte key");
        let pushed = script.chunks()[0].data.clone().unwrap();
        assert_eq!(to_hex(&pushed), to_hex(&bytes), "{site}");
    }
}

#[cfg(feature = "kvstore")]
#[tokio::test]
async fn the_local_store_pushes_the_wallet_key_as_returned_545() {
    use bsv_rs::kvstore::{KVStoreConfig, LocalKVStore};
    for form in [sites::uncompressed as fn(&str) -> String, sites::hybrid] {
        let wallet = sites::wallet(form);
        let config = KVStoreConfig::default().with_encrypt(false);
        let store = LocalKVStore::new(wallet.clone(), config).unwrap();
        // The counting wallet answers createAction with no transaction.
        let _ = store.set("alpha", "one", None).await;
        sites::assert_pushed_as_returned("local store", &wallet).await;
    }
}

#[cfg(feature = "kvstore")]
struct NothingFound;

#[cfg(feature = "kvstore")]
#[async_trait::async_trait(?Send)]
impl bsv_rs::overlay::OverlayLookupFacilitator for NothingFound {
    async fn lookup(
        &self,
        _url: &str,
        _question: &bsv_rs::overlay::LookupQuestion,
        _timeout_ms: Option<u64>,
    ) -> bsv_rs::Result<bsv_rs::overlay::LookupAnswer> {
        Ok(bsv_rs::overlay::LookupAnswer::OutputList {
            outputs: Vec::new(),
        })
    }
}

#[cfg(feature = "kvstore")]
#[tokio::test]
async fn the_global_store_pushes_the_wallet_key_as_returned_545() {
    use bsv_rs::kvstore::{GlobalKVStore, KVStoreConfig};
    use bsv_rs::overlay::{LookupResolver, LookupResolverConfig, NetworkPreset};
    use std::sync::Arc;
    for form in [sites::uncompressed as fn(&str) -> String, sites::hybrid] {
        let wallet = sites::wallet(form);
        let config = KVStoreConfig::default();
        let mut host_overrides = std::collections::HashMap::new();
        host_overrides.insert(
            config.service_name.clone(),
            vec!["https://kvstore-545.invalid".to_string()],
        );
        let resolver = LookupResolver::new(LookupResolverConfig {
            network_preset: NetworkPreset::Local,
            facilitator: Some(Arc::new(NothingFound)),
            slap_trackers: Some(Vec::new()),
            host_overrides: Some(host_overrides),
            ..Default::default()
        });
        let store =
            GlobalKVStore::with_resolver(wallet.clone(), config, NetworkPreset::Local, resolver);
        let _ = store.set("alpha", "one", None).await;
        sites::assert_pushed_as_returned("global store", &wallet).await;
    }
}

#[cfg(feature = "registry")]
#[tokio::test]
async fn the_registry_pushes_the_wallet_key_as_returned_545() {
    use bsv_rs::registry::{BasketDefinitionData, RegistryClient, RegistryClientConfig};
    for form in [sites::uncompressed as fn(&str) -> String, sites::hybrid] {
        let wallet = sites::wallet(form);
        let client = RegistryClient::new(wallet.clone(), RegistryClientConfig::new());
        let basket = BasketDefinitionData::new("basket_545", "Basket 545");
        let _ = client.register_definition(basket.into()).await;
        sites::assert_pushed_as_returned("registry", &wallet).await;
    }
}

#[cfg(feature = "identity")]
#[tokio::test]
async fn the_contacts_manager_pushes_the_wallet_key_as_returned_545() {
    use bsv_rs::identity::{Contact, ContactsManager, ContactsManagerConfig};
    use bsv_rs::primitives::PrivateKey;
    for form in [sites::uncompressed as fn(&str) -> String, sites::hybrid] {
        let wallet = sites::wallet(form);
        let manager = ContactsManager::new(wallet.clone(), ContactsManagerConfig::default());
        let contact = Contact::new(
            "Contact 545",
            PrivateKey::from_bytes(&[7; 32])
                .unwrap()
                .public_key()
                .to_hex(),
        );
        let _ = manager.add_contact(contact).await;
        sites::assert_pushed_as_returned("contacts manager", &wallet).await;
    }
}

/// The identity client's reveal (`src/identity/reveal.rs`, the reference's
/// `IdentityClient.ts:502-509` lock): the certificate and keyring of #315's
/// first witness, the subject's wallet answering its derived keys
/// uncompressed or hybrid.
#[cfg(feature = "identity")]
#[tokio::test]
async fn the_identity_reveal_pushes_the_wallet_key_as_returned_545() {
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
    for form in [sites::uncompressed as fn(&str) -> String, sites::hybrid] {
        let mut wallet = sites::wallet(form);
        wallet.keyring = Some(serde_json::from_value(witness["keyring"].clone()).unwrap());
        let client = IdentityClient::new(wallet.clone(), IdentityClientConfig::default());
        let _ = client
            .publicly_reveal_attributes(certificate.clone(), names.clone())
            .await;
        sites::assert_pushed_as_returned("identity reveal", &wallet).await;
    }
}
