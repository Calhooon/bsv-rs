//! The contacts manager returns its wallet's failures as the reference's
//! does (#904, the bucket #907's line 1), each cell against the reference's
//! own answer in `tests/vectors/contacts_listed_spend.json`
//! (`tests/support/signaction_reference_326.mjs --contacts-listed`,
//! `ts-stack@edf6e03` `ContactsManager.ts` under Node v22.18.0): a wallet
//! error as it came, or the reference's words; the cache written after the
//! chain alone (`:566`, `:912`, `:919`), and the removal asking the wallet
//! whatever the cache holds (`:891-920`). Until #904 a failed HMAC, listing
//! or createAction left `add_contact` with `Ok(())` and the contact in the
//! cache alone, a failed HMAC or listing left `remove_contact` with
//! `Ok(())` after it had emptied the cache, signAction answering no
//! transaction was `Ok` for the removal, nothing was aborted, and a failed
//! listing refreshed the contacts to none.
//!
//! The double is the #318 counting wallet of the scalar 9; a call it is told
//! to fail answers `<name> failed`, the recorder's wallet `<name> failed` in
//! the reference's camelCase names, so the two are compared by the call.
//!
//! The bound (#904's seventh fold): these tests and the differential replay
//! (`tests/contacts_replay.rs`, against `tests/vectors/contacts_replay.json`:
//! 320 sequences of 4 to 16 steps, 3,155 steps, generated from the seed
//! `bsv-rs#904 fold7` by `tests/support/contacts_replay_reference.mjs`, and
//! 13 directed sequences, every step run on the reference) hold, against the
//! reference's recorded answers, what the cache answers and keeps (every
//! answer in order since the eighth fold) and what the update and the removal sign, send, refuse (alone and in pairs) and
//! cache, with up to three contacts cached and up to two faults in a step;
//! they do not hold a step with three or more faults, a cache of four or more
//! contacts, the replay's stated readings (the load's concurrent reads,
//! compared by count; a save, an
//! update or a read by key over a cold cache, which the generator does not
//! make), this crate's search helpers (`search_contacts`,
//! `get_contacts_by_tag`, which have no reference twin), or the twelve lines
//! listed in `docs/lanes/fix-contacts.md` under "The bound".
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(feature = "identity")]

#[path = "support/identity_reveal_wallet.rs"]
mod identity_reveal_wallet;

use bsv_rs::identity::{Contact, ContactsManager, ContactsManagerConfig};
use bsv_rs::primitives::{from_hex, PrivateKey};
use bsv_rs::transaction::Transaction;
use bsv_rs::wallet::{ListOutputsResult, Outpoint, WalletOutput};
use bsv_rs::Error;
use identity_reveal_wallet::{wallet_call, Counting};
use serde_json::{json, Value};

fn vector() -> Value {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/contacts_listed_spend.json"
    ))
    .unwrap();
    serde_json::from_str(&text).unwrap()
}

fn case(name: &str) -> Value {
    vector()["cases"][name].clone()
}

fn identity_key() -> String {
    let mut k = [0u8; 32];
    k[31] = 3;
    PrivateKey::from_bytes(&k).unwrap().public_key().to_hex()
}

fn contact(name: &str) -> Contact {
    Contact::new(name, identity_key()).with_avatar_url("https://example.com/bob.png")
}

/// A second contact, the scalar 4's, cached beside Bob so a test tells "this
/// entry" from "every entry" (#904's fourth fold).
fn carol() -> Contact {
    let mut k = [0u8; 32];
    k[31] = 4;
    Contact::new(
        "Carol Example",
        PrivateKey::from_bytes(&k).unwrap().public_key().to_hex(),
    )
}

fn empty() -> ListOutputsResult {
    ListOutputsResult {
        outputs: vec![],
        total_outputs: 0,
        beef: None,
    }
}

/// A wallet listing the recorded token alone in its BEEF, createAction
/// spending it as asked.
fn listing_token() -> Counting {
    let v = vector();
    let shape = &v["shapes"]["token_at_0"];
    let txid = shape["txid"].as_str().unwrap();
    let mut wallet = Counting::of_scalar(9);
    wallet.create_from_request = true;
    *wallet.listed.lock().unwrap() = Some(ListOutputsResult {
        outputs: vec![WalletOutput {
            satoshis: 1,
            locking_script: None,
            spendable: true,
            custom_instructions: v["token"]["custom_instructions"]
                .as_str()
                .map(str::to_string),
            tags: None,
            outpoint: Outpoint::from_string(&format!("{txid}.0")).unwrap(),
            labels: None,
        }],
        total_outputs: 1,
        beef: Some(from_hex(shape["beef"].as_str().unwrap()).unwrap()),
    });
    wallet
}

fn failed(name: &str) -> Error {
    Error::WalletError(format!("{name} failed"))
}

/// The recorded answer to a failing call, its name in the reference's form.
fn assert_reference_failed(name: &str, call: &str) {
    assert_eq!(
        case(name)["outcome"],
        json!({ "error": format!("{call} failed"), "cause": null }),
        "{name}: the reference lets the wallet's error through"
    );
}

#[tokio::test]
async fn an_add_whose_hmac_fails_returns_the_wallets_error_contacts() {
    let wallet = Counting::of_scalar(9);
    wallet.fail.lock().unwrap().push(wallet_call!(create_hmac));
    let manager = ContactsManager::new(wallet.clone(), ContactsManagerConfig::default());
    let err = manager
        .add_contact(contact("Bob Example"))
        .await
        .unwrap_err();
    assert_eq!(err, failed(wallet_call!(create_hmac)));
    assert_reference_failed("add_hmac_fails", "createHmac");
    assert!(manager
        .get_contact(&identity_key())
        .await
        .unwrap()
        .is_none());
    assert!(!wallet.calls().contains(&wallet_call!(create_action)));
}

#[tokio::test]
async fn an_add_whose_listing_fails_returns_the_wallets_error_contacts() {
    let wallet = Counting::of_scalar(9);
    wallet.fail.lock().unwrap().push(wallet_call!(list_outputs));
    let manager = ContactsManager::new(wallet.clone(), ContactsManagerConfig::default());
    let err = manager
        .add_contact(contact("Bob Example"))
        .await
        .unwrap_err();
    assert_eq!(err, failed(wallet_call!(list_outputs)));
    assert_reference_failed("add_list_fails", "listOutputs");
    assert!(manager
        .get_contact(&identity_key())
        .await
        .unwrap()
        .is_none());
    assert!(!wallet.calls().contains(&wallet_call!(create_action)));
}

#[tokio::test]
async fn an_add_whose_create_action_fails_is_not_cached_contacts() {
    let wallet = Counting::of_scalar(9);
    *wallet.listed.lock().unwrap() = Some(empty());
    wallet
        .fail
        .lock()
        .unwrap()
        .push(wallet_call!(create_action));
    let manager = ContactsManager::new(wallet.clone(), ContactsManagerConfig::default());
    let err = manager
        .add_contact(contact("Bob Example"))
        .await
        .unwrap_err();
    assert_eq!(err, failed(wallet_call!(create_action)));
    assert_reference_failed("add_create_fails", "createAction");
    assert!(manager
        .get_contact(&identity_key())
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn an_add_whose_create_action_answers_no_transaction_is_refused_contacts() {
    let wallet = Counting::of_scalar(9);
    *wallet.listed.lock().unwrap() = Some(empty());
    let manager = ContactsManager::new(wallet.clone(), ContactsManagerConfig::default());
    let err = manager
        .add_contact(contact("Bob Example"))
        .await
        .unwrap_err();
    let words = "Failed to create contact output";
    assert_eq!(err, Error::IdentityError(words.into()));
    assert_eq!(case("add_create_no_tx")["outcome"]["error"], words);
    assert!(manager
        .get_contact(&identity_key())
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn an_update_whose_sign_action_answers_no_transaction_is_aborted_contacts() {
    let wallet = listing_token();
    let manager = ContactsManager::new(wallet.clone(), ContactsManagerConfig::default());
    let err = manager
        .add_contact(contact("Bob Updated"))
        .await
        .unwrap_err();
    let recorded = case("update_sign_no_tx");
    assert_eq!(
        err,
        Error::IdentityError("Failed to update contact output".into())
    );
    assert_eq!(
        recorded["outcome"]["error"],
        "Failed to update contact output"
    );
    let aborts: Vec<_> = wallet
        .aborts
        .lock()
        .unwrap()
        .iter()
        .map(|a| json!({ "reference": a.reference }))
        .collect();
    assert_eq!(Value::Array(aborts), recorded["abort_action"]);
    assert!(manager
        .get_contact(&identity_key())
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn an_update_whose_create_action_fails_returns_the_wallets_error_contacts() {
    let wallet = listing_token();
    wallet
        .fail
        .lock()
        .unwrap()
        .push(wallet_call!(create_action));
    let manager = ContactsManager::new(wallet.clone(), ContactsManagerConfig::default());
    let err = manager
        .add_contact(contact("Bob Updated"))
        .await
        .unwrap_err();
    assert_eq!(err, failed(wallet_call!(create_action)));
    assert_reference_failed("update_create_fails", "createAction");
    assert!(wallet.aborts.lock().unwrap().is_empty());
}

/// The update's checks of the signed transaction (`ContactsManager.ts:841-851`),
/// each failure aborting the action: a template moved, a signature left out.
#[tokio::test]
async fn an_update_whose_signed_transaction_moves_the_template_is_aborted_contacts() {
    for (mode, words) in [
        (
            "signed_version",
            "Signed contact transaction substituted the authorized transaction template",
        ),
        (
            "signed_output",
            "Signed contact transaction substituted an authorized output",
        ),
        (
            "signed_script",
            "Signed contact transaction omitted or substituted the authorized signature",
        ),
    ] {
        let wallet = listing_token();
        *wallet.sign_mode.lock().unwrap() = mode;
        let manager = ContactsManager::new(wallet.clone(), ContactsManagerConfig::default());
        let err = manager
            .add_contact(contact("Bob Updated"))
            .await
            .unwrap_err();
        assert_eq!(err, Error::IdentityError(words.into()), "{mode}");
        assert_eq!(wallet.aborts.lock().unwrap().len(), 1, "{mode}");
    }
}

/// The signable transaction the wallet answers is checked before any
/// signature is asked (`#findBoundInput`, `#requireContactOutput`,
/// `ContactsManager.ts:689-697`, `:729-736`, called at `:819-820` before
/// createSignature at `:821-830` and signAction at `:832`), and the action
/// aborted (`:853`): the contact's input twice or absent, the contact output
/// gone (#904's strength read, two of its survivors: `[index, ..]` in
/// `find_bound_input`, and the signable's output check dropped, which moved
/// the refusal past signAction). Since the third fold the order is pinned
/// against the recorded `update_duplicate_input`, `update_missing_input` and
/// `update_output`: the call list the reference's, and after createAction no
/// createSignature (the re-read's plant, the update signing before it
/// refuses, passed every test until then: the lock's own createSignature
/// comes before createAction, so a list without it could not be asked).
#[tokio::test]
async fn an_update_whose_signable_transaction_is_not_the_requested_one_is_aborted_unsigned_contacts(
) {
    for (mode, words) in [
        (
            "duplicate_input",
            "Contact transaction does not spend the exact contact outpoint once",
        ),
        (
            "missing_input",
            "Contact transaction does not spend the exact contact outpoint once",
        ),
        (
            "output",
            "Contact transaction does not contain the exact requested output",
        ),
    ] {
        let wallet = listing_token();
        *wallet.create_mode.lock().unwrap() = mode;
        let manager = ContactsManager::new(wallet.clone(), ContactsManagerConfig::default());
        let err = manager
            .add_contact(contact("Bob Updated"))
            .await
            .unwrap_err();
        assert_eq!(err, Error::IdentityError(words.into()), "{mode}");
        assert_eq!(wallet.aborts.lock().unwrap().len(), 1, "{mode}");
        let calls = wallet.calls();
        assert!(!calls.contains(&wallet_call!(sign_action)), "{mode}");
        let created = calls
            .iter()
            .rposition(|c| *c == wallet_call!(create_action))
            .unwrap();
        assert!(
            !calls[created..].contains(&wallet_call!(create_signature)),
            "{mode}: {calls:?}"
        );
        let recorded = case(&format!("update_{mode}"));
        assert_eq!(
            recorded["outcome"],
            json!({ "error": words, "cause": null }),
            "{mode}"
        );
        assert_eq!(recorded["sign_action"], json!([]), "{mode}");
        // The reference's cold `saveContact` loads the basket before its
        // tagged listing (`:529-531`), a stated residue not ported: its
        // leading listOutputs is the one call this crate does not make.
        let recorded_calls = recorded["calls"].as_array().unwrap();
        assert_eq!(recorded_calls[0], json!("listOutputs"), "{mode}");
        let expected: Vec<String> = recorded_calls[1..]
            .iter()
            .map(|c| snake(c.as_str().unwrap()))
            .collect();
        assert_eq!(calls, expected, "{mode}");
        assert_eq!(
            wallet.aborts.lock().unwrap()[0].reference,
            recorded["abort_action"][0]["reference"].as_str().unwrap(),
            "{mode}"
        );
    }
}

#[tokio::test]
async fn a_removal_whose_hmac_fails_returns_the_wallets_error_contacts() {
    let wallet = Counting::of_scalar(9);
    wallet.fail.lock().unwrap().push(wallet_call!(create_hmac));
    let manager = ContactsManager::new(wallet.clone(), ContactsManagerConfig::default());
    let err = manager.remove_contact(&identity_key()).await.unwrap_err();
    assert_eq!(err, failed(wallet_call!(create_hmac)));
    assert_reference_failed("remove_hmac_fails", "createHmac");
}

#[tokio::test]
async fn a_removal_whose_listing_fails_keeps_the_cached_contact_contacts() {
    let wallet = Counting::of_scalar(9);
    *wallet.listed.lock().unwrap() = Some(empty());
    *wallet.create_finished.lock().unwrap() = true;
    let manager = ContactsManager::new(wallet.clone(), ContactsManagerConfig::default());
    manager.add_contact(contact("Bob Example")).await.unwrap();
    wallet.fail.lock().unwrap().push(wallet_call!(list_outputs));
    let err = manager.remove_contact(&identity_key()).await.unwrap_err();
    assert_eq!(err, failed(wallet_call!(list_outputs)));
    assert_reference_failed("remove_list_fails", "listOutputs");
    assert!(manager
        .get_contact(&identity_key())
        .await
        .unwrap()
        .is_some());
}

#[tokio::test]
async fn a_removal_whose_sign_action_answers_no_transaction_is_aborted_contacts() {
    let wallet = listing_token();
    let manager = ContactsManager::new(wallet.clone(), ContactsManagerConfig::default());
    let err = manager.remove_contact(&identity_key()).await.unwrap_err();
    let recorded = case("remove_sign_no_tx");
    let words = "Unable to authenticate or remove a contact output";
    assert_eq!(err, Error::IdentityError(words.into()));
    assert_eq!(
        recorded["outcome"],
        json!({ "error": words, "cause": "Failed to delete contact output" })
    );
    assert_eq!(wallet.aborts.lock().unwrap().len(), 1);
    assert_eq!(
        wallet.aborts.lock().unwrap()[0].reference,
        recorded["abort_action"][0]["reference"].as_str().unwrap()
    );
}

/// A removal that fails at its spend keeps the cached contact; one that
/// spends drops it and it alone (`ContactsManager.ts:908-919`: the cache
/// entry deleted after `#trySpendContactOutput` answers, a throw leaving it;
/// `#commitCachedRemoval`, `:923-939`, filters out the one identity key).
/// The cache is filled by two adds over an empty listing, Bob and Carol,
/// then Bob's recorded token listed. Three failures past the listing:
/// signAction answering no transaction (`remove_sign_no_tx`), createAction
/// failing and signAction failing, each in the removal's wrapper, both
/// contacts still cached; then the same wallet signing, the removal `Ok`,
/// Bob gone and Carol kept (#904's third fold: the re-read's plant, the
/// cache entry dropped before the spend, passed every test until then; the
/// fourth fold: the fold's re-read's plant, every entry dropped by
/// `contacts.clear()` at the removal, passed every test until Carol).
#[tokio::test]
async fn a_removal_that_fails_at_its_spend_keeps_the_cached_contact_contacts() {
    let words = "Unable to authenticate or remove a contact output";
    let failures: [(&str, Option<&'static str>); 3] = [
        ("sign_no_tx", None),
        ("create_fails", Some(wallet_call!(create_action))),
        ("sign_fails", Some(wallet_call!(sign_action))),
    ];
    for (name, fail) in failures {
        let wallet = listing_token();
        let manager = ContactsManager::new(wallet.clone(), ContactsManagerConfig::default());
        let listing = wallet.listed.lock().unwrap().replace(empty());
        *wallet.create_finished.lock().unwrap() = true;
        manager.add_contact(contact("Bob Example")).await.unwrap();
        manager.add_contact(carol()).await.unwrap();
        *wallet.listed.lock().unwrap() = listing;
        assert_eq!(manager.cached_count().await, 2, "{name}");
        if let Some(call) = fail {
            wallet.fail.lock().unwrap().push(call);
        }
        let err = manager.remove_contact(&identity_key()).await.unwrap_err();
        assert_eq!(err, Error::IdentityError(words.into()), "{name}");
        assert!(
            manager
                .get_contact(&identity_key())
                .await
                .unwrap()
                .is_some(),
            "{name}: a failed spend dropped the cached contact"
        );
        assert!(
            manager
                .get_contact(&carol().identity_key)
                .await
                .unwrap()
                .is_some(),
            "{name}: a failed spend dropped another cached contact"
        );
        wallet.fail.lock().unwrap().clear();
        *wallet.sign_mode.lock().unwrap() = "signed";
        manager.remove_contact(&identity_key()).await.unwrap();
        assert!(
            manager
                .get_contact(&identity_key())
                .await
                .unwrap()
                .is_none(),
            "{name}: a spent contact stayed cached"
        );
        assert!(
            manager
                .get_contact(&carol().identity_key)
                .await
                .unwrap()
                .is_some(),
            "{name}: the removal of one contact dropped another"
        );
        assert_eq!(manager.cached_count().await, 1, "{name}");
    }
    assert_eq!(
        case("remove_sign_no_tx")["outcome"],
        json!({ "error": words, "cause": "Failed to delete contact output" })
    );
}

/// The removal checks the signable transaction before any signature is asked,
/// as the update does: the contact's input twice or absent is refused and
/// the action aborted, signAction never called (`ContactsManager.ts:987`,
/// `#findBoundInput` `:689-697`, the abort at `:1018`; the recorded
/// `remove_duplicate_input` and `remove_missing_input`). The reference's
/// words are its wrapper's over the cause; this crate's error carries the
/// wrapper alone (#904's stated residue), so the call list is the pin: with
/// the refusal skipped on the removal path (the re-read's plant P1, the
/// input taken as 0) the removal signs, calls signAction, and fails later
/// in the same wrapper.
#[tokio::test]
async fn a_removal_whose_signable_transaction_does_not_spend_the_contact_once_is_aborted_unsigned_contacts(
) {
    for mode in ["duplicate_input", "missing_input"] {
        let wallet = listing_token();
        *wallet.create_mode.lock().unwrap() = mode;
        let manager = ContactsManager::new(wallet.clone(), ContactsManagerConfig::default());
        let err = manager.remove_contact(&identity_key()).await.unwrap_err();
        let recorded = case(&format!("remove_{mode}"));
        let words = "Unable to authenticate or remove a contact output";
        assert_eq!(err, Error::IdentityError(words.into()), "{mode}");
        assert_eq!(
            recorded["outcome"],
            json!({
                "error": words,
                "cause": "Contact transaction does not spend the exact contact outpoint once"
            }),
            "{mode}"
        );
        assert!(
            !wallet.calls().contains(&wallet_call!(sign_action)),
            "{mode}: {:?}",
            wallet.calls()
        );
        assert_eq!(recorded["sign_action"], json!([]), "{mode}");
        let calls: Vec<String> = recorded["calls"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| snake(c.as_str().unwrap()))
            .collect();
        assert_eq!(wallet.calls(), calls, "{mode}");
        let aborts = wallet.aborts.lock().unwrap().clone();
        assert_eq!(aborts.len(), 1, "{mode}");
        assert_eq!(
            aborts[0].reference,
            recorded["abort_action"][0]["reference"].as_str().unwrap(),
            "{mode}"
        );
    }
}

/// The reference's camelCase call name as this double's.
fn snake(name: &str) -> String {
    let mut out = String::new();
    for c in name.chars() {
        if c.is_ascii_uppercase() {
            out.push('_');
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

#[tokio::test]
async fn a_removal_of_a_key_the_cache_lacks_asks_the_wallet_contacts() {
    let wallet = Counting::of_scalar(9);
    *wallet.listed.lock().unwrap() = Some(empty());
    let manager = ContactsManager::new(wallet.clone(), ContactsManagerConfig::default());
    manager.remove_contact(&identity_key()).await.unwrap();
    assert_eq!(
        wallet.calls(),
        vec![wallet_call!(create_hmac), wallet_call!(list_outputs)]
    );
    let recorded = case("remove_nothing_listed");
    assert_eq!(recorded["outcome"], json!({ "ok": true }));
    assert_eq!(recorded["calls"], json!(["createHmac", "listOutputs"]));
}

/// The removal spends a listed token the cache never held, as the reference
/// asks its wallet whatever its cache holds.
#[tokio::test]
async fn a_removal_of_an_uncached_listed_token_spends_it_contacts() {
    let wallet = listing_token();
    *wallet.sign_mode.lock().unwrap() = "signed";
    let manager = ContactsManager::new(wallet.clone(), ContactsManagerConfig::default());
    manager.remove_contact(&identity_key()).await.unwrap();
    assert_eq!(wallet.signs.lock().unwrap().len(), 1);
    let beef = from_hex(vector()["shapes"]["token_at_0"]["beef"].as_str().unwrap()).unwrap();
    assert!(Transaction::from_beef(&beef, None).is_ok());
}

#[tokio::test]
async fn a_refresh_whose_listing_fails_returns_the_wallets_error_contacts() {
    let wallet = Counting::of_scalar(9);
    wallet.fail.lock().unwrap().push(wallet_call!(list_outputs));
    let manager = ContactsManager::new(wallet.clone(), ContactsManagerConfig::default());
    let err = manager.list_contacts_with_refresh(true).await.unwrap_err();
    assert_eq!(err, failed(wallet_call!(list_outputs)));
    assert_reference_failed("list_fails", "listOutputs");
    assert!(!manager.is_cache_initialized().await);
}

/// The recorded token listed `count` times.
fn listing_token_times(count: usize) -> Counting {
    let wallet = listing_token();
    {
        let mut listed = wallet.listed.lock().unwrap();
        let listing = listed.as_mut().unwrap();
        let one = listing.outputs[0].clone();
        listing.outputs = vec![one; count];
        listing.total_outputs = count as u32;
    }
    wallet
}

/// The lookups' bounds and the other identity's refusal, against the
/// recorded `update_other_identity`, `update_listing_100`,
/// `update_listing_101`, `remove_listing_100` and `remove_listing_101`
/// (`#findExistingOutput`, `ContactsManager.ts:591-592`, `:620-625`;
/// `removeContact`, `:904-905`): a save of another identity over a listed
/// token refused, a lookup of 100 outputs read (the update's 100 matches
/// refused as several, the removal spending the leading one) and one of 101
/// refused before any output is read. The update's call count is the
/// reference's less its cold load (`:529-531`, a stated residue). #904's
/// third fold, the sweep: six mutants of `find_existing` and
/// `remove_contact` (`> 100` as `==` or `>=` at both, the guard and the arm
/// for no match) passed every test until then.
#[tokio::test]
async fn the_lookups_bounds_and_another_identitys_token_are_the_references_contacts() {
    let words = |name: &str| case(name)["outcome"]["error"].as_str().unwrap().to_string();
    let calls = |name: &str| case(name)["call_count"].as_u64().unwrap() as usize;

    let wallet = listing_token();
    let manager = ContactsManager::new(wallet.clone(), ContactsManagerConfig::default());
    let mut k = [0u8; 32];
    k[31] = 4;
    let other = PrivateKey::from_bytes(&k).unwrap().public_key().to_hex();
    let err = manager
        .add_contact(Contact::new("Carol Example", other))
        .await
        .unwrap_err();
    assert_eq!(err, Error::IdentityError(words("update_other_identity")));
    assert_eq!(wallet.calls().len(), calls("update_other_identity") - 1);
    assert!(!wallet.calls().contains(&wallet_call!(create_action)));

    for (count, name) in [(100, "update_listing_100"), (101, "update_listing_101")] {
        let wallet = listing_token_times(count);
        let manager = ContactsManager::new(wallet.clone(), ContactsManagerConfig::default());
        let err = manager
            .add_contact(contact("Bob Updated"))
            .await
            .unwrap_err();
        assert_eq!(err, Error::IdentityError(words(name)), "{name}");
        assert_eq!(wallet.calls().len(), calls(name) - 1, "{name}");
        assert_eq!(case(name)["sign_action_count"], json!(0), "{name}");
    }

    let wallet = listing_token_times(100);
    *wallet.sign_mode.lock().unwrap() = "signed";
    let manager = ContactsManager::new(wallet.clone(), ContactsManagerConfig::default());
    manager.remove_contact(&identity_key()).await.unwrap();
    assert_eq!(case("remove_listing_100")["outcome"], json!({ "ok": true }));
    assert_eq!(wallet.calls().len(), calls("remove_listing_100"));
    assert_eq!(
        wallet.signs.lock().unwrap().len() as u64,
        case("remove_listing_100")["sign_action_count"]
            .as_u64()
            .unwrap()
    );

    let wallet = listing_token_times(101);
    let manager = ContactsManager::new(wallet.clone(), ContactsManagerConfig::default());
    let err = manager.remove_contact(&identity_key()).await.unwrap_err();
    assert_eq!(err, Error::IdentityError(words("remove_listing_101")));
    assert_eq!(wallet.calls().len(), calls("remove_listing_101"));
}

/// The add's and the refresh's cache writes, with two contacts cached: an add
/// writes its own entry after the chain and no other (`saveContact`,
/// `ContactsManager.ts:529-534`, `:566`: the cached list with this contact
/// replaced or appended), a failed add writes nothing, an update replaces its
/// own entry, and a forced refresh whose listing fails leaves the cache cold
/// (`getContacts`' `#invalidate` before the load, `:321`, `:343-347`), the
/// next read finding nothing cached. #904's fourth fold, the kind of the
/// re-read's FIX 1: each of the three writes this pull request moved is held
/// with a second entry beside the one it writes. The sweep found the last one
/// kept both entries where the reference drops them (#904 had made the
/// failure the caller's error and left the cache; before #904 the failure
/// refreshed to none).
#[tokio::test]
async fn the_cache_writes_touch_their_own_entry_alone_with_two_contacts_cached_contacts() {
    let wallet = listing_token();
    *wallet.sign_mode.lock().unwrap() = "signed";
    let manager = ContactsManager::new(wallet.clone(), ContactsManagerConfig::default());
    let listing = wallet.listed.lock().unwrap().replace(empty());
    *wallet.create_finished.lock().unwrap() = true;
    manager.add_contact(contact("Bob Example")).await.unwrap();
    manager.add_contact(carol()).await.unwrap();
    assert_eq!(
        manager.cached_count().await,
        2,
        "an add dropped another entry"
    );

    // A failed add writes nothing and keeps both.
    let mut k = [0u8; 32];
    k[31] = 5;
    let dave = Contact::new(
        "Dave Example",
        PrivateKey::from_bytes(&k).unwrap().public_key().to_hex(),
    );
    wallet
        .fail
        .lock()
        .unwrap()
        .push(wallet_call!(create_action));
    manager.add_contact(dave.clone()).await.unwrap_err();
    wallet.fail.lock().unwrap().clear();
    assert_eq!(
        manager.cached_count().await,
        2,
        "a failed add moved the cache"
    );
    assert!(manager
        .get_contact(&dave.identity_key)
        .await
        .unwrap()
        .is_none());

    // An update over Bob's listed token replaces Bob's entry and keeps Carol's.
    *wallet.listed.lock().unwrap() = listing;
    manager.add_contact(contact("Bob Updated")).await.unwrap();
    assert_eq!(
        manager.cached_count().await,
        2,
        "an update dropped another entry"
    );
    assert_eq!(
        manager
            .get_contact(&identity_key())
            .await
            .unwrap()
            .unwrap()
            .name,
        "Bob Updated"
    );
    assert_eq!(
        manager
            .get_contact(&carol().identity_key)
            .await
            .unwrap()
            .unwrap()
            .name,
        "Carol Example"
    );

    // A forced refresh whose listing fails leaves the cache cold: against the
    // recorded `refresh_fails_after_two_saves`, the refusal the wallet's,
    // then a plain read asking the wallet again (an empty listing, none read).
    let recorded = case("refresh_fails_after_two_saves");
    assert_eq!(recorded["saved"], json!([{ "ok": true }, { "ok": true }]));
    wallet.fail.lock().unwrap().push(wallet_call!(list_outputs));
    let before = wallet.calls().len();
    let err = manager.list_contacts_with_refresh(true).await.unwrap_err();
    assert_eq!(err, failed(wallet_call!(list_outputs)));
    assert_eq!(
        recorded["refresh"],
        json!({ "error": "listOutputs failed", "cause": null })
    );
    // The cache the reference's `#invalidate` leaves: nothing held, not
    // initialized (this crate's adds leave it uninitialized, so the plain read
    // below loads on both sides; the entries are what tells them apart).
    assert_eq!(
        manager.cached_count().await,
        0,
        "a failed forced refresh kept the cache"
    );
    assert!(!manager.is_cache_initialized().await);
    assert!(manager
        .get_contact(&carol().identity_key)
        .await
        .unwrap()
        .is_none());
    wallet.fail.lock().unwrap().clear();
    *wallet.listed.lock().unwrap() = Some(empty());
    let read = manager.list_contacts_with_refresh(false).await.unwrap();
    assert_eq!(recorded["read"], json!({ "ok": true }));
    assert_eq!(json!(read.len()), recorded["read_count"]);
    let after: Vec<Value> = wallet.calls()[before..].iter().map(|c| json!(c)).collect();
    let expected: Vec<Value> = recorded["calls_after_saves"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| json!(snake(c.as_str().unwrap())))
        .collect();
    assert_eq!(after, expected, "the read after a failed forced refresh");
}

/// A forced refresh whose listing fails over a loaded cache leaves it to
/// list again (#904's fifth fold; the fourth fold's re-read, its plant A):
/// the reference's `#invalidate` (`ContactsManager.ts:321`, `:343-347`)
/// leaves its cache unloaded, so the plain read after the failure asks the
/// wallet, as the recorded `refresh_fails_after_two_saves` shows. The cache
/// is loaded by a successful forced refresh ahead of the failure, so the
/// test fails when the failure leaves it marked loaded (this crate's adds
/// leave it unloaded, which the test above cannot tell apart).
#[tokio::test]
async fn a_failed_forced_refresh_over_a_loaded_cache_leaves_it_to_list_again_904() {
    let wallet = listing_token();
    *wallet.sign_mode.lock().unwrap() = "signed";
    let manager = ContactsManager::new(wallet.clone(), ContactsManagerConfig::default());
    *wallet.listed.lock().unwrap() = Some(empty());
    manager.list_contacts_with_refresh(true).await.unwrap();
    assert!(manager.is_cache_initialized().await);
    *wallet.create_finished.lock().unwrap() = true;
    manager.add_contact(contact("Bob Example")).await.unwrap();
    manager.add_contact(carol()).await.unwrap();
    assert_eq!(manager.cached_count().await, 2);
    let recorded = case("refresh_fails_after_two_saves");
    wallet.fail.lock().unwrap().push(wallet_call!(list_outputs));
    let before = wallet.calls().len();
    manager.list_contacts_with_refresh(true).await.unwrap_err();
    wallet.fail.lock().unwrap().clear();
    let read = manager.list_contacts_with_refresh(false).await.unwrap();
    assert_eq!(json!(read.len()), recorded["read_count"]);
    let after: Vec<Value> = wallet.calls()[before..].iter().map(|c| json!(c)).collect();
    let expected: Vec<Value> = recorded["calls_after_saves"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| json!(snake(c.as_str().unwrap())))
        .collect();
    assert_eq!(
        after, expected,
        "the read after a failed forced refresh over a loaded cache"
    );
}

/// A forced refresh whose listing fails over a cache a successful forced
/// refresh loaded EMPTY leaves it to list again: the reference's
/// `#invalidate` (`ContactsManager.ts:321`, `:343-347`) clears `#knownEmpty`
/// and the cached item before the load, so after the failure the plain read
/// asks the wallet (`:323-339`). A fold's witness: RED under the `:36` guard
/// narrowed to `force_refresh && !contacts.is_empty()` (plant R2).
#[tokio::test]
async fn a_failed_forced_refresh_over_a_loaded_empty_cache_leaves_it_to_list_again_904() {
    let wallet = listing_token();
    let manager = ContactsManager::new(wallet.clone(), ContactsManagerConfig::default());
    *wallet.listed.lock().unwrap() = Some(empty());
    manager.list_contacts_with_refresh(true).await.unwrap();
    assert!(manager.is_cache_initialized().await);
    assert_eq!(manager.cached_count().await, 0);
    wallet.fail.lock().unwrap().push(wallet_call!(list_outputs));
    let before = wallet.calls().len();
    manager.list_contacts_with_refresh(true).await.unwrap_err();
    assert!(
        !manager.is_cache_initialized().await,
        "a failed forced refresh left an empty cache loaded"
    );
    wallet.fail.lock().unwrap().clear();
    let read = manager.list_contacts_with_refresh(false).await.unwrap();
    assert!(read.is_empty());
    let after: Vec<String> = wallet.calls()[before..]
        .iter()
        .map(|c| c.to_string())
        .collect();
    assert_eq!(
        after,
        ["list_outputs", "list_outputs"],
        "the read after the failure did not list again"
    );
}

/// The listing of one contact token per `(name, identity key, len)`, each
/// encrypted and locked by `wallet` as `#encryptAndLock` does
/// (`ContactsManager.ts:748-772`) under its own key ID, its record padded
/// with JSON whitespace to `len` bytes when it is shorter (both `JSON.parse`
/// and serde read the padding); and each token's script length.
async fn contact_listing(
    wallet: &identity_reveal_wallet::Counting,
    records: &[(&str, String, usize)],
) -> (ListOutputsResult, Vec<usize>) {
    use bsv_rs::script::templates::{LockPosition, PushDrop};
    use bsv_rs::wallet::{Counterparty, EncryptArgs, Protocol, SecurityLevel, WalletInterface};
    let protocol = Protocol::new(SecurityLevel::Counterparty, "contact");
    let (mut outputs, mut lengths) = (Vec::new(), Vec::new());
    for (index, (name, key, len)) in records.iter().enumerate() {
        let key_id = ["A", "Q", "g", "w"][index].repeat(43) + "=";
        let mut plaintext = serde_json::to_vec(&json!({
            "name": name,
            "avatarURL": "",
            "abbreviatedKey": "",
            "identityKey": key,
            "badgeIconURL": "",
            "badgeLabel": "",
            "badgeClickURL": "",
        }))
        .unwrap();
        if plaintext.len() < *len {
            plaintext.resize(*len, b' ');
        }
        let ciphertext = wallet
            .encrypt(
                EncryptArgs {
                    plaintext,
                    protocol_id: protocol.clone(),
                    key_id: key_id.clone(),
                    counterparty: Some(Counterparty::Self_),
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap()
            .ciphertext;
        let script = PushDrop::lock_with_wallet(
            wallet,
            None,
            vec![ciphertext],
            protocol.clone(),
            &key_id,
            Counterparty::Self_,
            false,
            true,
            LockPosition::Before,
        )
        .await
        .unwrap()
        .to_binary();
        lengths.push(script.len());
        outputs.push(WalletOutput {
            satoshis: 1,
            locking_script: Some(script),
            spendable: true,
            custom_instructions: Some(json!({ "keyID": key_id }).to_string()),
            tags: None,
            outpoint: Outpoint::from_string(&format!("{}.{index}", "22".repeat(32))).unwrap(),
            labels: None,
        });
    }
    let total_outputs = outputs.len() as u32;
    let listing = ListOutputsResult {
        outputs,
        total_outputs,
        beef: None,
    };
    (listing, lengths)
}

/// The counting wallet of the scalar 9 listing Bob's token alone, its record
/// padded to `len` bytes, and the token's script length.
async fn listing_a_contact(len: usize) -> (identity_reveal_wallet::Counting, usize) {
    let wallet = identity_reveal_wallet::Counting::of_scalar(9);
    let (listing, lengths) =
        contact_listing(&wallet, &[("Bob Example", identity_key(), len)]).await;
    *wallet.listed.lock().unwrap() = Some(listing);
    (wallet, lengths[0])
}

/// A listed contact token past 64,512 bytes and inside the script bound is
/// read (#904's sixth fold: the mutation tool's sweep of
/// `contacts_cache.rs`, its `MAX_CIPHERTEXT + 2048` written `- 2048`, passed
/// every test). The reference drops a listed script only past
/// `MAX_CONTACT_CIPHERTEXT_BYTES * 2 + 4096` hex digits
/// (`ContactsManager.ts:487-492`), 68,608 bytes, the figure here; Bob's
/// record padded to 65,000 bytes gives a script of about 65,160, read back
/// as the contact. Read at the pin, not recorded.
#[tokio::test]
async fn a_listed_contact_token_past_64512_bytes_inside_the_script_bound_is_read_904() {
    let (wallet, script_len) = listing_a_contact(65_000).await;
    assert!(
        (64_513..=68_608).contains(&script_len),
        "the script's length {script_len} is not between the two bounds"
    );
    let manager = ContactsManager::new(wallet, ContactsManagerConfig::default());
    let read = manager.list_contacts_with_refresh(true).await.unwrap();
    assert_eq!(read.len(), 1, "the listed token was dropped");
    assert_eq!(read[0].name, "Bob Example");
    assert_eq!(read[0].identity_key, identity_key());
}

/// A plain read over a loaded cache answers the cache and asks the wallet
/// nothing, the cache loaded with one contact and loaded empty (#904's sixth
/// fold: the hand sweep of `contacts_cache.rs`, the cached read at `:20-25`
/// deleted, or narrowed to a loaded cache that is empty or one that is not,
/// passed every test). The reference's `getContacts` without `forceRefresh`
/// returns `[]` for a basket it has seen empty (`#knownEmpty`) and the
/// cached contacts otherwise, before any load (`ContactsManager.ts:321-328`).
/// Read at the pin, not recorded.
#[tokio::test]
async fn a_plain_read_over_a_loaded_cache_answers_it_without_the_wallet_904() {
    let (one, _) = listing_a_contact(0).await;
    let none = identity_reveal_wallet::Counting::of_scalar(9);
    *none.listed.lock().unwrap() = Some(empty());
    for (name, wallet, count) in [("one contact", one, 1), ("empty", none, 0)] {
        let manager = ContactsManager::new(wallet.clone(), ContactsManagerConfig::default());
        let loaded = manager.list_contacts_with_refresh(true).await.unwrap();
        assert_eq!(loaded.len(), count, "{name}");
        let before = wallet.calls().len();
        let read = manager.list_contacts_with_refresh(false).await.unwrap();
        let keys = |contacts: &[Contact]| -> Vec<(String, String)> {
            contacts
                .iter()
                .map(|c| (c.identity_key.clone(), c.name.clone()))
                .collect()
        };
        assert_eq!(
            keys(&read),
            keys(&loaded),
            "{name}: the plain read's answer"
        );
        assert_eq!(
            wallet.calls()[before..].len(),
            0,
            "{name}: the plain read over a loaded cache asked the wallet"
        );
    }
}

/// The names and keys of `contacts`, sorted by key.
fn names(contacts: &[Contact]) -> Vec<(String, String)> {
    let mut held: Vec<_> = contacts
        .iter()
        .map(|c| (c.identity_key.clone(), c.name.clone()))
        .collect();
    held.sort();
    held
}

/// A forced refresh reads every listed contact, over a cold cache and over
/// a loaded one, and keeps none the listing lacks (#904's sixth fold: the
/// hand sweep of `contacts_cache.rs`, the load keeping only its first
/// contact, keeping contacts only while the cache is empty, or the cache's
/// clear before the rewrite deleted, passed every test). The reference's
/// forced `getContacts` invalidates its cache and loads the whole basket
/// (`ContactsManager.ts:321`, `:343-347`, `:353-368`), every decrypted
/// output kept (`:507-513`). Read at the pin, not recorded.
#[tokio::test]
async fn a_forced_refresh_reads_every_listed_contact_and_keeps_none_the_listing_lacks_904() {
    let wallet = identity_reveal_wallet::Counting::of_scalar(9);
    let carol = carol();
    let (two, _) = contact_listing(
        &wallet,
        &[
            ("Bob Example", identity_key(), 0),
            ("Carol Example", carol.identity_key.clone(), 0),
        ],
    )
    .await;
    *wallet.listed.lock().unwrap() = Some(two);
    let manager = ContactsManager::new(wallet.clone(), ContactsManagerConfig::default());
    let mut expected = vec![
        (identity_key(), "Bob Example".to_string()),
        (carol.identity_key.clone(), "Carol Example".to_string()),
    ];
    expected.sort();
    for pass in ["over a cold cache", "over a loaded cache"] {
        let read = manager.list_contacts_with_refresh(true).await.unwrap();
        assert_eq!(names(&read), expected, "{pass}: the answer");
        let cached = manager.list_contacts().await.unwrap();
        assert_eq!(names(&cached), expected, "{pass}: the cache");
    }
    *wallet.listed.lock().unwrap() = Some(empty());
    let read = manager.list_contacts_with_refresh(true).await.unwrap();
    assert!(read.is_empty());
    assert_eq!(
        manager.cached_count().await,
        0,
        "a forced refresh kept contacts its listing lacks"
    );
}

/// A contact's saved-at time is the cache's and survives a forced refresh
/// that lists its token (#904's sixth fold: the hand sweep, the decode's
/// read of the cached time replaced by 0, passed every test). `added_at` is
/// this crate's member, never the token's (#544; the reference's record has
/// none, `ContactsManager.ts:171-198`).
#[tokio::test]
async fn a_forced_refresh_keeps_a_cached_contacts_saved_at_time_904() {
    let (wallet, _) = listing_a_contact(0).await;
    let listing = wallet.listed.lock().unwrap().replace(empty());
    *wallet.sign_mode.lock().unwrap() = "signed";
    *wallet.create_finished.lock().unwrap() = true;
    let manager = ContactsManager::new(wallet.clone(), ContactsManagerConfig::default());
    manager
        .add_contact(contact("Bob Example").with_added_at(1_700_000_000_000))
        .await
        .unwrap();
    *wallet.listed.lock().unwrap() = listing;
    let read = manager.list_contacts_with_refresh(true).await.unwrap();
    assert_eq!(read.len(), 1);
    assert_eq!(read[0].added_at, 1_700_000_000_000, "the saved-at time");
}

/// `clear_cache` leaves the next plain read to list again (#904's sixth
/// fold: the hand sweep, its `initialized = false` deleted, passed every
/// test): the cache is marked not loaded, so the read asks the wallet once
/// and answers the listing, as the reference's read after `#invalidate`
/// does (`ContactsManager.ts:323-339`, `:343-347`). Read at the pin, not
/// recorded.
#[tokio::test]
async fn clear_cache_leaves_the_next_plain_read_to_list_again_904() {
    let (wallet, _) = listing_a_contact(0).await;
    let manager = ContactsManager::new(wallet.clone(), ContactsManagerConfig::default());
    manager.list_contacts_with_refresh(true).await.unwrap();
    manager.clear_cache().await;
    assert!(!manager.is_cache_initialized().await);
    let before = wallet.calls().len();
    let read = manager.list_contacts_with_refresh(false).await.unwrap();
    assert_eq!(read.len(), 1, "the read after clear_cache");
    let after: Vec<String> = wallet.calls()[before..]
        .iter()
        .map(|c| c.to_string())
        .collect();
    assert_eq!(
        after[0], "list_outputs",
        "the read after clear_cache did not list"
    );
}

/// Two faults at once, against the recorded two-fault cells (#904's fourth
/// fold; the re-read's FIX 2 and its kind): the refusal the reference names
/// when two of the checks it orders would both refuse. The update's two
/// checks of the signable transaction, the bound input before the contact
/// output (`:819-820`); a fault of the signable transaction beside one of
/// the signed transaction, the signable one named and no signAction (one
/// signed fault stands for the three: a signed fault lives in signAction's
/// answer, which a signable fault never reaches); two faults of the signed
/// transaction, the template's header before its outputs and the template
/// before the signature (`:700-725`, `:847-850`). The removal's error is the
/// wrapper alone (#904's stated residue), so its pairs are pinned by the
/// recorded wrapper and call list, the cause the reference's recorded beside
/// it. The update's call list is the reference's less its cold load
/// (`:529-531`, the stated residue).
#[tokio::test]
async fn two_faults_at_once_are_refused_in_the_references_order_contacts() {
    let cells: [(&str, &'static str, &'static str, bool); 11] = [
        (
            "update_duplicate_input_and_output",
            "duplicate_input+output",
            "",
            true,
        ),
        (
            "update_missing_input_and_output",
            "missing_input+output",
            "",
            true,
        ),
        (
            "update_duplicate_input_and_signed_version",
            "duplicate_input",
            "signed_version",
            true,
        ),
        (
            "update_missing_input_and_signed_version",
            "missing_input",
            "signed_version",
            true,
        ),
        (
            "update_output_and_signed_version",
            "output",
            "signed_version",
            true,
        ),
        (
            "update_signed_version_and_output",
            "",
            "signed_version+signed_output",
            true,
        ),
        (
            "update_signed_version_and_script",
            "",
            "signed_version+signed_script",
            true,
        ),
        (
            "update_signed_output_and_script",
            "",
            "signed_output+signed_script",
            true,
        ),
        (
            "remove_duplicate_input_and_signed_version",
            "duplicate_input",
            "signed_version",
            false,
        ),
        (
            "remove_missing_input_and_signed_version",
            "missing_input",
            "signed_version",
            false,
        ),
        (
            "remove_signed_version_and_script",
            "",
            "signed_version+signed_script",
            false,
        ),
    ];
    let wrapper = "Unable to authenticate or remove a contact output";
    for (name, create, sign, update) in cells {
        let recorded = case(name);
        assert!(recorded.is_object(), "{name}: not recorded");
        let wallet = listing_token();
        *wallet.create_mode.lock().unwrap() = create;
        *wallet.sign_mode.lock().unwrap() = if sign.is_empty() { "signed" } else { sign };
        let manager = ContactsManager::new(wallet.clone(), ContactsManagerConfig::default());
        let err = if update {
            manager
                .add_contact(contact("Bob Updated"))
                .await
                .unwrap_err()
        } else {
            manager.remove_contact(&identity_key()).await.unwrap_err()
        };
        let mut recorded_calls: Vec<String> = recorded["calls"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| snake(c.as_str().unwrap()))
            .collect();
        if update {
            let words = recorded["outcome"]["error"].as_str().unwrap();
            assert_eq!(recorded["outcome"]["cause"], Value::Null, "{name}");
            assert_eq!(err, Error::IdentityError(words.into()), "{name}");
            assert_eq!(recorded_calls.remove(0), "list_outputs", "{name}");
        } else {
            assert_eq!(recorded["outcome"]["error"], wrapper, "{name}");
            assert_eq!(err, Error::IdentityError(wrapper.into()), "{name}");
        }
        assert_eq!(wallet.calls(), recorded_calls, "{name}");
        assert_eq!(
            wallet.signs.lock().unwrap().len(),
            recorded["sign_action"].as_array().unwrap().len(),
            "{name}"
        );
        let aborts = wallet.aborts.lock().unwrap().clone();
        assert_eq!(aborts.len(), 1, "{name}");
        assert_eq!(
            aborts[0].reference,
            recorded["abort_action"][0]["reference"].as_str().unwrap(),
            "{name}"
        );
    }
}

/// Two contacts cached at different saved-at times each keep their own
/// time through a forced refresh that lists both (#904's seventh fold: the
/// sixth re-read's plant K2, the saved-at time read as the cache's leading
/// entry's, `.values().next()`, passed every test). `added_at` is this
/// crate's member (#544; the reference's record has none,
/// `ContactsManager.ts:171-198`).
#[tokio::test]
async fn a_forced_refresh_keeps_each_of_two_cached_contacts_saved_at_time_904() {
    let wallet = identity_reveal_wallet::Counting::of_scalar(9);
    let carol = carol();
    let (two, _) = contact_listing(
        &wallet,
        &[
            ("Bob Example", identity_key(), 0),
            ("Carol Example", carol.identity_key.clone(), 0),
        ],
    )
    .await;
    *wallet.listed.lock().unwrap() = Some(empty());
    *wallet.sign_mode.lock().unwrap() = "signed";
    *wallet.create_finished.lock().unwrap() = true;
    let manager = ContactsManager::new(wallet.clone(), ContactsManagerConfig::default());
    manager
        .add_contact(contact("Bob Example").with_added_at(1_700_000_000_000))
        .await
        .unwrap();
    manager
        .add_contact(carol.clone().with_added_at(1_800_000_000_000))
        .await
        .unwrap();
    *wallet.listed.lock().unwrap() = Some(two);
    let read = manager.list_contacts_with_refresh(true).await.unwrap();
    assert_eq!(read.len(), 2);
    for c in &read {
        let want = if c.identity_key == identity_key() {
            1_700_000_000_000
        } else {
            1_800_000_000_000
        };
        assert_eq!(c.added_at, want, "{}: the saved-at time", c.name);
    }
}

/// A plain read over a cache loaded with two contacts answers both and asks
/// the wallet nothing (#904's seventh fold: the sixth re-read's plant K8,
/// the cached read cut to its leading contact, `.take(1)`, passed every
/// test). The reference returns every cached contact
/// (`ContactsManager.ts:326-328`).
#[tokio::test]
async fn a_plain_read_over_two_cached_contacts_answers_both_904() {
    let wallet = identity_reveal_wallet::Counting::of_scalar(9);
    let (two, _) = contact_listing(
        &wallet,
        &[
            ("Bob Example", identity_key(), 0),
            ("Carol Example", carol().identity_key.clone(), 0),
        ],
    )
    .await;
    *wallet.listed.lock().unwrap() = Some(two);
    let manager = ContactsManager::new(wallet.clone(), ContactsManagerConfig::default());
    let loaded = manager.list_contacts_with_refresh(true).await.unwrap();
    assert_eq!(loaded.len(), 2);
    let before = wallet.calls().len();
    let read = manager.list_contacts_with_refresh(false).await.unwrap();
    assert_eq!(names(&read), names(&loaded), "the plain read's answer");
    assert_eq!(wallet.calls()[before..].len(), 0);
}

/// A cold plain read loads and caches what it loaded, so the next plain read
/// asks the wallet nothing (#904's seventh fold: the sixth re-read's plant
/// K10, the cache written by a forced refresh alone, passed every test). The
/// reference caches after any load (`ContactsManager.ts:333-336`,
/// `:375-376`).
#[tokio::test]
async fn a_cold_plain_read_caches_what_it_loaded_904() {
    let (wallet, _) = listing_a_contact(0).await;
    let manager = ContactsManager::new(wallet.clone(), ContactsManagerConfig::default());
    let loaded = manager.list_contacts_with_refresh(false).await.unwrap();
    assert_eq!(loaded.len(), 1);
    assert!(
        manager.is_cache_initialized().await,
        "a cold plain read left the cache unloaded"
    );
    let before = wallet.calls().len();
    let read = manager.list_contacts_with_refresh(false).await.unwrap();
    assert_eq!(names(&read), names(&loaded));
    assert_eq!(
        wallet.calls()[before..].len(),
        0,
        "the second plain read asked the wallet"
    );
}
