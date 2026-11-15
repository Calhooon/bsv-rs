//! The contacts manager's cache replayed against the reference's recorded
//! answers (#904's seventh fold). `tests/vectors/contacts_replay.json` holds
//! 320 sequences of 4 to 16 steps generated from its seed by the recorder
//! (`tests/support/contacts_replay_reference.mjs`, a mode of
//! `signaction_reference_326.mjs`, `ts-stack@edf6e03` `ContactsManager.ts`
//! under Node v22.18.0) and one directed sequence for each survivor of the
//! six re-reads before this fold, each run on the reference over a wallet
//! keeping a basket; this test runs every sequence on this crate over the
//! same wallet (`tests/support/contacts_replay_wallet.rs`) and compares,
//! after every step, what a caller observes: the outcome (an error's
//! words), the contacts answered (key, name and saved-at time, in the
//! reference's order), the wallet's calls in order and the arguments the
//! pull request pins. A difference fails naming the sequence, the step and
//! the difference.
//!
//! Since #959 the corpus holds a second generated pass (200 sequences from
//! the seed `bsv-rs#959`, the 320 of the seventh fold drawn as they were)
//! and five more directed sequences: four contacts, every member of the
//! record `validateContact` keeps (`ContactsManager.ts:171-198`) drawn for a
//! save and an update and compared on every answer, and a save, an update
//! and a read by key over a cold cache; and every sequence records, and
//! this test compares, createHmac's protocol, key ID, counterparty and data
//! and encrypt's protocol and counterparty (`counterparty: 'self'` at
//! `:402-407`, `:574-579`, `:752-760`).
//!
//! Every answer is compared in order: a read the reference answers from its
//! cache array (a plain read over a warm cache, a read by key) in that
//! array's order, a read that loads in the listing's (#904's eighth fold;
//! the seventh compared the cached answers as sets, where this crate's
//! cache was a `HashMap` whose order changed from run to run). Two readings
//! are this crate's, each a stated residue of `docs/lanes/fix-contacts.md`,
//! and nothing else is normalized:
//!
//! - the reference's load decrypts its outputs concurrently
//!   (`Promise.allSettled`, `ContactsManager.ts:480-513`) where this crate
//!   reads them one after another, so a run of `getPublicKey`,
//!   `verifySignature` and `decrypt` calls is compared in a fixed order of
//!   the three names (the count of each, never the interleaving);
//! - `added_at` has no reference twin (`:171-198`): its expected value is
//!   the recorder's statement of this crate's rule (`contacts_cache.rs`: the
//!   time of the latest save while the cache held the contact, else 0).
//!
//! A step over a cold cache (`cold: true`: a save, an update, a read by
//! key) is replayed as any other since #959's conforming lane: the
//! reference's `saveContact` and `getContacts(identityKey)` load the whole
//! basket there themselves (`:529-531`, `:331-338`), and so do
//! `add_contact`, `get_contact` and `update_contact` (the replay composed
//! that load by a plain read of its own until then; 233 cold steps, 222 of
//! them generated). A cold update whose load did not cache its contact is
//! refused `ContactNotFound` after the load, `update_contact`'s own answer
//! with no reference twin, and the replay then saves it through
//! `add_contact`, over the cache the refused call left loaded, so the
//! step's calls are the reference's `saveContact`'s. A contact is compared
//! as the reference's record (`contact_answer`): `notes` and `tags` inside
//! `metadata`, an absent avatar the empty text, as `contacts_record.rs`
//! writes them, an empty `metadata` object kept apart from an absent one.
//! The generator draws no member value the validator rewrites; two directed
//! sequences do (`save_caches_the_validated_record_959` and its cold twin:
//! a `badgeClickURL` the URL parser serializes otherwise, an empty
//! `metadata`, empty `tags`), every answer the record the validator
//! returned, from the cache as after a refresh. The generator draws no
//! update of a contact a warm cache lacks, and keeps no sequence whose
//! basket holds one key in two outputs (none was drawn): those are outside
//! the replay.
//!
//! The three cells #991's fold recorded beside the sequences (`stated_959`,
//! the fold's name for them: a `badgeClickURL` the validator rewrites, an
//! empty `metadata` object, tags and notes given through the metadata) are
//! held one by one by `a_save_caches_the_validated_record_959`, the
//! reference's recorded record at each of four reads the expected value;
//! the fold held them as this crate answered then, under a `_stated_` name.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing
#![cfg(feature = "identity")]

#[path = "support/contacts_replay_wallet.rs"]
mod contacts_replay_wallet;

use bsv_rs::identity::{Contact, ContactsManager, ContactsManagerConfig};
use bsv_rs::Error;
use contacts_replay_wallet::{Basket, Fault};
use serde_json::{json, Value};

fn vector() -> Value {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/contacts_replay.json"
    ))
    .unwrap();
    serde_json::from_str(&text).unwrap()
}

/// An error's words: the message the reference throws.
fn words(error: &Error) -> String {
    match error {
        Error::IdentityError(words) | Error::WalletError(words) => words.clone(),
        other => other.to_string(),
    }
}

/// The calls with each run of the three concurrent load reads in a fixed
/// order (the second reading of the header).
fn normalized(calls: &[String]) -> Vec<String> {
    let rank = |c: &str| match c {
        "getPublicKey" => Some(0),
        "verifySignature" => Some(1),
        "decrypt" => Some(2),
        _ => None,
    };
    let mut out: Vec<String> = Vec::new();
    let mut run: Vec<String> = Vec::new();
    for call in calls {
        if rank(call).is_some() {
            run.push(call.clone());
            continue;
        }
        run.sort_by_key(|c| rank(c));
        out.append(&mut run);
        out.push(call.clone());
    }
    run.sort_by_key(|c| rank(c));
    out.append(&mut run);
    out
}

/// Each contact as the reference's record: every member `validateContact`
/// keeps, `notes` and `tags` in `metadata` where the record carries them.
fn contact_answer(contacts: &[Contact]) -> Vec<Value> {
    contacts
        .iter()
        .map(|c| {
            let mut metadata = match &c.metadata {
                Some(Value::Object(members)) => Some(members.clone()),
                _ => None,
            };
            if let Some(notes) = &c.notes {
                metadata
                    .get_or_insert_with(Default::default)
                    .insert("notes".into(), json!(notes));
            }
            if !c.tags.is_empty() {
                metadata
                    .get_or_insert_with(Default::default)
                    .insert("tags".into(), json!(c.tags));
            }
            json!({
                "identity_key": c.identity_key,
                "name": c.name,
                "added_at": c.added_at,
                "avatar_url": c.avatar_url.clone().unwrap_or_default(),
                "abbreviated_key": c.abbreviated_key,
                "badge_icon_url": c.badge_icon_url,
                "badge_label": c.badge_label,
                "badge_click_url": c.badge_click_url,
                "metadata": metadata.map_or(Value::Null, Value::Object),
            })
        })
        .collect()
}

/// Runs one sequence on this crate; the earliest step that differs, if any.
async fn replay(keys: &[String], steps: &[Value]) -> Option<(usize, String)> {
    let wallet = Basket::new();
    let manager = ContactsManager::new(wallet.clone(), ContactsManagerConfig::default());
    for (index, step) in steps.iter().enumerate() {
        let faults = step["faults"]
            .as_array()
            .map(|faults| {
                faults
                    .iter()
                    .map(|f| Fault {
                        call: f["call"].as_str().unwrap().into(),
                        turn: f["turn"].as_u64().unwrap() as u32,
                        mode: f["mode"].as_str().unwrap().into(),
                    })
                    .collect()
            })
            .unwrap_or_default();
        wallet.begin(faults);
        let key = step["contact"].as_u64().map(|k| keys[k as usize].clone());
        let contact = || {
            let member = |name: &str| step["members"][name].as_str().unwrap_or("").to_string();
            let contact = Contact::new(step["name"].as_str().unwrap(), key.clone().unwrap())
                .with_added_at(step["added_at"].as_u64().unwrap())
                .with_avatar_url(member("avatar_url"))
                .with_abbreviated_key(member("abbreviated_key"))
                .with_badge_icon_url(member("badge_icon_url"))
                .with_badge_label(member("badge_label"))
                .with_badge_click_url(member("badge_click_url"));
            match step["members"].get("metadata") {
                Some(metadata) => contact.with_metadata(metadata.clone()),
                None => contact,
            }
        };
        let op = step["op"].as_str().unwrap();
        let (outcome, answer) = match op {
            "plain" | "forced" => match manager.list_contacts_with_refresh(op == "forced").await {
                Ok(contacts) => (Ok(()), Some(contact_answer(&contacts))),
                Err(e) => (Err(e), None),
            },
            "by_key" => match manager.get_contact(&key.clone().unwrap()).await {
                Ok(found) => (Ok(()), Some(contact_answer(found.as_slice()))),
                Err(e) => (Err(e), None),
            },
            "save" => (manager.add_contact(contact()).await, None),
            "update" => {
                let key = key.clone().unwrap();
                match manager.update_contact(&key, contact()).await {
                    // This crate's own refusal, after the load: the
                    // reference's `saveContact` saves (the header).
                    Err(Error::ContactNotFound(_)) if step["cold"] == true => {
                        (manager.add_contact(contact()).await, None)
                    }
                    outcome => (outcome, None),
                }
            }
            "remove" => (manager.remove_contact(&key.clone().unwrap()).await, None),
            "clear" => {
                manager.clear_cache().await;
                (Ok(()), None)
            }
            "pad" => {
                wallet.pad(step["total"].as_u64().unwrap() as usize);
                (Ok(()), None)
            }
            other => panic!("unknown operation {other}"),
        };
        let (calls, args) = wallet.end();
        let outcome = match outcome {
            Ok(()) => json!({ "ok": true }),
            Err(e) => json!({ "error": words(&e) }),
        };
        let at = |what: &str, ours: &dyn std::fmt::Debug, theirs: &dyn std::fmt::Debug| {
            Some((
                index,
                format!("{op}: the {what}: this crate {ours:?}, the reference {theirs:?}"),
            ))
        };
        if outcome != step["outcome"] {
            return at("outcome", &outcome, &step["outcome"]);
        }
        let expected = step["answer"].as_array().cloned();
        if answer != expected {
            return at("answer", &answer, &expected);
        }
        let calls: Vec<String> = calls.iter().map(|c| c.to_string()).collect();
        let theirs: Vec<String> = step["calls"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c.as_str().unwrap().to_string())
            .collect();
        if normalized(&calls) != normalized(&theirs) {
            return at("calls", &calls, &theirs);
        }
        if Value::Array(args.clone()) != step["args"] {
            return at("arguments", &args, &step["args"]);
        }
    }
    None
}

/// Every recorded sequence replayed on this crate, each step's outcome,
/// answer, calls and arguments the reference's (the readings of the
/// header); a difference names the sequence and the step.
#[tokio::test]
async fn the_cache_replays_every_recorded_sequence_as_the_reference_answers_904() {
    let vector = vector();
    let keys: Vec<String> = vector["contact_keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k.as_str().unwrap().to_string())
        .collect();
    let mut sequences: Vec<(String, &Vec<Value>)> = vector["sequences"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
        .map(|(n, s)| (format!("sequence {n}"), s.as_array().unwrap()))
        .collect();
    for (name, steps) in vector["directed"].as_object().unwrap() {
        sequences.push((format!("directed {name}"), steps.as_array().unwrap()));
    }
    let mut differences = Vec::new();
    for (name, steps) in &sequences {
        // Each sequence in a task of its own, so a panic (a wallet asked
        // what no reference run asked it) is named with its sequence.
        let (keys, steps) = (keys.clone(), (*steps).clone());
        let local = tokio::task::LocalSet::new();
        let task = local.spawn_local(async move { replay(&keys, &steps).await });
        match local.run_until(task).await {
            Ok(None) => {}
            Ok(Some((step, difference))) => {
                differences.push(format!("{name}, step {step}: {difference}"))
            }
            Err(_) => differences.push(format!("{name}: the replay panicked")),
        }
    }
    assert!(
        differences.is_empty(),
        "{} of {} sequences differ from the reference:\n{}",
        differences.len(),
        sequences.len(),
        differences.join("\n")
    );
}

/// The corpus is what the fold says it is: at least 300 generated sequences
/// of 4 to 16 steps, every operation and every fault mode of the recorder
/// reached, three contacts answered at once, and one directed sequence for
/// each survivor of the six re-reads; and what #959 added: 520 sequences,
/// four contacts answered from the cache and from a listing, each member of
/// the record answered with a value, each cold operation succeeding and
/// failing, every createHmac and encrypt request recorded with `self`, and
/// the five directed sequences.
#[test]
fn the_corpus_reaches_every_operation_fault_and_three_contacts_904() {
    let vector = vector();
    let sequences = vector["sequences"].as_array().unwrap();
    assert_eq!(sequences.len(), 520, "sequences");
    assert_eq!(vector["discarded_959"], 0, "a sequence holding a key twice");
    let steps: Vec<&Value> = sequences
        .iter()
        .flat_map(|s| s.as_array().unwrap())
        .collect();
    for s in sequences {
        let n = s.as_array().unwrap().len();
        assert!((4..=16).contains(&n), "a sequence of {n} steps");
    }
    for op in [
        "plain", "forced", "by_key", "save", "update", "remove", "clear", "pad",
    ] {
        assert!(steps.iter().any(|s| s["op"] == op), "no {op} step");
    }
    for mode in [
        "throw",
        "no_tx",
        "duplicate_input",
        "missing_input",
        "output",
        "signed_version",
        "signed_output",
        "signed_script",
    ] {
        assert!(
            steps.iter().any(|s| s["faults"]
                .as_array()
                .is_some_and(|f| f.iter().any(|f| f["mode"] == mode))),
            "no {mode} fault"
        );
    }
    assert!(
        steps.iter().any(|s| s["outcome"]["error"]
            == "Invalid contacts result: outputs must be an array of at most 1000 entries"),
        "no listing past the bound"
    );
    assert!(
        steps
            .iter()
            .any(|s| s["answer"].as_array().is_some_and(|a| a.len() == 3)),
        "no answer of three contacts"
    );
    for order in ["cache", "listing"] {
        assert!(
            steps.iter().any(
                |s| s["order"] == order && s["answer"].as_array().is_some_and(|a| a.len() == 4)
            ),
            "no answer of four contacts in the {order}'s order"
        );
    }
    for member in [
        "avatar_url",
        "abbreviated_key",
        "badge_icon_url",
        "badge_label",
        "badge_click_url",
        "metadata",
    ] {
        for order in ["cache", "listing"] {
            assert!(
                steps.iter().any(|s| s["order"] == order
                    && s["answer"].as_array().is_some_and(|a| a
                        .iter()
                        .any(|c| !c[member].is_null() && c[member] != ""))),
                "no {member} answered in the {order}'s order"
            );
        }
    }
    for op in ["save", "update", "by_key"] {
        for ok in [true, false] {
            assert!(
                steps.iter().any(|s| s["op"] == op
                    && s["cold"] == true
                    && (s["outcome"]["ok"] == true) == ok),
                "no cold {op} with ok {ok}"
            );
        }
    }
    let key_calls: Vec<&Value> = steps
        .iter()
        .flat_map(|s| s["args"].as_array().unwrap())
        .filter(|a| a["call"] == "createHmac" || a["call"] == "encrypt")
        .collect();
    for call in ["createHmac", "encrypt"] {
        assert!(
            key_calls.iter().filter(|a| a["call"] == call).count() >= 500,
            "few {call} requests"
        );
    }
    assert!(
        key_calls
            .iter()
            .all(|a| a["counterparty"] == "self" && a["protocol_id"] == json!([2, "contact"])),
        "a key request of the reference without self or the contact protocol"
    );
    let directed = vector["directed"].as_object().unwrap();
    for name in [
        "cold_save_959",
        "cold_save_listing_faults_959",
        "cold_read_by_key_959",
        "members_replaced_by_an_update_959",
        "four_contacts_959",
        "removal_bound_input",
        "update_signs_before_refusal",
        "removal_failure_keeps_cache",
        "removal_of_one_of_two",
        "update_two_signable_faults",
        "failed_refresh_over_loaded",
        "failed_refresh_over_empty",
        "saved_at_of_two",
        "plain_read_of_two",
        "cold_plain_read_caches",
        "load_arguments",
        "listing_bound",
        "three_contacts",
    ] {
        assert!(directed.contains_key(name), "no directed {name}");
    }
}

/// `get_contacts_by_tag` answers the contacts carrying the tag whatever
/// either side's letter case, the whole tag and never a part of one, in the
/// cache's order (#959). The helper is this crate's own (the reference has
/// no read by tag), so no recorded cell can hold it: four contacts saved
/// through the basket wallet, tagged `Work`, `work` beside another tag,
/// `WORK`, and `homework`.
#[tokio::test]
async fn get_contacts_by_tag_matches_the_whole_tag_whatever_its_case_959() {
    let keys: Vec<String> = vector()["contact_keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k.as_str().unwrap().to_string())
        .collect();
    let manager = ContactsManager::new(Basket::new(), ContactsManagerConfig::default());
    let tagged: [(&str, &[&str]); 4] = [
        ("Bob", &["Work"]),
        ("Carol", &["friends", "work"]),
        ("Dave", &["WORK"]),
        ("Erin", &["homework"]),
    ];
    for ((name, tags), key) in tagged.iter().zip(&keys) {
        let contact = Contact::new(*name, key.clone())
            .with_abbreviated_key("")
            .with_tags(tags.iter().copied());
        manager.add_contact(contact).await.unwrap();
    }
    let names =
        |contacts: Vec<Contact>| -> Vec<String> { contacts.into_iter().map(|c| c.name).collect() };
    for asked in ["work", "Work", "WORK", "wORk"] {
        assert_eq!(
            names(manager.get_contacts_by_tag(asked).await.unwrap()),
            ["Bob", "Carol", "Dave"],
            "the tag {asked}"
        );
    }
    assert_eq!(
        names(manager.get_contacts_by_tag("FRIENDS").await.unwrap()),
        ["Carol"]
    );
    assert_eq!(
        names(manager.get_contacts_by_tag("homework").await.unwrap()),
        ["Erin"]
    );
    for part in ["wor", "home", "works", ""] {
        assert!(
            manager.get_contacts_by_tag(part).await.unwrap().is_empty(),
            "the part {part:?} matched a tag"
        );
    }
}

/// A manager over `wallet` with a cold cache, as a new process has it.
fn cold(wallet: &Basket) -> ContactsManager<Basket> {
    ContactsManager::new(wallet.clone(), ContactsManagerConfig::default())
}

fn keys() -> Vec<String> {
    vector()["contact_keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k.as_str().unwrap().to_string())
        .collect()
}

/// One call's wallet calls, by the reference's names.
macro_rules! calls_of {
    ($wallet:expr, $faults:expr, $call:expr) => {{
        $wallet.begin($faults);
        let outcome = $call;
        (outcome, $wallet.end().0)
    }};
}

fn fault(mode: &str) -> Vec<Fault> {
    vec![Fault {
        call: "listOutputs".into(),
        turn: 1,
        mode: mode.into(),
    }]
}

/// D6, the cost: a save over a cold cache asks the wallet the whole basket
/// ahead of its own calls, one listing more than a save over a warm cache
/// (`saveContact`, `ContactsManager.ts:529-531`), and the reads of each
/// contact the basket holds.
#[tokio::test]
async fn a_cold_save_loads_the_basket_ahead_of_its_own_calls_959() {
    let (wallet, keys) = (Basket::new(), keys());
    let manager = cold(&wallet);
    let (outcome, first) = calls_of!(
        wallet,
        vec![],
        manager.add_contact(Contact::new("Bob", &keys[0])).await
    );
    outcome.unwrap();
    let (outcome, warm) = calls_of!(
        wallet,
        vec![],
        manager.add_contact(Contact::new("Carol", &keys[1])).await
    );
    outcome.unwrap();
    // The leading listing itself, against the reference's recorded call
    // list, is `a_cold_add_lists_the_basket_ahead_of_its_own_calls_959`
    // (`tests/contacts_wallet_failures.rs`).
    assert_eq!(
        first[1..],
        warm[..],
        "the cold save's own calls are the warm save's"
    );
    assert_eq!(warm.iter().filter(|c| **c == "listOutputs").count(), 1);
    // A cold save over a basket of two: the load's listing and its three
    // reads of each contact, then the save's own calls.
    let again = cold(&wallet);
    let (outcome, loaded) = calls_of!(
        wallet,
        vec![],
        again.add_contact(Contact::new("Dave", &keys[2])).await
    );
    outcome.unwrap();
    assert_eq!(loaded.len(), warm.len() + 1 + 2 * 3, "{loaded:?}");
    assert_eq!(again.cached_count().await, 3);
}

/// A recorded step of a directed sequence, cold and answered `ok`.
fn cold_step(sequence: &str, step: usize, op: &str) -> Value {
    let step = vector()["directed"][sequence][step].clone();
    assert_eq!(step["op"], op, "{sequence}");
    assert_eq!(step["cold"], true, "{sequence}: the recorded step is cold");
    assert_eq!(step["outcome"], json!({ "ok": true }), "{sequence}");
    step
}

/// D6: a read by key and an update over a cold cache load the basket, so a
/// contact the basket holds is answered and updated
/// (`getContacts(identityKey)`, `ContactsManager.ts:331-338`; `saveContact`,
/// `:529-533`), where the read answered `None` and the update
/// `ContactNotFound`: the two cells #991's fold held as they stood in
/// `tests/contacts_wallet_failures.rs`
/// (`a_cold_get_contact_answers_none_for_a_key_the_basket_holds_stated_959`,
/// `a_cold_update_refuses_contact_not_found_for_a_key_the_basket_holds_stated_959`),
/// turned over here, over the basket wallet, where the update can spend.
/// The expected answers are the reference's recorded steps: its cold read by
/// key (`cold_read_by_key_959`) lists and answers the one contact, its cold
/// update (`cold_save_959`) lists ahead of its calls, succeeds and spends
/// the held output.
#[tokio::test]
async fn a_cold_read_by_key_and_a_cold_update_find_a_contact_the_basket_holds_959() {
    let read = cold_step("cold_read_by_key_959", 4, "by_key");
    assert_eq!(read["calls"][0], "listOutputs");
    assert_eq!(read["answer"].as_array().unwrap().len(), 1);
    let update = cold_step("cold_save_959", 6, "update");
    assert_eq!(update["calls"][0], "listOutputs");
    let update_calls: Vec<&str> = update["calls"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap())
        .collect();
    assert!(update_calls.contains(&"signAction"));

    let (wallet, keys) = (Basket::new(), keys());
    cold(&wallet)
        .add_contact(Contact::new("Bob", &keys[0]))
        .await
        .unwrap();
    let reader = cold(&wallet);
    let (found, calls) = calls_of!(wallet, vec![], reader.get_contact(&keys[0]).await);
    assert_eq!(found.unwrap().unwrap().name, "Bob");
    assert_eq!(calls[0], "listOutputs");
    assert!(reader.is_cache_initialized().await);
    let (found, calls) = calls_of!(wallet, vec![], reader.get_contact(&keys[1]).await);
    assert!(found.unwrap().is_none());
    assert!(calls.is_empty(), "a warm read asks nothing: {calls:?}");

    let updater = cold(&wallet);
    let (outcome, calls) = calls_of!(
        wallet,
        vec![],
        updater
            .update_contact(&keys[0], Contact::new("Bob v2", &keys[0]))
            .await
    );
    outcome.unwrap();
    assert_eq!(calls[0], "listOutputs");
    assert!(calls.contains(&"signAction"), "{calls:?}");
    assert_eq!(
        cold(&wallet)
            .get_contact(&keys[0])
            .await
            .unwrap()
            .unwrap()
            .name,
        "Bob v2"
    );
    // This crate's own refusal (no reference twin), after the load alone.
    let lacking = cold(&wallet);
    let (outcome, calls) = calls_of!(
        wallet,
        vec![],
        lacking
            .update_contact(&keys[1], Contact::new("Carol", &keys[1]))
            .await
    );
    assert!(
        matches!(outcome, Err(Error::ContactNotFound(_))),
        "{outcome:?}"
    );
    assert_eq!(calls.iter().filter(|c| **c == "listOutputs").count(), 1);
    assert!(!calls.contains(&"createHmac"), "{calls:?}");
}

/// D6, the failure: a cold save, read by key or update whose load's listing
/// fails returns the wallet's error as it came, the class a forced read
/// gives for the same listing, after that one call, and leaves the cache
/// cold; the next call loads.
#[tokio::test]
async fn a_cold_call_whose_listing_fails_returns_the_wallets_error_and_stays_cold_959() {
    let (wallet, keys) = (Basket::new(), keys());
    let manager = cold(&wallet);
    let (forced, _) = calls_of!(
        wallet,
        fault("throw"),
        manager.list_contacts_with_refresh(true).await
    );
    let expected = forced.unwrap_err();
    assert_eq!(expected, Error::WalletError("listOutputs failed".into()));
    let (save, calls) = calls_of!(
        wallet,
        fault("throw"),
        manager.add_contact(Contact::new("Bob", &keys[0])).await
    );
    assert_eq!(
        (save.unwrap_err(), calls),
        (expected.clone(), vec!["listOutputs"])
    );
    let (read, calls) = calls_of!(wallet, fault("throw"), manager.get_contact(&keys[0]).await);
    assert_eq!(
        (read.unwrap_err(), calls),
        (expected.clone(), vec!["listOutputs"])
    );
    let (update, calls) = calls_of!(
        wallet,
        fault("throw"),
        manager
            .update_contact(&keys[0], Contact::new("Bob", &keys[0]))
            .await
    );
    assert_eq!(
        (update.unwrap_err(), calls),
        (expected, vec!["listOutputs"])
    );
    assert!(!manager.is_cache_initialized().await);
    assert_eq!(manager.cached_count().await, 0);
    let (read, calls) = calls_of!(wallet, vec![], manager.get_contact(&keys[0]).await);
    assert!(read.unwrap().is_none());
    assert_eq!(calls, vec!["listOutputs"]);
}

/// D6, a listing that never answers: the cold call is pending, as a forced
/// read over the same wallet is (the manager has no clock of its own); a
/// caller that drops it leaves the cache cold and usable.
#[tokio::test]
async fn a_cold_call_whose_listing_hangs_is_pending_and_dropped_without_harm_959() {
    use futures::FutureExt;
    let (wallet, keys) = (Basket::new(), keys());
    let manager = cold(&wallet);
    wallet.begin(fault("hang"));
    assert!(manager
        .list_contacts_with_refresh(true)
        .now_or_never()
        .is_none());
    wallet.begin(fault("hang"));
    assert!(manager
        .add_contact(Contact::new("Bob", &keys[0]))
        .now_or_never()
        .is_none());
    wallet.begin(fault("hang"));
    assert!(manager.get_contact(&keys[0]).now_or_never().is_none());
    wallet.begin(fault("hang"));
    assert!(manager
        .update_contact(&keys[0], Contact::new("Bob", &keys[0]))
        .now_or_never()
        .is_none());
    assert_eq!(wallet.end().0, vec!["listOutputs"]);
    assert!(!manager.is_cache_initialized().await);
    manager
        .add_contact(Contact::new("Bob", &keys[0]))
        .await
        .unwrap();
    assert_eq!(
        manager.get_contact(&keys[0]).await.unwrap().unwrap().name,
        "Bob"
    );
}

/// One cell of #991's fold (`stated_959` in the vector): the recorded
/// sequence is a forced read, one save, then four reads (a warm plain read,
/// a warm read by key, a forced read, a plain read after it). Answers a
/// manager over the basket wallet with the forced read and the save made,
/// the contact as the caller gave it, and the reference's recorded record
/// at each of the four reads.
async fn recorded_cell(name: &str) -> (ContactsManager<Basket>, Contact, Vec<Value>) {
    let vector = vector();
    let steps = vector["stated_959"][name].as_array().unwrap().clone();
    let ops: Vec<&str> = steps.iter().map(|s| s["op"].as_str().unwrap()).collect();
    assert_eq!(
        ops,
        ["forced", "save", "plain", "by_key", "forced", "plain"],
        "{name}"
    );
    for step in &steps {
        assert_eq!(step["outcome"], json!({ "ok": true }), "{name}");
    }
    // The warm reads asked the reference's wallet nothing: its answers
    // there are its cache's.
    for warm in [2, 3, 5] {
        assert_eq!(steps[warm]["calls"], json!([]), "{name}, step {warm}");
        assert_eq!(steps[warm]["order"], "cache", "{name}, step {warm}");
    }
    assert_eq!(steps[4]["calls"][0], "listOutputs", "{name}");
    let save = &steps[1];
    let key = vector["contact_keys"][save["contact"].as_u64().unwrap() as usize]
        .as_str()
        .unwrap();
    let member = |m: &str| save["members"][m].as_str().unwrap().to_string();
    let mut given = Contact::new(save["name"].as_str().unwrap(), key)
        .with_added_at(save["added_at"].as_u64().unwrap())
        .with_avatar_url(member("avatar_url"))
        .with_abbreviated_key(member("abbreviated_key"))
        .with_badge_icon_url(member("badge_icon_url"))
        .with_badge_label(member("badge_label"))
        .with_badge_click_url(member("badge_click_url"));
    if let Some(metadata) = save["members"].get("metadata") {
        given = given.with_metadata(metadata.clone());
    }
    let theirs: Vec<Value> = [2, 3, 4, 5]
        .iter()
        .map(|&read| {
            let answer = steps[read]["answer"].as_array().unwrap();
            assert_eq!(answer.len(), 1, "{name}, step {read}");
            answer[0].clone()
        })
        .collect();
    let manager = ContactsManager::new(Basket::new(), ContactsManagerConfig::default());
    manager.list_contacts_with_refresh(true).await.unwrap();
    manager.add_contact(given.clone()).await.unwrap();
    (manager, given, theirs)
}

/// The four reads of one of those cells on this crate: the warm plain read, the
/// warm read by key, the forced read and the plain read after it, one
/// contact each.
async fn four_reads(manager: &ContactsManager<Basket>, key: &str) -> [Contact; 4] {
    let one = |mut contacts: Vec<Contact>| {
        assert_eq!(contacts.len(), 1);
        contacts.remove(0)
    };
    let plain = one(manager.list_contacts_with_refresh(false).await.unwrap());
    let by_key = manager.get_contact(key).await.unwrap().unwrap();
    let forced = one(manager.list_contacts_with_refresh(true).await.unwrap());
    let after = one(manager.list_contacts_with_refresh(false).await.unwrap());
    [plain, by_key, forced, after]
}

/// D7 (#959), the three cells #991's fold held as they stood under
/// `a_save_answers_the_callers_form_until_a_refresh_stated_959`, turned over:
/// after a save the cache holds the record `validateContact` returned
/// (`ContactsManager.ts:527-534`, `:566`; `safeNavigation`, `:104-122`), so
/// a read answered from the cache is the read after a refresh. Each cell is
/// a recorded sequence of the vector's `stated_959` (a forced read, the
/// save, a warm plain read, a warm read by key, a forced read, a plain
/// read), the reference's answer read from the recording and never typed
/// here:
///
/// - a `badgeClickURL` of `https://example.com`: the URL parser's form at
///   all four reads, never the caller's;
/// - an empty `metadata` object: `{}` at all four reads, after a refresh
///   too (a load read it as none until #959);
/// - tags and notes given through `with_metadata` alone: the record the
///   reference's at all four reads, and the contact's own `tags` and
///   `notes` set while warm as after a refresh, so `get_contacts_by_tag`
///   and `search_contacts` (this crate's helpers, no reference twin) find
///   it at once.
#[tokio::test]
async fn a_save_caches_the_validated_record_959() {
    let whole = |contacts: &[Contact]| -> Vec<Value> {
        contacts
            .iter()
            .map(|c| serde_json::to_value(c).unwrap())
            .collect()
    };

    // Cell 1: a `badgeClickURL` the validator rewrites.
    let (manager, given, theirs) = recorded_cell("click_url_the_validator_rewrites").await;
    let recorded = theirs[0]["badge_click_url"].as_str().unwrap();
    // The reference: one form at all four reads, and not the caller's.
    for read in &theirs {
        assert_eq!(read["badge_click_url"], recorded);
    }
    assert_ne!(recorded, given.badge_click_url);
    assert!(recorded.starts_with(given.badge_click_url.as_str()));
    let reads = four_reads(&manager, &given.identity_key).await;
    for (read, theirs) in reads.iter().zip(&theirs) {
        assert_eq!(read.badge_click_url, theirs["badge_click_url"]);
    }
    let all = whole(&reads);
    assert!(all.iter().all(|read| *read == all[0]), "{all:?}");

    // Cell 2: an empty `metadata` object.
    let (manager, given, theirs) = recorded_cell("empty_metadata_object").await;
    assert_eq!(given.metadata, Some(json!({})));
    let reads = four_reads(&manager, &given.identity_key).await;
    for (read, theirs) in reads.iter().zip(&theirs) {
        // The reference: `{}` at every read.
        assert_eq!(theirs["metadata"], json!({}));
        assert_eq!(read.metadata.as_ref(), Some(&theirs["metadata"]));
    }
    let all = whole(&reads);
    assert!(all.iter().all(|read| *read == all[0]), "{all:?}");

    // Cell 3: tags and notes given through `with_metadata` alone.
    let (manager, given, theirs) = recorded_cell("tags_and_notes_inside_metadata").await;
    let members = given.metadata.clone().unwrap();
    let tag = members["tags"][0].as_str().unwrap().to_string();
    let notes = members["notes"].as_str().unwrap().to_string();
    assert!(given.tags.is_empty() && given.notes.is_none());
    // The reference: the record carries both inside `metadata` at all
    // four reads (it has no read by tag).
    for read in &theirs {
        assert_eq!(read["metadata"], members);
    }
    // Warm, before any refresh: both helpers find the contact.
    let found = manager.get_contacts_by_tag(&tag).await.unwrap();
    assert_eq!(found.len(), 1, "a tag given through the metadata, warm");
    assert_eq!(found[0].identity_key, given.identity_key);
    assert_eq!(manager.search_contacts(&notes).await.unwrap().len(), 1);
    let reads = four_reads(&manager, &given.identity_key).await;
    for read in &reads {
        assert_eq!(read.tags, std::slice::from_ref(&tag));
        assert_eq!(read.notes.as_deref(), Some(notes.as_str()));
        assert_eq!(read.metadata, None);
    }
    // As a record the four answers are the reference's (the comparator
    // folds this crate's two members back into `metadata`).
    for (ours, theirs) in contact_answer(&reads).iter().zip(&theirs) {
        assert_eq!(ours["metadata"], theirs["metadata"]);
    }
    let all = whole(&reads);
    assert!(all.iter().all(|read| *read == all[0]), "{all:?}");
    // And after the refresh as before it.
    assert_eq!(manager.get_contacts_by_tag(&tag).await.unwrap().len(), 1);
    assert_eq!(manager.search_contacts(&notes).await.unwrap().len(), 1);
}

/// Stated (#959): a read by a text `validateIdentityKey` refuses answers
/// `None` and asks the wallet nothing, cold or warm, where the reference's
/// `getContacts(identityKey)` throws before its load (`:316-317`): no
/// contact is held under such a text on either side.
#[tokio::test]
async fn a_read_by_a_text_that_is_no_key_asks_the_wallet_nothing_stated_959() {
    let wallet = Basket::new();
    let manager = cold(&wallet);
    let (found, calls) = calls_of!(wallet, vec![], manager.get_contact("nonexistent").await);
    assert!(found.unwrap().is_none());
    assert!(calls.is_empty(), "{calls:?}");
    assert!(!manager.is_cache_initialized().await);
}

/// #959's fold, the strength read's minor: a `metadata` holding one of the
/// two members alone (`notes`; `tags`) reads as no metadata with that
/// member set, at all four reads, and as a record it is the reference's
/// (the vector's `stated_959` cells `notes_alone_inside_metadata` and
/// `tags_alone_inside_metadata`, recorded beside the three of #991's fold).
/// RED with `contact_of`'s `before != 0` changed to `before > 1`
/// (`Some({})` where `None` is read).
#[tokio::test]
async fn a_metadata_of_notes_alone_or_tags_alone_reads_as_no_metadata_959() {
    for (name, member) in [
        ("notes_alone_inside_metadata", "notes"),
        ("tags_alone_inside_metadata", "tags"),
    ] {
        let (manager, given, theirs) = recorded_cell(name).await;
        let members = given.metadata.clone().unwrap();
        assert_eq!(
            members.as_object().unwrap().keys().collect::<Vec<_>>(),
            [member],
            "{name}"
        );
        assert!(given.tags.is_empty() && given.notes.is_none(), "{name}");
        // The reference: the record carries the one member inside
        // `metadata` at all four reads.
        for read in &theirs {
            assert_eq!(read["metadata"], members, "{name}");
        }
        let reads = four_reads(&manager, &given.identity_key).await;
        for read in &reads {
            assert_eq!(read.metadata, None, "{name}");
            if member == "notes" {
                assert_eq!(read.notes.as_deref(), members["notes"].as_str(), "{name}");
                assert!(read.tags.is_empty(), "{name}");
            } else {
                assert_eq!(json!(read.tags), members["tags"], "{name}");
                assert_eq!(read.notes, None, "{name}");
            }
        }
        for (ours, theirs) in contact_answer(&reads).iter().zip(&theirs) {
            assert_eq!(ours["metadata"], theirs["metadata"], "{name}");
        }
        let all: Vec<Value> = reads
            .iter()
            .map(|c| serde_json::to_value(c).unwrap())
            .collect();
        assert!(all.iter().all(|read| *read == all[0]), "{name}: {all:?}");
    }
}

/// #959's fold, the strength read's item: an update over a cold cache
/// validates its record ahead of the load, as the reference's `saveContact`
/// validates before it reads its cache or the wallet
/// (`ContactsManager.ts:528`, then `:529-531`): a contact the validator
/// refuses (an empty name) is refused in the validator's words, the words a
/// cold save gives, with no wallet call and the cache left cold. RED with
/// `record::record_of(&updates)?;` deleted from `update_contact`
/// (`ContactNotFound` after a listing).
#[tokio::test]
async fn a_cold_update_the_validator_refuses_asks_the_wallet_nothing_959() {
    let (wallet, keys) = (Basket::new(), keys());
    let manager = cold(&wallet);
    let refused = Contact::new("", &keys[0]);
    let words = Error::IdentityError(
        "Invalid contact: name is empty, oversized, or contains control characters".into(),
    );
    let (save, calls) = calls_of!(wallet, vec![], manager.add_contact(refused.clone()).await);
    assert_eq!((save.unwrap_err(), calls), (words.clone(), vec![]));
    let (update, calls) = calls_of!(
        wallet,
        vec![],
        manager.update_contact(&keys[0], refused).await
    );
    assert_eq!((update.unwrap_err(), calls), (words, vec![]));
    assert!(!manager.is_cache_initialized().await);

    // The re-read's case: a valid name and ANOTHER field the validator refuses (an avatar address
    // of an unsafe scheme). A check of the name alone in place of the validator lists the wallet
    // first and answers `ContactNotFound`; the validator's words come with no wallet call.
    let refused = Contact::new("Ada", &keys[0]).with_avatar_url("javascript:alert(1)");
    let words = Error::IdentityError("Invalid contact: avatarURL uses an unsafe URL scheme".into());
    let (save, calls) = calls_of!(wallet, vec![], manager.add_contact(refused.clone()).await);
    assert_eq!((save.unwrap_err(), calls), (words.clone(), vec![]));
    let (update, calls) = calls_of!(
        wallet,
        vec![],
        manager.update_contact(&keys[0], refused).await
    );
    assert_eq!((update.unwrap_err(), calls), (words, vec![]));
    assert!(!manager.is_cache_initialized().await);
}

/// A lookup facilitator counting the questions it is asked and answering
/// an empty list: no network.
struct Counted(std::sync::Arc<std::sync::atomic::AtomicUsize>);

#[async_trait::async_trait(?Send)]
impl bsv_rs::overlay::OverlayLookupFacilitator for Counted {
    async fn lookup(
        &self,
        _url: &str,
        _question: &bsv_rs::overlay::LookupQuestion,
        _timeout_ms: Option<u64>,
    ) -> bsv_rs::Result<bsv_rs::overlay::LookupAnswer> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(bsv_rs::overlay::LookupAnswer::OutputList { outputs: vec![] })
    }
}

/// #959's fold, the rule read's item: `resolve_by_identity_key` with
/// contacts over a cold cache whose listing fails answers the wallet's
/// error as it came, the error the client's forced read gives for the same
/// listing, after that one call and with no host asked, as the reference
/// throws it for a boolean option (`IdentityClient.ts:331-334`,
/// `contactErrorMode: 'throw'`; `:398`; `:575`); the cache stays cold, and
/// the next call loads, finds no contact and asks the lookup. RED with the
/// door's `get_contact(..).await?` put back to `if let Ok(Some(..))` (the
/// lookup's empty answer, one host asked).
#[tokio::test]
async fn the_by_key_door_answers_a_failed_cold_listing_with_the_wallets_error_959() {
    use bsv_rs::identity::IdentityClient;
    use bsv_rs::overlay::{LookupResolver, LookupResolverConfig};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    let (wallet, keys) = (Basket::new(), keys());
    let asked = Arc::new(AtomicUsize::new(0));
    let resolver = Arc::new(LookupResolver::new(LookupResolverConfig {
        facilitator: Some(Arc::new(Counted(asked.clone()))),
        slap_trackers: Some(vec![]),
        host_overrides: Some(std::collections::HashMap::from([(
            "ls_identity".to_string(),
            vec!["https://ls-identity-959-fold.invalid".to_string()],
        )])),
        ..Default::default()
    }));
    let client = IdentityClient::with_resolver(wallet.clone(), Default::default(), resolver);
    let (forced, _) = calls_of!(wallet, fault("throw"), client.get_contacts(true).await);
    let expected = forced.unwrap_err();
    assert_eq!(expected, Error::WalletError("listOutputs failed".into()));
    let (resolved, calls) = calls_of!(
        wallet,
        fault("throw"),
        client.resolve_by_identity_key(&keys[0], true).await
    );
    assert_eq!(
        (resolved.unwrap_err(), calls),
        (expected, vec!["listOutputs"])
    );
    assert_eq!(asked.load(Ordering::SeqCst), 0);
    // Without contacts the door asks the wallet nothing and the lookup once.
    let (resolved, calls) = calls_of!(
        wallet,
        fault("throw"),
        client.resolve_by_identity_key(&keys[0], false).await
    );
    assert_eq!((resolved.unwrap().len(), calls.len()), (0, 0));
    assert_eq!(asked.load(Ordering::SeqCst), 1);
    // The cache was left cold: the next call lists, finds no contact and
    // goes on to the lookup.
    let (resolved, calls) = calls_of!(
        wallet,
        vec![],
        client.resolve_by_identity_key(&keys[0], true).await
    );
    assert_eq!((resolved.unwrap().len(), calls), (0, vec!["listOutputs"]));
    assert_eq!(asked.load(Ordering::SeqCst), 2);
}
