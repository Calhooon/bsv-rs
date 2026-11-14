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
//! key) is replayed as a caller of this crate composes it, a plain read and
//! then the call: the reference's `saveContact` and `getContacts(identityKey)`
//! load the whole basket there themselves (`:529-531`, `:331-338`), where
//! `add_contact` and `get_contact` read the cache alone (the stated residue
//! of the root `CLAUDE.md`'s #904 row; conforming is a decision, and the
//! replay then loses `load_as_the_reference_does`, nothing else). A cold
//! update whose load did not cache its contact is saved through
//! `add_contact`, `update_contact`'s `ContactNotFound` having no reference
//! twin. A contact is compared as the reference's record (`contact_answer`):
//! `notes` and `tags` inside `metadata`, an absent avatar the empty text, as
//! `contacts_record.rs` writes them. The generator draws no member value the
//! validator rewrites and no update of a contact a warm cache lacks, and
//! keeps no sequence whose basket holds one key in two outputs (none was
//! drawn): those are outside the replay.
//!
//! A value the validator rewrites is recorded beside the sequences
//! (`stated_959`, three cells) and held as this crate answers it today by
//! `a_save_answers_the_callers_form_until_a_refresh_stated_959`: a warm
//! read after a save answers the caller's own form, where the reference
//! answers the validated record (the root `CLAUDE.md`'s #904 row; ruled to
//! be conformed before the cut, which turns that test over).
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
                Some(Value::Object(members)) => members.clone(),
                _ => serde_json::Map::new(),
            };
            if let Some(notes) = &c.notes {
                metadata.insert("notes".into(), json!(notes));
            }
            if !c.tags.is_empty() {
                metadata.insert("tags".into(), json!(c.tags));
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
                "metadata": if metadata.is_empty() { Value::Null } else { Value::Object(metadata) },
            })
        })
        .collect()
}

/// The load the reference's `saveContact` and `getContacts(identityKey)`
/// make over a cold cache (`ContactsManager.ts:529-531`, `:331-338`), made
/// here as a caller makes it: a plain read.
async fn load_as_the_reference_does(manager: &ContactsManager<Basket>) -> bsv_rs::Result<()> {
    manager.list_contacts_with_refresh(false).await.map(|_| ())
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
        let loaded = if step["cold"] == true {
            load_as_the_reference_does(&manager).await
        } else {
            Ok(())
        };
        let (outcome, answer) = match op {
            _ if loaded.is_err() => (loaded, None),
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
                let lacking =
                    step["cold"] == true && manager.get_contact(&key).await.unwrap().is_none();
                if lacking {
                    (manager.add_contact(contact()).await, None)
                } else {
                    (manager.update_contact(&key, contact()).await, None)
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

/// One stated cell of #959 (`stated_959` in the vector): the recorded
/// sequence is a forced read, one save, then four reads (a warm plain read,
/// a warm read by key, a forced read, a plain read after it). Answers a
/// manager over the basket wallet with the forced read and the save made,
/// the contact as the caller gave it, and the reference's recorded record
/// at each of the four reads.
async fn stated_cell(name: &str) -> (ContactsManager<Basket>, Contact, Vec<Value>) {
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

/// The four reads of a stated cell on this crate: the warm plain read, the
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

/// STATED, held as it stands (#959's D7; the captain's ruling: conformed to
/// the reference before the cut by a later lane, which turns this test
/// over). After a save a warm read answers the contact as the caller gave
/// it, where the reference caches and answers the record `validateContact`
/// returned (`ContactsManager.ts:527-534`, `:566`; `safeNavigation`,
/// `:104-122`), so the two part until a refresh. Three cells, each a
/// recorded sequence of the vector's `stated_959` (a forced read, the save,
/// a warm plain read, a warm read by key, a forced read, a plain read),
/// the reference's answer read from the recording and never typed here:
///
/// - a `badgeClickURL` of `https://example.com`: as given while warm, the
///   URL parser's form after a refresh; the reference, that form at all
///   four reads;
/// - an empty `metadata` object: `Some({})` while warm, none after a
///   refresh; the reference, `{}` at all four reads;
/// - tags and notes given through `with_metadata` alone: the record is the
///   reference's at all four reads, but while warm the contact's `tags`
///   and `notes` are empty, so `get_contacts_by_tag` and `search_contacts`
///   (this crate's helpers, no reference twin) miss it, and after a
///   refresh they find it.
#[tokio::test]
async fn a_save_answers_the_callers_form_until_a_refresh_stated_959() {
    // Cell 1: a `badgeClickURL` the validator rewrites.
    let (manager, given, theirs) = stated_cell("click_url_the_validator_rewrites").await;
    let recorded = theirs[0]["badge_click_url"].as_str().unwrap();
    // The reference: one form at all four reads, and not the caller's.
    for read in &theirs {
        assert_eq!(read["badge_click_url"], recorded);
    }
    assert_ne!(recorded, given.badge_click_url);
    assert!(recorded.starts_with(given.badge_click_url.as_str()));
    let [plain, by_key, forced, after] = four_reads(&manager, &given.identity_key).await;
    // Today: the caller's form while warm. The reference's answer here is
    // `recorded` (the validated form, `https://example.com/`); the
    // conforming lane makes these two `assert_eq!(.., recorded)`.
    assert_eq!(plain.badge_click_url, given.badge_click_url);
    assert_eq!(by_key.badge_click_url, given.badge_click_url);
    // After a refresh both sides answer the validated form.
    assert_eq!(forced.badge_click_url, recorded);
    assert_eq!(after.badge_click_url, recorded);

    // Cell 2: an empty `metadata` object.
    let (manager, given, theirs) = stated_cell("empty_metadata_object").await;
    assert_eq!(given.metadata, Some(json!({})));
    // The reference: `{}` at all four reads.
    for read in &theirs {
        assert_eq!(read["metadata"], json!({}));
    }
    let [plain, by_key, forced, after] = four_reads(&manager, &given.identity_key).await;
    // Today: the caller's `Some({})` while warm, as the reference's `{}`.
    assert_eq!(plain.metadata, Some(json!({})));
    assert_eq!(by_key.metadata, Some(json!({})));
    // Today: none after a refresh. The reference's answer here is `{}`
    // (`theirs[2]`, `theirs[3]`, asserted above); the conforming lane
    // makes one form of the four, whichever it rules.
    assert_eq!(forced.metadata, None);
    assert_eq!(after.metadata, None);

    // Cell 3: tags and notes given through `with_metadata` alone.
    let (manager, given, theirs) = stated_cell("tags_and_notes_inside_metadata").await;
    let members = given.metadata.clone().unwrap();
    let tag = members["tags"][0].as_str().unwrap().to_string();
    let notes = members["notes"].as_str().unwrap().to_string();
    assert!(given.tags.is_empty() && given.notes.is_none());
    // The reference: the record carries both inside `metadata` at all
    // four reads (it has no read by tag).
    for read in &theirs {
        assert_eq!(read["metadata"], members);
    }
    // Today, warm: the contact as given, so neither helper finds it. The
    // reference's record at this read (`theirs[0]`) carries the tag and
    // the notes; the conforming lane (the validated record cached, read
    // back as after a refresh) makes these two answers the contact.
    assert!(manager.get_contacts_by_tag(&tag).await.unwrap().is_empty());
    assert!(manager.search_contacts(&notes).await.unwrap().is_empty());
    let [plain, by_key, forced, after] = four_reads(&manager, &given.identity_key).await;
    for warm in [&plain, &by_key] {
        assert!(warm.tags.is_empty() && warm.notes.is_none());
        assert_eq!(warm.metadata, Some(members.clone()));
    }
    for refreshed in [&forced, &after] {
        assert_eq!(refreshed.tags, std::slice::from_ref(&tag));
        assert_eq!(refreshed.notes.as_deref(), Some(notes.as_str()));
        assert_eq!(refreshed.metadata, None);
    }
    // As a record the four answers are the reference's: the difference is
    // this crate's own fields, which the comparator folds back.
    let ours = [plain, by_key, forced, after];
    for (ours, theirs) in contact_answer(&ours).iter().zip(&theirs) {
        assert_eq!(ours["metadata"], theirs["metadata"]);
    }
    // After the refresh both helpers find the contact.
    let found = manager.get_contacts_by_tag(&tag).await.unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].identity_key, given.identity_key);
    assert_eq!(manager.search_contacts(&notes).await.unwrap().len(), 1);
}
