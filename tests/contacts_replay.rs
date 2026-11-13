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
//! The generator does not save, update or read by key over a cold cache,
//! nor update a contact the cache lacks (the reference's cold save loads the
//! basket before its tagged listing, `:529-531`, its read by key loads where `get_contact` reads
//! the cache alone, and `update_contact` refuses an uncached key): those are
//! the stated residues, outside the replay.
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

fn contact_answer(contacts: &[Contact]) -> Vec<Value> {
    contacts
        .iter()
        .map(|c| json!({ "identity_key": c.identity_key, "name": c.name, "added_at": c.added_at }))
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
            Contact::new(step["name"].as_str().unwrap(), key.clone().unwrap())
                .with_abbreviated_key("")
                .with_added_at(step["added_at"].as_u64().unwrap())
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
            "update" => (
                manager
                    .update_contact(&key.clone().unwrap(), contact())
                    .await,
                None,
            ),
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
/// each survivor of the six re-reads.
#[test]
fn the_corpus_reaches_every_operation_fault_and_three_contacts_904() {
    let vector = vector();
    let sequences = vector["sequences"].as_array().unwrap();
    assert!(sequences.len() >= 300, "{} sequences", sequences.len());
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
    let directed = vector["directed"].as_object().unwrap();
    for name in [
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
