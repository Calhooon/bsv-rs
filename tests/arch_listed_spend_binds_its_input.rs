//! A spend of an output found in a listing or an answer signs at the input
//! the wallet bound, keyed by that index, over the output read by its txid
//! (#904, root rule 11). The contacts manager signed over the BEEF's leading
//! entry at input 0 and keyed its spend 0 (`src/identity/contacts_actions.rs`
//! until #904); the reference finds the input by outpoint and reads the
//! source by txid (`ts-stack@edf6e03` `ContactsManager.ts:640,689-697,819-838`).
//!
//! The machine: every caller of the one wallet PushDrop signer
//! (`crate::wallet::pushdrop::sign`) is listed in `CALLERS`, a fifth refused
//! until it is listed, a listed one that no longer calls it refused as
//! stale; in every listed file, read with whitespace and line comments
//! removed, no `input_index:` given a literal, no spend keyed by a literal
//! (`(0,SignActionSpend`, `insert(0,`), and no BEEF entry read by position
//! (`txs.first()`, `txs.last()`, `txs.get(`, `txs[`).
//!
//! What a lexical reading cannot see: an index computed to a constant
//! (`let i = 0;` then `input_index: i`), a source chosen by position through
//! another name (an iterator's `next()`, a helper in another file), a spend
//! map built by a macro, a caller reaching the signer through an alias or a
//! re-export. The runs that hold the rule at each door are the doors' tests:
//! `tests/contacts_listed_spend.rs` (the contacts manager), the revocation's
//! `tests/identity_revocation_checks_327.rs`, the registry's
//! `tests/registry_unlocking_548.rs` and the stores' `tests/kvstore_tokens_343.rs`
//! (their sources returned in reverse to exercise the outpoint binding).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

use std::path::{Path, PathBuf};

/// The callers of `wallet::pushdrop::sign`, each with how it binds.
const CALLERS: &[(&str, &str)] = &[
    (
        "src/identity/contacts_actions.rs",
        "the listed output read by txid (#readListedSource); the input bound by outpoint (#findBoundInput)",
    ),
    (
        "src/identity/revoke.rs",
        "the authenticated transaction's output; the one input at the outpoint (revelationInputOutpoint)",
    ),
    (
        "src/registry/unlock.rs",
        "the record's listed script and satoshis (#548's residue); the input found by outpoint",
    ),
    (
        "src/kvstore/token_spends.rs",
        "the signable transaction's linked source (#343's row); the input found by outpoint",
    ),
];

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// The source with line comments dropped and every whitespace removed.
fn squeezed(text: &str) -> String {
    text.lines()
        .map(|line| match line.find("//") {
            Some(at) => &line[..at],
            None => line,
        })
        .collect::<String>()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect()
}

/// Each refusal of `text` (one file, squeezed), by reason.
fn refusals(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let digit_after = |needle: &str| {
        text.match_indices(needle).any(|(at, _)| {
            text[at + needle.len()..]
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_digit())
        })
    };
    if digit_after("input_index:") {
        out.push("a literal input_index".to_string());
    }
    if digit_after("insert(") {
        out.push("a spend inserted at a literal key".to_string());
    }
    let keyed = text.match_indices(",SignActionSpend").any(|(at, _)| {
        let before = &text[..at];
        let digits = before.len() - before.trim_end_matches(|c: char| c.is_ascii_digit()).len();
        digits > 0 && before[..before.len() - digits].ends_with('(')
    });
    if keyed {
        out.push("a spend keyed by a literal".to_string());
    }
    for needle in ["txs.first()", "txs.last()", "txs.get(", "txs["] {
        if text.contains(needle) {
            out.push(format!("a BEEF entry read by position ({needle})"));
        }
    }
    out
}

#[test]
fn every_caller_of_the_pushdrop_signer_is_listed_and_binds_by_outpoint() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    files.sort();
    let mut found = Vec::new();
    for path in &files {
        let text = std::fs::read_to_string(path).unwrap();
        if squeezed(&text).contains("pushdrop::sign(") {
            let relative = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if relative != "src/wallet/pushdrop.rs" {
                found.push(relative);
            }
        }
    }
    let listed: Vec<String> = CALLERS.iter().map(|(f, _)| f.to_string()).collect();
    for file in &found {
        assert!(
            listed.contains(file),
            "{file} calls wallet::pushdrop::sign and is not in CALLERS: list it with how it binds"
        );
    }
    for file in &listed {
        assert!(
            found.contains(file),
            "CALLERS names {file}, which no longer calls wallet::pushdrop::sign: remove it"
        );
    }
    for (file, _) in CALLERS {
        let text = squeezed(&std::fs::read_to_string(root.join(file)).unwrap());
        let refused = refusals(&text);
        assert!(refused.is_empty(), "{file}: {refused:?}");
    }
}

#[test]
fn the_reading_refuses_the_shapes_it_names() {
    let refused = |text: &str| refusals(&squeezed(text));
    assert_eq!(refused("input_index: 0,"), vec!["a literal input_index"]);
    assert!(refused("input_index: index,").is_empty());
    assert_eq!(
        refused("let spends = [(\n    0,\n    SignActionSpend {"),
        vec!["a spend keyed by a literal"]
    );
    assert!(refused("[(key, SignActionSpend {").is_empty());
    assert_eq!(
        refused("spends.insert(1, spend)"),
        vec!["a spend inserted at a literal key"]
    );
    assert!(refused("spends.insert(index, spend)").is_empty());
    assert_eq!(
        refused("beef\n    .txs\n    .first()"),
        vec!["a BEEF entry read by position (txs.first())"]
    );
    assert!(refused("// input_index: 0 in a comment").is_empty());
}
