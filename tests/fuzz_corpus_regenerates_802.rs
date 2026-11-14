//! #802: the checked-in fuzz corpus is what `fuzz/corpus-gen` writes.
//!
//! This binary compiles the generator's own source (`fuzz/corpus-gen/src/main.rs`,
//! as a module), reruns it into a temporary directory and compares the result
//! with `fuzz/corpus/` byte for byte:
//!
//! - every seed the generator writes is checked in under its name with the
//!   same bytes;
//! - every checked-in seed the generator does not write is of a family `KEPT`
//!   names, with that family's count (a seed written by hand for an issue, a
//!   night's merged entry, the sibling's rows, the default-mode target's copy
//!   of `fuzz_script_spend`);
//! - the count per target is `COUNTS`, the empty seeds counted in, as the
//!   generator counts them, and named (`EMPTY`): libFuzzer leaves a file of
//!   no bytes out of the corpus it loads, so its count for the six targets
//!   holding the seven empty seeds is lower by their empty seeds (two for
//!   `fuzz_auth_messages`, one for each of the others).
//!
//! The sibling's seed rows (`lean-seed-*` of `fuzz_script_spend`) come from a
//! file outside this tree. Without `BSV_SCRIPT_SEED` they are a kept family,
//! counted and not compared; with it (the sibling's `corpus/seed/seed.jsonl`
//! at `tests/sibling/PIN`) they are regenerated and compared too.
//!
//! Run by the Test Suite's whole run and, on every pull request that is not
//! docs only, by the `fixtures` gate of `checks`.
#![cfg(all(feature = "full", feature = "http"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[allow(dead_code)]
#[path = "../fuzz/corpus-gen/src/main.rs"]
mod corpus_gen;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// A corpus: `<target>/<seed name>` to the seed's bytes.
type Tree = BTreeMap<String, Vec<u8>>;

const ROOT: &str = env!("CARGO_MANIFEST_DIR");

/// A family of checked-in seeds the generator does not write.
#[derive(Clone, Copy)]
enum Family {
    /// Names that start with the text.
    Prefix(&'static str),
    /// A libFuzzer entry merged from a night's artifact (`docs/NIGHTLY.md`):
    /// 40 lower-case hex digits, the SHA-1 of its bytes.
    Merged,
    /// A file of `fuzz_script_spend` under the same name with the same bytes.
    CopyOfScriptSpend,
}

/// `(target, family, count, why it is kept)`. A row whose count moves is a
/// finding: a seed added by hand or merged from a night names itself here.
const KEPT: &[(&str, Family, usize, &str)] = &[
    (
        "fuzz_auth_messages",
        Family::Prefix("known423-"),
        6,
        "#423's known-txids inputs",
    ),
    (
        "fuzz_auth_messages",
        Family::Prefix("label423-"),
        8,
        "#423's label conversions",
    ),
    (
        "fuzz_auth_messages",
        Family::Prefix("response423-"),
        54,
        "#423's strict response parser recordings",
    ),
    (
        "fuzz_auth_messages",
        Family::Prefix("socketio-connect-id"),
        1,
        "#110's CONNECT with an id",
    ),
    (
        "fuzz_auth_messages",
        Family::Prefix("socketio-connect-nan-id"),
        1,
        "#110's id run that is no number",
    ),
    (
        "fuzz_auth_messages",
        Family::Prefix("socketio-event-long-float"),
        1,
        "#285's long float",
    ),
    (
        "fuzz_beef_parser",
        Family::Prefix("issue-844-hand-pushed-entry-amount-unchecked"),
        1,
        "#844's fold, a hand state",
    ),
    (
        "fuzz_transaction_parser",
        Family::Prefix("json_fields_843d7"),
        1,
        "#843d7's JSON fields",
    ),
    (
        "fuzz_script_spend",
        Family::Merged,
        25,
        "a night's merged entries",
    ),
    (
        "fuzz_script_spend",
        Family::Prefix("lean-seed-"),
        75,
        "the sibling's seed rows, one per family (regenerated under BSV_SCRIPT_SEED)",
    ),
    (
        "fuzz_script_spend_default",
        Family::CopyOfScriptSpend,
        678,
        "fuzz_script_spend's seeds, copied (#398)",
    ),
    (
        "fuzz_script_spend_default",
        Family::Prefix("issue-331-"),
        2,
        "#331's read figure",
    ),
    (
        "fuzz_script_spend_default",
        Family::Prefix("issue-382-"),
        2,
        "#382's splice operands",
    ),
    (
        "fuzz_script_spend_default",
        Family::Prefix("issue-383-"),
        2,
        "#383's shift counts",
    ),
];

/// `(target, seeds checked in, of them empty)`: the generator's count, which
/// takes an empty seed as a seed. libFuzzer loads the non-empty ones.
const COUNTS: &[(&str, usize, usize)] = &[
    ("fuzz_auth_messages", 101, 2),
    ("fuzz_base58", 4, 0),
    ("fuzz_beef_parser", 68, 1),
    ("fuzz_bip32", 26, 0),
    ("fuzz_bip39", 276, 0),
    ("fuzz_bsm", 18, 0),
    ("fuzz_chain_primitives", 4, 0),
    ("fuzz_ecies", 25, 1),
    ("fuzz_http_json_responses", 111, 0),
    ("fuzz_merkle_path", 22, 0),
    ("fuzz_messages_encrypted", 9, 1),
    ("fuzz_messages_signed", 6, 0),
    ("fuzz_script_parser", 127, 1),
    ("fuzz_script_spend", 678, 0),
    ("fuzz_script_spend_default", 684, 0),
    ("fuzz_shamir_backup", 15, 0),
    ("fuzz_signature_der", 98, 1),
    ("fuzz_transaction_parser", 7, 0),
    ("fuzz_verify_input", 653, 0),
    ("fuzz_wire_decoders", 78, 0),
    ("fuzz_wire_protocol", 24, 0),
];

/// The seeds of no bytes: five written by the generator, #423's two kept.
const EMPTY: &[&str] = &[
    "fuzz_auth_messages/known423-1",
    "fuzz_auth_messages/response423-truncated_0",
    "fuzz_beef_parser/door-Truncated-bad_index-0-0",
    "fuzz_ecies/plain-0",
    "fuzz_messages_encrypted/plain-0",
    "fuzz_script_parser/script-valid-472",
    "fuzz_signature_der/842-reader-empty",
];

fn read_tree(base: &Path) -> Tree {
    let mut tree = Tree::new();
    for target in fs::read_dir(base).unwrap() {
        let target = target.unwrap();
        if !target.file_type().unwrap().is_dir() {
            continue;
        }
        let name = target.file_name().into_string().unwrap();
        for seed in fs::read_dir(target.path()).unwrap() {
            let seed = seed.unwrap();
            let seed_name = seed.file_name().into_string().unwrap();
            tree.insert(
                format!("{name}/{seed_name}"),
                fs::read(seed.path()).unwrap(),
            );
        }
    }
    tree
}

/// The sibling's seed file, only when the caller names it.
fn sibling() -> Option<PathBuf> {
    std::env::var_os("BSV_SCRIPT_SEED").map(PathBuf::from)
}

/// One rerun of the generator per binary, read back and removed.
fn generated() -> &'static Tree {
    static TREE: OnceLock<Tree> = OnceLock::new();
    TREE.get_or_init(|| {
        let out = std::env::temp_dir().join(format!(
            "bsv-rs-fuzz-corpus-regenerates-802-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&out);
        if let Some(path) = sibling() {
            assert!(
                path.is_file(),
                "BSV_SCRIPT_SEED names {}, which is no file",
                path.display()
            );
        }
        corpus_gen::generate(Path::new(ROOT), &out, sibling().as_deref(), None);
        let tree = read_tree(&out);
        fs::remove_dir_all(&out).unwrap();
        tree
    })
}

fn checked_in() -> Tree {
    read_tree(&Path::new(ROOT).join("fuzz/corpus"))
}

fn is_merged(name: &str) -> bool {
    name.len() == 40 && name.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Every way `checked_in` is not the generator's output beside the kept
/// families; empty when it is.
fn refusals(generated: &Tree, checked_in: &Tree, lean_regenerated: bool) -> Vec<String> {
    let mut out = Vec::new();
    for (path, bytes) in generated {
        match checked_in.get(path) {
            None => out.push(format!(
                "{path}: written by corpus-gen ({} bytes), not checked in",
                bytes.len()
            )),
            Some(held) if held != bytes => out.push(format!(
                "{path}: checked in with {} bytes, corpus-gen writes {} (differing at byte {})",
                held.len(),
                bytes.len(),
                held.iter()
                    .zip(bytes)
                    .position(|(a, b)| a != b)
                    .unwrap_or(held.len().min(bytes.len()))
            )),
            Some(_) => {}
        }
    }
    let mut found = vec![0usize; KEPT.len()];
    for (path, bytes) in checked_in {
        if generated.contains_key(path) {
            continue;
        }
        let (target, name) = path.split_once('/').unwrap();
        let row = KEPT.iter().position(|(t, family, _, _)| {
            *t == target
                && match family {
                    Family::Prefix(prefix) => name.starts_with(prefix),
                    Family::Merged => is_merged(name),
                    Family::CopyOfScriptSpend => {
                        checked_in.get(&format!("fuzz_script_spend/{name}")) == Some(bytes)
                    }
                }
        });
        match row {
            Some(i) => found[i] += 1,
            None => out.push(format!(
                "{path}: checked in, not written by corpus-gen and of no kept family"
            )),
        }
    }
    for (i, (target, family, count, why)) in KEPT.iter().enumerate() {
        let lean = matches!(family, Family::Prefix("lean-seed-"));
        let expected = if lean && lean_regenerated { 0 } else { *count };
        if found[i] != expected {
            out.push(format!(
                "{target}: {} kept seeds of the family `{why}`, {expected} listed",
                found[i]
            ));
        }
    }
    out
}

/// `(seeds, of them empty)` per target.
fn counts(tree: &Tree) -> BTreeMap<&str, (usize, usize)> {
    let mut out: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    for (path, bytes) in tree {
        let entry = out.entry(path.split_once('/').unwrap().0).or_default();
        entry.0 += 1;
        entry.1 += usize::from(bytes.is_empty());
    }
    out
}

#[test]
fn the_checked_in_corpus_is_what_corpus_gen_writes_byte_for_byte_802() {
    let refused = refusals(generated(), &checked_in(), sibling().is_some());
    assert!(
        refused.is_empty(),
        "fuzz/corpus is not what fuzz/corpus-gen writes ({} differences; rerun \
         `cargo run --release --manifest-path fuzz/corpus-gen/Cargo.toml` and commit, or list \
         a seed kept by hand in KEPT):\n{}",
        refused.len(),
        refused.join("\n")
    );
}

/// The finding the gate met on its base: the generator stopped at a file of
/// `tests/vectors/wallet_wire/` that is a recorded table and no message file
/// (`bounds_473.json`, no `wire` member), so no target after the BEEF ones was
/// rewritten by a whole run.
#[test]
fn the_generator_runs_past_a_recorded_table_among_the_wire_message_files_802() {
    let dir = Path::new(ROOT).join("tests/vectors/wallet_wire");
    let tables = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .filter(|p| {
            let value: serde_json::Value =
                serde_json::from_str(&fs::read_to_string(p).unwrap()).unwrap();
            !value["wire"].is_string()
        })
        .count();
    assert!(tables > 0, "the premise: the directory holds a table");
    let per_target = counts(generated());
    // The targets written after the wire files are read, the last among them.
    for target in [
        "fuzz_wire_decoders",
        "fuzz_http_json_responses",
        "fuzz_wire_protocol",
        "fuzz_verify_input",
    ] {
        assert!(
            per_target.get(target).is_some_and(|(seeds, _)| *seeds > 0),
            "{target}: no seed written"
        );
    }
    // A table seeds nothing: every seed of the wire files names a message file.
    for path in generated().keys() {
        for table in ["bounds_473", "call_code_callcode", "originator_338"] {
            assert!(!path.contains(table), "{path}: seeded from a table");
        }
    }
}

#[test]
fn the_seed_counts_take_the_empty_seeds_in_and_name_them_802() {
    let held = checked_in();
    let per_target = counts(&held);
    let listed: BTreeMap<&str, (usize, usize)> =
        COUNTS.iter().map(|(t, n, e)| (*t, (*n, *e))).collect();
    assert_eq!(
        per_target, listed,
        "the seeds checked in per target (seeds, of them empty)"
    );
    let empty: Vec<&str> = held
        .iter()
        .filter(|(_, bytes)| bytes.is_empty())
        .map(|(path, _)| path.as_str())
        .collect();
    assert_eq!(empty, EMPTY);
    // Five are the generator's own, counted in by its report; #423's two are kept.
    let written: Vec<&str> = EMPTY
        .iter()
        .copied()
        .filter(|path| generated().get(*path).is_some_and(Vec::is_empty))
        .collect();
    assert_eq!(
        written,
        [
            "fuzz_beef_parser/door-Truncated-bad_index-0-0",
            "fuzz_ecies/plain-0",
            "fuzz_messages_encrypted/plain-0",
            "fuzz_script_parser/script-valid-472",
            "fuzz_signature_der/842-reader-empty",
        ]
    );
    // The fuzz crate's targets and the corpus directories are the same set.
    let manifest = fs::read_to_string(Path::new(ROOT).join("fuzz/Cargo.toml")).unwrap();
    for (target, _, _) in COUNTS {
        assert!(
            manifest.contains(&format!("name = \"{target}\"")),
            "{target}: a corpus of no target"
        );
    }
}

#[test]
fn a_seed_edited_missing_or_unlisted_is_refused_naming_it_802() {
    let generated = generated();
    let held = checked_in();
    let lean = sibling().is_some();
    assert_eq!(refusals(generated, &held, lean), Vec::<String>::new());

    // One byte of a seed the generator writes.
    let mut edited = held.clone();
    edited.get_mut("fuzz_base58/hex").unwrap()[3] ^= 1;
    assert_eq!(
        refusals(generated, &edited, lean),
        ["fuzz_base58/hex: checked in with 8 bytes, corpus-gen writes 8 (differing at byte 3)"]
    );

    // A seed cut short, and an empty seed given a byte.
    let mut cut = held.clone();
    cut.get_mut("fuzz_base58/hex").unwrap().pop();
    cut.get_mut("fuzz_ecies/plain-0").unwrap().push(0);
    assert_eq!(
        refusals(generated, &cut, lean),
        [
            "fuzz_base58/hex: checked in with 7 bytes, corpus-gen writes 8 (differing at byte 7)",
            "fuzz_ecies/plain-0: checked in with 1 bytes, corpus-gen writes 0 (differing at byte 0)",
        ]
    );

    // A seed the generator writes, removed.
    let mut missing = held.clone();
    missing.remove("fuzz_verify_input/refused-truncated");
    assert_eq!(
        refusals(generated, &missing, lean),
        ["fuzz_verify_input/refused-truncated: written by corpus-gen (68 bytes), not checked in"]
    );

    // A seed of no family: one the generator stopped writing, or one added by hand.
    let mut stale = held.clone();
    stale.insert("fuzz_base58/an-old-name".into(), vec![1]);
    assert_eq!(
        refusals(generated, &stale, lean),
        ["fuzz_base58/an-old-name: checked in, not written by corpus-gen and of no kept family"]
    );

    // A kept family that grew: a merged entry not counted in.
    let mut merged = held.clone();
    merged.insert(
        format!("fuzz_script_spend/{}", "0".repeat(40)),
        vec![6, 0, 0],
    );
    assert_eq!(
        refusals(generated, &merged, lean),
        ["fuzz_script_spend: 26 kept seeds of the family `a night's merged entries`, 25 listed"]
    );

    // The default-mode target's copy edited apart from its source.
    let mut apart = held.clone();
    apart
        .get_mut("fuzz_script_spend_default/script_valid-0")
        .unwrap()
        .push(0);
    let refused = refusals(generated, &apart, lean);
    assert_eq!(
        refused,
        [
            "fuzz_script_spend_default/script_valid-0: checked in, not written by corpus-gen and of no kept family",
            "fuzz_script_spend_default: 677 kept seeds of the family `fuzz_script_spend's seeds, copied (#398)`, 678 listed",
        ]
    );
}

/// A pull request's Test Suite runs the binaries its change reaches by module;
/// a change to `fuzz/corpus/`, to the generator or to a vector names none, so
/// the `fixtures` gate of `checks` runs this binary by name.
#[test]
fn the_fixtures_gate_of_checks_runs_this_binary_802() {
    let ci = fs::read_to_string(Path::new(ROOT).join(".github/workflows/ci.yml"))
        .unwrap()
        .replace("\r\n", "\n");
    let gate = gate_step(&ci).expect("ci.yml: the `checks` job has no step `id: fixtures`");
    assert_eq!(gate_refusals(gate), Vec::<String>::new());

    let line = "          cargo test --features \"full,http\" --test fuzz_corpus_regenerates_802 --locked\n";
    assert!(ci.contains(line));
    for (planted, refusal) in [
        (
            ci.replacen(line, "", 1),
            "the `fixtures` gate does not run `--test fuzz_corpus_regenerates_802`",
        ),
        (
            ci.replacen(
                line,
                &line.replacen("          cargo", "          # cargo", 1),
                1,
            ),
            "the `fixtures` gate does not run `--test fuzz_corpus_regenerates_802`",
        ),
        (
            ci.replacen(line, &line.replacen("--locked", "--locked || true", 1), 1),
            "the `fixtures` gate absorbs the corpus comparison's failure",
        ),
        (
            ci.replacen(line, &line.replacen("--locked", "--locked --no-run", 1), 1),
            "the `fixtures` gate builds the corpus comparison without running it",
        ),
        (
            ci.replacen(
                line,
                &line.replacen("--locked", "--locked -- --ignored", 1),
                1,
            ),
            "the `fixtures` gate hands the corpus comparison a filter",
        ),
    ] {
        let gate = gate_step(&planted).unwrap();
        assert_eq!(gate_refusals(gate), [refusal]);
    }
}

/// The `fixtures` step of `ci.yml`: from its `- name:` line to the next step's.
fn gate_step(ci: &str) -> Option<&str> {
    let id = ci.find("\n        id: fixtures\n")?;
    let start = ci[..id].rfind("\n      - ")? + 1;
    let end = ci[id..]
        .find("\n      - ")
        .map_or(ci.len(), |next| id + next + 1);
    Some(&ci[start..end])
}

fn gate_refusals(step: &str) -> Vec<String> {
    let commands: Vec<&str> = step
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .filter(|l| l.contains("--test fuzz_corpus_regenerates_802"))
        .collect();
    let [command] = commands[..] else {
        return vec![
            "the `fixtures` gate does not run `--test fuzz_corpus_regenerates_802`".into(),
        ];
    };
    let mut out = Vec::new();
    if !command.starts_with("cargo test --features \"full,http\" ") {
        out.push("the `fixtures` gate runs the corpus comparison on another feature set".into());
    }
    if command.contains("||") || command.contains(';') || command.contains("&&") {
        out.push("the `fixtures` gate absorbs the corpus comparison's failure".into());
    }
    if command.contains("--no-run") {
        out.push("the `fixtures` gate builds the corpus comparison without running it".into());
    }
    if command.contains(" -- ") {
        out.push("the `fixtures` gate hands the corpus comparison a filter".into());
    }
    out
}
