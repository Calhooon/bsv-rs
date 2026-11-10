//! The door says everything `Spend` says (#855's fold, the captain's line on
//! the strength read's row): every public `set_*` method of `Spend` (read
//! from `src/script/spend/`, its test files skipped) and every public field
//! of `SpendParams` has a counterpart on `InputRules`, `DefaultMode` or
//! `NodeFigures` (named in `COUNTERPARTS`, each read from
//! `src/transaction/spending.rs` inside its type's `impl` block), or an entry
//! of `ALLOWED` with its reason. A new setter or field with neither is
//! refused by name, and a counterpart named that no longer exists is
//! refused too, so the table cannot go stale.
//!
//! The reading is lexical, line by line: a setter is a line whose text,
//! trimmed, starts `pub fn set_` (a `pub(crate)` or `pub(super)` one is not
//! public); a field is a `pub <name>:` line inside `pub struct SpendParams {`
//! up to its closing `}`; a counterpart is a `pub fn <name>` or
//! `pub const fn <name>` line between `impl <Type> {` and the next line that
//! is `}` alone.
#![allow(clippy::expect_used, clippy::panic)] // Source reads are test assertions.

use std::fs;

const SPEND_DIR: &str = "src/script/spend";
const DOOR_FILE: &str = "src/transaction/spending.rs";

/// `(Spend's setter or SpendParams' field, the door's type, its method)`.
const COUNTERPARTS: &[(&str, &str, &str)] = &[
    ("set_flags", "InputRules", "under"),
    (
        "set_require_push_only",
        "DefaultMode",
        "with_require_push_only",
    ),
    ("set_require_minimal", "DefaultMode", "with_require_minimal"),
    (
        "set_utxo_after_chronicle",
        "DefaultMode",
        "with_utxo_after_chronicle",
    ),
    (
        "set_stack_memory_policy",
        "NodeFigures",
        "with_stack_memory_policy",
    ),
    (
        "set_stack_memory_consensus",
        "NodeFigures",
        "with_stack_memory_consensus",
    ),
    (
        "set_script_num_length_policy",
        "NodeFigures",
        "with_script_num_length_policy",
    ),
    ("memory_limit", "InputRules", "with_memory_limit"),
    ("work_limit", "InputRules", "with_work_limit"),
];

/// `(Spend's setter or SpendParams' field, why the door needs none)`.
const ALLOWED: &[(&str, &str)] = &[
    (
        "source_txid",
        "the spending transaction's bytes carry the outpoint",
    ),
    (
        "source_output_index",
        "the spending transaction's bytes carry the outpoint",
    ),
    ("source_satoshis", "a door argument (`source_satoshis`)"),
    ("locking_script", "a door argument (`locking_script`)"),
    (
        "transaction_version",
        "the spending transaction's bytes carry it",
    ),
    (
        "other_inputs",
        "the spending transaction's bytes carry them",
    ),
    ("outputs", "the spending transaction's bytes carry them"),
    ("input_index", "a door argument (`input_index`)"),
    (
        "unlocking_script",
        "the spending transaction's bytes carry the input's own",
    ),
    (
        "input_sequence",
        "the spending transaction's bytes carry it",
    ),
    ("lock_time", "the spending transaction's bytes carry it"),
];

fn normalized(path: &str) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("{path}: {e}"))
        .replace("\r\n", "\n")
}

fn is_test_file(path: &str) -> bool {
    path.ends_with("/tests.rs") || path.ends_with("_tests.rs")
}

/// The public setters a source declares.
fn public_setters(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| line.trim_start().strip_prefix("pub fn set_"))
        .map(|rest| {
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            format!("set_{name}")
        })
        .collect()
}

/// The public fields of `pub struct <name> {` in a source.
fn public_fields(text: &str, name: &str) -> Vec<String> {
    let open = format!("pub struct {name} {{");
    let mut inside = false;
    let mut fields = Vec::new();
    for line in text.lines() {
        if line.trim() == open {
            inside = true;
            continue;
        }
        if inside {
            if line.trim() == "}" {
                break;
            }
            if let Some(rest) = line.trim_start().strip_prefix("pub ") {
                if let Some((field, _)) = rest.split_once(':') {
                    fields.push(field.trim().to_string());
                }
            }
        }
    }
    fields
}

/// The public methods of the `impl <ty> {` blocks of a source.
fn impl_methods(text: &str, ty: &str) -> Vec<String> {
    let open = format!("impl {ty} {{");
    let mut inside = false;
    let mut methods = Vec::new();
    for line in text.lines() {
        if line == open {
            inside = true;
            continue;
        }
        if inside {
            if line == "}" {
                inside = false;
                continue;
            }
            let trimmed = line.trim_start();
            let rest = trimmed
                .strip_prefix("pub const fn ")
                .or_else(|| trimmed.strip_prefix("pub fn "));
            if let Some(rest) = rest {
                let name: String = rest
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                methods.push(name);
            }
        }
    }
    methods
}

/// Every public knob of `Spend`: its setters and `SpendParams`' fields.
fn spend_knobs() -> Vec<String> {
    let mut knobs = Vec::new();
    let mut paths: Vec<String> = fs::read_dir(SPEND_DIR)
        .expect("the spend directory")
        .map(|e| {
            e.expect("an entry")
                .path()
                .to_string_lossy()
                .replace('\\', "/")
        })
        .filter(|p| p.ends_with(".rs") && !is_test_file(p))
        .collect();
    paths.sort();
    for path in &paths {
        let text = normalized(path);
        knobs.extend(public_setters(&text));
        knobs.extend(public_fields(&text, "SpendParams"));
    }
    knobs
}

/// The refusals: a knob with no counterpart and no allowance, a table entry
/// naming no knob, a counterpart the door does not declare.
fn refusals(knobs: &[String], door: &str) -> Vec<String> {
    let mut refused = Vec::new();
    for knob in knobs {
        let mapped = COUNTERPARTS.iter().any(|(k, _, _)| k == knob);
        let allowed = ALLOWED.iter().any(|(k, _)| k == knob);
        if !mapped && !allowed {
            refused.push(format!(
                "`Spend`'s `{knob}` has no counterpart on the door and no allowance"
            ));
        }
    }
    for (knob, ty, method) in COUNTERPARTS {
        if !knobs.iter().any(|k| k == knob) {
            refused.push(format!(
                "COUNTERPARTS names `{knob}`, which `Spend` no longer has"
            ));
        }
        if !impl_methods(door, ty).iter().any(|m| m == method) {
            refused.push(format!(
                "`{ty}::{method}`, the counterpart of `{knob}`, is not declared"
            ));
        }
    }
    for (knob, _) in ALLOWED {
        if !knobs.iter().any(|k| k == knob) {
            refused.push(format!(
                "ALLOWED names `{knob}`, which `Spend` no longer has"
            ));
        }
    }
    refused
}

#[test]
fn every_spend_setter_and_field_has_a_counterpart_on_the_door_855() {
    let knobs = spend_knobs();
    let refused = refusals(&knobs, &normalized(DOOR_FILE));
    assert!(refused.is_empty(), "{}", refused.join("\n"));
    // The reading reached them all: seven setters, thirteen fields.
    let setters = knobs.iter().filter(|k| k.starts_with("set_")).count();
    assert_eq!((setters, knobs.len() - setters), (7, 13), "{knobs:?}");
}

#[test]
fn the_reading_refuses_a_new_setter_a_stale_entry_and_a_missing_counterpart_855() {
    let door = normalized(DOOR_FILE);
    let mut knobs = spend_knobs();
    knobs.push("set_planted".to_string());
    assert_eq!(
        refusals(&knobs, &door),
        ["`Spend`'s `set_planted` has no counterpart on the door and no allowance"]
    );
    let text = "impl Spend {\n    pub fn set_planted(&mut self) {}\n    pub(crate) fn set_hidden(&mut self) {}\n}\n";
    assert_eq!(public_setters(text), ["set_planted"]);
    let knobs: Vec<String> = spend_knobs()
        .into_iter()
        .filter(|k| k != "work_limit")
        .collect();
    assert_eq!(
        refusals(&knobs, &door),
        ["COUNTERPARTS names `work_limit`, which `Spend` no longer has"]
    );
    let door = door.replace(
        "pub const fn with_stack_memory_policy",
        "const fn with_stack_memory_policy",
    );
    assert_eq!(
        refusals(&spend_knobs(), &door),
        ["`NodeFigures::with_stack_memory_policy`, the counterpart of `set_stack_memory_policy`, is not declared"]
    );
}
