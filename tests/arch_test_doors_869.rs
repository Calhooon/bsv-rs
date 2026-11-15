//! No public item under `src/` is built under `cfg(fuzzing)` (#869's
//! second fold, the rule re-read's row). cargo-fuzz sets `--cfg fuzzing` for
//! every crate of a build, a dependent's own fuzz build included, so a
//! public item behind it is callable by anyone who fuzzes against this
//! crate: a test door in the API. The crate's test doors are built under
//! `cfg(any(test, feature = "internal-test-doors"))`, the feature this
//! repository's fuzz crate alone turns on (`fuzz/Cargo.toml`) and which is
//! no part of the API.
//!
//! The rule, lexical, over every `.rs` file under `src/`: an outer `#[cfg(..)]`
//! or `#[cfg_attr(..)]` attribute whose text holds the word `fuzzing` at all
//! (`any(.., fuzzing, feature = "internal-test-doors")` builds the item under
//! `fuzzing` alone; a `not(fuzzing)` is refused too, conservatively: the
//! doors name the feature alone), on an item declared `pub` (the item line
//! after its attributes and comments starts `pub ` or `pub fn`, `pub struct`
//! and the rest; `pub(crate)` and `pub(super)` reach no dependent), is
//! refused naming the file and line; an inner `#![cfg(..)]` of that kind
//! refuses every `pub` line of its file. What it cannot see: a private
//! module behind such a cfg whose `pub` items another module re-exports, a
//! cfg written through a macro.
//!
//! Since #843b the doors themselves are a list: every `pub` item under a
//! cfg naming the `internal-test-doors` feature is one of [`DOORS`], by its
//! file and its name, and carries `#[doc(hidden)]`; a door added, renamed
//! or moved fails until the list moves in the same diff, which a reader
//! sees. Three doors: a transaction given cached bytes, the oracle of
//! `merge_beef`'s verdict, and (#843b) a BEEF holding rows as given, which
//! replaced the hand writes of the public `txs` and `bumps` the unit tests
//! and the fuzz target built their states with.
#![allow(clippy::expect_used, clippy::panic)] // Source reads are test assertions.

mod arch_support;

/// The attribute's whole text from line `at` (it may span lines) and the
/// index of the line after it.
fn attribute(lines: &[&str], at: usize) -> (String, usize) {
    let mut text = String::new();
    let mut depth = 0i32;
    let mut i = at;
    while i < lines.len() {
        for c in lines[i].chars() {
            match c {
                '[' | '(' => depth += 1,
                ']' | ')' => depth -= 1,
                _ => {}
            }
        }
        text.push_str(lines[i]);
        text.push('\n');
        i += 1;
        if depth <= 0 {
            break;
        }
    }
    (text, i)
}

/// The crate's test doors: `(file, function)`, each `pub`, `#[doc(hidden)]`
/// and built under `cfg(any(test, feature = "internal-test-doors"))` alone.
const DOORS: &[(&str, &str)] = &[
    ("src/transaction/beef/rows.rs", "with_rows_for_test"),
    ("src/transaction/beef_writable.rs", "merge_snapshot_oracle"),
    (
        "src/transaction/transaction/fields.rs",
        "with_cached_bytes_for_test",
    ),
];

/// Every `pub` item of `text` under a cfg naming the `internal-test-doors`
/// feature: `(path, name, hidden)`, `hidden` when `#[doc(hidden)]` stands
/// among the attributes between the cfg and the item.
fn doors(path: &str, text: &str) -> Vec<(String, String, bool)> {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i].trim();
        if !line.starts_with("#[cfg") {
            i += 1;
            continue;
        }
        let (attr, next) = attribute(&lines, i);
        i = next;
        if !attr.contains("internal-test-doors") {
            continue;
        }
        let (mut j, mut hidden) = (next, false);
        while j < lines.len() {
            let l = lines[j].trim();
            if l.starts_with("#[") {
                let (other, after) = attribute(&lines, j);
                hidden |= other.split_whitespace().collect::<String>() == "#[doc(hidden)]";
                j = after;
            } else if l.is_empty() || l.starts_with("//") {
                j += 1;
            } else {
                break;
            }
        }
        let Some(item) = lines.get(j).map(|l| l.trim()) else {
            continue;
        };
        if is_pub(item) {
            let name = item
                .split(|c: char| !(c.is_alphanumeric() || c == '_'))
                .skip_while(|w| *w != "fn")
                .nth(1)
                .unwrap_or(item);
            out.push((path.to_string(), name.to_string(), hidden));
        }
    }
    out
}

/// A cfg whose text names `fuzzing`, as a word.
fn names_fuzzing(attr: &str) -> bool {
    attr.split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .any(|w| w == "fuzzing")
}

fn is_pub(line: &str) -> bool {
    line.starts_with("pub ") || line == "pub"
}

/// Every refusal of `text`: `(path, line, item)`.
fn refusals(path: &str, text: &str) -> Vec<(String, usize, String)> {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i].trim();
        let inner = line.starts_with("#![cfg");
        if line.starts_with("#[cfg") || inner {
            let (attr, next) = attribute(&lines, i);
            if names_fuzzing(&attr) {
                if inner {
                    for (k, l) in lines.iter().enumerate() {
                        if is_pub(l.trim()) {
                            out.push((path.to_string(), k + 1, l.trim().to_string()));
                        }
                    }
                    return out;
                }
                // The item after its other attributes and comments.
                let mut j = next;
                while j < lines.len() {
                    let l = lines[j].trim();
                    if l.starts_with("#[") {
                        j = attribute(&lines, j).1;
                    } else if l.is_empty() || l.starts_with("//") {
                        j += 1;
                    } else {
                        break;
                    }
                }
                if let Some(item) = lines.get(j).map(|l| l.trim()) {
                    if is_pub(item) {
                        out.push((path.to_string(), j + 1, item.to_string()));
                    }
                }
            }
            i = next;
            continue;
        }
        i += 1;
    }
    out
}

#[test]
fn no_public_item_is_built_under_cfg_fuzzing_869() {
    let mut found = Vec::new();
    for source in arch_support::sources() {
        found.extend(refusals(&source.path, &source.text));
    }
    assert!(
        found.is_empty(),
        "a public item built under cfg(fuzzing) without the `internal-test-doors` feature: \
         cargo-fuzz sets cfg(fuzzing) for a dependent's build too (#869's second fold):\n{}",
        found
            .iter()
            .map(|(p, l, item)| format!("{p}:{l}: {item}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// The test doors are the listed ones, each hidden from the documentation
/// (#843b).
#[test]
fn the_test_doors_are_the_listed_ones_843b() {
    let mut found = Vec::new();
    for source in arch_support::sources() {
        found.extend(doors(&source.path, &source.text));
    }
    let unhidden: Vec<_> = found.iter().filter(|(_, _, hidden)| !hidden).collect();
    assert!(
        unhidden.is_empty(),
        "a test door without #[doc(hidden)]: {unhidden:?}"
    );
    let mut named: Vec<(&str, &str)> = found
        .iter()
        .map(|(path, name, _)| (path.as_str(), name.as_str()))
        .collect();
    named.sort_unstable();
    assert_eq!(
        named, DOORS,
        "the `pub` items under the `internal-test-doors` feature are not the listed doors: \
         a door is no part of the API, and one added or moved is read before the list moves"
    );
}

/// The doors' reader on a probe: a `pub` item under the feature is found
/// with its name, hidden or not; a crate-private one and one under another
/// cfg are not.
#[test]
fn the_doors_reader_judges_the_probe_843b() {
    let probe = "\
impl Beef {
    #[cfg(any(test, feature = \"internal-test-doors\"))]
    #[doc(hidden)]
    pub fn hidden_door(&self) {}

    #[cfg(any(test, feature = \"internal-test-doors\"))]
    pub fn open_door(&self) {}

    #[cfg(any(test, feature = \"internal-test-doors\"))]
    pub(super) fn crate_only(&self) {}

    #[cfg(test)]
    pub fn a_test_item(&self) {}
}
";
    assert_eq!(
        doors("probe.rs", probe),
        vec![
            ("probe.rs".to_string(), "hidden_door".to_string(), true),
            ("probe.rs".to_string(), "open_door".to_string(), false),
        ]
    );
}

#[test]
fn the_reader_judges_the_probe_869() {
    let probe = "\
impl Beef {
    #[cfg(any(test, fuzzing))]
    #[doc(hidden)]
    /// A door.
    pub fn planted(&self) {}

    #[cfg(
        fuzzing
    )]
    pub(crate) fn crate_only(&self) {}

    #[cfg(any(test, feature = \"internal-test-doors\"))]
    #[doc(hidden)]
    pub fn behind_the_feature(&self) {}

    #[cfg(any(test, fuzzing, feature = \"internal-test-doors\"))]
    pub fn either(&self) {}

    #[cfg(not(fuzzing_like))]
    pub fn another_word(&self) {}

    #[cfg_attr(fuzzing, derive(Debug))]
    pub struct Attr;
}
";
    let found: Vec<usize> = refusals("probe.rs", probe)
        .into_iter()
        .map(|(_, line, _)| line)
        .collect();
    assert_eq!(
        found,
        vec![5, 17, 23],
        "the planted door, `any` with the feature, the cfg_attr item"
    );
    let inner = "#![cfg(fuzzing)]\nmod m {}\npub fn a() {}\nfn b() {}\n";
    assert_eq!(
        refusals("inner.rs", inner).len(),
        1,
        "an inner cfg judges the file"
    );
}
