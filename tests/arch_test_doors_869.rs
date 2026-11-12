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
