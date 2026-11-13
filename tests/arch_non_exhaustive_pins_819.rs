//! Every `#[non_exhaustive]` type under `src/` has a pin of the attribute
//! that an addition cannot make stale, or stands on [`LISTED`] with its
//! reason (#819's fold; root `CLAUDE.md` rule 11).
//!
//! The two forms a pin takes:
//!
//! - an enum is defined inside `non_exhaustive_enum!`
//!   (`src/util/non_exhaustive.rs`), which writes the `compile_fail` match
//!   from the definition, one arm per variant and no wildcard, and the same
//!   match with a wildcard arm, which must compile;
//! - a struct's doc carries a `compile_fail` functional update that names no
//!   field (`fn rebuilt(value: T) -> T { T { ..value } }`: with the attribute
//!   no struct expression is allowed outside the crate, without it this one
//!   compiles whatever the fields are, provided each is `pub`, which this
//!   test reads) and a compiling twin naming the same path
//!   (`fn kept(value: T) -> T { value }`); a generic struct
//!   (`pub struct Name<..> {`) is pinned at one instantiation, `T` its path
//!   with the arguments and its `assert_no_drop!` naming them after its
//!   name (#843d8a's fold, `PeerOptions` at `ProtoWallet` and
//!   `MockTransport`: the attribute refuses the update whatever the
//!   arguments are).
//!
//! A hand-written `compile_fail,E0004` match and an `E0639` block of another
//! shape are refused anywhere under `src/`: both go stale at the next variant
//! or field, since stable rustdoc checks no error number.
//!
//! A functional update of a type that implements `Drop` is refused for that
//! reason alone (E0509), with the attribute or without it, so a pinned
//! struct implements no `Drop`: the compiler holds it, in any file the build
//! compiles, by `assert_no_drop!(Name, <pin's path>)`
//! (`src/util/non_exhaustive.rs`, its bounds `::core::ops::Drop` and
//! `::core::marker::Sized` since the fifth fold, so no `use` at a call site
//! changes them),
//! which this test requires after each pinned struct's closing brace (#819's
//! second fold). Since the third fold both macros also make the compiler
//! hold that the pin's path names the type it follows (`bsv_rs` the
//! crate's own name inside it, a function from the type to the path's type:
//! E0308 otherwise),
//! and the macros' own doc tests `include!` the file and apply them to
//! sample types (the exact blocks written for a sample enum, a `Drop` type
//! and a path naming another type refused, the twins compiling); what a
//! sample type cannot show (an arm specialised to one crate type ahead of
//! the general one, the third re-read's fault B) is held by text since the
//! fourth fold: the file pinned whole by [`MACRO_FILE_DIGEST`] and each
//! `macro_rules!` of it to one arm.
//!
//! Against an ordinary change the doc suite's own lines are the evidence
//! that every block exists, ran and passed (the third fold): [`DOC_PINS`] names each pinned type's doc
//! test (held equal to the pins this reader finds), and
//! `the_doc_suite_ran_every_pinned_block_819`, run by CI's step after the doc
//! step on the log that step writes, requires one `compile fail ... ok` line
//! and a plain `... ok` line for each, the macros' own doc tests' lines, no
//! line `FAILED` and a passing result: a block hidden by a fence, a
//! `cfg_attr`, a deleted line or anything else is absent there.
//!
//! The reading is by line, and refuses what it cannot read with certainty: a
//! line of code naming `non_exhaustive` that is not exactly the attribute
//! (`cfg_attr`, an attribute list), an attribute over several lines beside
//! it, an item line that is not `pub enum Name {` or `pub struct Name {`, a
//! variant under `cfg` inside an invocation, a pinned struct's field that is
//! not `pub`, a pinned struct with no `assert_no_drop!` of its name and pin's
//! path after it, two types of one name unless each carries its own pin
//! whose path begins with the top-level module its file lives in (a pin is
//! read from the doc comment directly above its item alone), and in the
//! macro's file an inner attribute, a `cfg_attr`, a `cfg` other than
//! `#[cfg(test)]`, a doc attribute that does not open `#[doc = ` or a block
//! not written by its helper. [`LISTED`] is pinned whole by [`LISTED_KEYS`]:
//! an entry added fails naming itself, an entry removed names the pin to
//! shrink.
//!
//! Since the fourth fold a pinned struct's `compile fail ... ok` line must
//! name the line of its functional update in the source (a block of another
//! reason standing in for a fenced update, the third re-read's row), and a
//! pinned enum's own doc may carry no `compile_fail` text (its block is the
//! one the macro writes; rustdoc numbers a macro-written doc from the
//! invocation, so the enum's line is not matched: a row, a block of another
//! reason reaching an enum's doc by a path other than its own lines, an
//! `include_str!` or a `cfg_attr`, unread).
//!
//! Since the fifth fold every path in the macros' bodies is absolute
//! (`::core::concat!`, `::core::stringify!`, `::core::primitive::str`,
//! `::core::marker::Sized`, `::core::ops::Drop`), and the macro file's code
//! writes no prelude or primitive name alone, not after `::`
//! ([`PRELUDE_NAMES`]; a path not rooted at `::`, such as `core::ops::Drop`,
//! passes that check and is held by [`MACRO_FILE_DIGEST`] alone); `mod util` and `mod non_exhaustive` are each
//! declared once, on the line [`MODULE_DECLARATIONS`] names, with no
//! attribute (as rule 14 holds `mod sealed {`, by the shared
//! `arch_support::attributes_before`); and
//! `tests/arch_ci_runs_every_test.rs` holds the Test Suite job's keys and
//! its two doc-log steps' keys by exact lists.
//!
//! What the machines do not see, besides the rows above (two constructed
//! ways, the fourth re-read's plants 4 and 5):
//!
//! - a `#[doc]` of bare line feeds that shifts rustdoc's numbering, so a
//!   stand-in `compile_fail` block is reported at a fenced functional update's
//!   line;
//! - a `concat!` spelling of the fence word in an enum's own doc beside an
//!   unclosed fence, which swallows the generated block.
//!
//! In both, making the stand-in compile turns its line `FAILED`, which shows
//! the pinned block was not running (the re-read's own observation).
//!
//! The bound:
//!
//! These machines keep a pinned type's attribute, fields and doc from going
//! stale unnoticed by an ordinary change: one made to the type, its fields,
//! its attribute or its doc for a reason of its own. They are not a defence
//! against a change built to defeat them (a pinned text edited together with
//! its pin, a digest with its constant, a doc attribute written to hide or
//! stand in for a block, a doc suite that is not run): such a change is
//! visible in its diff and is a reviewer's matter.
#![allow(clippy::expect_used, clippy::panic)] // Source reads are test assertions.

mod arch_support;

use std::collections::BTreeSet;

const MACRO_FILE: &str = "src/util/non_exhaustive.rs";

/// FNV-1a (64 bits) of [`MACRO_FILE`]'s whole text, line endings normalized
/// (#819's fourth fold, as rule 14 pins `sealed`; the whole text, not its
/// code tokens, since the macros' own doc tests are its comments). Whoever
/// changes the file deliberately reads the change, then sets this to the
/// digest the failure prints, in the same diff.
const MACRO_FILE_DIGEST: u64 = 0x9dce_d5a1_36dd_693d;

use arch_support::fnv;

/// The macro file's text moved from its digest, or a `macro_rules!` of it
/// with other than one arm (an arm specialised to one type ahead of the
/// general one made `assert_no_drop!` vacuous for that type: the third
/// re-read's fault B).
fn macro_file_pin_refusals(text: &str) -> Vec<String> {
    let mut refusals = Vec::new();
    let digest = fnv(text);
    if digest != MACRO_FILE_DIGEST {
        refusals.push(format!(
            "{MACRO_FILE}: its text moved (digest {digest:#018x}, pinned {MACRO_FILE_DIGEST:#018x}): read the change, then move MACRO_FILE_DIGEST in the same diff"
        ));
    }
    let source = arch_support::Source {
        path: MACRO_FILE.into(),
        text: text.into(),
    };
    let tokens = source.raw_tokens();
    let code: Vec<&str> = tokens
        .iter()
        .filter(|t| !t.literal)
        .map(|t| t.text)
        .collect();
    for at in (0..code.len().saturating_sub(3)).filter(|&k| code[k] == "macro_rules") {
        let (name, mut depth, mut arms) = (code[at + 2], 0usize, 0usize);
        for k in at + 3..code.len() {
            match code[k] {
                "(" | "[" | "{" => depth += 1,
                ")" | "]" | "}" => depth -= 1,
                "=" if depth == 1 && code.get(k + 1) == Some(&">") => arms += 1,
                _ => {}
            }
            if depth == 0 {
                break;
            }
        }
        if arms != 1 {
            refusals.push(format!(
                "{MACRO_FILE}: `macro_rules! {name}` has {arms} arms, where one"
            ));
        }
    }
    for (k, token) in tokens.iter().enumerate() {
        let absolute = k >= 2 && tokens[k - 1].text == ":" && tokens[k - 2].text == ":"
            || k >= 1 && tokens[k - 1].text == "::";
        if !token.literal && PRELUDE_NAMES.contains(&token.text) && !absolute {
            refusals.push(format!(
                "{MACRO_FILE}:{}: `{}` is named by a relative path, which a `use` at a call site can change: write `::core::..`",
                token.line, token.text
            ));
        }
    }
    refusals
}

/// Names of the prelude and the primitive types, which a macro body must
/// name by an absolute path (`::core::ops::Drop`), never alone (#819's
/// fifth fold: `assert_no_drop!`'s bare `Drop` resolved at the call site,
/// so a `use std::error::Error as Drop;` beside a pinned struct made the
/// assertion vacuous, the fourth re-read's plant 1). Read over the file's
/// code tokens, comments and literals aside.
const PRELUDE_NAMES: &[&str] = &[
    "Drop",
    "Sized",
    "Send",
    "Sync",
    "Unpin",
    "Copy",
    "Clone",
    "Default",
    "Eq",
    "PartialEq",
    "Ord",
    "PartialOrd",
    "Fn",
    "FnMut",
    "FnOnce",
    "From",
    "Into",
    "TryFrom",
    "TryInto",
    "Iterator",
    "IntoIterator",
    "Option",
    "Some",
    "None",
    "Result",
    "Ok",
    "Err",
    "Box",
    "String",
    "ToString",
    "Vec",
    "AsRef",
    "AsMut",
    "Extend",
    "concat",
    "stringify",
    "include",
    "str",
    "bool",
    "char",
    "u8",
    "u16",
    "u32",
    "u64",
    "u128",
    "usize",
    "i8",
    "i16",
    "i32",
    "i64",
    "i128",
    "isize",
    "f32",
    "f64",
];

/// `file:Type` with no pin yet, each with its reason. The list only shrinks:
/// an entry that is pinned, or names no type, is refused, and its contents
/// are [`LISTED_KEYS`], so an entry added fails naming itself.
const LISTED: &[(&str, &str)] = &[
    (
        "src/error.rs:Error",
        "no pin yet: variants under `cfg(feature)`, whose arms a doc test outside the crate cannot gate",
    ),
    (
        "src/transaction/beef_stream.rs:Stop",
        "no pin yet: the file stands at its ratchet line ceiling and its mutant entries are pinned by line",
    ),
    (
        "src/transaction/beef_stream.rs:Verdict",
        "no pin yet: the file stands at its ratchet line ceiling and its mutant entries are pinned by line",
    ),
    (
        "src/transaction/beef_stream.rs:AsyncVerifyError",
        "no pin yet: the file stands at its ratchet line ceiling and its mutant entries are pinned by line",
    ),
    (
        "src/transaction/spending.rs:InputVerified",
        "no pin yet: the file stands at the ratchet's 800 lines",
    ),
    (
        "src/transaction/spending.rs:InputRefusal",
        "no pin yet: the file stands at the ratchet's 800 lines",
    ),
];

/// [`LISTED`]'s keys, exactly: the list only shrinks, so this pin moves with
/// it by a removal alone.
const LISTED_KEYS: [&str; 6] = [
    "src/error.rs:Error",
    "src/transaction/beef_stream.rs:Stop",
    "src/transaction/beef_stream.rs:Verdict",
    "src/transaction/beef_stream.rs:AsyncVerifyError",
    "src/transaction/spending.rs:InputVerified",
    "src/transaction/spending.rs:InputRefusal",
];

#[derive(Debug, PartialEq, Eq)]
struct Found {
    key: String,
    /// The type's name.
    name: String,
    /// The public path its pin names, when it has one.
    path: Option<String>,
    /// `None` when pinned, else what the reader missed.
    unpinned: Option<String>,
}

fn pinned(key: &str, path: &str) -> Found {
    Found {
        key: key.into(),
        name: key.rsplit(':').next().unwrap_or_default().into(),
        path: Some(path.into()),
        unpinned: None,
    }
}

/// The macro that asserts a pinned struct implements no `Drop` and that its
/// pin's path names it, as the line after the struct's closing brace spells it.
/// A generic struct is named at its pin's instantiation: its name, then the
/// arguments its pin's path carries (#843d8a's fold).
fn no_drop_line(name: &str, path: &str) -> String {
    let arguments = path.find('<').map_or("", |at| &path[at..]);
    format!("crate::util::non_exhaustive::assert_no_drop!({name}{arguments}, {path});")
}

/// The name of a `pub struct` line's item, and whether it declares generic
/// parameters: `PeerOptions<W: WalletInterface, T: Transport>` is
/// `("PeerOptions", true)`.
fn split_generics(declared: &str) -> (&str, bool) {
    match declared.split_once('<') {
        Some((name, rest)) if rest.ends_with('>') => (name, true),
        _ => (declared, false),
    }
}

fn is_attribute(line: &str) -> bool {
    line.trim_start().starts_with("#[")
}

fn is_comment(line: &str) -> bool {
    line.trim_start().starts_with("//")
}

/// The code of a line that still names the attribute once this fold's own
/// identifiers and `Formatter::finish_non_exhaustive` are set aside.
fn names_the_attribute(line: &str) -> bool {
    if is_comment(line) {
        return false;
    }
    line.replace("non_exhaustive_", "")
        .replace("non_exhaustive::", "")
        .replace("mod non_exhaustive;", "")
        .replace("finish_non_exhaustive", "")
        .contains("non_exhaustive")
}

/// The doc text of a head, one string per `///` line.
fn doc_of<'a>(head: &[&'a str]) -> Vec<&'a str> {
    head.iter()
        .filter_map(|line| line.trim_start().strip_prefix("///"))
        .map(|line| line.strip_prefix(' ').unwrap_or(line))
        .collect()
}

fn struct_pin(doc: &[&str], name: &str, generic: bool) -> Result<String, String> {
    let at = doc
        .iter()
        .position(|line| *line == "```compile_fail,E0639")
        .ok_or("no `compile_fail,E0639` functional update in its doc")?;
    let path = doc
        .get(at + 1)
        .and_then(|line| line.strip_prefix("fn rebuilt(value: "))
        .and_then(|rest| rest.split_once(") -> "))
        .and_then(|(path, rest)| (rest == format!("{path} {{")).then_some(path))
        .ok_or("the block does not open `fn rebuilt(value: T) -> T {`")?;
    let base = path.split_once('<').map_or(path, |(base, _)| base);
    if base != name && !base.ends_with(&format!("::{name}")) {
        return Err(format!("the block rebuilds `{path}`, not `{name}`"));
    }
    if generic != (base.len() != path.len()) || generic && !path.ends_with('>') {
        return Err(format!(
            "the block's path `{path}` does not name `{name}` at one instantiation, or names arguments it does not declare"
        ));
    }
    // A generic struct's update names its base path, the arguments inferred
    // from `value`: `Path<A> { ..value }` does not parse as an expression, so
    // its block would fail without the attribute too (the fold's RED).
    let rest = [
        format!("    {base} {{ ..value }}"),
        "}".into(),
        "```".into(),
    ];
    if doc.get(at + 2..at + 5).map(<[&str]>::to_vec)
        != Some(rest.iter().map(String::as_str).collect())
    {
        return Err("the block is not the functional update alone".into());
    }
    let twin = [
        "```".to_string(),
        format!("fn kept(value: {path}) -> {path} {{"),
        "    value".into(),
        "}".into(),
    ];
    if !doc
        .windows(4)
        .any(|window| window.iter().zip(&twin).all(|(a, b)| a == b))
    {
        return Err("no compiling twin `fn kept(value: T) -> T { value }` of the same path".into());
    }
    Ok(path.to_string())
}

/// Every `#[non_exhaustive]` item of one file, and what the reader refuses.
fn judge(path: &str, text: &str) -> (Vec<Found>, Vec<String>) {
    let lines: Vec<&str> = text.lines().collect();
    let mut found = Vec::new();
    let mut refusals = Vec::new();
    let mut refuse = |line: usize, why: &str| refusals.push(format!("{path}:{}: {why}", line + 1));
    for (at, line) in lines.iter().enumerate() {
        if path != MACRO_FILE && line.contains("compile_fail,E0004") {
            refuse(
                at,
                "a `compile_fail,E0004` match written by hand goes stale at the next variant: define the enum in `non_exhaustive_enum!`",
            );
        }
        if line.trim() == "/// ```compile_fail,E0639"
            && !lines
                .get(at + 1)
                .is_some_and(|next| next.trim().starts_with("/// fn rebuilt(value: "))
        {
            refuse(
                at,
                "a `compile_fail,E0639` block that is not the functional update goes stale at the next field",
            );
        }
        if !names_the_attribute(line) {
            continue;
        }
        if line.trim() != "#[non_exhaustive]" {
            refuse(
                at,
                "names `non_exhaustive` in a spelling this reader does not read",
            );
            continue;
        }
        let mut item = at + 1;
        while lines
            .get(item)
            .is_some_and(|l| is_attribute(l) || is_comment(l))
        {
            item += 1;
        }
        let mut start = at;
        while start > 0 && (is_attribute(lines[start - 1]) || is_comment(lines[start - 1])) {
            start -= 1;
        }
        let head = &lines[start..item];
        let cut_above = start > 0 && lines[start - 1].trim_end().ends_with(")]");
        if cut_above
            || head
                .iter()
                .any(|l| is_attribute(l) && !l.trim_end().ends_with(']'))
        {
            refuse(at, "an attribute over several lines beside it");
            continue;
        }
        let declared = lines.get(item).copied().unwrap_or_default();
        let (is_enum, name, generic) = match declared
            .strip_prefix("pub enum ")
            .map(|rest| (true, rest))
            .or_else(|| {
                declared
                    .strip_prefix("pub struct ")
                    .map(|rest| (false, rest))
            })
            .and_then(|(is_enum, rest)| Some((is_enum, rest.strip_suffix(" {")?)))
            .map(|(is_enum, rest)| {
                let (name, generic) = if is_enum {
                    (rest, false)
                } else {
                    split_generics(rest)
                };
                (is_enum, name, generic)
            }) {
            Some((is_enum, name, generic)) if name.chars().all(char::is_alphanumeric) => {
                (is_enum, name, generic)
            }
            _ => {
                refuse(
                    item,
                    "not `pub enum Name {`, `pub struct Name {` or `pub struct Name<..> {` after the attribute",
                );
                continue;
            }
        };
        let end = (item..lines.len())
            .find(|&l| lines[l] == "}")
            .unwrap_or(item);
        let body = &lines[item + 1..end];
        let (unpinned, pin_path) = if is_enum {
            let macro_path = (start >= 2 && lines[start - 2].ends_with("non_exhaustive_enum! {"))
                .then(|| {
                    lines[start - 1]
                        .trim()
                        .strip_prefix("path = ")
                        .and_then(|rest| rest.strip_suffix(';'))
                        .filter(|p| p.starts_with("bsv_rs::"))
                })
                .flatten()
                .filter(|p| *p == name || p.ends_with(&format!("::{name}")));
            if macro_path.is_some() && body.iter().any(|l| l.trim_start().starts_with("#[cfg")) {
                refuse(item, "a variant under `cfg` inside `non_exhaustive_enum!`");
            }
            if macro_path.is_some() && head.iter().any(|l| l.contains("compile_fail")) {
                refuse(
                    item,
                    "a `compile_fail` block in a pinned enum's own doc: its pin's block is the one `non_exhaustive_enum!` writes",
                );
            }
            match macro_path {
                Some(p) => (None, Some(p.to_string())),
                None => (
                    Some("not defined in `non_exhaustive_enum!` under its path".to_string()),
                    None,
                ),
            }
        } else {
            match struct_pin(&doc_of(head), name, generic) {
                Ok(pin_path) => {
                    for (offset, field) in body.iter().enumerate() {
                        let field = field.trim();
                        let skipped = field.is_empty() || is_comment(field) || is_attribute(field);
                        if !skipped && !(field.starts_with("pub ") && field.ends_with(',')) {
                            refuse(
                                item + 1 + offset,
                                "a pinned struct's field that is not `pub`",
                            );
                        }
                    }
                    // The statement after the struct, through its `;`, its
                    // whitespace removed (rustfmt wraps a long one).
                    let mut after = String::new();
                    for line in lines.get(end + 1..).unwrap_or_default() {
                        if after.is_empty() && line.trim().is_empty() {
                            continue;
                        }
                        after.push_str(line);
                        if line.trim_end().ends_with(';')
                            || !line.starts_with("crate::") && after.len() == line.len()
                        {
                            break;
                        }
                    }
                    let spaceless = |text: &str| -> String {
                        text.chars()
                            .filter(|c| !c.is_whitespace())
                            .collect::<String>()
                            .replace(",)", ")")
                    };
                    if spaceless(&after) != spaceless(&no_drop_line(name, &pin_path)) {
                        refuse(
                            end,
                            "a pinned struct not followed by `assert_no_drop!` of its name and its pin's path (a `Drop` impl would make its block pass without the attribute)",
                        );
                    }
                    (None, Some(pin_path))
                }
                Err(why) => (Some(why), None),
            }
        };
        found.push(Found {
            key: format!("{path}:{name}"),
            name: name.to_string(),
            path: pin_path,
            unpinned,
        });
    }
    (found, refusals)
}

/// The top-level module a file under `src/` lives in: `src/block/params.rs`
/// and `src/block.rs` are both `block`'s.
fn top_module(key: &str) -> &str {
    let file = key.split(':').next().unwrap_or_default();
    let rest = file.strip_prefix("src/").unwrap_or(file);
    let first = rest.split('/').next().unwrap_or(rest);
    first.strip_suffix(".rs").unwrap_or(first)
}

/// A pin whose public path begins with its file's top-level module (item 3
/// of #819's third fold: one name, one type). The compiler holds the rest:
/// `assert_no_drop!` and `non_exhaustive_enum!` refuse to build when the
/// path names another type (`src/util/non_exhaustive.rs`).
fn path_in_own_module(item: &Found) -> bool {
    item.path
        .as_deref()
        .is_some_and(|path| path.starts_with(&format!("bsv_rs::{}::", top_module(&item.key))))
}

/// The refusals of a whole tree: the reader's, a type with neither pin nor
/// entry, and an entry that is pinned or names nothing.
fn refusals_of(files: &[(&str, &str)], listed: &[(&str, &str)]) -> (Vec<Found>, Vec<String>) {
    let mut found = Vec::new();
    let mut refusals = Vec::new();
    for (path, text) in files {
        let (mut f, mut r) = judge(path, text);
        found.append(&mut f);
        refusals.append(&mut r);
    }
    let entries: BTreeSet<&str> = listed.iter().map(|(key, _)| *key).collect();
    for item in &found {
        match (&item.unpinned, entries.contains(item.key.as_str())) {
            (Some(why), false) => refusals.push(format!(
                "{}: `#[non_exhaustive]` with no pin and no entry in LISTED ({why})",
                item.key
            )),
            (None, true) => refusals.push(format!(
                "{}: pinned, so its LISTED entry goes (the list only shrinks)",
                item.key
            )),
            _ => {}
        }
    }
    let mut names: Vec<&str> = found.iter().map(|item| item.name.as_str()).collect();
    names.sort_unstable();
    names.dedup();
    for name in names {
        let same: Vec<&Found> = found.iter().filter(|item| item.name == name).collect();
        if same.len() < 2 {
            continue;
        }
        let paths: BTreeSet<Option<&str>> = same.iter().map(|item| item.path.as_deref()).collect();
        let outside: Vec<&str> = same
            .iter()
            .filter(|item| !path_in_own_module(item))
            .map(|item| item.key.as_str())
            .collect();
        if paths.len() != same.len() || paths.contains(&None) || !outside.is_empty() {
            let keys: Vec<&str> = same.iter().map(|item| item.key.as_str()).collect();
            refusals.push(format!(
                "{}: two types named `{name}`, which this reader tells apart only when each carries its own pin whose path begins with the top-level module its file lives in{}",
                keys.join(", "),
                if outside.is_empty() {
                    String::new()
                } else {
                    format!(" (not so: {})", outside.join(", "))
                }
            ));
        }
    }
    for key in entries {
        if !found.iter().any(|item| item.key == key) {
            refusals.push(format!(
                "{key}: a LISTED entry that names no `#[non_exhaustive]` type"
            ));
        }
    }
    (found, refusals)
}

#[test]
fn every_non_exhaustive_type_under_src_has_a_pin_or_a_stated_reason_819() {
    let sources = arch_support::sources();
    let files: Vec<(&str, &str)> = sources
        .iter()
        .map(|source| (source.path.as_str(), source.text.as_str()))
        .collect();
    let (found, refusals) = refusals_of(&files, LISTED);
    assert!(refusals.is_empty(), "{}", refusals.join("\n"));
    let refusals = listed_refusals(LISTED);
    assert!(refusals.is_empty(), "{}", refusals.join("\n"));
    let pinned = found.iter().filter(|item| item.unpinned.is_none()).count();
    assert_eq!(found.len() - pinned, LISTED.len());
    assert!(pinned > 0, "the reader found no pinned type");
    for (key, reason) in LISTED {
        assert!(reason.starts_with("no pin yet: "), "{key}: {reason}");
    }
    println!(
        "{} `#[non_exhaustive]` types: {pinned} pinned, {} listed",
        found.len(),
        LISTED.len()
    );
}

/// [`LISTED`] against [`LISTED_KEYS`]: each entry added named, each pin left
/// over named.
fn listed_refusals(listed: &[(&str, &str)]) -> Vec<String> {
    let keys: Vec<&str> = listed.iter().map(|(key, _)| *key).collect();
    let mut refusals = Vec::new();
    for key in &keys {
        if !LISTED_KEYS.contains(key) {
            refusals.push(format!(
                "{key}: a LISTED entry added; the list only shrinks (pin the type instead)"
            ));
        }
    }
    for key in LISTED_KEYS {
        if !keys.contains(&key) {
            refusals.push(format!(
                "{key}: in LISTED_KEYS and no longer LISTED; remove it from LISTED_KEYS"
            ));
        }
    }
    if keys.len() != LISTED_KEYS.len() && refusals.is_empty() {
        refusals.push(format!(
            "LISTED holds {} entries, LISTED_KEYS {}",
            keys.len(),
            LISTED_KEYS.len()
        ));
    }
    refusals
}

/// The macro file's refusals: a generated block hidden behind a condition,
/// the two blocks not written by their helpers, or an inner attribute (the
/// file's doc tests `include!` it whole, which an inner attribute breaks).
fn macro_file_refusals(text: &str) -> Vec<String> {
    let mut refusals = Vec::new();
    for (at, line) in text.lines().enumerate() {
        let code = line.trim_start();
        let refuse = |why: &str| format!("{MACRO_FILE}:{}: {why}", at + 1);
        if code.starts_with("//!") || code.starts_with("#!") {
            refusals.push(refuse("an inner attribute in the macro's file"));
        }
        if code.starts_with("//") {
            continue;
        }
        if code.contains("cfg_attr") {
            refusals.push(refuse("a `cfg_attr` in the macro's file"));
        } else if code.contains("cfg") && code != "#[cfg(test)]" {
            refusals.push(refuse(
                "a `cfg` other than `#[cfg(test)]` in the macro's file",
            ));
        }
        if code.starts_with('#') && code.contains("doc") && !code.starts_with("#[doc = ") {
            refusals.push(refuse("a doc attribute that does not open `#[doc = `"));
        }
    }
    for helper in ["non_exhaustive_fail_block", "non_exhaustive_twin_block"] {
        let line = format!("#[doc = $crate::util::non_exhaustive::{helper}!(\n");
        let count = text.matches(&line).count();
        if count != 1 {
            refusals.push(format!(
                "{MACRO_FILE}: {count} doc attributes written by `{helper}!`, where the macro writes 1"
            ));
        }
    }
    refusals
}

/// The doc suite's test name of each pinned type's two blocks, as
/// `<file> - <module path>::<Name>` (item 1 of #819's third fold). The list
/// is the pins found under `src/` (the test below holds it so), and each
/// entry must have exactly one `compile fail ... ok` line and at least one
/// plain `... ok` line in the doc suite's log.
const DOC_PINS: [&str; 24] = [
    "src/auth/certificates/certificate.rs - auth::certificates::certificate::Certificate",
    "src/auth/clients/auth_fetch.rs - auth::clients::auth_fetch::AuthFetchOptions",
    "src/auth/peer.rs - auth::peer::PeerOptions",
    "src/auth/transports/websocket_transport.rs - auth::transports::websocket_transport::WebSocketTransportOptions",
    "src/block/activation.rs - block::activation::ActivationHeightsError",
    "src/block/difficulty.rs - block::difficulty::DifficultyError",
    "src/block/params.rs - block::params::ChainParams",
    "src/block/target.rs - block::target::PowError",
    "src/error.rs - error::TransportFault",
    "src/error/wallet_fault.rs - error::wallet_fault::AbortAcceptance",
    "src/error/wallet_fault.rs - error::wallet_fault::AbortKind",
    "src/error/wallet_fault.rs - error::wallet_fault::WalletFault",
    "src/error/wallet_fault.rs - error::wallet_fault::WalletFaultFamily",
    "src/error/wallet_refusal.rs - error::wallet_refusal::WalletRefusalClass",
    "src/identity/types.rs - identity::types::Contact",
    "src/overlay/lookup_limits.rs - overlay::lookup_limits::LookupLimits",
    "src/overlay/lookup_limits.rs - overlay::lookup_limits::LookupRequestOptions",
    "src/script/not_judged.rs - script::not_judged::NotJudgedCause",
    "src/transaction/beef_stream/reason.rs - transaction::beef_stream::reason::Kind",
    "src/transaction/beef_stream/reason.rs - transaction::beef_stream::reason::Reason",
    "src/transaction/chain_tracker.rs - transaction::chain_tracker::ChainTrackerError",
    "src/transaction/work_budget.rs - transaction::work_budget::WorkBudget",
    "src/wallet/hmac_tag.rs - wallet::hmac_tag::HmacKeyEncoding",
    "src/wallet/hmac_tag.rs - wallet::hmac_tag::HmacVerifyPolicy",
];

/// The macros' own doc tests (item 2): the name, its `compile fail ... ok`
/// lines exactly, its plain `... ok` lines at least.
const MACRO_DOC_TESTS: [(&str, usize, usize); 4] = [
    (
        "src/util/non_exhaustive.rs - util::non_exhaustive::assert_no_drop",
        3,
        1,
    ),
    (
        "src/util/non_exhaustive.rs - util::non_exhaustive::non_exhaustive_enum",
        1,
        1,
    ),
    (
        "src/util/non_exhaustive.rs - util::non_exhaustive::non_exhaustive_fail_block",
        0,
        1,
    ),
    (
        "src/util/non_exhaustive.rs - util::non_exhaustive::non_exhaustive_twin_block",
        0,
        1,
    ),
];

/// Another macro's doc tests the suite must run (#904's fourth fold, the row
/// its third fold's re-read left): `wallet_call!`'s hold on a wrong name
/// rests on the two `compile_fail` blocks of `WalletCallMacroDocTests`
/// (`src/lib.rs`, `cfg(all(doctest, feature = "wallet"))`), which an `ignore`
/// on either would silence; its one plain block the macro's compiling twin.
const OTHER_DOC_TESTS: [(&str, usize, usize); 1] = [("src/lib.rs - WalletCallMacroDocTests", 2, 1)];

/// The doc suite's test name of a pin found at `file:Name`.
fn doc_name(key: &str) -> String {
    let (file, name) = key.rsplit_once(':').unwrap_or((key, ""));
    let module = file
        .strip_prefix("src/")
        .and_then(|rest| rest.strip_suffix(".rs"))
        .unwrap_or(file);
    let module = module.strip_suffix("/mod").unwrap_or(module);
    format!("{file} - {}::{name}", module.replace('/', "::"))
}

/// What a doc suite's log lacks: for each name, its `compile fail ... ok`
/// lines exactly and its plain `... ok` lines at least, no line `FAILED`, and
/// the suite's result line `ok`.
fn doc_log_refusals(log: &str, wanted: &[(String, usize, usize)]) -> Vec<String> {
    let mut refusals = Vec::new();
    let mut counts: std::collections::BTreeMap<&str, (usize, usize)> = Default::default();
    for line in log.lines() {
        let Some(rest) = line.trim_end().strip_prefix("test ") else {
            continue;
        };
        if rest.ends_with(" ... FAILED") {
            refusals.push(format!("a doc test failed: {rest}"));
            continue;
        }
        let Some(rest) = rest.strip_suffix(" ... ok") else {
            continue;
        };
        let Some((name, tail)) = rest.split_once(" (line ") else {
            continue;
        };
        let entry = counts.entry(name).or_default();
        if tail.ends_with(") - compile fail") {
            entry.0 += 1;
        } else if tail.ends_with(')') {
            entry.1 += 1;
        }
    }
    if !log
        .lines()
        .any(|line| line.starts_with("test result: ok.") && line.contains(" passed;"))
    {
        refusals.push("no `test result: ok.` line: not a passing doc suite's log".into());
    }
    for (name, compile_fail, plain) in wanted {
        let (found_fail, found_plain) = counts.get(name.as_str()).copied().unwrap_or_default();
        if found_fail != *compile_fail {
            refusals.push(format!(
                "{name}: {found_fail} `compile fail ... ok` lines in the doc suite, where {compile_fail} must run"
            ));
        }
        if found_plain < *plain {
            refusals.push(format!(
                "{name}: {found_plain} plain `... ok` lines in the doc suite, where at least {plain} must run"
            ));
        }
    }
    refusals
}

/// Each pinned struct's doc test name and the source line of its
/// `compile_fail,E0639` block, the line rustdoc names in the log (#819's
/// fourth fold).
fn struct_fail_lines(files: &[(&str, &str)]) -> Vec<(String, usize)> {
    let mut out = Vec::new();
    for (path, text) in files {
        let lines: Vec<&str> = text.lines().collect();
        for (at, line) in lines.iter().enumerate() {
            if line.trim() != "/// ```compile_fail,E0639" {
                continue;
            }
            let name = lines[at..].iter().find_map(|l| {
                l.strip_prefix("pub struct ")
                    .and_then(|rest| rest.strip_suffix(" {"))
                    .map(|rest| split_generics(rest).0)
            });
            if let Some(name) = name {
                out.push((doc_name(&format!("{path}:{name}")), at + 1));
            }
        }
    }
    out
}

/// A pinned struct's `compile fail ... ok` line that names another line than
/// its functional update's: a block of another reason standing in for it
/// (the update hidden behind a fence, a bare `compile_fail` beside it).
fn fail_line_refusals(log: &str, wanted: &[(String, usize)]) -> Vec<String> {
    let mut refusals = Vec::new();
    for (name, line) in wanted {
        let prefix = format!("test {name} (line ");
        for found in log.lines().filter_map(|l| {
            l.trim_end()
                .strip_prefix(&prefix)?
                .strip_suffix(") - compile fail ... ok")
        }) {
            if found != line.to_string() {
                refusals.push(format!(
                    "{name}: its `compile fail` line is the block at line {found}, where its functional update is at line {line}"
                ));
            }
        }
    }
    refusals
}

/// Every name the doc suite's log must carry.
fn doc_wanted() -> Vec<(String, usize, usize)> {
    DOC_PINS
        .iter()
        .map(|name| ((*name).to_string(), 1, 1))
        .chain(
            MACRO_DOC_TESTS
                .iter()
                .chain(OTHER_DOC_TESTS.iter())
                .map(|(name, fail, plain)| ((*name).to_string(), *fail, *plain)),
        )
        .collect()
}

#[test]
fn the_doc_pins_are_every_pinned_type_found_under_src_819() {
    let sources = arch_support::sources();
    let files: Vec<(&str, &str)> = sources
        .iter()
        .map(|source| (source.path.as_str(), source.text.as_str()))
        .collect();
    let (found, _) = refusals_of(&files, LISTED);
    let derived: BTreeSet<String> = found
        .iter()
        .filter(|item| item.unpinned.is_none())
        .map(|item| doc_name(&item.key))
        .collect();
    let listed: BTreeSet<String> = DOC_PINS.iter().map(|name| (*name).to_string()).collect();
    assert_eq!(listed.len(), DOC_PINS.len(), "DOC_PINS repeats a name");
    assert_eq!(
        derived.difference(&listed).collect::<Vec<_>>(),
        Vec::<&String>::new(),
        "pinned types missing from DOC_PINS"
    );
    assert_eq!(
        listed.difference(&derived).collect::<Vec<_>>(),
        Vec::<&String>::new(),
        "DOC_PINS entries that name no pinned type"
    );
}

/// Item 1 of #819's third fold: the doc suite's own lines are the evidence
/// that each pinned type's blocks exist, ran and passed. Run by CI's step
/// after the doc step, on the log that step writes (`ci.yml`, pinned by
/// `tests/arch_ci_runs_every_test.rs`); by hand,
/// `cargo test --doc --all-features > doc.log 2>&1` then
/// `BSV_DOC_SUITE_LOG=doc.log cargo test --all-features --test arch_non_exhaustive_pins_819 -- --ignored`.
#[test]
#[ignore = "reads the doc suite's log, BSV_DOC_SUITE_LOG; CI's step after the doc step runs it"]
fn the_doc_suite_ran_every_pinned_block_819() {
    let path = std::env::var("BSV_DOC_SUITE_LOG")
        .expect("BSV_DOC_SUITE_LOG names the log of `cargo test --doc --all-features`");
    let log = std::fs::read_to_string(&path).expect("the doc suite's log");
    let wanted = doc_wanted();
    let mut refusals = doc_log_refusals(&log, &wanted);
    let sources = arch_support::sources();
    let files: Vec<(&str, &str)> = sources
        .iter()
        .map(|source| (source.path.as_str(), source.text.as_str()))
        .collect();
    refusals.extend(fail_line_refusals(&log, &struct_fail_lines(&files)));
    assert!(refusals.is_empty(), "{}", refusals.join("\n"));
    println!("{} doc test names read in {path}", wanted.len());
}

#[test]
fn a_pinned_structs_compile_fail_line_is_its_functional_updates_819() {
    let sources = arch_support::sources();
    let files: Vec<(&str, &str)> = sources
        .iter()
        .map(|source| (source.path.as_str(), source.text.as_str()))
        .collect();
    let lines = struct_fail_lines(&files);
    let work = "src/transaction/work_budget.rs - transaction::work_budget::WorkBudget";
    assert!(
        lines
            .iter()
            .all(|(name, _)| DOC_PINS.contains(&name.as_str())),
        "{lines:?}"
    );
    let at = lines
        .iter()
        .find(|(name, _)| name == work)
        .map(|(_, at)| *at);
    let at = at.expect("WorkBudget's block found");
    let log = |line: usize| format!("test {work} (line {line}) - compile fail ... ok\n");
    assert_eq!(fail_line_refusals(&log(at), &lines), Vec::<String>::new());
    // the third re-read's row: the update fenced as text, a bare
    // `compile_fail` block of another reason further down
    assert_eq!(
        fail_line_refusals(&log(at + 13), &lines),
        [format!(
            "{work}: its `compile fail` line is the block at line {}, where its functional update is at line {at}",
            at + 13
        )]
    );
}

#[test]
fn the_macro_file_is_pinned_whole_and_each_macro_has_one_arm_819() {
    let text = arch_support::read(MACRO_FILE);
    assert_eq!(macro_file_pin_refusals(&text), Vec::<String>::new());
    let general =
        "macro_rules! assert_no_drop {\n    ($name:ident $(< $($arg:ty),+ >)?, $path:path) => {";
    assert!(text.contains(general));
    // the third re-read's fault B: an arm for one type ahead of the general one
    let specialised = text.replacen(
        general,
        "macro_rules! assert_no_drop {\n    (LookupRequestOptions, $path:path) => {};\n    ($name:ident $(< $($arg:ty),+ >)?, $path:path) => {",
        1,
    );
    // the second fold's two vacuous macros: the body emptied, a unit body
    let body_start = text.find(general).expect("the macro") + general.len();
    let body_end = body_start + text[body_start..].find("\n    };\n}").expect("its end");
    let emptied = format!("{}{}", &text[..body_start], &text[body_end..]);
    let unit = format!(
        "{}\n        const _: () = ();{}",
        &text[..body_start],
        &text[body_end..]
    );
    // the fourth re-read's plant 1: a bound back on a relative `Drop`
    let relative = text.replacen("+ ::core::ops::Drop>", "+ Drop>", 1);
    assert_ne!(relative, text);
    assert!(macro_file_pin_refusals(&relative)
        .iter()
        .any(|r| r.ends_with("`Drop` is named by a relative path, which a `use` at a call site can change: write `::core::..`")));
    for (plant, arms) in [(&specialised, Some(2)), (&emptied, None), (&unit, None)] {
        assert_ne!(plant, &text);
        let refusals = macro_file_pin_refusals(plant);
        assert!(
            refusals
                .iter()
                .any(|r| r.starts_with(&format!("{MACRO_FILE}: its text moved"))),
            "{refusals:?}"
        );
        if let Some(arms) = arms {
            assert!(
                refusals.iter().any(|r| r.ends_with(&format!(
                    "`macro_rules! assert_no_drop` has {arms} arms, where one"
                ))),
                "{refusals:?}"
            );
        }
    }
}

/// The two declarations the pinned file is compiled through, each with the
/// file that holds it and its one line (#819's fifth fold, as rule 14 holds
/// `mod sealed {` in `tests/arch_field_writes_843.rs`, by the same helper,
/// `arch_support::attributes_before`).
const MODULE_DECLARATIONS: [(&str, &str, &str); 2] = [
    ("util", "src/lib.rs", "pub(crate) mod util;"),
    (
        "non_exhaustive",
        "src/util/mod.rs",
        "pub(crate) mod non_exhaustive;",
    ),
];

/// [`MACRO_FILE`] is the file the crate compiles: `mod util` and
/// `mod non_exhaustive` are each declared once under `src/`, in the file and
/// on the line [`MODULE_DECLARATIONS`] names, with no attribute (a
/// `#[path]` or a `cfg_attr(.., path = ..)` over either would compile
/// another file while the pinned one and its digest stood unchanged: the
/// fourth re-read's plant 2).
fn module_declaration_refusals(sources: &[arch_support::Source]) -> Vec<String> {
    let mut errors = Vec::new();
    for (name, file, line) in MODULE_DECLARATIONS {
        let mut found = Vec::new();
        for source in sources {
            let tokens = source.raw_tokens();
            for k in 0..tokens.len().saturating_sub(2) {
                if tokens[k].literal || tokens[k].text != "mod" || tokens[k + 1].text != name {
                    continue;
                }
                let at = format!("{}:{}", source.path, tokens[k].line);
                found.push(at.clone());
                let attributes = arch_support::attributes_before(&tokens, k);
                if source.path != file
                    || tokens[k + 2].text != ";"
                    || !attributes.is_empty()
                    || source.line(tokens[k].line) != line
                {
                    errors.push(format!(
                        "{at}: `mod {name}` must be `{line}` on a line of its own in {file} with no attribute (found {attributes:?}): this rule reads {MACRO_FILE}"
                    ));
                }
            }
        }
        if found.len() != 1 {
            errors.push(format!(
                "`mod {name}` declared {} times under src/ ({}): exactly once",
                found.len(),
                found.join(", ")
            ));
        }
    }
    errors
}

#[test]
fn the_macro_files_module_is_declared_once_with_no_attribute_819() {
    let sources = arch_support::sources();
    assert_eq!(module_declaration_refusals(&sources), Vec::<String>::new());
    let at = |path: &str| {
        sources
            .iter()
            .position(|s| s.path == path)
            .expect("the declaring file")
    };
    let (lib, util) = (at("src/lib.rs"), at("src/util/mod.rs"));
    let declaration = "pub(crate) mod non_exhaustive;";
    let plants = [
        // the fourth re-read's plant 2
        (
            util,
            declaration,
            "#[cfg_attr(not(doctest), path = \"ne_alt.rs\")]\npub(crate) mod non_exhaustive;",
            "with no attribute (found [\"cfg_attr ( not ( doctest ) , path = \\\"ne_alt.rs\\\" )\"])",
        ),
        (
            util,
            declaration,
            "#[path = \"ne_alt.rs\"]\npub(crate) mod non_exhaustive;",
            "with no attribute (found [\"path = \\\"ne_alt.rs\\\"\"])",
        ),
        (
            util,
            declaration,
            "pub(crate) mod non_exhaustive;\n#[cfg(test)]\nmod non_exhaustive;",
            "declared 2 times under src/",
        ),
        (
            util,
            declaration,
            "pub(crate) mod non_exhaustive { include!(\"ne_alt.rs\"); }",
            "on a line of its own in src/util/mod.rs",
        ),
        (
            lib,
            "pub(crate) mod util;",
            "#[path = \"util2/mod.rs\"]\npub(crate) mod util;",
            "`mod util` must be `pub(crate) mod util;`",
        ),
    ];
    for (file, from, to, words) in plants {
        let mut planted: Vec<arch_support::Source> = sources
            .iter()
            .map(|s| arch_support::Source {
                path: s.path.clone(),
                text: s.text.clone(),
            })
            .collect();
        assert!(planted[file].text.contains(from));
        planted[file].text = planted[file].text.replacen(from, to, 1);
        let refusals = module_declaration_refusals(&planted);
        assert!(
            refusals.iter().any(|r| r.contains(words)),
            "{to}: {refusals:?}"
        );
    }
}

#[test]
fn a_doc_log_missing_a_pin_line_is_refused_naming_it_819() {
    let wanted = doc_wanted();
    let mut log = String::new();
    for (name, fail, plain) in &wanted {
        for line in 0..*fail {
            log.push_str(&format!(
                "test {name} (line {line}) - compile fail ... ok\n"
            ));
        }
        for line in 0..*plain {
            log.push_str(&format!("test {name} (line {}) ... ok\n", 100 + line));
        }
    }
    let result = "\ntest result: ok. 367 passed; 0 failed; 128 ignored; 0 measured; 0 filtered out; finished in 9.02s\n";
    assert_eq!(
        doc_log_refusals(&format!("{log}{result}"), &wanted),
        Vec::<String>::new()
    );
    // A fence or a `cfg_attr` hides an enum's two blocks: both lines absent.
    let kind = "src/transaction/beef_stream/reason.rs - transaction::beef_stream::reason::Kind";
    let hidden: String = log
        .lines()
        .filter(|line| !line.contains(kind))
        .map(|line| format!("{line}\n"))
        .collect();
    let refusals = doc_log_refusals(&format!("{hidden}{result}"), &wanted);
    assert_eq!(refusals.len(), 2, "{refusals:?}");
    assert!(refusals.iter().all(|r| r.starts_with(kind)), "{refusals:?}");
    // A deleted `compile_fail` block alone.
    let work = "src/transaction/work_budget.rs - transaction::work_budget::WorkBudget";
    let deleted = log.replace(&format!("test {work} (line 0) - compile fail ... ok\n"), "");
    assert_eq!(
        doc_log_refusals(&format!("{deleted}{result}"), &wanted),
        [format!(
            "{work}: 0 `compile fail ... ok` lines in the doc suite, where 1 must run"
        )]
    );
    // A vacuous `assert_no_drop!`: its `compile_fail` block compiles, so FAILED.
    let line = "test src/util/non_exhaustive.rs - util::non_exhaustive::assert_no_drop (line 0) - compile fail ... ";
    let vacuous = log.replace(&format!("{line}ok"), &format!("{line}FAILED"));
    let refusals = doc_log_refusals(&format!("{vacuous}{result}"), &wanted);
    assert!(
        refusals.iter().any(|r| r.starts_with("a doc test failed")),
        "{refusals:?}"
    );
    // No result line: not a doc suite that passed.
    assert_eq!(
        doc_log_refusals(&log, &wanted),
        ["no `test result: ok.` line: not a passing doc suite's log"]
    );
}

#[test]
fn a_generated_block_hidden_behind_a_condition_is_refused_819() {
    let text = arch_support::read(MACRO_FILE);
    assert_eq!(macro_file_refusals(&text), Vec::<String>::new());
    let line = "#[doc = $crate::util::non_exhaustive::non_exhaustive_fail_block!(";
    let hidden = text.replacen(
        line,
        "#[cfg_attr(any(), doc = $crate::util::non_exhaustive::non_exhaustive_fail_block!(",
        1,
    );
    let refusals = macro_file_refusals(&hidden);
    assert!(
        refusals.iter().any(|r| r.contains("`cfg_attr`")),
        "{refusals:?}"
    );
    assert!(
        refusals
            .iter()
            .any(|r| r.contains("0 doc attributes written by `non_exhaustive_fail_block!`")),
        "{refusals:?}"
    );
    let gated = text.replacen(
        &format!("        {line}"),
        &format!("        #[cfg(any())]\n        {line}"),
        1,
    );
    assert!(macro_file_refusals(&gated)
        .iter()
        .any(|r| r.contains("a `cfg` other than")));
    let inner = format!("//! A module doc.\n{text}");
    assert!(macro_file_refusals(&inner)
        .iter()
        .any(|r| r.contains("an inner attribute")));
}

const ENUM_PINNED: &str = "crate::util::non_exhaustive::non_exhaustive_enum! {
    path = bsv_rs::sample::Sample;
/// A sample.
#[derive(Debug)]
#[non_exhaustive]
pub enum Sample {
    /// One.
    One,
}
}
";

const STRUCT_PINNED: &str = "/// A sample.
///
/// ```compile_fail,E0639
/// fn rebuilt(value: bsv_rs::sample::Record) -> bsv_rs::sample::Record {
///     bsv_rs::sample::Record { ..value }
/// }
/// ```
///
/// ```
/// fn kept(value: bsv_rs::sample::Record) -> bsv_rs::sample::Record {
///     value
/// }
/// ```
#[derive(Debug)]
#[non_exhaustive]
pub struct Record {
    /// One.
    pub one: u8,
}

crate::util::non_exhaustive::assert_no_drop!(Record, bsv_rs::sample::Record);
";

const GENERIC_PINNED: &str = "/// A sample.
///
/// ```compile_fail,E0639
/// fn rebuilt(value: bsv_rs::sample::Pair<u8>) -> bsv_rs::sample::Pair<u8> {
///     bsv_rs::sample::Pair { ..value }
/// }
/// ```
///
/// ```
/// fn kept(value: bsv_rs::sample::Pair<u8>) -> bsv_rs::sample::Pair<u8> {
///     value
/// }
/// ```
#[non_exhaustive]
pub struct Pair<A: Copy> {
    /// One.
    pub one: A,
}

crate::util::non_exhaustive::assert_no_drop!(Pair<u8>, bsv_rs::sample::Pair<u8>);
";

/// #843d8a's fold: a generic struct pinned at one instantiation is read as
/// pinned; its path without the arguments, arguments on a struct that
/// declares none, an update naming the arguments (no expression, so it
/// fails to compile with the attribute or without it) and an
/// `assert_no_drop!` without them are refused.
#[test]
fn a_generic_struct_is_pinned_at_one_instantiation_843d8a() {
    let (found, refusals) = one(GENERIC_PINNED);
    assert_eq!(refusals, Vec::<String>::new());
    assert_eq!(
        found,
        [pinned("src/sample.rs:Pair", "bsv_rs::sample::Pair<u8>")]
    );
    let unpinned = |text: &str, needle: &str| {
        let (found, refusals) = one(text);
        assert!(
            found.iter().all(|item| item.unpinned.is_some())
                && refusals.iter().any(|r| r.contains(needle)),
            "{needle}: {found:?} {refusals:?}"
        );
    };
    unpinned(
        &GENERIC_PINNED.replace("bsv_rs::sample::Pair<u8>", "bsv_rs::sample::Pair"),
        "at one instantiation",
    );
    unpinned(
        &GENERIC_PINNED.replace("pub struct Pair<A: Copy> {", "pub struct Pair {"),
        "at one instantiation",
    );
    unpinned(
        &GENERIC_PINNED.replace(
            "bsv_rs::sample::Pair { ..value }",
            "bsv_rs::sample::Pair<u8> { ..value }",
        ),
        "not the functional update alone",
    );
    let (_, refusals) =
        one(&GENERIC_PINNED.replace("assert_no_drop!(Pair<u8>,", "assert_no_drop!(Pair,"));
    assert!(
        refusals
            .iter()
            .any(|r| r.contains("not followed by `assert_no_drop!`")),
        "{refusals:?}"
    );
}

fn one(text: &str) -> (Vec<Found>, Vec<String>) {
    refusals_of(&[("src/sample.rs", text)], &[])
}

#[test]
fn the_two_pinned_forms_are_read_as_pinned_819() {
    let (found, refusals) = one(ENUM_PINNED);
    assert_eq!(refusals, Vec::<String>::new());
    assert_eq!(
        found,
        [pinned("src/sample.rs:Sample", "bsv_rs::sample::Sample")]
    );
    let (found, refusals) = one(STRUCT_PINNED);
    assert_eq!(refusals, Vec::<String>::new());
    assert_eq!(
        found,
        [pinned("src/sample.rs:Record", "bsv_rs::sample::Record")]
    );
}

#[test]
fn each_unpinned_or_unreadable_form_is_refused_naming_its_line_819() {
    let refused = |text: &str, needle: &str| {
        let (_, refusals) = one(text);
        assert!(
            refusals
                .iter()
                .any(|r| r.starts_with("src/sample.rs:") && r.contains(needle)),
            "{needle}: {refusals:?}"
        );
    };
    // An enum outside the macro, and a struct with no block.
    let bare = ENUM_PINNED
        .replace("crate::util::non_exhaustive::non_exhaustive_enum! {\n", "")
        .replace("    path = bsv_rs::sample::Sample;\n", "");
    refused(&bare, "no pin and no entry");
    refused(
        "#[non_exhaustive]\npub struct Record {\n    pub one: u8,\n}\n",
        "no `compile_fail,E0639`",
    );
    // The macro's path naming another type.
    refused(
        &ENUM_PINNED.replace("bsv_rs::sample::Sample", "bsv_rs::sample::Other"),
        "no pin and no entry",
    );
    // A block of another reason in a pinned enum's own doc (#819's fourth
    // fold: it would stand in for the generated block hidden by a fence).
    refused(
        &ENUM_PINNED.replace(
            "/// A sample.\n",
            "/// A sample.\n///\n/// ```compile_fail\n/// let x: u8 = \"\";\n/// ```\n",
        ),
        "a `compile_fail` block in a pinned enum's own doc",
    );
    // A hand-written match, wherever it stands.
    refused(
        "/// ```compile_fail,E0004\n/// ```\npub fn f() {}\n",
        "written by hand",
    );
    // The every-field literal.
    refused(
        &STRUCT_PINNED.replace(
            "/// fn rebuilt(value: bsv_rs::sample::Record) -> bsv_rs::sample::Record {",
            "/// let _ = bsv_rs::sample::Record { one: 1 };",
        ),
        "not the functional update",
    );
    // A functional update that names a field, another type, or has no twin.
    refused(
        &STRUCT_PINNED.replace("{ ..value }", "{ one: 1, ..value }"),
        "functional update alone",
    );
    refused(
        &STRUCT_PINNED.replace("pub struct Record {", "pub struct Other {"),
        "not `Other`",
    );
    refused(
        &STRUCT_PINNED.replace("///     value\n", "///     todo!()\n"),
        "no compiling twin",
    );
    // A field that is not `pub`, a `Drop` impl, a variant under `cfg`.
    refused(
        &STRUCT_PINNED.replace("    pub one: u8,", "    one: u8,"),
        "field that is not `pub`",
    );
    refused(
        &STRUCT_PINNED.replace("    pub one: u8,", "    pub(crate) one: u8,"),
        "field that is not `pub`",
    );
    refused(
        &STRUCT_PINNED.replace(
            "crate::util::non_exhaustive::assert_no_drop!(Record, bsv_rs::sample::Record);\n",
            "",
        ),
        "not followed by `assert_no_drop!`",
    );
    refused(
        &STRUCT_PINNED.replace("assert_no_drop!(Record, ", "assert_no_drop!(Other, "),
        "not followed by `assert_no_drop!`",
    );
    refused(
        &ENUM_PINNED.replace("    /// One.\n", "    #[cfg(test)]\n"),
        "variant under `cfg`",
    );
    // Spellings the reader does not read.
    refused(
        &ENUM_PINNED.replace("#[non_exhaustive]", "#[cfg_attr(all(), non_exhaustive)]"),
        "spelling",
    );
    refused(
        &ENUM_PINNED.replace(
            "#[derive(Debug)]\n#[non_exhaustive]",
            "#[derive(Debug), non_exhaustive]",
        ),
        "spelling",
    );
    refused(
        &ENUM_PINNED.replace("#[derive(Debug)]", "#[derive(\n    Debug)]"),
        "several lines",
    );
    refused(
        &ENUM_PINNED.replace("pub enum Sample {", "pub enum Sample<T> {"),
        "not `pub enum Name {`",
    );
    refused(
        &ENUM_PINNED.replace("pub enum Sample {", "pub(crate) enum Sample {"),
        "not `pub enum Name {`",
    );
}

#[test]
fn a_listed_entry_that_is_pinned_or_names_nothing_is_refused_819() {
    let listed = [("src/sample.rs:Sample", "no pin yet: a sample")];
    let (_, refusals) = refusals_of(&[("src/sample.rs", ENUM_PINNED)], &listed);
    assert_eq!(refusals.len(), 1, "{refusals:?}");
    assert!(refusals[0].contains("the list only shrinks"));
    let (_, refusals) = refusals_of(&[("src/sample.rs", "")], &listed);
    assert_eq!(refusals.len(), 1, "{refusals:?}");
    assert!(refusals[0].contains("names no `#[non_exhaustive]` type"));
    let bare = "#[non_exhaustive]\npub enum Sample {\n    One,\n}\n";
    let (found, refusals) = refusals_of(&[("src/sample.rs", bare)], &listed);
    assert_eq!(refusals, Vec::<String>::new());
    assert_eq!(found.len(), 1);
    assert!(found[0].unpinned.is_some());
}

#[test]
fn two_types_of_one_name_are_read_only_when_each_carries_its_own_path_819() {
    let twin = STRUCT_PINNED.replace("bsv_rs::sample::Record", "bsv_rs::other::Record");
    let (found, refusals) = refusals_of(
        &[("src/sample.rs", STRUCT_PINNED), ("src/other.rs", &twin)],
        &[],
    );
    assert_eq!(refusals, Vec::<String>::new());
    assert_eq!(found.len(), 2);
    // A twin in another top-level module's file whose pin's path begins in
    // another module (#819's third fold, item 3): a path through a re-export,
    // which the compiler refuses too (`assert_no_drop!`'s type identity).
    let elsewhere = STRUCT_PINNED.replace("bsv_rs::sample::Record", "bsv_rs::elsewhere::Record");
    let (_, refusals) = refusals_of(
        &[
            ("src/sample.rs", STRUCT_PINNED),
            ("src/other/x.rs", &elsewhere),
        ],
        &[],
    );
    assert_eq!(
        refusals,
        ["src/sample.rs:Record, src/other/x.rs:Record: two types named `Record`, which this reader tells apart only when each carries its own pin whose path begins with the top-level module its file lives in (not so: src/other/x.rs:Record)"]
    );
    // The crate root is no top-level module: a twin pinned there is refused.
    let root = STRUCT_PINNED.replace("bsv_rs::sample::Record", "bsv_rs::Record");
    let (_, refusals) = refusals_of(
        &[("src/sample.rs", STRUCT_PINNED), ("src/other.rs", &root)],
        &[],
    );
    assert_eq!(refusals.len(), 1, "{refusals:?}");
    assert!(
        refusals[0].ends_with("(not so: src/other.rs:Record)"),
        "{refusals:?}"
    );
    // One type of a name may be pinned at the crate root.
    let (_, refusals) = one(&root);
    assert_eq!(refusals, Vec::<String>::new());
    // The second type's pin names the first's path (the re-read's plant).
    let (_, refusals) = refusals_of(
        &[
            ("src/sample.rs", STRUCT_PINNED),
            ("src/other.rs", STRUCT_PINNED),
        ],
        &[],
    );
    assert_eq!(refusals.len(), 1, "{refusals:?}");
    assert!(
        refusals[0].contains("two types named `Record`"),
        "{refusals:?}"
    );
    // One pinned, one listed with no pin.
    let bare = "#[non_exhaustive]\npub struct Record {\n    pub one: u8,\n}\n";
    let (_, refusals) = refusals_of(
        &[("src/sample.rs", STRUCT_PINNED), ("src/other.rs", bare)],
        &[("src/other.rs:Record", "no pin yet: a sample")],
    );
    assert_eq!(refusals.len(), 1, "{refusals:?}");
    assert!(
        refusals[0].contains("two types named `Record`"),
        "{refusals:?}"
    );
    // A pin away from its item, below a blank line, is no pin of it.
    let apart = STRUCT_PINNED.replace("/// ```\n#[derive(Debug)]", "/// ```\n\n#[derive(Debug)]");
    let (found, _) = one(&apart);
    assert!(found[0].unpinned.is_some(), "{found:?}");
}

#[test]
fn the_listed_entries_are_pinned_by_name_so_an_addition_names_itself_819() {
    assert_eq!(listed_refusals(LISTED), Vec::<String>::new());
    let mut grown = LISTED.to_vec();
    grown.push(("src/sample.rs:Sample", "no pin yet: a sample"));
    assert_eq!(
        listed_refusals(&grown),
        ["src/sample.rs:Sample: a LISTED entry added; the list only shrinks (pin the type instead)"]
    );
    let shrunk = &LISTED[1..];
    let refusals = listed_refusals(shrunk);
    assert_eq!(refusals.len(), 1, "{refusals:?}");
    assert!(refusals[0].starts_with("src/error.rs:Error: in LISTED_KEYS"));
}
