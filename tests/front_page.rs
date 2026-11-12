//! The README's first screen says why to choose this crate, and every sentence of it is worked
//! out again from its producer in the tree (the front-page lane, three design reads of
//! 2026-11-11: D1 to D6).
//!
//! The README ships inside every published crate and is frozen there: crates.io's page for 0.8.6
//! read "0.7.1" and `=0.7.1` through seven releases. So the text before `## Examples` names no
//! version; the install line is `cargo add` without one; each factual sentence of the first screen
//! (everything before `## Install`) carries a marker, `<!-- F1 -->` and on, and the marker's
//! producer below reads the tree ON THIS LINE and says what the sentence may say (its numbers, its
//! names). A sentence whose producer this line lacks fails here, so it is absent from this line's
//! README with its producer (D3); a number on the first screen without a marker fails; a marker
//! without a producer fails; a producer whose marker is absent from the first screen, or a marker
//! written twice (on two lines or one), fails (#883's third fold). Every relative link and anchor
//! of the first screen resolves, and the front files exist. No network and no environment: the
//! files of the tree alone, as `readme_examples.rs`.
//!
//! What F7's `cargo publish` detector finds and what it does not (`runs_cargo_publish`): it reads
//! every workflow, every script under `.github/scripts/` (fixtures aside), every composite action
//! (`action.yml`, `action.yaml` under `.github/actions/`, none today) and every file of the tree a
//! line of those names; it finds `cargo`, any words that begin with `-` or `+`, `publish`. Not
//! found, stated: the command held in a variable (`C=cargo; $C publish`), a script reached by
//! `cd <dir> && ./<script>` outside the scanned folders, an option whose value is a word of its
//! own between `cargo` and `publish` (`cargo --config <k=v> publish`, `cargo -Z <flag> publish`,
//! `cargo --color always publish`; `--config=<k=v>` is found) and a command split by a line
//! continuation (`cargo \` then `publish` on the next line: a line is read alone). None can
//! publish: no workflow but `release.yml` can obtain a registry token (`stored_token`), and
//! crates.io's trusted publisher names `release.yml`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // test code: a failed read is the test failing

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

/// The install line, whole (D1).
const INSTALL: &str = "cargo add bsv-rs --features transaction,wallet";
/// The first screen's bound in lines (the brief's 45).
const FIRST_SCREEN_LINES: usize = 45;
/// The heading that ends the first screen, and the one that ends the version-free text.
const INSTALL_HEADING: &str = "## Install";
const EXAMPLES_HEADING: &str = "## Examples";

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// A file of the tree, or the reason it cannot be read (a producer this line lacks).
fn read(relative: &str) -> Result<String, String> {
    fs::read_to_string(root().join(relative))
        .map_err(|e| format!("{relative} cannot be read on this line ({e})"))
}

fn readme() -> String {
    read("README.md").unwrap()
}

/// The text before the line that is exactly `heading`.
fn before<'a>(text: &'a str, heading: &str) -> &'a str {
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        if line.trim_end() == heading {
            return &text[..offset];
        }
        offset += line.len();
    }
    panic!("README.md has no `{heading}` line");
}

/// The first screen: everything before `## Install`.
fn first_screen(readme: &str) -> &str {
    before(readme, INSTALL_HEADING)
}

/// A line's prose: HTML comments, inline code and link targets removed (a number inside a URL,
/// a path or a code span is not a figure the sentence states).
fn prose(line: &str) -> String {
    let mut out = String::new();
    let mut rest = line;
    loop {
        let comment = rest.find("<!--");
        let code = rest.find('`');
        let target = rest.find("](");
        let next = [comment, code, target].into_iter().flatten().min();
        let Some(at) = next else {
            out.push_str(rest);
            break;
        };
        out.push_str(&rest[..at]);
        let tail = &rest[at..];
        let skip = if Some(at) == comment {
            tail.find("-->").map(|e| e + 3)
        } else if Some(at) == code {
            tail[1..].find('`').map(|e| e + 2)
        } else {
            out.push(']');
            tail.find(')').map(|e| e + 1)
        };
        rest = &tail[skip.unwrap_or(tail.len())..];
    }
    out
}

/// The figures a line of prose states: runs of digits (with thousands commas), not part of a word,
/// an identifier or a hyphenated name (`wasm32`, `BRC-100`, `v4` are no figures).
fn figures(prose: &str) -> Vec<u64> {
    let chars: Vec<char> = prose.chars().collect();
    let joins = |c: char| c.is_alphanumeric() || c == '_' || c == '-' || c == '.';
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if !chars[i].is_ascii_digit() || (i > 0 && joins(chars[i - 1])) {
            i += 1;
            continue;
        }
        let mut digits = String::new();
        let mut j = i;
        while j < chars.len() {
            let c = chars[j];
            if c.is_ascii_digit() {
                digits.push(c);
            } else if c == ',' && chars.get(j + 1).is_some_and(|d| d.is_ascii_digit()) {
                // a thousands comma: three digits follow
            } else {
                break;
            }
            j += 1;
        }
        let word = chars
            .get(j)
            .is_some_and(|&c| c.is_alphanumeric() || c == '_' || c == '-')
            || (chars.get(j) == Some(&'.') && chars.get(j + 1).is_some_and(|d| d.is_ascii_digit()));
        if !word {
            out.push(digits.parse().unwrap());
        }
        i = j.max(i + 1);
    }
    out
}

/// The marker a line carries, `<!-- F<n> -->`, if any (the leading one, where it carries several).
fn marker(line: &str) -> Option<String> {
    markers(line).into_iter().next()
}

/// Every marker a line carries, in order: a line may write one twice, or two (refused).
fn markers(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = line;
    while let Some(at) = rest.find("<!-- F") {
        let tail = &rest[at + 5..];
        let Some(end) = tail.find(" -->") else { break };
        out.push(tail[..end].to_string());
        rest = &tail[end..];
    }
    out
}

/// The integer literal on the first line after `needle` that holds only one (a pinned figure in
/// an `assert_eq!`).
fn pinned_after(text: &str, needle: &str, file: &str) -> Result<u64, String> {
    let at = text
        .find(needle)
        .ok_or_else(|| format!("{file} has no `{needle}`"))?;
    text[at + needle.len()..]
        .lines()
        .map(|l| l.trim().trim_end_matches(','))
        .find(|l| !l.is_empty() && l.chars().all(|c| c.is_ascii_digit()))
        .and_then(|l| l.parse().ok())
        .ok_or_else(|| format!("{file}: no pinned figure after `{needle}`"))
}

fn require(text: &str, needle: &str, file: &str) -> Result<(), String> {
    if text.contains(needle) {
        Ok(())
    } else {
        Err(format!("{file} no longer holds `{needle}`"))
    }
}

/// The backticked names of a line, in order.
fn code_spans(line: &str) -> Vec<String> {
    line.split('`')
        .enumerate()
        .filter(|(i, _)| i % 2 == 1)
        .map(|(_, s)| s.to_string())
        .collect()
}

/// The job of `ci.yml` whose text holds `needle`, and the refusal if it would let the sentence
/// pass on a failure: a `continue-on-error` in it absorbs the failure the sentence relies on
/// (the strength read of 2026-11-11, the captain's ruling R5).
fn judging_job(needle: &str, what: &str) -> Result<String, String> {
    let ci = read(".github/workflows/ci.yml")?;
    let lines: Vec<&str> = ci.lines().collect();
    let starts: Vec<usize> = (0..lines.len())
        .filter(|&i| {
            let l = lines[i];
            l.len() > 3
                && l.starts_with("  ")
                && !l.starts_with("   ")
                && l.ends_with(':')
                && l[2..l.len() - 1]
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        })
        .collect();
    for (n, &start) in starts.iter().enumerate() {
        let end = starts.get(n + 1).copied().unwrap_or(lines.len());
        let job = lines[start..end].join("\n");
        if job.contains(needle) {
            if job.contains("continue-on-error") {
                return Err(format!(
                    "ci.yml's {} job, which {what}, carries `continue-on-error`: its failure is absorbed",
                    lines[start].trim().trim_end_matches(':')
                ));
            }
            return Ok(job);
        }
    }
    Err(format!("no job of ci.yml {what} (`{needle}`)"))
}

/// Whether a line runs `cargo publish` (not a dry run): the word `cargo`, any run of words that
/// begin with `-` or `+` (`+toolchain`, `--locked`, `-q`, `+stable --locked`), then `publish`,
/// whitespace of any kind between them; after an environment assignment, `env` or `xargs`,
/// inside `$(...)`, in any command of the line. `--dry-run` is judged per command (the line split
/// on `&&`, `||`, `;`, `|`), so `cargo publish --dry-run && cargo publish` publishes (the cold
/// re-read's five plants; the captain's ruling T1; the options between the words since #883's
/// third fold). A comment line is not a command, and a comment after a command is cut.
///
/// Four forms are NOT found, stated (the scoped re-read of `e76db545` and the cold read of
/// `35b81937`): the command held in a variable (`C=cargo; $C publish`), a script reached by
/// `cd <dir> && ./<script>` outside the scanned folders (`named_files` reads a path relative to
/// the root), an option whose value is a word of its own (`cargo --config <k=v> publish`,
/// `cargo -Z <flag> publish`: the value ends the run of options) and a command split by a line
/// continuation (each line is read alone). None can publish: no
/// workflow but `release.yml` can obtain a registry token (`stored_token` refuses every stored
/// one, and the OIDC line is accepted in `release.yml`'s publish step alone), and crates.io's
/// trusted publisher names `release.yml`.
fn runs_cargo_publish(line: &str) -> bool {
    let l = line.trim();
    if l.starts_with('#') || l.starts_with("//") {
        return false;
    }
    let l = l.split(" #").next().unwrap_or(l);
    l.split(['&', '|', ';']).any(|command| {
        let words: Vec<&str> = command
            .split_whitespace()
            .map(|w| w.trim_matches(|c: char| "\"'`$()".contains(c)))
            .collect();
        let publishes = words.iter().enumerate().any(|(i, w)| {
            if *w != "cargo" {
                return false;
            }
            words[i + 1..]
                .iter()
                .find(|t| !(t.starts_with('-') || t.starts_with('+')))
                == Some(&"publish")
        });
        publishes && !words.contains(&"--dry-run")
    })
}

/// A workflow called by a job-level `uses:` from outside this repository runs steps no test of
/// this tree can read (it may publish): refused unless named here with its reason. The tree
/// calls none today (every job-level `uses:` is `./.github/workflows/...`).
const REMOTE_WORKFLOWS: &[(&str, &str)] = &[];

/// The composite actions of this tree: every `action.yml` and `action.yaml` under
/// `.github/actions/`. A step's `uses: ./.github/actions/<dir>` runs one, so F7 reads each as it
/// reads a workflow.
fn composite_actions() -> Vec<PathBuf> {
    let mut files = Vec::new();
    files_under(&root().join(".github/actions"), "", &mut files);
    files.retain(|p| {
        p.file_name()
            .is_some_and(|n| n == "action.yml" || n == "action.yaml")
    });
    files.sort();
    files
}

/// How many composite actions the tree holds: none today. A new one moves this count, so its
/// author sees that F7 reads it (`the_composite_actions_are_counted`).
const COMPOSITE_ACTIONS: usize = 0;

/// The repository's relative paths a line names that are files of the tree (a script a `run:`
/// calls: `python3 -B .github/scripts/x.py`, `bash tools/x.sh`, `./tools/ratchet/run`).
fn named_files(line: &str) -> Vec<PathBuf> {
    line.split(|c: char| c.is_whitespace() || "\"'`;&|()=".contains(c))
        .map(|w| w.trim_start_matches("./"))
        .filter(|w| {
            w.contains('/') && !w.starts_with('/') && !w.contains("${") && !w.contains("://")
        })
        .map(|w| root().join(w))
        .filter(|p| p.is_file())
        .collect()
}

/// Every file under `dir`, recursively, `skip` excepted.
fn files_under(dir: &std::path::Path, skip: &str, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.file_name().is_some_and(|n| n == skip) {
            continue;
        }
        if path.is_dir() {
            files_under(&path, skip, out);
        } else {
            out.push(path);
        }
    }
}

/// One item of a `steps:` list: its opening line, the line after its end (0-based), and the text
/// of its `run:` as YAML reads it (empty when it has none).
struct Step {
    start: usize,
    end: usize,
    run: String,
}

/// A line's indentation in spaces.
fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start_matches(' ').len()
}

/// Whether a line opens a sequence item: `-` followed by a space or the end of the line.
fn is_item(trimmed: &str) -> bool {
    trimmed == "-" || trimmed.starts_with("- ")
}

/// Whether a line opens one or more sequence items, and its text after them.
fn item_rest(line: &str) -> (bool, &str) {
    let mut rest = line.trim_start_matches(' ');
    let mut had = false;
    while is_item(rest) {
        had = true;
        rest = rest[1..].trim_start_matches(' ');
    }
    (had, rest)
}

/// A structural line's key, its column and its value (`None` when the line holds no `key:`):
/// leading `- ` items are passed over, the key is the text before the line's earliest `: ` (or a
/// final `:`), the value what follows, trimmed.
fn key_value(line: &str) -> Option<(usize, &str, &str)> {
    let (_, rest) = item_rest(line);
    let col = line.len() - rest.len();
    if let Some(i) = rest.find(": ") {
        return Some((col, &rest[..i], rest[i + 2..].trim()));
    }
    rest.strip_suffix(':').map(|k| (col, k, ""))
}

/// A block scalar's header (`|` or `>`, at most one chomping indicator and one indentation
/// digit in either order, then nothing or a comment): whether it folds, and its indentation
/// indicator.
fn block_header(value: &str) -> Option<(bool, Option<usize>)> {
    let v = value.split(" #").next().unwrap_or(value).trim_end();
    let folded = match v.chars().next()? {
        '|' => false,
        '>' => true,
        _ => return None,
    };
    let (mut chomp, mut digit) = (false, None);
    for c in v[1..].chars() {
        match c {
            '+' | '-' if !chomp => chomp = true,
            '1'..='9' if digit.is_none() => digit = c.to_digit(10).map(|d| d as usize),
            _ => return None,
        }
    }
    Some((folded, digit))
}

/// Where a quoted scalar that opens `s` closes (the byte after its closing quote), or `None` when
/// it does not close on this line: `''` is a quote inside single quotes, `\` escapes the next
/// character inside double quotes.
fn quoted_end(s: &str) -> Option<usize> {
    let q = s.chars().next().filter(|c| *c == '"' || *c == '\'')?;
    let b = s.as_bytes();
    let mut i = 1;
    while i < b.len() {
        match b[i] {
            b'\\' if q == '"' => i += 2,
            c if c == q as u8 => {
                if q == '\'' && b.get(i + 1) == Some(&b'\'') {
                    i += 2;
                } else {
                    return Some(i + 1);
                }
            }
            _ => i += 1,
        }
    }
    None
}

/// Where a flow collection that opens `s` (`[` or `{`) closes (the byte after its closing
/// bracket), or `None` when it does not close on this line; quoted scalars inside it are passed
/// over whole.
fn flow_end(s: &str) -> Option<usize> {
    let b = s.as_bytes();
    let mut depth = 0usize;
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'[' | b'{' => depth += 1,
            b']' | b'}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            b'"' | b'\'' => {
                i += quoted_end(&s[i..])?;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Whether the text after a closed scalar or collection is nothing or a comment.
fn nothing_after(rest: &str) -> bool {
    rest.trim().is_empty() || (rest.starts_with(' ') && rest.trim_start().starts_with('#'))
}

/// The earliest character of `text` that `steps_of` does not read, refused by file, line and code
/// point, anywhere in the file (a comment, a quoted value and a block scalar's content
/// included), before any line is read (#883's sixth fold: the narrow read of the fifth found a
/// lone `\r`, U+0085, U+2028 and U+2029 each breaking a line for a YAML parser, Psych 5.3.1,
/// and none for this reader, which splits on `\n` alone, so a comment line holding one put the
/// token, for the parser, in a step that does not publish). Refused: a `\r` not followed by
/// `\n` (a line break in YAML 1.2); every other C0 control save `\n` and the tab (a tab is
/// refused by `steps_of` where it is structure, and read inside a block scalar's content or a
/// comment, where YAML reads it as text); U+007F; every C1 control, U+0080 to U+009F (U+0085,
/// NEL, among them); U+2028 and U+2029; U+FEFF anywhere, at the file's start included.
fn unread_character(name: &str, text: &str) -> Result<(), String> {
    let mut chars = text.chars().peekable();
    let mut line = 1;
    while let Some(c) = chars.next() {
        let refused = match c {
            '\n' | '\t' => false,
            '\r' => chars.peek() != Some(&'\n'),
            '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}' => true,
            '\u{2028}' | '\u{2029}' | '\u{feff}' => true,
            _ => false,
        };
        if refused {
            return Err(format!(
                "{name}:{line}: the character U+{:04X}, which this reader does not read",
                c as u32
            ));
        }
        if c == '\n' {
            line += 1;
        }
    }
    Ok(())
}

/// The steps of a workflow or a composite action, as read by a line reader that is NOT a YAML
/// parser, or the layout refused naming the file and the line (#883's fourth and fifth folds:
/// the narrow reads found a step opened by a bare `-` merged into the step before it, a step
/// whose `name:` said `cargo publish` taken for the publish, lines that looked like a publish
/// step inside a quoted scalar running over several lines, and a `steps:` key inside a `with:`).
///
/// Read: block style, one line at a time. Every block scalar of the file (`key: |` or `key: >`,
/// with a chomping and an indentation indicator) is its content, never a key. A `steps:` key is
/// a line that is exactly `steps:`, a key of a job (its parent a key of `jobs:` at the file's
/// first column) or of a composite action's `runs:`; the list under it is a block list whose
/// items sit at ONE indentation, that of its opening item (deeper than the key, or at the key's
/// own column); a line at that indentation whose leading character is `-`, followed by a space
/// or the end of the line, opens a step, and the step runs to the next such line or to the
/// list's end (a line at the key's column or shallower). A step's keys sit at one column, the
/// item's text after `- ` or, for a bare `-`, the next line's; its `run:` is the key `run` at
/// that column alone (never one inside `with:` or `env:`), read as YAML reads a plain scalar
/// (its continuation lines folded), a one-line quoted scalar, a literal `|` or a folded `>`
/// block (lines folded as YAML 1.2 folds them).
///
/// Refused, loudly, by file and line, anywhere in the file (the forms this reader lists as not
/// read, whatever YAML makes of them):
/// - before any line is read, a character a YAML parser breaks a line at or reads as a mark
///   where this reader, splitting on `\n` alone, does not (`unread_character`: a lone `\r`,
///   the other C0 controls save `\n` and the tab, U+007F, U+0080 to U+009F, U+2028, U+2029,
///   U+FEFF), named by its code point (#883's sixth fold);
/// - a tab in a line's indentation, or anywhere on a line that is not a block scalar's content
///   or a comment (a tab inside a `run: |` block's content, after its leading whitespace, is
///   read);
/// - a top-level line off the first column; a line whose indentation, going back, is no open
///   level's; a list item and a key at one indentation of one mapping; a key written twice in
///   one mapping;
/// - an anchor (`&`), an alias (`*`), a tag (`!`) or a merge key (`<<:`); a document marker
///   (`---`, `...`) or a directive (`%`); an explicit key (`?`) or a line opening with `:`;
/// - a quoted or flow key; a quoted scalar or a flow collection that opens a line and is no
///   list item;
/// - a quoted scalar that does not close on its line, or with text after its close; a flow
///   collection (`[` or `{`) that does not close on its line, or with text after its close; a
///   block scalar header it does not read;
/// - a plain scalar continued on a following line, save a `run:`'s, and a `run:` continuation
///   holding `: `, ` #` or a comment; a plain scalar holding `: `; a line deeper than a quoted,
///   flow or block value that has ended; a line that is neither a key, a list item, a comment
///   nor such a continuation;
/// - a `steps:` key that is not a job's (one in a list item, inside a step, a `with:`, an `env:`
///   or any mapping deeper than a job); a `steps:` key with anything after it (a flow list, an
///   anchor, a comment); a `steps:` with no block list under it; a line under `steps:` it cannot
///   place (deeper than the key and shallower than the items, or a key at the items'
///   indentation);
/// - a step that opens a flow mapping, a scalar or a quoted text; a bare `-` with nothing under
///   it; a line of a step shallower than its keys; a `run:` that is a flow collection.
///
/// What this proves, and what it does not: this is a line reader, not a YAML parser; it refuses
/// the forms and characters listed above and claims nothing of the rest. A differential against
/// a YAML parser (Psych 5.3.1) over 12,000 layouts of `release.yml` generated from a grammar of
/// step forms and of those characters at every kind of position (seeds 6061, 8830 and 20261112,
/// 4,000 each, 2026-11-11, #883's sixth fold; 8,000 on seeds 20261111 and 883 at the fifth)
/// found no layout this reader accepts with the token outside the publishing step, where
/// `c6c09e81`'s reader accepted 95, 82 and 88 (each a lone `\r`, U+0085, U+2028 or U+2029).
/// That run is evidence of the lane (`docs/lanes/front-pages-fold.md`, "Fold 6"), not a test of
/// the tree: a form outside that generator's grammar is not claimed.
fn steps_of(name: &str, text: &str) -> Result<Vec<Step>, String> {
    unread_character(name, text)?;
    let lines: Vec<&str> = text.lines().collect();
    let at = |n: usize, what: &str| format!("{name}:{}: {what}: `{}`", n + 1, lines[n].trim());
    // The content lines of every block scalar and of a `run:`'s plain continuation, and the
    // refusals any structural line earns.
    let mut content = vec![false; lines.len()];
    for (n, l) in lines.iter().enumerate() {
        if l[..l.len() - l.trim_start().len()].contains('\t') {
            return Err(at(
                n,
                "a tab in the indentation, which this reader does not read",
            ));
        }
    }
    // The value of the line before: the column a line under it passes, and what it is.
    #[derive(Clone, Copy)]
    enum Open {
        /// A `run:`'s plain scalar: a line under it is its continuation.
        Run,
        /// Any other plain scalar: a line under it is a continuation this reader does not read.
        Plain,
        /// A quoted scalar, a flow collection or a block scalar, ended: nothing may sit under it.
        Ended,
    }
    let mut open_plain: Option<(usize, Open)> = None;
    // Each structural line's indentation and index, to find a line's parent; the keys of each
    // mapping, by its parent line and its column.
    let mut stack: Vec<(usize, usize)> = Vec::new();
    let mut parent = vec![None; lines.len()];
    let mut keys = BTreeSet::new();
    // Whether each level (a parent line and an indentation) holds list items or keys; the keys
    // whose list sits at their own column; the structural line before.
    let mut levels = std::collections::BTreeMap::new();
    let mut list_at_key = BTreeSet::new();
    let mut previous: Option<usize> = None;
    let mut n = 0;
    while n < lines.len() {
        let t = lines[n].trim();
        if content[n] || t.is_empty() || t.starts_with('#') {
            if t.starts_with('#') {
                // A comment ends a plain scalar: nothing may continue it after.
                open_plain = open_plain.map(|(col, _)| (col, Open::Ended));
            }
            n += 1;
            continue;
        }
        if let Some((col, open)) = open_plain {
            if indent_of(lines[n]) > col {
                match open {
                    Open::Run if t.contains(": ") || t.contains(" #") || t.ends_with(':') => {
                        return Err(at(
                            n,
                            "a plain `run:` continuation this reader does not read",
                        ))
                    }
                    Open::Run => {
                        content[n] = true;
                        n += 1;
                        continue;
                    }
                    Open::Plain => {
                        return Err(at(
                            n,
                            "a plain scalar continued on a following line, which this reader does not read",
                        ))
                    }
                    Open::Ended => {
                        return Err(at(
                            n,
                            "a line deeper than a value that has ended, which this reader does not read",
                        ))
                    }
                }
            }
        }
        open_plain = None;
        if lines[n].contains('\t') {
            return Err(at(n, "a tab, which this reader does not read"));
        }
        if t == "---"
            || t.starts_with("--- ")
            || t == "..."
            || t.starts_with("... ")
            || t.starts_with('%')
        {
            return Err(at(
                n,
                "a document marker or a directive, which this reader does not read",
            ));
        }
        let (had_item, head) = item_rest(lines[n]);
        let dash = lines[n].len() - head.len();
        let dash = lines[n][..dash].rfind('-').unwrap_or(indent_of(lines[n]));
        if head == "?" || head.starts_with("? ") || head == ":" || head.starts_with(": ") {
            return Err(at(n, "an explicit key, which this reader does not read"));
        }
        if head.starts_with(['"', '\'', '[', '{']) {
            let close = if head.starts_with(['"', '\'']) {
                quoted_end(head)
            } else {
                flow_end(head)
            };
            let close = close.ok_or_else(|| {
                at(
                    n,
                    "a quoted scalar or a flow collection that does not close on its line, which this reader does not read",
                )
            })?;
            if head[close..].trim_start().starts_with(':') {
                return Err(at(
                    n,
                    "a quoted key or a flow key, which this reader does not read",
                ));
            }
            if !had_item || !nothing_after(&head[close..]) {
                return Err(at(
                    n,
                    "a quoted scalar or a flow collection that is no key's value and no list item, which this reader does not read",
                ));
            }
        }
        let kv = key_value(lines[n]);
        if kv.is_some_and(|(_, k, _)| k == "<<") {
            return Err(at(n, "a merge key, which this reader does not read"));
        }
        let value = kv.map_or(head, |(_, _, v)| v);
        let marked = |v: &str| v.starts_with(['&', '*', '!']);
        if marked(head) || (kv.is_some() && marked(value)) {
            return Err(at(
                n,
                "an anchor, an alias or a tag, which this reader does not read",
            ));
        }
        if kv.is_none() && !had_item {
            return Err(at(
                n,
                "a line that is no key, no list item and no `run:` continuation, which this reader does not read",
            ));
        }
        let ind = indent_of(lines[n]);
        let mut dedented = false;
        while stack.last().is_some_and(|&(i, _)| i > ind) {
            stack.pop();
            dedented = true;
        }
        if stack
            .last()
            .map_or(ind != 0, |&(i, _)| dedented && i != ind)
        {
            return Err(at(
                n,
                "a line whose indentation is no open level's, which this reader does not read",
            ));
        }
        // A list at its key's own column (`key:` then `- item` under it at that column) is the
        // key's value: the key stays open for the list's items.
        if let Some(p) = previous.filter(|&p| {
            had_item
                && key_value(lines[p])
                    .is_some_and(|(c, _, v)| c == ind && (v.is_empty() || v.starts_with('#')))
        }) {
            list_at_key.insert(p);
        }
        while stack
            .last()
            .is_some_and(|&(i, p)| i > ind || (i == ind && !(had_item && list_at_key.contains(&p))))
        {
            stack.pop();
        }
        parent[n] = stack.last().map(|&(_, p)| p);
        if *levels.entry((parent[n], ind)).or_insert(had_item) != had_item {
            return Err(at(
                n,
                "a list item and a key at one indentation of one mapping, which this reader does not read",
            ));
        }
        stack.push((ind, n));
        if let Some((col, _, _)) = kv.filter(|_| had_item) {
            // The mapping a list item opens: its keys sit at the item's key column.
            stack.push((col, n));
            levels.insert((Some(n), col), false);
        }
        if let Some((col, key, _)) = kv {
            let mapping = if had_item { Some(n) } else { parent[n] };
            if !keys.insert((mapping, col, key.to_string())) {
                return Err(at(n, "a key written twice in one mapping"));
            }
        }
        let value = if value.starts_with('#') { "" } else { value };
        if value.starts_with(['"', '\'']) {
            match quoted_end(value) {
                Some(close) if nothing_after(&value[close..]) => {}
                _ => {
                    return Err(at(
                        n,
                        "a quoted scalar that does not close on its line, which this reader does not read",
                    ))
                }
            }
        }
        if value.starts_with(['[', '{']) {
            match flow_end(value) {
                Some(close) if nothing_after(&value[close..]) => {}
                _ => {
                    return Err(at(
                        n,
                        "a flow collection that does not close on its line, which this reader does not read",
                    ))
                }
            }
        }
        if value.starts_with(['|', '>']) {
            let Some((_, explicit)) = block_header(value) else {
                return Err(at(n, "a block scalar header this reader does not read"));
            };
            let col = kv.map_or(ind, |(c, _, _)| c);
            let n_line = n;
            let mut m = n + 1;
            let first = lines[m.min(lines.len())..]
                .iter()
                .find(|l| !l.trim().is_empty())
                .map(|l| indent_of(l));
            let inner = explicit.map(|d| col + d).or(first).unwrap_or(usize::MAX);
            if inner > col {
                while m < lines.len()
                    && (lines[m].trim().is_empty() || indent_of(lines[m]) >= inner)
                {
                    content[m] = true;
                    m += 1;
                }
            }
            n = m;
            open_plain = Some((col, Open::Ended));
            previous = Some(n_line);
            continue;
        }
        if !value.is_empty() && !value.starts_with(['"', '\'', '[', '{']) {
            let plain = value.split(" #").next().unwrap_or(value);
            if plain.contains(": ") || plain.ends_with(':') {
                return Err(at(
                    n,
                    "a plain scalar holding `: `, which this reader does not read",
                ));
            }
        }
        if !value.is_empty() {
            let open = match kv {
                _ if value.starts_with(['"', '\'', '[', '{']) => Open::Ended,
                Some((_, "run", _)) => Open::Run,
                _ => Open::Plain,
            };
            open_plain = Some((kv.map_or(dash, |(col, _, _)| col), open));
        }
        previous = Some(n);
        n += 1;
    }
    let structural =
        |m: usize| !content[m] && !lines[m].trim().is_empty() && !lines[m].trim().starts_with('#');
    // A key of `jobs:` at the file's first column, or `runs:` there itself (a composite action).
    let job_or_runs = |p: usize| {
        let (had, _) = item_rest(lines[p]);
        match key_value(lines[p]) {
            Some((0, "runs", "")) => !had,
            Some((_, _, v)) if !had && (v.is_empty() || v.starts_with('#')) => parent[p]
                .is_some_and(|g| !item_rest(lines[g]).0 && matches!(key_value(lines[g]), Some((0, "jobs", v)) if v.is_empty() || v.starts_with('#'))),
            _ => false,
        }
    };
    let mut out = Vec::new();
    for n in 0..lines.len() {
        if !structural(n) {
            continue;
        }
        let Some((key_col, "steps", value)) = key_value(lines[n]) else {
            let t = lines[n].trim().trim_start_matches(['-', ' ']);
            if t.starts_with("steps:") {
                return Err(at(n, "a `steps:` key this reader cannot place"));
            }
            continue;
        };
        if !value.is_empty() {
            return Err(at(n, "a `steps:` key this reader cannot place"));
        }
        if item_rest(lines[n]).0 || !parent[n].is_some_and(job_or_runs) {
            return Err(at(n, "a `steps:` key that is not a job's"));
        }
        let Some(first) = (n + 1..lines.len()).find(|&m| structural(m)) else {
            return Err(at(n, "a `steps:` key with no block list under it"));
        };
        let item = indent_of(lines[first]);
        if !is_item(lines[first].trim()) || item < key_col {
            return Err(at(n, "a `steps:` key with no block list under it"));
        }
        let mut starts = Vec::new();
        let mut end = lines.len();
        for (m, line) in lines.iter().enumerate().skip(first) {
            if !structural(m) {
                continue;
            }
            let ind = indent_of(line);
            let dash = is_item(line.trim());
            if ind == item && dash {
                starts.push(m);
            } else if ind > item {
                continue;
            } else if ind > key_col || (ind == item && item > key_col) {
                return Err(at(m, "a line under `steps:` this reader cannot place"));
            } else {
                end = m;
                break;
            }
        }
        for (i, &s) in starts.iter().enumerate() {
            let e = starts.get(i + 1).copied().unwrap_or(end);
            out.push(Step {
                start: s,
                end: e,
                run: run_of(&lines, &content, s, e, item, &at)?,
            });
        }
    }
    Ok(out)
}

/// The text of the `run:` of the step on lines `s..e` whose dash sits at column `item`.
fn run_of(
    lines: &[&str],
    content: &[bool],
    s: usize,
    e: usize,
    item: usize,
    at: &dyn Fn(usize, &str) -> String,
) -> Result<String, String> {
    let after_dash = lines[s][item + 1..].trim_start_matches(' ');
    let structural =
        |m: usize| !content[m] && !lines[m].trim().is_empty() && !lines[m].trim().starts_with('#');
    let keys_col = if after_dash.is_empty() || after_dash.starts_with('#') {
        match (s + 1..e).find(|&m| structural(m)) {
            Some(m) => indent_of(lines[m]),
            None => return Err(at(s, "a step with nothing under it")),
        }
    } else {
        if after_dash.starts_with(['{', '[', '"', '\'', '|', '>', '&', '*', '!'])
            || key_value(lines[s]).is_none()
        {
            return Err(at(s, "a step this reader does not read (no block mapping)"));
        }
        lines[s].len() - after_dash.len()
    };
    let mut run = None;
    for m in s..e {
        if !structural(m) {
            continue;
        }
        let ind = if m == s {
            keys_col
        } else {
            indent_of(lines[m])
        };
        if ind < keys_col {
            return Err(at(m, "a line of a step shallower than its keys"));
        }
        let Some((col, "run", value)) = key_value(lines[m]) else {
            continue;
        };
        if col != keys_col {
            continue;
        }
        run = Some(if let Some((folded, explicit)) = block_header(value) {
            let body: Vec<&str> = (m + 1..e)
                .take_while(|&k| content[k])
                .map(|k| lines[k])
                .collect();
            let first = body
                .iter()
                .find(|l| !l.trim().is_empty())
                .map(|l| indent_of(l));
            let inner = explicit.map(|d| col + d).or(first).unwrap_or(0);
            let body: Vec<&str> = body.iter().map(|l| l.get(inner..).unwrap_or("")).collect();
            if folded {
                fold(&body)
            } else {
                body.join("\n")
            }
        } else if value.starts_with(['|', '>']) {
            return Err(at(m, "a `run:` block header this reader does not read"));
        } else if value.starts_with(['[', '{']) {
            return Err(at(
                m,
                "a `run:` that is a flow collection, which this reader does not read",
            ));
        } else if let Some(q) = value.chars().next().filter(|c| *c == '"' || *c == '\'') {
            if value.len() < 2 || !value.ends_with(q) {
                return Err(at(m, "a quoted `run:` that does not close on its line"));
            }
            value[1..value.len() - 1].to_string()
        } else {
            let mut text = value.split(" #").next().unwrap_or(value).to_string();
            for (k, line) in lines.iter().enumerate().take(e).skip(m + 1) {
                let t = line.trim();
                if !t.is_empty() && indent_of(line) <= keys_col {
                    break;
                }
                if t.starts_with('#') || t.contains(": ") || t.contains(" #") {
                    return Err(at(
                        k,
                        "a plain `run:` continuation this reader does not read",
                    ));
                }
                if t.is_empty() {
                    text.push('\n');
                } else {
                    if !text.is_empty() && !text.ends_with('\n') {
                        text.push(' ');
                    }
                    text.push_str(t);
                }
            }
            text
        });
    }
    Ok(run.unwrap_or_default())
}

/// A folded block's lines as YAML 1.2 folds them: a line break between two lines that begin
/// with no space is a space; blank lines between them are kept as line breaks; a more indented
/// line keeps its breaks.
fn fold(body: &[&str]) -> String {
    let mut out = String::new();
    let mut prev: Option<bool> = None;
    let mut blanks = 0;
    for l in body {
        if l.trim().is_empty() {
            blanks += 1;
            continue;
        }
        let more = l.starts_with(' ');
        match prev {
            None => out.push_str(&"\n".repeat(blanks)),
            Some(p) if !p && !more => {
                out.push_str(if blanks == 0 { " " } else { "" });
                out.push_str(&"\n".repeat(blanks));
            }
            Some(_) => out.push_str(&"\n".repeat(blanks + 1)),
        }
        out.push_str(l);
        prev = Some(more);
        blanks = 0;
    }
    out
}

/// F7's token half: no workflow (release.yml included, the captain's ruling T9) reads a stored
/// registry token or logs in; the one `CARGO_REGISTRY_TOKEN` is release.yml's, from the OIDC
/// exchange, and that exact line is accepted only inside a step of `release.yml` whose `run:`
/// runs `cargo publish` (#883's third fold), the step read by `steps_of` and the publish judged
/// on the `run:` text alone, never a `name:`, an `env:`, a `with:` or a comment (#883's fourth
/// fold), as read by a line reader that is not a YAML parser; the forms and characters
/// `steps_of` lists are refused by file and line, in every workflow and action (#883's fifth and
/// sixth folds), and nothing is claimed of a form outside that list and outside the grammar of
/// the differential against a YAML parser that found no other (`steps_of`'s comment).
fn stored_token(name: &str, text: &str) -> Option<String> {
    const OIDC: &str = "CARGO_REGISTRY_TOKEN: ${{ steps.auth.outputs.token }}";
    let steps = match steps_of(name, text) {
        Ok(steps) => steps,
        Err(why) => return Some(why),
    };
    let publish_steps: Vec<(usize, usize)> = steps
        .iter()
        .filter(|step| step.run.lines().any(runs_cargo_publish))
        .map(|step| (step.start, step.end))
        .collect();
    for (n, line) in text.lines().enumerate() {
        let l = line.trim();
        if l.starts_with('#') {
            continue;
        }
        let in_publish_step = publish_steps.iter().any(|&(s, e)| (s..e).contains(&n));
        if l.contains("CARGO_REGISTR") && !(name == "release.yml" && l == OIDC && in_publish_step) {
            return Some(format!("{name} sets or reads a registry token: `{l}`"));
        }
        if l.contains("secrets") && l.to_ascii_uppercase().contains("CARGO") {
            return Some(format!("{name} reads a stored secret for cargo: `{l}`"));
        }
        let cargo_with_token =
            l.contains("cargo") && (l.contains(" login") || l.contains("--token"));
        if cargo_with_token {
            return Some(format!("{name} hands cargo a token: `{l}`"));
        }
    }
    None
}

/// The combined wasm32 slice's features as `ci.yml` builds them on this line.
fn wasm_slice() -> Result<Vec<String>, String> {
    let ci = read(".github/workflows/ci.yml")?;
    let list = ci
        .lines()
        .find_map(|l| {
            let l = l.trim();
            l.strip_prefix("SLICE_FEATURES: ")
                .or_else(|| {
                    l.strip_prefix("combined) features=")
                        .map(|r| r.split_whitespace().next().unwrap_or(""))
                })
                .map(|r| r.trim_end_matches(';').to_string())
        })
        .ok_or("ci.yml names no combined wasm32 slice")?;
    Ok(list.split(',').map(str::to_string).collect())
}

/// The unit of a performance figure in a line of prose: a number followed by a time or a rate
/// (`12 ns`, `3.5 µs`, `40 MB/s`, `2,000 tx/s`, `3x faster`), if any.
fn performance_unit(prose: &str) -> Option<&'static str> {
    const UNITS: &[&str] = &[
        "ns",
        "µs",
        "us/",
        "ms/",
        "ms",
        "s",
        "×",
        "/s",
        "ops",
        "MB/s",
        "MiB/s",
        "GB/s",
        "GiB/s",
        "tx/s",
        "x faster",
        "times faster",
        "% faster",
        "x slower",
    ];
    let bytes = prose.as_bytes();
    for (i, c) in prose.char_indices() {
        if !c.is_ascii_digit() || bytes.get(i + 1).is_some_and(|b| b.is_ascii_digit()) {
            continue;
        }
        let after = &prose[i + 1..];
        let after = after.trim_start_matches(|c: char| c == '.' || c.is_ascii_digit());
        let after = after.strip_prefix(' ').unwrap_or(after);
        let after = after.strip_prefix('\u{a0}').unwrap_or(after);
        if let Some(unit) = UNITS.iter().find(|u| {
            after.starts_with(*u)
                && !after[u.len()..]
                    .chars()
                    .next()
                    .is_some_and(char::is_alphanumeric)
        }) {
            return Some(unit);
        }
    }
    None
}

/// What a marked sentence may say: it checks the line's names against the tree and returns the
/// figures the line must state, exactly.
type Producer = fn(&str) -> Result<Vec<u64>, String>;

/// Every marker and its producer. A marker the README carries that is not here fails; a
/// producer whose file this line lacks fails while the README carries its marker.
const PRODUCERS: &[(&str, &str, Producer)] = &[
    ("F1", "Cargo.toml's [features]", |_| {
        let manifest = read("Cargo.toml")?;
        let section = manifest
            .split("\n[features]\n")
            .nth(1)
            .ok_or("Cargo.toml has no [features]")?;
        let section = section.split("\n[").next().unwrap_or(section);
        let names: BTreeSet<&str> = section
            .lines()
            .filter_map(|l| l.split_once(" = ").map(|(k, _)| k.trim()))
            .collect();
        for feature in [
            "primitives",
            "script",
            "transaction",
            "wallet",
            "auth",
            "overlay",
            "wasm",
        ] {
            if !names.contains(feature) {
                return Err(format!(
                    "Cargo.toml has no `{feature}` feature, which the sentence names"
                ));
            }
        }
        Ok(vec![])
    }),
    (
        "F2",
        "the corpus total pinned in tests/conformance_scripts.rs and the corpus pin in ci.yml",
        |_| {
            let file = "tests/conformance_scripts.rs";
            let text = read(file)?;
            let total = pinned_after(&text, "vectors.len(),", file)?;
            let accounted = pinned_after(
                &text,
                "summary.run + summary.unsupported_total() + summary.skipped.len(),",
                file,
            )?;
            if total != accounted {
                return Err(format!(
                    "{file} pins {total} vectors and accounts for {accounted}"
                ));
            }
            let ci = read(".github/workflows/ci.yml")?;
            let at = ci
                .find("repository: bsv-blockchain/ts-stack")
                .ok_or("ci.yml checks out no ts-stack corpus")?;
            let pinned = ci[at..].lines().take(4).any(|l| {
                l.trim().strip_prefix("ref: ").is_some_and(|r| {
                    r.trim().len() == 40 && r.trim().chars().all(|c| c.is_ascii_hexdigit())
                })
            });
            if !pinned {
                return Err("ci.yml checks out the ts-stack corpus at no pinned commit".into());
            }
            // the corpus is run, not only checked out: a job runs the test (R5) with the corpus
            // present, or the test skips and passes (the strength re-read's F-4: `ci.yml`'s
            // `BSV_CONFORMANCE_DIR` and its `META.json` check; the captain's ruling T9)
            let job = judging_job("--test conformance_scripts", "runs the corpus")?;
            for needle in [
                "BSV_CONFORMANCE_DIR: ${{ github.workspace }}/ts-stack/conformance",
                "test -f \"$BSV_CONFORMANCE_DIR/META.json\"",
            ] {
                require(&job, needle, "the job of ci.yml that runs the corpus")?;
            }
            Ok(vec![total])
        },
    ),
    ("F3", "CLAUDE.md's divergence list and rule 1", |line| {
        let text = read("CLAUDE.md")?;
        let heading = "## Known cross-SDK divergences (keep this list honest)";
        let at = text
            .find(heading)
            .ok_or("CLAUDE.md has no divergence list")?;
        let section = &text[at + heading.len()..];
        let section = section.split("\n## ").next().unwrap_or(section);
        let rows = section.lines().filter(|l| l.starts_with("- ")).count();
        if rows == 0 {
            return Err("CLAUDE.md's divergence list has no row".into());
        }
        for side in ["ts-stack", "go-sdk"] {
            require(section, side, "CLAUDE.md's divergence list")?;
        }
        // the private channel is rule 1's exception, for rows stated since the owner's word of
        // 2026-11-10; older rows stand as written, so the sentence speaks of a new row
        // (the rule re-read's README.md:12; the captain's ruling T9)
        for words in [
            "a defect a peer's input can reach, it goes to its maintainers privately before any public line here names it",
            "rows stated before that word stand as written",
        ] {
            require(&text, words, "CLAUDE.md's rule 1")?;
        }
        if line.contains("privately") && !line.contains("privately before a new row names it") {
            return Err(
                "the sentence speaks of every row; rule 1's exception binds a new one".into(),
            );
        }
        Ok(vec![])
    }),
    (
        "F4",
        "tests/sibling/column.json's entries and corpora, and ci.yml's sibling job",
        |_| {
            let text = read("tests/sibling/column.json")?;
            let column: serde_json::Value = serde_json::from_str(&text)
                .map_err(|e| format!("tests/sibling/column.json: {e}"))?;
            let corpora = column["corpora"]
                .as_object()
                .ok_or("tests/sibling/column.json has no corpora")?;
            let entries: u64 = corpora
                .values()
                .map(|c| c["entries"].as_u64().unwrap_or(0))
                .sum();
            let ci = read(".github/workflows/ci.yml")?;
            let job = ci
                .split("\n  sibling:\n")
                .nth(1)
                .ok_or("ci.yml has no sibling job")?;
            let condition: String = job.lines().take(5).collect();
            judging_job(
                "\n    name: sibling\n",
                "judges the script verdicts against bsv-script-lean",
            )?;
            // "on `beta`" is the pull request clause, "before every tag cut from it" the push
            // clause (a tag's call is not a push to main): both (the strength re-read's F-4)
            for clause in [
                "github.base_ref == 'beta'",
                "github.event_name != 'push' || github.ref != 'refs/heads/main'",
            ] {
                require(&condition, clause, "ci.yml's sibling job")?;
            }
            require(
                &read(".github/workflows/release.yml")?,
                "uses: ./.github/workflows/ci.yml",
                "release.yml",
            )?;
            Ok(vec![entries, corpora.len() as u64])
        },
    ),
    (
        "F5",
        "fuzz/Cargo.toml's [[bin]] targets and bounded_capacity",
        |line| {
            // fuzzing finds panics, it does not prove there are none: no absolute (the strength
            // re-read's F-4, the captain's ruling T9)
            if line.contains("never") {
                return Err("the line says `never`; fuzzing does not prove an absence".into());
            }
            let fuzz = read("fuzz/Cargo.toml")?;
            let targets = fuzz.lines().filter(|l| l.trim() == "[[bin]]").count() as u64;
            require(
                &read("src/primitives/encoding.rs")?,
                "pub fn bounded_capacity(",
                "src/primitives/encoding.rs",
            )?;
            Ok(vec![targets])
        },
    ),
    ("F6", "ci.yml's combined wasm32 slice", |line| {
        let slice: BTreeSet<String> = wasm_slice()?.into_iter().filter(|f| f != "wasm").collect();
        let said: BTreeSet<String> = code_spans(line)
            .into_iter()
            .filter(|s| !s.contains('-'))
            .collect();
        if said != slice {
            return Err(format!(
                "the README names the features {said:?}; ci.yml's combined wasm32 slice builds {slice:?} (and `wasm`)"
            ));
        }
        require(
            &read(".github/workflows/ci.yml")?,
            "  pull_request:\n",
            "ci.yml",
        )?;
        judging_job("SLICE_FEATURES: ", "builds the combined wasm32 slice")
            .or_else(|_| judging_job("combined) features=", "builds the combined wasm32 slice"))?;
        Ok(vec![])
    }),
    (
        "F7",
        "ci.yml's semver job and release.yml's publish",
        |_| {
            let ci = read(".github/workflows/ci.yml")?;
            require(&ci, "cargo-semver-checks", "ci.yml")?;
            require(&ci, "--baseline-rev", "ci.yml")?;
            // the two runs of 2026-11-11 (the captain's ruling T9) were of this version: on a
            // stable version it judged a removed function; on a prerelease, equal or stepped,
            // it reported `0 checks` (the sentence's clause on `beta`)
            require(
                &ci,
                "cargo install cargo-semver-checks --version 0.51.0",
                "ci.yml",
            )?;
            let release = read(".github/workflows/release.yml")?;
            require(&release, "rust-lang/crates-io-auth-action@", "release.yml")?;
            require(&release, "id-token: write", "release.yml")?;
            require(
                &release,
                "CARGO_REGISTRY_TOKEN: ${{ steps.auth.outputs.token }}",
                "release.yml",
            )?;
            let mut scripts = Vec::new();
            files_under(&root().join(".github/scripts"), "fixtures", &mut scripts);
            for entry in fs::read_dir(root().join(".github/workflows")).unwrap() {
                let path = entry.unwrap().path();
                let name = path.file_name().unwrap().to_string_lossy().to_string();
                let text = fs::read_to_string(&path).unwrap();
                if text.lines().any(runs_cargo_publish) && name != "release.yml" {
                    return Err(format!("{name} runs `cargo publish` too"));
                }
                if let Some(why) = stored_token(&name, &text) {
                    return Err(why);
                }
                for line in text.lines() {
                    if let Some(called) = line.strip_prefix("    uses: ") {
                        let called = called.trim();
                        if !called.starts_with("./.github/workflows/")
                            && !REMOTE_WORKFLOWS.iter().any(|(w, _)| *w == called)
                        {
                            return Err(format!(
                                "{name} calls the workflow `{called}`, outside this tree: its steps cannot be read here"
                            ));
                        }
                    }
                    scripts.extend(named_files(line));
                }
            }
            for action in composite_actions() {
                let name = action
                    .strip_prefix(root())
                    .unwrap_or(&action)
                    .display()
                    .to_string();
                let text = fs::read_to_string(&action).unwrap();
                if text.lines().any(runs_cargo_publish) {
                    return Err(format!(
                        "{name} runs `cargo publish`; release.yml's publish step alone may"
                    ));
                }
                if let Some(why) = stored_token(&name, &text) {
                    return Err(why);
                }
                for line in text.lines() {
                    scripts.extend(named_files(line));
                }
            }
            for script in scripts {
                let Ok(text) = fs::read_to_string(&script) else {
                    continue;
                };
                if text.lines().any(runs_cargo_publish) {
                    return Err(format!(
                        "{} runs `cargo publish`; release.yml's publish step alone may",
                        script.strip_prefix(root()).unwrap_or(&script).display()
                    ));
                }
            }
            Ok(vec![])
        },
    ),
    ("F8", "release.yml's two lines", |_| {
        require(
            &read(".github/workflows/release.yml")?,
            "*-beta.*) line=beta ;;",
            "release.yml",
        )?;
        Ok(vec![])
    }),
    ("F9", "src/script/flags.rs's ProtocolEra::at_height", |_| {
        let file = "src/script/flags.rs";
        let text = read(file)?;
        let at = text
            .find("if height < genesis_height {")
            .ok_or_else(|| format!("{file} has no era below Genesis"))?;
        let next = text[at..].lines().nth(1).unwrap_or("").trim();
        if next != "None" {
            return Err(format!(
                "{file}: a height below Genesis answers `{next}`, not `None`"
            ));
        }
        Ok(vec![])
    }),
    ("F10", "SECURITY.md's audit sentence", |line| {
        let security = read("SECURITY.md")?;
        require(
            &security,
            "This crate has had no third-party security audit.",
            "SECURITY.md",
        )?;
        require(
            &security,
            "The advisories published so far were found by this project's own reads",
            "SECURITY.md",
        )?;
        require(
            line,
            "https://github.com/Calhooon/bsv-rs/security/advisories",
            "the README's line",
        )?;
        Ok(vec![])
    }),
    ("F11", "the README itself: no performance figure", |_| {
        let readme = readme();
        for (n, line) in readme.lines().enumerate() {
            if let Some(unit) = performance_unit(&prose(line)) {
                return Err(format!(
                    "README.md:{}: a performance figure (`{unit}`): {line}",
                    n + 1
                ));
            }
        }
        Ok(vec![])
    }),
    (
        "F12",
        "release.yml's release page and CHANGELOG.md's migrations",
        |_| {
            require(
                &read(".github/workflows/release.yml")?,
                "gh release create",
                "release.yml",
            )?;
            require(&read("CHANGELOG.md")?, "Migration", "CHANGELOG.md")?;
            Ok(vec![])
        },
    ),
    ("F13", "docs/ARCHITECTURE.md", |_| {
        require(
            &read("docs/ARCHITECTURE.md")?,
            "## ",
            "docs/ARCHITECTURE.md",
        )?;
        Ok(vec![])
    }),
];

#[test]
fn no_version_is_named_before_the_examples() {
    let readme = readme();
    let text = before(&readme, EXAMPLES_HEADING);
    let mut found = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let chars: Vec<char> = line.chars().collect();
        let literal = (0..chars.len()).any(|i| {
            if i > 0 && chars[i - 1].is_ascii_digit() {
                return false;
            }
            let mut j = i;
            let mut parts = 0;
            loop {
                let start = j;
                while j < chars.len() && chars[j].is_ascii_digit() {
                    j += 1;
                }
                if j == start {
                    return false;
                }
                parts += 1;
                if parts == 3 {
                    return true;
                }
                // a two-part version (`0.8`, `"0.8"`, `bsv-rs@0.8`) goes stale at the next
                // minor as a three-part one does at the next patch (the reads of 2026-11-11)
                if chars.get(j) != Some(&'.') || !chars.get(j + 1).is_some_and(char::is_ascii_digit)
                {
                    return parts == 2;
                }
                j += 1;
            }
        });
        let pin = line.contains("\"=")
            || line.contains("@=")
            || line.contains("= \"=")
            || line.contains("bsv-rs@")
            || line.contains("bsv-rs = \"");
        let requirement = line.contains("version = \"");
        if literal || pin || requirement {
            found.push(format!("README.md:{}: {line}", n + 1));
        }
    }
    assert!(
        found.is_empty(),
        "the README names a version before `{EXAMPLES_HEADING}` (it ships frozen in every published crate; D1):\n{}",
        found.join("\n")
    );
}

#[test]
fn the_install_line_is_cargo_add_without_a_version() {
    let readme = readme();
    let at = readme
        .find(&format!("\n{INSTALL_HEADING}\n"))
        .expect("README.md has no `## Install`");
    let section = &readme[at + INSTALL_HEADING.len() + 2..];
    let fence = section.find("```").expect("`## Install` has no code block");
    let block = &section[fence + 3..];
    let (lang, body) = block.split_once('\n').unwrap();
    let body = &body[..body.find("```").expect("unclosed code block")];
    assert_eq!(
        (lang.trim(), body.trim_end()),
        ("sh", INSTALL),
        "the install block must be exactly ```sh\\n{INSTALL}\\n``` (D1)"
    );
}

#[test]
fn the_first_screen_fits_its_bound() {
    let readme = readme();
    let lines = first_screen(&readme).lines().count();
    assert!(
        lines <= FIRST_SCREEN_LINES,
        "the first screen is {lines} lines before `{INSTALL_HEADING}`; at most {FIRST_SCREEN_LINES}"
    );
}

#[test]
fn every_marked_sentence_is_worked_out_again_from_its_producer() {
    let readme = readme();
    let mut seen = BTreeSet::new();
    let mut failures = Vec::new();
    for (n, line) in first_screen(&readme).lines().enumerate() {
        let all = markers(line);
        if all.len() > 1 {
            failures.push(format!(
                "README.md:{}: the line carries {} markers ({}); a sentence carries one",
                n + 1,
                all.len(),
                all.join(", ")
            ));
        }
        let Some(id) = all.into_iter().next() else {
            continue;
        };
        if !seen.insert(id.clone()) {
            failures.push(format!("README.md:{}: marker {id} twice", n + 1));
            continue;
        }
        let Some((_, source, produce)) = PRODUCERS.iter().find(|(p, _, _)| *p == id) else {
            failures.push(format!(
                "README.md:{}: marker {id} has no producer in tests/front_page.rs (D3: a figure or claim stands only where this test works it out again)",
                n + 1
            ));
            continue;
        };
        match produce(line) {
            Err(why) => failures.push(format!(
                "README.md:{}: {id} ({source}): {why}; a claim whose producer this line lacks is absent from this line's README",
                n + 1
            )),
            Ok(mut want) => {
                let mut said = figures(&prose(line));
                said.sort_unstable();
                want.sort_unstable();
                if said != want {
                    failures.push(format!(
                        "README.md:{}: {id} says {said:?}; the tree says {want:?} ({source})",
                        n + 1
                    ));
                }
            }
        }
    }
    // a dropped marker is seen (#883's third fold): the loop above runs a producer only for the
    // markers it finds, so every producer's marker must be there, or its sentence goes unchecked
    for (id, source, _) in PRODUCERS {
        if !seen.contains(*id) {
            failures.push(format!(
                "marker {id} ({source}) is absent from the first screen: every producer's marker stands there once, or its sentence is checked by nothing (a sentence a line cannot back leaves with its producer)"
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// A publish job of `release.yml` with `steps` in place of its steps, for the token check's
/// plants below.
fn release_with(steps: &str) -> String {
    format!(
        "name: release\non:\n  push:\njobs:\n  publish:\n    runs-on: ubuntu-latest\n    steps:\n{steps}"
    )
}

/// The OIDC token line alone.
const TOKEN: &str = "CARGO_REGISTRY_TOKEN: ${{ steps.auth.outputs.token }}";

/// The token line, at the depth of a step's `env:` under a `- name:` step.
const TOKEN_ENV: &str =
    "        env:\n          CARGO_REGISTRY_TOKEN: ${{ steps.auth.outputs.token }}\n";

#[test]
fn the_token_line_is_read_in_the_publish_step_alone_and_an_unread_layout_is_refused() {
    let publish = "      - name: Publish\n        run: cargo publish\n";
    let accepted = [
        ("in the publish step", format!("{publish}{TOKEN_ENV}")),
        (
            "name: after run:",
            format!("      - run: cargo publish\n        name: Publish\n{TOKEN_ENV}"),
        ),
        (
            "a bare `-` opening the publish step",
            format!("      -\n        name: Publish\n        run: cargo publish\n{TOKEN_ENV}"),
        ),
        (
            "a literal block",
            format!("      - name: Publish\n        run: |\n          set -e\n          cargo publish\n{TOKEN_ENV}"),
        ),
        (
            "a folded block split over two lines",
            format!("      - name: Publish\n        run: >-\n          cargo\n          publish\n{TOKEN_ENV}"),
        ),
        (
            "an indentation indicator",
            format!("      - name: Publish\n        run: |2\n            cargo publish\n{TOKEN_ENV}"),
        ),
        (
            "a quoted run",
            format!("      - name: Publish\n        run: 'cargo publish'\n{TOKEN_ENV}"),
        ),
    ];
    for (layout, steps) in accepted {
        assert_eq!(
            stored_token("release.yml", &release_with(&steps)),
            None,
            "{layout}: the token line in the step that runs `cargo publish` is accepted"
        );
    }
    let refused = [
        (
            "a bare `-` step after the publish step",
            format!("{publish}      -\n        name: Other\n        run: echo hi\n{TOKEN_ENV}"),
            "release.yml sets or reads a registry token",
        ),
        (
            "a step named for `cargo publish` that packages",
            format!("      - name: Check cargo publish would work\n        run: cargo package\n{TOKEN_ENV}"),
            "release.yml sets or reads a registry token",
        ),
        (
            "`cargo publish` in a `with:` value",
            format!("      - uses: x/y@v1\n        with:\n          run: cargo publish\n{TOKEN_ENV}"),
            "release.yml sets or reads a registry token",
        ),
        (
            "a dry run",
            format!("      - name: Dry\n        run: cargo publish --dry-run\n{TOKEN_ENV}"),
            "release.yml sets or reads a registry token",
        ),
        (
            "flow-style steps",
            "      [ { run: cargo publish } ]\n".to_string(),
            "release.yml:8: a quoted scalar or a flow collection that is no key's value and no list item",
        ),
        (
            "an anchored run",
            format!("      - name: Publish\n        run: &r cargo publish\n{TOKEN_ENV}      - run: *r\n"),
            "release.yml:9: an anchor, an alias or a tag",
        ),
        (
            "a tab in the indentation",
            format!("      - name: Publish\n\t        run: cargo publish\n{TOKEN_ENV}"),
            "release.yml:9: a tab in the indentation",
        ),
        (
            "a merge key",
            format!("      - <<: {{ run: cargo publish }}\n{TOKEN_ENV}"),
            "release.yml:8: a merge key",
        ),
        (
            "a line between the key and the items",
            "        - name: Publish\n          run: cargo publish\n       x: 1\n".to_string(),
            "release.yml:10: a line whose indentation is no open level's",
        ),
        (
            "two runs in one step",
            format!("{publish}        run: echo\n"),
            "release.yml:10: a key written twice in one mapping",
        ),
        // #883's fifth fold: the narrow read of the fourth found four layouts where the token
        // line read as the publish step's and YAML puts it in a step that does not publish
        // (Psych 5.3.1): lines that look like a publish step inside a double-quoted (19b) or
        // single-quoted (20) value of several lines, or a `name:` of several lines (23), and a
        // `steps:` key inside a `with:` (10).
        (
            "a double-quoted value of several lines hiding a publish step (19b)",
            format!("      - name: Other\n        uses: x/y@v1\n        env:\n          X: \"\n      - run: cargo publish\n        env:\n        \"\n          {TOKEN}\n"),
            "release.yml:11: a quoted scalar that does not close on its line",
        ),
        (
            "a single-quoted value of several lines hiding a publish step (20)",
            format!("      - name: Other\n        env:\n          X: '\n      - run: cargo publish\n        env:\n        '\n          {TOKEN}\n"),
            "release.yml:10: a quoted scalar that does not close on its line",
        ),
        (
            "a quoted `name:` of several lines hiding a publish step (23)",
            format!("      - name: \"Other\n      - run: cargo publish\n        x\"\n{TOKEN_ENV}"),
            "release.yml:8: a quoted scalar that does not close on its line",
        ),
        (
            "a `steps:` key inside a `with:` (10)",
            format!("      - name: Other\n        uses: x/y@v1\n        with:\n          steps:\n            - run: cargo publish\n              env:\n                {TOKEN}\n"),
            "release.yml:11: a `steps:` key that is not a job's",
        ),
    ];
    for (layout, steps, expected) in refused {
        let why = stored_token("release.yml", &release_with(&steps));
        assert!(
            why.as_deref().is_some_and(|w| w.starts_with(expected)),
            "{layout}: expected a refusal beginning `{expected}`, got {why:?}"
        );
    }
    // #883's sixth fold: the narrow read of the fifth found the reader splitting on `\n` alone
    // where a YAML parser (Psych 5.3.1) also breaks a line at a lone `\r` (YAML 1.2), U+0085,
    // U+2028 and U+2029: a comment line holding a lone `\r` inserted after the tree's own
    // `run: cargo publish` opens, for the parser, a step `Other` holding the publish step's
    // `env:` and the token, and the reader of `c6c09e81` accepted it; so it did the three
    // Unicode breaks on the `run:` line's comment. Each is refused now by its code point.
    let tree = read(".github/workflows/release.yml").unwrap();
    let publish_at = tree
        .lines()
        .position(|l| l == "        run: cargo publish")
        .expect("release.yml's publish step");
    let mut planted: Vec<&str> = tree.lines().collect();
    planted.insert(publish_at + 1, "        # the publish\r      - name: Other");
    let planted = planted.join("\n") + "\n";
    assert_eq!(
        stored_token("release.yml", &planted),
        Some(format!(
            "release.yml:{}: the character U+000D, which this reader does not read",
            publish_at + 2
        )),
        "a lone CR in a comment of the tree's release.yml"
    );
    for (c, code) in [
        ('\u{85}', "U+0085"),
        ('\u{2028}', "U+2028"),
        ('\u{2029}', "U+2029"),
    ] {
        let steps = format!(
            "      - name: Publish\n        run: cargo publish # the publish{c}      - name: Other\n{TOKEN_ENV}"
        );
        assert_eq!(
            stored_token("release.yml", &release_with(&steps)),
            Some(format!(
                "release.yml:9: the character {code}, which this reader does not read"
            )),
            "{code} in a comment of the publish step's `run:` line"
        );
    }
    // A byte-order mark before a layout whose token YAML reads in the publish step: `c6c09e81`
    // accepted it, rightly for that layout (no step moves); it is refused as a character this
    // reader does not read, wherever it sits.
    let bom = format!("\u{feff}{}", release_with(&format!("{publish}{TOKEN_ENV}")));
    assert_eq!(
        stored_token("release.yml", &bom).as_deref(),
        Some("release.yml:1: the character U+FEFF, which this reader does not read")
    );
    let flow = release_with("").replace("    steps:\n", "    steps: [ { run: cargo publish } ]\n");
    assert_eq!(
        stored_token("release.yml", &flow).as_deref(),
        Some("release.yml:7: a `steps:` key this reader cannot place: `steps: [ { run: cargo publish } ]`")
    );
}

#[test]
fn the_composite_actions_are_counted() {
    let found = composite_actions();
    assert_eq!(
        found.len(),
        COMPOSITE_ACTIONS,
        "the tree holds {} composite actions ({found:?}); F7 reads each for `cargo publish` and a registry token: move `COMPOSITE_ACTIONS` with them",
        found.len()
    );
}

#[test]
fn every_figure_on_the_first_screen_carries_a_marker() {
    let readme = readme();
    let unmarked: Vec<String> = first_screen(&readme)
        .lines()
        .enumerate()
        .filter(|(_, l)| marker(l).is_none() && !figures(&prose(l)).is_empty())
        .map(|(n, l)| format!("README.md:{}: {l}", n + 1))
        .collect();
    assert!(
        unmarked.is_empty(),
        "a figure on the first screen with no marker (D3):\n{}",
        unmarked.join("\n")
    );
}

/// GitHub's anchor of a heading: lower case, letters, digits, `-` and `_` kept, spaces to `-`.
fn slug(heading: &str) -> String {
    heading
        .trim()
        .to_lowercase()
        .chars()
        .filter_map(|c| match c {
            ' ' => Some('-'),
            c if c.is_alphanumeric() || c == '-' || c == '_' => Some(c),
            _ => None,
        })
        .collect()
}

#[test]
fn every_relative_link_of_the_first_screen_resolves() {
    let readme = readme();
    let mut failures = Vec::new();
    for (n, line) in first_screen(&readme).lines().enumerate() {
        for piece in line.split("](").skip(1) {
            let target = &piece[..piece.find(')').unwrap_or(piece.len())];
            if target.starts_with("http://") || target.starts_with("https://") {
                continue;
            }
            let (path, anchor) = match target.split_once('#') {
                Some((p, a)) => (p, Some(a)),
                None => (target, None),
            };
            let file = root().join(if path.is_empty() { "README.md" } else { path });
            if !file.exists() {
                failures.push(format!(
                    "README.md:{}: `{target}` is not in the tree",
                    n + 1
                ));
                continue;
            }
            if let Some(anchor) = anchor {
                let text = fs::read_to_string(&file).unwrap_or_default();
                let found = text
                    .lines()
                    .filter_map(|l| l.strip_prefix('#'))
                    .map(|l| slug(l.trim_start_matches('#')))
                    .any(|s| s == anchor);
                if !found {
                    failures.push(format!(
                        "README.md:{}: `{target}`: no heading of {path} has the anchor `{anchor}`",
                        n + 1
                    ));
                }
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn every_badge_shows_a_status() {
    let readme = readme();
    let mut failures = Vec::new();
    for (n, line) in first_screen(&readme).lines().enumerate() {
        if line.contains("img.shields.io/crates/v/") {
            failures.push(format!(
                "README.md:{}: shields' crates.io version badge shows the newest prerelease, not the stable release",
                n + 1
            ));
        }
        let Some(at) = line.find("/actions/workflows/") else {
            continue;
        };
        let rest = &line[at + "/actions/workflows/".len()..];
        let workflow = &rest[..rest.find('/').unwrap_or(rest.len())];
        let text = read(&format!(".github/workflows/{workflow}")).unwrap_or_default();
        let on_main = text
            .split("\n  push:\n")
            .nth(1)
            .and_then(|p| p.lines().next())
            .is_some_and(|l| l.contains("branches:") && l.contains("main"));
        if !on_main || !rest.contains("branch=main") {
            failures.push(format!(
                "README.md:{}: the badge of {workflow} shows no status: the workflow is not run by a push to `main`, or the badge does not read `main`",
                n + 1
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn the_front_files_exist_and_the_manifest_owns_the_pages() {
    for file in ["README.md", "SECURITY.md", "LICENSE-MIT", "LICENSE-APACHE"] {
        assert!(root().join(file).is_file(), "{file} is not in the tree");
    }
    let manifest = read("Cargo.toml").unwrap();
    let package = manifest.split("\n[").next().unwrap();
    for field in [
        "documentation = \"https://docs.rs/bsv-rs\"",
        "readme = \"README.md\"",
        "license = \"MIT OR Apache-2.0\"",
    ] {
        assert!(
            package.lines().any(|l| l.trim() == field),
            "Cargo.toml's [package] lacks `{field}`: the manifest owns the crates.io and docs.rs pages"
        );
    }
}
