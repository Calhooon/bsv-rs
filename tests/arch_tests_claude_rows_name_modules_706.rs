//! Every `tests/CLAUDE.md` row names the modules its file reaches (#706).
//!
//! The nightly's run selection (#685) gives a measured file's mutants the binaries that
//! name its module: a `bsv_rs::<m>` path, a crate-root re-export, or the binary's row in
//! `tests/CLAUDE.md`'s `## Files` table naming it in its Modules cell
//! (`.github/scripts/affected_tests.py`, `used_modules` and `row_modules`). This guard
//! reads the table, `src/lib.rs`'s re-exports, the module directories under `src/` and
//! every top-level `tests/*.rs` with the module files it declares (nothing else; no
//! network, no environment) and refuses, naming the file and the missing modules, a
//! binary without a row and a row whose Modules cell names fewer modules than the
//! binary's source. A row shared by several files names each file's modules apart
//! (`` `a.rs`: `m`; `b.rs`: none ``), and a file's part is its reading, never the row's
//! union; the caller clause's judged pairs (`tests/caller_modules_706.txt`) are refused
//! when a row drops one (the #708 fold). `.github/scripts/rows_from_sources.py` writes the
//! cells from the same reading; its `--check` is this guard's twin for a reader without
//! cargo, and CI runs it beside the plan's own tests.
#![allow(clippy::expect_used, clippy::panic)] // Source reads are test assertions.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

/// The convention, as the refusal quotes it.
const CONVENTION: &str = "a row names, in its Modules cell, at least the modules its file's \
    source names by a `bsv_rs::` path or a crate-root re-export (tests/CLAUDE.md, ## Files)";

/// Never named in a row: a change to `src/error*` reaches every target already, and `util`
/// is crate-private.
const UNNAMED: &[&str] = &["error", "util"];

/// The table's fourth cell is the Modules cell.
const MODULES_CELL: usize = 4;

/// The caller clause's judged pairs, `<stem> <module>` per line (`#` a comment): the
/// clause is the writer's judgment, frozen here so no edit drops one with CI green.
const FROZEN: &str = "tests/caller_modules_706.txt";

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn is_word(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// The identifier at the start of `s`, if one starts there.
fn ident(s: &str) -> Option<&str> {
    let end = s.find(|c: char| !is_word(c)).unwrap_or(s.len());
    let word = &s[..end];
    (!word.is_empty() && !word.starts_with(|c: char| c.is_ascii_digit())).then_some(word)
}

/// The byte offsets just past each `<word>` in `text` that stands as a whole word.
fn word_ends(text: &str, word: &str) -> Vec<usize> {
    text.match_indices(word)
        .filter(|(at, _)| text[..*at].chars().next_back().is_none_or(|c| !is_word(c)))
        .map(|(at, _)| at + word.len())
        .collect()
}

/// The module directories under `src/`, less [`UNNAMED`].
fn modules(root: &Path) -> BTreeSet<String> {
    fs::read_dir(root.join("src"))
        .expect("src/")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|m| !UNNAMED.contains(&m.as_str()))
        .collect()
}

/// The crate root's `pub use <module>::...` names, each to its module: a type and a function
/// alike (`sha256`, `sign`: the fourteen lowercase names went uncounted before the #708 fold).
fn reexports(lib: &str) -> BTreeMap<String, String> {
    let mut names = BTreeMap::new();
    for start in word_ends(lib, "pub use ") {
        let rest = &lib[start..];
        let Some(module) =
            ident(rest).filter(|m| m.chars().all(|c| c.is_ascii_lowercase() || c == '_'))
        else {
            continue;
        };
        let Some(body) = rest[module.len()..].strip_prefix("::") else {
            continue;
        };
        let items = match body.strip_prefix('{') {
            Some(group) => &group[..group.find('}').unwrap_or(group.len())],
            None => ident(body).unwrap_or(""),
        };
        for item in items.split(|c: char| c == ',' || c.is_whitespace()) {
            let function = item.starts_with(|c: char| c.is_ascii_lowercase() || c == '_')
                && item
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
            if item != "as" && (function || item.starts_with(|c: char| c.is_ascii_uppercase())) {
                names.insert(item.to_string(), module.to_string());
            }
        }
    }
    names
}

/// The body of the brace group opening at `text[0]`, nested braces kept.
fn group_body(text: &str) -> &str {
    let mut depth = 0usize;
    for (at, c) in text.char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &text[1..at];
                }
            }
            _ => {}
        }
    }
    &text[1..]
}

/// The leading name of each top-level item of a `use` group.
fn group_heads(body: &str) -> Vec<String> {
    let code: String = body
        .lines()
        .map(|l| l.split("//").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n");
    let (mut heads, mut depth, mut item) = (Vec::new(), 0i32, String::new());
    for c in code.chars().chain(std::iter::once(',')) {
        match c {
            '{' => depth += 1,
            '}' => depth -= 1,
            _ => {}
        }
        if c == ',' && depth == 0 {
            if let Some(head) = ident(item.trim_start()) {
                heads.push(head.to_string());
            }
            item.clear();
        } else {
            item.push(c);
        }
    }
    heads
}

/// The modules a test source names: a `<crate>::<m>` path, or a root re-export named through
/// the crate (`<crate>::Name`, an item of a `<crate>::{...}` group; an alias of the crate is
/// read the same). A re-exported name met anywhere else is no use; a glob import of the
/// crate's root reads every re-exported type's word and every re-exported function as a bare
/// call (`sign(`, never `.sign(`, `x::sign(` or `fn sign(`), the names it imports unlisted.
/// (Written with `<crate>` for `bsv_rs`: this file's own text names no module.)
fn used_modules(
    text: &str,
    modules: &BTreeSet<String>,
    exported: &BTreeMap<String, String>,
) -> BTreeSet<String> {
    let mut crates = vec!["bsv_rs".to_string()];
    for end in word_ends(text, "bsv_rs") {
        let rest = &text[end..];
        let spaced = rest.trim_start();
        if spaced.len() < rest.len() {
            if let Some(alias) = spaced
                .strip_prefix("as")
                .filter(|r| r.starts_with(char::is_whitespace))
            {
                if let Some(name) = ident(alias.trim_start()) {
                    crates.push(name.to_string());
                }
            }
        }
    }
    let mut found = BTreeSet::new();
    for krate in &crates {
        let mut heads = Vec::new();
        let mut glob = false;
        for end in word_ends(text, &format!("{krate}::")) {
            let rest = &text[end..];
            if rest.starts_with('{') {
                heads.extend(group_heads(group_body(rest)));
            } else if rest.starts_with('*') {
                glob = true;
            } else if let Some(head) = ident(rest) {
                heads.push(head.to_string());
            }
        }
        if glob {
            let words = text.split(|c: char| !is_word(c));
            heads.extend(
                words
                    .filter(|w| w.starts_with(|c: char| c.is_ascii_uppercase()))
                    .filter(|w| exported.contains_key(*w))
                    .map(str::to_string),
            );
            for name in exported
                .keys()
                .filter(|n| !n.starts_with(|c: char| c.is_ascii_uppercase()))
            {
                let bare = word_ends(text, name).into_iter().any(|end| {
                    let before = &text[..end - name.len()];
                    text[end..].trim_start().starts_with('(')
                        && !before.ends_with(['.', ':'])
                        && !before.ends_with("fn ")
                });
                if bare {
                    heads.push(name.clone());
                }
            }
        }
        for head in heads {
            if modules.contains(&head) {
                found.insert(head);
            } else if let Some(module) = exported.get(&head) {
                found.insert(module.clone());
            }
        }
    }
    found.retain(|m| modules.contains(m));
    found
}

/// `a/./b/../c` to `a/c`, as `os.path.normpath` reads it.
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for part in path.components() {
        match part {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other),
        }
    }
    out
}

/// The `mod` declarations of a source: (the `#[path]` value if any, the module's name).
fn declarations(text: &str) -> Vec<(Option<String>, String)> {
    let mut found = Vec::new();
    for end in word_ends(text, "mod") {
        let rest = &text[end..];
        let spaced = rest.trim_start();
        if spaced.len() == rest.len() {
            continue;
        }
        let Some(name) = ident(spaced).filter(|n| {
            n.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        }) else {
            continue;
        };
        if !spaced[name.len()..].trim_start().starts_with(';') {
            continue;
        }
        let mut before = text[..end - 3].trim_end();
        let visibility = before.strip_suffix(')').and_then(|b| b.rfind("pub("));
        if let Some(open) = visibility.filter(|&at| !before[at..].contains(['\n', ';'])) {
            before = before[..open].trim_end();
        } else if let Some(stripped) = before.strip_suffix("pub") {
            before = stripped.trim_end();
        }
        let path = before.strip_suffix(']').and_then(|b| {
            let attribute = &b[b.rfind("#[")? + 2..];
            let value = attribute
                .strip_prefix("path")?
                .trim_start()
                .strip_prefix('=')?
                .trim();
            Some(value.strip_prefix('"')?.strip_suffix('"')?.to_string())
        });
        found.push((path, name.to_string()));
    }
    found
}

/// A file and every module file it declares, transitively (`mod x;`, `#[path]`).
fn module_sources(root: &Path, file: &Path) -> Vec<PathBuf> {
    let (mut seen, mut todo) = (Vec::new(), vec![file.to_path_buf()]);
    while let Some(path) = todo.pop() {
        if seen.contains(&path) || !root.join(&path).is_file() {
            continue;
        }
        seen.push(path.clone());
        let text = read(&root.join(&path));
        let parent = path.parent().unwrap_or(Path::new("")).to_path_buf();
        let is_root = parent == Path::new("tests");
        let home = if is_root || path.file_name().is_some_and(|n| n == "mod.rs") {
            parent.clone()
        } else {
            path.with_extension("")
        };
        for (attribute, name) in declarations(&text) {
            match attribute {
                Some(target) => todo.push(normalize(&parent.join(target))),
                None => {
                    todo.push(home.join(format!("{name}.rs")));
                    todo.push(home.join(&name).join("mod.rs"));
                }
            }
        }
    }
    seen
}

/// A table row's cells, the outer pipes dropped (a `\|` inside a cell kept).
fn cells(row: &str) -> Vec<String> {
    let (mut out, mut cell, mut escaped) = (Vec::new(), String::new(), false);
    for c in row.trim().chars() {
        if c == '|' && !escaped {
            out.push(std::mem::take(&mut cell).trim().to_string());
        } else {
            cell.push(c);
        }
        escaped = c == '\\';
    }
    out.push(cell.trim().to_string());
    out[1..out.len().saturating_sub(1).max(1)].to_vec()
}

/// The backticked spans of a text.
fn ticked(text: &str) -> Vec<&str> {
    text.split('`').skip(1).step_by(2).collect()
}

/// A file's stem, the key every reader of the table uses: `support/a.rs` and `a.rs` are `a`.
fn stem(name: &str) -> &str {
    let file = name.strip_suffix(".rs").unwrap_or(name);
    file.rsplit('/').next().unwrap_or(file)
}

/// `tests/CLAUDE.md`'s `## Files` rows: each row's line number, its text and its File cell's
/// `.rs` names, the one reading of the table for `test_rows` and `doubled_rows` (#712).
fn table_rows(text: &str) -> Vec<(usize, &str, Vec<&str>)> {
    let (mut rows, mut inside) = (Vec::new(), false);
    for (index, line) in text.lines().enumerate() {
        if line.starts_with("## ") {
            inside = line.trim() == "## Files";
        } else if inside && line.starts_with("| `") {
            let file_cell = line.split('|').nth(1).unwrap_or("");
            let names = ticked(file_cell).into_iter().filter(|n| n.ends_with(".rs"));
            rows.push((index + 1, line, names.collect()));
        }
    }
    rows
}

/// `tests/CLAUDE.md`'s file table: each test file's stem to its row.
fn test_rows(text: &str) -> BTreeMap<String, String> {
    let mut rows = BTreeMap::new();
    for (_, line, names) in table_rows(text) {
        for name in names {
            rows.insert(stem(name).to_string(), line.to_string());
        }
    }
    rows
}

/// The stems named in two or more rows of the table (#712): every reader keys the rows by
/// the stem (`test_rows` here, `rows[Path(name).stem]` in the scripts) and keeps the last, so
/// an edit to another copy is never read, `support/a.rs` beside `a.rs` included. One refusal
/// per stem, naming its files and each row's line in `tests/CLAUDE.md`.
fn doubled_rows(text: &str) -> Vec<String> {
    let mut seen: BTreeMap<&str, (Vec<&str>, Vec<usize>)> = BTreeMap::new();
    for (number, _, names) in table_rows(text) {
        for name in names {
            let (files, at) = seen.entry(stem(name)).or_default();
            if !files.contains(&name) {
                files.push(name);
            }
            if at.last() != Some(&number) {
                at.push(number);
            }
        }
    }
    seen.into_iter()
        .filter(|(_, (_, at))| at.len() > 1)
        .map(|(stem, (files, at))| {
            let files: Vec<String> = files.iter().map(|f| format!("tests/{f}")).collect();
            let at: Vec<String> = at.iter().map(usize::to_string).collect();
            format!(
                "{}: {} rows of the stem `{stem}` in tests/CLAUDE.md's ## Files table, at \
                 lines {}; one row per stem (the readers key the rows by the stem and keep \
                 the last)",
                files.join(" and "),
                at.len(),
                at.join(" and ")
            )
        })
        .collect()
}

/// A shared row's Modules cell, file by file (`` `a.rs`: `m`, `n`; `b.rs`: none ``): each
/// file's stem to its modules' names; `None` when the cell names no file.
fn shared_cell(cell: &str) -> Option<BTreeMap<String, Vec<String>>> {
    if !ticked(cell).iter().any(|n| n.ends_with(".rs")) {
        return None;
    }
    let mut parts = BTreeMap::new();
    for part in cell.split(';') {
        let names = ticked(part);
        if let Some(file) = names.first().filter(|n| n.ends_with(".rs")) {
            let stem = stem(file);
            let own = names[1..].iter().filter(|n| !n.ends_with(".rs"));
            parts.insert(stem.to_string(), own.map(|n| n.to_string()).collect());
        }
    }
    Some(parts)
}

/// The modules a row names for `stem`: the backticked names of its Modules cell, or in a
/// shared row the file's own part (the row's union is no file's); a row of fewer cells names
/// none, and a path in the description (`src/<m>/`, `` `<m>::` ``) names nothing.
fn row_modules(row: &str, modules: &BTreeSet<String>, stem: &str) -> BTreeSet<String> {
    let cells = cells(row);
    if cells.len() <= MODULES_CELL {
        return BTreeSet::new();
    }
    let cell = &cells[MODULES_CELL - 1];
    let named: Vec<String> = match shared_cell(cell) {
        Some(parts) => parts.get(stem).cloned().unwrap_or_default(),
        None => ticked(cell).into_iter().map(str::to_string).collect(),
    };
    named.into_iter().filter(|m| modules.contains(m)).collect()
}

/// The `.rs` names of a row's File cell.
fn row_files(row: &str) -> Vec<String> {
    let cells = cells(row);
    let file = cells.first().map(String::as_str).unwrap_or("");
    ticked(file)
        .into_iter()
        .filter(|n| n.ends_with(".rs"))
        .map(str::to_string)
        .collect()
}

/// The frozen pairs: each stem to the modules its row must keep.
fn frozen(text: &str) -> BTreeMap<String, BTreeSet<String>> {
    let mut pairs: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for line in text.lines() {
        let words: Vec<&str> = line
            .split('#')
            .next()
            .unwrap_or("")
            .split_whitespace()
            .collect();
        if let [stem, module] = words[..] {
            pairs
                .entry(stem.to_string())
                .or_default()
                .insert(module.to_string());
        } else {
            assert!(
                words.is_empty(),
                "{FROZEN}: `{line}` is no `<stem> <module>` pair"
            );
        }
    }
    pairs
}

/// The refusals: a binary without a row, a row naming fewer modules than its source, a
/// shared row without a part for the file, a row dropping a frozen module, a frozen pair
/// naming no binary.
fn refusals(
    sources: &BTreeMap<String, BTreeSet<String>>,
    rows: &BTreeMap<String, String>,
    modules: &BTreeSet<String>,
    pinned: &BTreeMap<String, BTreeSet<String>>,
) -> Vec<String> {
    let mut out = Vec::new();
    for (binary, used) in sources {
        let Some(row) = rows.get(binary) else {
            out.push(format!(
                "tests/{binary}.rs: no row in tests/CLAUDE.md's ## Files table; {CONVENTION}"
            ));
            continue;
        };
        let cells = cells(row);
        if row_files(row).len() > 1 && cells.len() > MODULES_CELL {
            let parts = shared_cell(&cells[MODULES_CELL - 1]);
            if !parts.is_some_and(|p| p.contains_key(binary)) {
                out.push(format!(
                    "tests/{binary}.rs: its row is shared and its Modules cell has no part for it \
                     (`{binary}.rs`: ...); {CONVENTION}"
                ));
                continue;
            }
        }
        let named = row_modules(row, modules, binary);
        let missing: Vec<_> = used.difference(&named).map(String::as_str).collect();
        if !missing.is_empty() {
            out.push(format!(
                "tests/{binary}.rs: its row does not name {}; {CONVENTION}",
                missing.join(", ")
            ));
        }
        let kept = pinned.get(binary).cloned().unwrap_or_default();
        let dropped: Vec<_> = kept.difference(&named).map(String::as_str).collect();
        if !dropped.is_empty() {
            out.push(format!(
                "tests/{binary}.rs: its row drops {}, frozen in {FROZEN} (the caller clause's judgment)",
                dropped.join(", ")
            ));
        }
    }
    for stem in pinned.keys().filter(|s| !sources.contains_key(*s)) {
        out.push(format!("{FROZEN}: {stem} names no integration binary"));
    }
    out
}

/// Each top-level `tests/*.rs` binary to the modules its source names.
fn tree_sources(root: &Path) -> (BTreeMap<String, BTreeSet<String>>, BTreeSet<String>) {
    let modules = modules(root);
    let exported = reexports(&read(&root.join("src/lib.rs")));
    let mut sources = BTreeMap::new();
    for entry in fs::read_dir(root.join("tests"))
        .expect("tests/")
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "rs") {
            continue;
        }
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .expect("a stem")
            .to_string();
        let text: Vec<String> =
            module_sources(root, &Path::new("tests").join(format!("{stem}.rs")))
                .iter()
                .map(|p| read(&root.join(p)))
                .collect();
        sources.insert(stem, used_modules(&text.join("\n"), &modules, &exported));
    }
    (sources, modules)
}

#[test]
fn every_tests_claude_row_names_the_modules_its_source_names_706() {
    let root = root();
    let (sources, modules) = tree_sources(&root);
    assert!(
        sources.len() > 250,
        "the walk found {} binaries",
        sources.len()
    );
    let table = read(&root.join("tests/CLAUDE.md"));
    let rows = test_rows(&table);
    let pinned = frozen(&read(&root.join(FROZEN)));
    assert!(pinned.len() >= 6, "{FROZEN} holds {} pairs", pinned.len());
    let mut refused = doubled_rows(&table);
    refused.extend(refusals(&sources, &rows, &modules, &pinned));
    assert!(
        refused.is_empty(),
        "{} refusals over {} binaries (.github/scripts/rows_from_sources.py writes the cells):\n{}",
        refused.len(),
        sources.len(),
        refused.join("\n")
    );
}

fn fixture_modules() -> BTreeSet<String> {
    ["auth", "identity", "script", "transaction", "wallet"]
        .map(String::from)
        .into()
}

fn fixture_exports() -> BTreeMap<String, String> {
    reexports(
        "pub use script::{Address, Script};\npub use transaction::Transaction;\n\
         pub use auth::{Certificate, Transport};\npub use wallet::{Protocol, WalletFaultFamily};\n",
    )
}

/// The modules a fixture names, `KRATE` read as the crate's name: this file's own text then
/// names no module, so the reading puts this binary in no module's set.
fn used(text: &str) -> Vec<String> {
    let text = text.replace("KRATE", "bsv_rs");
    used_modules(&text, &fixture_modules(), &fixture_exports())
        .into_iter()
        .collect()
}

#[test]
fn a_re_export_met_outside_the_crate_path_is_no_use_706() {
    // The word reading these replaced took each of these for a use (`wallet_fault_439`,
    // `integration_tests`, `overlay_admin_token_envelope_544`, `identity_lone_surrogate_566`).
    assert_eq!(
        used("use KRATE::WalletFaultFamily;\nlet f = WalletFaultFamily::Transport;"),
        ["wallet"]
    );
    assert_eq!(
        used("use KRATE::{Transaction};\n// WIF and Address Roundtrip\n"),
        ["transaction"]
    );
    assert_eq!(used("use KRATE::script::{Protocol};\n"), ["script"]);
    assert_eq!(
        used("//! the Certificate's signature\nuse KRATE::wallet::x;\n"),
        ["wallet"]
    );
}

#[test]
fn a_re_export_named_through_the_crate_is_a_use() {
    assert_eq!(used("let t = KRATE::Transaction::new();"), ["transaction"]);
    assert_eq!(
        used("use KRATE::{\n    // a comment's Certificate\n    Script,\n    auth::{x, y},\n};"),
        ["auth", "script"]
    );
    assert_eq!(
        used("use KRATE as sdk;\nlet c = sdk::Certificate::default();"),
        ["auth"]
    );
    assert_eq!(used("use KRATE::*;\nlet t: Transaction;"), ["transaction"]);
    assert_eq!(
        used("use KRATE::identity::Client;\nlet n = KRATE::nothing;"),
        ["identity"]
    );
}

#[test]
fn a_description_path_names_no_module_706() {
    // `auth_certificate_field_value_261`'s row points at the identity unit tests; the
    // description reading put the auth binary in identity's set.
    let row = "| `a_261.rs` | 8 | `auth` | `auth`, `wallet` | witnesses are `src/identity/x_tests.rs` and `transaction::Beef` |";
    assert_eq!(
        row_modules(row, &fixture_modules(), "a_261"),
        ["auth", "wallet"].map(String::from).into()
    );
    let four = "| `a_261.rs` | 8 | `auth` | `src/identity/x.rs` |";
    assert!(row_modules(four, &fixture_modules(), "a_261").is_empty());
}

#[test]
fn a_row_naming_fewer_and_a_binary_without_a_row_are_refused() {
    let sources: BTreeMap<String, BTreeSet<String>> = [
        (
            "a".to_string(),
            ["script", "wallet"].map(String::from).into(),
        ),
        ("b".to_string(), BTreeSet::new()),
        ("c".to_string(), ["auth"].map(String::from).into()),
    ]
    .into();
    let rows = test_rows(
        "## Files\n\n| File | Tests | Feature Gate | Modules | Description |\n|-|-|-|-|-|\n\
         | `a.rs` | 1 | default | `script` | text |\n| `b.rs` | 1 | default | none | text |\n",
    );
    assert_eq!(
        refusals(&sources, &rows, &fixture_modules(), &BTreeMap::new()),
        [
            format!("tests/a.rs: its row does not name wallet; {CONVENTION}"),
            format!("tests/c.rs: no row in tests/CLAUDE.md's ## Files table; {CONVENTION}"),
        ]
    );
}

#[test]
fn a_shared_row_names_each_file_apart_and_its_union_is_no_file_s_708() {
    // the #537 and #544 rows' union put all twelve binaries in modules their sources never
    // name (the cold read's FIX): a file's part is its reading
    let rows = test_rows("## Files\n| `x_537.rs`, `y_537.rs` | 2 each | `a`, `b` | `x_537.rs`: `auth`, `identity`; `y_537.rs`: `script` | d |\n## Next\n| `z.rs` | 1 | d | `script` | d |\n");
    assert_eq!(rows.keys().collect::<Vec<_>>(), ["x_537", "y_537"]);
    let named = |stem: &str| row_modules(&rows[stem], &fixture_modules(), stem);
    assert_eq!(
        named("x_537"),
        ["auth", "identity"].map(String::from).into()
    );
    assert_eq!(named("y_537"), ["script"].map(String::from).into());
    let sources: BTreeMap<String, BTreeSet<String>> = [
        ("x_537".to_string(), ["auth"].map(String::from).into()),
        ("y_537".to_string(), ["script"].map(String::from).into()),
    ]
    .into();
    let none = BTreeMap::new();
    assert!(refusals(&sources, &rows, &fixture_modules(), &none).is_empty());
    // a union cell over a shared row is refused for each file
    let union = test_rows(
        "## Files\n| `x_537.rs`, `y_537.rs` | 2 each | `a`, `b` | `auth`, `script` | d |\n",
    );
    assert_eq!(
        refusals(&sources, &union, &fixture_modules(), &none),
        ["x_537", "y_537"].map(|b| format!(
            "tests/{b}.rs: its row is shared and its Modules cell has no part for it \
             (`{b}.rs`: ...); {CONVENTION}"
        ))
    );
}

#[test]
fn a_lowercase_root_re_export_is_a_use_708() {
    // `<crate>::sha256`, `<crate>::sign`: the fourteen lowercase names of the crate root went
    // uncounted, against the convention's "a crate-root re-export"
    let exported = reexports("pub use script::{sha256, Script};\npub use wallet::sign;\n");
    assert_eq!(exported.get("sha256").map(String::as_str), Some("script"));
    assert_eq!(exported.get("sign").map(String::as_str), Some("wallet"));
    let used = |text: &str| -> Vec<String> {
        let text = text.replace("KRATE", "bsv_rs");
        used_modules(&text, &fixture_modules(), &exported)
            .into_iter()
            .collect()
    };
    assert_eq!(used("let h = KRATE::sha256(b\"x\");"), ["script"]);
    assert_eq!(used("use KRATE::{sign, Script};"), ["script", "wallet"]);
    // a glob reads a function only as a bare call, never a word, a method or a definition
    assert!(used("use KRATE::*;\n// sign here\nx.sign();\nfn sign() {}").is_empty());
    assert_eq!(used("use KRATE::*;\nlet s = sign(&k);"), ["wallet"]);
}

#[test]
fn a_row_dropping_a_frozen_caller_module_is_refused_708() {
    // the caller clause is a judgment; its pairs are frozen so a later edit cannot drop one
    let pinned = frozen("# judged\nb_623 script  # spends\n\n");
    assert_eq!(pinned.len(), 1);
    let sources: BTreeMap<String, BTreeSet<String>> = [(
        "b_623".to_string(),
        ["transaction"].map(String::from).into(),
    )]
    .into();
    let kept = test_rows("## Files\n| `b_623.rs` | 1 | d | `script`, `transaction` | d |\n");
    assert!(refusals(&sources, &kept, &fixture_modules(), &pinned).is_empty());
    let dropped = test_rows("## Files\n| `b_623.rs` | 1 | d | `transaction` | d |\n");
    assert_eq!(
        refusals(&sources, &dropped, &fixture_modules(), &pinned),
        [format!(
            "tests/b_623.rs: its row drops script, frozen in {FROZEN} (the caller clause's judgment)"
        )]
    );
    let stale = frozen("gone_9 script\n");
    assert_eq!(
        refusals(&sources, &kept, &fixture_modules(), &stale),
        [format!("{FROZEN}: gone_9 names no integration binary")]
    );
}

#[test]
fn the_frozen_pairs_are_the_six_caller_rows_708() {
    let pinned = frozen(&read(&root().join(FROZEN)));
    let pairs: Vec<(String, String)> = pinned
        .iter()
        .flat_map(|(s, ms)| ms.iter().map(move |m| (s.clone(), m.clone())))
        .collect();
    let expected = [
        ("auth_fetch_423_payment", "transaction"),
        ("beef_order_held", "script"),
        ("beef_stream_603_s4", "script"),
        ("registry_integration_tests", "script"),
        ("wallet_http_json_pending_432", "transaction"),
        ("wallet_http_json_success_bytes_365", "transaction"),
    ]
    .map(|(s, m)| (s.to_string(), m.to_string()));
    assert_eq!(pairs, expected);
}

#[test]
fn the_module_sources_follow_mod_and_path_declarations() {
    let text =
        "mod support;\n#[path = \"support/a.rs\"]\npub(crate) mod a;\n// mod ghost\nfn f() {}\n";
    assert_eq!(
        declarations(text),
        [
            (None, "support".to_string()),
            (Some("support/a.rs".to_string()), "a".to_string())
        ]
    );
    let sources = module_sources(
        &root(),
        Path::new("tests/arch_tests_claude_rows_name_modules_706.rs"),
    );
    assert_eq!(
        sources,
        [PathBuf::from(
            "tests/arch_tests_claude_rows_name_modules_706.rs"
        )]
    );
}

#[test]
fn the_crate_root_re_exports_resolve_to_their_modules() {
    let exported = reexports(&read(&root().join("src/lib.rs")));
    for (name, module) in [
        ("Transaction", "transaction"),
        ("Script", "script"),
        ("TotpAlgorithm", "totp"),
    ] {
        assert_eq!(
            exported.get(name).map(String::as_str),
            Some(module),
            "{name}"
        );
    }
}

#[test]
fn a_file_named_in_two_rows_is_refused_with_both_lines_712() {
    let text = "| `a.rs` | 1 | d | `script` | d |\n## Files\n| File | Tests |\n\
        | `a.rs` | 1 | d | `script` | d |\n| `b.rs`, `a.rs` | 1 each | d | `b.rs`: none; `a.rs`: none | d |\n\
        | `c.rs` | 1 | d | none | names `a.rs` in its description |\n| `c.rs` | 1 | d | none | d |\n\
        ## Next\n| `c.rs` | 1 | d | none | d |\n";
    assert_eq!(
        doubled_rows(text),
        [
            "tests/a.rs: 2 rows of the stem `a` in tests/CLAUDE.md's ## Files table, at lines \
             4 and 5; one row per stem (the readers key the rows by the stem and keep the last)",
            "tests/c.rs: 2 rows of the stem `c` in tests/CLAUDE.md's ## Files table, at lines \
             6 and 7; one row per stem (the readers key the rows by the stem and keep the last)",
        ]
    );
    assert!(doubled_rows("## Files\n| `a.rs` | 1 |\n| `b.rs` | 1 |\n").is_empty());
}

#[test]
fn a_support_file_beside_a_top_level_file_of_its_stem_is_two_rows_712() {
    let text = "## Files\n| `a.rs` | 1 | d | none | d |\n| `b.rs` | 1 | d | none | d |\n\
        | `support/a.rs` | 1 | none | none | d |\n";
    // the readers hold one row for the stem, the later one
    assert_eq!(test_rows(text).len(), 2);
    assert!(test_rows(text)["a"].starts_with("| `support/a.rs`"));
    assert_eq!(
        doubled_rows(text),
        [
            "tests/a.rs and tests/support/a.rs: 2 rows of the stem `a` in tests/CLAUDE.md's \
             ## Files table, at lines 2 and 4; one row per stem (the readers key the rows by the \
             stem and keep the last)"
        ]
    );
}
