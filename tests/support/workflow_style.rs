//! The plain style of the workflows and the reader of their key paths (#1034's fourth and fifth
//! folds), shared by `tests/arch_workflow_plain_style_1034.rs` (the style's rules, each refusal
//! on a planted text) and `tests/arch_workflow_pinned_sets_1034.rs` (the pinned sets read
//! through [`key_paths`]).
//!
//! The grammar, line by line (a line is the text between two line feeds):
//!
//! - the file is a `.yml` or `.yaml` file directly under `.github/workflows/`, every other
//!   entry of the folder refused by its name;
//! - no character but the line feed below U+0020, no U+007F, U+0085, U+2028, U+2029 or U+FEFF
//!   anywhere (a line break or a byte-order mark to some YAML reader);
//! - a blank line, or a comment line (`#` after spaces alone);
//! - a key line: spaces, then at most one `- `, then a name of `[A-Za-z0-9_][A-Za-z0-9_.-]*`,
//!   a colon, then the end of the line or one space and a value;
//! - an item line: spaces, `- `, then a value;
//! - a value is a plain scalar (no leading indicator, no `: `, not ending in `:`), a quoted
//!   scalar closed on its line with no escape (`\` in double quotes, `''` in single quotes),
//!   the empty mapping `{}`, a flow sequence closed on its line of plain words or quoted
//!   scalars, or, for a key of [`PROSE_KEYS`] alone, a block scalar header `|` or `>` with an
//!   optional chomping indicator and no indentation indicator; a trailing ` #` comment allowed;
//! - the lines of a block scalar's body are its own (blank, or indented past the key), and the
//!   body ends at the first line that is not;
//! - after a line whose value is on it, the next line is indented no deeper than that line's
//!   key (or its `- `): a deeper one would continue a plain scalar over lines;
//! - the indentation (the fifth fold): a block opened under a key (a mapping, or a sequence of
//!   `- ` items) is [`INDENT`] spaces past that key's column, never at the key's own column; a
//!   `- ` is followed by one space alone, so an item's mapping opens at the dash's column plus
//!   two; every other line is at the column of a block still open;
//! - no key twice in one mapping (a parser keeps the later, a reader the earlier).
//!
//! Read at the string level; no network, no environment.
#![allow(dead_code)]
#![allow(clippy::expect_used, clippy::panic)] // Source reads are test assertions.

use std::collections::BTreeSet;

/// The keys whose value may be a block scalar: a step's script (`run`) and `actions/github-script`'s
/// script (`script`). A block scalar's body is text to the parser, so no key hides in it, and a
/// reader of keys does not read it.
pub const PROSE_KEYS: [&str; 7] = [
    "run",
    "script",
    "if",
    "path",
    "restore-keys",
    "sparse-checkout",
    "VERDICTS",
];

pub const BREAK: &str = "holds a character that is a line break or a byte-order mark to some YAML reader, or a control character";

/// A refusal: `file line N: what`.
pub fn at(file: &str, line: usize, what: &str) -> String {
    format!("{file} line {line}: {what} (the plain style, #1034)")
}

/// The value of a key or an item, as the style reads it: `Ok(None)` for a plain or quoted
/// scalar, `{}` or a flow sequence; `Ok(Some(()))` for a block scalar header; `Err` for a form
/// the style refuses.
pub fn value_form(value: &str) -> Result<bool, &'static str> {
    let value = strip_comment(value)?;
    let value = value.trim_end_matches(' ');
    if value.is_empty() {
        return Ok(false);
    }
    let first = value.chars().next().unwrap_or(' ');
    match first {
        '|' | '>' => {
            let rest = &value[1..];
            if rest.is_empty() || rest == "-" || rest == "+" {
                Ok(true)
            } else {
                Err("a block scalar header other than `|`, `>` and their chomping forms (an indentation indicator)")
            }
        }
        '"' | '\'' => quoted_end(value)
            .filter(|&end| end == value.len())
            .map(|_| false)
            .ok_or("a quoted scalar that is not closed on its line, holds an escape (`\\` or `''`) or has text after it"),
        '[' => flow_sequence(value).map(|()| false),
        '{' if value == "{}" => Ok(false),
        '{' => Err("a flow mapping (`{...}`), whose keys a reader of lines does not read"),
        '&' | '*' => Err("an anchor or an alias"),
        '!' => Err("a tag"),
        '?' => Err("an explicit key (`?`)"),
        '%' | '@' | '`' | ',' | ']' | '}' | '#' | ':' => Err("a scalar opening with a YAML indicator"),
        '-' if value == "-" || value.starts_with("- ") => {
            Err("a sequence inside a sequence on one line")
        }
        _ => plain(value).map(|()| false),
    }
}

/// The value with a trailing ` #` comment removed, a quoted scalar read to its close first.
pub fn strip_comment(value: &str) -> Result<&str, &'static str> {
    if value.starts_with('"') || value.starts_with('\'') {
        let Some(end) = quoted_end(value) else {
            return Err(
                "a quoted scalar that is not closed on its line or holds an escape (`\\` or `''`)",
            );
        };
        let rest = &value[end..];
        let trimmed = rest.trim_start_matches(' ');
        if trimmed.is_empty() || (trimmed.starts_with('#') && rest.starts_with(' ')) {
            return Ok(&value[..end]);
        }
        return Err("text after a quoted scalar");
    }
    if value.starts_with('[') {
        let Some(end) = value.find(']') else {
            return Err("a flow sequence that is not closed on its line");
        };
        let rest = &value[end + 1..];
        let trimmed = rest.trim_start_matches(' ');
        if trimmed.is_empty() || (trimmed.starts_with('#') && rest.starts_with(' ')) {
            return Ok(&value[..=end]);
        }
        return Err("text after a flow sequence");
    }
    Ok(value.find(" #").map_or(value, |at| &value[..at]))
}

/// The byte just past a quoted scalar's closing quote, when it closes on the text and holds no
/// escape.
pub fn quoted_end(value: &str) -> Option<usize> {
    let quote = value.chars().next()?;
    let body = &value[1..];
    let close = body.find(quote)?;
    let inner = &body[..close];
    let after = &body[close + 1..];
    if quote == '"' && inner.contains('\\') {
        return None;
    }
    if quote == '\'' && after.starts_with('\'') {
        return None;
    }
    Some(close + 2)
}

/// A plain scalar on one line: no `: ` inside and no `:` at its end (either would open a
/// mapping, or be no YAML), no tab.
pub fn plain(value: &str) -> Result<(), &'static str> {
    if value.contains(": ") || value.ends_with(':') {
        return Err("a plain scalar holding `: ` or ending in `:`");
    }
    Ok(())
}

/// A flow sequence of words or quoted scalars, closed on its line: in a flow, a `{`, a `[`, a
/// `?` or a `: ` would open a mapping, so an item holds none of them.
pub fn flow_sequence(value: &str) -> Result<(), &'static str> {
    const WRONG: &str = "a flow sequence with an item other than a plain word or a quoted scalar (a flow item can be a mapping)";
    let inner = value
        .strip_prefix('[')
        .and_then(|v| v.strip_suffix(']'))
        .ok_or(WRONG)?;
    if inner.trim().is_empty() {
        return Ok(());
    }
    for item in inner.split(',') {
        let item = item.trim_matches(' ');
        let ok = if item.starts_with('"') || item.starts_with('\'') {
            quoted_end(item) == Some(item.len())
        } else {
            !item.is_empty()
                && item
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_./*+-".contains(&b))
                && !item.starts_with('-')
        };
        if !ok {
            return Err(WRONG);
        }
    }
    Ok(())
}

/// A key's name at the start of `rest`, and the text after its `: ` (or `None` at the line's
/// end), when `rest` opens with a key in the plain style.
pub fn plain_key(rest: &str) -> Option<(&str, Option<&str>)> {
    let colon = rest.find(':')?;
    let name = &rest[..colon];
    let mut bytes = name.bytes();
    let lead = bytes.next()?;
    if !(lead.is_ascii_alphanumeric() || lead == b'_')
        || !bytes.all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
    {
        return None;
    }
    let after = &rest[colon + 1..];
    if after.is_empty() {
        Some((name, None))
    } else {
        after.strip_prefix(' ').map(|value| (name, Some(value)))
    }
}

/// The indentation of a nested block: two spaces past its key, or past its sequence item's
/// dash (#1034's fifth fold; every block of the thirteen workflows on 2026-11-17, 331 mappings
/// and 42 sequences, measured by a real parser).
pub const INDENT: usize = 2;

/// Every breach of the plain style in one workflow's text.
pub fn style_errors(file: &str, text: &str) -> Vec<String> {
    let mut errors = Vec::new();
    // the indentation of each open mapping and the keys it holds
    let mut frames: Vec<(usize, BTreeSet<String>)> = Vec::new();
    // the column of every open block, mapping or sequence, the outermost leading
    let mut columns: Vec<usize> = vec![0];
    // the column of a key whose value is not on its line: the next deeper line opens its block
    let mut opened: Option<usize> = None;
    // a block scalar's key column, while its body is read
    let mut body_of: Option<usize> = None;
    // the deepest indentation the next content line may take, when the line before it carried
    // its value inline
    let mut ceiling: Option<usize> = None;
    let lines: Vec<&str> = text.split('\n').collect();
    for (index, line) in lines.iter().enumerate() {
        let number = index + 1;
        if line.chars().any(|c| {
            (c.is_control() && c != '\n')
                || matches!(c, '\u{85}' | '\u{2028}' | '\u{2029}' | '\u{feff}')
        }) {
            errors.push(at(file, number, BREAK));
            continue;
        }
        let indent = line.len() - line.trim_start_matches(' ').len();
        let rest = &line[indent..];
        if let Some(key_col) = body_of {
            if rest.is_empty() || indent > key_col {
                continue;
            }
            body_of = None;
        }
        if rest.is_empty() || rest.starts_with('#') {
            continue;
        }
        if let Some(max) = ceiling.take() {
            if indent > max {
                errors.push(at(file, number, "a line deeper than the line before it allows (a plain scalar continued over lines)"));
                continue;
            }
        }
        // the item's dash, and the column the key or value after it opens at
        let (dash, body, col) = match rest.strip_prefix("- ") {
            Some(after) => {
                if after.starts_with(' ') {
                    errors.push(at(file, number, "more than one space after a sequence item's `- ` (its content at another column than the dash's plus two)"));
                    continue;
                }
                (Some(indent), after, indent + 2)
            }
            None if rest == "-" => {
                errors.push(at(file, number, "an empty sequence item (`-` alone)"));
                continue;
            }
            None => (None, rest, indent),
        };
        // the indentation: a block opened under a key at its key's column plus two, every other
        // line at the column of a block still open
        let parent = opened.take();
        match parent {
            Some(p) if indent > p || (dash.is_some() && indent == p) => {
                if indent != p + INDENT {
                    errors.push(at(file, number, &format!("a block indented {} spaces under its key at column {p} (the plain style indents a block two spaces past its key)", indent as isize - p as isize)));
                    continue;
                }
                columns.push(indent);
            }
            _ => {
                columns.retain(|&c| c <= indent);
                if columns.last() != Some(&indent) {
                    errors.push(at(file, number, &format!("a line at column {indent}, which is no open block's column {columns:?}")));
                    continue;
                }
            }
        }
        if dash.is_some() && plain_key(body).is_some() {
            columns.push(col);
        }
        // a `- ` opens a new mapping at its key's column: every deeper one is closed
        frames.retain(|(i, _)| *i <= dash.unwrap_or(col));
        match plain_key(body) {
            Some((name, value)) => {
                match frames.last_mut() {
                    Some((i, keys)) if *i == col && dash.is_none() => {
                        if !keys.insert(name.to_owned()) {
                            errors.push(at(file, number, &format!("the key `{name}` twice in one mapping")));
                        }
                    }
                    _ => frames.push((col, BTreeSet::from([name.to_owned()]))),
                }
                let Some(value) = value else {
                    opened = Some(col);
                    continue;
                };
                match value_form(value) {
                    Ok(false) if strip_comment(value).is_ok_and(|v| v.trim().is_empty()) => {
                        opened = Some(col);
                    }
                    Ok(false) => ceiling = Some(col),
                    Ok(true) if PROSE_KEYS.contains(&name) => body_of = Some(col),
                    Ok(true) => errors.push(at(file, number, &format!("a block scalar as the value of `{name}`, which is not one of {PROSE_KEYS:?}"))),
                    Err(what) => errors.push(at(file, number, what)),
                }
            }
            None => match dash {
                Some(d) => match value_form(body) {
                    Ok(false) => ceiling = Some(d),
                    Ok(true) => errors.push(at(file, number, "a block scalar as a sequence item")),
                    Err(what) => errors.push(at(file, number, what)),
                },
                None => errors.push(at(file, number, "a line that is no plain key, no `- ` item, no comment and not blank (a quoted key, a space before the colon, an explicit key, a merge key, a directive, a document marker or a scalar continued over lines)")),
            },
        }
    }
    errors
}

/// The refusal of an entry of `.github/workflows/` that is not a `.yml` or `.yaml` file (a
/// folder, a file under another extension, in any case): the style reads those two alone, so a
/// file the runner might read under another name is refused rather than left unread.
pub fn entry_error(name: &str, is_file: bool) -> Option<String> {
    (!is_file || !(name.ends_with(".yml") || name.ends_with(".yaml"))).then(|| {
        format!(".github/workflows/{name}: an entry of the workflows folder that is not a `.yml` or `.yaml` file (the plain style reads those alone, #1034)")
    })
}

/// Every entry of `.github/workflows/`, by name, with its text; an entry that is not a `.yml` or
/// `.yaml` file is refused by name.
pub fn workflow_folder() -> (Vec<(String, String)>, Vec<String>) {
    let dir = format!("{}/.github/workflows", env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    let mut errors = Vec::new();
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{dir}: {e}"))
        .map(|entry| entry.expect("an entry"))
        .collect();
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let name = entry.file_name().to_string_lossy().into_owned();
        let is_file = entry.file_type().map(|t| t.is_file()).unwrap_or(false);
        if let Some(error) = entry_error(&name, is_file) {
            errors.push(error);
            continue;
        }
        let bytes = std::fs::read(entry.path()).expect("a workflow");
        match String::from_utf8(bytes) {
            Ok(text) => files.push((name, text)),
            Err(_) => errors.push(format!(".github/workflows/{name}: not UTF-8")),
        }
    }
    (files, errors)
}

/// A key path and its scalar value, as the reader of [`key_paths`] gives them.
pub type Pair = (String, String);

/// A block the reader holds open: its column, its path, and for a sequence its next index.
struct Frame {
    col: usize,
    path: String,
    seq: Option<usize>,
}

fn join(base: &str, step: &str) -> String {
    if base.is_empty() {
        step.to_owned()
    } else {
        format!("{base}/{step}")
    }
}

/// The value of a quoted scalar the plain style admits (closed on its line, no escape): its
/// text between the quotes; any other text as it is.
fn unquoted(value: &str) -> &str {
    let quoted = (value.starts_with('"') && value.ends_with('"'))
        || (value.starts_with('\'') && value.ends_with('\''));
    if quoted && value.len() >= 2 {
        &value[1..value.len() - 1]
    } else {
        value
    }
}

/// The pairs of a value written on its key's or its item's line: a scalar, `{}`, or a flow
/// sequence of scalars (each item at `<path>/[i]`; `[]` the empty one).
fn inline_pairs(out: &mut Vec<Pair>, path: String, value: &str) {
    let value = strip_comment(value).unwrap_or(value).trim_end_matches(' ');
    if value == "{}" {
        out.push((path, "{}".to_owned()));
    } else if let Some(inner) = value.strip_prefix('[').and_then(|v| v.strip_suffix(']')) {
        if inner.trim().is_empty() {
            out.push((path, "[]".to_owned()));
        } else {
            for (i, item) in inner.split(',').enumerate() {
                out.push((
                    join(&path, &format!("[{i}]")),
                    unquoted(item.trim_matches(' ')).to_owned(),
                ));
            }
        }
    } else {
        out.push((path, unquoted(value).to_owned()));
    }
}

/// A block scalar's value from its header (`|` or `>`, a chomping indicator after it) and the
/// lines of its body: the indentation the body's earliest line with text has, a literal body's
/// lines kept and a folded one's joined as YAML folds them, then chomped.
fn block_value(header: &str, body: &[&str]) -> String {
    let folded = header.starts_with('>');
    let chomp = header[1..].chars().next();
    let ind = body
        .iter()
        .find(|l| !l.trim_start_matches(' ').is_empty())
        .map_or(0, |l| l.len() - l.trim_start_matches(' ').len());
    let content: Vec<&str> = body
        .iter()
        .map(|l| if l.len() > ind { &l[ind..] } else { "" })
        .collect();
    let Some(last) = content.iter().rposition(|l| !l.is_empty()) else {
        return if chomp == Some('+') {
            "\n".repeat(content.len())
        } else {
            String::new()
        };
    };
    let mut out = String::new();
    if folded {
        let mut started = false;
        let mut empties = 0;
        let mut prev_more = false;
        for line in &content[..=last] {
            if line.is_empty() {
                empties += 1;
                continue;
            }
            let more = line.starts_with(' ');
            if !started {
                out.push_str(&"\n".repeat(empties));
                started = true;
            } else if !prev_more && !more {
                if empties == 0 {
                    out.push(' ');
                } else {
                    out.push_str(&"\n".repeat(empties));
                }
            } else {
                out.push_str(&"\n".repeat(empties + 1));
            }
            out.push_str(line);
            prev_more = more;
            empties = 0;
        }
    } else {
        out = content[..=last].join("\n");
    }
    match chomp {
        Some('-') => {}
        Some('+') => out.push_str(&"\n".repeat(1 + content.len() - 1 - last)),
        _ => out.push('\n'),
    }
    out
}

/// Every key path of a workflow in the plain style and its scalar value: `jobs/<id>/steps/[i]/run`
/// and the script, a mapping key's path its keys from the top joined by `/`, a sequence item's
/// `[i]`; an empty mapping `{}`, an empty sequence `[]`, a key with no value the empty text. Read
/// by structure (the column each block opens at), so it reads a block at any indentation as a
/// YAML parser does; the plain style ([`style_errors`]) is what makes a key's path readable from
/// text at all, and the differential of `docs/lanes/fix-1034-deny-shape.md` shows these pairs
/// equal a real parser's on every workflow and every respelled copy the style lets through
/// (#1034's fifth fold). Meaningful on a text [`style_errors`] passes.
pub fn key_paths(text: &str) -> Vec<Pair> {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    let mut frames: Vec<Frame> = Vec::new();
    let mut pending: Option<(usize, String)> = None;
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        i += 1;
        let indent = line.len() - line.trim_start_matches(' ').len();
        let rest = &line[indent..];
        if rest.is_empty() || rest.starts_with('#') {
            continue;
        }
        let (dash, body, col) = match rest.strip_prefix("- ") {
            Some(after) => {
                let body = after.trim_start_matches(' ');
                (Some(indent), body, indent + 2 + (after.len() - body.len()))
            }
            None => (None, rest, indent),
        };
        let opens = pending
            .as_ref()
            .is_some_and(|(p, _)| indent > *p || (dash.is_some() && indent == *p));
        if opens {
            let (_, path) = pending.take().unwrap_or_default();
            frames.push(Frame {
                col: indent,
                path,
                seq: dash.map(|_| 0),
            });
        } else {
            if let Some((_, path)) = pending.take() {
                out.push((path, String::new()));
            }
            while frames.last().is_some_and(|f| {
                f.col > indent || (f.col == indent && f.seq.is_some() && dash.is_none())
            }) {
                frames.pop();
            }
        }
        if dash.is_some() {
            let Some(frame) = frames.last_mut().filter(|f| f.seq.is_some()) else {
                out.push(("<unread>".to_owned(), line.to_owned()));
                continue;
            };
            let n = frame.seq.unwrap_or(0);
            frame.seq = Some(n + 1);
            let item = join(&frame.path, &format!("[{n}]"));
            if plain_key(body).is_none() {
                inline_pairs(&mut out, item, body);
                continue;
            }
            frames.push(Frame {
                col,
                path: item,
                seq: None,
            });
        }
        let Some((name, value)) = plain_key(body) else {
            out.push(("<unread>".to_owned(), line.to_owned()));
            continue;
        };
        let path = join(frames.last().map_or("", |f| f.path.as_str()), name);
        let value = value.map(|v| strip_comment(v).unwrap_or(v).trim_end_matches(' '));
        match value {
            None | Some("") => pending = Some((col, path)),
            Some(v) if v.starts_with('|') || v.starts_with('>') => {
                let start = i;
                while i < lines.len() && {
                    let l = lines[i];
                    let d = l.len() - l.trim_start_matches(' ').len();
                    l.trim_start_matches(' ').is_empty() || d > col
                } {
                    i += 1;
                }
                out.push((path, block_value(v, &lines[start..i])));
            }
            Some(v) => inline_pairs(&mut out, path, v),
        }
    }
    if let Some((_, path)) = pending {
        out.push((path, String::new()));
    }
    out
}
