//! Small, dependency-free source scanner shared by the architecture rules.
//!
//! This is a lexical guard, not Rust name resolution. Comments and literals
//! cannot supply code tokens; balanced cfg-gated items are skipped without
//! hiding production code that follows a test module.
#![allow(dead_code)] // Each integration test uses a different part of the scanner.

use std::fs;
use std::path::{Path, PathBuf};

pub struct Source {
    pub path: String,
    pub text: String,
}

#[derive(Clone, Copy, Debug)]
pub struct Token<'a> {
    pub text: &'a str,
    pub line: usize,
    pub literal: bool,
}

/// A crate file's text with its line endings normalized to `\n`: a Windows
/// checkout converts the sources to CRLF (`.gitattributes` keeps only the
/// vectors, fixtures and corpora byte for byte), and the rules' needles are
/// written with `\n` (bsv-rs#367).
pub fn read(file: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(file);
    normalize(&fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display())))
}

/// `\r\n` to `\n`, before any search.
pub fn normalize(text: &str) -> String {
    text.replace("\r\n", "\n")
}

/// FNV-1a, 64 bits: the digest every text pin of the architecture rules takes
/// (`sealed` in `arch_field_writes_843.rs`, the macro file in
/// `arch_non_exhaustive_pins_819.rs`, the sync workflow in `arch_ci_lines.rs`).
pub fn fnv(text: &str) -> u64 {
    text.bytes().fold(0xcbf2_9ce4_8422_2325, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
    })
}

pub fn sources() -> Vec<Source> {
    fn visit(root: &Path, dir: &Path, out: &mut Vec<Source>) {
        for entry in fs::read_dir(dir).expect("read source directory") {
            let path = entry.expect("source entry").path();
            if path.is_dir() {
                visit(root, &path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(Source {
                    path: path
                        .strip_prefix(root)
                        .expect("source inside crate")
                        .to_string_lossy()
                        .replace('\\', "/"),
                    text: normalize(&fs::read_to_string(path).expect("read Rust source")),
                });
            }
        }
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut out = Vec::new();
    visit(&root, &root.join("src"), &mut out);
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

impl Source {
    pub fn tokens(&self) -> Vec<Token<'_>> {
        code_tokens(&self.text, false)
    }

    pub fn portable_tokens(&self) -> Vec<Token<'_>> {
        code_tokens(&self.text, true)
    }

    /// [`Source::tokens`] with the attributes kept (`#`, `[`, .., `]`): an
    /// item under a cfg this scan knows false is still skipped whole, its
    /// attributes with it (#869's fifth fold, the field guard's attribute
    /// rule).
    pub fn tokens_with_attributes(&self) -> Vec<Token<'_>> {
        scan_tokens(&self.text, false, true)
    }

    /// Every token as written, no attribute and no cfg-gated item skipped
    /// (comments and literals still opaque): the sealed-module pin's reading
    /// (#869's sixth fold), which a `#[cfg(..)]` must not hide from.
    pub fn raw_tokens(&self) -> Vec<Token<'_>> {
        lex(&self.text)
    }

    pub fn line(&self, number: usize) -> &str {
        self.text.lines().nth(number - 1).unwrap_or_default().trim()
    }
}

/// Lex strings (including raw/byte strings) as one opaque token, and discard
/// comments. Line numbers always refer to the original source.
fn lex(source: &str) -> Vec<Token<'_>> {
    let bytes = source.as_bytes();
    let mut out = Vec::new();
    let (mut i, mut line) = (0, 1);
    while i < bytes.len() {
        let start = i;
        let start_line = line;
        if bytes[i].is_ascii_whitespace() {
            line += usize::from(bytes[i] == b'\n');
            i += 1;
            continue;
        }
        if bytes[i..].starts_with(b"//") {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if bytes[i..].starts_with(b"/*") {
            let mut depth = 1;
            i += 2;
            while i < bytes.len() && depth != 0 {
                if bytes[i..].starts_with(b"/*") {
                    depth += 1;
                    i += 2;
                } else if bytes[i..].starts_with(b"*/") {
                    depth -= 1;
                    i += 2;
                } else {
                    line += usize::from(bytes[i] == b'\n');
                    i += 1;
                }
            }
            continue;
        }

        let mut quote = i;
        if matches!(bytes[i], b'b' | b'c') {
            quote += 1;
        }
        let mut raw = false;
        let mut hashes = 0;
        if bytes.get(quote) == Some(&b'r') {
            raw = true;
            quote += 1;
            while bytes.get(quote) == Some(&b'#') {
                hashes += 1;
                quote += 1;
            }
        }
        let string = bytes.get(quote) == Some(&b'"');
        // A character literal has one character or an escape before its closing
        // quote. A lifetime ('a, 'static) must remain ordinary code.
        let character = bytes.get(quote) == Some(&b'\'')
            && (bytes.get(quote + 1) == Some(&b'\\')
                || source[quote + 1..]
                    .chars()
                    .next()
                    .is_some_and(|ch| bytes.get(quote + 1 + ch.len_utf8()) == Some(&b'\'')));
        let literal = string || character;
        if literal {
            let delimiter = bytes[quote];
            i = quote + 1;
            while i < bytes.len() {
                if !raw && bytes[i] == b'\\' {
                    i += 1;
                    if i < bytes.len() {
                        line += usize::from(bytes[i] == b'\n');
                        i += 1;
                    }
                } else if bytes[i] == delimiter
                    && bytes
                        .get(i + 1..i + 1 + hashes)
                        .is_some_and(|suffix| suffix.iter().all(|b| *b == b'#'))
                {
                    i += 1 + hashes;
                    break;
                } else {
                    line += usize::from(bytes[i] == b'\n');
                    i += 1;
                }
            }
        } else if bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' || bytes[i] >= 128 {
            i += source[i..].chars().next().expect("character").len_utf8();
            while i < bytes.len()
                && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' || bytes[i] >= 128)
            {
                i += source[i..].chars().next().expect("character").len_utf8();
            }
        } else if bytes[i..].starts_with(b"::") || bytes[i..].starts_with(b"==") {
            i += 2;
        } else {
            i += 1;
        }
        out.push(Token {
            text: &source[start..i],
            line: start_line,
            literal,
        });
    }
    out
}

/// Match balanced delimiters, including nested parentheses inside attributes.
fn after_group(tokens: &[Token<'_>], start: usize) -> usize {
    let close = match tokens[start].text {
        "(" => ")",
        "[" => "]",
        "{" => "}",
        _ => panic!("expected a delimiter"),
    };
    let mut i = start + 1;
    while i < tokens.len() {
        match tokens[i].text {
            token if token == close => return i + 1,
            "(" | "[" | "{" => i = after_group(tokens, i),
            _ => i += 1,
        }
    }
    panic!("unbalanced source at line {}", tokens[start].line);
}

#[derive(Clone, Copy, PartialEq)]
enum Truth {
    Yes,
    No,
    Unknown,
}

/// Evaluate only facts this rule knows: production is not `test`, and the
/// portability scan targets wasm32. An unknown feature must never hide code.
fn cfg_value(tokens: &[Token<'_>], wasm: bool) -> Truth {
    use Truth::{No, Unknown, Yes};
    let Some(head) = tokens.first() else {
        return Unknown;
    };
    if head.text == "test" {
        return No;
    }
    if tokens.len() >= 3 && tokens[1].text == "=" {
        return if wasm && head.text == "target_arch" {
            let value = tokens[2]
                .text
                .trim_start_matches('r')
                .trim_matches('#')
                .trim_matches('"');
            match value {
                "wasm32" => Yes,
                value if value.contains('\\') => Unknown,
                _ => No,
            }
        } else {
            Unknown
        };
    }
    if tokens.get(1).is_none_or(|token| token.text != "(") {
        return Unknown;
    }
    let mut values = Vec::new();
    let (mut i, mut from) = (2, 2);
    while i + 1 < tokens.len() {
        match tokens[i].text {
            "(" | "[" | "{" => i = after_group(tokens, i),
            "," => {
                values.push(cfg_value(&tokens[from..i], wasm));
                i += 1;
                from = i;
            }
            _ => i += 1,
        }
    }
    if from < i {
        values.push(cfg_value(&tokens[from..i], wasm));
    }
    match head.text {
        "not" if values.len() == 1 => match values[0] {
            Yes => No,
            No => Yes,
            Unknown => Unknown,
        },
        "all" if values.contains(&No) => No,
        "all" if values.iter().all(|value| *value == Yes) => Yes,
        "any" if values.contains(&Yes) => Yes,
        "any" if values.iter().all(|value| *value == No) => No,
        _ => Unknown,
    }
}

fn after_item(tokens: &[Token<'_>], mut i: usize) -> usize {
    while i < tokens.len() {
        match tokens[i].text {
            "{" => return after_group(tokens, i),
            ";" => return i + 1,
            "(" | "[" => i = after_group(tokens, i),
            _ => i += 1,
        }
    }
    i
}

pub fn code_tokens(source: &str, wasm: bool) -> Vec<Token<'_>> {
    scan_tokens(source, wasm, false)
}

/// [`code_tokens`] with the attributes kept, on a text: what
/// [`Source::tokens_with_attributes`] reads from a file (#843d8a's probes).
pub fn scan_tokens_with_attributes(source: &str) -> Vec<Token<'_>> {
    scan_tokens(source, false, true)
}

fn scan_tokens(source: &str, wasm: bool, keep_attributes: bool) -> Vec<Token<'_>> {
    let tokens = lex(source);
    let mut out = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        if tokens[i].text == "#" {
            let inner = tokens.get(i + 1).is_some_and(|t| t.text == "!");
            let bracket = i + 1 + usize::from(inner);
            if tokens.get(bracket).is_some_and(|t| t.text == "[") {
                let end = after_group(&tokens, bracket);
                let attr = &tokens[bracket + 1..end - 1];
                if attr.first().is_some_and(|t| t.text == "cfg")
                    && attr.get(1).is_some_and(|t| t.text == "(")
                    && cfg_value(&attr[2..attr.len() - 1], wasm) == Truth::No
                {
                    if inner {
                        // A file-wide cfg disables this file. Module-level
                        // inner cfgs end at that module's closing brace.
                        while i < tokens.len() && tokens[i].text != "}" {
                            i = match tokens[i].text {
                                "(" | "[" | "{" => after_group(&tokens, i),
                                _ => i + 1,
                            };
                        }
                    } else {
                        i = after_item(&tokens, end);
                    }
                    continue;
                }
                if keep_attributes {
                    out.extend_from_slice(&tokens[i..end]);
                }
                i = end;
                continue;
            }
        }
        out.push(tokens[i]);
        i += 1;
    }
    out
}

pub fn is_call(tokens: &[Token<'_>], at: usize, names: &[&str]) -> bool {
    let receiver = (at > 0 && matches!(tokens[at - 1].text, "." | "::"))
        || (at >= 3
            && tokens[at - 1].text == "#"
            && tokens[at - 2].text == "r"
            && matches!(tokens[at - 3].text, "." | "::"));
    receiver
        && names.contains(&tokens[at].text)
        && tokens
            .get(at + 1)
            .is_some_and(|t| matches!(t.text, "(" | "::"))
}

/// Exact source-line exceptions, with a ceiling for duplicate occurrences.
/// Moving a line is fine; adding another copy or another token on it is not.
/// An entry that matches no site the rule finds is red too, and so is a
/// ceiling above the sites it matches (#347): an allowance dies with its
/// line, so the fix is to delete the entry or lower its ceiling.
pub fn check_sites(rule: &str, sites: &[(String, usize, String)], allowed: &[(&str, &str, usize)]) {
    let errors = site_errors(rule, sites, allowed);
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

/// The refusals `check_sites` asserts on: each site past its entry's ceiling,
/// then each entry no site used or used fewer times than its ceiling.
pub fn site_errors(
    rule: &str,
    sites: &[(String, usize, String)],
    allowed: &[(&str, &str, usize)],
) -> Vec<String> {
    let mut used = vec![0; allowed.len()];
    let mut errors = Vec::new();
    for (file, line, text) in sites {
        if let Some(index) = allowed.iter().position(|(f, s, _)| file == f && text == s) {
            used[index] += 1;
            if used[index] <= allowed[index].2 {
                continue;
            }
        }
        errors.push(format!("{file}:{line}: {rule}"));
    }
    for ((file, text, ceiling), count) in allowed.iter().zip(&used) {
        if *count == 0 {
            errors.push(format!(
                "{file}: allowlist entry `{text}` matches no {rule} site; delete the entry"
            ));
        } else if count < ceiling {
            errors.push(format!(
                "{file}: allowlist entry `{text}` allows {ceiling} {rule} sites and matches {count}; lower its ceiling to {count}"
            ));
        }
    }
    errors
}

/// The index after the group that opens at `tokens[open]` (`(`, `[` or `{`),
/// literals opaque; `tokens.len()` when it does not close.
pub fn group_end(tokens: &[Token<'_>], open: usize) -> usize {
    let (o, c) = match tokens[open].text {
        "(" => ("(", ")"),
        "[" => ("[", "]"),
        _ => ("{", "}"),
    };
    let mut depth = 0usize;
    for (i, t) in tokens.iter().enumerate().skip(open) {
        if t.literal {
            continue;
        }
        if t.text == o {
            depth += 1;
        } else if t.text == c {
            depth -= 1;
            if depth == 0 {
                return i + 1;
            }
        }
    }
    tokens.len()
}

/// The tokens' texts joined by one space.
pub fn joined(tokens: &[Token<'_>]) -> String {
    tokens.iter().map(|t| t.text).collect::<Vec<_>>().join(" ")
}

/// The attributes before the item whose opening token is `tokens[at]`, each
/// its tokens inside `#[..]` joined (`path = "x.rs"`, `cfg ( test )`); a
/// visibility before the item is passed over. Comments are not tokens, so a
/// doc comment is no attribute here (a `#[doc = ..]` is). Shared by rule 14's
/// module declarations (`tests/arch_field_writes_843.rs`) and #819's
/// (`tests/arch_non_exhaustive_pins_819.rs`).
pub fn attributes_before(tokens: &[Token<'_>], mut at: usize) -> Vec<String> {
    let mut names = Vec::new();
    // Skip a visibility.
    if at >= 1 && tokens[at - 1].text == "pub" {
        at -= 1;
    } else if at >= 2 && tokens[at - 1].text == ")" {
        if let Some(p) = (0..at).rev().find(|&k| tokens[k].text == "pub") {
            at = p;
        }
    }
    while at >= 1 && tokens[at - 1].text == "]" {
        let Some(open) = (0..at - 1).rev().find(|&k| {
            tokens[k].text == "["
                && k >= 1
                && tokens[k - 1].text == "#"
                && group_end(tokens, k) == at
        }) else {
            break;
        };
        names.push(joined(&tokens[open + 1..at - 1]));
        at = open - 1;
    }
    names
}
