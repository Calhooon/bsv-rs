//! No public constant, static or function return under `src/` is typed as an
//! array whose length is the count of a set that can grow (#843dall, the
//! freeze plan's Q4; root rule 11, the class of `WalletRefusalClass::ALL` and
//! `Kind::ALL`).
//!
//! Until #843dall both were `[Self; N]` on a `#[non_exhaustive]` enum, so each
//! variant added changed a public type (`Kind::ALL` was `[Kind; 18]` at
//! v0.4.0 and `[Kind; 26]` at v0.9.0-beta.2, twice inside a patch line). They
//! are `&'static [Self]` now, and this guard keeps the next such table from
//! being born an array: a `pub const`, a `pub static` or the return type of a
//! `pub fn` whose type holds an array `[T; N]` with `T` other than `u8` is
//! refused by file and line, save the rows of [`CLOSED_ARRAYS`], each a
//! `file`, a name and the reason its length can never move. A row that names
//! nothing the scan finds is refused too: the list only shrinks. An array of
//! `u8` is a byte string (a hash, a key, a version word), its length the
//! format's, and is not read.
//!
//! The scan is lexical (`arch_support`): comments, string literals and
//! `#[cfg(test)]` items supply nothing, and a file named `tests.rs` or
//! `*_tests.rs` is a test module and is not read. An item is found by `pub`
//! followed directly by `const`, `static` or `fn` (with `const`, `async`,
//! `unsafe` or `extern "abi"` before `fn`); its type is the tokens after the
//! name's `:` up to `=` or `;`, or after the parameter list's `->` up to the
//! body, `;` or `where`; an array is a `[` .. `]` group holding a `;` at its
//! own depth, at any depth of the type (`&[T; N]`, `Option<[T; N]>`, a tuple
//! member). What it cannot see: an array behind a `pub type` alias or inside
//! a struct or enum whose name the type gives; a public field typed as an
//! array; a trait's method or associated constant (they carry no `pub`); an
//! item under `pub(crate)`, `pub(super)` or `pub(in ..)` (not public, not
//! read) and, the other way, a `pub` item of a private module (read as
//! public: the refusal errs toward strictness); an item a macro writes; a
//! function's parameters; whether a `u8` array is in truth a table of small
//! numbers; a const-generic brace in a signature (`{ N }` ends the type
//! early).
#![allow(clippy::expect_used, clippy::panic)] // Source reads are test assertions.

mod arch_support;

use arch_support::Token;

/// `(file, name, reason)`: a public array whose length is closed by a
/// specification. The nine BIP-39 wordlists: 2048 words each, 11 bits a word
/// (`bip-0039.mediawiki`), a figure no later list can change.
const CLOSED_ARRAYS: &[(&str, &str, &str)] = &[
    (
        "src/compat/bip39/wordlists/mod.rs",
        "CHINESE_SIMPLIFIED",
        "BIP-39's 2048",
    ),
    (
        "src/compat/bip39/wordlists/mod.rs",
        "CHINESE_TRADITIONAL",
        "BIP-39's 2048",
    ),
    (
        "src/compat/bip39/wordlists/mod.rs",
        "CZECH",
        "BIP-39's 2048",
    ),
    (
        "src/compat/bip39/wordlists/mod.rs",
        "ENGLISH",
        "BIP-39's 2048",
    ),
    (
        "src/compat/bip39/wordlists/mod.rs",
        "FRENCH",
        "BIP-39's 2048",
    ),
    (
        "src/compat/bip39/wordlists/mod.rs",
        "ITALIAN",
        "BIP-39's 2048",
    ),
    (
        "src/compat/bip39/wordlists/mod.rs",
        "JAPANESE",
        "BIP-39's 2048",
    ),
    (
        "src/compat/bip39/wordlists/mod.rs",
        "KOREAN",
        "BIP-39's 2048",
    ),
    (
        "src/compat/bip39/wordlists/mod.rs",
        "SPANISH",
        "BIP-39's 2048",
    ),
];

/// A public item typed with an array of something other than `u8`.
#[derive(Debug, PartialEq, Eq)]
struct Site {
    name: String,
    line: usize,
    array: String,
}

/// The index after the group opening at `open`, or the end.
fn after(tokens: &[Token<'_>], open: usize) -> usize {
    arch_support::group_end(tokens, open)
}

/// The end of a type that starts at `from`: the first of `stops` outside
/// every `(` and `[` group.
fn type_end(tokens: &[Token<'_>], from: usize, stops: &[&str]) -> usize {
    let mut i = from;
    while i < tokens.len() {
        let t = tokens[i];
        if !t.literal && matches!(t.text, "(" | "[") {
            i = after(tokens, i);
            continue;
        }
        if !t.literal && stops.contains(&t.text) {
            return i;
        }
        i += 1;
    }
    tokens.len()
}

/// Every array `[T; N]` in a type whose `T` is not `u8`, as written.
fn open_arrays(ty: &[Token<'_>]) -> Vec<String> {
    let mut out = Vec::new();
    for (i, t) in ty.iter().enumerate() {
        if t.literal || t.text != "[" {
            continue;
        }
        let end = after(ty, i);
        let inner = &ty[i + 1..end.saturating_sub(1).max(i + 1)];
        let mut depth = 0usize;
        let mut semi = None;
        for (k, x) in inner.iter().enumerate() {
            match x.text {
                "(" | "[" | "{" if !x.literal => depth += 1,
                ")" | "]" | "}" if !x.literal => depth = depth.saturating_sub(1),
                ";" if depth == 0 && !x.literal => {
                    semi = Some(k);
                    break;
                }
                _ => {}
            }
        }
        if let Some(k) = semi {
            let element = arch_support::joined(&inner[..k]);
            if element != "u8" {
                out.push(format!("[{}]", arch_support::joined(inner)));
            }
        }
    }
    out
}

/// The public constants, statics and function returns of a token stream that
/// carry such an array.
fn sites(tokens: &[Token<'_>]) -> Vec<Site> {
    let mut out = Vec::new();
    for i in 0..tokens.len() {
        if tokens[i].text != "pub" || tokens[i].literal {
            continue;
        }
        let mut j = i + 1;
        // `pub(..)` is not public.
        if tokens.get(j).is_some_and(|t| t.text == "(") {
            continue;
        }
        let mut is_fn = false;
        let mut is_value = false;
        while let Some(t) = tokens.get(j) {
            match t.text {
                "fn" => {
                    is_fn = true;
                    break;
                }
                "async" | "unsafe" | "extern" => j += 1,
                _ if t.literal => j += 1, // extern "C"
                "const" | "static" => {
                    let next = tokens.get(j + 1).map_or("", |n| n.text);
                    if matches!(next, "fn" | "async" | "unsafe" | "extern") {
                        j += 1;
                    } else {
                        is_value = true;
                        break;
                    }
                }
                _ => break,
            }
        }
        if is_value {
            let mut n = j + 1;
            if tokens.get(n).is_some_and(|t| t.text == "mut") {
                n += 1;
            }
            let (Some(name), Some(colon)) = (tokens.get(n), tokens.get(n + 1)) else {
                continue;
            };
            if colon.text != ":" {
                continue;
            }
            let end = type_end(tokens, n + 2, &["=", ";"]);
            for array in open_arrays(&tokens[n + 2..end]) {
                out.push(Site {
                    name: name.text.to_string(),
                    line: name.line,
                    array,
                });
            }
        } else if is_fn {
            let Some(name) = tokens.get(j + 1) else {
                continue;
            };
            let mut k = j + 2;
            if tokens.get(k).is_some_and(|t| t.text == "<") {
                let mut angle = 0usize;
                while let Some(t) = tokens.get(k) {
                    match t.text {
                        "<" => angle += 1,
                        ">" if tokens[k - 1].text != "-" => {
                            angle -= 1;
                            if angle == 0 {
                                k += 1;
                                break;
                            }
                        }
                        _ => {}
                    }
                    k += 1;
                }
            }
            if !tokens.get(k).is_some_and(|t| t.text == "(") {
                continue;
            }
            k = after(tokens, k);
            let arrow = tokens.get(k).is_some_and(|t| t.text == "-")
                && tokens.get(k + 1).is_some_and(|t| t.text == ">");
            if !arrow {
                continue;
            }
            let end = type_end(tokens, k + 2, &["{", ";", "where"]);
            for array in open_arrays(&tokens[k + 2..end]) {
                out.push(Site {
                    name: name.text.to_string(),
                    line: name.line,
                    array,
                });
            }
        }
    }
    out
}

/// The refusals: each found site with no row, then each row naming nothing.
fn refusals(found: &[(String, Site)], closed: &[(&str, &str, &str)]) -> Vec<String> {
    let mut used = vec![false; closed.len()];
    let mut errors = Vec::new();
    for (file, site) in found {
        match closed
            .iter()
            .position(|(f, n, _)| f == file && *n == site.name)
        {
            Some(row) => used[row] = true,
            None => errors.push(format!(
                "{file}:{}: `{}` is public and typed {}: an array's length is part of the type, so a set that grows changes it; make it a slice (`&'static [T]`), or add a row to CLOSED_ARRAYS with the reason the length can never move",
                site.line, site.name, site.array
            )),
        }
    }
    for ((file, name, _), used) in closed.iter().zip(used) {
        if !used {
            errors.push(format!(
                "CLOSED_ARRAYS row `{file}` `{name}` names no public array the scan finds; delete the row"
            ));
        }
    }
    errors
}

fn found_under_src() -> Vec<(String, Site)> {
    let mut found = Vec::new();
    for source in arch_support::sources() {
        if source.path.ends_with("_tests.rs") || source.path.ends_with("/tests.rs") {
            continue;
        }
        for site in sites(&source.tokens()) {
            found.push((source.path.clone(), site));
        }
    }
    found
}

fn sample(text: &str) -> Vec<(String, String)> {
    sites(&arch_support::code_tokens(text, false))
        .into_iter()
        .map(|s| (s.name, s.array))
        .collect()
}

#[test]
fn no_public_constant_static_or_return_is_an_array_of_an_open_set_843dall() {
    let found = found_under_src();
    let errors = refusals(&found, CLOSED_ARRAYS);
    assert!(errors.is_empty(), "{}", errors.join("\n"));
    // The reader is seen to read: the nine closed rows were each found.
    assert_eq!(found.len(), CLOSED_ARRAYS.len());
}

#[test]
fn the_two_all_tables_are_slices_843dall() {
    for (file, needle) in [
        (
            "src/error/wallet_refusal.rs",
            "pub const ALL: &'static [Self] = &[",
        ),
        (
            "src/transaction/beef_stream/reason.rs",
            "pub const ALL: &'static [Kind] = &[",
        ),
    ] {
        assert_eq!(
            arch_support::read(file).matches(needle).count(),
            1,
            "{file}: `{needle}`"
        );
    }
}

#[test]
fn the_scan_reads_each_form_843dall() {
    let hit = |name: &str, array: &str| vec![(name.to_string(), array.to_string())];
    // The two shapes this lane found, as they stood.
    assert_eq!(
        sample("impl K { pub const ALL: [Self; 20] = [Self::A]; }"),
        hit("ALL", "[Self ; 20]")
    );
    assert_eq!(
        sample("impl K { pub const ALL: [Kind; 26] = [Kind::A]; }"),
        hit("ALL", "[Kind ; 26]")
    );
    assert_eq!(
        sample("pub static WORDS: [&str; 2048] = parse();"),
        hit("WORDS", "[& str ; 2048]")
    );
    assert_eq!(
        sample("pub static mut T: [u16; 4] = [0; 4];"),
        hit("T", "[u16 ; 4]")
    );
    // A function's return, plain and under each modifier, generic, with a
    // where clause, behind a reference and inside another type.
    assert_eq!(
        sample("pub fn all() -> [Kind; 3] { todo!() }"),
        hit("all", "[Kind ; 3]")
    );
    assert_eq!(
        sample("pub const fn all() -> [Kind; 3] { X }"),
        hit("all", "[Kind ; 3]")
    );
    assert_eq!(
        sample("pub async unsafe fn all() -> [Kind; 3] { X }"),
        hit("all", "[Kind ; 3]")
    );
    assert_eq!(
        sample("pub extern \"C\" fn all() -> [Kind; 3] { X }"),
        hit("all", "[Kind ; 3]")
    );
    assert_eq!(
        sample("pub fn all<F: Fn(u8) -> u8>(f: F) -> &'static [Kind; 3] where F: Copy { X }"),
        hit("all", "[Kind ; 3]")
    );
    assert_eq!(
        sample("pub fn all() -> Option<([Kind; 3], u8)>;"),
        hit("all", "[Kind ; 3]")
    );
    // An array of byte arrays is a table: its element is not `u8`.
    assert_eq!(
        sample("pub const T: [[u8; 32]; 2] = X;"),
        hit("T", "[[ u8 ; 32 ] ; 2]")
    );
}

#[test]
fn the_scan_passes_what_is_no_open_array_843dall() {
    for text in [
        // A slice, the form the rule asks for.
        "impl K { pub const ALL: &'static [Self] = &[Self::A]; }",
        "pub fn all() -> &'static [Kind] { X }",
        // A byte string.
        "pub const VERSION: [u8; 4] = [1, 2, 3, 4];",
        "pub fn hash(&self) -> [u8; 32] { X }",
        "pub fn id(&self) -> Option<&[u8; 32]> { X }",
        // Not public.
        "pub(crate) const ALL: [Kind; 3] = X;",
        "pub(super) fn all() -> [Kind; 3] { X }",
        "const ALL: [Kind; 3] = X;",
        "fn all() -> [Kind; 3] { X }",
        // An array in a parameter or a body is no public type of a value.
        "pub fn take(x: [Kind; 3]) -> u8 { 0 }",
        "pub fn make() -> u8 { let a: [Kind; 3] = X; 0 }",
        "pub fn f<F: Fn() -> [Kind; 3]>(f: F) {}",
        // A comment, a string and a test item supply nothing.
        "// pub const ALL: [Kind; 3] = X;",
        "pub const TEXT: &str = \"pub const ALL: [Kind; 3]\";",
        "#[cfg(test)] mod tests { pub const ALL: [Kind; 3] = X; }",
    ] {
        assert_eq!(sample(text), Vec::new(), "{text}");
    }
}

#[test]
fn a_site_without_a_row_and_a_row_naming_nothing_are_each_refused_843dall() {
    let site = |name: &str| Site {
        name: name.to_string(),
        line: 7,
        array: "[Kind ; 26]".to_string(),
    };
    let rows: &[(&str, &str, &str)] = &[("src/a.rs", "WORDS", "closed")];
    // A row for each site: nothing refused.
    assert!(refusals(&[("src/a.rs".to_string(), site("WORDS"))], rows).is_empty());
    // A site with no row, named by file, line and name.
    let errors = refusals(
        &[
            ("src/a.rs".to_string(), site("WORDS")),
            ("src/b.rs".to_string(), site("ALL")),
        ],
        rows,
    );
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(
        errors[0].starts_with("src/b.rs:7: `ALL` is public and typed [Kind ; 26]"),
        "{errors:?}"
    );
    // The same name in another file is another site.
    let errors = refusals(&[("src/b.rs".to_string(), site("WORDS"))], rows);
    assert_eq!(errors.len(), 2, "{errors:?}");
    // A row naming nothing.
    let errors = refusals(&[], rows);
    assert_eq!(
        errors,
        ["CLOSED_ARRAYS row `src/a.rs` `WORDS` names no public array the scan finds; delete the row"]
    );
}
