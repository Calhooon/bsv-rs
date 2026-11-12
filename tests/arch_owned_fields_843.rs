//! The ownership rule (#843, `docs/design/843-identity-and-framing.md`,
//! section 3, Part O): a type that stores something derived from its fields
//! (a cache, an index) owns those fields and lends them only through `&mut`
//! doors that clear or repair the derived value; a field nothing is derived
//! from stays public. Over every `struct` under `src/`, one that holds a cache
//! or an index (a field whose type names `RefCell`, `Cell`, `OnceLock`,
//! `OnceCell`, `Mutex` or `RwLock`, or whose name contains `cache` or
//! `index` and whose type is a collection, [`STORES`]) has no `pub`, `pub(crate)`, `pub(super)` or `pub(in ..)` field,
//! save the rows of [`ALLOWED`], each `Type.field` with its reason. A row that
//! no longer exists fails too: the list only shrinks.
//!
//! The scan is lexical (`arch_support`): comments, string literals and
//! `#[cfg(test)]` items supply nothing, and a file named `tests.rs` or
//! `*_tests.rs` is a test module and is not read. A struct is found by its
//! `struct` keyword and name, braced or tuple; a field's visibility, name and
//! type tokens are read up to the comma at its own depth. What it cannot
//! see: a cache held behind a type alias or a wrapper whose name is none of
//! the six (an `Arc<Inner>` whose `Inner` holds the cell), a field derived
//! from the others without a cell or a telling name (a plain `bool` flag), a
//! struct built by a macro. So `BeefTx`, whose derived members (`txid`,
//! `raw_tx`, `input_txids`, `is_valid`) carry no cell and no collection named
//! for a store, is not seen by this scan: #843's next pull request makes
//! `input_txids` and `is_valid` read-only by hand, and its rule names them.
#![allow(clippy::expect_used, clippy::panic)] // Source reads are test assertions.

mod arch_support;

use std::collections::BTreeSet;

/// The cells whose presence marks a struct as holding something derived.
const CELLS: &[&str] = &["RefCell", "Cell", "OnceLock", "OnceCell", "Mutex", "RwLock"];

/// `Type.field`: a public field of a struct that holds a cache or an index,
/// each with its reason. `Transaction.metadata` and `Transaction.merkle_path`
/// left the list with #869's fold: the caches moved into `Fields`, which has
/// no public field, and `Transaction` holds no cell of its own. #843's next pull request (the BEEF owns `txs` and
/// `bumps`) removes the rows that name it; the list only shrinks.
const ALLOWED: &[(&str, &str)] = &[
    (
        "Beef.bumps",
        "#843's next PR: private, with retain_bumps and edit_bump (Part O, 4 of 5)",
    ),
    (
        "Beef.txs",
        "#843's next PR: private, the index derived from it (Part O, 5 of 5)",
    ),
    (
        "Beef.version",
        "nothing derived from it: stays public by Part O (the next PR re-reads it)",
    ),
    (
        "Beef.atomic_txid",
        "nothing derived from it: stays public by Part O (the next PR re-reads it)",
    ),
    (
        "AuthFetch.wallet",
        "a finding of #843's lane: crate-private sharing (pub(super)) beside its locks; the locks hold sessions and peers, nothing derived from these fields",
    ),
    (
        "AuthFetch.requested_certificates",
        "a finding of #843's lane: crate-private sharing (pub(super)) beside its locks; the locks hold sessions and peers, nothing derived from these fields",
    ),
    (
        "AuthFetch.session_manager",
        "a finding of #843's lane: crate-private sharing (pub(super)) beside its locks; the locks hold sessions and peers, nothing derived from these fields",
    ),
    (
        "AuthFetch.peers",
        "a finding of #843's lane: crate-private sharing (pub(super)) beside its locks; the locks hold sessions and peers, nothing derived from these fields",
    ),
    (
        "AuthFetch.transport",
        "a finding of #843's lane: crate-private sharing (pub(super)) beside its locks; the locks hold sessions and peers, nothing derived from these fields",
    ),
    (
        "AuthFetch.received",
        "a finding of #843's lane: crate-private sharing (pub(super)) beside its locks; the locks hold sessions and peers, nothing derived from these fields",
    ),
    (
        "AuthFetch.originator",
        "a finding of #843's lane: crate-private sharing (pub(super)) beside its locks; the locks hold sessions and peers, nothing derived from these fields",
    ),
    (
        "AuthFetch.response_timeout_ms",
        "a finding of #843's lane: crate-private sharing (pub(super)) beside its locks; the locks hold sessions and peers, nothing derived from these fields",
    ),
    (
        "AuthFetch.max_response_bytes",
        "a finding of #843's lane: crate-private sharing (pub(super)) beside its locks; the locks hold sessions and peers, nothing derived from these fields",
    ),
    (
        "AuthFetch.http_client",
        "a finding of #843's lane: crate-private sharing (pub(super)) beside its locks; the locks hold sessions and peers, nothing derived from these fields",
    ),
    (
        "PeerState.peer",
        "a finding of #843's lane: a pub(super) struct whose RwLocks hold a peer's session facts, nothing derived from another field",
    ),
    (
        "PeerState.identity",
        "a finding of #843's lane: a pub(super) struct whose RwLocks hold a peer's session facts, nothing derived from another field",
    ),
    (
        "PeerState.mutual",
        "a finding of #843's lane: a pub(super) struct whose RwLocks hold a peer's session facts, nothing derived from another field",
    ),
    (
        "HistorianConfig.debug",
        "a finding of #843's lane: a caller's configuration; `history_cache` is the caller's own store, read, not derived from these fields",
    ),
    (
        "HistorianConfig.history_cache",
        "a finding of #843's lane: a caller's configuration; `history_cache` is the caller's own store, read, not derived from these fields",
    ),
    (
        "HistorianConfig.interpreter_version",
        "a finding of #843's lane: a caller's configuration; `history_cache` is the caller's own store, read, not derived from these fields",
    ),
    (
        "HistorianConfig.ctx_key_fn",
        "a finding of #843's lane: a caller's configuration; `history_cache` is the caller's own store, read, not derived from these fields",
    ),
    (
        "Envelope.atomic",
        "a finding of #843's lane: a pub(super) read-only parse of a result BEEF; its `bump_indexes` built once from the bytes, never after an edit",
    ),
    (
        "Envelope.transactions",
        "a finding of #843's lane: a pub(super) read-only parse of a result BEEF; its `bump_indexes` built once from the bytes, never after an edit",
    ),
];

fn is_test_file(path: &str) -> bool {
    path.ends_with("/tests.rs") || path.ends_with("_tests.rs")
}

/// One field: its visibility (`None` private), its name and its type tokens.
struct Field {
    public: Option<String>,
    name: String,
    ty: Vec<String>,
}

/// The index after the balanced group opening at `start` (`(`, `[`, `{`, `<`).
fn after(tokens: &[arch_support::Token<'_>], start: usize) -> usize {
    let mut depth = 0i32;
    let mut i = start;
    while i < tokens.len() {
        match tokens[i].text {
            "-" if tokens.get(i + 1).is_some_and(|t| t.text == ">") => i += 1,
            "(" | "[" | "{" | "<" => depth += 1,
            ")" | "]" | "}" | ">" => {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    panic!("unbalanced at line {}", tokens[start].line);
}

/// Reads `pub`, `pub(crate)`, `pub(super)`, `pub(in ..)` at `at`.
fn visibility(tokens: &[arch_support::Token<'_>], at: &mut usize) -> Option<String> {
    if tokens.get(*at)?.text != "pub" {
        return None;
    }
    *at += 1;
    if tokens.get(*at).is_some_and(|t| t.text == "(") {
        let end = after(tokens, *at);
        let inner: Vec<&str> = tokens[*at + 1..end - 1].iter().map(|t| t.text).collect();
        *at = end;
        return Some(format!("pub({})", inner.join(" ")));
    }
    Some("pub".to_string())
}

/// The fields of the struct body opening at `open` (`{` or `(`).
fn fields(tokens: &[arch_support::Token<'_>], open: usize) -> Vec<Field> {
    let tuple = tokens[open].text == "(";
    let close = after(tokens, open) - 1;
    let mut out = Vec::new();
    let mut at = open + 1;
    let mut position = 0;
    while at < close {
        let public = visibility(tokens, &mut at);
        let name = if tuple {
            position.to_string()
        } else {
            let name = tokens[at].text.to_string();
            if tokens.get(at + 1).is_none_or(|t| t.text != ":") {
                panic!("a field `name:` expected at line {}", tokens[at].line);
            }
            at += 2;
            name
        };
        let mut ty = Vec::new();
        while at < close && tokens[at].text != "," {
            match tokens[at].text {
                "(" | "[" | "{" | "<" => {
                    let end = after(tokens, at);
                    ty.extend(tokens[at..end].iter().map(|t| t.text.to_string()));
                    at = end;
                }
                text => {
                    ty.push(text.to_string());
                    at += 1;
                }
            }
        }
        at += 1; // the comma, or past the close
        position += 1;
        out.push(Field { public, name, ty });
    }
    out
}

/// Every struct under `src/`: `(path, line, name, fields)`.
fn structs() -> Vec<(String, usize, String, Vec<Field>)> {
    let mut out = Vec::new();
    for source in arch_support::sources() {
        if is_test_file(&source.path) {
            continue;
        }
        let tokens = source.tokens();
        for at in 0..tokens.len() {
            if tokens[at].text != "struct" || tokens[at].literal {
                continue;
            }
            // `struct $name` inside a `macro_rules!` body is no declaration.
            let Some(name) = tokens
                .get(at + 1)
                .filter(|t| t.text.starts_with(|c: char| c.is_alphabetic() || c == '_'))
            else {
                continue;
            };
            let mut i = at + 2;
            if tokens.get(i).is_some_and(|t| t.text == "<") {
                i = after(&tokens, i);
            }
            // A where clause, then the body (`{`, `(`) or a unit struct (`;`).
            while i < tokens.len() && !matches!(tokens[i].text, "{" | "(" | ";") {
                i += 1;
            }
            if tokens.get(i).is_some_and(|t| t.text == ";") {
                continue;
            }
            let read = std::panic::catch_unwind(|| fields(&tokens, i)).unwrap_or_else(|_| {
                panic!("{}: the struct at line {}", source.path, tokens[at].line)
            });
            out.push((
                source.path.clone(),
                tokens[at].line,
                name.text.to_string(),
                read,
            ));
        }
    }
    out
}

/// The collections a field named for a cache or an index holds it in: a
/// name alone (`output_index: u32`, a position; `hosts_cache_ttl_ms: u64`, a
/// figure) is data, not a derived store.
const STORES: &[&str] = &[
    "HashMap", "BTreeMap", "HashSet", "BTreeSet", "IndexMap", "IndexSet", "Vec", "VecDeque",
    "LruCache",
];

fn holds_derived(fields: &[Field]) -> bool {
    fields.iter().any(|f| {
        let names_store = f.name.contains("cache") || f.name.contains("index");
        f.ty.iter().any(|t| CELLS.contains(&t.as_str()))
            || (names_store && f.ty.iter().any(|t| STORES.contains(&t.as_str())))
    })
}

/// Every public field of a struct that holds a cache or an index, as
/// `(Type.field, where)`.
fn public_derived_fields() -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (path, line, name, fields) in structs() {
        if !holds_derived(&fields) {
            continue;
        }
        for f in &fields {
            if let Some(vis) = &f.public {
                out.push((
                    format!("{name}.{}", f.name),
                    format!("{path}:{line} ({vis})"),
                ));
            }
        }
    }
    out
}

#[test]
fn a_type_that_holds_a_cache_or_an_index_has_no_public_field_843() {
    let found = public_derived_fields();
    let allowed: BTreeSet<&str> = ALLOWED.iter().map(|(row, _)| *row).collect();
    let stray: Vec<String> = found
        .iter()
        .filter(|(row, _)| !allowed.contains(row.as_str()))
        .map(|(row, at)| format!("{row} at {at}"))
        .collect();
    assert!(
        stray.is_empty(),
        "a struct that holds a cache or an index has a public field: own it and lend it \
         through `&mut` doors that clear or repair what is derived (#843), or list it in \
         ALLOWED with its reason:\n{}",
        stray.join("\n")
    );
    let present: BTreeSet<&str> = found.iter().map(|(row, _)| row.as_str()).collect();
    let gone: Vec<&str> = allowed.difference(&present).copied().collect();
    assert!(
        gone.is_empty(),
        "an ALLOWED row names no public field any more: remove it (the list only shrinks):\n{}",
        gone.join("\n")
    );
}

#[test]
fn transaction_holds_its_caches_and_no_serialized_field_is_public_843() {
    // Since #869's fold the four fields and the three caches live in
    // `Fields` (`src/transaction/transaction/fields.rs`), every field of it
    // private; `Transaction` holds it in a private field and declares none
    // of the four names itself.
    let all = structs();
    let (_, _, _, inner) = all
        .iter()
        .find(|(path, _, name, _)| {
            path == "src/transaction/transaction/fields.rs" && name == "Fields"
        })
        .expect("Fields is declared in src/transaction/transaction/fields.rs");
    assert!(
        holds_derived(inner),
        "the scan sees Transaction's caches in Fields"
    );
    for name in ["version", "inputs", "outputs", "lock_time"] {
        let f = inner
            .iter()
            .find(|f| f.name == name)
            .unwrap_or_else(|| panic!("Fields.{name} is declared"));
        assert!(f.public.is_none(), "Fields.{name} is private (#843)");
    }
    assert!(
        inner.iter().all(|f| f.public.is_none()),
        "every field of Fields is private (#869's fold)"
    );
    let (_, _, _, outer) = all
        .iter()
        .find(|(path, _, name, _)| {
            path == "src/transaction/transaction.rs" && name == "Transaction"
        })
        .expect("Transaction is declared in src/transaction/transaction.rs");
    let held = outer
        .iter()
        .find(|f| f.name == "fields")
        .expect("Transaction holds its Fields");
    assert!(held.public.is_none(), "Transaction.fields is private");
    assert_eq!(held.ty, ["fields", "::", "Fields"]);
    for name in ["version", "inputs", "outputs", "lock_time"] {
        assert!(
            outer.iter().all(|f| f.name != name),
            "Transaction declares no {name} of its own"
        );
    }
}

/// The scanner's reading on a probe: visibility forms, a tuple struct, a
/// generic one with a `where` clause and a function-pointer field, a cell
/// behind a path, a struct in a comment and in a string supplying nothing.
#[test]
fn the_scanner_reads_the_probe_843() {
    let probe = r#"
        // struct InComment { pub cache: RefCell<u8> }
        const S: &str = "struct InString { pub index: u8 }";
        pub struct Open { pub a: u8, b: std::cell::RefCell<u8> }
        pub struct Crate { pub(crate) a: u8, cache: Vec<u8> }
        pub struct Figure { pub cache_ttl_ms: u64, pub output_index: u32 }
        pub struct Super<T> where T: Clone { pub(super) f: fn(&T) -> T, by_index: Vec<T> }
        pub struct Tuple(pub u8, std::sync::OnceLock<u8>);
        pub struct Plain { pub a: u8 }
        pub struct Unit;
    "#;
    let tokens = arch_support::code_tokens(probe, false);
    let mut read = Vec::new();
    for at in 0..tokens.len() {
        if tokens[at].text != "struct" {
            continue;
        }
        let mut i = at + 2;
        if tokens[i].text == "<" {
            i = after(&tokens, i);
        }
        while !matches!(tokens[i].text, "{" | "(" | ";") {
            i += 1;
        }
        if tokens[i].text == ";" {
            continue;
        }
        let fs = fields(&tokens, i);
        let public: Vec<String> = fs
            .iter()
            .filter_map(|f| f.public.as_ref().map(|v| format!("{}:{v}", f.name)))
            .collect();
        read.push(format!(
            "{} {} {:?}",
            tokens[at + 1].text,
            holds_derived(&fs),
            public
        ));
    }
    assert_eq!(
        read,
        [
            r#"Open true ["a:pub"]"#,
            r#"Crate true ["a:pub(crate)"]"#,
            r#"Figure false ["cache_ttl_ms:pub", "output_index:pub"]"#,
            r#"Super true ["f:pub(super)"]"#,
            r#"Tuple true ["0:pub"]"#,
            r#"Plain false ["a:pub"]"#,
        ]
    );
}
