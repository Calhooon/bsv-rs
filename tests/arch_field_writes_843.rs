//! What the compiler does not hold of #843's write door, read lexically
//! (#869's sixth fold).
//!
//! The compiler holds every WRITE of `Transaction`'s four serialized fields:
//! they and the three caches derived from them live in `Fields`, declared in
//! the inline module `sealed` of `src/transaction/transaction/fields.rs`,
//! whose fields are private to that module. No code outside it can name a
//! field (E0616), build a `Fields` by a literal or a struct update (E0451),
//! or reach a `&mut` of a field but through `Fields::write`, which empties
//! every cache before it lends; `Fields::replace_source` links a source and
//! keeps the caches only under the outpoint rule's `Named` arm, and the two
//! copies keep the original's caches only where the copy writes the same
//! bytes. Until the sixth fold this file read every function of fields.rs
//! by name (the leading clear, the struct update, the macro, attribute and
//! derive lists), and each of three reads in a row found a spelling it did
//! not read (a trait method named `clear_caches`, `Self { .., ..f }`, a
//! closure in a `const`, `#[path]` on `mod fields;`); the compiler reads
//! none of them as a write, and the lists are gone.
//!
//! This file pins what the compiler's guarantee rests on, and claims nothing
//! else:
//! (a) the `sealed` module's text: its items, each by its signature (a new
//!     item, a changed signature or a second `impl` is red), no `pub` wider
//!     than `pub(super)` but the struct's name (`pub(in
//!     crate::transaction::transaction)`, for the owner `Transaction`), no
//!     attribute (`#`) and no macro (`!`) inside, `write` opening with the
//!     three takes, and the whole token stream's digest, so a body changed
//!     is red until the digest moves in the same diff, which a reader sees;
//! (b) the modules are the files read: `mod transaction;` in `src/lib.rs`
//!     and `src/transaction/mod.rs` with no `#[path]` or `#[cfg_attr]`,
//!     `mod fields;` in `transaction.rs` on its own line with no attribute,
//!     `mod sealed {` inline in fields.rs with no attribute, and no other
//!     module of either name under `src/` (plant Q, `#[path]` on `mod
//!     fields;`, compiled another file while this rule read the dead one);
//! (c) the cache fills: outside `sealed`, fields.rs names `caches` only in
//!     the functions on [`CACHE_READERS`], fills a cache by `.set(..)` only
//!     in [`SET_FILLS`] (the readers' fill, the test door) and by
//!     `.get_or_init(..)` only in [`LAZY_FILLS`] (the three fills from the
//!     fields). Lexical: a listed function's body is not read for what it
//!     puts in a cache, and a cache handed to a function of another file is
//!     not followed. A wrong value put into a cache through `&self` is what
//!     the identity property (`tests/transaction_identity_843.rs`) and the
//!     fuzz invariant (`fuzz_transaction_parser`, `fuzz_beef_parser`) catch,
//!     at every door they exercise.
//!
//! Since #843b the same pin holds the BEEF's write door. A `Beef`'s entries
//! and BUMPs live in `Rows`, declared in the inline module `sealed` of
//! `src/transaction/beef/rows.rs` beside the txid index and the two marks,
//! every field private to that module, so the compiler holds every write of
//! a row as it holds a transaction's: no code outside `sealed` can name a
//! field (E0616), build a `Rows` by a literal (E0451), or reach a `&mut` of
//! the entries but through `Rows::write`, which empties the index and sets
//! both marks before it lends; the other exclusive functions change one row
//! and its index key themselves, and no function lends the BUMPs' `Vec`
//! mutably. For that module this file pins rules (a) and (b), by the same
//! readers: its items by signature ([`ROWS_ITEMS`]), no `pub` wider than
//! `pub(super)` but the struct's name (`pub(in crate::transaction::beef)`),
//! no attribute and no macro inside, `write` opening with the index's
//! `take()` and the two marks, the tokens' digest ([`ROWS_DIGEST`]), and the
//! declarations (`mod beef;` in `src/transaction/mod.rs` with no `#[path]`,
//! `mod rows;` in `beef.rs` on its own line with no attribute and declared
//! once under `src/`, `mod sealed {` inline in `rows.rs`). Rule (c) has no
//! counterpart there: `Rows` lends no handle to its index (there is no
//! `caches`), so it is filled inside `sealed` alone, by `index` from the
//! rows and by `copy` from a filled one, which rule (a)'s digest holds and
//! [`ROWS_FILLS`] names. What this claims of the BEEF and nothing else:
//! the text the compiler's guarantee rests on is the text read. That an
//! entry's txid is its bytes' hash is the property's
//! (`tests/beef_rows_843b.rs`) and the fuzz target's.
#![allow(clippy::expect_used, clippy::panic)] // Source reads are test assertions.

mod arch_support;

use arch_support::{attributes_before, group_end, joined, Source, Token};

const FIELDS: &str = "src/transaction/transaction/fields.rs";
const OWNER: &str = "src/transaction/transaction.rs";

/// The `sealed` module's items in order, each its tokens from its first to
/// its body's `{` (a `use`, its `;`; the struct, whole), joined by spaces.
const SEALED_ITEMS: &[&str] = &[
    "use std :: sync :: OnceLock ;",
    "use crate :: transaction :: { Transaction , TransactionInput , TransactionOutput } ;",
    "pub ( in crate :: transaction :: transaction ) struct Fields { version : u32 , inputs : Vec < TransactionInput > , outputs : Vec < TransactionOutput > , lock_time : u32 , cached_hash : OnceLock < [ u8 ; 32 ] > , raw_bytes_cache : OnceLock < Vec < u8 > > , hex_cache : OnceLock < String > , }",
    "fn named ( input : & TransactionInput ) - > bool",
    "impl Fields",
    "impl Fields > pub ( super ) fn new ( version : u32 , inputs : Vec < TransactionInput > , outputs : Vec < TransactionOutput > , lock_time : u32 , ) - > Self",
    "impl Fields > pub ( super ) fn read ( & self ) - > ( u32 , & [ TransactionInput ] , & [ TransactionOutput ] , u32 )",
    "impl Fields > pub ( super ) fn caches ( & self , ) - > ( & OnceLock < [ u8 ; 32 ] > , & OnceLock < Vec < u8 > > , & OnceLock < String > )",
    "impl Fields > pub ( super ) fn write ( & mut self , ) - > ( & mut u32 , & mut Vec < TransactionInput > , & mut Vec < TransactionOutput > , & mut u32 , )",
    "impl Fields > pub ( super ) fn into_four ( self ) - > ( u32 , Vec < TransactionInput > , Vec < TransactionOutput > , u32 )",
    "impl Fields > pub ( super ) fn replace_source ( & mut self , index : usize , source : Option < Box < Transaction > > , ) - > Option < Box < Transaction > >",
    "impl Fields > pub ( super ) fn copy_relinked ( & self , sources : Vec < Option < Box < Transaction > > > ) - > Self",
    "impl Fields > pub ( super ) fn copy_named ( & self ) - > Self",
    "impl Fields > fn copy_with ( & self , inputs : Vec < TransactionInput > , keep : bool ) - > Self",
];

/// FNV-1a (64 bits) of the `sealed` module's tokens joined by one space:
/// a body changed moves it (comments and layout do not).
const SEALED_DIGEST: u64 = 0xa0d0_a5a0_53ac_1924;

/// The BEEF's sealed module (#843b) and the module that owns it.
const ROWS: &str = "src/transaction/beef/rows.rs";
const ROWS_OWNER: &str = "src/transaction/beef.rs";

/// The items of `rows.rs`' `sealed` module in order, read as
/// [`SEALED_ITEMS`] is.
const ROWS_ITEMS: &[&str] = &[
    "use std :: collections :: HashMap ;",
    "use std :: sync :: OnceLock ;",
    "use crate :: transaction :: { BeefTx , MerklePath , Transaction , Txid } ;",
    "struct Index { at : HashMap < Txid , usize > , twins : bool , }",
    "pub ( in crate :: transaction :: beef ) struct Rows { txs : Vec < BeefTx > , bumps : Vec < MerklePath > , index : OnceLock < Index > , needs_sort : bool , wire_order : bool , }",
    "impl Rows",
    "impl Rows > pub ( super ) fn of ( txs : Vec < BeefTx > , bumps : Vec < MerklePath > , as_read : bool ) - > Self",
    "impl Rows > pub ( super ) fn copy ( & self ) - > Self",
    "impl Rows > pub ( super ) fn txs ( & self ) - > & [ BeefTx ]",
    "impl Rows > pub ( super ) fn bumps ( & self ) - > & [ MerklePath ]",
    "impl Rows > pub ( super ) fn needs_sort ( & self ) - > bool",
    "impl Rows > pub ( super ) fn wire_order ( & self ) - > bool",
    "impl Rows > fn index ( & self ) - > & Index",
    "impl Rows > pub ( super ) fn position ( & self , txid : & Txid ) - > Option < usize >",
    "impl Rows > pub ( super ) fn append ( & mut self , entry : BeefTx ) - > usize",
    "impl Rows > pub ( super ) fn replace ( & mut self , position : usize , entry : BeefTx ) - > BeefTx",
    "impl Rows > pub ( super ) fn swap_parse ( & mut self , position : usize , tx : Transaction , ) - > Option < Transaction >",
    "impl Rows > pub ( super ) fn point ( & mut self , position : usize , bump : Option < usize > )",
    "impl Rows > pub ( super ) fn push_bump ( & mut self , bump : MerklePath ) - > usize",
    "impl Rows > pub ( super ) fn bump_mut ( & mut self , index : usize ) - > Option < & mut MerklePath >",
    "impl Rows > pub ( super ) fn retain_bumps ( & mut self , mut keep : impl FnMut ( usize , & MerklePath ) - > bool )",
    "impl Rows > pub ( super ) fn write ( & mut self ) - > ( & mut Vec < BeefTx > , & [ MerklePath ] )",
    "impl Rows > pub ( super ) fn hold_order ( & mut self )",
    "impl Rows > pub ( super ) fn touch ( & mut self )",
];

/// FNV-1a (64 bits) of `rows.rs`' `sealed` module's tokens.
const ROWS_DIGEST: u64 = 0x8628_ec31_d463_adf3;

/// The functions of `rows.rs`' `sealed` module that fill the index, each
/// with its `OnceLock` method: `index` from the rows as they stand, `copy`
/// from a filled index of the rows it copies.
const ROWS_FILLS: &[(&str, &str)] = &[("copy", "set"), ("index", "get_or_init")];

/// One sealed module as rule (a) reads it.
struct Sealed {
    /// Its items in order.
    items: &'static [&'static str],
    /// Its tokens' digest.
    digest: u64,
    /// The tokens after the one `pub` wider than `pub(super)`: the struct's
    /// name, visible to its owner's module.
    struct_name: &'static str,
    /// The one exclusive door that lends, and the tokens its body opens with.
    door: &'static str,
    opens: &'static str,
}

/// `Transaction`'s (`fields.rs`).
const FIELDS_SEALED: Sealed = Sealed {
    items: SEALED_ITEMS,
    digest: SEALED_DIGEST,
    struct_name: "( in crate :: transaction :: transaction ) struct Fields {",
    door: "write",
    opens: "self . cached_hash . take ( ) ; self . raw_bytes_cache . take ( ) ; self . hex_cache . take ( ) ;",
};

/// `Beef`'s (`rows.rs`, #843b).
const ROWS_SEALED: Sealed = Sealed {
    items: ROWS_ITEMS,
    digest: ROWS_DIGEST,
    struct_name: "( in crate :: transaction :: beef ) struct Rows {",
    door: "write",
    opens: "self . index . take ( ) ; self . needs_sort = true ; self . wire_order = false ;",
};

/// The functions of fields.rs, outside `sealed`, that may name `caches`.
const CACHE_READERS: &[&str] = &[
    // The readers' fill and the test door (below).
    "read_exact",
    "with_cached_bytes_for_test",
    // The three fills from the fields.
    "serialized_bytes",
    "serialized_hex",
    "serialized_hash",
    // Reads the cached bytes for the BEEF writers' check.
    "with_cached_bytes",
    // Reads whether a linked source's hash is cached.
    "unhashed",
    // `Debug` prints the caches.
    "fmt",
];

/// The functions that fill a cache by `.set(..)`: the readers' fill (the
/// bytes just read, exactly one transaction, #840) and the test door (the
/// crate's tests and `internal-test-doors`, no part of the API).
const SET_FILLS: &[&str] = &["read_exact", "with_cached_bytes_for_test"];

/// The functions that fill a cache by `.get_or_init(..)`, from the fields.
const LAZY_FILLS: &[&str] = &["serialized_bytes", "serialized_hex", "serialized_hash"];

/// The `OnceLock` methods that fill through `&self`.
const FILL_METHODS: &[&str] = &["set", "get_or_init", "get_or_try_init", "try_insert"];

fn source(path: &str) -> Source {
    Source {
        path: path.into(),
        text: arch_support::read(path),
    }
}

use arch_support::fnv;

/// The `sealed` module's body, `mod sealed {` .. `}` exclusive, as raw
/// tokens, with the line of its `mod` token; `None` when fields.rs holds no
/// `mod sealed {`.
fn sealed_body<'a>(tokens: &'a [Token<'a>]) -> Option<(&'a [Token<'a>], usize)> {
    let at = (0..tokens.len().saturating_sub(2)).find(|&k| {
        !tokens[k].literal
            && tokens[k].text == "mod"
            && tokens[k + 1].text == "sealed"
            && tokens[k + 2].text == "{"
    })?;
    let end = group_end(tokens, at + 2);
    Some((&tokens[at + 3..end - 1], tokens[at].line))
}

/// The items of a body: each from its first token to its body's `{` (the
/// body itself skipped, an `impl`'s items read with the `impl`'s header as
/// a prefix) or to its `;`; a struct whole.
fn items(tokens: &[Token<'_>], prefix: &str, out: &mut Vec<String>) {
    let mut k = 0;
    while k < tokens.len() {
        let start = k;
        let mut struct_item = false;
        if tokens[k].text == "use" {
            while k < tokens.len() && (tokens[k].literal || tokens[k].text != ";") {
                k += 1;
            }
            out.push(format!(
                "{prefix}{}",
                joined(&tokens[start..(k + 1).min(tokens.len())])
            ));
            k += 1;
            continue;
        }
        while k < tokens.len() && (tokens[k].literal || !matches!(tokens[k].text, "{" | ";")) {
            if tokens[k].text == "struct" {
                struct_item = true;
            }
            k = if matches!(tokens[k].text, "(" | "[") && !tokens[k].literal {
                group_end(tokens, k)
            } else {
                k + 1
            };
            if k >= tokens.len() {
                break;
            }
        }
        if k >= tokens.len() {
            out.push(format!(
                "{prefix}{} (unterminated)",
                joined(&tokens[start..])
            ));
            return;
        }
        if tokens[k].text == ";" {
            out.push(format!("{prefix}{}", joined(&tokens[start..=k])));
            k += 1;
            continue;
        }
        let end = group_end(tokens, k);
        if struct_item {
            out.push(format!("{prefix}{}", joined(&tokens[start..end])));
        } else {
            let header = joined(&tokens[start..k]);
            out.push(format!("{prefix}{header}"));
            if tokens[start].text == "impl" {
                items(&tokens[k + 1..end - 1], &format!("{header} > "), out);
            }
        }
        k = end;
    }
}

/// Rule (a): the `sealed` module's text.
fn sealed_errors(fields: &Source, spec: &Sealed) -> Vec<String> {
    let tokens = fields.raw_tokens();
    let Some((body, line)) = sealed_body(&tokens) else {
        return vec![format!("{}: no inline `mod sealed {{`", fields.path)];
    };
    let mut errors = Vec::new();
    let mut found = Vec::new();
    items(body, "", &mut found);
    let want: Vec<String> = spec.items.iter().map(|s| s.to_string()).collect();
    let count = |list: &[String], item: &String| list.iter().filter(|i| *i == item).count();
    let mut seen = Vec::new();
    for item in found.iter().filter(|i| count(&found, i) > count(&want, i)) {
        if seen.contains(item) {
            continue;
        }
        seen.push(item.clone());
        errors.push(format!(
            "{}:{line}: `sealed` holds an item not on its list, or one whose signature moved: `{item}`",
            fields.path
        ));
    }
    for item in want.iter().filter(|i| !found.contains(i)) {
        errors.push(format!(
            "{}:{line}: `sealed` lacks the listed item `{item}`",
            fields.path
        ));
    }
    if errors.is_empty() && found != want {
        errors.push(format!(
            "{}:{line}: `sealed`'s items are out of their listed order",
            fields.path
        ));
    }
    for (k, t) in body.iter().enumerate() {
        if t.literal {
            continue;
        }
        if t.text == "pub" {
            let rest = joined(&body[k + 1..(k + 4).min(body.len())]);
            let struct_name = joined(&body[k + 1..(k + 12).min(body.len())]);
            if rest != "( super )" && struct_name != spec.struct_name {
                errors.push(format!(
                    "{}:{}: a `pub` wider than `pub(super)` in `sealed` (only the struct's name is visible to the owner's module)",
                    fields.path, t.line
                ));
            }
        }
        if t.text == "#" {
            errors.push(format!(
                "{}:{}: an attribute in `sealed`: nothing may be expanded, gated or derived into it",
                fields.path, t.line
            ));
        }
        if t.text == "!"
            && k > 0
            && body[k - 1]
                .text
                .chars()
                .all(|c| c.is_alphanumeric() || c == '_')
            && body
                .get(k + 1)
                .is_some_and(|n| matches!(n.text, "(" | "[" | "{"))
        {
            errors.push(format!(
                "{}:{}: a macro in `sealed`: its expansion is code this pin cannot read",
                fields.path, t.line
            ));
        }
    }
    let write = (0..body.len().saturating_sub(1))
        .find(|&k| body[k].text == "fn" && body[k + 1].text == spec.door);
    let length = spec.opens.split(' ').count();
    let opens = write
        .and_then(|w| (w..body.len()).find(|&k| body[k].text == "{"))
        .is_some_and(|open| {
            joined(&body[open + 1..(open + 1 + length).min(body.len())]) == spec.opens
        });
    if !opens {
        errors.push(format!(
            "{}:{line}: `{}` does not open with `{}`: the one exclusive door must empty what is derived before it lends",
            fields.path, spec.door, spec.opens
        ));
    }
    let digest = fnv(&joined(body));
    if digest != spec.digest {
        errors.push(format!(
            "{}:{line}: `sealed`'s text moved (digest {digest:#018x}, pinned {:#018x}): a body of the module that holds the write door changed; read it, then move the pin in the same diff",
            fields.path, spec.digest
        ));
    }
    errors
}

/// The BEEF's index is filled inside `sealed` alone, by the listed
/// functions: every `OnceLock` fill of `rows.rs` stands inside the module,
/// in a function of [`ROWS_FILLS`] with its method.
fn rows_fill_errors(rows: &Source) -> Vec<String> {
    let tokens = rows.raw_tokens();
    let sealed = sealed_body(&tokens).map(|(body, _)| {
        (
            body.first().map_or(0, |t| t.line),
            body.last().map_or(0, |t| t.line),
        )
    });
    let in_sealed = |t: &Token<'_>| sealed.is_some_and(|(a, b)| t.line >= a && t.line <= b);
    let spans = fn_spans(&tokens);
    let mut errors = Vec::new();
    for (k, t) in tokens.iter().enumerate() {
        let method = k >= 1 && tokens[k - 1].text == "." && FILL_METHODS.contains(&t.text);
        if t.literal || !method {
            continue;
        }
        let name = spans
            .iter()
            .filter(|(a, b, _)| *a <= k && k < *b)
            .max_by_key(|(a, _, _)| *a)
            .map_or("<no function>", |(_, _, n)| n.as_str());
        if !in_sealed(t) || !ROWS_FILLS.contains(&(name, t.text)) {
            errors.push(format!(
                "{}:{}: `{name}` calls `.{}(..)`: the index is filled inside `sealed` by {ROWS_FILLS:?} alone",
                rows.path, t.line, t.text
            ));
        }
    }
    errors
}

/// Rule (b): the modules are the files read.
fn module_errors(sources: &[Source]) -> Vec<String> {
    let mut errors = Vec::new();
    let mut fields_decls = Vec::new();
    let mut sealed_decls = Vec::new();
    let mut rows_decls = Vec::new();
    let mut beef_decl = false;
    let mut chain = [("src/lib.rs", false), ("src/transaction/mod.rs", false)];
    for s in sources {
        let tokens = s.raw_tokens();
        for k in 0..tokens.len().saturating_sub(2) {
            if tokens[k].literal || tokens[k].text != "mod" {
                continue;
            }
            let name = tokens[k + 1].text;
            let next = tokens[k + 2].text;
            let attrs = attributes_before(&tokens, k);
            match name {
                "transaction" => {
                    if let Some(entry) = chain.iter_mut().find(|(p, _)| *p == s.path) {
                        entry.1 = true;
                        if attrs
                            .iter()
                            .any(|a| a.starts_with("path") || a.starts_with("cfg_attr"))
                            || next != ";"
                        {
                            errors.push(format!(
                                "{}:{}: `mod transaction` must be declared `mod transaction;` with no `#[path]` or `#[cfg_attr]`: this rule reads the default file",
                                s.path, tokens[k].line
                            ));
                        }
                    }
                }
                "fields" => {
                    fields_decls.push(format!("{}:{}", s.path, tokens[k].line));
                    if s.path != OWNER
                        || next != ";"
                        || !attrs.is_empty()
                        || s.line(tokens[k].line) != "mod fields;"
                    {
                        errors.push(format!(
                            "{}:{}: `mod fields` must be `mod fields;` on a line of its own in {OWNER} with no attribute: this rule reads {FIELDS}",
                            s.path, tokens[k].line
                        ));
                    }
                }
                "sealed" => {
                    sealed_decls.push(format!("{}:{}", s.path, tokens[k].line));
                    if !(s.path == FIELDS || s.path == ROWS) || next != "{" || !attrs.is_empty() {
                        errors.push(format!(
                            "{}:{}: `mod sealed` must be inline (`mod sealed {{`) in {FIELDS} or {ROWS} with no attribute",
                            s.path, tokens[k].line
                        ));
                    }
                }
                // The BEEF's chain (#843b): `mod beef;` in the transaction
                // module (another module of the name, elsewhere, is not it).
                "beef" if s.path == "src/transaction/mod.rs" => {
                    beef_decl = true;
                    if attrs
                        .iter()
                        .any(|a| a.starts_with("path") || a.starts_with("cfg_attr"))
                        || next != ";"
                    {
                        errors.push(format!(
                            "{}:{}: `mod beef` must be declared `mod beef;` with no `#[path]` or `#[cfg_attr]`: this rule reads {ROWS_OWNER}",
                            s.path, tokens[k].line
                        ));
                    }
                }
                "rows" => {
                    rows_decls.push(format!("{}:{}", s.path, tokens[k].line));
                    if s.path != ROWS_OWNER
                        || next != ";"
                        || !attrs.is_empty()
                        || s.line(tokens[k].line) != "mod rows;"
                    {
                        errors.push(format!(
                            "{}:{}: `mod rows` must be `mod rows;` on a line of its own in {ROWS_OWNER} with no attribute: this rule reads {ROWS}",
                            s.path, tokens[k].line
                        ));
                    }
                }
                _ => {}
            }
        }
    }
    for (path, seen) in chain {
        if !seen && sources.iter().any(|s| s.path == path) {
            errors.push(format!("{path}: no `mod transaction;`"));
        }
    }
    if !beef_decl && sources.iter().any(|s| s.path == "src/transaction/mod.rs") {
        errors.push("src/transaction/mod.rs: no `mod beef;`".to_string());
    }
    // `mod sealed` once in each of the two files that hold a write door.
    for (name, decls, times) in [
        ("fields", &fields_decls, 1),
        ("rows", &rows_decls, 1),
        ("sealed", &sealed_decls, 2),
    ] {
        if decls.len() != times {
            errors.push(format!(
                "`mod {name}` declared {} times under src/ ({}): exactly {times}",
                decls.len(),
                decls.join(", ")
            ));
        }
    }
    for path in [FIELDS, ROWS] {
        let held = sealed_decls
            .iter()
            .filter(|d| d.starts_with(&format!("{path}:")))
            .count();
        if held != 1 && sources.iter().any(|s| s.path == path) {
            errors.push(format!(
                "{path}: `mod sealed` declared {held} times: exactly once"
            ));
        }
    }
    errors
}

/// `(fn token, body end)` of every `fn` item with a body.
fn fn_spans(tokens: &[Token<'_>]) -> Vec<(usize, usize, String)> {
    let mut out = Vec::new();
    for i in 0..tokens.len() {
        // `fn` before `(` is a pointer type, not an item.
        if tokens[i].literal
            || tokens[i].text != "fn"
            || tokens.get(i + 1).is_some_and(|t| t.text == "(")
        {
            continue;
        }
        let mut j = i + 2;
        while j < tokens.len() && !matches!(tokens[j].text, "{" | ";") {
            j = if matches!(tokens[j].text, "(" | "[") {
                group_end(tokens, j)
            } else {
                j + 1
            };
        }
        if j < tokens.len() && tokens[j].text == "{" {
            out.push((i, group_end(tokens, j), tokens[i + 1].text.to_string()));
        }
    }
    out
}

/// Rule (c): where fields.rs, outside `sealed`, names the caches and fills
/// one.
fn fill_errors(fields: &Source) -> Vec<String> {
    let tokens = fields.raw_tokens();
    let sealed = sealed_body(&tokens).map(|(body, _)| {
        let start = body.first().map_or(0, |t| t.line);
        let end = body.last().map_or(0, |t| t.line);
        (start, end)
    });
    let in_sealed = |t: &Token<'_>| sealed.is_some_and(|(a, b)| t.line >= a && t.line <= b);
    let spans = fn_spans(&tokens);
    let enclosing = |k: usize| {
        spans
            .iter()
            .filter(|(a, b, _)| *a <= k && k < *b)
            .max_by_key(|(a, _, _)| *a)
            .map_or("<no function>", |(_, _, n)| n.as_str())
    };
    let mut errors = Vec::new();
    for (k, t) in tokens.iter().enumerate() {
        if t.literal || in_sealed(t) {
            continue;
        }
        let name = enclosing(k);
        if t.text == "caches" && !CACHE_READERS.contains(&name) {
            errors.push(format!(
                "{}:{}: `{name}` names `caches` outside the listed readers ({CACHE_READERS:?})",
                fields.path, t.line
            ));
        }
        let method = k >= 1 && tokens[k - 1].text == "." && FILL_METHODS.contains(&t.text);
        let listed = match t.text {
            "set" => SET_FILLS.contains(&name),
            "get_or_init" => LAZY_FILLS.contains(&name),
            _ => false,
        };
        if method && !listed {
            errors.push(format!(
                "{}:{}: `{name}` calls `.{}(..)` outside the listed fills (set: {SET_FILLS:?}; get_or_init: {LAZY_FILLS:?})",
                fields.path, t.line, t.text
            ));
        }
    }
    errors
}

/// The one macro fields.rs may invoke outside `sealed`: `debug_assert!`,
/// std's, expanding to its arguments' code, which is the file's text.
const MACROS: &[&str] = &["debug_assert"];

/// Rule (c), what a fill could hide behind (kept from the fifth fold for
/// (c) alone; a write it once refused is the compiler's now): outside
/// `sealed`, fields.rs invokes no macro but [`MACROS`] (a `macro_rules!` of
/// `transaction.rs`, `include!`, a macro named by a path could fill a cache
/// in a listed or unlisted function without naming `caches` in the file's
/// text), defines none, imports none by a `use` or a glob, and declares no
/// module but `sealed` and modules under exactly `#[cfg(test)]` (a child
/// module in another file calls `caches` unread); and no `macro_rules!`
/// under `src/` takes a name on [`MACROS`] (it would shadow std's).
fn expansion_errors(fields: &Source, sources: &[Source]) -> Vec<String> {
    let tokens = fields.raw_tokens();
    let sealed = sealed_body(&tokens).map(|(body, _)| {
        (
            body.first().map_or(0, |t| t.line),
            body.last().map_or(0, |t| t.line),
        )
    });
    let in_sealed = |t: &Token<'_>| sealed.is_some_and(|(a, b)| t.line >= a && t.line <= b);
    let word =
        |t: &Token<'_>| !t.literal && t.text.chars().all(|c| c.is_alphanumeric() || c == '_');
    let mut errors = Vec::new();
    for k in 0..tokens.len() {
        let t = tokens[k];
        if t.literal || in_sealed(&t) {
            continue;
        }
        if t.text == "!"
            && k >= 1
            && word(&tokens[k - 1])
            && !matches!(
                tokens[k - 1].text,
                "if" | "while" | "return" | "match" | "in" | "let" | "else" | "mut" | "as"
            )
            && tokens
                .get(k + 1)
                .is_some_and(|n| matches!(n.text, "(" | "[" | "{"))
        {
            let name = tokens[k - 1].text;
            let path = k >= 2 && tokens[k - 2].text == "::";
            if path || !MACROS.contains(&name) {
                errors.push(format!(
                    "{}:{}: `{name}!` in fields.rs: a macro outside {MACROS:?} (or named by a path) can fill a cache where rule (c) cannot read it",
                    fields.path, t.line
                ));
            }
        }
        if t.text == "use" {
            let end = (k..tokens.len())
                .find(|&j| tokens[j].text == ";")
                .unwrap_or(tokens.len());
            for u in &tokens[k..end] {
                if u.text == "*" || MACROS.contains(&u.text) {
                    errors.push(format!(
                        "{}:{}: `use` of `{}` in fields.rs: a glob or an import of a listed macro's name",
                        fields.path, u.line, u.text
                    ));
                }
            }
        }
        if t.text == "mod" {
            let name = tokens.get(k + 1).map_or("", |n| n.text);
            let attrs = attributes_before(&tokens, k);
            if name != "sealed" && !attrs.iter().any(|a| a == "cfg ( test )") {
                errors.push(format!(
                    "{}:{}: `mod {name}` in fields.rs outside `#[cfg(test)]`: a child module in another file can fill a cache where rule (c) cannot read it",
                    fields.path, t.line
                ));
            }
        }
    }
    for s in std::iter::once(fields).chain(sources.iter().filter(|s| s.path != fields.path)) {
        let tokens = s.raw_tokens();
        for k in 0..tokens.len().saturating_sub(2) {
            if !tokens[k].literal
                && tokens[k].text == "macro_rules"
                && tokens[k + 1].text == "!"
                && (s.path == fields.path || MACROS.contains(&tokens[k + 2].text))
            {
                errors.push(format!(
                    "{}:{}: `macro_rules! {}`: a macro defined in fields.rs, or one shadowing a macro fields.rs invokes",
                    s.path, tokens[k].line, tokens[k + 2].text
                ));
            }
        }
    }
    errors
}

fn all_errors(fields: &Source, sources: &[Source]) -> Vec<String> {
    let mut errors = sealed_errors(fields, &FIELDS_SEALED);
    errors.extend(module_errors(sources));
    errors.extend(fill_errors(fields));
    errors.extend(expansion_errors(fields, sources));
    errors
}

/// The BEEF's pin (#843b): rule (a) on `rows.rs` and where its index is
/// filled (rule (b) is `module_errors`, read once for both modules).
fn rows_errors(rows: &Source) -> Vec<String> {
    let mut errors = sealed_errors(rows, &ROWS_SEALED);
    errors.extend(rows_fill_errors(rows));
    errors
}

#[test]
fn the_sealed_module_the_declarations_and_the_fills_are_as_pinned_869() {
    let errors = all_errors(&source(FIELDS), &arch_support::sources());
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

/// The tree's fields.rs with `edit` applied, as a probe.
fn fields_with(from: &str, to: &str) -> Source {
    let real = source(FIELDS);
    assert!(
        real.text.contains(from),
        "the probe's anchor `{from}` moved"
    );
    Source {
        path: FIELDS.into(),
        text: real.text.replacen(from, to, 1),
    }
}

/// Rule (a) on probes: the reverse plants of the sixth fold, each red by
/// its message.
#[test]
fn the_sealed_pin_refuses_each_change_869() {
    let cases = [
        (
            // The exclusive door without its clear.
            "            self.cached_hash.take();\n            self.raw_bytes_cache.take();\n            self.hex_cache.take();\n            (\n",
            "            (\n",
            "`write` does not open with `self . cached_hash . take ( ) ;",
        ),
        (
            // A third function in the module's impl.
            "        /// The four fields, shared.\n",
            "        pub(super) fn version_mut(&mut self) -> &mut u32 { &mut self.version }\n",
            "an item not on its list",
        ),
        (
            // `pub(crate)` on a field.
            "        version: u32,\n        inputs",
            "        pub(crate) version: u32,\n        inputs",
            "a `pub` wider than `pub(super)`",
        ),
        (
            "        lock_time: u32,\n        cached_hash",
            "        #[cfg(test)]\n        lock_time: u32,\n        cached_hash",
            "an attribute in `sealed`",
        ),
        (
            "            self.copy_with(inputs, true)\n",
            "            debug_assert!(true);\n            self.copy_with(inputs, true)\n",
            "a macro in `sealed`",
        ),
        (
            "            self.copy_with(inputs, true)\n",
            "            self.copy_with(inputs, false)\n",
            "`sealed`'s text moved",
        ),
        (
            "    impl Fields {\n        /// The four fields, no cache.",
            "    impl Fields {}\n    impl Fields {\n        /// The four fields, no cache.",
            "an item not on its list",
        ),
    ];
    for (from, to, want) in cases {
        let errors = sealed_errors(&fields_with(from, to), &FIELDS_SEALED);
        assert!(
            errors.iter().any(|e| e.contains(want)),
            "`{to}` should read `{want}`: {errors:#?}"
        );
    }
}

/// The BEEF's `sealed` module and where its index is filled are as pinned
/// (#843b).
#[test]
fn the_beefs_sealed_module_is_as_pinned_843b() {
    let errors = rows_errors(&source(ROWS));
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

/// The tree's rows.rs with `edit` applied, as a probe.
fn rows_with(from: &str, to: &str) -> Source {
    let real = source(ROWS);
    assert!(
        real.text.contains(from),
        "the probe's anchor `{from}` moved"
    );
    Source {
        path: ROWS.into(),
        text: real.text.replacen(from, to, 1),
    }
}

/// Rule (a) on probes of `rows.rs`, the reverse plants of #843b, each red
/// by its message: the general door without its emptying or without a
/// mark, a new function in the module (one that lends an entry, one that
/// lends the BUMPs), a wider `pub`, an attribute, a macro, a body changed
/// (an append that skips the index), a second `impl`; and a fill of the
/// index outside `sealed` or in an unlisted function.
#[test]
fn the_beefs_sealed_pin_refuses_each_change_843b() {
    let door = "            self.index.take();\n            self.needs_sort = true;\n            self.wire_order = false;\n            (&mut self.txs, &self.bumps)\n";
    let cases = [
        (
            // The general door without its emptying.
            door,
            "            self.needs_sort = true;\n            self.wire_order = false;\n            (&mut self.txs, &self.bumps)\n",
            "`write` does not open with `self . index . take ( ) ;",
        ),
        (
            // The general door without the wire mark.
            door,
            "            self.index.take();\n            self.needs_sort = true;\n            (&mut self.txs, &self.bumps)\n",
            "`write` does not open with `self . index . take ( ) ;",
        ),
        (
            // A function that lends a held entry.
            "        /// The entries, shared.\n",
            "        pub(super) fn entry_mut(&mut self, at: usize) -> &mut BeefTx { &mut self.txs[at] }\n",
            "an item not on its list",
        ),
        (
            // A function that lends the BUMPs' list.
            "        /// The entries, shared.\n",
            "        pub(super) fn bumps_mut(&mut self) -> &mut Vec<MerklePath> { &mut self.bumps }\n",
            "an item not on its list",
        ),
        (
            // `pub(crate)` on a field.
            "        txs: Vec<BeefTx>,\n        bumps",
            "        pub(crate) txs: Vec<BeefTx>,\n        bumps",
            "a `pub` wider than `pub(super)`",
        ),
        (
            "        bumps: Vec<MerklePath>,\n        index",
            "        #[cfg(test)]\n        bumps: Vec<MerklePath>,\n        index",
            "an attribute in `sealed`",
        ),
        (
            "            self.bumps.push(bump);\n",
            "            debug_assert!(true);\n            self.bumps.push(bump);\n",
            "a macro in `sealed`",
        ),
        (
            // An append that skips the index.
            "                index.twins |= index.at.insert(entry.txid(), position).is_some();\n            }\n            self.needs_sort = true;",
            "            }\n            self.needs_sort = true;",
            "`sealed`'s text moved",
        ),
        (
            "    impl Rows {\n        /// The rows as given",
            "    impl Rows {}\n    impl Rows {\n        /// The rows as given",
            "an item not on its list",
        ),
    ];
    for (from, to, want) in cases {
        let errors = sealed_errors(&rows_with(from, to), &ROWS_SEALED);
        assert!(
            errors.iter().any(|e| e.contains(want)),
            "`{to}` should read `{want}`: {errors:#?}"
        );
    }
    let fills = [
        (
            // A fill outside `sealed` (it could not name the field: the
            // compiler refuses it; the rule reads the method all the same).
            "impl Beef {\n    /// The entries, in the order held.",
            "fn plant(c: &std::sync::OnceLock<u8>) { let _ = c.set(1); }\nimpl Beef {\n    /// The entries, in the order held.",
            "`plant` calls `.set(..)`",
        ),
        (
            // A fill in another function of `sealed`.
            "            self.wire_order = false;\n            self.bumps.get_mut(index)\n",
            "            self.wire_order = false;\n            let _ = self.index.get_or_init(|| Index { at: HashMap::new(), twins: false });\n            self.bumps.get_mut(index)\n",
            "`bump_mut` calls `.get_or_init(..)`",
        ),
    ];
    for (from, to, want) in fills {
        let errors = rows_fill_errors(&rows_with(from, to));
        assert!(
            errors.iter().any(|e| e.contains(want)),
            "`{to}` should read `{want}`: {errors:#?}"
        );
    }
}

/// Rule (b) on probes of the BEEF's chain: `#[path]` on `mod rows;` or on
/// `mod beef;`, `mod rows;` made visible, a second `mod sealed` in
/// `rows.rs`, each refused.
#[test]
fn the_module_rule_refuses_another_file_for_the_rows_843b() {
    let mut sources = arch_support::sources();
    let at = |sources: &[Source], path: &str| {
        sources
            .iter()
            .position(|s| s.path == path)
            .unwrap_or_else(|| panic!("{path}"))
    };
    let owner = at(&sources, ROWS_OWNER);
    for (to, want) in [
        (
            "#[path = \"beef/rows_q.rs\"]\nmod rows;",
            "`mod rows` must be `mod rows;`",
        ),
        (
            "#[cfg_attr(all(), path = \"q.rs\")]\nmod rows;",
            "`mod rows` must be `mod rows;`",
        ),
        ("pub(super) mod rows;", "`mod rows` must be `mod rows;`"),
        (
            "mod rows;\nmod rows;",
            "`mod rows` declared 2 times under src/",
        ),
    ] {
        let saved = sources[owner].text.clone();
        assert!(saved.contains("\nmod rows;\n"));
        sources[owner].text = saved.replacen("mod rows;", to, 1);
        let errors = module_errors(&sources);
        assert!(errors.iter().any(|e| e.contains(want)), "{to}: {errors:#?}");
        sources[owner].text = saved;
    }
    let module = at(&sources, "src/transaction/mod.rs");
    let saved = sources[module].text.clone();
    assert!(saved.contains("pub mod beef;"));
    sources[module].text = saved.replacen("pub mod beef;", "#[path = \"b2.rs\"]\npub mod beef;", 1);
    let errors = module_errors(&sources);
    assert!(
        errors
            .iter()
            .any(|e| e.contains("`mod beef` must be declared")),
        "{errors:#?}"
    );
    sources[module].text = saved;
    let rows = at(&sources, ROWS);
    let saved = sources[rows].text.clone();
    sources[rows].text = format!("{saved}\nmod sealed {{}}\n");
    let errors = module_errors(&sources);
    assert!(
        errors
            .iter()
            .any(|e| e.contains("`mod sealed` declared 2 times")),
        "{errors:#?}"
    );
    sources[rows].text = saved;
    assert!(module_errors(&sources).is_empty());
}

/// Rule (b) on probes: plant Q and its siblings.
#[test]
fn the_module_rule_refuses_another_file_869() {
    let mut sources = arch_support::sources();
    let owner = sources
        .iter()
        .position(|s| s.path == OWNER)
        .expect("the owner");
    let plants = [
        (
            "#[path = \"transaction/fields_q.rs\"]\nmod fields;",
            "`mod fields` must be `mod fields;`",
        ),
        (
            "#[cfg_attr(all(), path = \"q.rs\")]\nmod fields;",
            "`mod fields` must be `mod fields;`",
        ),
        (
            "pub(super) mod fields;",
            "`mod fields` must be `mod fields;`",
        ),
        ("mod fields;\nmod sealed;", "`mod sealed` must be inline"),
    ];
    for (to, want) in plants {
        let saved = sources[owner].text.clone();
        sources[owner].text = saved.replacen("mod fields;", to, 1);
        let errors = module_errors(&sources);
        assert!(errors.iter().any(|e| e.contains(want)), "{to}: {errors:#?}");
        sources[owner].text = saved;
    }
    let fields = sources
        .iter()
        .position(|s| s.path == FIELDS)
        .expect("fields.rs");
    let saved = sources[fields].text.clone();
    sources[fields].text = saved.replacen("mod sealed {", "#[path = \"x.rs\"]\nmod sealed {", 1);
    let errors = module_errors(&sources);
    assert!(
        errors
            .iter()
            .any(|e| e.contains("`mod sealed` must be inline")),
        "{errors:#?}"
    );
    sources[fields].text = saved;
    let module = sources
        .iter()
        .position(|s| s.path == "src/transaction/mod.rs")
        .expect("src/transaction/mod.rs");
    let saved = sources[module].text.clone();
    assert!(saved.contains("mod transaction;"));
    sources[module].text = saved.replacen(
        "mod transaction;",
        "#[path = \"t2.rs\"]\nmod transaction;",
        1,
    );
    let errors = module_errors(&sources);
    assert!(
        errors
            .iter()
            .any(|e| e.contains("`mod transaction` must be declared")),
        "{errors:#?}"
    );
    sources[module].text = saved;
    assert!(module_errors(&sources).is_empty());
}

/// Rule (c) on probes: a cache named or filled outside the listed
/// functions, at item level or in a `const`'s closure, is refused.
#[test]
fn the_fill_rule_refuses_an_unlisted_fill_869() {
    let anchor = "/// What the serializer writes as an input's outpoint txid";
    let plants = [
        (
            "fn plant(&self) { let _ = self.fields.caches().1.set(Vec::new()); }\n",
            "`plant` names `caches` outside the listed readers",
        ),
        (
            "fn plant(c: &std::sync::OnceLock<Vec<u8>>) { let _ = c.set(Vec::new()); }\n",
            "`plant` calls `.set(..)` outside the listed fills",
        ),
        (
            "const PLANT: fn(&Transaction) = |t| { let _ = t.fields.caches().2.get_or_init(String::new); };\n",
            "`<no function>` names `caches`",
        ),
    ];
    for (plant, want) in plants {
        let errors = fill_errors(&fields_with(anchor, &format!("{plant}{anchor}")));
        assert!(
            errors.iter().any(|e| e.contains(want)),
            "{plant}: {errors:#?}"
        );
    }
}

/// Rule (c)'s expansion part on probes: the fifth fold's three plants,
/// adapted to `caches`, and the fourth fold's child module, each refused.
#[test]
fn the_expansion_rule_refuses_a_hidden_fill_869() {
    let anchor = "/// What the serializer writes as an input's outpoint txid";
    let sources = arch_support::sources();
    let plants = [
        ("include!(\"plant.rs\");\n", "`include!` in fields.rs"),
        ("plant_w!();\n", "`plant_w!` in fields.rs"),
        (
            "impl Transaction { fn peek(&self) -> usize { plant_fill!(self); 0 } }\n",
            "`plant_fill!` in fields.rs",
        ),
        ("fn p() { super::vec![1u8]; }\n", "`vec!` in fields.rs"),
        (
            "#[path = \"m.rs\"]\nmod m;\n",
            "`mod m` in fields.rs outside `#[cfg(test)]`",
        ),
        (
            "#[cfg(any(test, debug_assertions))]\nmod m;\n",
            "`mod m` in fields.rs outside",
        ),
        ("macro_rules! fill { () => {}; }\n", "`macro_rules! fill`"),
        (
            "use crate::plant as debug_assert;\n",
            "`use` of `debug_assert`",
        ),
    ];
    for (plant, want) in plants {
        let errors = expansion_errors(&fields_with(anchor, &format!("{plant}{anchor}")), &sources);
        assert!(
            errors.iter().any(|e| e.contains(want)),
            "{plant}: {errors:#?}"
        );
    }
    let shadow = Source {
        path: "src/x.rs".into(),
        text: "macro_rules! debug_assert { ($($t:tt)*) => {}; }\n".into(),
    };
    let errors = expansion_errors(&source(FIELDS), &[shadow]);
    assert!(
        errors
            .iter()
            .any(|e| e.contains("`macro_rules! debug_assert`")),
        "{errors:#?}"
    );
}
