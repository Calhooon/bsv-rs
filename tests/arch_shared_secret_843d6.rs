//! The ECDH shared secret is a crate-owned type, held by the compiler (#843,
//! the freeze plan's row 6; three design reads of 2026-11-12): every door
//! that derives it returns `SharedSecret`, whose `Debug` prints no secret and
//! which has no `Display`, `Hash`, serde or conversion into a `PublicKey`
//! (`tests/secret_debug.rs` pins what it prints; its `compile_fail` doc
//! tests pin the impls it lacks at the use site).
//!
//! What the rule reads, lexically, by signature over every file under
//! `src/` (comments and literals opaque, `#[cfg(test)]` items included):
//! (1) no `fn`, inherent or a trait's, whose name holds `shared_secret` or
//! `counterparty_secret` names `PublicKey` in its return type (the tokens
//! between `->` and the body, `;` or `where`); (2) the `fn`s whose return
//! type names `SharedSecret` are exactly the six of `SIX_DOORS`, by file and
//! name, each name holding a door word; (3) in
//! `src/primitives/ec/shared_secret.rs`: a `derive(..)` names `Clone`
//! alone (so no derived `Debug`, `PartialEq`, `Hash`, `Serialize` or
//! `Default`); no `impl` header names `Display`, `LowerHex`, `UpperHex`,
//! `ToString`, `Hash`, `Serialize`, `Deserialize`, `Deref`, `AsRef`,
//! `Borrow`, `Default`, `Into`, `From` or `TryFrom` (so neither
//! `From<SharedSecret>` nor `From<&SharedSecret>`, nor a constructor by
//! `From`); every `pub` is the type's own `pub struct SharedSecret` or,
//! after any of the qualifiers `const`, `async`, `unsafe`, `extern` and an
//! ABI string, the `fn` of one of the three doors (`to_compressed`, `x`,
//! `to_point`), so a `pub` field, `pub const fn to_hex` and `pub async fn`
//! are refused; the hand-written `impl PartialEq for SharedSecret` is there
//! and its body calls `ct_eq`. A `pub` followed by `(` is a restricted
//! visibility (`pub(crate)`, `pub(super)`, `pub(in ..)`): not public, and
//! passed over; that is how the rule tells.
//!
//! The scan's bound, in one sentence: a lexical reading sees the tokens of
//! `src/` as written, so it cannot see a type alias (`type Ecdh =
//! PublicKey`, or an alias of `SharedSecret`), a return type written `Self`,
//! a signature or impl built by a macro, a re-export of the type under
//! another name, a door whose name holds neither word, or an impl of a
//! forbidden trait written in another file (the doc tests on the type catch
//! `Display`, `Hash`, `Serialize`, the `PublicKey` coercion and a struct
//! expression at the use site wherever the impl lives).
#![allow(clippy::expect_used, clippy::panic)] // Source reads are test assertions.

mod arch_support;

use arch_support::{Source, Token};

/// Every token of `text` as written (comments and literals opaque, no
/// attribute or cfg-gated item skipped).
fn raw(text: &str) -> Source {
    Source {
        path: String::new(),
        text: text.to_owned(),
    }
}

const DOOR_WORDS: &[&str] = &["shared_secret", "counterparty_secret"];
const TYPE_FILE: &str = "src/primitives/ec/shared_secret.rs";
const FORBIDDEN_IMPLS: &[&str] = &[
    "Display",
    "LowerHex",
    "UpperHex",
    "ToString",
    "Hash",
    "Serialize",
    "Deserialize",
    "Deref",
    "AsRef",
    "Borrow",
    "Default",
    "Into",
    "From",
    "TryFrom",
];
const DOORS: &[&str] = &["to_compressed", "x", "to_point"];
/// What may stand between a public `pub` and its `fn`.
const FN_QUALIFIERS: &[&str] = &["const", "async", "unsafe", "extern"];
/// The six `fn`s under `src/` whose return type names `SharedSecret`, by
/// file and name, in the order the scan finds them (files sorted, then line).
const SIX_DOORS: &[(&str, &str)] = &[
    ("src/primitives/ec/private_key.rs", "derive_shared_secret"),
    ("src/primitives/ec/public_key.rs", "derive_shared_secret"),
    (
        "src/wallet/cached_key_deriver.rs",
        "reveal_counterparty_secret",
    ),
    ("src/wallet/key_deriver.rs", "reveal_counterparty_secret"),
    ("src/wallet/key_deriver.rs", "reveal_counterparty_secret"),
    ("src/wallet/key_deriver.rs", "reveal_counterparty_secret"),
];

/// The return type's tokens of the `fn` at `at` (its name at `at + 1`).
fn return_type<'a>(tokens: &'a [Token<'a>], at: usize) -> Vec<&'a str> {
    let mut i = at + 2;
    // Skip to the parameter list (generics before it).
    while i < tokens.len() && tokens[i].text != "(" {
        i += 1;
    }
    let mut depth = 0usize;
    while i < tokens.len() {
        match tokens[i].text {
            "(" => depth += 1,
            ")" => {
                depth -= 1;
                if depth == 0 {
                    i += 1;
                    break;
                }
            }
            _ => {}
        }
        i += 1;
    }
    if !(tokens.get(i).map(|t| t.text) == Some("-")
        && tokens.get(i + 1).map(|t| t.text) == Some(">"))
    {
        return Vec::new();
    }
    tokens[i + 2..]
        .iter()
        .map(|t| t.text)
        .take_while(|t| !matches!(*t, "{" | ";" | "where"))
        .collect()
}

/// Every door (file, line, name) whose return type names `PublicKey`.
fn doors_returning_public_key(sources: &[(String, String)]) -> Vec<(String, usize, String)> {
    let mut found = Vec::new();
    for (path, text) in sources {
        let source = raw(text);
        let tokens = source.raw_tokens();
        for (at, token) in tokens.iter().enumerate() {
            if token.text != "fn" || token.literal {
                continue;
            }
            let Some(name) = tokens.get(at + 1) else {
                continue;
            };
            if !DOOR_WORDS.iter().any(|w| name.text.contains(w)) {
                continue;
            }
            if return_type(&tokens, at).contains(&"PublicKey") {
                found.push((path.clone(), name.line, name.text.to_owned()));
            }
        }
    }
    found
}

/// Every `fn` (file, name) whose return type names `SharedSecret`.
fn doors_returning_shared_secret(sources: &[(String, String)]) -> Vec<(String, String)> {
    let mut found = Vec::new();
    for (path, text) in sources {
        let source = raw(text);
        let tokens = source.raw_tokens();
        for (at, token) in tokens.iter().enumerate() {
            if token.text != "fn" || token.literal {
                continue;
            }
            let Some(name) = tokens.get(at + 1) else {
                continue;
            };
            if return_type(&tokens, at).contains(&"SharedSecret") {
                found.push((path.clone(), name.text.to_owned()));
            }
        }
    }
    found
}

/// What the type's file must not hold: a derive of anything but `Clone`, a
/// forbidden impl, a `pub` that is neither the type nor a door.
fn type_file_refusals(text: &str) -> Vec<String> {
    let source = raw(text);
    let tokens = source.raw_tokens();
    let texts: Vec<&str> = tokens.iter().map(|t| t.text).collect();
    let mut refusals = Vec::new();
    for (i, token) in tokens.iter().enumerate() {
        if token.literal {
            continue;
        }
        match token.text {
            "derive" if texts.get(i + 1) == Some(&"(") => {
                let close = texts[i..]
                    .iter()
                    .position(|t| *t == ")")
                    .map_or(texts.len(), |p| i + p);
                for name in &texts[i + 2..close] {
                    let word = name.starts_with(|c: char| c.is_alphabetic() || c == '_');
                    if word && *name != "Clone" {
                        refusals.push(format!("line {}: a derived {name}", token.line));
                    }
                }
            }
            "impl" => {
                let end = texts[i..]
                    .iter()
                    .position(|t| *t == "{")
                    .map_or(texts.len(), |p| i + p);
                let header = &texts[i..end];
                for word in FORBIDDEN_IMPLS {
                    if header.contains(word) {
                        refusals.push(format!("line {}: an impl of {word}", token.line));
                    }
                }
            }
            // `pub(crate)`, `pub(super)`, `pub(in ..)`: restricted, not public.
            "pub" if texts.get(i + 1) == Some(&"(") => {}
            "pub" => {
                let mut j = i + 1;
                while tokens
                    .get(j)
                    .is_some_and(|t| t.literal || FN_QUALIFIERS.contains(&t.text))
                {
                    j += 1;
                }
                let next = texts.get(j).copied().unwrap_or_default();
                let name = texts.get(j + 1).copied().unwrap_or_default();
                match next {
                    "fn" if DOORS.contains(&name) => {}
                    "fn" => refusals.push(format!(
                        "line {}: a public fn {name} beyond the doors",
                        token.line
                    )),
                    "struct" if j == i + 1 && name == "SharedSecret" => {}
                    _ => refusals.push(format!(
                        "line {}: a public `{next}` that is neither the type nor a door",
                        token.line
                    )),
                }
            }
            _ => {}
        }
    }
    refusals
}

/// The comparison is the hand-written one: an `impl` whose header names
/// `PartialEq` and whose body calls `ct_eq`.
fn equality_refusals(text: &str) -> Vec<String> {
    let source = raw(text);
    let tokens = source.raw_tokens();
    let texts: Vec<&str> = tokens
        .iter()
        .filter(|t| !t.literal)
        .map(|t| t.text)
        .collect();
    for (i, text) in texts.iter().enumerate() {
        if *text != "impl" {
            continue;
        }
        let Some(open) = texts[i..].iter().position(|t| *t == "{").map(|p| i + p) else {
            continue;
        };
        if !texts[i..open].contains(&"PartialEq") {
            continue;
        }
        let mut depth = 0usize;
        let mut close = texts.len();
        for (k, t) in texts.iter().enumerate().skip(open) {
            match *t {
                "{" => depth += 1,
                "}" => {
                    depth -= 1;
                    if depth == 0 {
                        close = k;
                        break;
                    }
                }
                _ => {}
            }
        }
        return if texts[open..close].contains(&"ct_eq") {
            Vec::new()
        } else {
            vec!["the impl of PartialEq does not call ct_eq".to_owned()]
        };
    }
    vec!["no hand-written impl of PartialEq".to_owned()]
}

#[test]
fn no_ecdh_door_returns_a_public_key_843d6() {
    let sources: Vec<(String, String)> = arch_support::sources()
        .into_iter()
        .map(|s| (s.path, s.text))
        .collect();
    let found = doors_returning_public_key(&sources);
    assert!(
        found.is_empty(),
        "an ECDH door returns a PublicKey, whose Debug, Display and serde print the secret; \
         return SharedSecret: {found:#?}"
    );
    // The doors returning `SharedSecret` are exactly the six, by name.
    let doors = doors_returning_shared_secret(&sources);
    let named: Vec<(String, String)> = SIX_DOORS
        .iter()
        .map(|(file, name)| ((*file).to_owned(), (*name).to_owned()))
        .collect();
    assert_eq!(
        doors, named,
        "the fns returning SharedSecret are not the six named in SIX_DOORS: a new door is \
         reviewed and named there, a removed one taken out"
    );
    for (file, name) in &doors {
        assert!(
            DOOR_WORDS.iter().any(|w| name.contains(w)),
            "{file}: {name} returns SharedSecret under a name the PublicKey rule does not read"
        );
    }
}

#[test]
fn the_shared_secret_type_has_no_printing_or_converting_impl_843d6() {
    let text = arch_support::read(TYPE_FILE);
    let refusals = type_file_refusals(&text);
    assert!(refusals.is_empty(), "{TYPE_FILE}: {refusals:#?}");
    let equality = equality_refusals(&text);
    assert!(equality.is_empty(), "{TYPE_FILE}: {equality:#?}");
    assert!(
        text.contains("pub struct SharedSecret"),
        "{TYPE_FILE} declares the type"
    );
}

#[test]
fn the_rules_refuse_their_plants_843d6() {
    let plant = |s: &str| vec![("src/plant.rs".to_owned(), s.to_owned())];
    for refused in [
        "pub fn derive_shared_secret(&self, k: &PublicKey) -> Result<PublicKey> { x }",
        "fn reveal_counterparty_secret(&self, c: &Counterparty) -> Result<PublicKey>;",
        "pub fn derive_shared_secret<T>(&self, k: T) -> PublicKey where T: Into<u8> { x }",
    ] {
        assert_eq!(
            doors_returning_public_key(&plant(refused)).len(),
            1,
            "{refused}"
        );
    }
    for passed in [
        "pub fn derive_shared_secret(&self, k: &PublicKey) -> Result<SharedSecret> { x }",
        "// fn derive_shared_secret() -> PublicKey",
        "fn derive_child(&self, k: &PublicKey) -> Result<PublicKey> { x }",
    ] {
        assert!(
            doors_returning_public_key(&plant(passed)).is_empty(),
            "{passed}"
        );
    }
    for refused in [
        "#[derive(Clone, Debug)]\npub struct SharedSecret { point: PublicKey }",
        "impl std::fmt::Display for SharedSecret {}",
        "impl std::hash::Hash for SharedSecret {}",
        "impl serde::Serialize for SharedSecret {}",
        "impl std::ops::Deref for SharedSecret {}",
        "impl AsRef<PublicKey> for SharedSecret {}",
        "impl From<SharedSecret> for PublicKey {}",
        "impl SharedSecret { pub fn to_hex(&self) -> String { x } }",
        // The strength read's spellings (S1 to S4).
        "pub struct SharedSecret { pub point: PublicKey }",
        "pub struct SharedSecret { pub(crate) point: PublicKey, pub tag: u8 }",
        "#[derive(Clone, PartialEq)]\npub struct SharedSecret { point: PublicKey }",
        "#[derive(Clone, Hash)]\npub struct SharedSecret { point: PublicKey }",
        "#[cfg_attr(test, derive(serde::Serialize))]\npub struct SharedSecret { point: PublicKey }",
        "impl SharedSecret { pub const fn to_hex(&self) -> String { x } }",
        "impl SharedSecret { pub async fn to_hex(&self) -> String { x } }",
        "impl SharedSecret { pub unsafe fn to_hex(&self) -> String { x } }",
        "impl SharedSecret { pub extern \"C\" fn to_hex(&self) -> String { x } }",
        "impl SharedSecret { pub const unsafe fn to_hex(&self) -> String { x } }",
        "impl SharedSecret { pub const HEX: u8 = 0; }",
        "impl From<&SharedSecret> for PublicKey {}",
        "impl<'a> From<&'a SharedSecret> for PublicKey {}",
        "impl From<PublicKey> for SharedSecret {}",
        "impl TryFrom<SharedSecret> for PublicKey {}",
        "impl TryFrom<&SharedSecret> for [u8; 33] {}",
        "impl std::fmt::LowerHex for SharedSecret {}",
        "impl std::fmt::UpperHex for SharedSecret {}",
        "impl ToString for SharedSecret {}",
        "impl std::string::ToString for SharedSecret {}",
    ] {
        assert!(!type_file_refusals(refused).is_empty(), "{refused}");
    }
    // A restricted visibility is not public, whatever follows it.
    for passed in [
        "impl SharedSecret { pub(crate) fn to_hex(&self) -> String { x } }",
        "impl SharedSecret { pub(super) const fn from_point(p: PublicKey) -> Self { x } }",
        "impl SharedSecret { pub const fn x(&self) {} pub fn to_point(&self) {} }",
    ] {
        assert!(type_file_refusals(passed).is_empty(), "{passed}");
    }
    // The comparison: hand-written, in constant time.
    for refused in [
        "#[derive(Clone, PartialEq)]\npub struct SharedSecret { point: PublicKey }",
        "impl PartialEq for SharedSecret { fn eq(&self, o: &Self) -> bool { true } }",
        "impl PartialEq for SharedSecret { fn eq(&self, o: &Self) -> bool { self.point == o.point } }\n\
         fn other() { a.ct_eq(&b); }",
        "// impl PartialEq for SharedSecret { fn eq() { ct_eq } }",
    ] {
        assert!(!equality_refusals(refused).is_empty(), "{refused}");
    }
    assert!(equality_refusals(
        "impl PartialEq for SharedSecret { fn eq(&self, o: &Self) -> bool { \
         self.to_compressed().ct_eq(&o.to_compressed()).into() } }"
    )
    .is_empty());
    // The door count: a seventh door, a door under `Self` (the stated bound).
    let seventh = plant("pub fn ecdh(&self, k: &PublicKey) -> Result<SharedSecret> { x }");
    assert_eq!(
        doors_returning_shared_secret(&seventh),
        vec![("src/plant.rs".to_owned(), "ecdh".to_owned())]
    );
    let generic =
        plant("pub const fn ecdh<'a, T: X>(&'a self, k: T) -> SharedSecret where T: Y { x }");
    assert_eq!(doors_returning_shared_secret(&generic).len(), 1);
    for unseen in [
        "pub(crate) fn from_point(point: PublicKey) -> Self { x }",
        "fn takes(s: &SharedSecret) -> [u8; 33] { x }",
        "// fn ecdh() -> SharedSecret",
    ] {
        assert!(
            doors_returning_shared_secret(&plant(unseen)).is_empty(),
            "{unseen}"
        );
    }
    assert!(type_file_refusals(
        "#[derive(Clone)]\npub struct SharedSecret { point: PublicKey }\n\
         impl SharedSecret { pub(crate) fn from_point(p: PublicKey) -> Self { x }\n\
         pub fn to_compressed(&self) {} pub fn x(&self) {} pub fn to_point(&self) {} }\n\
         impl std::fmt::Debug for SharedSecret {}\nimpl PartialEq for SharedSecret {}"
    )
    .is_empty());
}
