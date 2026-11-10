//! A type that holds secret material never derives `Debug` (the API read of
//! 2026-11-10, C-DEBUG; widened by the fold of PR #851): a derived `Debug`
//! prints every field, so a `{:?}` in a dependent's log line or panic writes
//! the secret. Such a type writes its own `Debug`, naming itself and
//! redacting (`tests/secret_debug.rs` pins what each prints).
//!
//! What the rule reads, lexically, in every file under `src/`: a `struct` or
//! `enum` of any visibility (`pub`, `pub(crate)`, `pub(super)`, `pub(in ..)`,
//! none) that derives `Debug`, through `#[derive(..)]` written on one line or
//! across several, or through `#[cfg_attr(.., derive(..))]`, with other
//! attributes and comments between the derive and the declaration; it is
//! caught when its name, in snake case, carries a word of
//! `SECRET_TYPE_WORDS`, or when one of its named fields is a word of
//! `SECRET_FIELD_WORDS`; a field name too common to judge alone (`key`, `y`,
//! `token`) is caught too, and each type it catches that holds no secret is
//! listed in `ALLOWED` with the reason it was reviewed (an entry naming no
//! caught type is refused, as the crate's other allowlists refuse).
//!
//! Since the second fold the rule follows the class the lane closes (a
//! credential leaves only through a door a caller names) into a header's
//! value and a URL: a field named for a header set or a URL that can carry a
//! credential (`headers`, `required_headers`, `upload_url`, `url`, `uri`,
//! `base_url`, `policy_url`, `storage_url`, `certifier_url`) or ending in
//! `_url`, `_uri`, `_urls` or `_headers` is caught on a deriving type, which
//! then writes its `Debug` through `crate::util::debug_redact` or is in
//! `ALLOWED` with its reason (a published record's URL, a content address).
//!
//! What it cannot see, stated: a tuple struct is read by its name alone (a
//! `struct Material(pub [u8; 32])` passes); a field whose name says nothing
//! (`bytes`, `inner`) passes; a type defined by a macro passes; and a
//! hand-written `Debug` that prints a secret is not read here at all: it is
//! caught only for the types `tests/secret_debug.rs` formats. The reader's
//! own shape also passes, read by name alone: an enum variant's fields
//! (`Variant { seed: .. }`, one level deeper than a struct's); a braced body
//! whose `{` is not on the declaration's line (a `where` clause) or that
//! closes on it (`struct S { key: u8 }`); a field not exactly four spaces
//! deeper than its type; a derive naming `Debug` by another path
//! (`fmt::Debug`); a blank line between the attributes and the type. None of
//! these held a secret field in `src/` at the rule read of 2026-11-10.
#![allow(clippy::expect_used, clippy::panic)] // Source reads are test assertions.

mod arch_support;

/// Words that mark a type name (in snake case) as holding a secret.
const SECRET_TYPE_WORDS: &[&str] = &[
    "mnemonic",
    "private_key",
    "secret",
    "seed",
    "entropy",
    "wif",
    "xprv",
    "symmetric_key",
    "key_shares",
    "point_in_finite_field",
    "polynomial",
    "drbg",
    "key_deriver",
    "proto_wallet",
    "extended_key",
    "passphrase",
    "password",
    "credential",
];

/// Field names that hold a secret, or may: the list of the fold's brief and
/// what a grep of `src/` for secret-sounding field names showed (the
/// derivers' `private_key_cache` and `symmetric_key_cache`, `privkey`).
const SECRET_FIELD_WORDS: &[&str] = &[
    "secret",
    "seed",
    "entropy",
    "wif",
    "xprv",
    "mnemonic",
    "passphrase",
    "password",
    "phrase",
    "root_key",
    "private_key",
    "privkey",
    "private_key_cache",
    "symmetric_key_cache",
    "chain_code",
    "words",
    "share",
    "shares",
    "api_key",
    "auth_token",
    "token",
    "key",
    "y",
    // The second fold's class: a header set and a URL that can carry a
    // credential (a header's value; a URL's user info, query, fragment).
    "headers",
    "required_headers",
    "upload_url",
    "url",
    "uri",
    "base_url",
    "policy_url",
    "storage_url",
    "certifier_url",
];

/// Field-name suffixes of the same class, so a header set or URL nobody
/// listed is caught too: every derived-`Debug` field whose name ends in one
/// is refused unless its type is in `ALLOWED` (the second fold's grep found
/// 25 such fields on 14 types; 11 are reviewed below and 3 write their own
/// `Debug` through `debug_redact`).
const SECRET_FIELD_SUFFIXES: &[&str] = &["_url", "_uri", "_urls", "_headers"];

/// `(path, type, reason)`: a type the rule catches that was reviewed and
/// holds no secret. Each entry must still catch its type.
const ALLOWED: &[(&str, &str, &str)] = &[
    (
        "src/kvstore/interpreter.rs",
        "KVStoreContext",
        "`key` is the store's key name, public on the token",
    ),
    (
        "src/kvstore/interpreter.rs",
        "KVStoreFields",
        "`key` is the store's key name, public on the token",
    ),
    (
        "src/kvstore/token_validation.rs",
        "AuthenticatedToken",
        "`key` is the store's key name, public on the token",
    ),
    (
        "src/kvstore/types.rs",
        "KVStoreEntry",
        "`key` is the key name, `token` the on-chain token (outpoint, BEEF)",
    ),
    (
        "src/kvstore/types.rs",
        "KVStoreQuery",
        "`key` is a lookup's key name",
    ),
    (
        "src/primitives/symmetric.rs",
        "TestVector",
        "a published AES-GCM test vector's key, under cfg(test)",
    ),
    (
        "src/registry/types.rs",
        "RegistryRecord",
        "`token` is the on-chain registry token (txid, output, script)",
    ),
    (
        "src/wallet/wire/validation.rs",
        "Refusal",
        "`words` is an error's text, not a phrase",
    ),
    // The second fold's URL class: URLs of a published record (a contact,
    // an identity certificate, an on-chain registry or overlay definition) or
    // a content address, public on the record, never an endpoint a caller
    // configures with a credential.
    (
        "src/identity/contacts_record.rs",
        "ContactRecord",
        "`avatar_url`, `badge_*_url`: the contact record's published image and link",
    ),
    (
        "src/identity/types.rs",
        "DisplayableIdentity",
        "`avatar_url`, `badge_*_url`: an identity's published image and link",
    ),
    (
        "src/identity/types.rs",
        "Contact",
        "`avatar_url`, `badge_*_url`: the contact record's published image and link",
    ),
    (
        "src/identity/types.rs",
        "CertifierInfo",
        "`icon_url`: a certifier's published icon",
    ),
    (
        "src/wallet/types.rs",
        "IdentityCertifier",
        "`icon_url`: a certifier's published icon (BRC-100 discovery result)",
    ),
    (
        "src/overlay/types.rs",
        "ServiceMetadata",
        "`icon_url`, `info_url`: an overlay service's published metadata",
    ),
    (
        "src/registry/types.rs",
        "BasketDefinitionData",
        "`icon_url`, `documentation_url`: an on-chain registry definition's fields",
    ),
    (
        "src/registry/types.rs",
        "ProtocolDefinitionData",
        "`icon_url`, `documentation_url`: an on-chain registry definition's fields",
    ),
    (
        "src/registry/types.rs",
        "CertificateDefinitionData",
        "`icon_url`, `documentation_url`: an on-chain registry definition's fields",
    ),
    (
        "src/storage/types.rs",
        "UploadFileResult",
        "`uhrp_url`: a content address, `uhrp://` and the file's hash",
    ),
    (
        "src/storage/types.rs",
        "UploadMetadata",
        "`uhrp_url`: a content address, `uhrp://` and the file's hash",
    ),
];

fn snake(name: &str) -> String {
    let mut out = String::new();
    for (i, c) in name.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

fn field_name(line: &str) -> Option<&str> {
    let t = strip_visibility(line.trim_start());
    let (name, rest) = t.split_once(':')?;
    let name = name.trim();
    (!rest.starts_with(':')
        && !name.is_empty()
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
    .then_some(name)
}

/// `t` without a leading `pub`, `pub(crate)`, `pub(super)` or `pub(in ..)`.
fn strip_visibility(t: &str) -> &str {
    if let Some(rest) = t.strip_prefix("pub(") {
        return rest.split_once(')').map_or(t, |(_, r)| r.trim_start());
    }
    t.strip_prefix("pub ").unwrap_or(t)
}

/// The bracket depth an attribute line leaves open.
fn depth(line: &str) -> i32 {
    line.chars().fold(0, |d, c| match c {
        '[' | '(' => d + 1,
        ']' | ')' => d - 1,
        _ => d,
    })
}

/// The attribute starting at line `i`, joined over its lines, and the index
/// of the line after it.
fn attribute(lines: &[&str], i: usize) -> (String, usize) {
    let mut text = lines[i].trim().to_owned();
    let mut open = depth(lines[i]);
    let mut j = i + 1;
    while open > 0 && j < lines.len() {
        text.push(' ');
        text.push_str(lines[j].trim());
        open += depth(lines[j]);
        j += 1;
    }
    (text, j)
}

/// Whether an attribute's text derives `Debug`: a `derive(..)` list, at the
/// top or inside a `cfg_attr(..)`, naming `Debug` or a path to it.
fn derives_debug(attr: &str) -> bool {
    let mut rest = attr;
    while let Some(at) = rest.find("derive(") {
        let list = &rest[at + "derive(".len()..];
        let end = list.find(')').unwrap_or(list.len());
        if list[..end]
            .split(',')
            .any(|d| matches!(d.trim(), "Debug" | "std::fmt::Debug" | "core::fmt::Debug"))
        {
            return true;
        }
        rest = &list[end..];
    }
    false
}

/// `(line, type, reasons)` of every type in `text` that derives `Debug` and
/// matches the secret list.
fn findings(text: &str) -> Vec<(usize, String, Vec<String>)> {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if !lines[i].trim_start().starts_with("#[") {
            i += 1;
            continue;
        }
        // The attributes and comments above one declaration, read whole.
        let mut debug = false;
        let mut j = i;
        while j < lines.len() {
            let u = lines[j].trim_start();
            if u.starts_with("#[") {
                let (attr, next) = attribute(&lines, j);
                debug |= derives_debug(&attr);
                j = next;
            } else if u.starts_with("//") {
                j += 1;
            } else {
                break;
            }
        }
        i = j.max(i + 1);
        if !debug {
            continue;
        }
        let Some(decl) = lines.get(j).map(|l| l.trim_start()) else {
            continue;
        };
        let item = strip_visibility(decl);
        let Some(rest) = item
            .strip_prefix("struct ")
            .or_else(|| item.strip_prefix("enum "))
        else {
            continue;
        };
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        let mut reasons = Vec::new();
        let snake_name = snake(&name);
        for word in SECRET_TYPE_WORDS {
            if snake_name.contains(word) {
                reasons.push(format!("name has `{word}`"));
            }
        }
        // A braced body: the fields until the closing brace at the
        // declaration's indentation. A unit or tuple struct has none.
        if decl.trim_end().ends_with('{') {
            let indent = lines[j].len() - decl.len();
            for body in &lines[j + 1..] {
                let b = body.trim_start();
                if b.starts_with('}') && body.len() - b.len() == indent {
                    break;
                }
                if body.len() - b.len() != indent + 4 {
                    continue;
                }
                if let Some(field) = field_name(body) {
                    if SECRET_FIELD_WORDS.contains(&field)
                        || SECRET_FIELD_SUFFIXES.iter().any(|s| field.ends_with(s))
                    {
                        reasons.push(format!("field `{field}`"));
                    }
                }
            }
        }
        if !reasons.is_empty() {
            out.push((j + 1, name, reasons));
        }
    }
    out
}

#[test]
fn no_type_holding_a_secret_derives_debug() {
    let sources = arch_support::sources();
    let mut bad = Vec::new();
    for source in &sources {
        for (line, name, reasons) in findings(&source.text) {
            if ALLOWED
                .iter()
                .any(|(p, n, _)| *p == source.path && *n == name)
            {
                continue;
            }
            bad.push(format!(
                "{}:{line}: `{name}` derives Debug ({}); write a redacting Debug",
                source.path,
                reasons.join(", ")
            ));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
    for (path, name, _) in ALLOWED {
        assert!(
            sources
                .iter()
                .any(|s| s.path == *path && findings(&s.text).iter().any(|f| f.1 == *name)),
            "stale allowance: {path} {name}"
        );
    }
}

#[test]
fn the_rule_reads_names_fields_and_derives() {
    let text = r#"
#[derive(Debug, Clone)]
pub struct Mnemonic {
    words: Vec<String>,
}

/// Doc.
#[derive(Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Options {
    pub digits: u32,
    pub seed: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct P2PK;

impl P2PK {
    pub fn unlock(private_key: &PrivateKey) {}
}

#[derive(Debug)]
pub struct Plain {
    pub label: String,
    inner: Inner {
        seed: u8,
    },
}

#[derive(Clone)]
pub struct SymmetricKey {
    key: [u8; 32],
}

#[derive(Debug)]
pub enum PrivateKeyForm {
    Hex,
}
"#;
    let found: Vec<(String, Vec<String>)> =
        findings(text).into_iter().map(|(_, n, r)| (n, r)).collect();
    assert_eq!(
        found,
        vec![
            (
                "Mnemonic".to_owned(),
                vec!["name has `mnemonic`".to_owned(), "field `words`".to_owned()]
            ),
            ("Options".to_owned(), vec!["field `seed`".to_owned()]),
            (
                "PrivateKeyForm".to_owned(),
                vec!["name has `private_key`".to_owned()]
            ),
        ]
    );
}

/// The cold read's five misses of `508283f5`'s rule, each planted: every one
/// is caught now (each was RED against that rule's reader, the fold's log).
#[test]
fn the_widened_rule_catches_the_cold_reads_five_misses() {
    let planted = [
        // A derive split over lines.
        ("#[derive(\n    Clone,\n    Debug,\n)]\npub struct Wallet {\n    pub seed: Vec<u8>,\n}\n", "Wallet"),
        // A derive under cfg_attr.
        ("#[cfg_attr(feature = \"x\", derive(Clone, Debug))]\npub struct Holder {\n    pub passphrase: String,\n}\n", "Holder"),
        // A crate-visible type.
        ("#[derive(Debug)]\npub(crate) struct Seeded {\n    pub(crate) label: String,\n}\n", "Seeded"),
        // A tuple struct, by its name, private.
        ("#[derive(Debug, Clone)]\nstruct SecretBytes([u8; 32]);\n", "SecretBytes"),
        // Raw bytes under ordinary field names.
        ("#[derive(Debug)]\npub struct Material {\n    private_key: [u8; 32],\n    key: Vec<u8>,\n}\n", "Material"),
        // A credential, an attribute between the derive and the type.
        ("#[derive(Debug, Clone)]\n#[deprecated(\n    since = \"0.9.0\",\n    note = \"x\"\n)]\npub struct Config {\n    pub api_key: Option<String>,\n    pub auth_token: Option<String>,\n}\n", "Config"),
    ];
    let missed: Vec<&str> = planted
        .iter()
        .filter(|(text, name)| !findings(text).iter().any(|f| f.1 == *name))
        .map(|(_, name)| *name)
        .collect();
    assert!(missed.is_empty(), "not caught: {missed:?}");
    // And still not caught: what it states it cannot see.
    let unseen = "#[derive(Debug)]\npub struct Material(pub [u8; 32]);\n\n#[derive(Debug)]\npub struct Blob {\n    bytes: Vec<u8>,\n}\n";
    assert!(findings(unseen).is_empty());
}

/// The second fold's class, each arm planted: a header set and a URL under
/// every listed name and each suffix (each RED against the first fold's
/// lists, the fold's log), and a field of neither shape still not caught.
#[test]
fn the_rule_catches_a_derived_header_set_or_url() {
    let planted = [
        "headers: Vec<(String, String)>",
        "required_headers: HashMap<String, String>",
        "upload_url: String",
        "url: String",
        "uri: String",
        "base_url: Option<String>",
        "policy_url: String",
        "storage_url: String",
        "certifier_url: Option<String>",
        "callback_url: String",
        "redirect_uri: String",
        "mirror_urls: Vec<String>",
        "response_headers: IndexMap<String, String>",
    ];
    let missed: Vec<&str> = planted
        .iter()
        .filter(|field| {
            let text =
                format!("#[derive(Debug, Clone)]\npub struct Planted {{\n    pub {field},\n}}\n");
            !findings(&text).iter().any(|f| f.1 == "Planted")
        })
        .copied()
        .collect();
    assert!(missed.is_empty(), "not caught: {missed:?}");
    let unseen = "#[derive(Debug)]\npub struct Plain {\n    pub urlish: String,\n    pub header: String,\n}\n";
    assert!(findings(unseen).is_empty());
}
