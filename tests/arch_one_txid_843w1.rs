//! One transaction id type for the whole crate, the wallet included (#843,
//! W1; root rule 11: the class, held by a machine).
//!
//! Until W1 the wallet held `TxId = [u8; 32]` in DISPLAY order beside the
//! crate's `Txid`, which holds WIRE order, so a transaction's `hash()` handed
//! to `Outpoint::new` type-checked and named another transaction. The alias
//! is gone; every wallet type holds `Txid`, and the wallet wire and the
//! certificate binary, which carry the display order, convert at one codec
//! pair (`src/wallet/wire/txid_codec.rs`). Four lexical refusals keep it so
//! (comments and literals opaque; `#[cfg(test)]` items and `*_tests.rs`
//! files excepted in (b), (c) and (d), as the other rules except them):
//!
//! (a) the word `TxId` in any `.rs` under `src/`, `tests/`, `examples/`,
//!     `benches/` or `fuzz/`;
//! (b) `from_display_bytes` or `to_display_bytes` under `src/` outside
//!     `src/transaction/` and outside the pair's file;
//! (c) under `src/wallet/` and `src/auth/`, `from_wire_bytes` or
//!     `as_wire_bytes` outside `WIRE_DOORS`, a list of `(file, door, count)`
//!     that only shrinks, and any `.reverse()` call;
//! (d) under `src/` outside `src/transaction/`, a field or a parameter named
//!     `*txid*` whose type names `[u8; 32]`, save `BYTE_HOLDERS` with each
//!     entry's reason (read wider than the public ones: a private field and a
//!     private function's parameter are refused too), and, under
//!     `src/wallet/` and `src/auth/`, a local named `*txid*` declared as or
//!     initialized by a 32-byte array.
//!
//! What a lexical reading cannot see: a hand copy of the 32 bytes under a
//! name without `txid` (`let id = [0u8; 32]`, a field `hash: [u8; 32]`); a
//! display conversion made through text (`hex::decode(txid.to_string())`,
//! then reversed by a loop or an iterator's `rev()`); a byte door reached
//! through an alias, a re-export or a macro; a type named through an alias
//! of `[u8; 32]` under another name; a `Vec<u8>` or a slice holding an id.
//! The runs that hold the order itself are `tests/wallet_txid_wires_843w1.rs`
//! (every wire door, byte for byte against the base's recording) and
//! `tests/wallet_txid_843w1.rs` (the typed property).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // #134: test code: a failed unwrap is the test failing

mod arch_support;

use arch_support::{code_tokens, Token};
use std::path::Path;

/// The one file outside `src/transaction/` that converts an id to and from
/// display-order bytes.
const PAIR: &str = "src/wallet/wire/txid_codec.rs";

/// (c): the wire-order byte doors named under `src/wallet/` and `src/auth/`.
/// Only shrinks.
const WIRE_DOORS: &[(&str, &str, usize, &str)] = &[(
    "src/wallet/substrates/result_values/beef.rs",
    "from_wire_bytes",
    2,
    "reads a serialized transaction and a BUMP, not the wallet wire: an outpoint's 32 bytes and a transaction's own hash, shown as the text the wallet's results are keyed by",
)];

/// (d): the `*txid*` fields and parameters outside `src/transaction/` that
/// are a bare `[u8; 32]`: `(file, name, count, reason)`. Wire-order arrays of
/// modules below `transaction` in the feature order, where `Txid` cannot be
/// named.
const BYTE_HOLDERS: &[(&str, &str, usize, &str)] = &[
    (
        "src/primitives/bsv/sighash.rs",
        "txid",
        1,
        "`TxInput.txid`, the sighash preimage's outpoint in wire order: `primitives` is below `transaction`",
    ),
    (
        "src/script/spend/mod.rs",
        "source_txid",
        2,
        "`SpendParams.source_txid` and `Spend`'s own copy, wire order: `script` is below `transaction`",
    ),
    (
        "src/script/transaction.rs",
        "txid",
        1,
        "`UtxoProvider::get_utxo`'s parameter, wire order: `script` is below `transaction`",
    ),
];

fn is_test_file(path: &str) -> bool {
    path.ends_with("_tests.rs") || path.ends_with("/tests.rs")
}

fn code<'a>(tokens: &'a [Token<'a>]) -> impl Iterator<Item = (usize, &'a Token<'a>)> {
    tokens.iter().enumerate().filter(|(_, t)| !t.literal)
}

/// (a): the alias's name, anywhere.
fn alias_refusals(path: &str, text: &str) -> Vec<String> {
    let tokens = code_tokens(text, false);
    let alias = ["Tx", "Id"].concat();
    code(&tokens)
        .filter(|(_, t)| t.text == alias)
        .map(|(_, t)| {
            format!(
                "{path}:{}: names `{alias}`; the wallet's alias is gone (#843, W1): the crate has one `Txid`",
                t.line
            )
        })
        .collect()
}

/// (b): the display-order byte doors, outside the pair's file.
fn display_door_refusals(path: &str, text: &str) -> Vec<String> {
    if !path.starts_with("src/")
        || path.starts_with("src/transaction/")
        || path == PAIR
        || is_test_file(path)
    {
        return Vec::new();
    }
    let tokens = code_tokens(text, false);
    code(&tokens)
        .filter(|(_, t)| t.text == "from_display_bytes" || t.text == "to_display_bytes")
        .map(|(_, t)| {
            format!(
                "{path}:{}: names `{}` outside {PAIR}; the wallet wire and the certificate binary convert at that one pair (`read_txid`, `write_txid`)",
                t.line, t.text
            )
        })
        .collect()
}

fn in_wallet_or_auth(path: &str) -> bool {
    (path.starts_with("src/wallet/") || path.starts_with("src/auth/")) && !is_test_file(path)
}

/// (c): the wire-order byte doors and a hand reversal, under the wallet and
/// auth modules.
fn wire_door_refusals(path: &str, text: &str, listed: &[(&str, &str, usize, &str)]) -> Vec<String> {
    if !in_wallet_or_auth(path) {
        return Vec::new();
    }
    let tokens = code_tokens(text, false);
    let mut out = Vec::new();
    for door in ["from_wire_bytes", "as_wire_bytes"] {
        let lines: Vec<usize> = code(&tokens)
            .filter(|(_, t)| t.text == door)
            .map(|(_, t)| t.line)
            .collect();
        let allowed = listed
            .iter()
            .find(|(file, name, ..)| *file == path && *name == door)
            .map_or(0, |entry| entry.2);
        if lines.len() > allowed {
            out.push(format!(
                "{path}: names `{door}` {} time(s) (lines {lines:?}), {allowed} listed; a wallet or auth site builds an id from text, a transaction or `read_txid`, never from wire-order bytes",
                lines.len()
            ));
        } else if lines.len() < allowed {
            out.push(format!(
                "{path}: `{door}` is listed {allowed} time(s) and named {}; the list only shrinks: lower its entry",
                lines.len()
            ));
        }
    }
    for (at, token) in code(&tokens) {
        if token.text == "reverse"
            && at > 0
            && tokens[at - 1].text == "."
            && tokens.get(at + 1).is_some_and(|t| t.text == "(")
        {
            out.push(format!(
                "{path}:{}: calls `.reverse()`; an id's order is converted by `Txid`'s named doors, at the pair for a wire, never by hand",
                token.line
            ));
        }
    }
    out
}

/// A listed file that no longer exists or no longer names its door is stale.
fn stale_wire_doors(paths: &[String], listed: &[(&str, &str, usize, &str)]) -> Vec<String> {
    listed
        .iter()
        .filter(|(file, ..)| !paths.iter().any(|p| p == file))
        .map(|(file, door, ..)| format!("{file}: listed for `{door}` and not a file under src/"))
        .collect()
}

fn names_txid(name: &str) -> bool {
    name.to_ascii_lowercase().contains("txid")
}

/// Whether the tokens from `at` open a 32-byte array type or value:
/// `[` .. `;` `32` `]`, with `&`, a lifetime and `mut` allowed ahead.
fn array_of_32(tokens: &[Token<'_>], mut at: usize) -> bool {
    while tokens
        .get(at)
        .is_some_and(|t| matches!(t.text, "&" | "mut" | "*" | "static") || t.text.starts_with('\''))
    {
        at += 1;
    }
    if tokens.get(at).is_none_or(|t| t.text != "[") {
        return false;
    }
    let mut depth = 0usize;
    for i in at..tokens.len() {
        match tokens[i].text {
            "[" => depth += 1,
            "]" => {
                depth -= 1;
                if depth == 0 {
                    return i >= 2 && tokens[i - 1].text == "32" && tokens[i - 2].text == ";";
                }
            }
            _ => {}
        }
    }
    false
}

/// (d), the fields and parameters: `name: [u8; 32]` (or a reference to one)
/// under a name holding `txid`, by name and count.
fn byte_holders(path: &str, text: &str) -> Vec<(String, usize)> {
    if !path.starts_with("src/") || path.starts_with("src/transaction/") || is_test_file(path) {
        return Vec::new();
    }
    let tokens = code_tokens(text, false);
    let mut found: Vec<(String, usize)> = Vec::new();
    for (at, token) in code(&tokens) {
        let declared = names_txid(token.text)
            && tokens.get(at + 1).is_some_and(|t| t.text == ":")
            && tokens.get(at + 2).is_some_and(|t| t.text != ":")
            && (at == 0 || tokens[at - 1].text != ":")
            && array_of_32(&tokens, at + 2);
        if declared {
            found.push((token.text.to_string(), token.line));
        }
    }
    found
}

fn byte_holder_refusals(
    path: &str,
    text: &str,
    listed: &[(&str, &str, usize, &str)],
) -> Vec<String> {
    let found = byte_holders(path, text);
    let mut names: Vec<&str> = found.iter().map(|(name, _)| name.as_str()).collect();
    names.sort_unstable();
    names.dedup();
    let mut out = Vec::new();
    for name in names {
        let lines: Vec<usize> = found
            .iter()
            .filter(|(n, _)| n == name)
            .map(|(_, line)| *line)
            .collect();
        let allowed = listed
            .iter()
            .find(|(file, listed_name, ..)| *file == path && *listed_name == name)
            .map_or(0, |entry| entry.2);
        if lines.len() > allowed {
            out.push(format!(
                "{path}: `{name}: [u8; 32]` {} time(s) (lines {lines:?}), {allowed} listed; a transaction id is a `Txid` (#843, W1), or the site is listed with its reason",
                lines.len()
            ));
        }
    }
    for (file, name, count, _) in listed.iter().filter(|(file, ..)| *file == path) {
        let have = found.iter().filter(|(n, _)| n == name).count();
        if have < *count {
            out.push(format!(
                "{file}: `{name}: [u8; 32]` is listed {count} time(s) and found {have}; lower or remove its entry"
            ));
        }
    }
    out
}

/// (d), the locals: under the wallet and auth modules, `let [mut] <*txid*>`
/// declared as a 32-byte array or initialized by one.
fn local_refusals(path: &str, text: &str) -> Vec<String> {
    if !in_wallet_or_auth(path) {
        return Vec::new();
    }
    let tokens = code_tokens(text, false);
    let mut out = Vec::new();
    for (at, token) in code(&tokens) {
        if token.text != "let" {
            continue;
        }
        let mut name_at = at + 1;
        if tokens.get(name_at).is_some_and(|t| t.text == "mut") {
            name_at += 1;
        }
        let Some(name) = tokens.get(name_at) else {
            continue;
        };
        if !names_txid(name.text) {
            continue;
        }
        let next = tokens.get(name_at + 1).map(|t| t.text);
        let typed = next == Some(":") && array_of_32(&tokens, name_at + 2);
        let mut equals = name_at + 1;
        while tokens
            .get(equals)
            .is_some_and(|t| t.text != "=" && t.text != ";")
        {
            equals += 1;
        }
        let initialized =
            tokens.get(equals).is_some_and(|t| t.text == "=") && array_of_32(&tokens, equals + 1);
        if typed || initialized {
            out.push(format!(
                "{path}:{}: the local `{}` is a 32-byte array; a wallet or auth site holds a `Txid`, read by `read_txid` or from text",
                name.line, name.text
            ));
        }
    }
    out
}

/// Every `.rs` file under `dir`, as `(path from the crate root, text)`.
fn rust_files(root: &Path, dir: &Path, out: &mut Vec<(String, String)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        if path.is_dir() {
            // Build output and fuzz corpora hold no source of the crate.
            if !matches!(
                name.as_str(),
                "target" | "corpus" | "artifacts" | "coverage"
            ) {
                rust_files(root, &path, out);
            }
        } else if name.ends_with(".rs") {
            let relative = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            let text = arch_support::normalize(&std::fs::read_to_string(&path).unwrap());
            out.push((relative, text));
        }
    }
}

fn tree() -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    for dir in ["src", "tests", "examples", "benches", "fuzz"] {
        rust_files(root, &root.join(dir), &mut files);
    }
    files.sort();
    files
}

fn report(rule: &str, refusals: &[String]) {
    assert!(
        refusals.is_empty(),
        "{rule}: {} refusal(s)\n{}",
        refusals.len(),
        refusals.join("\n")
    );
}

#[test]
fn no_source_names_the_wallets_alias_843w1() {
    let files = tree();
    assert!(
        files.len() > 500,
        "the tree was read: {} files",
        files.len()
    );
    for dir in ["src/", "tests/", "examples/", "benches/", "fuzz/"] {
        assert!(files.iter().any(|(path, _)| path.starts_with(dir)), "{dir}");
    }
    let refusals: Vec<String> = files
        .iter()
        .flat_map(|(path, text)| alias_refusals(path, text))
        .collect();
    report("(a) the alias", &refusals);
}

#[test]
fn the_display_order_doors_are_named_in_the_pairs_file_alone_843w1() {
    let files = tree();
    let refusals: Vec<String> = files
        .iter()
        .flat_map(|(path, text)| display_door_refusals(path, text))
        .collect();
    report("(b) the display-order doors", &refusals);
    // The pair is seen to be read: its file names both doors.
    let pair = &files.iter().find(|(path, _)| path == PAIR).expect(PAIR).1;
    let tokens = code_tokens(pair, false);
    for door in ["from_display_bytes", "to_display_bytes"] {
        assert!(tokens.iter().any(|t| t.text == door), "{PAIR} names {door}");
    }
}

#[test]
fn no_wallet_or_auth_site_names_a_wire_order_door_or_reverses_by_hand_843w1() {
    let files = tree();
    let mut refusals: Vec<String> = files
        .iter()
        .flat_map(|(path, text)| wire_door_refusals(path, text, WIRE_DOORS))
        .collect();
    let paths: Vec<String> = files.iter().map(|(path, _)| path.clone()).collect();
    refusals.extend(stale_wire_doors(&paths, WIRE_DOORS));
    report("(c) the wire-order doors and `.reverse()`", &refusals);
    assert_eq!(WIRE_DOORS.len(), 1, "the list only shrinks");
}

#[test]
fn no_txid_is_a_bare_array_outside_the_listed_holders_843w1() {
    let files = tree();
    let mut refusals: Vec<String> = files
        .iter()
        .flat_map(|(path, text)| byte_holder_refusals(path, text, BYTE_HOLDERS))
        .collect();
    for (file, ..) in BYTE_HOLDERS {
        if !files.iter().any(|(path, _)| path == file) {
            refusals.push(format!("{file}: listed and not a file under src/"));
        }
    }
    refusals.extend(
        files
            .iter()
            .flat_map(|(path, text)| local_refusals(path, text)),
    );
    report("(d) a txid held as `[u8; 32]`", &refusals);
    assert_eq!(BYTE_HOLDERS.len(), 3, "the list only shrinks");
    for (.., reason) in BYTE_HOLDERS {
        assert!(reason.len() > 20, "each entry says why");
    }
}

/// Each refusal refuses a planted line, and reads past a comment, a literal
/// and a test module.
#[test]
fn each_refusal_refuses_a_planted_line_843w1() {
    let alias = ["Tx", "Id"].concat();

    // (a)
    let planted = format!("pub type {alias} = [u8; 32];\n");
    assert_eq!(alias_refusals("src/wallet/types.rs", &planted).len(), 1);
    let planted = format!("fn f(txid: {alias}) {{}}\n");
    assert_eq!(alias_refusals("tests/some_test.rs", &planted).len(), 1);
    assert_eq!(alias_refusals("fuzz/fuzz_targets/x.rs", &planted).len(), 1);
    let quiet = format!("// the old {alias}\nconst A: &str = \"{alias}\";\nstruct Txid;\n");
    assert!(alias_refusals("src/wallet/types.rs", &quiet).is_empty());

    // (b)
    let planted = "fn f(t: Txid) -> [u8; 32] { t.to_display_bytes() }\n";
    assert_eq!(
        display_door_refusals("src/wallet/wire/encoding.rs", planted).len(),
        1
    );
    assert_eq!(
        display_door_refusals("src/kvstore/local.rs", planted).len(),
        1
    );
    let planted = "fn f(b: [u8; 32]) -> Txid { Txid::from_display_bytes(b) }\n";
    assert_eq!(
        display_door_refusals("src/auth/certificates/certificate.rs", planted).len(),
        1
    );
    assert!(display_door_refusals(PAIR, planted).is_empty());
    assert!(display_door_refusals("src/transaction/txid.rs", planted).is_empty());
    assert!(display_door_refusals("src/wallet/wire/some_tests.rs", planted).is_empty());
    let in_tests = format!("#[cfg(test)]\nmod tests {{\n{planted}}}\n");
    assert!(display_door_refusals("src/wallet/wire/encoding.rs", &in_tests).is_empty());

    // (c)
    let planted = "fn f(t: &Txid, w: &mut W) { w.write_bytes(t.as_wire_bytes()); }\n";
    let refused = wire_door_refusals("src/wallet/wire/transceiver.rs", planted, WIRE_DOORS);
    assert_eq!(refused.len(), 1, "{refused:?}");
    let planted = "fn f(b: [u8; 32]) -> Txid { Txid::from_wire_bytes(b) }\n";
    assert_eq!(
        wire_door_refusals("src/auth/peer.rs", planted, WIRE_DOORS).len(),
        1
    );
    assert!(wire_door_refusals("src/kvstore/local.rs", planted, WIRE_DOORS).is_empty());
    // The listed file at its count passes, one more is refused, one fewer stale.
    let listed = WIRE_DOORS[0].0;
    let twice = format!("{planted}{planted}");
    assert!(wire_door_refusals(listed, &twice, WIRE_DOORS).is_empty());
    let thrice = format!("{twice}{planted}");
    assert_eq!(wire_door_refusals(listed, &thrice, WIRE_DOORS).len(), 1);
    let stale = wire_door_refusals(listed, planted, WIRE_DOORS);
    assert!(
        stale.len() == 1 && stale[0].contains("only shrinks"),
        "{stale:?}"
    );
    assert_eq!(
        stale_wire_doors(&["src/lib.rs".to_string()], WIRE_DOORS).len(),
        1
    );
    let planted = "fn f(mut b: Vec<u8>) -> Vec<u8> { b.reverse(); b }\n";
    assert_eq!(
        wire_door_refusals("src/wallet/substrates/result_values/beef.rs", planted, &[]).len(),
        1
    );
    assert_eq!(
        wire_door_refusals("src/auth/certificates/certificate.rs", planted, &[]).len(),
        1
    );
    let quiet = "fn reverse() {}\nfn g() { reverse(); let s = \".reverse()\"; }\n";
    assert!(wire_door_refusals("src/wallet/types.rs", quiet, &[]).is_empty());

    // (d), fields and parameters
    for planted in [
        "pub struct S { pub txid: [u8; 32], pub vout: u32 }\n",
        "pub fn f(source_txid: [u8; 32]) {}\n",
        "pub trait T { fn get(&self, txid: &[u8; 32]) -> u8; }\n",
        "pub struct S { known_txids: Vec<u8>, pub competing_txid: &'static [u8; 32] }\n",
    ] {
        let refused = byte_holder_refusals("src/wallet/types.rs", planted, BYTE_HOLDERS);
        assert_eq!(refused.len(), 1, "{planted}: {refused:?}");
        assert!(byte_holder_refusals("src/transaction/input.rs", planted, BYTE_HOLDERS).is_empty());
    }
    for quiet in [
        "pub struct S { pub txid: Txid, pub hash: [u8; 32] }\n",
        "pub struct S { pub txid: String }\nfn f() { let x = Outpoint { txid: id, vout: 0 }; }\n",
        "fn f() { let a = crate::txid::Txid::from_hex(t); }\n",
    ] {
        let refused = byte_holder_refusals("src/wallet/types.rs", quiet, BYTE_HOLDERS);
        assert!(refused.is_empty(), "{quiet}: {refused:?}");
    }
    // A listed holder at its count passes; one more is refused; gone is stale.
    let (file, name, ..) = BYTE_HOLDERS[0];
    let one = format!("pub struct TxInput {{ pub {name}: [u8; 32] }}\n");
    assert!(byte_holder_refusals(file, &one, BYTE_HOLDERS).is_empty());
    let two = format!("{one}pub struct Other {{ pub {name}: [u8; 32] }}\n");
    assert_eq!(byte_holder_refusals(file, &two, BYTE_HOLDERS).len(), 1);
    let gone = byte_holder_refusals(
        file,
        "pub struct TxInput { pub txid: Txid }\n",
        BYTE_HOLDERS,
    );
    assert!(
        gone.len() == 1 && gone[0].contains("lower or remove"),
        "{gone:?}"
    );

    // (d), locals
    for planted in [
        "fn f() { let mut txid = [0u8; 32]; txid.copy_from_slice(b); }\n",
        "fn f() { let mut txid_arr: [u8; 32] = Default::default(); }\n",
        "fn f() { let txid: [u8; 32] = b.try_into().unwrap(); }\n",
        "fn f() { let source_txid = [0xab; 32]; }\n",
    ] {
        assert_eq!(
            local_refusals("src/wallet/validation.rs", planted).len(),
            1,
            "{planted}"
        );
        assert_eq!(
            local_refusals("src/auth/certificates/certificate.rs", planted).len(),
            1
        );
        assert!(local_refusals("src/registry/client.rs", planted).is_empty());
    }
    for quiet in [
        "fn f() { let txid = Txid::from_hex(text)?; }\n",
        "fn f() { let txid = reader.read_txid()?; let nonce = [0u8; 32]; }\n",
        "fn f() { let txids: Vec<Txid> = vec![]; }\n",
    ] {
        assert!(
            local_refusals("src/wallet/validation.rs", quiet).is_empty(),
            "{quiet}"
        );
    }
}
