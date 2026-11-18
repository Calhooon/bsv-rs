//! The removals of the 0.9.0 cut stay removed (#843, the owner's ruling of
//! 2026-11-17: the cut fixes every break that should happen, and a public
//! item that stays through the freeze stays for the whole 0.9 line).
//!
//! A census, read from the source as the other `arch_*` rules are. Three
//! claims, each no wider than what it reads:
//!
//! 1. No code token under `src/` is one of [`REMOVED`]: the names of row 10's
//!    deprecated doors (`Beef::from_binary_with_limits` and `BeefLimits`, the
//!    legacy admin-token lock, `verify_signature_legacy`,
//!    `Error::HmacMinimalLengthKey`), of `script::transaction` (its five
//!    traits and `SimpleUtxo`) and of the six methods of the wire codec that
//!    wrote or read a 0/1 mode byte no wire call carries. A name is refused
//!    whatever its visibility, in a test module too: none has a use left.
//! 2. `src/script/transaction.rs` is no file and `src/script/` declares no
//!    module `transaction`.
//! 3. In `src/wallet/wire/mod.rs`: `status_codes` and `counterparty_codes`
//!    are `pub(crate)`; `encoding` is a private module; and the one `pub use`
//!    under `src/` that names `WireReader` or `WireWriter` is the wire
//!    module's, under `#[doc(hidden)]`, with the module docs saying the codec
//!    is no part of the public contract.
//!
//! Not seen: a name brought back under another spelling, a re-export by a
//! glob, an item made by a macro. Comments and string literals are no code
//! token, so a record may still name what left.
#![allow(clippy::expect_used, clippy::panic)] // Source reads are test assertions.

mod arch_support;

use arch_support::{normalize, sources, Source, Token};

/// `(name, what to call instead)`: every name the cut removed.
const REMOVED: &[(&str, &str)] = &[
    ("from_binary_with_limits", "Beef::from_binary"),
    ("BeefLimits", "nothing: the hints refused nothing"),
    (
        "create_overlay_admin_token",
        "create_signed_overlay_admin_token",
    ),
    (
        "verify_signature_legacy",
        "KVStoreInterpreter::verify_signature",
    ),
    ("HmacMinimalLengthKey", "Error::HmacLegacyKey"),
    ("SimpleUtxo", "transaction::verify_input"),
    ("SpendValidation", "Transaction::verify"),
    ("TransactionContext", "Transaction's accessors"),
    ("TransactionInputContext", "TransactionInput"),
    ("TransactionOutputContext", "TransactionOutput"),
    ("UtxoProvider", "a ChainTracker and the linked sources"),
    ("write_query_mode", "write_optional_query_mode"),
    ("read_query_mode", "read_optional_query_mode"),
    ("write_output_include", "the byte, written by list_outputs"),
    ("read_output_include", "the byte"),
    (
        "write_optional_output_include",
        "the byte, written by list_outputs",
    ),
    ("read_optional_output_include", "the byte"),
];

const WIRE_MOD: &str = "src/wallet/wire/mod.rs";
const CONTRACT_SENTENCE: &str = "no part of the public contract";

fn texts<'a>(tokens: &[Token<'a>], from: usize, len: usize) -> Vec<&'a str> {
    tokens.iter().skip(from).take(len).map(|t| t.text).collect()
}

/// Claim 1 over one file.
fn removed_names(source: &Source) -> Vec<String> {
    source
        .raw_tokens()
        .iter()
        .filter(|t| !t.literal)
        .filter_map(|t| {
            REMOVED
                .iter()
                .find(|(name, _)| *name == t.text)
                .map(|(name, instead)| {
                    format!(
                        "{}:{}: `{name}` was removed in the 0.9.0 cut (#843); use {instead}",
                        source.path, t.line
                    )
                })
        })
        .collect()
}

/// Claim 2 over the tree's files.
fn script_transaction(all: &[Source]) -> Vec<String> {
    let mut out = Vec::new();
    for source in all {
        if source.path == "src/script/transaction.rs"
            || source.path.starts_with("src/script/transaction/")
        {
            out.push(format!(
                "{}: `script::transaction` was removed in the 0.9.0 cut (#843)",
                source.path
            ));
        }
        if source.path == "src/script/mod.rs" {
            let tokens = source.raw_tokens();
            for (at, token) in tokens.iter().enumerate() {
                if token.text == "mod" && texts(&tokens, at + 1, 1) == ["transaction"] {
                    out.push(format!(
                        "{}:{}: `script` declares a module `transaction`, removed in the 0.9.0 cut (#843)",
                        source.path, token.line
                    ));
                }
            }
        }
    }
    out
}

/// Whether the tokens ending just before `at` are `pub ( crate )`.
fn crate_private(tokens: &[Token<'_>], at: usize) -> bool {
    at >= 4 && texts(tokens, at - 4, 4) == ["pub", "(", "crate", ")"]
}

/// Claim 3 over the tree's files.
fn wire_codec(all: &[Source]) -> Vec<String> {
    let mut out = Vec::new();
    let mut hidden_exports = 0;
    let mut code_modules = 0;
    for source in all {
        let tokens = source.raw_tokens();
        for (at, token) in tokens.iter().enumerate() {
            let here = |what: &str| format!("{}:{}: {what}", source.path, token.line);
            if token.text == "use" && at >= 1 && tokens[at - 1].text == "pub" {
                let end = tokens[at..]
                    .iter()
                    .position(|t| t.text == ";")
                    .map_or(tokens.len(), |n| at + n);
                let names_codec = tokens[at..end]
                    .iter()
                    .any(|t| t.text == "WireReader" || t.text == "WireWriter");
                if !names_codec {
                    continue;
                }
                let hidden = at >= 8
                    && texts(&tokens, at - 8, 7) == ["#", "[", "doc", "(", "hidden", ")", "]"];
                if source.path != WIRE_MOD {
                    out.push(here("a `pub use` of the wire codec outside `wallet::wire`"));
                } else if !hidden {
                    out.push(here(
                        "the `pub use` of `WireReader`/`WireWriter` is not directly under `#[doc(hidden)]`",
                    ));
                } else {
                    hidden_exports += 1;
                }
            }
            if source.path != WIRE_MOD || token.text != "mod" {
                continue;
            }
            match texts(&tokens, at + 1, 1).first().copied() {
                Some(name @ ("status_codes" | "counterparty_codes")) => {
                    code_modules += 1;
                    if !crate_private(&tokens, at) {
                        out.push(here(&format!("`{name}` is not `pub(crate)`")));
                    }
                }
                Some("encoding") if at >= 1 && matches!(tokens[at - 1].text, "pub" | ")") => {
                    out.push(here("`encoding` is not a private module"));
                }
                _ => {}
            }
        }
        if source.path == WIRE_MOD {
            let docs: String = source
                .text
                .lines()
                .filter(|l| l.starts_with("//!"))
                .collect::<Vec<_>>()
                .join("\n");
            if !docs.contains(CONTRACT_SENTENCE) {
                out.push(format!(
                    "{WIRE_MOD}: the module docs do not say the codec is {CONTRACT_SENTENCE}"
                ));
            }
        }
    }
    if hidden_exports != 1 {
        out.push(format!(
            "{WIRE_MOD}: {hidden_exports} hidden `pub use` of the wire codec, where one is expected (moved? update this rule)"
        ));
    }
    if code_modules != 2 {
        out.push(format!(
            "{WIRE_MOD}: {code_modules} of `status_codes` and `counterparty_codes` declared, where two are expected (removed? update this rule)"
        ));
    }
    out
}

fn refusals(all: &[Source]) -> Vec<String> {
    let mut out: Vec<String> = all.iter().flat_map(removed_names).collect();
    out.extend(script_transaction(all));
    out.extend(wire_codec(all));
    out
}

#[test]
fn no_name_the_cut_removed_is_back_843() {
    let found = refusals(&sources());
    assert!(found.is_empty(), "{}", found.join("\n"));
}

fn sample(path: &str, text: &str) -> Source {
    Source {
        path: path.to_string(),
        text: normalize(text),
    }
}

/// The wire module as the cut leaves it, in small.
const WIRE_SAMPLE: &str = "//! The codec is no part of the public contract.\n\
    mod encoding;\n\
    #[doc(hidden)]\n\
    pub use encoding::{WireReader, WireWriter};\n\
    pub(crate) mod counterparty_codes {}\n\
    pub(crate) mod status_codes {}\n";

fn tree(extra: &[(&str, &str)], wire: &str) -> Vec<Source> {
    let mut all = vec![sample(WIRE_MOD, wire)];
    all.extend(extra.iter().map(|(path, text)| sample(path, text)));
    all
}

#[test]
fn the_sample_tree_passes_and_each_plant_is_refused_843() {
    assert_eq!(refusals(&tree(&[], WIRE_SAMPLE)), Vec::<String>::new());

    // Claim 1: each removed name, at any visibility, in any position.
    for (name, _) in REMOVED {
        for text in [
            format!("pub fn {name}() {{}}"),
            format!("pub(crate) struct {name};"),
            format!("#[cfg(test)]\nmod tests {{ fn t() {{ super::{name}(); }} }}"),
        ] {
            let found = refusals(&tree(&[("src/a.rs", &text)], WIRE_SAMPLE));
            assert!(
                found.len() == 1 && found[0].contains(name),
                "{name} in `{text}`: {found:?}"
            );
        }
    }
    // A comment or a literal naming one is a record, not code.
    let record = "// BeefLimits left in 0.9.0\nconst NOTE: &str = \"verify_signature_legacy\";";
    assert_eq!(
        refusals(&tree(&[("src/a.rs", record)], WIRE_SAMPLE)),
        Vec::<String>::new()
    );
    // A longer name that only contains one is another name.
    let longer = "pub fn write_optional_query_mode() {} pub struct BeefLimitsNext;";
    assert_eq!(
        refusals(&tree(&[("src/a.rs", longer)], WIRE_SAMPLE)),
        Vec::<String>::new()
    );

    // Claim 2.
    for (path, text, words) in [
        (
            "src/script/transaction.rs",
            "",
            "`script::transaction` was removed",
        ),
        (
            "src/script/transaction/mod.rs",
            "",
            "`script::transaction` was removed",
        ),
        (
            "src/script/mod.rs",
            "pub mod transaction;",
            "declares a module `transaction`",
        ),
        (
            "src/script/mod.rs",
            "mod transaction {}",
            "declares a module `transaction`",
        ),
    ] {
        let found = refusals(&tree(&[(path, text)], WIRE_SAMPLE));
        assert!(
            found.len() == 1 && found[0].contains(words),
            "{path} `{text}`: {found:?}"
        );
    }
    // The transaction module of the crate is not `script`'s.
    assert_eq!(
        refusals(&tree(
            &[("src/lib.rs", "pub mod transaction;")],
            WIRE_SAMPLE
        )),
        Vec::<String>::new()
    );

    // Claim 3: one change of the wire module at a time.
    for (from, to, words) in [
        (
            "#[doc(hidden)]\n",
            "",
            "not directly under `#[doc(hidden)]`",
        ),
        (
            "#[doc(hidden)]\n",
            "#[doc(hidden)]\n#[allow(unused)]\n",
            "not directly under `#[doc(hidden)]`",
        ),
        (
            "pub(crate) mod status_codes",
            "pub mod status_codes",
            "`status_codes` is not `pub(crate)`",
        ),
        (
            "pub(crate) mod counterparty_codes",
            "pub(super) mod counterparty_codes",
            "`counterparty_codes` is not `pub(crate)`",
        ),
        (
            "pub(crate) mod counterparty_codes {}\n",
            "",
            "1 of `status_codes` and `counterparty_codes` declared",
        ),
        (
            "mod encoding;",
            "pub mod encoding;",
            "`encoding` is not a private module",
        ),
        (
            "mod encoding;",
            "pub(crate) mod encoding;",
            "`encoding` is not a private module",
        ),
        (
            "no part of the public contract",
            "stable",
            "the module docs do not say",
        ),
        (
            "#[doc(hidden)]\npub use encoding::{WireReader, WireWriter};\n",
            "",
            "0 hidden `pub use`",
        ),
    ] {
        assert!(WIRE_SAMPLE.contains(from), "{from}");
        let found = refusals(&tree(&[], &WIRE_SAMPLE.replace(from, to)));
        assert!(
            found.iter().any(|line| line.contains(words)),
            "`{from}` to `{to}`: {found:?}"
        );
    }
    // A second public path to the codec.
    for text in [
        "pub use crate::wallet::wire::WireWriter;",
        "#[doc(hidden)]\npub use wire::{WireReader as Reader};",
    ] {
        let found = refusals(&tree(&[("src/wallet/mod.rs", text)], WIRE_SAMPLE));
        assert!(
            found.len() == 1 && found[0].contains("outside `wallet::wire`"),
            "`{text}`: {found:?}"
        );
    }
    // A crate-private use of it is no public path.
    assert_eq!(
        refusals(&tree(
            &[(
                "src/wallet/wire/flags.rs",
                "use super::{refused, WireReader};"
            )],
            WIRE_SAMPLE
        )),
        Vec::<String>::new()
    );
}
