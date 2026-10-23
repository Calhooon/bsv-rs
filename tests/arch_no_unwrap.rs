//! Executable unwrap/expect sites, with per-file ceilings that may only fall.
#![allow(clippy::expect_used, clippy::panic)] // Source reads are test assertions.

mod arch_support;

// Counted on efe12e6, excluding comments, literals and cfg-gated test items.
// #78's original 276 also counted documentation and compound-cfg tests.
const CEILINGS: &[(&str, usize)] = &[
    ("src/overlay/overlay_admin_token_template.rs", 3),
    ("src/primitives/ec/public_key.rs", 1),
    ("src/primitives/hash.rs", 5),
    ("src/primitives/p256.rs", 3),
    ("src/primitives/symmetric.rs", 1),
    ("src/transaction/beef_stream.rs", 24),
    ("src/transaction/transaction.rs", 2),
    ("src/wallet/key_deriver.rs", 1),
];

#[test]
fn unwrap_and_expect_counts_never_rise() {
    let mut errors = Vec::new();
    let mut total = 0;
    for source in arch_support::sources() {
        let tokens = source.tokens();
        let sites: Vec<_> = (0..tokens.len())
            .filter(|at| arch_support::is_call(&tokens, *at, &["unwrap", "expect"]))
            .collect();
        total += sites.len();
        let ceiling = CEILINGS
            .iter()
            .find(|(file, _)| *file == source.path)
            .map_or(0, |(_, count)| *count);
        if sites.len() > ceiling {
            for at in sites {
                errors.push(format!(
                    "{}:{}: {} site; file exceeds ceiling {ceiling}",
                    source.path, tokens[at].line, tokens[at].text,
                ));
            }
        }
    }
    assert!(errors.is_empty(), "{}", errors.join("\n"));
    println!(
        "production unwrap/expect: {total}; ceiling files: {}",
        CEILINGS.len()
    );
}

#[test]
fn scanner_keeps_code_after_test_modules_and_ignores_literal_text() {
    let source = r####"
// value.unwrap();
/* outer /* nested .expect("comment") */ comment */
const DOC: &str = r###"a quote \" .unwrap() #[cfg(test)] { }"###;
fn before() { value . unwrap (); }
#[cfg(test)] mod tests { fn test() { value.unwrap(); } }
fn after() { value.expect("production"); }
#[cfg(all(test, feature = "http"))]
mod http_tests { fn test() { value.unwrap(); } }
#[cfg(any(test, feature = "http"))]
fn also_production() { value.unwrap(); }
#[cfg(test)]
use test_support::Helper;
fn after_test_import() { value.unwrap(); }
fn raw_identifier() { value.r#unwrap(); }
"####;
    let tokens = arch_support::code_tokens(source, false);
    let sites: Vec<_> = (0..tokens.len())
        .filter(|at| arch_support::is_call(&tokens, *at, &["unwrap", "expect"]))
        .map(|at| tokens[at].line)
        .collect();
    assert_eq!(sites, [5, 7, 11, 14, 15]);
}
