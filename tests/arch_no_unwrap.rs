//! Executable unwrap/expect sites, with per-file ceilings that may only fall.
#![allow(clippy::expect_used, clippy::panic)] // Source reads are test assertions.

mod arch_support;

// Counted on efe12e6, excluding comments, literals and cfg-gated test items.
// #78's original 276 also counted documentation and compound-cfg tests.
// A ceiling equals its file's count: a file under its ceiling, or gone, is red
// until the ceiling falls with it (#347).
const CEILINGS: &[(&str, usize)] = &[
    ("src/overlay/overlay_admin_token_template.rs", 3),
    ("src/primitives/ec/public_key.rs", 1),
    ("src/primitives/hash.rs", 5),
    ("src/primitives/p256.rs", 3),
    ("src/primitives/symmetric.rs", 1),
    ("src/transaction/beef_stream.rs", 23), // 24 until #347 found one gone
    ("src/transaction/transaction.rs", 2),
    ("src/wallet/key_deriver.rs", 1),
];

/// A ceiling entry above its file's count: the file gone or without a site
/// (delete the entry), or with fewer sites (lower the ceiling).
fn stale_ceilings(counts: &[(String, usize)], ceilings: &[(&str, usize)]) -> Vec<String> {
    let mut errors = Vec::new();
    for (file, ceiling) in ceilings {
        let count = counts
            .iter()
            .find(|(path, _)| path == file)
            .map_or(0, |(_, count)| *count);
        if count == 0 {
            errors.push(format!(
                "{file}: ceiling entry {ceiling} matches no unwrap/expect site; delete the entry"
            ));
        } else if count < *ceiling {
            errors.push(format!(
                "{file}: ceiling entry {ceiling} matches {count} unwrap/expect sites; lower its ceiling to {count}"
            ));
        }
    }
    errors
}

#[test]
fn unwrap_and_expect_counts_never_rise() {
    let mut errors = Vec::new();
    let mut counts = Vec::new();
    let mut total = 0;
    for source in arch_support::sources() {
        let tokens = source.tokens();
        let sites: Vec<_> = (0..tokens.len())
            .filter(|at| arch_support::is_call(&tokens, *at, &["unwrap", "expect"]))
            .collect();
        total += sites.len();
        counts.push((source.path.clone(), sites.len()));
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
    errors.extend(stale_ceilings(&counts, CEILINGS));
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

#[test]
fn a_stale_ceiling_entry_reads_red_naming_the_entry() {
    let counts = [
        ("src/kept.rs".to_owned(), 2),
        ("src/fallen.rs".to_owned(), 1),
    ];
    let errors = stale_ceilings(
        &counts,
        &[("src/kept.rs", 2), ("src/fallen.rs", 3), ("src/gone.rs", 1)],
    );
    assert_eq!(
        errors,
        [
            "src/fallen.rs: ceiling entry 3 matches 1 unwrap/expect sites; lower its ceiling to 1",
            "src/gone.rs: ceiling entry 1 matches no unwrap/expect site; delete the entry",
        ]
    );
}
