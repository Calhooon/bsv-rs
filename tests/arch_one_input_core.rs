//! One core judges an input (#855): outside `src/script/`, every construction
//! of the interpreter for one input of a transaction (`Spend::new(`,
//! `Spend::with_transaction(`, a `SpendParams {` or `TxSpendParams {`
//! literal) sits in `src/transaction/spending.rs`, the file of the door and
//! the crate-private core `Transaction::verify` and the streaming reader call.
//! A third site is refused by its `file:line`, so the door, the whole
//! verifier and the stream cannot drift apart.
//!
//! The scan is lexical (`arch_support`): comments and string literals supply
//! no site, a `#[cfg(test)]` item is skipped, and a file named `tests.rs` or
//! `*_tests.rs` is a test module and is not read.
#![allow(clippy::expect_used, clippy::panic)] // Source reads are test assertions.

mod arch_support;

/// The one file allowed to build a `Spend` outside the interpreter.
const CORE_FILE: &str = "src/transaction/spending.rs";

fn is_test_file(path: &str) -> bool {
    path.ends_with("/tests.rs") || path.ends_with("_tests.rs")
}

/// The sites of one source: `(line, what)` for each construction found.
fn construction_sites(tokens: &[arch_support::Token<'_>]) -> Vec<(usize, &'static str)> {
    let text = |i: usize| tokens.get(i).map(|t| (t.text, t.literal));
    let mut sites = Vec::new();
    for (at, token) in tokens.iter().enumerate() {
        if token.literal {
            continue;
        }
        let what = match token.text {
            "Spend" if text(at + 1) == Some(("::", false)) => match text(at + 2) {
                Some(("new", false)) if text(at + 3) == Some(("(", false)) => "Spend::new(",
                Some(("with_transaction", false)) if text(at + 3) == Some(("(", false)) => {
                    "Spend::with_transaction("
                }
                _ => continue,
            },
            "SpendParams" if text(at + 1) == Some(("{", false)) => "SpendParams {",
            "TxSpendParams" if text(at + 1) == Some(("{", false)) => "TxSpendParams {",
            _ => continue,
        };
        sites.push((token.line, what));
    }
    sites
}

/// Every construction outside `src/script/` and test files, as
/// `(path, line, what)`.
fn all_sites() -> Vec<(String, usize, &'static str)> {
    let mut out = Vec::new();
    for source in arch_support::sources() {
        if source.path.starts_with("src/script/") || is_test_file(&source.path) {
            continue;
        }
        for (line, what) in construction_sites(&source.tokens()) {
            out.push((source.path.clone(), line, what));
        }
    }
    out
}

#[test]
fn every_spend_built_for_an_input_outside_the_interpreter_sits_in_the_one_core_855() {
    let sites = all_sites();
    let stray: Vec<String> = sites
        .iter()
        .filter(|(path, _, _)| path != CORE_FILE)
        .map(|(path, line, what)| format!("{path}:{line}: {what}"))
        .collect();
    assert!(
        stray.is_empty(),
        "a Spend is built for an input outside {CORE_FILE}: route it through the core \
         (`spending::judge_input`) instead:\n{}",
        stray.join("\n")
    );
    assert!(
        sites.iter().any(|(path, _, _)| path == CORE_FILE),
        "{CORE_FILE} builds no Spend: the core moved, so this rule names the wrong file"
    );
}

#[test]
fn the_scan_finds_each_construction_and_ignores_comments_and_literals() {
    let probe = "\
fn a() { let s = Spend::new(SpendParams { x: 1 }); }
// Spend::new( in a comment
fn b() { let t = \"Spend::with_transaction(\"; }
fn c() { let s = Spend::with_transaction(TxSpendParams { y: 2 }); }
#[cfg(test)]
mod tests { fn d() { Spend::new(p); } }
";
    let tokens = arch_support::code_tokens(probe, false);
    let found = construction_sites(&tokens);
    assert_eq!(
        found,
        vec![
            (1, "Spend::new("),
            (1, "SpendParams {"),
            (4, "Spend::with_transaction("),
            (4, "TxSpendParams {"),
        ]
    );
}

#[test]
fn the_two_production_paths_call_the_core() {
    for file in [
        "src/transaction/verify.rs",
        "src/transaction/beef_stream/spends.rs",
    ] {
        let text = arch_support::read(file);
        assert!(
            text.contains("judge_input("),
            "{file} no longer calls the one core (`judge_input`)"
        );
    }
}
