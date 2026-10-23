//! Library configuration is explicit; environment reads belong to callers.
#![allow(clippy::expect_used, clippy::panic)] // Source reads are test assertions.

mod arch_support;

// No existing environment sites. The array is deliberately empty.
const ALLOWED: &[(&str, &str, usize)] = &[];

fn env_sites(tokens: &[arch_support::Token<'_>]) -> Vec<usize> {
    let mut in_std_use = false;
    let mut sites = Vec::new();
    for (at, token) in tokens.iter().enumerate() {
        if token.text == "use" {
            in_std_use = tokens.get(at + 1).is_some_and(|t| t.text == "std")
                || (tokens.get(at + 1).is_some_and(|t| t.text == "::")
                    && tokens.get(at + 2).is_some_and(|t| t.text == "std"));
        }
        if token.text == ";" {
            in_std_use = false;
        }
        if token.text == "env"
            && (in_std_use
                || (at >= 2 && tokens[at - 2].text == "std" && tokens[at - 1].text == "::"))
        {
            sites.push(at);
        }
    }
    sites
}

#[test]
fn library_never_reads_the_environment() {
    let mut sites = Vec::new();
    for source in arch_support::sources() {
        let tokens = source.tokens();
        for at in env_sites(&tokens) {
            sites.push((
                source.path.clone(),
                tokens[at].line,
                source.line(tokens[at].line).to_owned(),
            ));
        }
    }
    arch_support::check_sites("std::env belongs to the caller", &sites, ALLOWED);
    println!("environment exceptions: {}", ALLOWED.len());
}

#[test]
fn direct_and_grouped_environment_imports_are_sites() {
    for text in [
        "std :: env :: var(name);",
        "use std::env as process_env;",
        "use std::{io, env::{var as setting}};",
    ] {
        assert_eq!(env_sites(&arch_support::code_tokens(text, false)).len(), 1);
    }
}
