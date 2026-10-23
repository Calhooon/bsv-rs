//! Native time and threads cannot leak into code compiled for wasm32.
#![allow(clippy::expect_used, clippy::panic)] // Source reads are test assertions.

mod arch_support;

const ALLOWED: &[(&str, &str, usize)] = &[];

fn native_site(tokens: &[arch_support::Token<'_>], at: usize) -> bool {
    if tokens[at].literal {
        return false;
    }
    if tokens[at].text == "SystemTime" {
        return true;
    }
    if tokens[at].text != "thread" {
        return false;
    }
    // Reject the module at direct and grouped std imports too, so an alias
    // cannot hide a later spawn. An ordinary variable named thread is fine.
    let in_std_import = tokens[..at]
        .iter()
        .rposition(|t| matches!(t.text, "use" | ";"))
        .is_some_and(|start| {
            tokens[start].text == "use"
                && (tokens.get(start + 1).is_some_and(|t| t.text == "std")
                    || (tokens.get(start + 1).is_some_and(|t| t.text == "::")
                        && tokens.get(start + 2).is_some_and(|t| t.text == "std")))
        });
    in_std_import
        || (at >= 2 && tokens[at - 2].text == "std" && tokens[at - 1].text == "::")
        || (tokens.get(at + 1).is_some_and(|t| t.text == "::")
            && tokens.get(at + 2).is_some_and(|t| t.text == "spawn"))
}

#[test]
fn native_time_and_threads_stay_in_util_or_native_cfg() {
    let mut sites = Vec::new();
    for source in arch_support::sources() {
        if source.path.starts_with("src/util/") {
            continue;
        }
        let tokens = source.portable_tokens();
        for at in 0..tokens.len() {
            if native_site(&tokens, at) {
                sites.push((
                    source.path.clone(),
                    tokens[at].line,
                    source.line(tokens[at].line).to_owned(),
                ));
            }
        }
    }
    arch_support::check_sites(
        "native time/thread outside util or a native cfg",
        &sites,
        ALLOWED,
    );
    println!("native time/thread exceptions: {}", ALLOWED.len());
}

#[test]
fn native_cfg_covers_only_the_annotated_item_or_block() {
    let source = r#"
#[cfg(not(target_arch = "wasm32"))]
fn native() { std::thread::spawn(task); }
fn portable() { std::time::SystemTime::now(); }
#[cfg(all(feature = "http", not(target_arch = "wasm32")))]
fn native_http() { std::thread::spawn(task); }
#[cfg(any(feature = "http", not(target_arch = "wasm32")))]
fn could_be_wasm() { std::thread::spawn(task); }
fn block() {
    #[cfg(not(target_arch = "wasm32"))]
    { std::thread::spawn(task); }
    std::time::SystemTime::now();
}
"#;
    let tokens = arch_support::code_tokens(source, true);
    let lines: Vec<_> = (0..tokens.len())
        .filter(|at| native_site(&tokens, *at))
        .map(|at| tokens[at].line)
        .collect();
    assert_eq!(lines, [4, 8, 12]);
}

#[test]
fn grouped_thread_import_and_wasm_only_code_are_not_exempt() {
    for source in [
        "use std::{thread::{spawn as start}};",
        "#[cfg(target_arch = r#\"wasm32\"#)] fn f() { std::thread::spawn(task); }",
    ] {
        let tokens = arch_support::code_tokens(source, true);
        assert!((0..tokens.len()).any(|at| native_site(&tokens, at)));
    }
    let tokens = arch_support::code_tokens("fn f() { let thread = 1; drop(thread); }", true);
    assert!(!(0..tokens.len()).any(|at| native_site(&tokens, at)));
}
