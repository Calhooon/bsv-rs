//! The ARC client surface is deprecated and is nowhere a default (bsv-rs#350,
//! the owner's word of 2026-10-27: "arc is just deprecated, arcade is the
//! standard"). Read from the source, as the other `arch_*` rules are: each
//! named item carries `#[deprecated(since = "0.9.0", ..)]` with a note naming
//! ARCade, and the `Default` impls `#[deprecated]` cannot mark (rustc refuses
//! it on a trait impl block) do not choose ARC's URL.
#![allow(clippy::expect_used, clippy::panic)] // Source reads are test assertions.

mod arch_support;

/// `(file, the item's first line)`: every ARC item a caller can name.
const DEPRECATED: &[(&str, &str)] = &[
    (
        "src/transaction/broadcasters/arc.rs",
        "pub struct ArcConfig {",
    ),
    (
        "src/transaction/broadcasters/arc.rs",
        "pub struct ArcBroadcaster {",
    ),
    (
        "src/transaction/broadcasters/arc.rs",
        "pub fn new(url: &str, api_key: Option<String>) -> Self {",
    ),
    (
        "src/transaction/broadcasters/arc.rs",
        "pub fn with_config(config: ArcConfig) -> Self {",
    ),
    (
        "src/transaction/fee_models/live_policy.rs",
        "pub const DEFAULT_POLICY_URL: &str",
    ),
    (
        "src/transaction/fee_models/live_policy.rs",
        "pub fn new() -> Self {",
    ),
];

use arch_support::read;

/// The attribute and doc lines directly above `item`, joined.
fn attributes_of(source: &str, item: &str) -> Option<String> {
    let lines: Vec<&str> = source.lines().collect();
    let at = lines
        .iter()
        .position(|l| l.trim_start().starts_with(item))?;
    let mut above = Vec::new();
    for line in lines[..at].iter().rev() {
        let t = line.trim();
        if t.starts_with("#[")
            || t.starts_with("///")
            || t.starts_with(')')
            || t.starts_with("note")
            || t.starts_with("since")
            || t.starts_with('"')
        {
            above.push(t);
        } else {
            break;
        }
    }
    above.reverse();
    Some(above.join(" "))
}

#[test]
fn every_arc_client_item_is_deprecated_since_0_9_0_naming_arcade() {
    let mut missing = Vec::new();
    for (file, item) in DEPRECATED {
        let source = read(file);
        let attrs = attributes_of(&source, item)
            .unwrap_or_else(|| panic!("{file}: no item `{item}` (renamed? update this rule)"));
        let marked = attrs.contains("#[deprecated(")
            && attrs.contains("since = \"0.9.0\"")
            && attrs.contains("ARCade is the standard");
        if !marked {
            missing.push(format!("{file}: `{item}`"));
        }
    }
    assert!(
        missing.is_empty(),
        "ARC items without #[deprecated(since = \"0.9.0\", note = \"..ARCade is the standard..\")]:\n{}",
        missing.join("\n")
    );
}

/// The `impl` block opened by `header`, up to its closing brace at column 0.
/// `source` is read through `arch_support`, its line endings `\n`.
fn impl_body<'a>(source: &'a str, header: &str) -> &'a str {
    let start = source
        .find(header)
        .unwrap_or_else(|| panic!("live_policy.rs: no `{header}`"));
    let body = &source[start..];
    let end = body.find("\n}\n").expect("the impl's closing brace");
    &body[..end]
}

#[test]
fn no_live_policy_default_chooses_the_arc_policy_url() {
    let source = read("src/transaction/fee_models/live_policy.rs");
    for header in [
        "impl Default for LivePolicyConfig {",
        "impl Default for LivePolicy {",
    ] {
        let body = impl_body(&source, header);
        for arc in ["DEFAULT_POLICY_URL", "arc.", "Self::new()"] {
            assert!(
                !body.contains(arc),
                "`{header}` chooses ARC (`{arc}`): a Default cannot carry #[deprecated], so it takes no URL"
            );
        }
    }
}

/// A Windows checkout holds the source in CRLF (run 40513515368's two Windows
/// cells, bsv-rs#367): the reader's normalization lets the `\n}\n` search find
/// the closing brace there as on a LF checkout.
#[test]
fn a_crlf_checkout_finds_the_impl_closing_brace_as_lf_does() {
    let crlf = "impl Default for LivePolicy {\r\n    fn default() -> Self {\r\n        \
                Self::with_config(LivePolicyConfig::default())\r\n    }\r\n}\r\n\r\nfn after() {}\r\n";
    let source = arch_support::normalize(crlf);
    let body = impl_body(&source, "impl Default for LivePolicy {");
    assert!(body.contains("Self::with_config("), "{body}");
    assert!(!body.contains("fn after"), "{body}");
    assert_eq!(
        body,
        impl_body(&crlf.replace("\r\n", "\n"), "impl Default for LivePolicy {")
    );
}
