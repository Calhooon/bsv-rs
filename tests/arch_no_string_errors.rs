//! Refuse new text classification in the four transport directories (#87).
#![allow(clippy::expect_used, clippy::panic)] // Source reads are test assertions.

mod arch_support;

const HOMES: &[&str] = &[
    "src/wallet/substrates/",
    "src/auth/transports/",
    "src/transaction/broadcasters/",
    "src/transaction/chain_trackers/",
];

// Conservatively scan all literal comparisons: error variable names and
// aliases are not reliable. Today's protocol comparisons are allowed as whole
// lines, never as permission for an entire file. #87 reviewed this list
// (docs/ARCH-RULES.md section 3): every line a protocol comparison, no
// error-message allowance.
const ALLOWED: &[(&str, &str, usize)] = &[
    // The constructors' base URL and originator (#323): the caller's own
    // strings read at construction, the reference's
    // `normalizeWalletHttpBaseUrl` and `isLoopbackHostname`; no answer read.
    (
        "src/wallet/substrates/origin.rs",
        "&& parsed.path() == \"/\"",
        1,
    ),
    (
        "src/wallet/substrates/origin.rs",
        "if parsed.scheme() == \"http\" && !is_loopback_hostname(host) {",
        1,
    ),
    (
        "src/wallet/substrates/origin.rs",
        "normalized == \"localhost\"",
        1,
    ),
    (
        "src/wallet/substrates/origin.rs",
        "|| normalized == \"127.0.0.1\"",
        1,
    ),
    (
        "src/wallet/substrates/origin.rs",
        "|| normalized == \"[::1]\"",
        1,
    ),
    (
        "src/auth/transports/websocket_transport.rs",
        "if !options.base_url.starts_with(\"ws://\") && !options.base_url.starts_with(\"wss://\") {",
        2,
    ),
    (
        "src/auth/transports/http.rs",
        "if lower_key.starts_with(\"x-bsv-\")",
        1,
    ),
    (
        "src/auth/transports/http.rs",
        "|| lower_key == \"authorization\"",
        1,
    ),
    (
        "src/auth/transports/http.rs",
        "|| lower_key == \"content-type\"",
        1,
    ),
    (
        "src/auth/transports/http.rs",
        "if !lower_key.starts_with(\"x-bsv-auth\") {",
        1,
    ),
    (
        "src/auth/transports/http.rs",
        "if (key_str.starts_with(\"x-bsv-\") || key_str == \"authorization\")",
        2,
    ),
    (
        "src/auth/transports/http.rs",
        "&& !key_str.starts_with(\"x-bsv-auth\")",
        1,
    ),
    (
        "src/auth/transports/http.rs",
        "if msg_type.to_str().ok() == Some(\"certificateRequest\") {",
        1,
    ),
    // The unsigned general answer's body preview (#354): the reference's
    // `#isTextualContent` reads the answer's `Content-Type` header for a
    // `charset=` (`SimplifiedFetchTransport.ts:559`) to choose text or hex
    // for the refusal's preview; a header value, never an error's text, and
    // it decides no class.
    (
        "src/auth/transports/http/unauthenticated.rs",
        "if TEXTUAL.iter().any(|token| lowered.contains(token)) || lowered.contains(\"charset=\") {",
        1,
    ),
    (
        "src/auth/transports/socketio/mod.rs",
        "if data.len() >= 2 && data[0].as_str() == Some(\"authMessage\") {",
        1,
    ),
    (
        "src/transaction/broadcasters/arc.rs",
        "let is_orphan = upper_status.contains(\"ORPHAN\")",
        1,
    ),
    (
        "src/transaction/broadcasters/arc.rs",
        ".is_some_and(|info| info.to_uppercase().contains(\"ORPHAN\"));",
        1,
    ),
];

fn literal_rhs(tokens: &[arch_support::Token<'_>]) -> bool {
    let mut rest = tokens;
    while rest.first().is_some_and(|t| matches!(t.text, "&" | "(")) {
        rest = &rest[1..];
    }
    rest.first().is_some_and(text_literal)
        || (rest.first().is_some_and(|t| t.text == "Some")
            && rest.get(1).is_some_and(|t| t.text == "(")
            && literal_rhs(&rest[2..]))
}

fn text_literal(token: &arch_support::Token<'_>) -> bool {
    token.literal && !token.text.starts_with('\'') && !token.text.starts_with("b'")
}

fn string_conversion(tokens: &[arch_support::Token<'_>]) -> bool {
    tokens.ends_with_text(&[".", "to_string", "(", ")"])
        || tokens.ends_with_text(&[".", "to_owned", "(", ")"])
}

trait TokenSuffix {
    fn ends_with_text(&self, suffix: &[&str]) -> bool;
}

impl TokenSuffix for [arch_support::Token<'_>] {
    fn ends_with_text(&self, suffix: &[&str]) -> bool {
        self.len() >= suffix.len()
            && self[self.len() - suffix.len()..]
                .iter()
                .zip(suffix)
                .all(|(token, text)| token.text == *text)
    }
}

fn comparison(tokens: &[arch_support::Token<'_>], at: usize) -> bool {
    if arch_support::is_call(tokens, at, &["contains", "starts_with"])
        && tokens.get(at + 1).is_some_and(|t| t.text == "(")
    {
        return literal_rhs(&tokens[at + 2..]);
    }
    if tokens[at].text != "==" {
        return false;
    }
    literal_rhs(&tokens[at + 1..])
        || tokens[..at].last().is_some_and(text_literal)
        || string_conversion(&tokens[..at])
        || tokens[at + 1..]
            .windows(4)
            .take(4)
            .any(|window| string_conversion(window))
}

#[test]
fn transport_code_adds_no_text_classification() {
    let mut sites = Vec::new();
    for source in arch_support::sources() {
        if !HOMES.iter().any(|home| source.path.starts_with(home)) {
            continue;
        }
        let tokens = source.tokens();
        for at in 0..tokens.len() {
            if comparison(&tokens, at) {
                sites.push((
                    source.path.clone(),
                    tokens[at].line,
                    source.line(tokens[at].line).to_owned(),
                ));
            }
        }
    }
    arch_support::check_sites("text classification in a transport", &sites, ALLOWED);
    println!(
        "text comparison exceptions: {} sites in 6 files",
        sites.len()
    );
}

#[test]
fn error_text_detection_ignores_formatting_and_operand_order() {
    for text in [
        "error.to_string().contains(\"busy\")",
        "error.to_string() . starts_with ( r#\"busy\"# )",
        "error.to_string() == \"busy\"",
        "\"busy\" == error.to_string()",
        "message == Some(\"busy\")",
        "error.to_string() == expected",
    ] {
        let tokens = arch_support::code_tokens(text, false);
        assert_eq!(
            (0..tokens.len())
                .filter(|at| comparison(&tokens, *at))
                .count(),
            1,
            "missed {text}"
        );
    }
}
