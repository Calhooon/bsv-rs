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
    // #432: the result decoder's ECMAScript array-index key order.
    (
        "src/wallet/substrates/result_values.rs",
        ".filter(|n| *n != u32::MAX && n.to_string() == key);",
        1,
    ),
    // #432: method dispatch, schema-field names, filter modes and canonical
    // JSON index spellings. These predicates never inspect error messages.
    (
        "src/wallet/substrates/result_values/actions.rs",
        "if call == \"createAction\" {",
        1,
    ),
    (
        "src/wallet/substrates/result_values/actions.rs",
        "if call == \"signAction\" {",
        1,
    ),
    (
        "src/wallet/substrates/result_values/actions.rs",
        "if call == \"signAction\" && result.contains_key(\"noSendChange\") {",
        1,
    ),
    (
        "src/wallet/substrates/result_values/boundary.rs",
        "if call == \"createAction\" {",
        1,
    ),
    (
        "src/wallet/substrates/result_values/raw_tree.rs",
        "key == &i.to_string() && matches!(value, Member::Scalar(text) if is_byte(text))",
        1,
    ),
    (
        "src/wallet/substrates/result_values/certificates.rs",
        "if call == \"listCertificates\" {",
        1,
    ),
    (
        "src/wallet/substrates/result_values/certificates.rs",
        "if key == \"certifier\" {",
        1,
    ),
    (
        "src/wallet/substrates/result_values/certificates.rs",
        "if call == \"discoverByIdentityKey\"",
        1,
    ),
    (
        "src/wallet/substrates/result_values/certificates.rs",
        "if call == \"discoverByAttributes\" {",
        1,
    ),
    (
        "src/wallet/substrates/result_values/identity.rs",
        "Some(actual) if key == \"userName\" => *actual == normalized,",
        1,
    ),
    (
        "src/wallet/substrates/result_values/lists.rs",
        "if !outputs.is_empty() && request[\"include\"] == \"entire transactions\" && beef.is_none() {",
        1,
    ),
    (
        "src/wallet/substrates/result_values/lists.rs",
        "if request[\"include\"] == \"locking scripts\" && locking.is_none() {",
        1,
    ),
    (
        "src/wallet/substrates/result_values/lists.rs",
        "let matches = if request[mode] == \"all\" {",
        1,
    ),
    (
        "src/wallet/substrates/result_values/scalars.rs",
        "if call == \"revealCounterpartyKeyLinkage\" {",
        1,
    ),
    (
        "src/wallet/substrates/result_values/scalars.rs",
        "(_, Some(\"self\" | \"anyone\")) if call == \"revealSpecificKeyLinkage\" => None,",
        1,
    ),
    (
        "src/wallet/substrates/result_values/scalars.rs",
        "if call == \"revealSpecificKeyLinkage\" {",
        1,
    ),
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
        "src/auth/transports/http/general.rs",
        "if (lower.starts_with(\"x-bsv-\") || lower == \"authorization\" || lower == \"content-type\")",
        3,
    ),
    (
        "src/auth/transports/http/general.rs",
        "&& !lower.starts_with(\"x-bsv-auth\")",
        1,
    ),
    (
        "src/auth/transports/http/response_bounds.rs",
        "(name.starts_with(\"x-bsv-\") || *name == \"authorization\")",
        2,
    ),
    (
        "src/auth/transports/http/response_bounds.rs",
        "&& !name.starts_with(\"x-bsv-auth\")",
        1,
    ),
    // #416: the response's protocol message-type header, not an error text.
    // SimplifiedFetchTransport.ts:343-346 preserves this exact type.
    (
        "src/auth/transports/http/general.rs",
        "== Some(\"certificateRequest\")",
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
    println!("text comparison exceptions: {} sites", sites.len());
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

/// #347: an allowlist entry that matches no site is refused with the entry in
/// its message, and so is a ceiling above the sites it matches; a matched one
/// passes.
#[test]
fn an_unused_allowlist_entry_reads_red_naming_the_entry() {
    let sites = [
        ("src/a.rs".to_owned(), 3, "if x == \"a\" {".to_owned()),
        ("src/b.rs".to_owned(), 9, "if y == \"b\" {".to_owned()),
    ];
    let allowed = [
        ("src/a.rs", "if x == \"a\" {", 1),
        ("src/b.rs", "if y == \"b\" {", 2),
        ("src/gone.rs", "if z == \"gone\" {", 1),
    ];
    assert_eq!(
        arch_support::site_errors("rule", &sites, &allowed),
        [
            "src/b.rs: allowlist entry `if y == \"b\" {` allows 2 rule sites and matches 1; lower its ceiling to 1",
            "src/gone.rs: allowlist entry `if z == \"gone\" {` matches no rule site; delete the entry",
        ]
    );
    assert!(arch_support::site_errors("rule", &sites, &allowed[..1])
        .iter()
        .all(|e| e.starts_with("src/b.rs:9: rule")));
}
