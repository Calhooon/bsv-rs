//! The table of `text_doors_any_string.rs` follows the source: every public
//! function under `src/` with a `&str` parameter (`Option<&str>` among them)
//! is a row of that file's family property, or is listed here with the reason
//! it cuts no text; and every `.split_at(` of the crate is counted here per
//! file, an offset `clippy::string_slice` does not see (a new one is read for
//! whether it can fall inside a character before its count moves).
//!
//! The byte-offset `str` index sites are counted by the census command
//! `cargo clippy --lib --features full,http,websocket -- -A clippy::all
//! -W clippy::string_slice` (its count and its reading in `tests/CLAUDE.md`).
//!
//! A lexical scan, not name resolution: comments and literals are blanked, a
//! `#[cfg(test)]` module is skipped, a file whose name ends in `tests.rs` is
//! not read, and `pub(crate)` is not `pub`.
#![allow(clippy::expect_used, clippy::panic)] // Source reads are test assertions.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// Why a door that takes text is not a row of the family table.
const SENDS: &str = "sends the text to a wallet, a peer, an overlay or an endpoint whole \
     (a JSON or wire field, a header, a query), no cut here";
const KEYS: &str = "keys a map, a store or a cache with the text, or compares it whole";
const DERIVES: &str = "reads the text as bytes into a derivation, an HMAC, a signature \
     or an encryption, no cut";
const URLS: &str = "keeps the text as a URL for later requests, no cut";
const WRITES: &str = "writes the text whole, as bytes, into a field, no cut";
const NAMES: &str = "names a field in an error message, no cut";
const UNREACHED: &str = "a `pub` function of a `pub(crate)` module, no door of the crate";

/// The doors of `src/` that take text and are not rows of the family table:
/// a file, its doors (a name twice for two doors of that name), the reason.
const CUTS_NO_TEXT: &[(&str, &str, &str)] = &[
    ("auth/certificates/certificate.rs", "get_field", KEYS),
    ("auth/certificates/certificate.rs", "get_field_encryption_key_id_verifiable", DERIVES),
    (
        "auth/certificates/master.rs",
        "create_certificate_fields create_keyring_for_verifier issue_for_subject decrypt_field decrypt_fields",
        DERIVES,
    ),
    ("auth/certificates/verifiable.rs", "decrypt_field decrypt_fields", DERIVES),
    ("auth/clients/auth_fetch.rs", "with_transport_factory fetch", SENDS),
    (
        "auth/clients/labels.rs",
        "payment_labels",
        "cuts the text at a `find` of an ASCII `=`: an edge by construction",
    ),
    ("auth/clients/response.rs", "header from_authenticated_payload", KEYS),
    ("auth/clients/state.rs", "send_certificate_request", SENDS),
    (
        "auth/peer.rs",
        "to_peer get_authenticated_session request_certificates send_certificate_response",
        SENDS,
    ),
    (
        "auth/session_manager.rs",
        "get_session get_session_mut remove_by_nonce has_session get_sessions_for_identity",
        KEYS,
    ),
    ("auth/session_nonces.rs", "claim_message_nonce claim_initial_request_nonce", KEYS),
    ("auth/transports/http.rs", "new", URLS),
    ("auth/transports/http/client.rs", "with_client", URLS),
    ("auth/transports/socketio/mod.rs", "build_envelope_payload", SENDS),
    (
        "auth/types.rs",
        "get_key_id is_certifier_trusted is_type_requested get_fields_for_type",
        KEYS,
    ),
    ("auth/utils/nonce.rs", "create_nonce verify_nonce", DERIVES),
    ("auth/utils/validation.rs", "validate_certificates validate_certificate", KEYS),
    ("auth/utils/verifiable.rs", "get_verifiable_certificates", SENDS),
    ("compat/bip32.rs", "generate_hd_key_from_mnemonic", DERIVES),
    ("compat/bip39/mnemonic.rs", "to_seed", DERIVES),
    (
        "identity/client.rs",
        "revoke_certificate_revelation resolve_by_identity_key discover_certificates discover_certificates_by_type get_contact remove_contact",
        "sends the text to an overlay or a wallet whole; its one cut is of a certificate subject's hex, ASCII",
    ),
    ("identity/contacts.rs", "get_contact update_contact", KEYS),
    ("identity/contacts_actions.rs", "remove_contact", KEYS),
    ("identity/contacts_cache.rs", "search_contacts get_contacts_by_tag", KEYS),
    (
        "kvstore/global.rs",
        "get set remove get_by_controller batch_get batch_set batch_remove get_by_tags",
        SENDS,
    ),
    ("kvstore/interpreter.rs", "verify_signature", DERIVES),
    ("kvstore/local.rs", "get get_entry set remove has batch_get batch_set batch_remove", SENDS),
    ("overlay/host_reputation_tracker.rs", "record_success record_failure snapshot", KEYS),
    ("overlay/lookup_resolver/discovery.rs", "find_competent_hosts", SENDS),
    (
        "overlay/overlay_admin_token_template.rs",
        "create_signed_overlay_admin_token",
        DERIVES,
    ),
    ("primitives/ec/private_key.rs", "derive_child", DERIVES),
    ("primitives/ec/public_key.rs", "derive_child", DERIVES),
    (
        "registry/types.rs",
        "to_pushdrop_fields to_pushdrop_fields to_pushdrop_fields to_pushdrop_fields",
        WRITES,
    ),
    ("script/templates/pushdrop_wallet.rs", "lock_with_wallet", SENDS),
    ("script/templates/pushdrop_wallet_unlock.rs", "unlock_with_wallet", SENDS),
    ("storage/downloader.rs", "resolve download download", URLS),
    ("storage/uploader.rs", "find_file find_file renew_file renew_file", URLS),
    (
        "transaction/beef.rs",
        "find_transaction_for_signing make_txid_only",
        KEYS,
    ),
    (
        "transaction/beef/link.rs",
        "find_atomic_transaction find_atomic_transaction_limited find_atomic_transaction_with_budget from_beef_with_budget",
        KEYS,
    ),
    ("transaction/beef/index.rs", "find_txid_mut edit_tx", KEYS),
    ("transaction/beef_atomic.rs", "to_binary_atomic", KEYS),
    ("transaction/broadcasters/arc.rs", "new", URLS),
    ("transaction/broadcasters/teranode.rs", "new", URLS),
    ("transaction/broadcasters/whatsonchain.rs", "with_base_url", URLS),
    ("transaction/chain_trackers/block_headers_service.rs", "with_url", URLS),
    ("transaction/chain_trackers/whatsonchain.rs", "with_base_url", URLS),
    ("transaction/fee_models/live_policy.rs", "with_url", URLS),
    ("transaction/merkle_path.rs", "contains_and_mark", KEYS),
    ("transaction/merkle_path_verify.rs", "verify", KEYS),
    ("transaction/transaction.rs", "from_beef from_beef_subject from_beef_with_limits add_input_from update_metadata", KEYS),
    (
        "wallet/key_deriver.rs",
        "derive_public_key derive_private_key derive_private_key_raw derive_symmetric_key reveal_specific_secret",
        DERIVES,
    ),
    (
        "wallet/substrates/http_json.rs",
        "get_public_key encrypt decrypt create_hmac verify_hmac create_signature verify_signature is_authenticated get_height get_network get_version create_action sign_action abort_action list_actions internalize_action list_outputs relinquish_output acquire_certificate list_certificates prove_certificate relinquish_certificate discover_by_identity_key discover_by_attributes get_header wait_for_authentication reveal_counterparty_key_linkage reveal_specific_key_linkage",
        SENDS,
    ),
    ("wallet/substrates/result_values/beef.rs", "subject", KEYS),
    ("wallet/types.rs", "validate_satoshis", NAMES),
    (
        "wallet/validation.rs",
        "validate_satoshis validate_integer validate_integer_u32 validate_positive_integer_or_zero",
        NAMES,
    ),
    ("wallet/validation/crypto.rs", "validate_result_public_key", UNREACHED),
    ("wallet/wire/discovery.rs", "discover_by_identity_key discover_by_attributes", SENDS),
    ("wallet/wire/encoding.rs", "write_signed_var_int", NAMES),
    (
        "wallet/wire/linkage.rs",
        "reveal_counterparty_key_linkage reveal_specific_key_linkage",
        SENDS,
    ),
    (
        "wallet/wire/transceiver.rs",
        "get_public_key encrypt decrypt create_hmac verify_hmac create_signature verify_signature is_authenticated get_height get_network get_version create_action sign_action abort_action list_actions internalize_action list_outputs relinquish_output acquire_certificate list_certificates prove_certificate relinquish_certificate get_header wait_for_authentication",
        SENDS,
    ),
];

/// `.split_at(` per file of `src/`, each read: an offset from `find` or a
/// count of ASCII bytes (an edge by construction), or a cut of bytes or of
/// a `Vec`.
const SPLIT_AT: &[(&str, usize)] = &[
    // at a `find`: an edge
    ("auth/transports/socketio/packet_rules.rs", 1),
    // an HMAC's bytes
    ("compat/bip32.rs", 2),
    // a wordlist's bytes, at an LF
    ("compat/bip39/wordlists/mod.rs", 2),
    // bytes, at `valid_up_to`
    ("identity/client_record_lenient.rs", 1),
    // a `Vec` of fields
    ("kvstore/token_validation.rs", 1),
    // at a `find`: an edge
    ("overlay/admin_token_validation.rs", 1),
    // a ciphertext's bytes
    ("primitives/symmetric.rs", 1),
    // a `Vec` of fields
    ("registry/token.rs", 1),
    // a reader's bytes
    ("transaction/beef_stream.rs", 1),
    // at a `find` of an ASCII byte: an edge
    ("util/debug_redact.rs", 3),
    // a compiled table's bytes
    ("wallet/collation.rs", 4),
    // six ASCII bytes checked first
    ("wallet/substrates/result_values/timestamp.rs", 1),
];

/// A crate file's text, `\r\n` read as `\n`, comments and the insides of
/// literals blanked to spaces (lines kept).
fn code(text: &str) -> String {
    let text = text.replace("\r\n", "\n");
    let b = text.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    let blank = |out: &mut Vec<u8>, c: u8| out.push(if c == b'\n' { b'\n' } else { b' ' });
    while i < b.len() {
        if b[i..].starts_with(b"//") {
            while i < b.len() && b[i] != b'\n' {
                out.push(b' ');
                i += 1;
            }
        } else if b[i..].starts_with(b"/*") {
            let mut depth = 0;
            while i < b.len() {
                if b[i..].starts_with(b"/*") {
                    depth += 1;
                    out.extend_from_slice(b"  ");
                    i += 2;
                } else if b[i..].starts_with(b"*/") {
                    depth -= 1;
                    out.extend_from_slice(b"  ");
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    blank(&mut out, b[i]);
                    i += 1;
                }
            }
        } else if b[i] == b'r'
            && (b.get(i + 1) == Some(&b'"') || b.get(i + 1) == Some(&b'#'))
            && (i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_'))
        {
            let hashes = b[i + 1..].iter().take_while(|c| **c == b'#').count();
            if b.get(i + 1 + hashes) != Some(&b'"') {
                out.push(b[i]);
                i += 1;
                continue;
            }
            let mut close = vec![b'"'];
            close.extend(std::iter::repeat_n(b'#', hashes));
            out.extend_from_slice(&b[i..i + 2 + hashes]);
            i += 2 + hashes;
            while i < b.len() && !b[i..].starts_with(&close) {
                blank(&mut out, b[i]);
                i += 1;
            }
            out.extend_from_slice(&close);
            i += close.len();
        } else if b[i] == b'"' {
            out.push(b'"');
            i += 1;
            while i < b.len() && b[i] != b'"' {
                let step = if b[i] == b'\\' { 2 } else { 1 };
                for _ in 0..step.min(b.len() - i) {
                    blank(&mut out, b[i]);
                    i += 1;
                }
            }
            out.push(b'"');
            i += 1;
        } else if b[i] == b'\'' && (b.get(i + 2) == Some(&b'\'') || b.get(i + 1) == Some(&b'\\')) {
            // a char literal ('x', '\n', '\u{..}'); a lifetime has no closing quote
            out.push(b'\'');
            i += 1;
            while i < b.len() && b[i] != b'\'' {
                let step = if b[i] == b'\\' { 2 } else { 1 };
                for _ in 0..step.min(b.len() - i) {
                    blank(&mut out, b[i]);
                    i += 1;
                }
            }
            out.push(b'\'');
            i += 1;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `text` with every `#[cfg(test)]` item blanked (its braces balanced).
fn without_test_items(text: &str) -> String {
    let mut out = text.to_string();
    let mut from = 0;
    while let Some(at) = out[from..].find("#[cfg(test)]").map(|i| i + from) {
        let Some(open) = out[at..].find(['{', ';']).map(|i| i + at) else {
            break;
        };
        let mut end = open + 1;
        if out.as_bytes()[open] == b'{' {
            let mut depth = 0;
            for (i, c) in out[open..].char_indices() {
                match c {
                    '{' => depth += 1,
                    '}' => depth -= 1,
                    _ => {}
                }
                if depth == 0 {
                    end = open + i + 1;
                    break;
                }
            }
        }
        let blanked: String = out[at..end]
            .chars()
            .map(|c| if c == '\n' { '\n' } else { ' ' })
            .collect();
        out.replace_range(at..end, &blanked);
        from = end;
    }
    out
}

/// Every crate file under `src/` (its path under `src/`, its code).
fn crate_files() -> Vec<(String, String)> {
    fn visit(root: &Path, dir: &Path, out: &mut Vec<(String, String)>) {
        for entry in fs::read_dir(dir).expect("read src") {
            let path = entry.expect("an entry of src").path();
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            if path.is_dir() {
                visit(root, &path, out);
            } else if name.ends_with(".rs") && !name.ends_with("tests.rs") {
                let rel = path.strip_prefix(root).expect("inside src");
                let rel = rel.to_string_lossy().replace('\\', "/");
                let text =
                    fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
                out.push((rel, without_test_items(&code(&text))));
            }
        }
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut out = Vec::new();
    visit(&root, &root, &mut out);
    out.sort();
    out
}

/// The names of the `pub fn`s of `code` whose parameters take a `&str`.
fn text_doors(code: &str) -> Vec<String> {
    let words: Vec<(usize, &str)> = code
        .match_indices(|c: char| !(c.is_alphanumeric() || c == '_'))
        .scan(0, |start, (at, _)| {
            let word = (*start, &code[*start..at]);
            *start = at + 1;
            Some(word)
        })
        .filter(|(_, w)| !w.is_empty())
        .collect();
    let mut doors = Vec::new();
    for (k, &(at, word)) in words.iter().enumerate() {
        if word != "pub" || code[at + 3..].trim_start().starts_with('(') {
            continue;
        }
        let mut j = k + 1;
        while words
            .get(j)
            .is_some_and(|(_, w)| matches!(*w, "const" | "async" | "unsafe" | "extern" | "C"))
        {
            j += 1;
        }
        let (Some((_, "fn")), Some(&(name_at, name))) = (words.get(j), words.get(j + 1)) else {
            continue;
        };
        // the parameters: from the first `(` after the name to its match
        let rest = &code[name_at + name.len()..];
        let mut angle = 0i32;
        let Some(open) = rest.char_indices().find_map(|(i, c)| {
            match c {
                '<' => angle += 1,
                '>' => angle -= 1,
                '(' if angle == 0 => return Some(i),
                _ => {}
            }
            None
        }) else {
            continue;
        };
        let mut depth = 0;
        let params = rest[open..]
            .char_indices()
            .find_map(|(i, c)| {
                match c {
                    '(' => depth += 1,
                    ')' => depth -= 1,
                    _ => {}
                }
                (depth == 0).then(|| &rest[open..open + i + 1])
            })
            .unwrap_or("");
        let compact: String = params.split_whitespace().collect();
        let takes_text = compact
            .match_indices("str")
            .any(|(i, _)| takes_str_at(&compact, i));
        if takes_text {
            doors.push(name.to_string());
        }
    }
    doors
}

/// `compact[i..]` starts the type `str` behind a `&` (a lifetime between).
fn takes_str_at(compact: &str, i: usize) -> bool {
    let after = compact[i + 3..].chars().next();
    if after.is_some_and(|c| c.is_alphanumeric() || c == '_') {
        return false;
    }
    let before = &compact[..i];
    let before = match before.rfind('\'') {
        Some(q)
            if before[q + 1..]
                .chars()
                .all(|c| c.is_alphanumeric() || c == '_') =>
        {
            &before[..q]
        }
        _ => before,
    };
    before.ends_with('&') || before.ends_with("&mut")
}

/// The labels of the family table (`door!("<file> <name>", ..)`).
fn table() -> Vec<(String, String)> {
    let text = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/text_doors_any_string.rs"),
    )
    .expect("read the family table");
    text.split("door!(")
        .skip(1)
        .filter_map(|row| {
            let label = row.trim_start().strip_prefix('"')?;
            let label = &label[..label.find('"')?];
            let (file, name) = label.split_once(' ')?;
            Some((file.to_string(), name.to_string()))
        })
        .collect()
}

#[test]
fn every_public_door_that_takes_text_is_a_row_of_the_family_table_or_cuts_no_text() {
    let mut found: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (file, code) in crate_files() {
        let doors = text_doors(&code);
        if !doors.is_empty() {
            found.insert(file, doors);
        }
    }
    let mut listed: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (file, name) in table() {
        listed.entry(file).or_default().push(name);
    }
    for (file, names, reason) in CUTS_NO_TEXT {
        assert!(!reason.is_empty(), "{file}: a reason");
        let entry = listed.entry(file.to_string()).or_default();
        entry.extend(names.split_whitespace().map(str::to_string));
    }
    let mut missing = Vec::new();
    for (file, doors) in &found {
        let mut left = listed.get(file).cloned().unwrap_or_default();
        for door in doors {
            match left.iter().position(|n| n == door) {
                Some(at) => {
                    left.remove(at);
                }
                None => missing.push(format!("{file} {door}")),
            }
        }
    }
    let mut stale = Vec::new();
    for (file, names, _) in CUTS_NO_TEXT {
        let doors = found.get(*file).cloned().unwrap_or_default();
        for name in names.split_whitespace() {
            let want = names.split_whitespace().filter(|n| *n == name).count();
            if doors.iter().filter(|d| *d == name).count() < want {
                stale.push(format!("{file} {name}"));
            }
        }
    }
    stale.dedup();
    assert!(
        missing.is_empty(),
        "a public door that takes text is neither a row of the family table \
         (tests/text_doors_any_string.rs) nor listed with its reason here: {missing:#?}"
    );
    assert!(
        stale.is_empty(),
        "listed here, not found in src/: {stale:#?}"
    );
}

#[test]
fn every_split_at_of_the_crate_is_counted_and_read() {
    let mut found: BTreeMap<String, usize> = BTreeMap::new();
    for (file, code) in crate_files() {
        let count = code.matches(".split_at(").count();
        if count > 0 {
            found.insert(file, count);
        }
    }
    let listed: BTreeMap<String, usize> = SPLIT_AT
        .iter()
        .map(|(file, count)| (file.to_string(), *count))
        .collect();
    assert_eq!(
        found, listed,
        "a `.split_at(` moved: read whether its offset can fall inside a character, then its count"
    );
}

/// The scan itself, on text written for it.
#[test]
fn the_scan_finds_a_door_that_takes_text_and_no_other() {
    let doors = text_doors(&without_test_items(&code(concat!(
        "pub fn a(s: &str) {}\n",
        "pub fn b<'a>(s: &'a str) -> &'a str { s }\n",
        "pub async fn c(o: Option<&str>) {}\n",
        "pub(crate) fn d(s: &str) {}\n",
        "fn e(s: &str) {}\n",
        "pub fn f(s: String, t: &[u8]) -> &str { \"pub fn g(s: &str)\" }\n",
        "// pub fn h(s: &str) {}\n",
        "pub fn i(&self, x: &mut str) {}\n",
        "pub fn j(s: &strings::S) {}\n",
        "#[cfg(test)]\nmod tests { pub fn k(s: &str) {} }\n",
        "pub const fn l(s: &'static str) {}\n",
        "pub fn m(c: char) -> bool { c == '\"' || c == '{' }\n",
        "pub fn n(s: &str) {}\n",
    ))));
    assert_eq!(doors, ["a", "b", "c", "i", "l", "n"]);
}
