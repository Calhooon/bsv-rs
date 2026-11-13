//! No public signature names a foreign type (#843d23, #843's freeze plan,
//! rows 2 and 3; rule 11 of the root `CLAUDE.md`): a type of another crate
//! in this crate's public surface makes that crate's major release this
//! crate's break (rule 9). The compiler cannot hold this on stable
//! (`exported_private_dependencies` is unstable), so this is a lexical law.
//!
//! What it reads, over every file under `src/` but test modules (a file
//! named `tests.rs` or `*_tests.rs`, and every `#[cfg(test)]` item, which
//! `arch_support` drops with comments and literals): each `pub fn` signature
//! (from `fn` to its body's `{` or its `;`, the inherent impl's type named in
//! the label), each `pub` field of a struct (braced or tuple), each
//! `pub type` alias, each variant's fields of a `pub enum`, each method
//! signature a `pub trait` declares, and each `impl <Trait><..> for <Type>`
//! header. A site names one of the seven crates
//! of [`CRATES`] when a token is the crate's name at the root of a path
//! (`num_bigint::BigInt`; `futures_channel` and `futures_util` count as
//! `futures`, `tokio_tungstenite` as `tokio`) or an identifier the file
//! imports from it by a `use` (`use serde_json::Value;` then `Value`, an
//! `as` rename read). Only a bare `pub` is public here: `pub(crate)`,
//! `pub(super)` and `pub(in ..)` are not read.
//!
//! What it cannot see: a glob import (`use serde_json::*`), a signature a
//! macro builds (a `thiserror` `#[from]` impl among them), a trait method's
//! copy in an impl (its declaration is read), an associated type or
//! constant, a re-export of a foreign item (`pub use reqwest::Client`), and
//! reachability (a `pub fn` in a private module is read as public, and a
//! public item reached only through a private one is listed all the same).
//! Those were covered once, at `3e1ade84` and at this lane's tip, by the
//! rustdoc JSON survey of `docs/lanes/fix-843d23.md` (every public item whose
//! signature, field, variant, alias or trait impl names a path of the seven
//! crates); a later change in those forms is a reader's to catch.
//!
//! Every site found is refused unless [`ALLOWED`] names it (file, item,
//! crate, reason; one row per site, a repeated item one row per copy), and a
//! row matching no site fails too: the list only shrinks. The totals per
//! crate are pinned in [`TOTALS`]: `num_bigint`, `futures`, `k256` and
//! `p256` at 0.
#![allow(clippy::expect_used, clippy::panic)] // Source reads are test assertions.

mod arch_support;

use arch_support::Token;
use std::collections::BTreeMap;

/// The crates whose types may not appear in a public signature unlisted:
/// (the token at a path's root, the crate it counts as).
const CRATES: &[(&str, &str)] = &[
    ("num_bigint", "num_bigint"),
    ("futures", "futures"),
    ("futures_channel", "futures"),
    ("futures_util", "futures"),
    ("futures_core", "futures"),
    ("tokio", "tokio"),
    ("tokio_tungstenite", "tokio"),
    ("reqwest", "reqwest"),
    ("k256", "k256"),
    ("p256", "p256"),
    ("serde_json", "serde_json"),
];

/// The pinned count of listed sites per crate. A total that moves is a
/// finding: a new site is a row and a raised total, a removed one a row
/// deleted and a lowered total.
const TOTALS: &[(&str, usize)] = &[
    ("num_bigint", 0),
    ("futures", 0),
    ("k256", 0),
    ("p256", 0),
    ("tokio", 3),
    ("reqwest", 4),
    ("serde_json", 28),
];

/// (file, item, crate, reason): one row per site.
const ALLOWED: &[(&str, &str, &str, &str)] = &[
    (
        "src/auth/certificates/verifiable.rs",
        "fn VerifiableCertificate::to_json_value",
        "serde_json",
        "a JSON document of the caller's or the wire's, carried as given (the reference's untyped member); captain's candidate",
    ),
    (
        "src/auth/peer.rs",
        "fn Peer::session_manager",
        "tokio",
        "captain's candidate (#843d23's REPORT): a tokio type in a public return, the class of the futures receiver",
    ),
    (
        "src/auth/transports/fetch_client.rs",
        "type NativeFetchClient",
        "reqwest",
        "#423's native fallback client: the alias names the caller's reqwest client, the transport boundary (captain's candidate)",
    ),
    (
        "src/auth/transports/http/client.rs",
        "fn SimplifiedFetchTransport::with_client",
        "reqwest",
        "the reference's `fetchClient` hook (#320): the caller's own HTTP client, by design",
    ),
    (
        "src/auth/transports/socketio/codec.rs",
        "SocketIoPacket::Connect",
        "serde_json",
        "a JSON document of the caller's or the wire's, carried as given (the reference's untyped member); captain's candidate",
    ),
    (
        "src/auth/transports/socketio/codec.rs",
        "SocketIoPacket::Event",
        "serde_json",
        "a JSON document of the caller's or the wire's, carried as given (the reference's untyped member); captain's candidate",
    ),
    (
        "src/auth/transports/socketio/codec.rs",
        "SocketIoPacket::Ack",
        "serde_json",
        "a JSON document of the caller's or the wire's, carried as given (the reference's untyped member); captain's candidate",
    ),
    (
        "src/auth/transports/socketio/codec.rs",
        "SocketIoPacket::ConnectError",
        "serde_json",
        "a JSON document of the caller's or the wire's, carried as given (the reference's untyped member); captain's candidate",
    ),
    (
        "src/auth/transports/socketio/codec.rs",
        "fn decode_event_args_text",
        "serde_json",
        "the event argument's text as received (#280): a RawValue keeps its bytes",
    ),
    (
        "src/auth/transports/socketio/mod.rs",
        "AppEvent.data",
        "serde_json",
        "a JSON document of the caller's or the wire's, carried as given (the reference's untyped member); captain's candidate",
    ),
    (
        "src/auth/transports/socketio/mod.rs",
        "fn parse_app_event_payload",
        "serde_json",
        "a JSON document of the caller's or the wire's, carried as given (the reference's untyped member); captain's candidate",
    ),
    (
        "src/auth/transports/socketio/mod.rs",
        "fn build_envelope_payload",
        "serde_json",
        "a JSON document of the caller's or the wire's, carried as given (the reference's untyped member); captain's candidate",
    ),
    (
        "src/auth/types.rs",
        "AuthMessage.certificates_text",
        "serde_json",
        "the signed member's text as received or sent (#280, #426): a RawValue keeps its bytes",
    ),
    (
        "src/auth/types.rs",
        "AuthMessage.requested_certificates_text",
        "serde_json",
        "the signed member's text as received or sent (#280, #426): a RawValue keeps its bytes",
    ),
    (
        "src/identity/client.rs",
        "fn IdentityClient::save_contact",
        "serde_json",
        "a JSON document of the caller's or the wire's, carried as given (the reference's untyped member); captain's candidate",
    ),
    (
        "src/identity/types.rs",
        "Contact.metadata",
        "serde_json",
        "a JSON document of the caller's or the wire's, carried as given (the reference's untyped member); captain's candidate",
    ),
    (
        "src/identity/types.rs",
        "fn Contact::with_metadata",
        "serde_json",
        "a JSON document of the caller's or the wire's, carried as given (the reference's untyped member); captain's candidate",
    ),
    (
        "src/kvstore/types.rs",
        "fn KVStoreQuery::to_json",
        "serde_json",
        "a JSON document of the caller's or the wire's, carried as given (the reference's untyped member); captain's candidate",
    ),
    (
        "src/overlay/facilitators.rs",
        "fn OverlayLookupFacilitator::lookup_ordered",
        "serde_json",
        "the lookup body's text as ordered (#394): a RawValue keeps its bytes",
    ),
    (
        "src/overlay/facilitators.rs",
        "fn OverlayLookupFacilitator::lookup_bounded",
        "serde_json",
        "the lookup body's text as ordered (#394): a RawValue keeps its bytes",
    ),
    (
        "src/overlay/host_reputation_tracker.rs",
        "fn HostReputationTracker::subscribe",
        "tokio",
        "captain's candidate (#843d23's REPORT): a tokio type in a public return, the class of the futures receiver",
    ),
    (
        "src/overlay/host_reputation_tracker.rs",
        "fn HostReputationTracker::on_rank_change",
        "tokio",
        "captain's candidate (#843d23's REPORT): a tokio type in a public return, the class of the futures receiver",
    ),
    (
        "src/overlay/types.rs",
        "LookupQuestion.query",
        "serde_json",
        "a JSON document of the caller's or the wire's, carried as given (the reference's untyped member); captain's candidate",
    ),
    (
        "src/overlay/types.rs",
        "fn LookupQuestion::new",
        "serde_json",
        "a JSON document of the caller's or the wire's, carried as given (the reference's untyped member); captain's candidate",
    ),
    (
        "src/overlay/types.rs",
        "LookupAnswer::Freeform",
        "serde_json",
        "a JSON document of the caller's or the wire's, carried as given (the reference's untyped member); captain's candidate",
    ),
    (
        "src/storage/uploader.rs",
        "fn StorageUploader::list_uploads",
        "serde_json",
        "a JSON document of the caller's or the wire's, carried as given (the reference's untyped member); captain's candidate",
    ),
    (
        "src/storage/uploader.rs",
        "fn StorageUploader::list_uploads",
        "serde_json",
        "a JSON document of the caller's or the wire's, carried as given (the reference's untyped member); captain's candidate",
    ),
    (
        "src/transaction/broadcaster.rs",
        "BroadcastFailure.more",
        "serde_json",
        "a JSON document of the caller's or the wire's, carried as given (the reference's untyped member); captain's candidate",
    ),
    (
        "src/transaction/broadcaster.rs",
        "fn BroadcastFailure::with_details",
        "serde_json",
        "a JSON document of the caller's or the wire's, carried as given (the reference's untyped member); captain's candidate",
    ),
    (
        "src/transaction/transaction.rs",
        "Transaction.metadata",
        "serde_json",
        "a JSON document of the caller's or the wire's, carried as given (the reference's untyped member); captain's candidate",
    ),
    (
        "src/transaction/transaction.rs",
        "fn Transaction::update_metadata",
        "serde_json",
        "a JSON document of the caller's or the wire's, carried as given (the reference's untyped member); captain's candidate",
    ),
    (
        "src/transaction/transaction/fields.rs",
        "TransactionParts.metadata",
        "serde_json",
        "a JSON document of the caller's or the wire's, carried as given (the reference's untyped member); captain's candidate",
    ),
    (
        "src/transaction/transaction/fields.rs",
        "TransactionPartsMut.metadata",
        "serde_json",
        "a JSON document of the caller's or the wire's, carried as given (the reference's untyped member); captain's candidate",
    ),
    (
        "src/wallet/substrates/http_json.rs",
        "fn HttpWalletJson::with_client",
        "reqwest",
        "the reference's `fetchClient` hook (#320): the caller's own HTTP client, by design",
    ),
    (
        "src/wallet/substrates/http_wire.rs",
        "fn HttpWalletWire::with_client",
        "reqwest",
        "the reference's `fetchClient` hook (#320): the caller's own HTTP client, by design",
    ),
];

/// One site: the file, its line, the item's label and the crate it names.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Site {
    file: String,
    line: usize,
    item: String,
    krate: &'static str,
}

fn crate_of_root(token: &str) -> Option<&'static str> {
    CRATES
        .iter()
        .find(|(root, _)| *root == token)
        .map(|(_, krate)| *krate)
}

fn is_ident(token: &str) -> bool {
    token
        .chars()
        .next()
        .is_some_and(|c| c.is_alphanumeric() || c == '_')
}

/// The end of a balanced group opened at `start` (`(`, `[`, `{`), or of the
/// token stream when it is unbalanced.
fn group_end(tokens: &[Token<'_>], start: usize) -> usize {
    let mut depth = 0usize;
    let mut i = start;
    while i < tokens.len() {
        match tokens[i].text {
            "(" | "[" | "{" => depth += 1,
            ")" | "]" | "}" => {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    tokens.len()
}

/// The first `{` or `;` at the depth of `start` (parentheses and brackets
/// skipped), or the end.
fn to_brace_or_semi(tokens: &[Token<'_>], mut i: usize, end: usize) -> usize {
    while i < end {
        match tokens[i].text {
            "{" | ";" => return i,
            "(" | "[" => i = group_end(tokens, i),
            _ => i += 1,
        }
    }
    end
}

/// Every identifier a `use` of a foreign crate brings into the file, with
/// the crate (a group and an `as` rename read; a glob, unseen).
fn imports(tokens: &[Token<'_>]) -> BTreeMap<String, &'static str> {
    let mut out = BTreeMap::new();
    let mut i = 0;
    while i < tokens.len() {
        if tokens[i].text == "use" {
            let mut j = i + 1;
            if tokens.get(j).is_some_and(|t| t.text == "::") {
                j += 1;
            }
            let end = (j..tokens.len())
                .find(|&k| tokens[k].text == ";")
                .unwrap_or(tokens.len());
            if let Some(krate) = tokens.get(j).and_then(|t| crate_of_root(t.text)) {
                use_tree(&tokens[j..end], krate, &mut out);
            }
            i = end;
        }
        i += 1;
    }
    out
}

/// The leaves of one use tree: an identifier followed by `,`, `}` or the
/// end is a leaf; `as name` renames it; `self` names its parent segment.
fn use_tree(tokens: &[Token<'_>], krate: &'static str, out: &mut BTreeMap<String, &'static str>) {
    for (k, token) in tokens.iter().enumerate() {
        if !is_ident(token.text) || token.text == "as" {
            continue;
        }
        let next = tokens.get(k + 1).map(|t| t.text);
        let leaf = matches!(next, None | Some(",") | Some("}"));
        if !leaf {
            continue;
        }
        let name = if token.text == "self" {
            // `foo::{self, ..}`: the segment before the `::{`
            let mut back = k;
            while back > 0 && tokens[back].text != "{" {
                back -= 1;
            }
            match back.checked_sub(2).map(|b| tokens[b].text) {
                Some(segment) if is_ident(segment) => segment,
                _ => continue,
            }
        } else {
            token.text
        };
        out.insert(name.to_string(), krate);
    }
}

/// The crates a slice of tokens names: a crate's name at the root of a path,
/// or an identifier imported from it (not itself a later path segment).
fn named_crates(
    tokens: &[Token<'_>],
    imported: &BTreeMap<String, &'static str>,
) -> Vec<&'static str> {
    let mut out = Vec::new();
    for (k, token) in tokens.iter().enumerate() {
        let after_path = k > 0 && tokens[k - 1].text == "::";
        let rooted_after_path = after_path && (k < 2 || !is_ident(tokens[k - 2].text));
        if after_path && !rooted_after_path {
            continue;
        }
        let next_is_path = tokens.get(k + 1).is_some_and(|t| t.text == "::");
        let krate = if next_is_path {
            crate_of_root(token.text).or_else(|| imported.get(token.text).copied())
        } else {
            imported.get(token.text).copied()
        };
        if let Some(krate) = krate {
            if !out.contains(&krate) {
                out.push(krate);
            }
        }
    }
    out
}

/// Joins tokens as a label: a space between two words, none elsewhere.
fn label(tokens: &[Token<'_>]) -> String {
    let mut out = String::new();
    for (k, token) in tokens.iter().enumerate() {
        let words = k > 0 && is_ident(tokens[k - 1].text) && is_ident(token.text);
        let around_for = k > 0 && (token.text == "for" || tokens[k - 1].text == "for");
        if words || around_for {
            out.push(' ');
        }
        out.push_str(token.text);
    }
    out
}

/// Splits a group's inside at its top-level commas.
fn split_commas<'t, 'a>(tokens: &'t [Token<'a>]) -> Vec<&'t [Token<'a>]> {
    let mut parts = Vec::new();
    let (mut i, mut from, mut angle) = (0, 0, 0i32);
    while i < tokens.len() {
        match tokens[i].text {
            "(" | "[" | "{" => {
                i = group_end(tokens, i);
                continue;
            }
            "<" => angle += 1,
            ">" if !(i > 0 && tokens[i - 1].text == "-") => angle -= 1,
            "," if angle == 0 => {
                parts.push(&tokens[from..i]);
                from = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    if from < tokens.len() {
        parts.push(&tokens[from..]);
    }
    parts
}

struct Scan<'f> {
    file: &'f str,
    imported: BTreeMap<String, &'static str>,
    sites: Vec<Site>,
}

impl Scan<'_> {
    fn record(&mut self, tokens: &[Token<'_>], item: String) {
        let line = tokens.first().map_or(0, |t| t.line);
        for krate in named_crates(tokens, &self.imported) {
            self.sites.push(Site {
                file: self.file.to_string(),
                line,
                item: item.clone(),
                krate,
            });
        }
    }

    /// Walks the items of `tokens[start..end]`; `owner` names the inherent
    /// impl's type for a method's label.
    fn walk(&mut self, tokens: &[Token<'_>], start: usize, end: usize, owner: Option<&str>) {
        let mut i = start;
        while i < end {
            let text = tokens[i].text;
            if text == "impl" {
                let brace = to_brace_or_semi(tokens, i + 1, end);
                let header = &tokens[i..brace];
                let body_end = if brace < end && tokens[brace].text == "{" {
                    group_end(tokens, brace)
                } else {
                    brace + 1
                };
                if let Some(for_at) = top_level_for(header) {
                    let _ = for_at;
                    let label = label(header);
                    self.record(header, label);
                } else if brace < end && tokens[brace].text == "{" {
                    let ty = self_type(&header[1..]);
                    self.walk(tokens, brace + 1, body_end - 1, ty.as_deref());
                }
                i = body_end;
                continue;
            }
            if text == "mod" && tokens.get(i + 2).is_some_and(|t| t.text == "{") {
                let body_end = group_end(tokens, i + 2);
                self.walk(tokens, i + 3, body_end - 1, None);
                i = body_end;
                continue;
            }
            if text == "pub" && tokens.get(i + 1).is_some_and(|t| t.text != "(") {
                i = self.public_item(tokens, i + 1, end, owner);
                continue;
            }
            if text == "{" {
                i = group_end(tokens, i);
                continue;
            }
            i += 1;
        }
    }

    /// One `pub` item at `i` (after the `pub`); the index after it.
    fn public_item(
        &mut self,
        tokens: &[Token<'_>],
        mut i: usize,
        end: usize,
        owner: Option<&str>,
    ) -> usize {
        while i < end
            && matches!(
                tokens[i].text,
                "const" | "async" | "unsafe" | "extern" | "default"
            )
        {
            // `pub const NAME: T = ..;` is a constant, not a qualifier
            if tokens[i].text == "const" && tokens.get(i + 1).is_some_and(|t| t.text != "fn") {
                break;
            }
            i += 1;
        }
        let Some(keyword) = tokens.get(i).map(|t| t.text) else {
            return end;
        };
        let name = tokens.get(i + 1).map_or("", |t| t.text);
        match keyword {
            "fn" => {
                let brace = to_brace_or_semi(tokens, i, end);
                let item = match owner {
                    Some(ty) => format!("fn {ty}::{name}"),
                    None => format!("fn {name}"),
                };
                self.record(&tokens[i..brace], item);
                if brace < end && tokens[brace].text == "{" {
                    group_end(tokens, brace)
                } else {
                    brace + 1
                }
            }
            "struct" => {
                let open = to_brace_or_semi(tokens, i, end);
                // A tuple struct's `(..)` comes before its `;`
                let paren = (i..open).find(|&k| tokens[k].text == "(");
                if let Some(paren) = paren {
                    let close = group_end(tokens, paren);
                    for (n, field) in split_commas(&tokens[paren + 1..close - 1])
                        .into_iter()
                        .enumerate()
                    {
                        if field.first().is_some_and(|t| t.text == "pub")
                            && field.get(1).is_some_and(|t| t.text != "(")
                        {
                            self.record(&field[1..], format!("{name}.{n}"));
                        }
                    }
                }
                if open < end && tokens[open].text == "{" {
                    let close = group_end(tokens, open);
                    for field in split_commas(&tokens[open + 1..close - 1]) {
                        if field.first().is_some_and(|t| t.text == "pub")
                            && field.get(1).is_some_and(|t| t.text != "(")
                        {
                            let field_name = field.get(1).map_or("", |t| t.text);
                            self.record(&field[2..], format!("{name}.{field_name}"));
                        }
                    }
                    close
                } else {
                    open + 1
                }
            }
            "enum" => {
                let open = to_brace_or_semi(tokens, i, end);
                if open < end && tokens[open].text == "{" {
                    let close = group_end(tokens, open);
                    for variant in split_commas(&tokens[open + 1..close - 1]) {
                        let Some(variant_name) = variant.first().map(|t| t.text) else {
                            continue;
                        };
                        if variant.len() > 1 {
                            self.record(&variant[1..], format!("{name}::{variant_name}"));
                        }
                    }
                    close
                } else {
                    open + 1
                }
            }
            "type" => {
                let semi = (i..end).find(|&k| tokens[k].text == ";").unwrap_or(end);
                self.record(&tokens[i + 2..semi], format!("type {name}"));
                semi + 1
            }
            "trait" => {
                // Each method's signature as the trait declares it (an
                // impl's copy of it is not read: it cannot differ)
                let open = to_brace_or_semi(tokens, i, end);
                if open >= end || tokens[open].text != "{" {
                    return open + 1;
                }
                let close = group_end(tokens, open);
                let mut k = open + 1;
                while k < close - 1 {
                    match tokens[k].text {
                        "fn" => {
                            let stop = to_brace_or_semi(tokens, k, close - 1);
                            let method = tokens.get(k + 1).map_or("", |t| t.text);
                            self.record(&tokens[k..stop], format!("fn {name}::{method}"));
                            k = if stop < close - 1 && tokens[stop].text == "{" {
                                group_end(tokens, stop)
                            } else {
                                stop + 1
                            };
                        }
                        "{" => k = group_end(tokens, k),
                        _ => k += 1,
                    }
                }
                close
            }
            "mod" if tokens.get(i + 2).is_some_and(|t| t.text == "{") => {
                let close = group_end(tokens, i + 2);
                self.walk(tokens, i + 3, close - 1, None);
                close
            }
            // A re-export, a constant, a static, a macro:
            // not read (the header states it)
            _ => {
                let stop = to_brace_or_semi(tokens, i, end);
                if stop < end && tokens[stop].text == "{" {
                    group_end(tokens, stop)
                } else {
                    stop + 1
                }
            }
        }
    }
}

/// The index of an impl header's `for` at its top level (a trait impl), not
/// a `for<'a>` bound.
fn top_level_for(header: &[Token<'_>]) -> Option<usize> {
    let mut angle = 0i32;
    for (k, token) in header.iter().enumerate() {
        match token.text {
            "<" => angle += 1,
            ">" if !(k > 0 && header[k - 1].text == "-") => angle -= 1,
            "for" if angle == 0 && header.get(k + 1).is_none_or(|t| t.text != "<") => {
                return Some(k)
            }
            _ => {}
        }
    }
    None
}

/// An inherent impl's type: the first identifier after its generics.
fn self_type(header: &[Token<'_>]) -> Option<String> {
    let mut k = 0;
    if header.first().is_some_and(|t| t.text == "<") {
        let mut angle = 0i32;
        while k < header.len() {
            match header[k].text {
                "<" => angle += 1,
                ">" => {
                    angle -= 1;
                    if angle == 0 {
                        k += 1;
                        break;
                    }
                }
                _ => {}
            }
            k += 1;
        }
    }
    header[k..]
        .iter()
        .find(|t| is_ident(t.text) && t.text != "crate" && t.text != "dyn")
        .map(|t| t.text.to_string())
}

fn is_test_file(path: &str) -> bool {
    path.ends_with("/tests.rs") || path.ends_with("_tests.rs")
}

fn scan(file: &str, text: &str) -> Vec<Site> {
    let tokens = arch_support::code_tokens(text, false);
    let mut scan = Scan {
        file,
        imported: imports(&tokens),
        sites: Vec::new(),
    };
    scan.walk(&tokens, 0, tokens.len(), None);
    scan.sites
}

fn tree_sites() -> Vec<Site> {
    let mut sites = Vec::new();
    for source in arch_support::sources() {
        if is_test_file(&source.path) {
            continue;
        }
        sites.extend(scan(&source.path, &source.text));
    }
    sites.sort();
    sites
}

/// The refusals: each site no row names, each row no site matches.
fn refusals(sites: &[Site]) -> Vec<String> {
    let mut used = vec![false; ALLOWED.len()];
    let mut errors = Vec::new();
    for site in sites {
        let row = ALLOWED
            .iter()
            .enumerate()
            .position(|(n, (f, item, krate, _))| {
                !used[n] && *f == site.file && *item == site.item && *krate == site.krate
            });
        match row {
            Some(n) => used[n] = true,
            None => errors.push(format!(
                "{}:{}: `{}` names a type of `{}` in a public signature (#843d23)",
                site.file, site.line, site.item, site.krate
            )),
        }
    }
    for ((file, item, krate, _), used) in ALLOWED.iter().zip(&used) {
        if !used {
            errors.push(format!(
                "{file}: listed exception `{item}` ({krate}) matches no site; delete the row"
            ));
        }
    }
    errors
}

#[test]
fn no_public_signature_names_a_foreign_type_843d23() {
    let errors: Vec<String> = refusals(&tree_sites())
        .into_iter()
        .filter(|e| !e.contains("matches no site"))
        .collect();
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

#[test]
fn every_listed_exception_still_exists_843d23() {
    let errors: Vec<String> = refusals(&tree_sites())
        .into_iter()
        .filter(|e| e.contains("matches no site"))
        .collect();
    assert!(errors.is_empty(), "{}", errors.join("\n"));
    for (krate, total) in TOTALS {
        let listed = ALLOWED.iter().filter(|row| row.2 == *krate).count();
        assert_eq!(
            listed, *total,
            "the pinned total for `{krate}` is {total}, the list holds {listed}"
        );
    }
    for row in ALLOWED {
        assert!(
            TOTALS.iter().any(|(krate, _)| *krate == row.2),
            "a row names `{}`, which has no pinned total",
            row.2
        );
        assert!(!row.3.is_empty(), "the row for `{}` gives no reason", row.1);
    }
}

fn planted(text: &str) -> Vec<(String, &'static str)> {
    scan("src/planted.rs", text)
        .into_iter()
        .map(|site| (site.item, site.krate))
        .collect()
}

#[test]
fn the_scan_refuses_a_planted_bigint_return_843d23() {
    assert_eq!(
        planted("pub fn planted() -> num_bigint::BigInt { todo!() }"),
        vec![("fn planted".to_string(), "num_bigint")]
    );
    // A method, labelled by its type; a crate-private one not read
    assert_eq!(
        planted(
            "impl BigNumber {\n pub fn as_bigint(&self) -> &num_bigint::BigInt { &self.inner }\n \
             pub(crate) fn hidden(&self) -> &num_bigint::BigInt { &self.inner }\n}"
        ),
        vec![("fn BigNumber::as_bigint".to_string(), "num_bigint")]
    );
    // A test module is not read
    assert!(
        planted("#[cfg(test)]\nmod tests { pub fn t() -> num_bigint::BigInt { todo!() } }")
            .is_empty()
    );
}

#[test]
fn the_scan_refuses_an_imported_identifier_843d23() {
    assert_eq!(
        planted(
            "use futures::channel::mpsc::{self, UnboundedReceiver as Rx};\n\
             pub async fn listen() -> (Rx<u8>, u32) { todo!() }\n\
             pub fn other(r: mpsc::Receiver<u8>) {}"
        ),
        vec![
            ("fn listen".to_string(), "futures"),
            ("fn other".to_string(), "futures"),
        ]
    );
    // A trait's declared method; its default body and an impl's copy not read
    assert_eq!(
        planted(
            "use serde_json::value::RawValue;\n\
             pub trait Facilitator {\n  async fn lookup(&self) -> Box<RawValue>;\n  \
             fn plain(&self) -> u8 { let _v: serde_json::Value = todo!(); 0 }\n}\n\
             impl Facilitator for Https { async fn lookup(&self) -> Box<RawValue> { todo!() } }"
        ),
        vec![("fn Facilitator::lookup".to_string(), "serde_json")]
    );
    // A local type of the same name as a path segment is not the import
    assert!(planted(
        "use serde_json::Value;\npub fn f(v: crate::json::Value2) -> crate::Value3 { todo!() }"
    )
    .is_empty());
}

#[test]
fn the_scan_refuses_a_planted_field_843d23() {
    assert_eq!(
        planted(
            "use serde_json::Value;\n\
             pub struct Event {\n  #[serde(default)]\n  pub data: Value,\n  inner: tokio::sync::Mutex<u8>,\n  pub(crate) hidden: Value,\n}\n\
             pub struct Tuple(pub reqwest::Client, k256::Scalar);\n\
             pub enum Shape { A(p256::PublicKey), B { x: num_bigint::BigInt }, C }\n\
             pub type Alias = futures_channel::mpsc::Receiver<u8>;"
        ),
        vec![
            ("Event.data".to_string(), "serde_json"),
            ("Tuple.0".to_string(), "reqwest"),
            ("Shape::A".to_string(), "p256"),
            ("Shape::B".to_string(), "num_bigint"),
            ("type Alias".to_string(), "futures"),
        ]
    );
}

#[test]
fn the_scan_refuses_a_planted_impl_843d23() {
    assert_eq!(
        planted(
            "use num_bigint::BigInt;\n\
             impl From<BigInt> for BigNumber { fn from(b: BigInt) -> Self { todo!() } }\n\
             impl From<BigNumber> for num_bigint::BigInt { fn from(b: BigNumber) -> Self { todo!() } }\n\
             impl BigNumber { fn private(&self) -> BigInt { todo!() } }"
        ),
        vec![
            ("impl From<BigInt> for BigNumber".to_string(), "num_bigint"),
            (
                "impl From<BigNumber> for num_bigint::BigInt".to_string(),
                "num_bigint"
            ),
        ]
    );
}
