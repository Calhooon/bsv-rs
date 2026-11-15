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
//! header. The crates read are the manifest's `[dependencies]` (a hyphen as
//! an underscore; #843dforeign, the seven of a hand list until then, which
//! left `indexmap` unread) less [`VOCABULARY`], each name of it with its
//! reason. A site names a crate when a token is the crate's name at the root
//! of a path (`num_bigint::BigInt`; `futures_channel`, `futures_util` and
//! `futures_core` count as `futures`, `tokio_tungstenite` as `tokio`), an
//! identifier the file imports from it by a `use` (`use serde_json::Value;`
//! then `Value`, an `as` rename read), or the name of one of this crate's own
//! `pub type` aliases of such a type, learnt over the whole tree by a
//! pre-pass and counted at every site (`RequestedCertificateTypes`, an
//! `IndexMap`, reaches `RequestedCertificateSet.types`). Only a bare `pub` is
//! public here: `pub(crate)`, `pub(super)` and `pub(in ..)` are not read.
//!
//! What it cannot see: a glob import (`use serde_json::*`), a signature a
//! macro builds (a `thiserror` `#[from]` impl among them), a trait method's
//! copy in an impl (its declaration is read), an associated type or
//! constant, a re-export of a foreign item (`pub use reqwest::Client`), a
//! local item that shares an alias's name (read as the alias), an alias
//! that is not a bare `pub` (`pub(crate) type Hidden = IndexMap<..>;` then
//! `pub fn hidden() -> Hidden`: not learnt, so not read, where the public
//! signature is the foreign type all the same), and
//! reachability (a `pub fn` in a private module is read as public, and a
//! public item reached only through a private one is listed all the same).
//! Those were covered once, at `3e1ade84` and at #843d23's tip, by the
//! rustdoc JSON survey of `docs/lanes/fix-843d23.md`, and again for
//! #843dforeign (`docs/lanes/fix-843dforeign.md`); a later change in those
//! forms is a reader's to catch.
//!
//! Every site found is refused unless [`ALLOWED`] names it (file, item,
//! crate, reason; one row per site, a repeated item one row per copy), and a
//! row matching no site fails too: the list only shrinks. The totals per
//! crate are pinned in [`TOTALS`]: `num_bigint`, `futures`, `k256`, `p256`
//! and, since #843dforeign, `tokio` at 0; a crate with no pinned total has
//! none to list.
//!
//! The rule for the list (the captain's ruling of 2026-11-12 on three design
//! reads, #843dforeign): A foreign type may be listed when its crate is at
//! 1.0 or later, the type is data and not behaviour, and either the reference
//! exposes the same thing as an untyped, ordered or signed value or the
//! instance is the caller's own.
//!
//! Held so ([`row_refusal`]): every row's reason opens with one of the four
//! classes of [`CLASSES`] and any other opening fails. The three data classes
//! (`untyped member`, `text as received`, `ordered record`) are the
//! sentence's first three clauses: the guard reads the row's crate's version
//! from the manifest and a row of them for a crate below 1.0 fails by name.
//! `caller's instance` is the sentence's last clause, read as standing alone
//! (the ruling keeps the four `reqwest` rows, and `reqwest` is at 0.12): the
//! instance is built by the caller, and under `http` reqwest's next breaking
//! release is this crate's, which each such row's reason says. Whether a
//! type is data, and what the reference exposes, no machine reads: the class
//! is the row's claim, with the reference's line in its reason.
#![allow(clippy::expect_used, clippy::panic)] // Source reads are test assertions.

mod arch_support;

use arch_support::Token;
use std::collections::BTreeMap;
use std::sync::OnceLock;

/// Root tokens that count as another crate's: a family's sub-crates, two of
/// them no dependency of the manifest (reached through `futures`).
const COUNTS_AS: &[(&str, &str)] = &[
    ("futures_channel", "futures"),
    ("futures_util", "futures"),
    ("futures_core", "futures"),
    ("tokio_tungstenite", "tokio"),
];

/// The dependencies that are not read, each with its reason: the vocabulary
/// a Rust crate speaks to its callers by design. A name here that is no
/// dependency of the manifest fails.
const VOCABULARY: &[(&str, &str)] = &[
    (
        "serde",
        "the `Serialize` and `Deserialize` traits and their `Serializer` and `Deserializer` \
     parameters: the ecosystem's serialization vocabulary, at 1.0 since 2017; a public type \
     that implements them is the point of them",
    ),
    (
        "thiserror",
        "a derive macro alone: no type of it can stand in a signature, and its `Error` derive is \
         imported under the name of this crate's own `Error` (`src/error.rs`), which would read \
         every `Result` as its site",
    ),
];

/// The `[dependencies]` of a manifest's text: (name, a hyphen as an
/// underscore; version requirement), the inline form (`name = "1"`,
/// `name = { version = "1", .. }`) and the table form (`[dependencies.name]`
/// then `version = "1"`).
fn manifest_dependencies(text: &str) -> Vec<(String, String)> {
    fn quoted(value: &str) -> Option<String> {
        let start = value.find('"')? + 1;
        let end = start + value[start..].find('"')?;
        Some(value[start..end].to_string())
    }
    let mut out: Vec<(String, String)> = Vec::new();
    // `Some(None)`: inside `[dependencies]`; `Some(Some(name))`: inside
    // `[dependencies.name]`; `None`: another section
    let mut section: Option<Option<String>> = None;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            let header = line.trim_matches(|c| c == '[' || c == ']').trim();
            section = if header == "dependencies" {
                Some(None)
            } else {
                header
                    .strip_prefix("dependencies.")
                    .map(|name| Some(name.replace('-', "_")))
            };
            if let Some(Some(name)) = &section {
                out.push((name.clone(), String::new()));
            }
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        match &section {
            Some(None) => {
                let version = if value.starts_with('{') {
                    value
                        .find("version")
                        .and_then(|at| quoted(&value[at..]))
                        .unwrap_or_default()
                } else {
                    quoted(value).unwrap_or_default()
                };
                out.push((key.replace('-', "_"), version));
            }
            Some(Some(name)) if key == "version" => {
                if let Some(row) = out.iter_mut().find(|(n, _)| n == name) {
                    row.1 = quoted(value).unwrap_or_default();
                }
            }
            _ => {}
        }
    }
    out
}

/// The leading number of a version requirement (`"0.12"` is 0, `"1.0.125"`
/// and `"2"` are 1 and 2; an operator before it skipped).
fn major(version: &str) -> Option<u64> {
    let digits: String = version
        .trim_start_matches(|c: char| !c.is_ascii_digit())
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

fn manifest() -> &'static [(String, String)] {
    static MANIFEST: OnceLock<Vec<(String, String)>> = OnceLock::new();
    MANIFEST.get_or_init(|| manifest_dependencies(&arch_support::read("Cargo.toml")))
}

/// The crates whose types may not appear in a public signature unlisted:
/// (the token at a path's root, the crate it counts as). Every dependency of
/// the manifest less [`VOCABULARY`], and [`COUNTS_AS`].
fn roots() -> &'static [(&'static str, &'static str)] {
    static ROOTS: OnceLock<Vec<(&'static str, &'static str)>> = OnceLock::new();
    ROOTS.get_or_init(|| roots_of(manifest()))
}

fn roots_of(dependencies: &[(String, String)]) -> Vec<(&'static str, &'static str)> {
    let mut out: Vec<(&'static str, &'static str)> = COUNTS_AS.to_vec();
    for (name, _) in dependencies {
        if VOCABULARY.iter().any(|(v, _)| v == name) || out.iter().any(|(root, _)| root == name) {
            continue;
        }
        // The names live as long as the test binary: one small leak per run
        let name: &'static str = Box::leak(name.clone().into_boxed_str());
        out.push((name, name));
    }
    out
}

/// The pinned count of listed sites per crate. A total that moves is a
/// finding: a new site is a row and a raised total, a removed one a row
/// deleted and a lowered total.
const TOTALS: &[(&str, usize)] = &[
    ("num_bigint", 0),
    ("futures", 0),
    ("k256", 0),
    ("p256", 0),
    ("tokio", 0),
    ("reqwest", 4),
    ("serde_json", 26),
    ("indexmap", 36),
];

/// (file, item, crate, reason): one row per site.
const ALLOWED: &[(&str, &str, &str, &str)] = &[
    (
        "src/auth/certificates/certificate.rs",
        "Certificate.fields",
        "indexmap",
        "ordered record: a certificate's fields or keyring in insertion order, the reference's `Record` (`Certificate.ts:179`, #385, #394), the order its bounds are checked in",
    ),
    (
        "src/auth/certificates/certificate.rs",
        "fn Certificate::with_fields",
        "indexmap",
        "ordered record: a certificate's fields or keyring in insertion order, the reference's `Record` (`Certificate.ts:179`, #385, #394), the order its bounds are checked in",
    ),
    (
        "src/auth/certificates/certificate.rs",
        "fn Certificate::set_fields",
        "indexmap",
        "ordered record: a certificate's fields or keyring in insertion order, the reference's `Record` (`Certificate.ts:179`, #385, #394), the order its bounds are checked in",
    ),
    (
        "src/auth/certificates/master.rs",
        "MasterCertificate.master_keyring",
        "indexmap",
        "ordered record: a certificate's fields or keyring in insertion order, the reference's `Record` (`Certificate.ts:179`, #385, #394), the order its bounds are checked in",
    ),
    (
        "src/auth/certificates/master.rs",
        "fn MasterCertificate::new",
        "indexmap",
        "ordered record: a certificate's fields or keyring in insertion order, the reference's `Record` (`Certificate.ts:179`, #385, #394), the order its bounds are checked in",
    ),
    (
        "src/auth/certificates/master.rs",
        "fn MasterCertificate::create_certificate_fields",
        "indexmap",
        "ordered record: a certificate's fields or keyring in insertion order, the reference's `Record` (`Certificate.ts:179`, #385, #394), the order its bounds are checked in",
    ),
    (
        "src/auth/certificates/master.rs",
        "fn MasterCertificate::create_keyring_for_verifier",
        "indexmap",
        "ordered record: a certificate's fields or keyring in insertion order, the reference's `Record` (`Certificate.ts:179`, #385, #394), the order its bounds are checked in",
    ),
    (
        "src/auth/certificates/master.rs",
        "fn MasterCertificate::issue_for_subject",
        "indexmap",
        "ordered record: a certificate's fields or keyring in insertion order, the reference's `Record` (`Certificate.ts:179`, #385, #394), the order its bounds are checked in",
    ),
    (
        "src/auth/certificates/master.rs",
        "fn MasterCertificate::decrypt_fields",
        "indexmap",
        "ordered record: a certificate's fields or keyring in insertion order, the reference's `Record` (`Certificate.ts:179`, #385, #394), the order its bounds are checked in",
    ),
    (
        "src/auth/certificates/verifiable.rs",
        "VerifiableCertificate.keyring",
        "indexmap",
        "ordered record: a certificate's fields or keyring in insertion order, the reference's `Record` (`Certificate.ts:179`, #385, #394), the order its bounds are checked in",
    ),
    (
        "src/auth/certificates/verifiable.rs",
        "fn VerifiableCertificate::new",
        "indexmap",
        "ordered record: a certificate's fields or keyring in insertion order, the reference's `Record` (`Certificate.ts:179`, #385, #394), the order its bounds are checked in",
    ),
    (
        "src/auth/certificates/verifiable.rs",
        "fn VerifiableCertificate::decrypt_fields",
        "indexmap",
        "ordered record: a certificate's fields or keyring in insertion order, the reference's `Record` (`Certificate.ts:179`, #385, #394), the order its bounds are checked in",
    ),
    (
        "src/auth/certificates/verifiable.rs",
        "fn VerifiableCertificate::get_decrypted_fields",
        "indexmap",
        "ordered record: a certificate's fields or keyring in insertion order, the reference's `Record` (`Certificate.ts:179`, #385, #394), the order its bounds are checked in",
    ),
    (
        "src/auth/clients/auth_fetch.rs",
        "fn AuthFetch::with_client",
        "reqwest",
        "caller's instance: the reference's `fetchClient` hook (`AuthFetch.ts:197`, #423), the caller's own HTTP client; under `http` reqwest's next breaking release is this crate's",
    ),
    (
        "src/auth/clients/auth_fetch.rs",
        "AuthFetchOptions.headers",
        "indexmap",
        "ordered record: the headers in the order given or received, the reference's `Record<string, string>` (`AuthFetch.ts:35`, `:78`)",
    ),
    (
        "src/auth/clients/auth_fetch.rs",
        "fn AuthFetchOptions::with_headers",
        "indexmap",
        "ordered record: the headers in the order given or received, the reference's `Record<string, string>` (`AuthFetch.ts:35`, `:78`)",
    ),
    (
        "src/auth/clients/response.rs",
        "Response.headers",
        "indexmap",
        "ordered record: the headers in the order given or received, the reference's `Record<string, string>` (`AuthFetch.ts:35`, `:78`)",
    ),
    (
        "src/auth/transports/http/client.rs",
        "fn SimplifiedFetchTransport::with_client",
        "reqwest",
        "caller's instance: the reference's `fetchClient` hook (`SimplifiedFetchTransport.ts:66`, #320), the caller's own HTTP client; under `http` reqwest's next breaking release is this crate's",
    ),
    (
        "src/auth/transports/socketio/codec.rs",
        "SocketIoPacket::Connect",
        "serde_json",
        "untyped member: a JSON document of the caller's or the wire's, carried as given (the reference's `unknown`, `LookupResolver.ts:43`)",
    ),
    (
        "src/auth/transports/socketio/codec.rs",
        "SocketIoPacket::Event",
        "serde_json",
        "untyped member: a JSON document of the caller's or the wire's, carried as given (the reference's `unknown`, `LookupResolver.ts:43`)",
    ),
    (
        "src/auth/transports/socketio/codec.rs",
        "SocketIoPacket::Ack",
        "serde_json",
        "untyped member: a JSON document of the caller's or the wire's, carried as given (the reference's `unknown`, `LookupResolver.ts:43`)",
    ),
    (
        "src/auth/transports/socketio/codec.rs",
        "SocketIoPacket::ConnectError",
        "serde_json",
        "untyped member: a JSON document of the caller's or the wire's, carried as given (the reference's `unknown`, `LookupResolver.ts:43`)",
    ),
    (
        "src/auth/transports/socketio/codec.rs",
        "fn decode_event_args_text",
        "serde_json",
        "text as received: the event argument's text as received (#280): a RawValue keeps its bytes",
    ),
    (
        "src/auth/transports/socketio/mod.rs",
        "AppEvent.data",
        "serde_json",
        "untyped member: a JSON document of the caller's or the wire's, carried as given (the reference's `unknown`, `LookupResolver.ts:43`)",
    ),
    (
        "src/auth/transports/socketio/mod.rs",
        "fn parse_app_event_payload",
        "serde_json",
        "untyped member: a JSON document of the caller's or the wire's, carried as given (the reference's `unknown`, `LookupResolver.ts:43`)",
    ),
    (
        "src/auth/transports/socketio/mod.rs",
        "fn build_envelope_payload",
        "serde_json",
        "untyped member: a JSON document of the caller's or the wire's, carried as given (the reference's `unknown`, `LookupResolver.ts:43`)",
    ),
    (
        "src/auth/types.rs",
        "AuthMessage.certificates_text",
        "serde_json",
        "text as received: the signed member's text as received or sent (#280, #426): a RawValue keeps its bytes",
    ),
    (
        "src/auth/types.rs",
        "AuthMessage.requested_certificates_text",
        "serde_json",
        "text as received: the signed member's text as received or sent (#280, #426): a RawValue keeps its bytes",
    ),
    (
        "src/auth/types.rs",
        "type RequestedCertificateTypes",
        "indexmap",
        "ordered record: the requested types in insertion order, the reference's `Record` (`types.ts:21-23`, #288), the order a certificateRequest signs",
    ),
    (
        "src/auth/types.rs",
        "RequestedCertificateSet.types",
        "indexmap",
        "ordered record: the requested types in insertion order, the reference's `Record` (`types.ts:21-23`, #288), the order a certificateRequest signs",
    ),
    (
        "src/identity/client.rs",
        "fn IdentityClient::save_contact",
        "serde_json",
        "untyped member: a JSON document of the caller's or the wire's, carried as given (the reference's `unknown`, `LookupResolver.ts:43`)",
    ),
    (
        "src/identity/client.rs",
        "fn IdentityClient::resolve_by_attributes",
        "indexmap",
        "ordered record: the attributes in insertion order, the reference's `Record` (`IdentityClient.ts:667`, #394), the order the lookup body is written in",
    ),
    (
        "src/identity/types.rs",
        "Contact.metadata",
        "serde_json",
        "untyped member: a JSON document of the caller's or the wire's, carried as given (the reference's `unknown`, `LookupResolver.ts:43`)",
    ),
    (
        "src/identity/types.rs",
        "fn Contact::with_metadata",
        "serde_json",
        "untyped member: a JSON document of the caller's or the wire's, carried as given (the reference's `unknown`, `LookupResolver.ts:43`)",
    ),
    (
        "src/identity/types.rs",
        "IdentityQuery.attributes",
        "indexmap",
        "ordered record: the attributes in insertion order, the reference's `Record` (`IdentityClient.ts:667`, #394), the order the lookup body is written in",
    ),
    (
        "src/identity/types.rs",
        "fn IdentityQuery::by_attributes",
        "indexmap",
        "ordered record: the attributes in insertion order, the reference's `Record` (`IdentityClient.ts:667`, #394), the order the lookup body is written in",
    ),
    (
        "src/identity/types.rs",
        "IdentityCertificate.publicly_revealed_keyring",
        "indexmap",
        "ordered record: a certificate's fields or keyring in insertion order, the reference's `Record` (`Certificate.ts:179`, #385, #394), the order its bounds are checked in",
    ),
    (
        "src/identity/types.rs",
        "IdentityCertificate.decrypted_fields",
        "indexmap",
        "ordered record: a certificate's fields or keyring in insertion order, the reference's `Record` (`Certificate.ts:179`, #385, #394), the order its bounds are checked in",
    ),
    (
        "src/overlay/facilitators.rs",
        "fn OverlayLookupFacilitator::lookup_ordered",
        "serde_json",
        "text as received: the lookup body's text as ordered (#394): a RawValue keeps its bytes",
    ),
    (
        "src/overlay/facilitators.rs",
        "fn OverlayLookupFacilitator::lookup_bounded",
        "serde_json",
        "text as received: the lookup body's text as ordered (#394): a RawValue keeps its bytes",
    ),
    (
        "src/overlay/types.rs",
        "LookupQuestion.query",
        "serde_json",
        "untyped member: a JSON document of the caller's or the wire's, carried as given (the reference's `unknown`, `LookupResolver.ts:43`)",
    ),
    (
        "src/overlay/types.rs",
        "fn LookupQuestion::new",
        "serde_json",
        "untyped member: a JSON document of the caller's or the wire's, carried as given (the reference's `unknown`, `LookupResolver.ts:43`)",
    ),
    (
        "src/overlay/types.rs",
        "LookupAnswer::Freeform",
        "serde_json",
        "untyped member: a JSON document of the caller's or the wire's, carried as given (the reference's `unknown`, `LookupResolver.ts:43`)",
    ),
    (
        "src/storage/uploader.rs",
        "fn StorageUploader::list_uploads",
        "serde_json",
        "untyped member: a JSON document of the caller's or the wire's, carried as given (the reference's `unknown`, `LookupResolver.ts:43`)",
    ),
    (
        "src/storage/uploader.rs",
        "fn StorageUploader::list_uploads",
        "serde_json",
        "untyped member: a JSON document of the caller's or the wire's, carried as given (the reference's `unknown`, `LookupResolver.ts:43`)",
    ),
    (
        "src/transaction/broadcaster.rs",
        "BroadcastFailure.more",
        "serde_json",
        "untyped member: a JSON document of the caller's or the wire's, carried as given (the reference's `unknown`, `LookupResolver.ts:43`)",
    ),
    (
        "src/transaction/broadcaster.rs",
        "fn BroadcastFailure::with_details",
        "serde_json",
        "untyped member: a JSON document of the caller's or the wire's, carried as given (the reference's `unknown`, `LookupResolver.ts:43`)",
    ),
    (
        "src/transaction/transaction.rs",
        "Transaction.metadata",
        "serde_json",
        "untyped member: a JSON document of the caller's or the wire's, carried as given (the reference's `unknown`, `LookupResolver.ts:43`)",
    ),
    (
        "src/transaction/transaction.rs",
        "fn Transaction::update_metadata",
        "serde_json",
        "untyped member: a JSON document of the caller's or the wire's, carried as given (the reference's `unknown`, `LookupResolver.ts:43`)",
    ),
    (
        "src/transaction/transaction/fields.rs",
        "TransactionParts.metadata",
        "serde_json",
        "untyped member: a JSON document of the caller's or the wire's, carried as given (the reference's `unknown`, `LookupResolver.ts:43`)",
    ),
    (
        "src/transaction/transaction/fields.rs",
        "TransactionPartsMut.metadata",
        "serde_json",
        "untyped member: a JSON document of the caller's or the wire's, carried as given (the reference's `unknown`, `LookupResolver.ts:43`)",
    ),
    (
        "src/wallet/substrates/http_json.rs",
        "fn HttpWalletJson::with_client",
        "reqwest",
        "caller's instance: the reference's `httpClient` parameter (`HTTPWalletJSON.ts:278`, #320), the caller's own HTTP client; under `http` reqwest's next breaking release is this crate's",
    ),
    (
        "src/wallet/substrates/http_wire.rs",
        "fn HttpWalletWire::with_client",
        "reqwest",
        "caller's instance: the reference's `httpClient` parameter (`HTTPWalletWire.ts:15`, #320), the caller's own HTTP client; under `http` reqwest's next breaking release is this crate's",
    ),
    (
        "src/wallet/types.rs",
        "Certificate.fields",
        "indexmap",
        "ordered record: a certificate's fields or keyring in insertion order, the reference's `Record` (`Certificate.ts:179`, #385, #394), the order its bounds are checked in",
    ),
    (
        "src/wallet/types.rs",
        "WalletCertificate.fields",
        "indexmap",
        "ordered record: a certificate's fields or keyring in insertion order, the reference's `Record` (`Certificate.ts:179`, #385, #394), the order its bounds are checked in",
    ),
    (
        "src/wallet/types.rs",
        "AcquireCertificateArgs.fields",
        "indexmap",
        "ordered record: a certificate's fields or keyring in insertion order, the reference's `Record` (`Certificate.ts:179`, #385, #394), the order its bounds are checked in",
    ),
    (
        "src/wallet/types.rs",
        "AcquireCertificateArgs.keyring_for_subject",
        "indexmap",
        "ordered record: a certificate's fields or keyring in insertion order, the reference's `Record` (`Certificate.ts:179`, #385, #394), the order its bounds are checked in",
    ),
    (
        "src/wallet/types.rs",
        "CertificateResult.keyring",
        "indexmap",
        "ordered record: a certificate's fields or keyring in insertion order, the reference's `Record` (`Certificate.ts:179`, #385, #394), the order its bounds are checked in",
    ),
    (
        "src/wallet/types.rs",
        "ProveCertificateResult.keyring_for_verifier",
        "indexmap",
        "ordered record: a certificate's fields or keyring in insertion order, the reference's `Record` (`Certificate.ts:179`, #385, #394), the order its bounds are checked in",
    ),
    (
        "src/wallet/types.rs",
        "IdentityCertificate.publicly_revealed_keyring",
        "indexmap",
        "ordered record: a certificate's fields or keyring in insertion order, the reference's `Record` (`Certificate.ts:179`, #385, #394), the order its bounds are checked in",
    ),
    (
        "src/wallet/types.rs",
        "IdentityCertificate.decrypted_fields",
        "indexmap",
        "ordered record: a certificate's fields or keyring in insertion order, the reference's `Record` (`Certificate.ts:179`, #385, #394), the order its bounds are checked in",
    ),
    (
        "src/wallet/types.rs",
        "DiscoverByAttributesArgs.attributes",
        "indexmap",
        "ordered record: the attributes in insertion order, the reference's `Record` (`IdentityClient.ts:667`, #394), the order the lookup body is written in",
    ),
    (
        "src/wallet/validation.rs",
        "fn validate_certificate_fields",
        "indexmap",
        "ordered record: a certificate's fields or keyring in insertion order, the reference's `Record` (`Certificate.ts:179`, #385, #394), the order its bounds are checked in",
    ),
    (
        "src/wallet/wire/encoding.rs",
        "fn WireReader::read_string_map",
        "indexmap",
        "ordered record: a wire string map in the order read or written, the reference's `Record` (`WalletWireTransceiver.ts:1389`, #385)",
    ),
    (
        "src/wallet/wire/encoding.rs",
        "fn WireReader::read_optional_string_map",
        "indexmap",
        "ordered record: a wire string map in the order read or written, the reference's `Record` (`WalletWireTransceiver.ts:1389`, #385)",
    ),
    (
        "src/wallet/wire/encoding.rs",
        "fn WireWriter::write_string_map",
        "indexmap",
        "ordered record: a wire string map in the order read or written, the reference's `Record` (`WalletWireTransceiver.ts:1389`, #385)",
    ),
];

/// The four classes a row's reason opens with: (the class, whether it is one
/// of the rule's data classes, which ask a crate at 1.0 or later).
const CLASSES: &[(&str, bool)] = &[
    ("untyped member", true),
    ("text as received", true),
    ("ordered record", true),
    ("caller's instance", false),
];

/// Why a row may not stand, by the rule for the list: its reason opens with
/// no class, or with a data class for a crate the manifest has below 1.0 (or
/// does not have).
fn row_refusal(
    row: &(&str, &str, &str, &str),
    dependencies: &[(String, String)],
) -> Option<String> {
    let (file, item, krate, reason) = *row;
    let class = CLASSES.iter().find(|(class, _)| {
        reason
            .strip_prefix(class)
            .is_some_and(|rest| rest.starts_with(": "))
    });
    let Some((class, data)) = class else {
        return Some(format!(
            "{file}: the row for `{item}` ({krate}) opens with none of the four classes \
             (`untyped member: `, `text as received: `, `ordered record: `, `caller's instance: `)"
        ));
    };
    if !*data {
        return None;
    }
    let version = dependencies
        .iter()
        .find(|(name, _)| name == krate)
        .map(|(_, version)| version.as_str());
    match version.and_then(major) {
        Some(major) if major >= 1 => None,
        _ => Some(format!(
            "{file}: the row for `{item}` is classed `{class}`, a data class, and `{krate}` is \
             at {} in Cargo.toml: below 1.0, only the caller's own instance may be listed",
            version.map_or("no version".to_string(), |v| format!("`{v}`"))
        )),
    }
}

/// One site: the file, its line, the item's label and the crate it names.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Site {
    file: String,
    line: usize,
    item: String,
    krate: &'static str,
}

fn crate_of_root(token: &str) -> Option<&'static str> {
    roots()
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
    aliases: &Aliases,
) -> Vec<&'static str> {
    let mut out = Vec::new();
    for (k, token) in tokens.iter().enumerate() {
        // This crate's own alias of a read crate's type, wherever it is
        // named (bare or as a path's segment): the alias is that crate
        for krate in aliases.get(token.text).into_iter().flatten() {
            if !out.contains(krate) {
                out.push(*krate);
            }
        }
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

/// This crate's own `pub type` aliases of a read crate's type: the alias's
/// name, the crates its right-hand side names.
type Aliases = BTreeMap<String, Vec<&'static str>>;

/// The pre-pass: every `pub type Name<..> = <rhs>;` of the texts whose
/// right-hand side names a read crate (by a path, an import of its file or
/// an alias already learnt), to a fixed point, so an alias of an alias is
/// learnt too.
fn learn_aliases(texts: &[&str]) -> Aliases {
    let mut aliases = Aliases::new();
    let files: Vec<Vec<Token<'_>>> = texts
        .iter()
        .map(|text| arch_support::code_tokens(text, false))
        .collect();
    loop {
        let before = aliases.clone();
        for tokens in &files {
            let imported = imports(tokens);
            for i in 0..tokens.len() {
                let public =
                    tokens[i].text == "pub" && tokens.get(i + 1).is_some_and(|t| t.text == "type");
                if !public {
                    continue;
                }
                let Some(name) = tokens.get(i + 2).map(|t| t.text) else {
                    continue;
                };
                let semi = (i..tokens.len())
                    .find(|&k| tokens[k].text == ";")
                    .unwrap_or(tokens.len());
                let Some(eq) = (i..semi).find(|&k| tokens[k].text == "=") else {
                    continue;
                };
                let crates = named_crates(&tokens[eq + 1..semi], &imported, &aliases);
                if !crates.is_empty() {
                    let held = aliases.entry(name.to_string()).or_default();
                    for krate in crates {
                        if !held.contains(&krate) {
                            held.push(krate);
                        }
                    }
                }
            }
        }
        if aliases == before {
            return aliases;
        }
    }
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
    aliases: &'f Aliases,
    sites: Vec<Site>,
}

impl Scan<'_> {
    fn record(&mut self, tokens: &[Token<'_>], item: String) {
        let line = tokens.first().map_or(0, |t| t.line);
        for krate in named_crates(tokens, &self.imported, self.aliases) {
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

fn scan(file: &str, text: &str, aliases: &Aliases) -> Vec<Site> {
    let tokens = arch_support::code_tokens(text, false);
    let mut scan = Scan {
        file,
        imported: imports(&tokens),
        aliases,
        sites: Vec::new(),
    };
    scan.walk(&tokens, 0, tokens.len(), None);
    scan.sites
}

fn tree_sites() -> Vec<Site> {
    let sources: Vec<arch_support::Source> = arch_support::sources()
        .into_iter()
        .filter(|source| !is_test_file(&source.path))
        .collect();
    let texts: Vec<&str> = sources.iter().map(|source| source.text.as_str()).collect();
    let aliases = learn_aliases(&texts);
    let mut sites = Vec::new();
    for source in &sources {
        sites.extend(scan(&source.path, &source.text, &aliases));
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
    scan("src/planted.rs", text, &learn_aliases(&[text]))
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

#[test]
fn the_roots_are_the_manifests_dependencies_843dforeign() {
    // The reader, on a text of each form
    let sample = "[package]\nname = \"x\"\nversion = \"9.9.9\"\n\n[dependencies]\n\
                  # a comment = \"7\"\nnum-bigint = \"0.4\"\n\
                  serde_json = { version = \"1.0.125\", features = [\"raw_value\"] }\n\
                  indexmap = { features = [\"serde\"], version = \"2\", optional = true }\n\n\
                  [dev-dependencies]\ntokio = \"1\"\n\n[dependencies.dhat]\nversion = \"0.3\"\n\
                  optional = true\n\n[features]\nversion = [\"x\"]\n";
    let read = manifest_dependencies(sample);
    let expected: Vec<(String, String)> = [
        ("num_bigint", "0.4"),
        ("serde_json", "1.0.125"),
        ("indexmap", "2"),
        ("dhat", "0.3"),
    ]
    .iter()
    .map(|(name, version)| (name.to_string(), version.to_string()))
    .collect();
    assert_eq!(read, expected);
    assert_eq!(major("0.12"), Some(0));
    assert_eq!(major("1.0.125"), Some(1));
    assert_eq!(major("2"), Some(2));
    assert_eq!(major("^1.4"), Some(1));
    assert_eq!(major(""), None);
    // A vocabulary name is not a root; every other dependency is, as itself
    let sample_roots = roots_of(&[
        ("serde".to_string(), "1.0".to_string()),
        ("indexmap".to_string(), "2".to_string()),
        ("futures_util".to_string(), "0.3".to_string()),
    ]);
    assert!(!sample_roots.iter().any(|(root, _)| *root == "serde"));
    assert!(sample_roots.contains(&("indexmap", "indexmap")));
    assert!(sample_roots.contains(&("futures_util", "futures")));

    // The tree's manifest: the seven of the hand list and `indexmap` are
    // read, every dependency is a root or a vocabulary name with its reason,
    // and the vocabulary names nothing the manifest lacks
    for krate in [
        "num_bigint",
        "futures",
        "tokio",
        "reqwest",
        "k256",
        "p256",
        "serde_json",
        "indexmap",
    ] {
        assert_eq!(crate_of_root(krate), Some(krate), "`{krate}` is not read");
        assert!(
            manifest().iter().any(|(name, _)| name == krate),
            "`{krate}` is no dependency of Cargo.toml"
        );
    }
    for (name, version) in manifest() {
        let vocabulary = VOCABULARY.iter().any(|(v, _)| v == name);
        assert!(
            vocabulary != crate_of_root(name).is_some(),
            "`{name}` is neither read nor on the vocabulary list (or both)"
        );
        assert!(major(version).is_some(), "`{name}` has no version read");
    }
    for (name, reason) in VOCABULARY {
        assert!(
            manifest().iter().any(|(dep, _)| dep == name),
            "the vocabulary names `{name}`, no dependency of Cargo.toml; delete it"
        );
        assert!(
            !reason.is_empty(),
            "the vocabulary gives `{name}` no reason"
        );
        assert_eq!(crate_of_root(name), None);
    }
}

#[test]
fn the_scan_refuses_a_planted_tokio_receiver_843dforeign() {
    assert_eq!(
        planted("pub fn planted() -> tokio::sync::broadcast::Receiver<u8> { todo!() }"),
        vec![("fn planted".to_string(), "tokio")]
    );
    // The three doors as they stood until #843dforeign
    assert_eq!(
        planted(
            "use tokio::sync::{broadcast, RwLock};\n\
             impl Peer {\n pub fn session_manager(&self) -> &Arc<RwLock<SessionManager>> { todo!() }\n}\n\
             impl HostReputationTracker {\n \
             pub fn subscribe(&self) -> broadcast::Receiver<RankChangeEvent> { todo!() }\n \
             pub fn on_rank_change(&self, callback: impl Fn(RankChangeEvent)) -> tokio::task::JoinHandle<()> { todo!() }\n}"
        ),
        vec![
            ("fn Peer::session_manager".to_string(), "tokio"),
            ("fn HostReputationTracker::subscribe".to_string(), "tokio"),
            ("fn HostReputationTracker::on_rank_change".to_string(), "tokio"),
        ]
    );
    // This crate's own types over a private lock are no site
    assert!(planted(
        "use tokio::sync::RwLock;\n\
         pub struct Handle { inner: Arc<RwLock<SessionManager>> }\n\
         impl Peer { pub fn session_manager(&self) -> &Handle { todo!() } }"
    )
    .is_empty());
}

#[test]
fn the_scan_reads_indexmap_and_an_alias_of_this_crates_own_843dforeign() {
    assert_eq!(
        planted("pub fn planted() -> indexmap::IndexMap<String, String> { todo!() }"),
        vec![("fn planted".to_string(), "indexmap")]
    );
    // A field typed by a planted alias: the alias's own site, and every site
    // that names it, bare or as a path's last segment; an alias of the alias
    // too; a crate-private alias is not learnt
    assert_eq!(
        planted(
            "use indexmap::IndexMap;\n\
             pub type Planted = IndexMap<String, Vec<String>>;\n\
             pub type Again = Vec<Planted>;\n\
             pub(crate) type Hidden = IndexMap<String, u8>;\n\
             pub struct Set {\n  pub types: Planted,\n  pub certifiers: Vec<String>,\n  hidden: Planted,\n}\n\
             pub fn takes(types: &crate::auth::Planted) {}\n\
             pub fn again() -> Again { todo!() }\n\
             pub fn hidden() -> Hidden { todo!() }"
        ),
        vec![
            ("type Planted".to_string(), "indexmap"),
            ("type Again".to_string(), "indexmap"),
            ("Set.types".to_string(), "indexmap"),
            ("fn takes".to_string(), "indexmap"),
            ("fn again".to_string(), "indexmap"),
        ]
    );
    // An alias declared in one file is read at a site in another
    let aliases = learn_aliases(&[
        "pub type Elsewhere = reqwest::Client;",
        "pub fn other() -> u8 { 0 }",
    ]);
    let sites = scan(
        "src/other.rs",
        "pub fn with(client: Elsewhere) {}",
        &aliases,
    );
    assert_eq!(sites.len(), 1);
    assert_eq!(
        (sites[0].item.as_str(), sites[0].krate),
        ("fn with", "reqwest")
    );

    // The tree: the alias this lane was opened for reaches its field
    let sites = tree_sites();
    for item in [
        "type RequestedCertificateTypes",
        "RequestedCertificateSet.types",
    ] {
        assert!(
            sites.iter().any(|site| site.file == "src/auth/types.rs"
                && site.item == item
                && site.krate == "indexmap"),
            "`{item}` is not read as an `indexmap` site"
        );
    }
    // Every `indexmap` site the scan finds, counted: the pinned figure
    assert_eq!(
        sites.iter().filter(|site| site.krate == "indexmap").count(),
        36
    );
    assert_eq!(sites.iter().filter(|site| site.krate == "tokio").count(), 0);
}

#[test]
fn every_row_opens_with_a_class_its_crate_may_carry_843dforeign() {
    let errors: Vec<String> = ALLOWED
        .iter()
        .filter_map(|row| row_refusal(row, manifest()))
        .collect();
    assert!(errors.is_empty(), "{}", errors.join("\n"));
    // The classes by crate, as the ruling counted them
    let count = |krate: &str, class: &str| {
        ALLOWED
            .iter()
            .filter(|row| row.2 == krate && row.3.starts_with(class))
            .count()
    };
    assert_eq!(count("serde_json", "untyped member: "), 21);
    assert_eq!(count("serde_json", "text as received: "), 5);
    assert_eq!(count("indexmap", "ordered record: "), 36);
    assert_eq!(count("reqwest", "caller's instance: "), 4);
    assert_eq!(ALLOWED.len(), 21 + 5 + 36 + 4);
    // A `caller's instance` row says whose break the crate's next one is
    for row in ALLOWED
        .iter()
        .filter(|row| row.3.starts_with("caller's instance: "))
    {
        assert!(
            row.3.contains("next breaking release is this crate's"),
            "the row for `{}` does not say that the crate's next breaking release is this crate's",
            row.1
        );
    }
}

#[test]
fn a_planted_row_outside_the_rule_is_refused_843dforeign() {
    let dependencies = manifest_dependencies(
        "[dependencies]\nreqwest = { version = \"0.12\", optional = true }\n\
         serde_json = \"1.0.125\"\nindexmap = { version = \"2\" }\n",
    );
    let row =
        |krate: &'static str, reason: &'static str| ("src/planted.rs", "fn planted", krate, reason);

    // A data class for a crate below 1.0: refused naming the crate and its version
    let refused = row_refusal(&row("reqwest", "untyped member: a client"), &dependencies)
        .expect("a data class row for reqwest 0.12 stands");
    assert!(refused.contains("`reqwest`"), "{refused}");
    assert!(refused.contains("`0.12`"), "{refused}");
    assert!(refused.contains("`untyped member`"), "{refused}");
    for class in ["text as received", "ordered record"] {
        let reason: &'static str = Box::leak(format!("{class}: planted").into_boxed_str());
        assert!(row_refusal(&row("reqwest", reason), &dependencies).is_some());
    }
    // The same row as the caller's own instance: accepted, on the last clause alone
    assert_eq!(
        row_refusal(
            &row("reqwest", "caller's instance: a client"),
            &dependencies
        ),
        None
    );
    // The data classes at 1.0 or later: accepted
    assert_eq!(
        row_refusal(
            &row("serde_json", "untyped member: a document"),
            &dependencies
        ),
        None
    );
    assert_eq!(
        row_refusal(&row("indexmap", "ordered record: a record"), &dependencies),
        None
    );
    // A crate the manifest does not have is at no version
    let refused = row_refusal(&row("tokio", "ordered record: planted"), &dependencies)
        .expect("a row for a crate outside the manifest stands");
    assert!(refused.contains("no version"), "{refused}");
    // A reason with no class, the class not at the opening, or the class
    // without its colon: refused
    for reason in [
        "a JSON document of the caller's, carried as given",
        "captain's candidate: untyped member: a document",
        "untyped member, more or less",
        "ordered record:",
        "",
    ] {
        let refused = row_refusal(&row("serde_json", reason), &dependencies)
            .unwrap_or_else(|| panic!("`{reason}` stands"));
        assert!(refused.contains("none of the four classes"), "{refused}");
    }
}
