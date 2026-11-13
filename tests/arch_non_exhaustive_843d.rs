//! Every all-public struct under `src/` is attributed or listed (#843d8a,
//! the freeze plan's row 8, part a; the captain's rulings of 2026-11-12).
//!
//! A record of options grows, so a struct a caller builds with a literal is
//! a break waiting for its next field. The rule, read lexically over every
//! `pub struct` under `src/` whose fields are all `pub` (braced or tuple, a
//! generic one included, and the structs a `key_args!` invocation declares,
//! whose macro adds three `pub` fields to the ones written): it carries
//! `#[non_exhaustive]` or is a row of [`ROWS`], `file:Name` with a class and
//! a reason. A row naming no such struct, or an attributed one, fails; the
//! `Pending` and `Unruled` classes take no new row (their lengths are pinned
//! and only lowered). Each `pub` field of an attributed struct has a
//! `with_<field>` method in an inherent `impl` of its name, or is a
//! parameter of its `new`, else the struct is a row of [`ASSIGNED`] with its
//! reason.
//!
//! The scan is lexical (`arch_support`): comments and string literals supply
//! nothing, `#[cfg(test)]` items and files named `tests.rs` or `*_tests.rs`
//! are not read. What it refuses rather than passes: a `pub struct` inside
//! a macro invocation other than `key_args!` (a `macro_rules!` body's
//! `$name` is no declaration). A struct is attributed by `#[non_exhaustive]`
//! alone; any other spelling naming it (a `cfg_attr`, an attribute list) is
//! read as no attribute here and refused by
//! `tests/arch_non_exhaustive_pins_819.rs`, which holds every attributed
//! type's pin (its doc blocks, its `assert_no_drop!`, its name in the doc
//! suite's log): one machine for the pins, this one for the table (#843d8a's
//! fold). What it cannot see: a
//! struct a macro builds without the `struct` keyword in the source, a setter
//! defined by a macro or a trait, a `new` in another impl of a same-named
//! type in another module (setters are matched by the type's name alone).
#![allow(clippy::expect_used, clippy::panic)] // Source reads are test assertions.

mod arch_support;

use arch_support::Token;
use std::collections::{BTreeMap, BTreeSet};

/// A struct the scan found.
#[derive(Debug, Clone)]
struct Found {
    path: String,
    line: usize,
    name: String,
    /// `{` or `(`.
    body: &'static str,
    generic: bool,
    /// Declared inside a `key_args!` invocation.
    key_args: bool,
    attributed: bool,
    deprecated: bool,
    /// `(field, visibility)`; tuple fields are named by position.
    fields: Vec<(String, Option<String>)>,
}

impl Found {
    fn row(&self) -> String {
        format!("{}:{}", self.path, self.name)
    }
    fn all_public(&self) -> bool {
        !self.fields.is_empty() && self.fields.iter().all(|(_, v)| v.as_deref() == Some("pub"))
    }
}

/// The index after the balanced group opening at `start`.
fn after(tokens: &[Token<'_>], start: usize) -> usize {
    let (open, close) = match tokens[start].text {
        "(" => ("(", ")"),
        "[" => ("[", "]"),
        "{" => ("{", "}"),
        "<" => ("<", ">"),
        other => panic!("no group at `{other}` line {}", tokens[start].line),
    };
    let mut depth = 0i32;
    let mut i = start;
    while i < tokens.len() {
        let t = tokens[i].text;
        if open == "<" && t == "-" && tokens.get(i + 1).is_some_and(|n| n.text == ">") {
            i += 2;
            continue;
        }
        if t == open {
            depth += 1;
        } else if t == close {
            depth -= 1;
            if depth == 0 {
                return i + 1;
            }
        }
        i += 1;
    }
    panic!("unbalanced at line {}", tokens[start].line);
}

/// The attribute groups ending just before `at`, each as its inner tokens'
/// texts joined by a space, nearest last.
fn attributes_before(tokens: &[Token<'_>], at: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut end = at;
    while end > 0 && tokens[end - 1].text == "]" {
        let mut depth = 0i32;
        let mut i = end - 1;
        loop {
            match tokens[i].text {
                "]" => depth += 1,
                "[" => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
            assert!(
                i > 0,
                "unbalanced attribute before line {}",
                tokens[at].line
            );
            i -= 1;
        }
        if i == 0 || tokens[i - 1].text != "#" {
            break;
        }
        let inner: Vec<&str> = tokens[i + 1..end - 1].iter().map(|t| t.text).collect();
        out.push(inner.join(" "));
        end = i - 1;
    }
    out.reverse();
    out
}

/// The attribute's verdict: `#[non_exhaustive]` alone attributes a struct;
/// any other spelling is `tests/arch_non_exhaustive_pins_819.rs`'s to refuse.
fn non_exhaustive(attribute: &str) -> bool {
    attribute == "non_exhaustive"
}

/// The fields of the body opening at `open` (`{` or `(`); in a `key_args!`
/// invocation a field is `pub name: Type = default,`.
fn fields(tokens: &[Token<'_>], open: usize) -> Vec<(String, Option<String>)> {
    let tuple = tokens[open].text == "(";
    let close = after(tokens, open) - 1;
    let mut out = Vec::new();
    let mut at = open + 1;
    while at < close {
        while tokens[at].text == "#" && tokens.get(at + 1).is_some_and(|t| t.text == "[") {
            at = after(tokens, at + 1);
        }
        if at >= close {
            break;
        }
        let mut vis = None;
        if tokens[at].text == "pub" {
            at += 1;
            if tokens[at].text == "(" {
                let end = after(tokens, at);
                let inner: Vec<&str> = tokens[at + 1..end - 1].iter().map(|t| t.text).collect();
                vis = Some(format!("pub({})", inner.join(" ")));
                at = end;
            } else {
                vis = Some("pub".to_string());
            }
        }
        let name = if tuple {
            out.len().to_string()
        } else {
            let name = tokens[at].text.to_string();
            assert!(
                tokens.get(at + 1).is_some_and(|t| t.text == ":"),
                "a field `name:` expected at line {}",
                tokens[at].line
            );
            at += 2;
            name
        };
        while at < close && tokens[at].text != "," {
            at = match tokens[at].text {
                "(" | "[" | "{" | "<" => after(tokens, at),
                _ => at + 1,
            };
        }
        at += 1;
        out.push((name, vis));
    }
    out
}

/// One file's `pub struct`s, and its refusals (`path:line: reason`).
fn scan(path: &str, tokens: &[Token<'_>]) -> (Vec<Found>, Vec<String>) {
    let mut found = Vec::new();
    let mut refused = Vec::new();
    // Macro invocation bodies: (start, end, name).
    let mut macros: Vec<(usize, usize, String)> = Vec::new();
    for i in 0..tokens.len().saturating_sub(2) {
        let t = tokens[i].text;
        if t.starts_with(|c: char| c.is_alphabetic() || c == '_')
            && !tokens[i].literal
            && tokens[i + 1].text == "!"
            && matches!(tokens[i + 2].text, "(" | "[" | "{")
        {
            macros.push((i + 2, after(tokens, i + 2), t.to_string()));
        }
    }
    for at in 0..tokens.len() {
        if tokens[at].text != "struct" || tokens[at].literal {
            continue;
        }
        if at == 0 || tokens[at - 1].text != "pub" {
            continue;
        }
        let pub_at = at - 1;
        let line = tokens[at].line;
        let inside = macros
            .iter()
            .find(|(s, e, _)| *s < at && at < *e)
            .map(|(_, _, n)| n.clone());
        let Some(name) = tokens
            .get(at + 1)
            .filter(|t| t.text.starts_with(|c: char| c.is_alphabetic() || c == '_'))
        else {
            continue; // `struct $name` in a macro_rules! body
        };
        match inside.as_deref() {
            None | Some("key_args") => {}
            Some("macro_rules") => continue,
            Some(other) => {
                refused.push(format!(
                    "{path}:{line}: `pub struct {}` inside `{other}!`, which this scan cannot read",
                    name.text
                ));
                continue;
            }
        }
        let mut i = at + 2;
        let generic = tokens.get(i).is_some_and(|t| t.text == "<");
        if generic {
            i = after(tokens, i);
        }
        while i < tokens.len() && !matches!(tokens[i].text, "{" | "(" | ";") {
            i += 1;
        }
        if tokens.get(i).is_none_or(|t| t.text == ";") {
            continue;
        }
        let body = if tokens[i].text == "{" { "{" } else { "(" };
        let mut attributed = false;
        let mut deprecated = false;
        for attribute in attributes_before(tokens, pub_at) {
            if non_exhaustive(&attribute) {
                attributed = true;
            }
            if attribute.starts_with("deprecated") {
                deprecated = true;
            }
        }
        let mut fs = fields(tokens, i);
        let key_args = inside.as_deref() == Some("key_args");
        if key_args {
            for added in ["privileged", "privileged_reason", "seek_permission"] {
                fs.push((added.to_string(), Some("pub".to_string())));
            }
        }
        found.push(Found {
            path: path.to_string(),
            line,
            name: name.text.to_string(),
            body,
            generic,
            key_args,
            attributed,
            deprecated,
            fields: fs,
        });
    }
    (found, refused)
}

/// The inherent impls' methods of one file: type name to `(fn names, new's
/// parameter names)`.
fn methods(tokens: &[Token<'_>]) -> BTreeMap<String, (BTreeSet<String>, BTreeSet<String>)> {
    let mut out: BTreeMap<String, (BTreeSet<String>, BTreeSet<String>)> = BTreeMap::new();
    let mut at = 0;
    while at < tokens.len() {
        if tokens[at].text != "impl" || tokens[at].literal {
            at += 1;
            continue;
        }
        let mut i = at + 1;
        if tokens.get(i).is_some_and(|t| t.text == "<") {
            i = after(tokens, i);
        }
        let mut last_ident = None;
        let mut trait_impl = false;
        while i < tokens.len() && tokens[i].text != "{" && tokens[i].text != ";" {
            match tokens[i].text {
                "<" => {
                    i = after(tokens, i);
                    continue;
                }
                "for" => trait_impl = true,
                "where" => {
                    while i < tokens.len() && tokens[i].text != "{" {
                        i = match tokens[i].text {
                            "<" | "(" => after(tokens, i),
                            _ => i + 1,
                        };
                    }
                    break;
                }
                t if t.starts_with(|c: char| c.is_alphabetic() || c == '_') => {
                    last_ident = Some(t.to_string())
                }
                _ => {}
            }
            i += 1;
        }
        if tokens.get(i).is_none_or(|t| t.text != "{") {
            at = i;
            continue;
        }
        let end = after(tokens, i);
        if !trait_impl {
            if let Some(name) = last_ident {
                let entry = out.entry(name).or_default();
                let mut j = i + 1;
                while j < end - 1 {
                    if tokens[j].text == "fn" {
                        let f = tokens[j + 1].text.to_string();
                        if f == "new" {
                            let open = (j..end).find(|&k| tokens[k].text == "(").expect("params");
                            let close = after(tokens, open) - 1;
                            let mut depth = 0;
                            for k in open + 1..close {
                                match tokens[k].text {
                                    "(" | "[" | "{" | "<" => depth += 1,
                                    ")" | "]" | "}" | ">" => depth -= 1,
                                    ":" if depth == 0 => {
                                        entry.1.insert(tokens[k - 1].text.to_string());
                                    }
                                    _ => {}
                                }
                            }
                        }
                        entry.0.insert(f);
                    }
                    j = match tokens[j].text {
                        "{" => after(tokens, j),
                        _ => j + 1,
                    };
                }
            }
        }
        at = end;
    }
    out
}

fn is_test_file(path: &str) -> bool {
    path.ends_with("/tests.rs") || path.ends_with("_tests.rs")
}

/// Every `pub struct` under `src/`, the refusals, and the impls' methods.
#[allow(clippy::type_complexity)]
fn crate_scan() -> (
    Vec<Found>,
    Vec<String>,
    BTreeMap<String, (BTreeSet<String>, BTreeSet<String>)>,
) {
    let mut found = Vec::new();
    let mut refused = Vec::new();
    let mut impls: BTreeMap<String, (BTreeSet<String>, BTreeSet<String>)> = BTreeMap::new();
    for source in arch_support::sources() {
        if is_test_file(&source.path) {
            continue;
        }
        let tokens = source.tokens_with_attributes();
        let (f, r) = scan(&source.path, &tokens);
        found.extend(f);
        refused.extend(r);
        for (name, (fns, params)) in methods(&tokens) {
            let entry = impls.entry(name).or_default();
            entry.0.extend(fns);
            entry.1.extend(params);
        }
    }
    (found, refused, impls)
}

/// A row: `file:Name`, its class, its reason.
type Row<'a> = (&'a str, Class, &'a str);

/// A row's class (the captain's rulings of 2026-11-12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    /// It mirrors a reference record; the reason is that record's
    /// `path:line` at `edf6e03`.
    Record,
    /// Every field a caller's choice; its field names are pinned
    /// ([`PARAMETER_BLOCKS`]).
    ParameterBlock,
    /// Deprecated, or a deprecated door's alone.
    Deprecated,
    /// The freeze plan's row 8b or 8c: opened by a later part. Takes no new
    /// row; [`PENDING_LEN`] only lowers.
    Pending,
    /// No class holds it and no ruling names it. Takes no new row;
    /// [`UNRULED_LEN`] only lowers.
    Unruled,
}

/// The rows of `Pending`: only lowered, as each struct is opened.
const PENDING_LEN: usize = 20;
/// The rows of `Unruled`: only lowered, as each struct takes a class or the
/// attribute.
const UNRULED_LEN: usize = 57;

/// `file:Name`, the class, the reason: every all-public struct under `src/`
/// without `#[non_exhaustive]`.
const ROWS: &[(&str, Class, &str)] = &[
    ("src/auth/certificates/master.rs:MasterCertificate", Class::Record, "`MasterCertificate`, `packages/sdk/src/auth/certificates/MasterCertificate.ts:164` at `edf6e03`"),
    ("src/auth/types.rs:AuthMessage", Class::Record, "`AuthMessage`, `packages/sdk/src/auth/types.ts:26` at `edf6e03`"),
    ("src/auth/types.rs:PeerSession", Class::Record, "`PeerSession`, `packages/sdk/src/auth/types.ts:62` at `edf6e03`"),
    ("src/auth/types.rs:RequestedCertificateSet", Class::Record, "`RequestedCertificateSet`, `packages/sdk/src/auth/types.ts:21` at `edf6e03`"),
    ("src/identity/types.rs:DisplayableIdentity", Class::Record, "`DisplayableIdentity`, `packages/sdk/src/identity/types/index.ts:29` at `edf6e03`"),
    ("src/identity/types.rs:IdentityQuery", Class::Record, "`IdentityQuery`, `packages/overlays/topics/src/identity/types.ts:28` at `edf6e03`"),
    ("src/identity/types.rs:IdentityCertificate", Class::Record, "`IdentityCertificate`, `packages/sdk/src/wallet/Wallet.interfaces.ts:877` at `edf6e03`"),
    ("src/identity/types.rs:BroadcastFailure", Class::Record, "`BroadcastFailure`, `packages/sdk/src/transaction/Broadcaster.ts:130` at `edf6e03`"),
    ("src/kvstore/types.rs:KVStoreToken", Class::Record, "`KVStoreToken`, `packages/sdk/src/kvstore/types.ts:149` at `edf6e03`"),
    ("src/kvstore/types.rs:KVStoreEntry", Class::Record, "`KVStoreEntry`, `packages/sdk/src/kvstore/types.ts:123` at `edf6e03`"),
    ("src/kvstore/types.rs:KVStoreLookupResult", Class::Record, "`KVStoreLookupResult`, `packages/sdk/src/kvstore/types.ts:137` at `edf6e03`"),
    ("src/kvstore/types.rs:KVStoreQuery", Class::Record, "`KVStoreQuery`, `packages/sdk/src/kvstore/types.ts:74` at `edf6e03`"),
    ("src/overlay/host_reputation_tracker.rs:HostReputationEntry", Class::Record, "`HostReputationEntry`, `packages/sdk/src/overlay-tools/HostReputationTracker.ts:4` at `edf6e03`"),
    ("src/overlay/host_reputation_tracker.rs:RankedHost", Class::Record, "`RankedHost`, `packages/sdk/src/overlay-tools/HostReputationTracker.ts:16` at `edf6e03`"),
    ("src/overlay/types.rs:LookupQuestion", Class::Record, "`LookupQuestion`, `packages/sdk/src/overlay-tools/LookupResolver.ts:33` at `edf6e03`"),
    ("src/overlay/types.rs:LookupFormula", Class::Record, "`LookupFormula`, `packages/overlays/overlay/src/LookupFormula.ts:4` at `edf6e03`"),
    ("src/overlay/types.rs:TaggedBEEF", Class::Record, "`TaggedBEEF`, `packages/sdk/src/overlay-tools/SHIPBroadcaster.ts:19` at `edf6e03`"),
    ("src/overlay/types.rs:AdmittanceInstructions", Class::Record, "`AdmittanceInstructions`, `packages/sdk/src/overlay-tools/SHIPBroadcaster.ts:28` at `edf6e03`"),
    ("src/primitives/bsv/polynomial.rs:PointInFiniteField", Class::Record, "`PointInFiniteField`, `packages/sdk/src/primitives/Polynomial.ts:18` at `edf6e03`"),
    ("src/primitives/bsv/polynomial.rs:Polynomial", Class::Record, "`Polynomial`, `packages/sdk/src/primitives/Polynomial.ts:66` at `edf6e03`"),
    ("src/primitives/bsv/shamir.rs:KeyShares", Class::Record, "`KeyShares`, `packages/sdk/src/primitives/PrivateKey.ts:44` at `edf6e03`"),
    ("src/registry/types.rs:TokenData", Class::Record, "`TokenData`, `packages/sdk/src/registry/types/index.ts:68` at `edf6e03`"),
    ("src/registry/types.rs:BasketDefinitionData", Class::Record, "`BasketDefinitionData`, `packages/sdk/src/registry/types/index.ts:22` at `edf6e03`"),
    ("src/registry/types.rs:ProtocolDefinitionData", Class::Record, "`ProtocolDefinitionData`, `packages/sdk/src/registry/types/index.ts:35` at `edf6e03`"),
    ("src/registry/types.rs:CertificateFieldDescriptor", Class::Record, "`CertificateFieldDescriptor`, `packages/sdk/src/registry/types/index.ts:12` at `edf6e03`"),
    ("src/registry/types.rs:CertificateDefinitionData", Class::Record, "`CertificateDefinitionData`, `packages/sdk/src/registry/types/index.ts:48` at `edf6e03`"),
    ("src/registry/types.rs:RegistryRecord", Class::Record, "`RegistryRecord`, `packages/sdk/src/registry/types/index.ts:80` at `edf6e03`"),
    ("src/registry/types.rs:BasketQuery", Class::Record, "`BasketQuery`, `packages/sdk/src/registry/types/index.ts:92` at `edf6e03`"),
    ("src/registry/types.rs:ProtocolQuery", Class::Record, "`ProtocolQuery`, `packages/sdk/src/registry/types/index.ts:104` at `edf6e03`"),
    ("src/registry/types.rs:CertificateQuery", Class::Record, "`CertificateQuery`, `packages/sdk/src/registry/types/index.ts:116` at `edf6e03`"),
    ("src/registry/types.rs:BroadcastFailure", Class::Record, "`BroadcastFailure`, `packages/sdk/src/transaction/Broadcaster.ts:130` at `edf6e03`"),
    ("src/script/chunk.rs:ScriptChunk", Class::Record, "`ScriptChunk`, `packages/sdk/src/script/ScriptChunk.ts:4` at `edf6e03`"),
    ("src/script/evaluation_error.rs:ScriptEvaluationError", Class::Record, "`ScriptEvaluationError`, `packages/sdk/src/script/ScriptEvaluationError.ts:9` at `edf6e03`"),
    ("src/script/templates/pushdrop.rs:PushDrop", Class::Record, "`PushDrop`, `packages/sdk/src/script/templates/PushDrop.ts:53` at `edf6e03`"),
    ("src/script/templates/rpuzzle.rs:RPuzzle", Class::Record, "`RPuzzle`, `packages/sdk/src/script/templates/RPuzzle.ts:20` at `edf6e03`"),
    ("src/storage/types.rs:UploadableFile", Class::Record, "`UploadableFile`, `packages/sdk/src/storage/StorageUploader.ts:38` at `edf6e03`"),
    ("src/storage/types.rs:DownloadResult", Class::Record, "`DownloadResult`, `packages/sdk/src/storage/StorageDownloader.ts:38` at `edf6e03`"),
    ("src/storage/types.rs:UploadFileResult", Class::Record, "`UploadFileResult`, `packages/sdk/src/storage/StorageUploader.ts:43` at `edf6e03`"),
    ("src/storage/types.rs:FindFileData", Class::Record, "`FindFileData`, `packages/sdk/src/storage/StorageUploader.ts:50` at `edf6e03`"),
    ("src/storage/types.rs:RenewFileResult", Class::Record, "`RenewFileResult`, `packages/sdk/src/storage/StorageUploader.ts:68` at `edf6e03`"),
    ("src/transaction/broadcaster.rs:BroadcastResponse", Class::Record, "`BroadcastResponse`, `packages/sdk/src/transaction/Broadcaster.ts:113` at `edf6e03`"),
    ("src/transaction/broadcaster.rs:BroadcastFailure", Class::Record, "`BroadcastFailure`, `packages/sdk/src/transaction/Broadcaster.ts:130` at `edf6e03`"),
    ("src/transaction/fee_models/sats_per_kb.rs:SatoshisPerKilobyte", Class::Record, "`SatoshisPerKilobyte`, `packages/sdk/src/transaction/fee-models/SatoshisPerKilobyte.ts:7` at `edf6e03`"),
    ("src/transaction/input.rs:TransactionInput", Class::Record, "`TransactionInput`, `packages/sdk/src/transaction/TransactionInput.ts:53` at `edf6e03`"),
    ("src/transaction/merkle_path.rs:MerklePathLeaf", Class::Record, "`MerklePathLeaf`, `packages/sdk/src/transaction/MerklePath.ts:6` at `edf6e03`"),
    ("src/transaction/merkle_path.rs:MerklePath", Class::Record, "`MerklePath`, `packages/sdk/src/transaction/MerklePath.ts:86` at `edf6e03`"),
    ("src/transaction/output.rs:TransactionOutput", Class::Record, "`TransactionOutput`, `packages/sdk/src/transaction/TransactionOutput.ts:32` at `edf6e03`"),
    ("src/wallet/interface.rs:RevealCounterpartyKeyLinkageArgs", Class::Record, "`RevealCounterpartyKeyLinkageArgs`, `packages/sdk/src/wallet/Wallet.interfaces.ts:693` at `edf6e03`"),
    ("src/wallet/interface.rs:RevealSpecificKeyLinkageArgs", Class::Record, "`RevealSpecificKeyLinkageArgs`, `packages/sdk/src/wallet/Wallet.interfaces.ts:708` at `edf6e03`"),
    ("src/wallet/key_args.rs:GetPublicKeyArgs", Class::Record, "`GetPublicKeyArgs`, `packages/sdk/src/wallet/Wallet.interfaces.ts:682` at `edf6e03`"),
    ("src/wallet/key_args.rs:GetPublicKeyResult", Class::Record, "`GetPublicKeyResult`, `packages/sdk/src/wallet/Wallet.interfaces.ts:1029` at `edf6e03`"),
    ("src/wallet/key_args.rs:EncryptArgs", Class::Record, "`WalletEncryptArgs`, `packages/sdk/src/wallet/Wallet.interfaces.ts:749` at `edf6e03`"),
    ("src/wallet/key_args.rs:EncryptResult", Class::Record, "`WalletEncryptResult`, `packages/sdk/src/wallet/Wallet.interfaces.ts:753` at `edf6e03`"),
    ("src/wallet/key_args.rs:DecryptArgs", Class::Record, "`WalletDecryptArgs`, `packages/sdk/src/wallet/Wallet.interfaces.ts:760` at `edf6e03`"),
    ("src/wallet/key_args.rs:DecryptResult", Class::Record, "`WalletDecryptResult`, `packages/sdk/src/wallet/Wallet.interfaces.ts:764` at `edf6e03`"),
    ("src/wallet/key_args.rs:CreateHmacArgs", Class::Record, "`CreateHmacArgs`, `packages/sdk/src/wallet/Wallet.interfaces.ts:771` at `edf6e03`"),
    ("src/wallet/key_args.rs:CreateHmacResult", Class::Record, "`CreateHmacResult`, `packages/sdk/src/wallet/Wallet.interfaces.ts:775` at `edf6e03`"),
    ("src/wallet/key_args.rs:VerifyHmacArgs", Class::Record, "`VerifyHmacArgs`, `packages/sdk/src/wallet/Wallet.interfaces.ts:783` at `edf6e03`"),
    ("src/wallet/key_args.rs:VerifyHmacResult", Class::Record, "`VerifyHmacResult`, `packages/sdk/src/wallet/Wallet.interfaces.ts:788` at `edf6e03`"),
    ("src/wallet/key_args.rs:CreateSignatureArgs", Class::Record, "`CreateSignatureArgs`, `packages/sdk/src/wallet/Wallet.interfaces.ts:796` at `edf6e03`"),
    ("src/wallet/key_args.rs:CreateSignatureResult", Class::Record, "`CreateSignatureResult`, `packages/sdk/src/wallet/Wallet.interfaces.ts:801` at `edf6e03`"),
    ("src/wallet/key_args.rs:VerifySignatureArgs", Class::Record, "`VerifySignatureArgs`, `packages/sdk/src/wallet/Wallet.interfaces.ts:811` at `edf6e03`"),
    ("src/wallet/key_args.rs:VerifySignatureResult", Class::Record, "`VerifySignatureResult`, `packages/sdk/src/wallet/Wallet.interfaces.ts:818` at `edf6e03`"),
    ("src/wallet/proto_wallet.rs:RevealCounterpartyKeyLinkageArgs", Class::Record, "`RevealCounterpartyKeyLinkageArgs`, `packages/sdk/src/wallet/Wallet.interfaces.ts:693` at `edf6e03`"),
    ("src/wallet/proto_wallet.rs:RevealCounterpartyKeyLinkageResult", Class::Record, "`RevealCounterpartyKeyLinkageResult`, `packages/sdk/src/wallet/Wallet.interfaces.ts:734` at `edf6e03`"),
    ("src/wallet/proto_wallet.rs:RevealSpecificKeyLinkageArgs", Class::Record, "`RevealSpecificKeyLinkageArgs`, `packages/sdk/src/wallet/Wallet.interfaces.ts:708` at `edf6e03`"),
    ("src/wallet/proto_wallet.rs:RevealSpecificKeyLinkageResult", Class::Record, "`RevealSpecificKeyLinkageResult`, `packages/sdk/src/wallet/Wallet.interfaces.ts:740` at `edf6e03`"),
    ("src/wallet/types.rs:CreateActionInput", Class::Record, "`CreateActionInput`, `packages/sdk/src/wallet/Wallet.interfaces.ts:261` at `edf6e03`"),
    ("src/wallet/types.rs:CreateActionOutput", Class::Record, "`CreateActionOutput`, `packages/sdk/src/wallet/Wallet.interfaces.ts:277` at `edf6e03`"),
    ("src/wallet/types.rs:CreateActionOptions", Class::Record, "`packages/sdk/src/wallet/Wallet.interfaces.ts:297-307` at `edf6e03`: `signAndProcess?`, `acceptDelayedBroadcast?`, `trustSelf?`, `knownTxids?`, `returnTXIDOnly?`, `noSend?`, `noSendChange?`, `sendWith?`, `randomizeOutputs?`"),
    ("src/wallet/types.rs:SendWithResult", Class::Record, "`SendWithResult`, `packages/sdk/src/wallet/Wallet.interfaces.ts:311` at `edf6e03`"),
    ("src/wallet/types.rs:ReviewActionResult", Class::Record, "`ReviewActionResult`, `packages/sdk/src/wallet/Wallet.interfaces.ts:327` at `edf6e03`"),
    ("src/wallet/types.rs:SignableTransaction", Class::Record, "`SignableTransaction`, `packages/sdk/src/wallet/Wallet.interfaces.ts:340` at `edf6e03`"),
    ("src/wallet/types.rs:CreateActionResult", Class::Record, "`CreateActionResult`, `packages/sdk/src/wallet/Wallet.interfaces.ts:354` at `edf6e03`"),
    ("src/wallet/types.rs:WalletActionInput", Class::Record, "`WalletActionInput`, `packages/sdk/src/wallet/Wallet.interfaces.ts:499` at `edf6e03`"),
    ("src/wallet/types.rs:WalletActionOutput", Class::Record, "`WalletActionOutput`, `packages/sdk/src/wallet/Wallet.interfaces.ts:509` at `edf6e03`"),
    ("src/wallet/types.rs:WalletAction", Class::Record, "`WalletAction`, `packages/sdk/src/wallet/Wallet.interfaces.ts:540` at `edf6e03`"),
    ("src/wallet/types.rs:WalletOutput", Class::Record, "`WalletOutput`, `packages/sdk/src/wallet/Wallet.interfaces.ts:526` at `edf6e03`"),
    ("src/wallet/types.rs:CreateActionArgs", Class::Record, "`CreateActionArgs`, `packages/sdk/src/wallet/Wallet.interfaces.ts:389` at `edf6e03`"),
    ("src/wallet/types.rs:SignActionSpend", Class::Record, "`SignActionSpend`, `packages/sdk/src/wallet/Wallet.interfaces.ts:404` at `edf6e03`"),
    ("src/wallet/types.rs:SignActionOptions", Class::Record, "`packages/sdk/src/wallet/Wallet.interfaces.ts:417-422` at `edf6e03`: `acceptDelayedBroadcast?`, `returnTXIDOnly?`, `noSend?`, `sendWith?`"),
    ("src/wallet/types.rs:SignActionArgs", Class::Record, "`SignActionArgs`, `packages/sdk/src/wallet/Wallet.interfaces.ts:429` at `edf6e03`"),
    ("src/wallet/types.rs:SignActionResult", Class::Record, "`SignActionResult`, `packages/sdk/src/wallet/Wallet.interfaces.ts:438` at `edf6e03`"),
    ("src/wallet/types.rs:AbortActionArgs", Class::Record, "`AbortActionArgs`, `packages/sdk/src/wallet/Wallet.interfaces.ts:447` at `edf6e03`"),
    ("src/wallet/types.rs:AbortActionResult", Class::Record, "`AbortActionResult`, `packages/sdk/src/wallet/Wallet.interfaces.ts:466` at `edf6e03`"),
    ("src/wallet/types.rs:ListActionsArgs", Class::Record, "`ListActionsArgs`, `packages/sdk/src/wallet/Wallet.interfaces.ts:485` at `edf6e03`"),
    ("src/wallet/types.rs:ListActionsResult", Class::Record, "`ListActionsResult`, `packages/sdk/src/wallet/Wallet.interfaces.ts:554` at `edf6e03`"),
    ("src/wallet/types.rs:WalletPayment", Class::Record, "`WalletPayment`, `packages/sdk/src/wallet/Wallet.interfaces.ts:564` at `edf6e03`"),
    ("src/wallet/types.rs:BasketInsertion", Class::Record, "`BasketInsertion`, `packages/sdk/src/wallet/Wallet.interfaces.ts:575` at `edf6e03`"),
    ("src/wallet/types.rs:InternalizeActionArgs", Class::Record, "`InternalizeActionArgs`, `packages/sdk/src/wallet/Wallet.interfaces.ts:601` at `edf6e03`"),
    ("src/wallet/types.rs:InternalizeActionResult", Class::Record, "`InternalizeActionResult`, `packages/sdk/src/wallet/Wallet.interfaces.ts:609` at `edf6e03`"),
    ("src/wallet/types.rs:ListOutputsArgs", Class::Record, "`ListOutputsArgs`, `packages/sdk/src/wallet/Wallet.interfaces.ts:629` at `edf6e03`"),
    ("src/wallet/types.rs:ListOutputsResult", Class::Record, "`ListOutputsResult`, `packages/sdk/src/wallet/Wallet.interfaces.ts:642` at `edf6e03`"),
    ("src/wallet/types.rs:RelinquishOutputArgs", Class::Record, "`RelinquishOutputArgs`, `packages/sdk/src/wallet/Wallet.interfaces.ts:648` at `edf6e03`"),
    ("src/wallet/types.rs:RelinquishOutputResult", Class::Record, "`RelinquishOutputResult`, `packages/sdk/src/wallet/Wallet.interfaces.ts:653` at `edf6e03`"),
    ("src/wallet/types.rs:WalletCertificate", Class::Record, "`WalletCertificate`, `packages/sdk/src/wallet/Wallet.interfaces.ts:851` at `edf6e03`"),
    ("src/wallet/types.rs:AcquireCertificateArgs", Class::Record, "`AcquireCertificateArgs`, `packages/sdk/src/wallet/Wallet.interfaces.ts:836` at `edf6e03`"),
    ("src/wallet/types.rs:ListCertificatesArgs", Class::Record, "`ListCertificatesArgs`, `packages/sdk/src/wallet/Wallet.interfaces.ts:891` at `edf6e03`"),
    ("src/wallet/types.rs:CertificateResult", Class::Record, "`CertificateResult`, `packages/sdk/src/wallet/Wallet.interfaces.ts:900` at `edf6e03`"),
    ("src/wallet/types.rs:ListCertificatesResult", Class::Record, "`ListCertificatesResult`, `packages/sdk/src/wallet/Wallet.interfaces.ts:905` at `edf6e03`"),
    ("src/wallet/types.rs:ProveCertificateArgs", Class::Record, "`ProveCertificateArgs`, `packages/sdk/src/wallet/Wallet.interfaces.ts:917` at `edf6e03`"),
    ("src/wallet/types.rs:ProveCertificateResult", Class::Record, "`ProveCertificateResult`, `packages/sdk/src/wallet/Wallet.interfaces.ts:925` at `edf6e03`"),
    ("src/wallet/types.rs:RelinquishCertificateArgs", Class::Record, "`RelinquishCertificateArgs`, `packages/sdk/src/wallet/Wallet.interfaces.ts:936` at `edf6e03`"),
    ("src/wallet/types.rs:RelinquishCertificateResult", Class::Record, "`RelinquishCertificateResult`, `packages/sdk/src/wallet/Wallet.interfaces.ts:942` at `edf6e03`"),
    ("src/wallet/types.rs:IdentityCertifier", Class::Record, "`IdentityCertifier`, `packages/sdk/src/wallet/Wallet.interfaces.ts:870` at `edf6e03`"),
    ("src/wallet/types.rs:IdentityCertificate", Class::Record, "`IdentityCertificate`, `packages/sdk/src/wallet/Wallet.interfaces.ts:877` at `edf6e03`"),
    ("src/wallet/types.rs:DiscoverByIdentityKeyArgs", Class::Record, "`DiscoverByIdentityKeyArgs`, `packages/sdk/src/wallet/Wallet.interfaces.ts:989` at `edf6e03`"),
    ("src/wallet/types.rs:DiscoverByAttributesArgs", Class::Record, "`DiscoverByAttributesArgs`, `packages/sdk/src/wallet/Wallet.interfaces.ts:1009` at `edf6e03`"),
    ("src/wallet/types.rs:DiscoverCertificatesResult", Class::Record, "`DiscoverCertificatesResult`, `packages/sdk/src/wallet/Wallet.interfaces.ts:998` at `edf6e03`"),
    ("src/wallet/types.rs:AuthenticatedResult", Class::Record, "`AuthenticatedResult`, `packages/sdk/src/wallet/Wallet.interfaces.ts:946` at `edf6e03`"),
    ("src/wallet/types.rs:GetHeightResult", Class::Record, "`GetHeightResult`, `packages/sdk/src/wallet/Wallet.interfaces.ts:950` at `edf6e03`"),
    ("src/wallet/types.rs:GetHeaderArgs", Class::Record, "`GetHeaderArgs`, `packages/sdk/src/wallet/Wallet.interfaces.ts:961` at `edf6e03`"),
    ("src/wallet/types.rs:GetHeaderResult", Class::Record, "`GetHeaderResult`, `packages/sdk/src/wallet/Wallet.interfaces.ts:965` at `edf6e03`"),
    ("src/wallet/types.rs:GetNetworkResult", Class::Record, "`GetNetworkResult`, `packages/sdk/src/wallet/Wallet.interfaces.ts:974` at `edf6e03`"),
    ("src/wallet/types.rs:GetVersionResult", Class::Record, "`GetVersionResult`, `packages/sdk/src/wallet/Wallet.interfaces.ts:979` at `edf6e03`"),
    ("src/wallet/types/internalize_output.rs:InternalizeOutput", Class::Record, "`InternalizeOutput`, `packages/sdk/src/wallet/Wallet.interfaces.ts:587` at `edf6e03`"),
    ("src/wallet/types/linkage.rs:KeyLinkageResult", Class::Record, "`KeyLinkageResult`, `packages/sdk/src/wallet/Wallet.interfaces.ts:719` at `edf6e03`"),
    ("src/wallet/types/linkage.rs:RevealCounterpartyKeyLinkageResult", Class::Record, "`RevealCounterpartyKeyLinkageResult`, `packages/sdk/src/wallet/Wallet.interfaces.ts:734` at `edf6e03`"),
    ("src/wallet/types/linkage.rs:RevealSpecificKeyLinkageResult", Class::Record, "`RevealSpecificKeyLinkageResult`, `packages/sdk/src/wallet/Wallet.interfaces.ts:740` at `edf6e03`"),
    ("src/wallet/validation.rs:ValidCreateActionInput", Class::Record, "`ValidCreateActionInput`, `packages/sdk/src/wallet/validationHelpers.ts:569` at `edf6e03`"),
    ("src/wallet/validation.rs:ValidCreateActionOutput", Class::Record, "`ValidCreateActionOutput`, `packages/sdk/src/wallet/validationHelpers.ts:615` at `edf6e03`"),
    ("src/wallet/validation.rs:ValidCreateActionOptions", Class::Record, "`packages/sdk/src/wallet/validationHelpers.ts:683-689` at `edf6e03`: `signAndProcess`, `trustSelf?`, `knownTxids`, `noSendChange`, `randomizeOutputs` over `ValidProcessActionOptions`, `:676-681`"),
    ("src/wallet/validation.rs:ValidCreateActionArgs", Class::Record, "`ValidCreateActionArgs`, `packages/sdk/src/wallet/validationHelpers.ts:714` at `edf6e03`"),
    ("src/wallet/validation.rs:ValidListOutputsArgs", Class::Record, "`ValidListOutputsArgs`, `packages/sdk/src/wallet/validationHelpers.ts:1589` at `edf6e03`"),
    ("src/wallet/validation.rs:ValidListActionsArgs", Class::Record, "`ValidListActionsArgs`, `packages/sdk/src/wallet/validationHelpers.ts:1656` at `edf6e03`"),
    ("src/primitives/bsv/sighash.rs:SighashParams", Class::ParameterBlock, "every field a caller's choice of the digest's inputs"),
    ("src/script/spend/mod.rs:SpendParams", Class::ParameterBlock, "every field a caller's choice of the input judged and its budgets"),
    ("src/script/spend/mod.rs:TxSpendParams", Class::ParameterBlock, "every field a caller's choice of the input judged and its budgets"),
    ("src/transaction/beef.rs:BeefLimits", Class::Deprecated, "the hints of the deprecated `Beef::from_binary_with_limits` door alone (0.4.0)"),
    ("src/transaction/broadcasters/arc.rs:ArcConfig", Class::Deprecated, "deprecated since 0.9.0 with ARC (#350, the owner's word of 2026-10-27): ARCade is the standard"),
    ("src/identity/types.rs:IdentityClientConfig", Class::Pending, "the freeze plan's row 8c"),
    ("src/identity/types.rs:ContactsManagerConfig", Class::Pending, "the freeze plan's row 8c"),
    ("src/kvstore/types.rs:KVStoreConfig", Class::Pending, "the freeze plan's row 8c"),
    ("src/kvstore/types.rs:KVStoreGetOptions", Class::Pending, "the freeze plan's row 8c"),
    ("src/kvstore/types.rs:KVStoreSetOptions", Class::Pending, "the freeze plan's row 8c"),
    ("src/kvstore/types.rs:KVStoreRemoveOptions", Class::Pending, "the freeze plan's row 8c"),
    ("src/overlay/historian.rs:HistorianConfig", Class::Pending, "the freeze plan's row 8c"),
    ("src/overlay/host_reputation_tracker.rs:ReputationConfig", Class::Pending, "the freeze plan's row 8c"),
    ("src/overlay/lookup_resolver.rs:LookupResolverConfig", Class::Pending, "the freeze plan's row 8b"),
    ("src/overlay/topic_broadcaster.rs:TopicBroadcasterConfig", Class::Pending, "the freeze plan's row 8b"),
    ("src/registry/client.rs:RegistryClientConfig", Class::Pending, "the freeze plan's row 8c"),
    ("src/storage/downloader.rs:StorageDownloaderConfig", Class::Pending, "the freeze plan's row 8c"),
    ("src/storage/uploader.rs:StorageUploaderConfig", Class::Pending, "the freeze plan's row 8c"),
    ("src/totp/core.rs:TotpOptions", Class::Pending, "the freeze plan's row 8c"),
    ("src/totp/core.rs:TotpValidateOptions", Class::Pending, "the freeze plan's row 8c"),
    ("src/transaction/broadcasters/teranode.rs:TeranodeConfig", Class::Pending, "the freeze plan's row 8c"),
    ("src/transaction/broadcasters/whatsonchain.rs:WocBroadcastConfig", Class::Pending, "the freeze plan's row 8c"),
    ("src/transaction/chain_trackers/block_headers_service.rs:BlockHeadersServiceConfig", Class::Pending, "the freeze plan's row 8c"),
    ("src/transaction/fee_models/live_policy.rs:LivePolicyConfig", Class::Pending, "the freeze plan's row 8c"),
    ("src/wallet/cached_key_deriver.rs:CacheConfig", Class::Pending, "the freeze plan's row 8c"),
    ("src/auth/clients/response.rs:Response", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/auth/transports/http.rs:HttpRequest", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/auth/transports/http.rs:HttpResponse", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/auth/transports/socketio/mod.rs:AppEvent", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/block/difficulty.rs:HeaderLink", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/block/header.rs:BlockHeader", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/block/merkle.rs:MerkleRoot", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/block/target.rs:CompactTarget", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/identity/types.rs:IdentityResolutionResult", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/identity/types.rs:CertifierInfo", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/identity/types.rs:BroadcastSuccess", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/kvstore/interpreter.rs:KVStoreContext", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/kvstore/interpreter.rs:KVStoreFields", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/overlay/host_reputation_tracker.rs:RankChangeEvent", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/overlay/overlay_admin_token_template.rs:OverlayAdminTokenData", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/overlay/types.rs:OutputListItem", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/overlay/types.rs:HostResponse", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/overlay/types.rs:ServiceMetadata", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/primitives/bsv/schnorr.rs:SchnorrProof", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/primitives/bsv/sighash.rs:TxInput", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/primitives/bsv/sighash.rs:TxOutput", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/primitives/bsv/sighash.rs:RawTransaction", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/registry/types.rs:RegisterDefinitionResult", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/registry/types.rs:BroadcastSuccess", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/registry/types.rs:RevokeDefinitionResult", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/registry/types.rs:UpdateDefinitionResult", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/script/evaluation_error.rs:ScriptResourceLimit", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/script/template.rs:SigningContext", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/script/templates/multisig.rs:Multisig", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/script/transaction.rs:SimpleUtxo", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/storage/types.rs:UploadMetadata", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/transaction/beef.rs:SortResult", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/transaction/beef.rs:BeefValidationResult", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/transaction/beef_stream.rs:Refusal", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/transaction/beef_stream.rs:Leaf", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/transaction/beef_stream.rs:Bump", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/transaction/beef_stream.rs:InputRef", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/transaction/beef_stream.rs:OutputRef", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/transaction/beef_stream.rs:TxBody", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/transaction/beef_stream.rs:ChainTip", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/transaction/beef_stream.rs:HeadersFn", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/transaction/chain_tracker.rs:AlwaysValidChainTracker", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/transaction/input.rs:Utxo", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/transaction/transaction.rs:ScriptOffsets", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/transaction/transaction.rs:ScriptOffset", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/transaction/transaction/fields.rs:TransactionParts", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/transaction/transaction/fields.rs:TransactionPartsMut", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/wallet/review_actions.rs:ReviewActionsRefusal", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/wallet/types.rs:Protocol", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/wallet/types.rs:Outpoint", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/wallet/types.rs:Certificate", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/wallet/validation.rs:CreateActionInputRaw", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/wallet/validation.rs:CreateActionOutputRaw", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/wallet/validation.rs:CreateActionOptionsRaw", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/wallet/validation.rs:CreateActionArgsRaw", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/wallet/validation.rs:SignActionSpendRaw", Class::Unruled, "no class holds it and no ruling names it"),
    ("src/wallet/validation.rs:ValidSignActionSpend", Class::Unruled, "no class holds it and no ruling names it"),
];

/// The parameter blocks' field names, in declaration order.
const PARAMETER_BLOCKS: &[(&str, &[&str])] = &[
    (
        "src/script/spend/mod.rs:SpendParams",
        &[
            "source_txid",
            "source_output_index",
            "source_satoshis",
            "locking_script",
            "transaction_version",
            "other_inputs",
            "outputs",
            "input_index",
            "unlocking_script",
            "input_sequence",
            "lock_time",
            "memory_limit",
            "work_limit",
        ],
    ),
    (
        "src/script/spend/mod.rs:TxSpendParams",
        &[
            "transaction",
            "input_index",
            "source_satoshis",
            "locking_script",
            "unlocking_script",
            "memory_limit",
            "work_limit",
        ],
    ),
    (
        "src/primitives/bsv/sighash.rs:SighashParams",
        &[
            "version",
            "inputs",
            "outputs",
            "locktime",
            "input_index",
            "subscript",
            "satoshis",
            "scope",
        ],
    ),
];

/// `file:Name` of an attributed struct with a `pub` field that has no
/// `with_<field>` and is no parameter of its `new`, with the reason.
const ASSIGNED: &[(&str, &str)] = &[
    (
        "src/auth/certificates/certificate.rs:Certificate",
        "`received_unsigned` is the unsigned prefix `from_binary` and `sign` set and the `set_*` doors clear (#249), never a caller's input",
    ),
    (
        "src/block/params.rs:ChainParams",
        "built by `main`, `test`, `regtest` and `with_activation_heights`: the difficulty fields are the node's `consensus` constants, read and not chosen (#440)",
    ),
    (
        "src/error/wallet_fault.rs:AbortAcceptance",
        "built by `new(reference, class, message)`; `txid`, `status`, `accepting_word` and `kind` set on the record when known, as its docs say (#439, #604)",
    ),
    (
        "src/overlay/lookup_limits.rs:LookupLimits",
        "built from `default()` and its fields set, as its doc example does (#775, #785)",
    ),
    (
        "src/overlay/lookup_limits.rs:LookupRequestOptions",
        "the bounds the resolver hands a facilitator, built from `default()` and set by the crate (#775)",
    ),
    (
        "src/transaction/spending.rs:InputVerified",
        "an answer the one-input door returns, never built by a caller (#855)",
    ),
];

/// The structs the scan reads by name: the generic ones, the tuple one and
/// the ones a `key_args!` invocation declares.
const GENERIC: &[&str] = &[
    "src/auth/peer.rs:PeerOptions",
    "src/overlay/historian.rs:HistorianConfig",
    "src/primitives/bsv/sighash.rs:SighashParams",
    "src/script/template.rs:SigningContext",
    "src/transaction/beef_stream.rs:HeadersFn",
    "src/transaction/transaction/fields.rs:TransactionPartsMut",
];
const TUPLE: &[&str] = &["src/transaction/beef_stream.rs:HeadersFn"];
const KEY_ARGS: &[&str] = &[
    "src/wallet/key_args.rs:GetPublicKeyArgs",
    "src/wallet/key_args.rs:EncryptArgs",
    "src/wallet/key_args.rs:DecryptArgs",
    "src/wallet/key_args.rs:CreateHmacArgs",
    "src/wallet/key_args.rs:VerifyHmacArgs",
    "src/wallet/key_args.rs:CreateSignatureArgs",
    "src/wallet/key_args.rs:VerifySignatureArgs",
];

/// The fields of an attributed struct that have no setter and are no
/// parameter of its `new`.
fn unset_fields(
    found: &Found,
    impls: &BTreeMap<String, (BTreeSet<String>, BTreeSet<String>)>,
) -> Vec<String> {
    found
        .fields
        .iter()
        .filter(|(_, vis)| vis.as_deref() == Some("pub"))
        .map(|(name, _)| name.clone())
        .filter(|name| {
            impls.get(&found.name).is_none_or(|(fns, params)| {
                !fns.contains(&format!("with_{name}")) && !params.contains(name)
            })
        })
        .collect()
}

/// Every refusal of the rule over a scan, one line each.
fn errors(
    found: &[Found],
    refused: &[String],
    impls: &BTreeMap<String, (BTreeSet<String>, BTreeSet<String>)>,
    rows: &[(&str, Class, &str)],
    assigned: &[(&str, &str)],
) -> Vec<String> {
    let mut out: Vec<String> = refused.to_vec();
    let public: Vec<&Found> = found.iter().filter(|f| f.all_public()).collect();
    let by_row: BTreeMap<String, &Found> = public.iter().map(|f| (f.row(), *f)).collect();
    let listed: BTreeMap<&str, (Class, &str)> =
        rows.iter().map(|(r, c, why)| (*r, (*c, *why))).collect();
    if listed.len() != rows.len() {
        out.push("a row is listed twice".to_string());
    }
    for f in &public {
        let row = f.row();
        match (f.attributed, listed.get(row.as_str())) {
            (false, None) => out.push(format!(
                "{row} (line {}): every field is `pub` and it has no #[non_exhaustive]: \
                 add the attribute, `new` or `Default` and a `with_<field>` per field \
                 (#843d8a), or give it a row of a class with its reason",
                f.line
            )),
            (true, Some(_)) => {
                out.push(format!("{row}: attributed and still a row: remove the row"))
            }
            _ => {}
        }
        if f.attributed {
            let unset = unset_fields(f, impls);
            let is_assigned = assigned.iter().any(|(r, _)| *r == row);
            if !unset.is_empty() && !is_assigned {
                out.push(format!(
                    "{row}: `pub` fields {unset:?} have no `with_<field>` and are no \
                     parameter of `new`: add the setters, or list it in ASSIGNED with its reason"
                ));
            }
            if unset.is_empty() && is_assigned {
                out.push(format!(
                    "{row}: every field has a setter: remove its ASSIGNED row"
                ));
            }
        }
    }
    for (row, (class, why)) in &listed {
        if !by_row.contains_key(*row) {
            out.push(format!(
                "{row}: the row names no all-public struct: remove it"
            ));
            continue;
        }
        if why.trim().is_empty() {
            out.push(format!("{row}: a row without its reason"));
        }
        if *class == Class::Record
            && !(why.contains("at `edf6e03`") && why.contains("packages/") && why.contains(".ts:"))
        {
            out.push(format!(
                "{row}: a Record's reason is its reference record's `path:line` at `edf6e03`"
            ));
        }
        if *class == Class::Deprecated && !by_row[*row].deprecated && !why.contains("deprecated") {
            out.push(format!(
                "{row}: Deprecated, but neither it nor its reason is"
            ));
        }
    }
    for (row, _) in assigned {
        if !by_row.get(*row).is_some_and(|f| f.attributed) {
            out.push(format!(
                "{row}: an ASSIGNED row names no attributed struct: remove it"
            ));
        }
    }
    out
}

#[test]
fn every_all_public_struct_is_attributed_or_listed_843d8a() {
    let (found, refused, impls) = crate_scan();
    let errors = errors(&found, &refused, &impls, ROWS, ASSIGNED);
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

#[test]
fn the_pending_and_unruled_classes_take_no_new_row_843d8a() {
    let count = |class| ROWS.iter().filter(|(_, c, _)| *c == class).count();
    assert_eq!(
        count(Class::Pending),
        PENDING_LEN,
        "Pending takes no new row; lower PENDING_LEN when a struct leaves it"
    );
    assert_eq!(
        count(Class::Unruled),
        UNRULED_LEN,
        "Unruled takes no new row; lower UNRULED_LEN when a struct leaves it"
    );
}

#[test]
fn a_parameter_block_holds_its_pinned_fields_843d8a() {
    let (found, _, _) = crate_scan();
    let blocks: BTreeSet<&str> = ROWS
        .iter()
        .filter(|(_, c, _)| *c == Class::ParameterBlock)
        .map(|(r, _, _)| *r)
        .collect();
    assert_eq!(
        blocks,
        PARAMETER_BLOCKS
            .iter()
            .map(|(r, _)| *r)
            .collect::<BTreeSet<_>>(),
        "the ParameterBlock rows are the pinned blocks"
    );
    for (row, names) in PARAMETER_BLOCKS {
        let f = found
            .iter()
            .find(|f| f.row() == *row)
            .unwrap_or_else(|| panic!("{row} is declared"));
        let held: Vec<&str> = f.fields.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            &held, names,
            "{row}'s fields moved: a further knob is a `Spend` setter, not a field of a \
             parameter block (#843d8a)"
        );
    }
}

/// The census: the scan's totals and the structs it reads by name.
#[test]
fn the_scan_reads_every_form_by_name_843d8a() {
    let (found, refused, _) = crate_scan();
    assert!(refused.is_empty(), "{}", refused.join("\n"));
    let public: Vec<&Found> = found.iter().filter(|f| f.all_public()).collect();
    let rows = |pick: &dyn Fn(&Found) -> bool| -> BTreeSet<String> {
        public.iter().filter(|f| pick(f)).map(|f| f.row()).collect()
    };
    let set = |list: &[&str]| list.iter().map(|s| s.to_string()).collect::<BTreeSet<_>>();
    assert_eq!(
        rows(&|f| f.generic),
        set(GENERIC),
        "the generic all-public structs"
    );
    assert_eq!(
        rows(&|f| f.body == "("),
        set(TUPLE),
        "the tuple all-public structs"
    );
    assert_eq!(
        rows(&|f| f.key_args),
        set(KEY_ARGS),
        "the key_args! structs"
    );
    assert_eq!(public.len(), 219, "all-public structs under src/");
    assert_eq!(
        public.iter().filter(|f| f.attributed).count(),
        12,
        "attributed"
    );
    assert_eq!(ROWS.len() + 12, public.len(), "every other one a row");
}

fn probe(text: &str) -> (Vec<Found>, Vec<String>) {
    let tokens = arch_support::scan_tokens_with_attributes(text);
    scan("probe.rs", &tokens)
}

/// The scanner's reading on sample texts: each form and each refusal.
#[test]
fn the_scanner_reads_each_form_and_refuses_what_it_cannot_read_843d8a() {
    let (found, refused) = probe(
        r#"
        // pub struct InComment { pub a: u8 }
        const S: &str = "pub struct InString { pub a: u8 }";
        /// Doc.
        #[derive(Clone)] // a trailing comment
        #[non_exhaustive]
        pub struct Attributed { pub a: u8, #[serde(skip)] pub b: Vec<u8> }
        pub struct Plain { pub a: u8 }
        pub struct Mixed { pub a: u8, pub(crate) b: u8 }
        pub(crate) struct Crate { pub a: u8 }
        pub struct Generic<W: Clone, T> where T: Copy { pub w: W, pub t: fn(&T) -> T }
        pub struct Tuple<F>(pub F);
        pub struct Unit;
        pub struct Empty {}
        #[cfg(test)]
        pub struct Gated { pub a: u8 }
        macro_rules! m { ($name:ident) => { pub struct $name { pub a: u8 } } }
        key_args! { pub struct Keyed { pub a: bool = false, } }
        "#,
    );
    assert!(refused.is_empty(), "{refused:?}");
    let read: Vec<String> = found
        .iter()
        .map(|f| {
            format!(
                "{} {} {} {} {} {}",
                f.name,
                f.all_public(),
                f.attributed,
                f.generic,
                f.body,
                f.fields.len()
            )
        })
        .collect();
    assert_eq!(
        read,
        [
            "Attributed true true false { 2",
            "Plain true false false { 1",
            "Mixed false false false { 2",
            "Generic true false true { 2",
            "Tuple true false true ( 1",
            "Empty false false false { 0",
            "Keyed true false false { 4",
        ]
    );
    assert!(found
        .iter()
        .find(|f| f.name == "Keyed")
        .is_some_and(|f| f.key_args));

    // Another spelling of the attribute is no attribute here (the pins'
    // machine refuses the spelling), so the struct needs a row.
    for text in [
        "#[cfg_attr(feature = \"x\", non_exhaustive)]\npub struct A { pub a: u8 }",
        "#[non_exhaustive, doc = \"x\"]\npub struct B { pub a: u8 }",
    ] {
        let (found, refused) = probe(text);
        assert!(refused.is_empty(), "{text}: {refused:?}");
        assert!(
            found.len() == 1 && !found[0].attributed,
            "{text}: {found:?}"
        );
    }
    let text = "other! { pub struct C { pub a: u8 } }";
    let (_, refused) = probe(text);
    assert_eq!(refused.len(), 1, "{text}: {refused:?}");
    assert!(
        refused[0].contains("inside `other!`, which this scan cannot read"),
        "{text}: {refused:?}"
    );
}

/// The rule's refusals on sample texts: an unlisted struct, a row naming
/// none, a row on an attributed struct, a field without a setter, a stale
/// ASSIGNED row, a Record without its reference line.
#[test]
fn the_rule_refuses_each_case_on_a_probe_843d8a() {
    let text = r#"
        pub struct Planted { pub a: u8 }
        #[non_exhaustive]
        pub struct Open { pub a: u8, pub b: u8 }
        impl Open { pub fn new(a: u8) -> Self { Self { a, b: 0 } } pub fn with_b(mut self, b: u8) -> Self { self.b = b; self } }
        #[non_exhaustive]
        pub struct Half { pub a: u8, pub b: u8 }
        impl Half { pub fn new(a: u8) -> Self { Self { a, b: 0 } } }
        pub struct Listed { pub a: u8 }
    "#;
    let tokens = arch_support::scan_tokens_with_attributes(text);
    let (found, refused) = scan("probe.rs", &tokens);
    let impls = methods(&tokens);
    let clean = errors(
        &found,
        &refused,
        &impls,
        &[
            ("probe.rs:Planted", Class::Unruled, "a probe"),
            (
                "probe.rs:Listed",
                Class::Record,
                "`L`, `packages/sdk/src/L.ts:1` at `edf6e03`",
            ),
        ],
        &[("probe.rs:Half", "a probe")],
    );
    assert!(clean.is_empty(), "{clean:?}");
    type Case<'a> = (&'a [Row<'a>], &'a [(&'a str, &'a str)], &'a str);
    let cases: [Case<'_>; 6] = [
        (
            &[("probe.rs:Listed", Class::Unruled, "a probe")],
            &[("probe.rs:Half", "a probe")],
            "probe.rs:Planted (line 2): every field is `pub` and it has no #[non_exhaustive]",
        ),
        (
            &[
                ("probe.rs:Planted", Class::Unruled, "a probe"),
                ("probe.rs:Listed", Class::Unruled, "a probe"),
                ("probe.rs:Gone", Class::Unruled, "a probe"),
            ],
            &[("probe.rs:Half", "a probe")],
            "probe.rs:Gone: the row names no all-public struct",
        ),
        (
            &[
                ("probe.rs:Planted", Class::Unruled, "a probe"),
                ("probe.rs:Listed", Class::Unruled, "a probe"),
                ("probe.rs:Open", Class::Unruled, "a probe"),
            ],
            &[("probe.rs:Half", "a probe")],
            "probe.rs:Open: attributed and still a row",
        ),
        (
            &[
                ("probe.rs:Planted", Class::Unruled, "a probe"),
                ("probe.rs:Listed", Class::Unruled, "a probe"),
            ],
            &[],
            "probe.rs:Half: `pub` fields [\"b\"] have no `with_<field>`",
        ),
        (
            &[
                ("probe.rs:Planted", Class::Unruled, "a probe"),
                ("probe.rs:Listed", Class::Unruled, "a probe"),
            ],
            &[("probe.rs:Half", "a probe"), ("probe.rs:Open", "a probe")],
            "probe.rs:Open: every field has a setter: remove its ASSIGNED row",
        ),
        (
            &[
                ("probe.rs:Planted", Class::Unruled, "a probe"),
                ("probe.rs:Listed", Class::Record, "it looks like one"),
            ],
            &[("probe.rs:Half", "a probe")],
            "probe.rs:Listed: a Record's reason is its reference record's `path:line`",
        ),
    ];
    for (rows, assigned, words) in cases {
        let got = errors(&found, &refused, &impls, rows, assigned);
        assert_eq!(got.len(), 1, "{words}: {got:?}");
        assert!(got[0].starts_with(words), "{words}: {got:?}");
    }
}
