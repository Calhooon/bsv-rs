//! The `Send` rule (#843, the captain's ruling 1 of 2026-11-17): every public
//! async trait is `Send` on every target, with no `cfg` in a public
//! signature, and every public async door's future is `Send`.
//!
//! The compiler holds the claim itself, in `src/send_rule/` (witnesses built
//! with the library on native and on wasm32). This file holds, lexically,
//! what that rests on and what the compiler cannot see:
//!
//! 1. no `?Send` anywhere under `src/` (an `async_trait(?Send)` on a trait or
//!    an implementation, in code or in a doc example);
//! 2. no `cfg` or `cfg_attr` naming a target on a `pub` item, and no
//!    `cfg_attr` around an `async_trait` attribute anywhere;
//! 3. the public async traits are exactly the eight listed, each a plain
//!    `#[async_trait]` with the supertraits listed, and the three object
//!    traits keep `Send + Sync`;
//! 4. every `dyn Future` and `impl Future` written under `src/` carries
//!    `+ Send`, save the listed lines;
//! 5. the census: every `pub async fn` under `src/` and every `async fn` of
//!    the eight traits is named by a `send(..)` line under its file's heading
//!    in `src/send_rule/`, and nothing else is; the witness modules are all
//!    declared, under feature gates alone.
//!
//! Not seen, stated: a `cfg` on a parameter or a field of a `pub` item; a
//! marker trait whose blanket implementations differ by target (rule 2 finds
//! the `cfg` on those implementations only when the item under it is `pub`);
//! a future type spelled through an alias of another crate; whether a
//! witness's argument types are the door's own (the compiler's claim).
#![allow(clippy::expect_used, clippy::panic)] // Source reads are test assertions.

mod arch_support;

use arch_support::{attributes_before, group_end, joined, Source, Token};
use std::collections::{BTreeMap, BTreeSet};

/// The public async traits: file, name, supertraits. A ninth is added here
/// with its witness, never without.
const ASYNC_TRAITS: &[(&str, &str, &str)] = &[
    ("src/auth/transports/http.rs", "Transport", "Send + Sync"),
    (
        "src/auth/transports/socketio/mod.rs",
        "SocketIoFrameSource",
        "Send",
    ),
    (
        "src/overlay/facilitators.rs",
        "OverlayLookupFacilitator",
        "Send + Sync",
    ),
    (
        "src/overlay/facilitators.rs",
        "OverlayBroadcastFacilitator",
        "Send + Sync",
    ),
    (
        "src/transaction/broadcaster.rs",
        "Broadcaster",
        "Send + Sync",
    ),
    (
        "src/transaction/chain_tracker.rs",
        "ChainTracker",
        "Send + Sync",
    ),
    ("src/wallet/interface.rs", "WalletInterface", "Send + Sync"),
    ("src/wallet/wire/mod.rs", "WalletWire", "Send + Sync"),
];

/// The synchronous traits this crate holds as objects beside them: `Send +
/// Sync` on every target, the same rule (the tie-break's reads, 3 of 3).
const OBJECT_TRAITS: &[(&str, &str, &str)] = &[
    (
        "src/auth/transports/socketio/mod.rs",
        "SocketIoSink",
        "Send + Sync",
    ),
    (
        "src/overlay/host_reputation_tracker.rs",
        "ReputationStorage",
        "Send + Sync",
    ),
    ("src/transaction/fee_model.rs", "FeeModel", "Send + Sync"),
];

/// A future written without `+ Send`, each with its reason.
const UNSENT_FUTURES: &[(&str, &str, usize)] = &[
    // A static trait (no object, no `async_trait`): its future's `Send` is
    // its implementor's, and the stream's two doors are `Send` when it is
    // (witnessed with a `Send` source). A `Send` sibling is additive.
    (
        "src/transaction/beef_stream.rs",
        "fn next_chunk(&mut self) -> impl Future<Output = std::io::Result<Option<Vec<u8>>>>;",
        1,
    ),
    // A private helper's argument, a wallet call's own future: `Send` by
    // inference at each call, held by the processor's witness.
    (
        "src/wallet/wire/processor.rs",
        "operation: impl std::future::Future<Output = Result<T, Error>>,",
        1,
    ),
];

/// A `pub async fn` the witnesses cannot name, each with its reason.
const NOT_NAMEABLE: &[(&str, &str)] = &[
    // A method of `PeerState`, `pub(super)` in a private module: reached
    // through `AuthFetch`'s doors alone, which are witnessed.
    ("src/auth/clients/state.rs", "wait_for_certificates"),
];

/// The attributes a witness file may carry: a feature gate of an item that
/// exists only under it. Any other could compile a witness out unseen.
const WITNESS_ATTRIBUTES: &[&str] = &[
    "cfg ( feature = \"http\" )",
    "cfg ( feature = \"socketio\" )",
];

/// The witness modules `src/send_rule.rs` declares, each with its gate.
const WITNESS_MODULES: &[(&str, &str)] = &[
    ("auth", "cfg ( feature = \"auth\" )"),
    ("identity", "cfg ( feature = \"identity\" )"),
    ("kvstore", "cfg ( feature = \"kvstore\" )"),
    ("overlay", "cfg ( feature = \"overlay\" )"),
    ("registry", "cfg ( feature = \"registry\" )"),
    ("storage", "cfg ( feature = \"storage\" )"),
    ("transaction", ""),
    ("wallet", "cfg ( feature = \"wallet\" )"),
];

fn source(path: &str, text: &str) -> Source {
    Source {
        path: path.to_string(),
        text: arch_support::normalize(text),
    }
}

fn is_test_file(path: &str) -> bool {
    path.ends_with("_tests.rs") || path.ends_with("_test.rs") || path.ends_with("/tests.rs")
}

fn is_witness_file(path: &str) -> bool {
    path == "src/send_rule.rs" || path.starts_with("src/send_rule/")
}

// ---------------------------------------------------------------------------
// Rule 1: no `?Send`
// ---------------------------------------------------------------------------

/// Every line that spells `?Send`, in code, in a comment or in a doc example.
fn question_mark_send(source: &Source) -> Vec<String> {
    source
        .text
        .lines()
        .enumerate()
        .filter(|(_, line)| {
            let squeezed: String = line.chars().filter(|c| !c.is_whitespace()).collect();
            squeezed.contains("?Send")
        })
        .map(|(i, line)| {
            format!(
                "{}:{}: `?Send`: every public async trait is `Send` on every target (#843): {}",
                source.path,
                i + 1,
                line.trim()
            )
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Rule 2: no target `cfg` on a public item, no `cfg_attr` around `async_trait`
// ---------------------------------------------------------------------------

/// The attribute that opens at `tokens[hash]` (`#`): its tokens inside the
/// brackets and the index after it; `None` when `#` opens no attribute.
fn attribute_at<'a, 'b>(tokens: &'b [Token<'a>], hash: usize) -> Option<(&'b [Token<'a>], usize)> {
    let inner = tokens.get(hash + 1).is_some_and(|t| t.text == "!");
    let bracket = hash + 1 + usize::from(inner);
    if tokens[hash].text != "#" || tokens.get(bracket).is_none_or(|t| t.text != "[") {
        return None;
    }
    let end = group_end(tokens, bracket);
    Some((&tokens[bracket + 1..end - 1], end))
}

fn names_a_target(attribute: &[Token<'_>]) -> bool {
    attribute
        .iter()
        .any(|t| !t.literal && t.text.starts_with("target_"))
}

fn target_cfg_refusals(source: &Source) -> Vec<String> {
    let tokens = source.raw_tokens();
    let mut out = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        let Some((attribute, end)) = attribute_at(&tokens, i) else {
            i += 1;
            continue;
        };
        let head = attribute.first().map_or("", |t| t.text);
        if head == "cfg_attr" && attribute.iter().any(|t| t.text == "async_trait") {
            out.push(format!(
                "{}:{}: a `cfg_attr` around `async_trait`: one attribute on every target (#843)",
                source.path, tokens[i].line
            ));
        }
        if matches!(head, "cfg" | "cfg_attr") && names_a_target(attribute) {
            // Past the item's other attributes, to its visibility.
            let mut at = end;
            while let Some((_, next)) = tokens.get(at).and_then(|_| attribute_at(&tokens, at)) {
                at = next;
            }
            let public = tokens.get(at).is_some_and(|t| t.text == "pub")
                && tokens.get(at + 1).is_none_or(|t| t.text != "(");
            if public {
                out.push(format!(
                    "{}:{}: a target `cfg` on a `pub` item: no `cfg` in a public signature (#843)",
                    source.path, tokens[i].line
                ));
            }
        }
        i = end;
    }
    out
}

// ---------------------------------------------------------------------------
// Rule 3: the traits
// ---------------------------------------------------------------------------

struct PublicTrait {
    name: String,
    line: usize,
    supertraits: String,
    attributes: Vec<String>,
    /// The names of the `async fn`s of its body.
    async_methods: Vec<String>,
}

fn public_traits(source: &Source) -> Vec<PublicTrait> {
    let tokens = source.tokens_with_attributes();
    let mut out = Vec::new();
    for at in 0..tokens.len() {
        if tokens[at].text != "trait" || at == 0 || tokens[at - 1].text != "pub" {
            continue;
        }
        let Some(open) = (at..tokens.len()).find(|&k| tokens[k].text == "{") else {
            continue;
        };
        let colon = (at..open).find(|&k| tokens[k].text == ":");
        let supertraits = colon.map_or(String::new(), |c| joined(&tokens[c + 1..open]));
        let body = &tokens[open..group_end(&tokens, open)];
        let async_methods = body
            .windows(3)
            .filter(|w| w[0].text == "async" && w[1].text == "fn")
            .map(|w| w[2].text.to_string())
            .collect();
        out.push(PublicTrait {
            name: tokens[at + 1].text.to_string(),
            line: tokens[at].line,
            supertraits,
            attributes: attributes_before(&tokens, at),
            async_methods,
        });
    }
    out
}

fn trait_refusals(sources: &[Source]) -> Vec<String> {
    let mut out = Vec::new();
    let mut found: BTreeSet<(String, String)> = BTreeSet::new();
    for source in sources {
        for item in public_traits(source) {
            let listed = ASYNC_TRAITS
                .iter()
                .chain(OBJECT_TRAITS)
                .find(|(file, name, _)| *file == source.path && *name == item.name);
            let is_async = !item.async_methods.is_empty();
            let Some((_, _, supertraits)) = listed else {
                if is_async {
                    out.push(format!(
                        "{}:{}: `{}` is a public async trait outside ASYNC_TRAITS: list it with \
                         its supertraits and add its witness to src/send_rule/",
                        source.path, item.line, item.name
                    ));
                }
                continue;
            };
            found.insert((source.path.clone(), item.name.clone()));
            if item.supertraits != *supertraits {
                out.push(format!(
                    "{}:{}: `{}: {}`, where the rule holds `{}` on every target",
                    source.path, item.line, item.name, item.supertraits, supertraits
                ));
            }
            let listed_async = ASYNC_TRAITS
                .iter()
                .any(|(file, name, _)| *file == source.path && *name == item.name);
            if listed_async != is_async {
                out.push(format!(
                    "{}:{}: `{}` is listed on the wrong list (async: {is_async})",
                    source.path, item.line, item.name
                ));
            }
            let plain = item
                .attributes
                .iter()
                .filter(|a| a.contains("async_trait"))
                .collect::<Vec<_>>();
            let expected = is_async
                && plain.len() == 1
                && matches!(
                    plain[0].as_str(),
                    "async_trait" | "async_trait :: async_trait"
                );
            if is_async && !expected {
                out.push(format!(
                    "{}:{}: `{}` carries {:?}, where the rule holds one plain `#[async_trait]`",
                    source.path, item.line, item.name, item.attributes
                ));
            }
        }
    }
    for (file, name, _) in ASYNC_TRAITS.iter().chain(OBJECT_TRAITS) {
        if !found.contains(&((*file).to_string(), (*name).to_string())) {
            out.push(format!(
                "{file}: the listed trait `{name}` is not there; move or delete the entry"
            ));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Rule 4: a future written under `src/` is `Send`
// ---------------------------------------------------------------------------

/// Each `dyn Future<..>` or `impl Future<..>` not followed by `+ Send`: the
/// file, the line and the line's text.
fn unsent_futures(source: &Source) -> Vec<(String, usize, String)> {
    let tokens = source.tokens();
    let mut out = Vec::new();
    for at in 0..tokens.len() {
        if tokens[at].text != "Future" || tokens[at].literal {
            continue;
        }
        // `dyn Future`, `impl std::future::Future`: back over the path.
        let mut head = at;
        while head >= 2 && tokens[head - 1].text == "::" {
            head -= 2;
        }
        if head == 0 || !matches!(tokens[head - 1].text, "dyn" | "impl") {
            continue;
        }
        let mut after = at + 1;
        if tokens.get(after).is_some_and(|t| t.text == "<") {
            let mut depth = 0usize;
            while after < tokens.len() {
                match tokens[after].text {
                    "<" => depth += 1,
                    ">" if tokens[after - 1].text != "-" => {
                        depth -= 1;
                        if depth == 0 {
                            after += 1;
                            break;
                        }
                    }
                    _ => {}
                }
                after += 1;
            }
        }
        let sent = tokens.get(after).is_some_and(|t| t.text == "+")
            && tokens.get(after + 1).is_some_and(|t| t.text == "Send");
        if !sent {
            out.push((
                source.path.clone(),
                tokens[at].line,
                source.line(tokens[at].line).to_string(),
            ));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Rule 5: the census
// ---------------------------------------------------------------------------

/// The doors of one file: every `pub async fn` and, for a listed async
/// trait, every `async fn` of its body. A name once, whatever `cfg`
/// alternates the file writes it under.
fn doors(source: &Source) -> BTreeSet<String> {
    let tokens = source.tokens();
    let mut out: BTreeSet<String> = tokens
        .windows(4)
        .filter(|w| w[0].text == "pub" && w[1].text == "async" && w[2].text == "fn")
        .map(|w| w[3].text.to_string())
        .collect();
    for item in public_traits(source) {
        out.extend(item.async_methods);
    }
    out
}

/// The doors a witness file names, by the `// src/<file>` heading above each
/// `send(..)` line: the identifier before the call's opening parenthesis.
fn witnessed(source: &Source) -> Result<BTreeMap<String, BTreeSet<String>>, String> {
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut heading: Option<String> = None;
    let mut code = String::new();
    let flush = |heading: &Option<String>,
                 code: &mut String,
                 out: &mut BTreeMap<String, BTreeSet<String>>|
     -> Result<(), String> {
        let text = std::mem::take(code);
        let mut rest = text.as_str();
        while let Some(found) = rest.find("send(") {
            let boundary = rest[..found]
                .chars()
                .next_back()
                .is_none_or(|c| !(c.is_alphanumeric() || c == '_' || c == '.' || c == ':'));
            let call = &rest[found + "send(".len()..];
            rest = call;
            if !boundary {
                continue;
            }
            let Some(open) = call.find('(') else {
                return Err(format!("{}: a `send(` with no call inside", source.path));
            };
            let head: String = call[..open]
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            let name: String = head
                .chars()
                .rev()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            let receiver = &head[..head.len() - name.len()];
            let plain = receiver
                .chars()
                .all(|c| c.is_alphanumeric() || matches!(c, '_' | '.' | ':'));
            if name.is_empty() || !plain {
                return Err(format!(
                    "{}: `send({head}(` is no `receiver.door(`, `Type::door(` or `door(`",
                    source.path
                ));
            }
            let Some(file) = heading else {
                return Err(format!(
                    "{}: `send({head}(..)` stands under no `// src/<file>` heading",
                    source.path
                ));
            };
            out.entry(file.clone()).or_default().insert(name);
        }
        Ok(())
    };
    for line in source.text.lines() {
        let trimmed = line.trim();
        if let Some(comment) = trimmed.strip_prefix("//") {
            let comment = comment.trim();
            if trimmed.starts_with("// src/") && comment.ends_with(".rs") && !comment.contains(' ')
            {
                flush(&heading, &mut code, &mut out)?;
                heading = Some(comment.to_string());
            }
            continue;
        }
        code.push_str(line);
        code.push('\n');
    }
    flush(&heading, &mut code, &mut out)?;
    Ok(out)
}

fn census_refusals(sources: &[Source]) -> Vec<String> {
    let mut out = Vec::new();
    let mut expected: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut named: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for source in sources {
        if source.path.starts_with("src/send_rule/") {
            match witnessed(source) {
                Ok(found) => {
                    for (file, names) in found {
                        named.entry(file).or_default().extend(names);
                    }
                }
                Err(refusal) => out.push(refusal),
            }
        } else if !is_witness_file(&source.path) && !is_test_file(&source.path) {
            let found = doors(source);
            if !found.is_empty() {
                expected.insert(source.path.clone(), found);
            }
        }
    }
    for (file, name) in NOT_NAMEABLE {
        let removed = expected
            .get_mut(*file)
            .is_some_and(|names| names.remove(*name));
        if !removed {
            out.push(format!(
                "{file}: NOT_NAMEABLE lists `{name}`, which is no `pub async fn` there; delete \
                 the entry"
            ));
        }
        if expected.get(*file).is_some_and(BTreeSet::is_empty) {
            expected.remove(*file);
        }
    }
    for (file, names) in &expected {
        for name in names {
            if !named.get(file).is_some_and(|n| n.contains(name)) {
                out.push(format!(
                    "{file}: the public async door `{name}` has no witness: add \
                     `send(<receiver>.{name}(..));` under `// {file}` in src/send_rule/ (#843)"
                ));
            }
        }
    }
    for (file, names) in &named {
        for name in names {
            if !expected.get(file).is_some_and(|n| n.contains(name)) {
                out.push(format!(
                    "src/send_rule/: a witness names `{name}` under `// {file}`, which holds no \
                     such public async door; move or delete the line"
                ));
            }
        }
    }
    out
}

/// The witness modules are all compiled: each file of `src/send_rule/`
/// declared by `src/send_rule.rs` under its feature gate alone, the root
/// declared by `src/lib.rs` under `transaction`, and no attribute inside a
/// witness file but a feature gate of the listed ones.
fn module_refusals(sources: &[Source]) -> Vec<String> {
    let mut out = Vec::new();
    let by_path = |path: &str| sources.iter().find(|s| s.path == path);
    let declared = |source: &Source, name: &str| -> Option<Vec<String>> {
        let tokens = source.raw_tokens();
        (0..tokens.len())
            .find(|&at| {
                tokens[at].text == "mod"
                    && tokens.get(at + 1).is_some_and(|t| t.text == name)
                    && tokens.get(at + 2).is_some_and(|t| t.text == ";")
            })
            .map(|at| attributes_before(&tokens, at))
    };
    match by_path("src/lib.rs").and_then(|lib| declared(lib, "send_rule")) {
        Some(attributes) if attributes == ["cfg ( feature = \"transaction\" )"] => {}
        other => out.push(format!(
            "src/lib.rs: `mod send_rule;` under {other:?}, where the witnesses are built under \
             `transaction` alone"
        )),
    }
    let Some(root) = by_path("src/send_rule.rs") else {
        return vec!["src/send_rule.rs is gone: the rule's witnesses (#843)".to_string()];
    };
    let files: BTreeSet<String> = sources
        .iter()
        .filter_map(|s| s.path.strip_prefix("src/send_rule/"))
        .map(|name| name.trim_end_matches(".rs").to_string())
        .collect();
    let listed: BTreeSet<String> = WITNESS_MODULES
        .iter()
        .map(|(m, _)| (*m).to_string())
        .collect();
    if files != listed {
        out.push(format!(
            "src/send_rule/ holds {files:?}, where WITNESS_MODULES lists {listed:?}"
        ));
    }
    for (module, gate) in WITNESS_MODULES {
        let expected: Vec<String> = if gate.is_empty() {
            Vec::new()
        } else {
            vec![(*gate).to_string()]
        };
        match declared(root, module) {
            Some(attributes) if attributes == expected => {}
            other => out.push(format!(
                "src/send_rule.rs: `mod {module};` under {other:?}, where it is declared under \
                 {expected:?}"
            )),
        }
    }
    for source in sources
        .iter()
        .filter(|s| s.path.starts_with("src/send_rule/"))
    {
        let tokens = source.raw_tokens();
        let mut i = 0;
        while i < tokens.len() {
            let Some((attribute, end)) = attribute_at(&tokens, i) else {
                i += 1;
                continue;
            };
            let text = joined(attribute);
            if !WITNESS_ATTRIBUTES.contains(&text.as_str()) {
                out.push(format!(
                    "{}:{}: `#[{text}]` in a witness file: only {WITNESS_ATTRIBUTES:?} may stand \
                     there",
                    source.path, tokens[i].line
                ));
            }
            i = end;
        }
    }
    out
}

// ---------------------------------------------------------------------------
// The tree
// ---------------------------------------------------------------------------

#[test]
fn no_public_async_trait_is_question_mark_send_843() {
    let refusals: Vec<String> = arch_support::sources()
        .iter()
        .flat_map(question_mark_send)
        .collect();
    assert!(refusals.is_empty(), "{}", refusals.join("\n"));
}

#[test]
fn no_cfg_stands_on_a_public_async_signature_843() {
    let refusals: Vec<String> = arch_support::sources()
        .iter()
        .flat_map(target_cfg_refusals)
        .collect();
    assert!(refusals.is_empty(), "{}", refusals.join("\n"));
}

#[test]
fn the_eight_async_traits_are_plain_async_trait_under_send_supertraits_843() {
    let refusals = trait_refusals(&arch_support::sources());
    assert!(refusals.is_empty(), "{}", refusals.join("\n"));
}

#[test]
fn every_future_written_in_a_signature_is_send_843() {
    let sites: Vec<(String, usize, String)> = arch_support::sources()
        .iter()
        .filter(|s| !is_witness_file(&s.path) && !is_test_file(&s.path))
        .flat_map(unsent_futures)
        .collect();
    arch_support::check_sites("future without `+ Send` (#843)", &sites, UNSENT_FUTURES);
}

#[test]
fn every_public_async_door_has_its_send_witness_843() {
    let sources = arch_support::sources();
    let mut refusals = census_refusals(&sources);
    refusals.extend(module_refusals(&sources));
    assert!(refusals.is_empty(), "{}", refusals.join("\n"));
    // The census is not empty: the reader reads.
    let doors: usize = sources
        .iter()
        .filter(|s| !is_witness_file(&s.path) && !is_test_file(&s.path))
        .map(|s| doors(s).len())
        .sum();
    assert!(doors >= 200, "only {doors} public async doors were read");
}

// ---------------------------------------------------------------------------
// Each refusal, on a planted text
// ---------------------------------------------------------------------------

#[test]
fn a_planted_question_mark_send_is_refused_843() {
    for text in [
        "#[async_trait(?Send)]\npub trait Broadcaster: Send + Sync {}\n",
        "#[async_trait::async_trait(?Send)]\nimpl Broadcaster for Mine {}\n",
        "#[async_trait( ? Send )]\nimpl Broadcaster for Mine {}\n",
        "/// #[async_trait(?Send)]\n/// impl Broadcaster for Mine {}\npub trait X {}\n",
    ] {
        let refusals = question_mark_send(&source("src/planted.rs", text));
        assert_eq!(refusals.len(), 1, "{text}: {refusals:?}");
        assert!(refusals[0].starts_with("src/planted.rs:1: `?Send`"));
    }
    let plain = "#[async_trait]\npub trait Broadcaster: Send + Sync {}\nfn f<T: ?Sized>() {}\n";
    assert!(question_mark_send(&source("src/planted.rs", plain)).is_empty());
}

#[test]
fn a_planted_target_cfg_on_a_public_item_is_refused_843() {
    let refused = [
        // the per-target rule the tie-break ruled out, in its three spellings
        "#[cfg_attr(target_arch = \"wasm32\", async_trait(?Send))]\n\
         #[cfg_attr(not(target_arch = \"wasm32\"), async_trait)]\npub trait ChainTracker {}\n",
        "#[cfg(target_arch = \"wasm32\")]\npub trait ChainTracker {}\n",
        "#[cfg(not(target_arch = \"wasm32\"))]\n#[async_trait]\npub trait ChainTracker: Send {}\n",
        "#[cfg(target_family = \"wasm\")]\npub type TransportCallback = dyn Fn();\n",
        "#[cfg(all(target_arch = \"wasm32\", feature = \"wasm\"))]\npub async fn door() {}\n",
        // a feature in place of the target, around the attribute
        "#[cfg_attr(feature = \"wasm\", async_trait(?Send))]\nimpl ChainTracker for Mine {}\n",
    ];
    for text in refused {
        let refusals = target_cfg_refusals(&source("src/planted.rs", text));
        assert!(!refusals.is_empty(), "{text}");
    }
    let allowed = [
        // a private bridge, as `util::time` and `auth::peer` carry
        "#[cfg(all(target_arch = \"wasm32\", feature = \"wasm\"))]\npub(crate) fn now() {}\n",
        "#[cfg(not(target_arch = \"wasm32\"))]\nfn not_connected() {}\n",
        "#[cfg(feature = \"http\")]\npub async fn door() {}\n",
        "#[cfg_attr(not(feature = \"http\"), allow(dead_code))]\npub fn door() {}\n",
    ];
    for text in allowed {
        let refusals = target_cfg_refusals(&source("src/planted.rs", text));
        assert!(refusals.is_empty(), "{text}: {refusals:?}");
    }
}

#[test]
fn a_planted_trait_off_the_rule_is_refused_843() {
    let tree = |broadcaster: &str| -> Vec<Source> {
        let mut sources: Vec<Source> = arch_support::sources()
            .into_iter()
            .filter(|s| s.path != "src/transaction/broadcaster.rs")
            .collect();
        sources.push(source("src/transaction/broadcaster.rs", broadcaster));
        sources
    };
    let plain =
        "#[async_trait]\npub trait Broadcaster: Send + Sync {\n    async fn broadcast(&self);\n}\n";
    assert_eq!(trait_refusals(&tree(plain)), Vec::<String>::new());
    for (text, needle) in [
        (
            "#[async_trait(?Send)]\npub trait Broadcaster: Send + Sync {\n    async fn broadcast(&self);\n}\n",
            "one plain `#[async_trait]`",
        ),
        (
            "#[async_trait]\npub trait Broadcaster {\n    async fn broadcast(&self);\n}\n",
            "`Broadcaster: `, where the rule holds `Send + Sync`",
        ),
        (
            "#[async_trait]\npub trait Broadcaster: MaybeSend + MaybeSync {\n    async fn broadcast(&self);\n}\n",
            "where the rule holds `Send + Sync`",
        ),
        (
            "pub trait Broadcaster: Send + Sync {\n    fn broadcast(&self);\n}\n",
            "listed on the wrong list",
        ),
        ("pub struct Broadcaster;\n", "is not there"),
        (
            "#[async_trait]\npub trait Broadcaster: Send + Sync {\n    async fn broadcast(&self);\n}\n\
             #[async_trait]\npub trait Ninth: Send + Sync {\n    async fn door(&self);\n}\n",
            "`Ninth` is a public async trait outside ASYNC_TRAITS",
        ),
    ] {
        let refusals = trait_refusals(&tree(text));
        assert!(
            refusals.iter().any(|r| r.contains(needle)),
            "{text}: {refusals:?}"
        );
    }
}

#[test]
fn a_planted_future_without_send_is_refused_843() {
    let unsent = [
        "pub type InterpreterFn<T> = Box<dyn Fn() -> Pin<Box<dyn Future<Output = Option<T>>>> + Send + Sync>;\n",
        "pub type Callback = dyn Fn() -> Pin<Box<dyn std::future::Future<Output = ()>>>;\n",
        "pub fn door() -> impl Future<Output = u8> { ready(1) }\n",
        "pub fn door() -> impl core::future::Future<Output = Box<dyn Fn() -> u8>> + 'static { f() }\n",
    ];
    for text in unsent {
        let sites = unsent_futures(&source("src/planted.rs", text));
        assert_eq!(sites.len(), 1, "{text}");
    }
    let sent = [
        "pub type Callback = dyn Fn() -> Pin<Box<dyn Future<Output = Result<()>> + Send>>;\n",
        "pub fn door(&self) -> impl Future<Output = Result<u8>> + Send + '_ { f() }\n",
        "use std::future::Future;\nfn f<F: Future>(_: F) {}\n",
    ];
    for text in sent {
        let sites = unsent_futures(&source("src/planted.rs", text));
        assert!(sites.is_empty(), "{text}: {sites:?}");
    }
}

#[test]
fn a_planted_door_without_its_witness_is_refused_843() {
    let door = |text: &str| source("src/overlay/planted.rs", text);
    let witness = |text: &str| source("src/send_rule/overlay.rs", text);
    let census = |door: Source, witness: Source| {
        // NOT_NAMEABLE's own file beside them, so its entry is not stale here
        let state = source(
            "src/auth/clients/state.rs",
            "impl PeerState {\n    pub async fn wait_for_certificates(&self) {}\n}\n",
        );
        census_refusals(&[door, witness, state])
    };
    let two = "impl Resolver {\n    pub async fn query(&self) {}\n    #[cfg(feature = \"http\")]\n    \
               pub async fn fetch(&self) {}\n    #[cfg(not(feature = \"http\"))]\n    pub async fn \
               fetch(&self) {}\n    pub(crate) async fn private(&self) {}\n    async fn inner(&self) {}\n}\n";
    let both = "// src/overlay/planted.rs\nfn w<V: Values>(v: &V) {\n    let r = v.any::<&Resolver>();\n    \
                send(r.query());\n    send(\n        r.fetch(),\n    );\n}\n";
    assert_eq!(census(door(two), witness(both)), Vec::<String>::new());

    // a door added with no witness
    let three = format!("{two}impl Resolver {{\n    pub async fn added(&self) {{}}\n}}\n");
    let refusals = census(door(&three), witness(both));
    assert_eq!(refusals.len(), 1, "{refusals:?}");
    assert!(refusals[0].contains("the public async door `added` has no witness"));

    // a witness line removed
    let one = both.replace("    send(r.query());\n", "");
    let refusals = census(door(two), witness(&one));
    assert_eq!(refusals.len(), 1, "{refusals:?}");
    assert!(refusals[0].contains("`query` has no witness"));

    // a witness under another file's heading, or under none
    let elsewhere = both.replace("// src/overlay/planted.rs", "// src/overlay/other.rs");
    let refusals = census(door(two), witness(&elsewhere));
    assert_eq!(refusals.len(), 4, "{refusals:?}");
    let headless = both.replace("// src/overlay/planted.rs\n", "");
    let refusals = census(door(two), witness(&headless));
    assert!(refusals
        .iter()
        .any(|r| r.contains("under no `// src/<file>` heading")));

    // a witness for a door that is gone, and one commented out
    let stale = both.replace("send(r.query());", "send(r.query());\n    send(r.gone());");
    let refusals = census(door(two), witness(&stale));
    assert_eq!(refusals.len(), 1, "{refusals:?}");
    assert!(refusals[0].contains("a witness names `gone`"));
    let commented = both.replace("    send(r.query());", "    // send(r.query());");
    let refusals = census(door(two), witness(&commented));
    assert!(refusals
        .iter()
        .any(|r| r.contains("`query` has no witness")));

    // a call the reader cannot name
    let wrapped = both.replace("send(r.query());", "send(wrap(r).query());");
    let refusals = census(door(two), witness(&wrapped));
    assert!(
        refusals.iter().any(|r| r.contains("has no witness")),
        "{refusals:?}"
    );

    // a trait's methods are doors of its file
    let methods = doors(&source(
        "src/planted.rs",
        "#[async_trait]\npub trait Tracker: Send + Sync {\n    async fn height(&self) -> u32;\n    \
         fn sync(&self);\n}\n",
    ));
    assert_eq!(methods.into_iter().collect::<Vec<_>>(), ["height"]);
}

#[test]
fn a_planted_witness_compiled_out_is_refused_843() {
    let sources = arch_support::sources();
    assert_eq!(module_refusals(&sources), Vec::<String>::new());
    let with = |path: &str, edit: &dyn Fn(&str) -> String| -> Vec<Source> {
        sources
            .iter()
            .map(|s| {
                if s.path == path {
                    source(&s.path, &edit(&s.text))
                } else {
                    source(&s.path, &s.text)
                }
            })
            .collect()
    };
    // a witness under a `cfg` that never holds
    let planted = with("src/send_rule/overlay.rs", &|text| {
        text.replacen("\nfn resolver<", "\n#[cfg(any())]\nfn resolver<", 1)
    });
    let refusals = module_refusals(&planted);
    assert_eq!(refusals.len(), 1, "{refusals:?}");
    assert!(refusals[0].contains("`#[cfg ( any ( ) )]` in a witness file"));
    // a witness module no longer declared, or declared under a target
    let planted = with("src/send_rule.rs", &|text| {
        text.replacen("mod overlay;", "// mod overlay;", 1)
    });
    assert!(module_refusals(&planted)
        .iter()
        .any(|r| r.contains("`mod overlay;` under None")));
    let planted = with("src/send_rule.rs", &|text| {
        text.replacen(
            "mod transaction;",
            "#[cfg(not(target_arch = \"wasm32\"))]\nmod transaction;",
            1,
        )
    });
    assert!(module_refusals(&planted)
        .iter()
        .any(|r| r.contains("`mod transaction;` under Some")));
    // the root out of the library, or under a `cfg` of its own
    let planted = with("src/lib.rs", &|text| {
        text.replacen("mod send_rule;", "// mod send_rule;", 1)
    });
    assert!(module_refusals(&planted)
        .iter()
        .any(|r| r.contains("`mod send_rule;` under None")));
    let planted = with("src/lib.rs", &|text| {
        text.replacen("mod send_rule;", "#[cfg(test)]\nmod send_rule;", 1)
    });
    assert!(module_refusals(&planted)
        .iter()
        .any(|r| r.contains("`mod send_rule;` under Some")));
}
