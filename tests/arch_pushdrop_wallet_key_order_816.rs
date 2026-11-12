//! One door orders a wallet PushDrop lock's two calls (#816): the public
//! `PushDrop::lock_with_wallet` (`src/script/templates/pushdrop_wallet.rs`,
//! #782) asks the wallet's key, reads its text and only then asks the
//! signature, as the reference's `PushDrop.lock` does (`ts-stack@edf6e03`
//! `PushDrop.ts:155-163`, `:166-172`, `:173-185`). The crate-visible helper
//! `wallet_key_lock` reads the key text where its caller put it, so a site
//! that asks its own signature and then calls the helper judges the key text
//! after a `createSignature` the reference never makes for a text that is
//! not hex: the order four sites had until #816.
//!
//! This test refuses `wallet_key_lock` named anywhere under `src/` but its
//! definition and `src/kvstore/global_actions.rs`, the global key-value
//! store, whose signature-before-key order is #343's stated residue (the
//! root `CLAUDE.md`'s #343 row: `token_lock` calling createSignature before
//! getPublicKey). It refuses `read_wallet_key`, the read the door is built
//! on, anywhere but its definition's file and the door's. A sixth site fails
//! here by its `file:line`.
//!
//! What it cannot see: a site that asks `get_public_key` and
//! `create_signature` itself and reads the key by another parser. The scan
//! is lexical (`arch_support`): comments and string literals supply no site,
//! a `#[cfg(test)]` item is skipped.
#![allow(clippy::expect_used, clippy::panic)] // Source reads are test assertions.

mod arch_support;

/// Where `wallet_key_lock` and `read_wallet_key` are defined.
const DEFINITION: &str = "src/script/templates/pushdrop_key_bytes.rs";
/// The public door, the one caller of `read_wallet_key`.
const DOOR: &str = "src/script/templates/pushdrop_wallet.rs";
/// #343's stated site: the global store asks its signature before its key.
const STATED_343: &str = "src/kvstore/global_actions.rs";

/// Every non-literal naming of `name` under `src/`, as `(path, line)`.
fn named(name: &str) -> Vec<(String, usize)> {
    let mut out = Vec::new();
    for source in arch_support::sources() {
        for token in source.tokens() {
            if !token.literal && token.text == name {
                out.push((source.path.clone(), token.line));
            }
        }
    }
    out
}

fn count(sites: &[(String, usize)], path: &str) -> usize {
    sites.iter().filter(|(at, _)| at == path).count()
}

#[test]
fn the_wallet_key_lock_helper_has_one_stated_caller_816() {
    let sites = named("wallet_key_lock");
    let stray: Vec<String> = sites
        .iter()
        .filter(|(path, _)| path != DEFINITION && path != STATED_343)
        .map(|(path, line)| format!("{path}:{line}"))
        .collect();
    assert!(
        stray.is_empty(),
        "`wallet_key_lock` is named outside {DEFINITION} and {STATED_343} (#343's stated \
         residue): lock through `PushDrop::lock_with_wallet`, which reads the key text \
         before any signature is asked (#816):\n{}",
        stray.join("\n")
    );
    // The rule names the right files: the definition once, the stated
    // caller's import and its one call.
    assert_eq!(count(&sites, DEFINITION), 1, "{DEFINITION}: {sites:?}");
    assert_eq!(count(&sites, STATED_343), 2, "{STATED_343}: {sites:?}");

    let reads = named("read_wallet_key");
    let stray: Vec<String> = reads
        .iter()
        .filter(|(path, _)| path != DEFINITION && path != DOOR)
        .map(|(path, line)| format!("{path}:{line}"))
        .collect();
    assert!(
        stray.is_empty(),
        "`read_wallet_key` is named outside {DEFINITION} and {DOOR}: the door alone \
         orders the read before the signature (#816):\n{}",
        stray.join("\n")
    );
    // The door reads the key text: its import and its one read.
    assert_eq!(count(&reads, DOOR), 2, "{DOOR}: {reads:?}");
}
