//! The `Send` rule, held by the compiler on every target (#843, the captain's
//! ruling 1 of 2026-11-17): the future of every method of every public async
//! trait, and of every public `async fn` of this crate, is `Send`, with no
//! `cfg` in a public signature, so a broadcast, a lookup or a wallet call can
//! be spawned on a multi-threaded runtime and awaited inside another `Send`
//! trait's method, on native and on wasm32 alike.
//!
//! Each function below is a witness: it is never called, and it compiles only
//! while the future it hands to [`send`] is `Send`. A witness generic over an
//! implementor (`W: WalletInterface`, `B: Broadcaster + ?Sized`) is checked
//! for every implementor at once, by the trait's signature alone. The module
//! is part of the library, not of its tests, so the wasm32 build of the root
//! `CLAUDE.md`'s rule 6 holds the same claims (a `tests/` file is never built
//! for wasm32: its dev-dependencies do not build there).
//!
//! `tests/arch_send_rule_843.rs` holds the census: every `pub async fn` under
//! `src/`, and every `async fn` of a public `#[async_trait]` trait, is named
//! by a `send(..)` line under the `// src/<file>` heading of its file here,
//! and nothing else is. A door added without its witness fails that test by
//! name.
//!
//! Three doors are generic over a future the caller supplies, and their
//! witnesses say what the signatures say: the door's future is `Send` when
//! the caller's is (`AsyncByteSource::next_chunk`, a static trait with no
//! bound either way, under `AsyncStreamVerifier::run` and
//! `verify_stream_async`; the operation of `with_double_spend_retry`).

// Never called: a witness is its own type check.
#![allow(dead_code)]

#[cfg(feature = "auth")]
mod auth;
#[cfg(feature = "identity")]
mod identity;
#[cfg(feature = "kvstore")]
mod kvstore;
#[cfg(feature = "overlay")]
mod overlay;
#[cfg(feature = "registry")]
mod registry;
#[cfg(feature = "storage")]
mod storage;
mod transaction;
#[cfg(feature = "wallet")]
mod wallet;

/// Hands a witness its arguments. No type implements it: a witness is generic
/// over its source of values, so it is type-checked and never instantiated,
/// and no argument needs constructing.
trait Values {
    /// A value of any type.
    fn any<T>(&self) -> T;
}

/// Compiles only where the future handed to it is `Send`.
fn send<T: Send>(_future: T) {}
