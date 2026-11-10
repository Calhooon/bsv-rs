//! `ExtendedKey`'s two formatters side by side (the secret Debug fold,
//! 2026-11-10): `Debug` redacts, `Display` is the serialization, which for
//! a private key is the secret.

use super::ExtendedKey;

/// The depth, child number and whether the key is private: never the key,
/// the chain code or the serialization (`tests/secret_debug.rs`).
impl std::fmt::Debug for ExtendedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtendedKey")
            .field("depth", &self.depth)
            .field("child_number", &self.child_number)
            .field("is_private", &self.is_private)
            .finish_non_exhaustive()
    }
}

/// The Base58Check serialization (`xprv`/`tprv` for a private key,
/// `xpub`/`tpub` for a public one): for a private key this reveals the
/// secret, the key and its chain code, so a `{}` of one in a log line writes
/// it; `{:?}` is the redacted form for a log. The explicit conversion, as the
/// reference's `toString` is (`ts-stack@edf6e03` `compat/HD.ts:234`).
impl std::fmt::Display for ExtendedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.serialize())
    }
}
