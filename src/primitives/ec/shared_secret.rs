//! The ECDH shared secret (#843, the freeze plan's row 6).
//!
//! `PrivateKey::derive_shared_secret`, `PublicKey::derive_shared_secret` and
//! the key derivers' `reveal_counterparty_secret` return a [`SharedSecret`],
//! a type this crate owns, whose `Debug` prints no secret and which has no
//! `Display`, `Hash`, serde or conversion into a [`PublicKey`]: the secret
//! leaves only through a door a caller names.

use super::PublicKey;

/// The ECDH shared secret: the point `a * B = b * A` two parties derive from
/// one's private key and the other's public key.
///
/// It is secret material: BRC-42 keys its HMAC with its 33 compressed bytes,
/// and its x coordinate is a symmetric key. It is read only through three
/// doors, each of which reveals it: [`to_compressed`](Self::to_compressed),
/// [`x`](Self::x) and [`to_point`](Self::to_point) (whose [`PublicKey`]
/// prints the point under `Debug` and `Display`). `{:?}` and `{:#?}` write
/// `SharedSecret { .. }`; equality is constant time over the compressed
/// bytes. Only the derivation doors make one: there is no public constructor.
///
/// The point is not wiped from memory on drop.
///
/// What it does not offer, by the compiler:
///
/// ```compile_fail
/// use bsv_rs::primitives::ec::PrivateKey;
/// let a = PrivateKey::random();
/// let s = a.derive_shared_secret(&PrivateKey::random().public_key()).unwrap();
/// let _ = format!("{s}"); // no Display
/// ```
///
/// ```compile_fail
/// use bsv_rs::primitives::ec::PrivateKey;
/// let a = PrivateKey::random();
/// let s = a.derive_shared_secret(&PrivateKey::random().public_key()).unwrap();
/// let mut set = std::collections::HashSet::new();
/// set.insert(s); // no Hash
/// ```
///
/// ```compile_fail
/// use bsv_rs::primitives::ec::PrivateKey;
/// let a = PrivateKey::random();
/// let s = a.derive_shared_secret(&PrivateKey::random().public_key()).unwrap();
/// let _ = serde_json::to_string(&s); // no Serialize
/// ```
///
/// ```compile_fail
/// use bsv_rs::primitives::ec::{PrivateKey, PublicKey};
/// fn takes(_: &PublicKey) {}
/// let a = PrivateKey::random();
/// let s = a.derive_shared_secret(&PrivateKey::random().public_key()).unwrap();
/// takes(&s); // not a PublicKey; name `s.to_point()`
/// ```
///
/// Nor can a caller build one: the field is private (E0451). Stable rustdoc
/// does not check the error number, so this block would also pass for a
/// misspelt path, a missing import or a field of another name; the block
/// after it is the same lines without the struct expression, and compiles,
/// and `tests/arch_shared_secret_843d6.rs` refuses a `pub` field by any name.
///
/// ```compile_fail
/// use bsv_rs::primitives::ec::{PrivateKey, PublicKey, SharedSecret};
/// let point: PublicKey = PrivateKey::random().public_key();
/// let built: SharedSecret = SharedSecret { point }; // private field
/// let _ = built.to_compressed();
/// ```
///
/// ```
/// use bsv_rs::primitives::ec::{PrivateKey, PublicKey, SharedSecret};
/// let point: PublicKey = PrivateKey::random().public_key();
/// let built: SharedSecret = PrivateKey::random().derive_shared_secret(&point).unwrap();
/// let _ = built.to_compressed();
/// ```
#[derive(Clone)]
pub struct SharedSecret {
    point: PublicKey,
}

impl SharedSecret {
    /// Wraps the result of a derivation door (crate-only: no caller builds a
    /// `SharedSecret` from a point).
    pub(crate) fn from_point(point: PublicKey) -> Self {
        Self { point }
    }

    /// The secret's 33 compressed SEC1 bytes (BRC-42's HMAC key). Reveals
    /// the secret.
    pub fn to_compressed(&self) -> [u8; 33] {
        self.point.to_compressed()
    }

    /// The secret's x coordinate, 32 bytes big-endian (a symmetric key in
    /// the wallet's encryption and in ECIES). Reveals the secret.
    pub fn x(&self) -> [u8; 32] {
        self.point.x()
    }

    /// The secret as a [`PublicKey`] (for point arithmetic or a Schnorr
    /// proof's `S`). Reveals the secret: the returned key prints the point
    /// under `Debug`, `Display` and serde.
    pub fn to_point(&self) -> PublicKey {
        self.point.clone()
    }
}

impl std::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SharedSecret { .. }")
    }
}

impl PartialEq for SharedSecret {
    fn eq(&self, other: &Self) -> bool {
        // Constant-time comparison, as `PrivateKey`'s.
        use subtle::ConstantTimeEq;
        self.to_compressed().ct_eq(&other.to_compressed()).into()
    }
}

impl Eq for SharedSecret {}
