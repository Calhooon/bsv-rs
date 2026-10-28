//! BRC-56 HMAC issuance and verification (#379).
//!
//! BRCs PR 362 (`d4ce8119f`, `wallet/0056.md`) specifies the child-key ECDH
//! X coordinate as minimal-length unsigned big-endian bytes, without another
//! hash. Zero retains one zero octet. This is the issuance and strict
//! verification of ts-stack PR 1423 (`9a2787b8c`). AES-GCM retains 32 bytes.
//! By the owner's 19.5 (a) of 2026-10-28, this crate also accepts a tag under
//! the former 32-byte key on a miss, named and counted as legacy. A store
//! without pre-amendment tags should use [`HmacVerifyPolicy::MinimalLengthOnly`].

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use subtle::ConstantTimeEq;

use crate::error::{Error, Result};
use crate::primitives::hash::sha256_hmac;
use crate::primitives::SymmetricKey;

use super::key_args::VerifyHmacArgs;
use super::types::Counterparty;
use super::{KeyDeriverApi, ProtoWallet};

/// The key encoding a verified HMAC tag was made under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HmacKeyEncoding {
    /// The amended BRC-56 key: minimal-length unsigned big-endian X
    /// coordinate. A key with no leading zero octet has this encoding only.
    MinimalLength,
    /// The pre-amendment 32-byte key, accepted on a miss of the standard tag
    /// under [`HmacVerifyPolicy::BothEncodings`] and counted as legacy.
    Legacy {
        /// The leading zero octets retained by the legacy key.
        leading_zero_bytes: usize,
    },
}

/// Which HMAC key encodings [`ProtoWallet::verify_hmac`] accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum HmacVerifyPolicy {
    /// The standard minimal-length key's tag, then the legacy 32-byte key's
    /// tag on a miss (the default, the owner's 19.5 (a)).
    #[default]
    BothEncodings,
    /// The amended BRC-56 and ts-stack PR 1423 verifier. Use for a store
    /// without pre-amendment tags; a legacy tag is [`Error::HmacLegacyKey`].
    MinimalLengthOnly,
}

/// BRC-56's serialization, distinct from BRC-2's fixed-width AES-GCM key.
pub(crate) fn minimal_length_key(key: &SymmetricKey) -> &[u8] {
    let bytes = key.as_bytes();
    let omitted = bytes
        .iter()
        .take_while(|b| **b == 0)
        .count()
        .min(bytes.len() - 1);
    &bytes[omitted..]
}

/// A wallet's HMAC verification policy and legacy acceptance count,
/// shared by its clones.
#[derive(Debug, Clone, Default)]
pub(crate) struct HmacVerifier {
    policy: HmacVerifyPolicy,
    legacy_acceptances: Arc<AtomicU64>,
}

impl HmacVerifier {
    /// Both tags are always computed and compared in constant time, even
    /// under the strict policy. When both match, the standard wins.
    pub(crate) fn verify(
        &self,
        key: &SymmetricKey,
        data: &[u8],
        tag: &[u8],
    ) -> Result<HmacKeyEncoding> {
        let minimal_key = minimal_length_key(key);
        let leading_zero_bytes = key.as_bytes().len() - minimal_key.len();
        let minimal = bool::from(sha256_hmac(minimal_key, data).ct_eq(tag));
        let legacy = bool::from(sha256_hmac(key.as_bytes(), data).ct_eq(tag));
        if minimal {
            return Ok(HmacKeyEncoding::MinimalLength);
        }
        if !legacy || leading_zero_bytes == 0 {
            return Err(Error::WalletError("HMAC is not valid".to_string()));
        }
        if self.policy == HmacVerifyPolicy::MinimalLengthOnly {
            return Err(Error::HmacLegacyKey { leading_zero_bytes });
        }
        self.legacy_acceptances.fetch_add(1, Ordering::Relaxed);
        Ok(HmacKeyEncoding::Legacy { leading_zero_bytes })
    }
}

impl ProtoWallet {
    /// Sets which HMAC keys verification accepts. Issuance always uses the
    /// minimal-length key, regardless of this policy.
    ///
    /// ```rust
    /// use bsv_rs::wallet::{HmacVerifyPolicy, ProtoWallet};
    /// use bsv_rs::primitives::PrivateKey;
    ///
    /// let strict = ProtoWallet::new(Some(PrivateKey::random()))
    ///     .with_hmac_verify_policy(HmacVerifyPolicy::MinimalLengthOnly);
    /// assert_eq!(strict.hmac_verify_policy(), HmacVerifyPolicy::MinimalLengthOnly);
    /// ```
    #[must_use]
    pub fn with_hmac_verify_policy(mut self, policy: HmacVerifyPolicy) -> Self {
        self.hmac.policy = policy;
        self
    }

    /// The wallet's HMAC verification policy.
    #[must_use]
    pub fn hmac_verify_policy(&self) -> HmacVerifyPolicy {
        self.hmac.policy
    }

    /// The number of legacy 32-byte-key tags accepted by this wallet and its
    /// clones, through the inherent and async verification methods alike.
    /// Standard tags, invalid tags and strict-policy refusals do not count.
    #[must_use]
    pub fn legacy_hmac_acceptances(&self) -> u64 {
        self.hmac.legacy_acceptances.load(Ordering::Relaxed)
    }

    /// Verifies an HMAC as [`ProtoWallet::verify_hmac`] does and names the
    /// key encoding the tag was made under.
    ///
    /// # Errors
    /// Returns argument or key-derivation errors, [`Error::HmacLegacyKey`]
    /// for a legacy tag under the strict policy, or [`Error::WalletError`]
    /// when neither tag matches.
    pub fn verify_hmac_encoding(&self, args: VerifyHmacArgs) -> Result<HmacKeyEncoding> {
        super::validation::crypto::verify_hmac_args(&args)?;
        let counterparty = args.counterparty.unwrap_or(Counterparty::Self_);
        let symmetric_key = self.key_deriver().derive_symmetric_key(
            &args.protocol_id,
            &args.key_id,
            &counterparty,
        )?;
        self.hmac.verify(&symmetric_key, &args.data, &args.hmac)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_retains_one_octet_and_nonzero_keys_omit_only_leading_zeros() {
        let mut bytes = [0; 32];
        assert_eq!(
            minimal_length_key(&SymmetricKey::from_bytes(&bytes).unwrap()),
            &[0]
        );
        for start in 0..32 {
            bytes[start] = 1;
            let key = SymmetricKey::from_bytes(&bytes).unwrap();
            assert_eq!(minimal_length_key(&key), &bytes[start..]);
            bytes[start] = 0;
        }
    }
}
