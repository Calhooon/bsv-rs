//! BRC-56 HMAC tag verification under both key encodings (#379).
//!
//! BRC-56 (`5119a9b` `wallet/0056.md:66`) keys the HMAC with the shared
//! point's X coordinate as exactly 32 big-endian bytes; ts-sdk's
//! `ProtoWallet` keys it with that number's minimal-length encoding (the
//! leading zero bytes dropped, `:73`), a different tag for one key in 256,
//! and keeps that as its default after the revert of ts-stack PR 1370.
//! This crate issues the 32-byte tag (as go-sdk and py-sdk do) and, by the
//! owner's 18.10 (a) of 2026-10-27, verifies the 32-byte tag first and the
//! minimal-length tag on a miss, both computed and compared in constant time
//! (ts-stack PR #1423's verifier, `109bc7017`), the second acceptance named
//! in [`HmacKeyEncoding`] and counted on the wallet. A caller that wants the
//! BRC's key alone sets [`HmacVerifyPolicy::ThirtyTwoByteOnly`], under which
//! a minimal-length tag is refused by name, [`Error::HmacMinimalLengthKey`].

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
    /// BRC-56's key: the X coordinate as exactly 32 bytes (`wallet/0056.md:66`),
    /// the key this crate, go-sdk and py-sdk issue under. A key with no
    /// leading zero byte has this encoding only.
    ThirtyTwoByte,
    /// The minimal-length key: the 32-byte key with its leading zero bytes
    /// dropped, the key ts-sdk issues under (`wallet/0056.md:73`). Accepted
    /// on a miss of the 32-byte tag under [`HmacVerifyPolicy::BothEncodings`].
    MinimalLength {
        /// How many zero bytes the 32-byte key begins with: the bytes the
        /// sender dropped.
        leading_zero_bytes: usize,
    },
}

/// Which HMAC key encodings [`ProtoWallet::verify_hmac`] accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum HmacVerifyPolicy {
    /// The 32-byte key's tag, and the minimal-length key's on a miss (the
    /// default, the owner's 18.10 (a); ts-stack PR #1423's verifier).
    #[default]
    BothEncodings,
    /// The 32-byte key's tag alone; a tag under the minimal-length key is
    /// refused as [`Error::HmacMinimalLengthKey`] (this crate's verifier
    /// from #148 to #379).
    ThirtyTwoByteOnly,
}

/// A wallet's HMAC verification policy and its count of minimal-length
/// acceptances (shared by the wallet's clones).
#[derive(Debug, Clone, Default)]
pub(crate) struct HmacVerifier {
    policy: HmacVerifyPolicy,
    minimal_length_acceptances: Arc<AtomicU64>,
}

impl HmacVerifier {
    /// Checks `tag` under both encodings of `key`, in constant time.
    ///
    /// Both tags are always computed and compared; a key with no leading
    /// zero byte has one encoding, so both comparisons agree. A tag matching
    /// neither key is `WalletError("HMAC is not valid")`.
    pub(crate) fn verify(
        &self,
        key: &SymmetricKey,
        data: &[u8],
        tag: &[u8],
    ) -> Result<HmacKeyEncoding> {
        let key = key.as_bytes();
        // ts-sdk's `toArray()` keeps one byte of a zero number
        let leading_zero_bytes = key
            .iter()
            .take_while(|b| **b == 0)
            .count()
            .min(key.len().saturating_sub(1));
        let full = bool::from(sha256_hmac(key, data).ct_eq(tag));
        let minimal = bool::from(sha256_hmac(&key[leading_zero_bytes..], data).ct_eq(tag));
        if full {
            return Ok(HmacKeyEncoding::ThirtyTwoByte);
        }
        if !minimal || leading_zero_bytes == 0 {
            return Err(Error::WalletError("HMAC is not valid".to_string()));
        }
        if self.policy == HmacVerifyPolicy::ThirtyTwoByteOnly {
            return Err(Error::HmacMinimalLengthKey { leading_zero_bytes });
        }
        self.minimal_length_acceptances
            .fetch_add(1, Ordering::Relaxed);
        Ok(HmacKeyEncoding::MinimalLength { leading_zero_bytes })
    }
}

impl ProtoWallet {
    /// Sets which HMAC key encodings [`ProtoWallet::verify_hmac`] accepts
    /// (#379); the default is [`HmacVerifyPolicy::BothEncodings`].
    ///
    /// ```rust
    /// use bsv_rs::wallet::{HmacVerifyPolicy, ProtoWallet};
    /// use bsv_rs::primitives::PrivateKey;
    ///
    /// let strict = ProtoWallet::new(Some(PrivateKey::random()))
    ///     .with_hmac_verify_policy(HmacVerifyPolicy::ThirtyTwoByteOnly);
    /// assert_eq!(strict.hmac_verify_policy(), HmacVerifyPolicy::ThirtyTwoByteOnly);
    /// ```
    pub fn with_hmac_verify_policy(mut self, policy: HmacVerifyPolicy) -> Self {
        self.hmac.policy = policy;
        self
    }

    /// The wallet's HMAC verification policy.
    pub fn hmac_verify_policy(&self) -> HmacVerifyPolicy {
        self.hmac.policy
    }

    /// How many tags this wallet (and its clones) accepted under the
    /// minimal-length key: the count of [`HmacKeyEncoding::MinimalLength`]
    /// verdicts, through [`ProtoWallet::verify_hmac`] and
    /// [`ProtoWallet::verify_hmac_encoding`] alike.
    pub fn minimal_length_hmac_acceptances(&self) -> u64 {
        self.hmac.minimal_length_acceptances.load(Ordering::Relaxed)
    }

    /// Verifies an HMAC as [`ProtoWallet::verify_hmac`] does and names the
    /// key encoding the tag was made under.
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
