//! Shamir Secret Sharing for private key backup and recovery.
//!
//! This module implements Shamir's Secret Sharing scheme for splitting a private key
//! into multiple shares, where any threshold number of shares can reconstruct the
//! original key, but fewer shares reveal nothing about it.
//!
//! # Example
//!
//! ```rust
//! use bsv_rs::primitives::bsv::shamir::{split_private_key, KeyShares};
//! use bsv_rs::primitives::ec::PrivateKey;
//!
//! // Generate a random private key
//! let key = PrivateKey::random();
//!
//! // Split into 5 shares with threshold of 3
//! let shares = split_private_key(&key, 3, 5).unwrap();
//!
//! // Export to backup format
//! let backup = shares.to_backup_format();
//! assert_eq!(backup.len(), 5);
//!
//! // Recover from any 3 shares
//! let subset = KeyShares::from_backup_format(&backup[0..3]).unwrap();
//! let recovered = subset.recover_private_key().unwrap();
//!
//! assert_eq!(key.to_bytes(), recovered.to_bytes());
//! ```
//!
//! # Backup Format
//!
//! Each share is serialized as: `base58(x).base58(y).threshold.integrity`
//!
//! - `base58(x)` and `base58(y)` are the point coordinates
//! - `threshold` is the minimum number of shares needed for recovery
//! - `integrity` is the first 4 characters of base58(sha256(secret)) for verification

use crate::error::{Error, Result};
use crate::primitives::bsv::polynomial::{PointInFiniteField, Polynomial};
use crate::primitives::encoding::{from_base58, to_base58};
use crate::primitives::hash::sha256;
use crate::primitives::BigNumber;
use crate::primitives::PrivateKey;

/// A collection of key shares that can be used to recover a private key.
///
/// Contains the share points, the threshold needed for recovery, and an
/// integrity checksum to verify successful recovery.
#[derive(Clone, Debug)]
pub struct KeyShares {
    /// The share points (x, y coordinates in the finite field).
    pub points: Vec<PointInFiniteField>,
    /// The minimum number of shares needed for recovery.
    pub threshold: usize,
    /// Integrity check: first 4 characters of base58(sha256(secret)).
    pub integrity: String,
}

impl KeyShares {
    /// Creates a new KeyShares instance.
    ///
    /// # Arguments
    ///
    /// * `points` - The share points
    /// * `threshold` - The minimum number of shares needed for recovery
    /// * `integrity` - The integrity checksum string
    pub fn new(points: Vec<PointInFiniteField>, threshold: usize, integrity: String) -> Self {
        Self {
            points,
            threshold,
            integrity,
        }
    }

    /// Parses key shares from backup format strings.
    ///
    /// Each share string must be in the format: `base58(x).base58(y).threshold.integrity`
    ///
    /// # Arguments
    ///
    /// * `shares` - The backup format strings
    ///
    /// # Returns
    ///
    /// The parsed KeyShares, or an error if parsing fails or shares are inconsistent
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Any share string has an invalid format
    /// - Shares have different thresholds
    /// - Shares have different integrity values
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_rs::primitives::bsv::shamir::KeyShares;
    ///
    /// let backup = vec![
    ///     "2.someY.3.abcd".to_string(),
    ///     "3.otherY.3.abcd".to_string(),
    ///     "4.anotherY.3.abcd".to_string(),
    /// ];
    /// // Note: This example would fail because "someY" etc. aren't valid base58
    /// // In practice, use actual share strings from split_private_key()
    /// ```
    pub fn from_backup_format(shares: &[String]) -> Result<Self> {
        if shares.is_empty() {
            return Err(Error::CryptoError(
                "No shares provided for recovery".to_string(),
            ));
        }

        let mut points = Vec::with_capacity(shares.len());
        let mut threshold: Option<usize> = None;
        let mut integrity: Option<String> = None;

        for (idx, share) in shares.iter().enumerate() {
            let (point, t, i) = decode_share(share)?;

            // Validate consistency
            if let Some(existing_threshold) = threshold {
                if existing_threshold != t {
                    return Err(Error::CryptoError(format!(
                        "Threshold mismatch: share 0 has threshold {}, share {} has threshold {}",
                        existing_threshold, idx, t
                    )));
                }
            } else {
                threshold = Some(t);
            }

            if let Some(ref existing_integrity) = integrity {
                if existing_integrity != &i {
                    return Err(Error::CryptoError(format!(
                        "Integrity mismatch: share 0 has integrity '{}', share {} has integrity '{}'",
                        existing_integrity, idx, i
                    )));
                }
            } else {
                integrity = Some(i);
            }

            points.push(point);
        }

        let (Some(threshold), Some(integrity)) = (threshold, integrity) else {
            return Err(Error::CryptoError("No shares to recombine".to_string()));
        };
        Ok(Self {
            points,
            threshold,
            integrity,
        })
    }

    /// Converts the key shares to backup format strings.
    ///
    /// Each share is serialized as: `base58(x).base58(y).threshold.integrity`
    ///
    /// # Returns
    ///
    /// A vector of backup format strings, one per share
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_rs::primitives::bsv::shamir::split_private_key;
    /// use bsv_rs::primitives::ec::PrivateKey;
    ///
    /// let key = PrivateKey::random();
    /// let shares = split_private_key(&key, 2, 3).unwrap();
    /// let backup = shares.to_backup_format();
    ///
    /// // Each string can be stored separately
    /// for (i, share_str) in backup.iter().enumerate() {
    ///     println!("Share {}: {}", i + 1, share_str);
    /// }
    /// ```
    pub fn to_backup_format(&self) -> Vec<String> {
        self.points
            .iter()
            .map(|point| {
                format!(
                    "{}.{}.{}",
                    point.to_point_string(),
                    self.threshold,
                    self.integrity
                )
            })
            .collect()
    }

    /// Recovers the private key from the shares using Lagrange interpolation.
    ///
    /// The secret is the y-intercept (value at x=0) of the polynomial that passes
    /// through all the share points.
    ///
    /// # Returns
    ///
    /// The recovered private key, or an error if:
    /// - There are fewer shares than the threshold
    /// - The integrity check fails
    /// - The recovered value is not a valid private key
    ///
    /// # Example
    ///
    /// ```rust
    /// use bsv_rs::primitives::bsv::shamir::split_private_key;
    /// use bsv_rs::primitives::ec::PrivateKey;
    ///
    /// let key = PrivateKey::random();
    /// let shares = split_private_key(&key, 3, 5).unwrap();
    ///
    /// // Recover from exactly 3 shares
    /// let recovered = shares.recover_private_key().unwrap();
    /// assert_eq!(key.to_bytes(), recovered.to_bytes());
    /// ```
    pub fn recover_private_key(&self) -> Result<PrivateKey> {
        if self.points.len() < self.threshold {
            return Err(Error::CryptoError(format!(
                "Insufficient shares: have {}, need {}",
                self.points.len(),
                self.threshold
            )));
        }

        // Create polynomial from points and evaluate at x=0
        let poly = Polynomial::new(self.points.clone(), self.threshold);
        let secret = poly.value_at(&BigNumber::zero());

        // Convert to 32-byte representation
        // The secret should fit in 32 bytes (it's a private key value)
        let secret_bytes = secret.to_bytes_be(32);

        // Create the private key
        let key = PrivateKey::from_bytes(&secret_bytes)?;

        // Verify integrity
        let computed_integrity = compute_integrity(&key);
        if computed_integrity != self.integrity {
            return Err(Error::CryptoError(format!(
                "Integrity check failed: computed '{}', expected '{}'",
                computed_integrity, self.integrity
            )));
        }

        Ok(key)
    }
}

/// Splits a private key into multiple shares using Shamir's Secret Sharing.
///
/// The secret (private key) becomes the constant term of a random polynomial.
/// Shares are generated by evaluating the polynomial at x = 1, 2, 3, ..., total.
///
/// # Arguments
///
/// * `key` - The private key to split
/// * `threshold` - The minimum number of shares needed for recovery (must be >= 2)
/// * `total` - The total number of shares to generate (must be >= threshold)
///
/// # Returns
///
/// The generated key shares, or an error if the parameters are invalid
///
/// # Example
///
/// ```rust
/// use bsv_rs::primitives::bsv::shamir::split_private_key;
/// use bsv_rs::primitives::ec::PrivateKey;
///
/// let key = PrivateKey::random();
///
/// // Create 5 shares where any 3 can recover the key
/// let shares = split_private_key(&key, 3, 5).unwrap();
///
/// assert_eq!(shares.points.len(), 5);
/// assert_eq!(shares.threshold, 3);
/// ```
///
/// # Security
///
/// - Choose threshold based on your security requirements
/// - Higher threshold = more shares needed = more secure against partial compromise
/// - Lower threshold = easier to recover = less secure
/// - Typical values: 2-of-3, 3-of-5, etc.
pub fn split_private_key(key: &PrivateKey, threshold: usize, total: usize) -> Result<KeyShares> {
    // a_1..a_{t-1}: random scalars, never zero (the `_with` form checks)
    let draws = 1..threshold.clamp(1, 255);
    let coefficients: Vec<[u8; 32]> = draws.map(|_| PrivateKey::random().to_bytes()).collect();
    split_private_key_with(key, threshold, total, &coefficients)
}

/// [`split_private_key`] with the coefficients a_1..a_{t-1} given, each 32
/// bytes big-endian reduced modulo p; the plain form draws them and calls
/// this, so the same coefficients give the same shares (a reproducible seed
/// corpus, bsv-rs#180). This crate's addition: TS draws its polynomial inside
/// `toKeyShares`. Refuses as the plain form does, a count other than
/// `threshold - 1` as `InvalidDataLength` (in bytes), and a coefficient 0
/// modulo p as `CryptoError` (a zero top one lowers the degree). Production
/// code uses [`split_private_key`]: the coefficients and one share give the key.
pub fn split_private_key_with(
    key: &PrivateKey,
    threshold: usize,
    total: usize,
    coefficients: &[[u8; 32]],
) -> Result<KeyShares> {
    // Validate parameters
    if threshold < 2 {
        return Err(Error::CryptoError(
            "Threshold must be at least 2".to_string(),
        ));
    }
    if total < threshold {
        return Err(Error::CryptoError(format!(
            "Total shares ({}) must be at least threshold ({})",
            total, threshold
        )));
    }
    if threshold > 255 {
        return Err(Error::CryptoError(
            "Threshold cannot exceed 255".to_string(),
        ));
    }

    let p = BigNumber::secp256k1_prime();

    if coefficients.len() != threshold - 1 {
        let (expected, actual) = (32 * (threshold - 1), 32 * coefficients.len());
        return Err(Error::InvalidDataLength { expected, actual });
    }
    // The constant term a_0 is the secret, then a_1..a_{t-1}
    let mut terms = vec![BigNumber::from_bytes_be(&key.to_bytes())];
    terms.extend(
        coefficients
            .iter()
            .map(|c| BigNumber::from_bytes_be(c).modulo(&p)),
    );
    if terms[1..].iter().any(BigNumber::is_zero) {
        let zero = "Shamir coefficient is zero modulo p";
        return Err(Error::CryptoError(zero.into()));
    }

    // Generate shares by evaluating polynomial at x = 1, 2, ..., total
    let mut points = Vec::with_capacity(total);

    for i in 1..=total {
        let x = BigNumber::from_u64(i as u64);
        let y = evaluate_polynomial(&terms, &x, &p);
        points.push(PointInFiniteField::new(x, y));
    }

    // Compute integrity checksum
    let integrity = compute_integrity(key);

    Ok(KeyShares {
        points,
        threshold,
        integrity,
    })
}

/// Evaluates a polynomial at a given point.
///
/// Given coefficients [a_0, a_1, ..., a_{n-1}], computes:
/// f(x) = a_0 + a_1*x + a_2*x^2 + ... + a_{n-1}*x^{n-1}
///
/// Uses Horner's method for efficiency.
fn evaluate_polynomial(
    coefficients: &[BigNumber],
    x: &BigNumber,
    modulus: &BigNumber,
) -> BigNumber {
    // Horner's method: f(x) = a_0 + x*(a_1 + x*(a_2 + ... + x*a_{n-1}))
    let mut result = BigNumber::zero();

    for coeff in coefficients.iter().rev() {
        result = result.mul(x).add(coeff).modulo(modulus);
    }

    result
}

/// Computes the integrity checksum for a private key.
///
/// Returns the first 4 characters of base58(sha256(key_bytes)).
fn compute_integrity(key: &PrivateKey) -> String {
    let hash = sha256(&key.to_bytes());
    let b58 = to_base58(&hash);

    // Take first 4 characters
    if b58.len() >= 4 {
        b58[..4].to_string()
    } else {
        b58
    }
}

/// Decodes a share from its backup format string.
///
/// Format: `base58(x).base58(y).threshold.integrity`
///
/// Returns the point, threshold, and integrity string.
fn decode_share(share: &str) -> Result<(PointInFiniteField, usize, String)> {
    let components: Vec<&str> = share.split('.').collect();

    if components.len() != 4 {
        return Err(Error::CryptoError(format!(
            "Invalid share format: expected 'base58(x).base58(y).threshold.integrity', got '{}'",
            share
        )));
    }

    // Parse x and y from base58
    let x_bytes = from_base58(components[0])?;
    let y_bytes = from_base58(components[1])?;

    let x = BigNumber::from_bytes_be(&x_bytes);
    let y = BigNumber::from_bytes_be(&y_bytes);

    let point = PointInFiniteField::new(x, y);

    // Parse threshold
    let threshold: usize = components[2].parse().map_err(|e| {
        Error::CryptoError(format!(
            "Invalid threshold in share: {} ({})",
            components[2], e
        ))
    })?;

    // Integrity is the last component
    let integrity = components[3].to_string();

    Ok((point, threshold, integrity))
}

#[cfg(test)]
#[path = "shamir_tests.rs"]
mod tests;
