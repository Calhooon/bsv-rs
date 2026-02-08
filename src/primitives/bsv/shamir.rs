//! Shamir Secret Sharing for private key backup and recovery.
//!
//! This module implements Shamir's Secret Sharing scheme for splitting a private key
//! into multiple shares, where any threshold number of shares can reconstruct the
//! original key, but fewer shares reveal nothing about it.
//!
//! # Example
//!
//! ```rust
//! use bsv_sdk::primitives::bsv::shamir::{split_private_key, KeyShares};
//! use bsv_sdk::primitives::ec::PrivateKey;
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
    /// use bsv_sdk::primitives::bsv::shamir::KeyShares;
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

        Ok(Self {
            points,
            threshold: threshold.unwrap(),
            integrity: integrity.unwrap(),
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
    /// use bsv_sdk::primitives::bsv::shamir::split_private_key;
    /// use bsv_sdk::primitives::ec::PrivateKey;
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
    /// use bsv_sdk::primitives::bsv::shamir::split_private_key;
    /// use bsv_sdk::primitives::ec::PrivateKey;
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
/// use bsv_sdk::primitives::bsv::shamir::split_private_key;
/// use bsv_sdk::primitives::ec::PrivateKey;
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

    // The secret is the private key as a BigNumber
    let secret = BigNumber::from_bytes_be(&key.to_bytes());

    // Generate random polynomial coefficients a_1, a_2, ..., a_{t-1}
    // The constant term a_0 is the secret
    let mut coefficients = Vec::with_capacity(threshold);
    coefficients.push(secret);

    for _ in 1..threshold {
        // Generate random 32-byte coefficient
        let random_key = PrivateKey::random();
        let coeff = BigNumber::from_bytes_be(&random_key.to_bytes()).modulo(&p);
        coefficients.push(coeff);
    }

    // Generate shares by evaluating polynomial at x = 1, 2, ..., total
    let mut points = Vec::with_capacity(total);

    for i in 1..=total {
        let x = BigNumber::from_u64(i as u64);
        let y = evaluate_polynomial(&coefficients, &x, &p);
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
mod tests {
    use super::*;

    #[test]
    fn test_split_recover_roundtrip() {
        let key = PrivateKey::random();
        let shares = split_private_key(&key, 3, 5).unwrap();

        assert_eq!(shares.points.len(), 5);
        assert_eq!(shares.threshold, 3);

        // Recover from first 3 shares
        let subset = KeyShares::new(shares.points[0..3].to_vec(), 3, shares.integrity.clone());
        let recovered = subset.recover_private_key().unwrap();
        assert_eq!(key.to_bytes(), recovered.to_bytes());
    }

    #[test]
    fn test_split_recover_different_subsets() {
        let key = PrivateKey::random();
        let shares = split_private_key(&key, 3, 5).unwrap();

        // Try different subsets of 3 shares
        let subsets = vec![
            vec![0, 1, 2],
            vec![0, 1, 3],
            vec![0, 1, 4],
            vec![0, 2, 3],
            vec![0, 2, 4],
            vec![0, 3, 4],
            vec![1, 2, 3],
            vec![1, 2, 4],
            vec![1, 3, 4],
            vec![2, 3, 4],
        ];

        for indices in subsets {
            let points: Vec<_> = indices.iter().map(|&i| shares.points[i].clone()).collect();
            let subset = KeyShares::new(points, 3, shares.integrity.clone());
            let recovered = subset.recover_private_key().unwrap();
            assert_eq!(
                key.to_bytes(),
                recovered.to_bytes(),
                "Failed for indices {:?}",
                indices
            );
        }
    }

    #[test]
    fn test_backup_format_roundtrip() {
        let key = PrivateKey::random();
        let shares = split_private_key(&key, 3, 5).unwrap();

        // Export to backup format
        let backup = shares.to_backup_format();
        assert_eq!(backup.len(), 5);

        // Each backup string should have 4 parts
        for s in &backup {
            assert_eq!(s.split('.').count(), 4);
        }

        // Restore from backup (using middle 3 shares)
        let restored = KeyShares::from_backup_format(&backup[1..4]).unwrap();
        let recovered = restored.recover_private_key().unwrap();
        assert_eq!(key.to_bytes(), recovered.to_bytes());
    }

    #[test]
    fn test_minimum_threshold() {
        // Test with threshold = 2
        let key = PrivateKey::random();
        let shares = split_private_key(&key, 2, 3).unwrap();

        let subset = KeyShares::new(shares.points[0..2].to_vec(), 2, shares.integrity.clone());
        let recovered = subset.recover_private_key().unwrap();
        assert_eq!(key.to_bytes(), recovered.to_bytes());
    }

    #[test]
    fn test_exact_threshold_equals_total() {
        // Test with threshold = total (all shares needed)
        let key = PrivateKey::random();
        let shares = split_private_key(&key, 5, 5).unwrap();

        let recovered = shares.recover_private_key().unwrap();
        assert_eq!(key.to_bytes(), recovered.to_bytes());
    }

    #[test]
    fn test_insufficient_shares() {
        let key = PrivateKey::random();
        let shares = split_private_key(&key, 3, 5).unwrap();

        // Try to recover with only 2 shares (less than threshold)
        let subset = KeyShares::new(shares.points[0..2].to_vec(), 3, shares.integrity.clone());
        let result = subset.recover_private_key();
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_threshold() {
        let key = PrivateKey::random();

        // Threshold less than 2
        assert!(split_private_key(&key, 1, 5).is_err());
        assert!(split_private_key(&key, 0, 5).is_err());

        // Total less than threshold
        assert!(split_private_key(&key, 5, 3).is_err());
    }

    #[test]
    fn test_integrity_check_fails_on_corruption() {
        let key = PrivateKey::random();
        let shares = split_private_key(&key, 2, 3).unwrap();

        // Create shares with wrong integrity
        let corrupted = KeyShares::new(
            shares.points.clone(),
            2,
            "XXXX".to_string(), // Wrong integrity
        );

        let result = corrupted.recover_private_key();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Integrity check failed"));
    }

    #[test]
    fn test_backup_format_parsing() {
        let key = PrivateKey::random();
        let shares = split_private_key(&key, 2, 3).unwrap();
        let backup = shares.to_backup_format();

        // Verify format
        let parsed = KeyShares::from_backup_format(&backup).unwrap();
        assert_eq!(parsed.threshold, shares.threshold);
        assert_eq!(parsed.integrity, shares.integrity);
        assert_eq!(parsed.points.len(), shares.points.len());
    }

    #[test]
    fn test_mismatched_threshold_in_shares() {
        // Create two shares manually with different thresholds
        let share1 = "2.abc.3.XXXX".to_string();
        let share2 = "3.def.4.XXXX".to_string(); // Different threshold

        let result = KeyShares::from_backup_format(&[share1, share2]);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Threshold mismatch"));
    }

    #[test]
    fn test_mismatched_integrity_in_shares() {
        // Create two shares manually with different integrity
        let share1 = "2.abc.3.AAAA".to_string();
        let share2 = "3.def.3.BBBB".to_string(); // Different integrity

        let result = KeyShares::from_backup_format(&[share1, share2]);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Integrity mismatch"));
    }

    #[test]
    fn test_known_private_key() {
        // Test with a known private key value
        let key = PrivateKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();

        let shares = split_private_key(&key, 2, 3).unwrap();
        let recovered = shares.recover_private_key().unwrap();

        assert_eq!(key.to_bytes(), recovered.to_bytes());
    }

    #[test]
    fn test_large_number_of_shares() {
        let key = PrivateKey::random();
        let shares = split_private_key(&key, 5, 10).unwrap();

        assert_eq!(shares.points.len(), 10);

        // Recover from any 5 shares
        let subset = KeyShares::new(
            shares.points[5..10].to_vec(), // Last 5 shares
            5,
            shares.integrity.clone(),
        );
        let recovered = subset.recover_private_key().unwrap();
        assert_eq!(key.to_bytes(), recovered.to_bytes());
    }

    #[test]
    fn test_compute_integrity() {
        let key = PrivateKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();

        let integrity = compute_integrity(&key);
        // Should be 4 characters
        assert_eq!(integrity.len(), 4);

        // Integrity should be deterministic
        let integrity2 = compute_integrity(&key);
        assert_eq!(integrity, integrity2);
    }

    #[test]
    fn test_evaluate_polynomial() {
        let p = BigNumber::secp256k1_prime();

        // Test polynomial f(x) = 5 + 3x + 2x^2
        // f(0) = 5, f(1) = 10, f(2) = 19
        let coefficients = vec![
            BigNumber::from_u64(5),
            BigNumber::from_u64(3),
            BigNumber::from_u64(2),
        ];

        assert_eq!(
            evaluate_polynomial(&coefficients, &BigNumber::zero(), &p),
            BigNumber::from_u64(5)
        );
        assert_eq!(
            evaluate_polynomial(&coefficients, &BigNumber::from_u64(1), &p),
            BigNumber::from_u64(10)
        );
        assert_eq!(
            evaluate_polynomial(&coefficients, &BigNumber::from_u64(2), &p),
            BigNumber::from_u64(19)
        );
    }

    #[test]
    fn test_decode_share() {
        // Create a valid share format
        let key = PrivateKey::random();
        let shares = split_private_key(&key, 2, 3).unwrap();
        let backup = shares.to_backup_format();

        let (point, threshold, integrity) = decode_share(&backup[0]).unwrap();
        assert_eq!(threshold, 2);
        assert_eq!(integrity, shares.integrity);
        assert_eq!(point.x, shares.points[0].x);
        assert_eq!(point.y, shares.points[0].y);
    }

    #[test]
    fn test_decode_share_invalid_format() {
        // Too few parts
        assert!(decode_share("a.b.c").is_err());

        // Too many parts
        assert!(decode_share("a.b.c.d.e").is_err());

        // Invalid threshold
        assert!(decode_share("2.abc.notanumber.XXXX").is_err());
    }

    #[test]
    fn test_empty_shares() {
        let result = KeyShares::from_backup_format(&[]);
        assert!(result.is_err());
    }

    // ========================
    // Edge case tests (GAP-06)
    // ========================

    #[test]
    fn test_threshold_greater_than_total_shares() {
        // Mirrors Go: TestThresholdLargerThanTotalShares
        let key = PrivateKey::random();
        let result = split_private_key(&key, 50, 5);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("must be at least"),
            "Expected error about total shares being less than threshold"
        );
    }

    #[test]
    fn test_total_shares_less_than_2() {
        // Mirrors Go: TestTotalSharesLessThanTwo
        let key = PrivateKey::random();

        // total=1 with threshold=2 should fail (total < threshold)
        let result = split_private_key(&key, 2, 1);
        assert!(result.is_err());

        // total=1 with threshold=1 should also fail (threshold < 2)
        let result = split_private_key(&key, 1, 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_duplicate_shares_in_recovery() {
        // Mirrors Go: TestDuplicateShareDetected
        // Providing the same share twice should result in failed recovery
        // (the Lagrange interpolation will produce incorrect results or fail)
        let key = PrivateKey::random();
        let shares = split_private_key(&key, 3, 5).unwrap();
        let backup = shares.to_backup_format();

        // Use share 0, share 1, and share 1 again (duplicate)
        let recovery = KeyShares::from_backup_format(&[
            backup[0].clone(),
            backup[1].clone(),
            backup[1].clone(),
        ])
        .unwrap();

        // Recovery should fail: either the interpolation gives wrong result
        // (integrity check fails) or the mod_inverse fails on duplicate x coords
        let result = recovery.recover_private_key();
        assert!(
            result.is_err(),
            "Expected error when using duplicate shares for recovery"
        );
    }

    #[test]
    fn test_fewer_points_than_threshold() {
        // Mirrors Go: TestFewerPointsThanThreshold
        // Explicitly test the error message when fewer shares than threshold
        let key = PrivateKey::random();
        let shares = split_private_key(&key, 3, 5).unwrap();

        // Manually set only 2 points but keep threshold at 3
        let subset = KeyShares::new(shares.points[..2].to_vec(), 3, shares.integrity.clone());
        let result = subset.recover_private_key();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Insufficient shares"),
            "Expected 'Insufficient shares' error message"
        );
    }

    #[test]
    fn test_consistency_across_multiple_splits() {
        // Mirrors Go: TestPolynomialConsistency
        // Splitting the same secret twice gives different shares (randomness)
        // but both sets should recover the same secret
        let key = PrivateKey::random();

        let shares1 = split_private_key(&key, 3, 5).unwrap();
        let shares2 = split_private_key(&key, 3, 5).unwrap();

        // The shares themselves should be different (different random polynomials)
        assert_ne!(
            shares1.points[0].y, shares2.points[0].y,
            "Two splits of the same key should produce different shares due to randomness"
        );

        // But both should recover the same key
        let recovered1 = KeyShares::new(shares1.points[..3].to_vec(), 3, shares1.integrity.clone())
            .recover_private_key()
            .unwrap();
        let recovered2 = KeyShares::new(shares2.points[..3].to_vec(), 3, shares2.integrity.clone())
            .recover_private_key()
            .unwrap();

        assert_eq!(key.to_bytes(), recovered1.to_bytes());
        assert_eq!(key.to_bytes(), recovered2.to_bytes());

        // Integrity should also match since it's derived from the same key
        assert_eq!(shares1.integrity, shares2.integrity);
    }

    #[test]
    fn test_different_recovery_subsets() {
        // Mirrors Go: TestPolynomialReconstructionWithDifferentSubsets
        // Split into 5 shares with threshold 3, recover using all C(5,3)=10 subsets
        let key = PrivateKey::random();
        let shares = split_private_key(&key, 3, 5).unwrap();

        let all_subsets: Vec<Vec<usize>> = vec![
            vec![0, 1, 2],
            vec![0, 1, 3],
            vec![0, 1, 4],
            vec![0, 2, 3],
            vec![0, 2, 4],
            vec![0, 3, 4],
            vec![1, 2, 3],
            vec![1, 2, 4],
            vec![1, 3, 4],
            vec![2, 3, 4],
        ];

        for subset_indices in &all_subsets {
            let subset_points: Vec<_> = subset_indices
                .iter()
                .map(|&i| shares.points[i].clone())
                .collect();
            let subset = KeyShares::new(subset_points, 3, shares.integrity.clone());
            let recovered = subset.recover_private_key().unwrap();
            assert_eq!(
                key.to_bytes(),
                recovered.to_bytes(),
                "Recovery failed for subset {:?}",
                subset_indices
            );
        }
    }

    #[test]
    fn test_single_share_threshold() {
        // Threshold of 1 should be rejected (1-of-N is just copying the secret)
        let key = PrivateKey::random();
        let result = split_private_key(&key, 1, 5);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("at least 2"),
            "Expected error about threshold being at least 2"
        );
    }

    #[test]
    fn test_max_shares() {
        // Test with the maximum allowed number of shares (255)
        let key = PrivateKey::random();
        let shares = split_private_key(&key, 3, 255).unwrap();
        assert_eq!(shares.points.len(), 255);

        // Recover from first 3 shares
        let subset = KeyShares::new(shares.points[..3].to_vec(), 3, shares.integrity.clone());
        let recovered = subset.recover_private_key().unwrap();
        assert_eq!(key.to_bytes(), recovered.to_bytes());

        // Recover from last 3 shares
        let subset = KeyShares::new(
            shares.points[252..255].to_vec(),
            3,
            shares.integrity.clone(),
        );
        let recovered = subset.recover_private_key().unwrap();
        assert_eq!(key.to_bytes(), recovered.to_bytes());

        // Recover from widely spaced shares (first, middle, last)
        let subset = KeyShares::new(
            vec![
                shares.points[0].clone(),
                shares.points[127].clone(),
                shares.points[254].clone(),
            ],
            3,
            shares.integrity.clone(),
        );
        let recovered = subset.recover_private_key().unwrap();
        assert_eq!(key.to_bytes(), recovered.to_bytes());
    }

    #[test]
    fn test_threshold_exceeds_255() {
        // Threshold > 255 should be rejected
        let key = PrivateKey::random();
        let result = split_private_key(&key, 256, 300);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("255"),
            "Expected error about threshold exceeding 255"
        );
    }

    #[test]
    fn test_different_thresholds_and_shares() {
        // Mirrors Go: TestPolynomialDifferentThresholdsAndShares
        // Test various threshold/total combinations
        let test_cases = vec![(2, 3), (2, 5), (3, 5), (4, 7), (5, 10), (10, 10)];

        for (threshold, total) in test_cases {
            let key = PrivateKey::random();
            let shares = split_private_key(&key, threshold, total).unwrap();
            assert_eq!(shares.points.len(), total);

            let subset = KeyShares::new(
                shares.points[..threshold].to_vec(),
                threshold,
                shares.integrity.clone(),
            );
            let recovered = subset.recover_private_key().unwrap();
            assert_eq!(
                key.to_bytes(),
                recovered.to_bytes(),
                "Failed for threshold={}, total={}",
                threshold,
                total
            );
        }
    }

    #[test]
    fn test_recovery_with_more_shares_than_threshold() {
        // Providing more shares than the threshold should still work
        let key = PrivateKey::random();
        let shares = split_private_key(&key, 3, 5).unwrap();

        // Use all 5 shares even though only 3 are needed
        let recovered = shares.recover_private_key().unwrap();
        assert_eq!(key.to_bytes(), recovered.to_bytes());

        // Use 4 shares
        let subset = KeyShares::new(shares.points[..4].to_vec(), 3, shares.integrity.clone());
        let recovered = subset.recover_private_key().unwrap();
        assert_eq!(key.to_bytes(), recovered.to_bytes());
    }

    #[test]
    fn test_recovery_with_wrong_shares_fails_integrity() {
        // Shares from different keys should fail integrity check
        let key1 = PrivateKey::random();
        let key2 = PrivateKey::random();

        let shares1 = split_private_key(&key1, 2, 3).unwrap();
        let shares2 = split_private_key(&key2, 2, 3).unwrap();

        // Mix shares from two different keys but use integrity from key1
        let mixed = KeyShares::new(
            vec![shares1.points[0].clone(), shares2.points[1].clone()],
            2,
            shares1.integrity.clone(),
        );
        let result = mixed.recover_private_key();
        // Should fail with integrity check error (or invalid private key)
        assert!(
            result.is_err(),
            "Expected error when mixing shares from different keys"
        );
    }

    #[test]
    fn test_multiple_recovery_iterations() {
        // Mirrors Go: TestPolynomialConsistency - run multiple iterations
        // to ensure randomness doesn't cause flaky behavior
        for _ in 0..10 {
            let key = PrivateKey::random();
            let shares = split_private_key(&key, 3, 5).unwrap();
            let subset = KeyShares::new(shares.points[..3].to_vec(), 3, shares.integrity.clone());
            let recovered = subset.recover_private_key().unwrap();
            assert_eq!(key.to_bytes(), recovered.to_bytes());
        }
    }

    #[test]
    fn test_backup_recovery_full_roundtrip() {
        // Mirrors Go: TestPrivateKeyToKeyShares - full backup/recovery cycle
        for _ in 0..3 {
            let key = PrivateKey::random();
            let shares = split_private_key(&key, 3, 5).unwrap();
            let backup = shares.to_backup_format();
            assert_eq!(backup.len(), 5);

            // Recover from first 3 backup strings
            let recovered_shares = KeyShares::from_backup_format(&backup[..3]).unwrap();
            let recovered_key = recovered_shares.recover_private_key().unwrap();
            assert_eq!(key.to_bytes(), recovered_key.to_bytes());
        }
    }

    #[test]
    fn test_zero_threshold() {
        // Threshold of 0 should be rejected
        let key = PrivateKey::random();
        let result = split_private_key(&key, 0, 5);
        assert!(result.is_err());
    }

    #[test]
    fn test_zero_total_shares() {
        // Total of 0 should be rejected (threshold >= 2 > 0)
        let key = PrivateKey::random();
        let result = split_private_key(&key, 2, 0);
        assert!(result.is_err());
    }
}
